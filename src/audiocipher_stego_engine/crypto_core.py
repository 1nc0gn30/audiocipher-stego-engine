"""
Audio-Keyed Cryptography & Authenticated Payload Encryption.
Derives 256-bit cryptographic keys from acoustic waveforms and volume modifiers
with strict domain-separated encryption and MAC subkeys.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
from typing import Optional, Tuple

CRYPTO_MAGIC_V2 = b"AC2\x02"
PBKDF2_ITERATIONS_V2 = 200_000
PBKDF2_ITERATIONS_V1 = 10_000
ENC_DOMAIN_LABEL = b"audiocipher-enc-v2"
MAC_DOMAIN_LABEL = b"audiocipher-mac-v2"


def _validate_volume_db(volume_db: float) -> float:
    """Validate that volume_db is a finite real number."""
    if isinstance(volume_db, bool):
        raise ValueError("volume_db must be a finite numeric value, not bool.")
    try:
        val = float(volume_db)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid volume_db: {volume_db!r}") from exc
    if not math.isfinite(val):
        raise ValueError("volume_db must be finite (NaN/inf rejected).")
    return val


def derive_subkeys(master_key: bytes) -> Tuple[bytes, bytes]:
    """
    Derive cryptographically independent 256-bit encryption and MAC keys
    from a 256-bit master key using domain-separated HMAC-SHA256.
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
        raise ValueError("master_key must be exactly 32 bytes.")
    enc_key = hmac.new(master_key, ENC_DOMAIN_LABEL, hashlib.sha256).digest()
    mac_key = hmac.new(master_key, MAC_DOMAIN_LABEL, hashlib.sha256).digest()
    return enc_key, mac_key


def derive_audio_key(
    audio_bytes: bytes,
    volume_db: float = 50.0,
    salt: Optional[bytes] = None,
    iterations: int = PBKDF2_ITERATIONS_V2,
) -> Tuple[bytes, bytes]:
    """
    Derive a high-entropy 256-bit master key from acoustic waveform bytes and decibel modifiers.
    Returns (master_key_32_bytes, salt_16_bytes).
    """
    vol = _validate_volume_db(volume_db)
    if salt is None:
        salt = os.urandom(16)
    elif len(salt) != 16:
        raise ValueError("salt must be exactly 16 bytes.")

    # Blend audio stream with decibel modifier
    vol_bytes = struct.pack("<d", vol)
    audio_digest = hashlib.sha256(audio_bytes + vol_bytes).digest()

    # Apply PBKDF2-HMAC-SHA256 key stretching (default 200,000 rounds for v2)
    derived_key = hashlib.pbkdf2_hmac("sha256", audio_digest, salt, int(iterations), dklen=32)
    return derived_key, salt


def _generate_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """Deterministic cryptographic keystream using iterative HMAC-SHA256 counters."""
    blocks = []
    counter = 0
    generated = 0

    while generated < length:
        counter_bytes = struct.pack("<Q", counter)
        block = hmac.new(key, iv + counter_bytes, hashlib.sha256).digest()
        blocks.append(block)
        generated += len(block)
        counter += 1

    stream = b"".join(blocks)
    return stream[:length]


def encrypt_payload(data: bytes, audio_key: bytes, salt: bytes) -> bytes:
    """
    Encrypt binary payload with v2 key-separated authenticated stream cipher
    (domain-separated enc_key for HMAC-CTR keystream + independent mac_key for Encrypt-then-MAC).
    Wire format v2: [4-byte 'AC2\\x02'] + [16-byte Salt] + [16-byte IV] + [Ciphertext] + [32-byte HMAC-SHA256 Tag]
    """
    if len(salt) != 16:
        raise ValueError("salt must be exactly 16 bytes.")
    enc_key, mac_key = derive_subkeys(audio_key)
    iv = os.urandom(16)
    keystream = _generate_keystream(enc_key, iv, len(data))

    # Encrypt via keystream XOR using enc_key
    ciphertext = bytes(b ^ k for b, k in zip(data, keystream))

    # Authenticate version prefix + header + ciphertext with independent mac_key
    auth_tag = hmac.new(mac_key, CRYPTO_MAGIC_V2 + salt + iv + ciphertext, hashlib.sha256).digest()

    return CRYPTO_MAGIC_V2 + salt + iv + ciphertext + auth_tag


def decrypt_payload(encrypted_blob: bytes, audio_bytes: bytes, volume_db: float = 50.0) -> bytes:
    """
    Decrypt and authenticate payload using the original audio key and volume decibel modifier.
    Supports v2 key-separated blobs (AC2\\x02, 200k PBKDF2 rounds) and legacy v1 blobs (10k rounds)
    for seamless backward compatibility.
    Raises ValueError if ciphertext is corrupted or incorrect audio key/dB is supplied.
    """
    vol = _validate_volume_db(volume_db)

    if encrypted_blob.startswith(CRYPTO_MAGIC_V2):
        if len(encrypted_blob) < 68:
            raise ValueError("Invalid v2 ciphertext length: minimum 68 bytes required (Magic + Salt + IV + Tag).")
        salt = encrypted_blob[4:20]
        iv = encrypted_blob[20:36]
        auth_tag = encrypted_blob[-32:]
        ciphertext = encrypted_blob[36:-32]

        master_key, _ = derive_audio_key(audio_bytes, volume_db=vol, salt=salt, iterations=PBKDF2_ITERATIONS_V2)
        enc_key, mac_key = derive_subkeys(master_key)

        expected_tag = hmac.new(mac_key, CRYPTO_MAGIC_V2 + salt + iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("Decryption authentication failed: Incorrect audio key, decibel level, or corrupted payload.")

        keystream = _generate_keystream(enc_key, iv, len(ciphertext))
        return bytes(b ^ k for b, k in zip(ciphertext, keystream))

    # Legacy v1 backward-compatible decryption path
    if len(encrypted_blob) < 64:
        raise ValueError("Invalid ciphertext length: minimum 64 bytes required (Salt + IV + Tag).")

    salt = encrypted_blob[:16]
    iv = encrypted_blob[16:32]
    auth_tag = encrypted_blob[-32:]
    ciphertext = encrypted_blob[32:-32]

    derived_key, _ = derive_audio_key(audio_bytes, volume_db=vol, salt=salt, iterations=PBKDF2_ITERATIONS_V1)
    expected_tag = hmac.new(derived_key, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(auth_tag, expected_tag):
        raise ValueError("Decryption authentication failed: Incorrect audio key, decibel level, or corrupted payload.")

    keystream = _generate_keystream(derived_key, iv, len(ciphertext))
    return bytes(b ^ k for b, k in zip(ciphertext, keystream))
