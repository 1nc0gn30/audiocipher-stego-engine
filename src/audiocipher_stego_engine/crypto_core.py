"""
Audio-Keyed Cryptography & Authenticated Payload Encryption.
Derives 256-bit cryptographic keys from acoustic waveforms and volume modifiers.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional, Tuple


def derive_audio_key(audio_bytes: bytes, volume_db: float = 50.0, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a high-entropy 256-bit key from acoustic waveform bytes and decibel modifiers.
    Returns (key_32_bytes, salt_16_bytes).
    """
    if salt is None:
        salt = os.urandom(16)

    # Blend audio stream with decibel modifier
    vol_bytes = struct.pack("<d", float(volume_db))
    audio_digest = hashlib.sha256(audio_bytes + vol_bytes).digest()

    # Apply PBKDF2-HMAC-SHA256 key stretching (10,000 rounds)
    derived_key = hashlib.pbkdf2_hmac("sha256", audio_digest, salt, 10000, dklen=32)
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
    Encrypt binary payload with authenticated stream cipher (XOR Keystream + HMAC-SHA256).
    Wire format: [16-byte Salt] + [16-byte IV] + [Ciphertext] + [32-byte HMAC-SHA256 Tag]
    """
    iv = os.urandom(16)
    keystream = _generate_keystream(audio_key, iv, len(data))

    # Encrypt via keystream XOR
    ciphertext = bytes(b ^ k for b, k in zip(data, keystream))

    # Authenticate header + ciphertext with HMAC-SHA256
    auth_tag = hmac.new(audio_key, salt + iv + ciphertext, hashlib.sha256).digest()

    return salt + iv + ciphertext + auth_tag


def decrypt_payload(encrypted_blob: bytes, audio_bytes: bytes, volume_db: float = 50.0) -> bytes:
    """
    Decrypt and authenticate payload using the original audio key and volume decibel modifier.
    Raises ValueError if ciphertext is corrupted or incorrect audio key/dB is supplied.
    """
    if len(encrypted_blob) < 64:
        raise ValueError("Invalid ciphertext length: minimum 64 bytes required (Salt + IV + Tag).")

    salt = encrypted_blob[:16]
    iv = encrypted_blob[16:32]
    auth_tag = encrypted_blob[-32:]
    ciphertext = encrypted_blob[32:-32]

    # Derive key from audio key and salt
    derived_key, _ = derive_audio_key(audio_bytes, volume_db=volume_db, salt=salt)

    # Verify HMAC authentication tag in constant time
    expected_tag = hmac.new(derived_key, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(auth_tag, expected_tag):
        raise ValueError("Decryption authentication failed: Incorrect audio key, decibel level, or corrupted payload.")

    # Decrypt via keystream XOR
    keystream = _generate_keystream(derived_key, iv, len(ciphertext))
    plaintext = bytes(b ^ k for b, k in zip(ciphertext, keystream))

    return plaintext
