"""Tests for Audio-Keyed Cryptography and Authenticated Payload Encryption."""

import os
import pytest
from audiocipher_stego_engine.crypto_core import (
    decrypt_payload,
    derive_audio_key,
    encrypt_payload,
)


def test_derive_audio_key():
    audio_data = b"AUDIO_SAMPLE_DATA_12345"
    key1, salt1 = derive_audio_key(audio_data, volume_db=50.0)
    assert len(key1) == 32
    assert len(salt1) == 16

    # Deterministic with fixed salt
    key2, _ = derive_audio_key(audio_data, volume_db=50.0, salt=salt1)
    assert key1 == key2

    # Different dB yields different key
    key3, _ = derive_audio_key(audio_data, volume_db=60.0, salt=salt1)
    assert key1 != key3


def test_encryption_decryption_roundtrip():
    audio_key_data = b"MY_SECRET_RECORDING_WAV"
    message = b"Top Secret Sovereign Agent Directive #757"

    key, salt = derive_audio_key(audio_key_data, volume_db=45.0)
    encrypted_blob = encrypt_payload(message, key, salt)

    assert encrypted_blob != message
    assert len(encrypted_blob) >= len(message) + 64

    # Successful decryption
    decrypted = decrypt_payload(encrypted_blob, audio_key_data, volume_db=45.0)
    assert decrypted == message


def test_decryption_auth_failure():
    audio_key_data = b"MY_SECRET_RECORDING_WAV"
    message = b"Secret Mission"

    key, salt = derive_audio_key(audio_key_data, volume_db=50.0)
    encrypted_blob = encrypt_payload(message, key, salt)

    # Wrong volume dB should fail HMAC authentication
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_payload(encrypted_blob, audio_key_data, volume_db=50.5)

    # Wrong audio key should fail
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_payload(encrypted_blob, b"WRONG_AUDIO_KEY", volume_db=50.0)

    # Corrupted ciphertext should fail
    corrupted_blob = bytearray(encrypted_blob)
    corrupted_blob[35] ^= 0xFF
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_payload(bytes(corrupted_blob), audio_key_data, volume_db=50.0)
