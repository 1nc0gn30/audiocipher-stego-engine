"""Unit tests for Parity Bit Steganography, stego capacity, and audio SNR calculation."""

import math
from audiocipher_stego_engine import AudioBuffer, StegoEngine


def _generate_synthetic_tone(duration_s=1.0, freq=440.0, sample_rate=16000):
    samples = []
    total = int(duration_s * sample_rate)
    for i in range(total):
        t = i / sample_rate
        val = int(12000 * math.sin(2.0 * math.pi * freq * t))
        samples.append(val)
    return AudioBuffer(sample_rate=sample_rate, channels=1, sample_width=2, samples=samples)


def test_parity_stego_roundtrip():
    audio = _generate_synthetic_tone(duration_s=1.5, sample_rate=16000)  # 24,000 samples
    secret_payload = b"SUPER_SECRET_COMMUNICATION_KEY_12345"

    # Embed with block_size = 8
    stego_audio = StegoEngine.embed_parity_stego(audio, secret_payload, block_size=8)
    assert len(stego_audio.samples) == len(audio.samples)

    # Extract
    extracted = StegoEngine.extract_parity_stego(stego_audio, block_size=8)
    assert extracted == secret_payload


def test_stego_capacity_calculator():
    audio = _generate_synthetic_tone(duration_s=1.0, sample_rate=16000)  # 16,000 samples
    cap_lsb = StegoEngine.calculate_stego_capacity(audio, method="lsb")
    assert cap_lsb["max_payload_bytes"] == (16000 // 8) - 12
    assert cap_lsb["method"] == "LSB"

    cap_parity = StegoEngine.calculate_stego_capacity(audio, method="parity", block_size=16)
    assert cap_parity["max_payload_bytes"] == ((16000 // 16) // 8) - 12
    assert cap_parity["method"] == "PARITY"


def test_audio_snr_calculation():
    orig = _generate_synthetic_tone(duration_s=0.5, sample_rate=16000)
    # SNR with identical audio is 999
    assert StegoEngine.calculate_audio_snr(orig, orig) == 999.0

    # Embed payload using LSB
    stego_lsb = StegoEngine.embed_lsb(orig, b"TEST_PAYLOAD")
    snr_lsb = StegoEngine.calculate_audio_snr(orig, stego_lsb)
    # LSB on 12,000 amplitude tone has high SNR (>70 dB)
    assert snr_lsb > 60.0
