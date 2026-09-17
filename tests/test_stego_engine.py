"""Tests for LSB Audio Steganography and Ultrasonic Watermarking."""

import pytest
from audiocipher_stego_engine.stego_engine import StegoEngine
from audiocipher_stego_engine.wav_codec import AudioBuffer


def test_lsb_steganography_roundtrip(sine_carrier):
    payload = b"Top Secret Embedded Stego Vector 123"

    stego_audio = StegoEngine.embed_lsb(sine_carrier, payload)
    assert stego_audio.sample_rate == sine_carrier.sample_rate
    assert len(stego_audio.samples) == len(sine_carrier.samples)

    extracted = StegoEngine.extract_lsb(stego_audio)
    assert extracted == payload


def test_lsb_carrier_too_short():
    tiny_audio = AudioBuffer.generate_sine_tone(440.0, 0.01, sample_rate=44100)
    huge_payload = b"A" * 10000

    with pytest.raises(ValueError, match="too short"):
        StegoEngine.embed_lsb(tiny_audio, huge_payload)


def test_lsb_extraction_on_clean_carrier_fails(sine_carrier):
    with pytest.raises(ValueError, match="No hidden steganographic payload"):
        StegoEngine.extract_lsb(sine_carrier)


def test_ultrasonic_watermark(sine_carrier):
    watermarked = StegoEngine.embed_ultrasonic_watermark(sine_carrier, "COPYRIGHT_757")
    assert len(watermarked.samples) >= len(sine_carrier.samples)
    assert watermarked.samples != sine_carrier.samples
