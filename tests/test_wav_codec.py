"""Tests for pure Python WAV PCM Codec."""

import pytest
from audiocipher_stego_engine.wav_codec import AudioBuffer


def test_generate_sine_tone():
    buf = AudioBuffer.generate_sine_tone(frequency=440.0, duration=0.5, sample_rate=44100)
    assert buf.sample_rate == 44100
    assert buf.channels == 1
    assert buf.sample_width == 2
    assert len(buf.samples) == 22050
    assert abs(buf.duration_seconds - 0.5) < 0.01


def test_wav_roundtrip(sine_carrier):
    wav_bytes = sine_carrier.to_wav_bytes()
    assert wav_bytes.startswith(b"RIFF")
    assert b"WAVE" in wav_bytes

    decoded = AudioBuffer.from_wav_bytes(wav_bytes)
    assert decoded.sample_rate == sine_carrier.sample_rate
    assert decoded.channels == sine_carrier.channels
    assert decoded.sample_width == sine_carrier.sample_width
    assert len(decoded.samples) == len(sine_carrier.samples)
    assert decoded.samples == sine_carrier.samples


def test_carrier_chord(chord_carrier):
    assert chord_carrier.duration_seconds >= 2.0
    wav = chord_carrier.to_wav_bytes()
    assert len(wav) > 10000
