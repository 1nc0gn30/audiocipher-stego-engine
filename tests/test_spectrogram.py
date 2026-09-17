"""Tests for Morse Code and Spectrogram visual synthesis."""

import pytest
from audiocipher_stego_engine.spectrogram import (
    synthesize_morse_audio,
    synthesize_spectrogram_watermark,
    text_to_morse,
)


def test_text_to_morse():
    assert text_to_morse("SOS") == "... --- ..."
    assert text_to_morse("HELLO") == ".... . .-.. .-.. ---"


def test_synthesize_morse_audio():
    audio = synthesize_morse_audio("SOS", tone_frequency=800.0, wpm=20)
    assert audio.sample_rate == 44100
    assert audio.duration_seconds > 0.5
    wav = audio.to_wav_bytes()
    assert len(wav) > 1000


def test_synthesize_spectrogram_watermark():
    bitmap = [
        [1, 0, 1],
        [0, 1, 0],
        [1, 0, 1]
    ]
    audio = synthesize_spectrogram_watermark(bitmap, pixel_duration=0.02)
    assert audio.duration_seconds >= 0.05
    assert len(audio.samples) > 0


def test_dtmf_synthesis_and_decode():
    from audiocipher_stego_engine.spectrogram import decode_dtmf_audio, synthesize_dtmf_audio

    digits = "8675309#"
    audio = synthesize_dtmf_audio(digits, tone_duration=0.08, silence_duration=0.04)
    assert audio.duration_seconds > 0.5
    decoded = decode_dtmf_audio(audio, tone_duration=0.08, silence_duration=0.04)
    assert decoded == digits

