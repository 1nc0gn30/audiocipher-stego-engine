"""Pytest configuration and fixtures for audiocipher-stego-engine."""

import os
import sys
from pathlib import Path
import pytest

# Ensure src is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from audiocipher_stego_engine.wav_codec import AudioBuffer


@pytest.fixture
def sine_carrier() -> AudioBuffer:
    """Fixture providing a 1.0s 440Hz sine wave carrier."""
    return AudioBuffer.generate_sine_tone(440.0, 1.0, sample_rate=44100)


@pytest.fixture
def chord_carrier() -> AudioBuffer:
    """Fixture providing a rich harmonic chord carrier."""
    return AudioBuffer.generate_carrier_chord([440.0, 554.37, 659.25], duration=2.0)
