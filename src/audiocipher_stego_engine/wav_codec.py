"""
Pure Python PCM WAV Codec & Acoustic Signal Synthesizer.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import io
import math
import struct
import wave
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Union


@dataclass
class AudioBuffer:
    """Represents an uncompressed PCM audio buffer."""
    sample_rate: int
    channels: int
    sample_width: int  # 2 for 16-bit, 1 for 8-bit
    samples: List[int]  # Interleaved integer samples (-32768 to 32767 for 16-bit)

    @property
    def duration_seconds(self) -> float:
        total_frames = len(self.samples) // self.channels if self.channels else 0
        return total_frames / self.sample_rate if self.sample_rate else 0.0

    def to_wav_bytes(self) -> bytes:
        """Encode audio buffer to standard RIFF/WAVE PCM binary bytes."""
        bio = io.BytesIO()
        with wave.open(bio, "wb") as wf:
            wf.setnchannels(self.channels)
            wf.setsampwidth(self.sample_width)
            wf.setframerate(self.sample_rate)

            # Pack samples
            if self.sample_width == 2:
                # 16-bit signed little-endian
                clamped = [max(-32768, min(32767, int(s))) for s in self.samples]
                raw = struct.pack(f"<{len(clamped)}h", *clamped)
            elif self.sample_width == 1:
                # 8-bit unsigned
                clamped = [max(0, min(255, int(s))) for s in self.samples]
                raw = struct.pack(f"<{len(clamped)}B", *clamped)
            else:
                raise ValueError(f"Unsupported sample width: {self.sample_width}")

            wf.writeframes(raw)
        return bio.getvalue()

    @classmethod
    def from_wav_bytes(cls, data: bytes) -> AudioBuffer:
        """Decode standard RIFF/WAVE PCM bytes into AudioBuffer."""
        bio = io.BytesIO(data)
        with wave.open(bio, "rb") as wf:
            channels = wf.getnchannels()
            sample_width = wf.getsampwidth()
            sample_rate = wf.getframerate()
            num_frames = wf.getnframes()
            raw_frames = wf.readframes(num_frames)

            total_samples = num_frames * channels
            if sample_width == 2:
                samples = list(struct.unpack(f"<{total_samples}h", raw_frames))
            elif sample_width == 1:
                samples = list(struct.unpack(f"<{total_samples}B", raw_frames))
            else:
                raise ValueError(f"Unsupported sample width: {sample_width} (only 8/16-bit supported)")

            return cls(
                sample_rate=sample_rate,
                channels=channels,
                sample_width=sample_width,
                samples=samples
            )

    @classmethod
    def generate_sine_tone(
        cls,
        frequency: float = 440.0,
        duration: float = 2.0,
        sample_rate: int = 44100,
        amplitude: float = 0.5,
        channels: int = 1
    ) -> AudioBuffer:
        """Generate a pure sinusoidal acoustic tone."""
        total_frames = int(sample_rate * duration)
        samples: List[int] = []
        max_amp = 32767 * max(0.0, min(1.0, amplitude))

        for i in range(total_frames):
            t = i / sample_rate
            val = int(max_amp * math.sin(2.0 * math.pi * frequency * t))
            for _ in range(channels):
                samples.append(val)

        return cls(
            sample_rate=sample_rate,
            channels=channels,
            sample_width=2,
            samples=samples
        )

    @classmethod
    def generate_carrier_chord(
        cls,
        frequencies: List[float],
        duration: float = 2.0,
        sample_rate: int = 44100,
        amplitude: float = 0.6
    ) -> AudioBuffer:
        """Synthesize a rich harmonic acoustic carrier with multiple frequency components."""
        total_frames = int(sample_rate * duration)
        samples: List[int] = []
        scale = (32767 * amplitude) / max(1, len(frequencies))

        for i in range(total_frames):
            t = i / sample_rate
            sample_sum = sum(math.sin(2.0 * math.pi * f * t) for f in frequencies)
            val = int(scale * sample_sum)
            samples.append(val)

        return cls(
            sample_rate=sample_rate,
            channels=1,
            sample_width=2,
            samples=samples
        )
