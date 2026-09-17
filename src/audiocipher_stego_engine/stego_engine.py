"""
Audio Steganography Engine: LSB PCM Injection & Ultrasonic Acoustic Watermarking.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import math
import struct
import zlib
from typing import Optional, Tuple

from audiocipher_stego_engine.wav_codec import AudioBuffer

STEGO_MAGIC = b"STEG"


class StegoEngine:
    """Acoustic Steganography and LSB Injection Subsystem."""

    @staticmethod
    def embed_lsb(audio: AudioBuffer, payload: bytes) -> AudioBuffer:
        """
        Embed binary payload into the least significant bits of 16-bit PCM audio samples.
        Header: 4-byte Magic (b"STEG") + 4-byte Payload Length + 4-byte CRC32 + Payload.
        """
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = STEGO_MAGIC + struct.pack("<II", len(payload), crc)
        full_payload = header + payload

        total_bits = len(full_payload) * 8
        if len(audio.samples) < total_bits:
            raise ValueError(
                f"Audio carrier too short: requires at least {total_bits} samples for payload, "
                f"but carrier only has {len(audio.samples)} samples ({audio.duration_seconds:.2f}s)."
            )

        new_samples = list(audio.samples)
        bit_idx = 0

        for byte_val in full_payload:
            for b in range(8):
                bit = (byte_val >> (7 - b)) & 1
                sample = new_samples[bit_idx]
                # Replace LSB with payload bit
                new_samples[bit_idx] = (sample & ~1) | bit
                bit_idx += 1

        return AudioBuffer(
            sample_rate=audio.sample_rate,
            channels=audio.channels,
            sample_width=audio.sample_width,
            samples=new_samples
        )

    @staticmethod
    def extract_lsb(audio: AudioBuffer) -> bytes:
        """
        Extract hidden LSB payload from audio carrier.
        Validates magic signature and CRC32 checksum.
        """
        if len(audio.samples) < 96:  # 12 bytes * 8 bits = 96 bits for header
            raise ValueError("Audio carrier too short to contain steganographic header.")

        # Extract first 12 bytes (header)
        header_bytes = bytearray(12)
        sample_idx = 0

        for byte_i in range(12):
            val = 0
            for b in range(8):
                bit = audio.samples[sample_idx] & 1
                val = (val << 1) | bit
                sample_idx += 1
            header_bytes[byte_i] = val

        if header_bytes[:4] != STEGO_MAGIC:
            raise ValueError("No hidden steganographic payload found in audio carrier (Magic mismatch).")

        payload_len, expected_crc = struct.unpack("<II", header_bytes[4:12])

        total_samples_needed = (12 + payload_len) * 8
        if len(audio.samples) < total_samples_needed:
            raise ValueError(f"Corrupted steganography carrier: header requests {payload_len} bytes but audio is truncated.")

        payload = bytearray(payload_len)
        for byte_i in range(payload_len):
            val = 0
            for b in range(8):
                bit = audio.samples[sample_idx] & 1
                val = (val << 1) | bit
                sample_idx += 1
            payload[byte_i] = val

        # Verify CRC32
        actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError("Steganography CRC32 integrity check failed: payload was modified or corrupted.")

        return bytes(payload)

    @staticmethod
    def embed_ultrasonic_watermark(
        audio: AudioBuffer,
        watermark_text: str,
        base_freq: float = 18500.0,
        bit_duration: float = 0.05
    ) -> AudioBuffer:
        """
        Embed text watermark into high-frequency ultrasonic spectrum (18.5kHz / 19.5kHz FSK).
        """
        wm_bytes = watermark_text.encode("utf-8")
        bits = []
        for byte_val in wm_bytes:
            for b in range(8):
                bits.append((byte_val >> (7 - b)) & 1)

        samples_per_bit = int(audio.sample_rate * bit_duration)
        total_samples_needed = len(bits) * samples_per_bit

        new_samples = list(audio.samples)
        while len(new_samples) < total_samples_needed:
            new_samples.extend([0] * (total_samples_needed - len(new_samples)))

        freq_0 = base_freq
        freq_1 = base_freq + 1000.0  # 19.5 kHz for bit 1

        watermark_amp = 1500  # Low amplitude ultrasonic overlay

        for bit_i, bit in enumerate(bits):
            target_freq = freq_1 if bit == 1 else freq_0
            start_s = bit_i * samples_per_bit
            for s in range(samples_per_bit):
                t = (start_s + s) / audio.sample_rate
                overlay = int(watermark_amp * math.sin(2.0 * math.pi * target_freq * t))
                idx = start_s + s
                if idx < len(new_samples):
                    new_samples[idx] = max(-32768, min(32767, new_samples[idx] + overlay))

        return AudioBuffer(
            sample_rate=audio.sample_rate,
            channels=audio.channels,
            sample_width=audio.sample_width,
            samples=new_samples
        )
