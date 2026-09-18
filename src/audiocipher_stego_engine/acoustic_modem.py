"""
Pure Python Binary Frequency Shift Keying (BFSK) Acoustic Modem & Demodulator.
Supports audible acoustic transmission and ultrasonic covert air-gap data transfer.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from audiocipher_stego_engine.wav_codec import AudioBuffer

# Frame synchronizer constants
PREAMBLE_BYTE = 0x55       # Alternating 01010101 for clock/energy stabilization
FRAME_DELIMITER = 0x7E     # HDLC / PPP standard frame sync flag (01111110)


def crc16_ccitt(data: bytes) -> int:
    """Calculate standard CRC-16-CCITT (poly 0x1021, init 0xFFFF)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


@dataclass
class FSKConfig:
    """Configuration for Binary Frequency Shift Keying (BFSK) acoustic modem."""
    baud_rate: int = 300
    mark_freq: float = 1200.0     # Frequency for binary '1' (Hz)
    space_freq: float = 2200.0    # Frequency for binary '0' (Hz)
    sample_rate: int = 44100
    ultrasonic: bool = False
    amplitude: float = 0.5
    preamble_bytes: int = 4
    lead_in_bits: int = 8
    lead_out_bits: int = 8

    def __post_init__(self) -> None:
        if self.ultrasonic:
            # Shift carrier to inaudible ultrasonic acoustic band (>18kHz)
            if self.mark_freq == 1200.0 and self.space_freq == 2200.0:
                self.mark_freq = 18500.0
                self.space_freq = 20000.0

        if self.baud_rate <= 0:
            raise ValueError("baud_rate must be positive")
        if self.sample_rate <= 0:
            raise ValueError("sample_rate must be positive")
        if self.mark_freq <= 0 or self.space_freq <= 0:
            raise ValueError("frequencies must be positive")
        if self.mark_freq >= self.sample_rate / 2 or self.space_freq >= self.sample_rate / 2:
            raise ValueError(f"Frequencies must be strictly below Nyquist limit ({self.sample_rate / 2} Hz)")


def modulate_fsk(payload: Union[str, bytes], config: Optional[FSKConfig] = None) -> AudioBuffer:
    """
    Modulate binary payload into an AudioBuffer using continuous-phase BFSK.
    
    Frames the payload with preamble sync, frame delimiter, 2-byte length header,
    payload bytes, and CRC16-CCITT checksum. Each byte is encoded as a 10-bit UART frame
    (1 start bit '0', 8 data bits LSB-first, 1 stop bit '1').
    """
    if config is None:
        config = FSKConfig()

    data_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    if len(data_bytes) > 65535:
        raise ValueError("Payload exceeds maximum FSK packet size (65535 bytes)")

    # Build raw frame bytes
    length_header = len(data_bytes).to_bytes(2, byteorder="big")
    checksum = crc16_ccitt(length_header + data_bytes).to_bytes(2, byteorder="big")
    preamble = bytes([PREAMBLE_BYTE] * config.preamble_bytes + [FRAME_DELIMITER])
    frame_packet = preamble + length_header + data_bytes + checksum

    # Encode bytes into bitstream (UART 8-N-1 framing)
    bits: List[int] = []
    # Lead-in mark tones
    bits.extend([1] * config.lead_in_bits)

    for b in frame_packet:
        bits.append(0)  # Start bit (space)
        for bit_idx in range(8):
            bits.append((b >> bit_idx) & 1)  # LSB first
        bits.append(1)  # Stop bit (mark)

    # Lead-out mark tones
    bits.extend([1] * config.lead_out_bits)

    # Continuous-phase frequency synthesis
    samples_per_bit = max(1, round(config.sample_rate / config.baud_rate))
    total_samples = len(bits) * samples_per_bit
    samples: List[int] = []

    phase = 0.0
    two_pi = 2.0 * math.pi
    amp_scale = 32767.0 * max(0.01, min(1.0, config.amplitude))

    for bit in bits:
        target_freq = config.mark_freq if bit == 1 else config.space_freq
        phase_step = two_pi * target_freq / config.sample_rate
        for _ in range(samples_per_bit):
            phase = (phase + phase_step) % two_pi
            val = int(amp_scale * math.sin(phase))
            samples.append(val)

    return AudioBuffer(
        sample_rate=config.sample_rate,
        channels=1,
        sample_width=2,
        samples=samples
    )


def _compute_tone_energy(
    samples: List[int],
    start_idx: int,
    spb: int,
    cos_table: List[float],
    sin_table: List[float]
) -> float:
    """Discrete Fourier energy correlation over a bit period."""
    real = 0.0
    imag = 0.0
    end_idx = min(len(samples), start_idx + spb)
    actual_len = end_idx - start_idx

    for i in range(actual_len):
        s = samples[start_idx + i]
        real += s * cos_table[i]
        imag += s * sin_table[i]

    return real * real + imag * imag


def demodulate_fsk(audio: AudioBuffer, config: Optional[FSKConfig] = None) -> Tuple[bytes, Dict[str, Any]]:
    """
    Demodulate an AudioBuffer using discrete matched-filter energy detection.
    
    Recovers the UART bitstream, synchronizes to the frame delimiter, validates
    the CRC16-CCITT checksum, and returns the payload along with transmission telemetry.
    """
    if config is None:
        config = FSKConfig()

    spb = max(1, round(audio.sample_rate / config.baud_rate))
    total_samples = len(audio.samples)
    if total_samples < spb * 20:
        raise ValueError("Audio buffer too short for FSK demodulation")

    # Extract mono channel samples if multichannel
    if audio.channels > 1:
        mono_samples = [audio.samples[i] for i in range(0, len(audio.samples), audio.channels)]
    else:
        mono_samples = audio.samples

    # Precompute correlation tables for mark and space frequencies
    two_pi = 2.0 * math.pi
    mark_step = two_pi * config.mark_freq / audio.sample_rate
    space_step = two_pi * config.space_freq / audio.sample_rate

    mark_cos = [math.cos(mark_step * i) for i in range(spb)]
    mark_sin = [math.sin(mark_step * i) for i in range(spb)]
    space_cos = [math.cos(space_step * i) for i in range(spb)]
    space_sin = [math.sin(space_step * i) for i in range(spb)]

    # Search across candidate phase offsets to lock onto bit clock
    step_size = max(1, spb // 8)
    candidate_offsets = list(range(0, spb, step_size))

    best_payload: Optional[bytes] = None
    best_telemetry: Optional[Dict[str, Any]] = None

    for phase_offset in candidate_offsets:
        # Demodulate bit decisions from this phase offset
        num_bits = (len(mono_samples) - phase_offset) // spb
        if num_bits < 20:
            continue

        raw_bits: List[int] = []
        signal_energies: List[float] = []
        noise_energies: List[float] = []

        for b_idx in range(num_bits):
            s_start = phase_offset + b_idx * spb
            e_mark = _compute_tone_energy(mono_samples, s_start, spb, mark_cos, mark_sin)
            e_space = _compute_tone_energy(mono_samples, s_start, spb, space_cos, space_sin)

            if e_mark >= e_space:
                raw_bits.append(1)
                signal_energies.append(e_mark)
                noise_energies.append(e_space)
            else:
                raw_bits.append(0)
                signal_energies.append(e_space)
                noise_energies.append(e_mark)

        # Parse UART frames from raw bitstream
        # Scan for start delimiter 0x7E
        # A valid byte is [start=0, bit0..bit7, stop=1] (10 bits)
        parsed_bytes: List[Tuple[int, int]] = []  # (byte_val, bit_start_idx)
        i = 0
        while i + 10 <= len(raw_bits):
            if raw_bits[i] == 0 and raw_bits[i + 9] == 1:  # Start=0 and Stop=1
                val = 0
                for b in range(8):
                    val |= (raw_bits[i + 1 + b] << b)
                parsed_bytes.append((val, i))
                i += 10
            else:
                i += 1

        # Locate frame delimiter
        byte_values = [bv[0] for bv in parsed_bytes]
        for d_idx, bv in enumerate(byte_values):
            if bv == FRAME_DELIMITER:
                # Check if we have at least 2 length bytes + 2 crc bytes
                rem = byte_values[d_idx + 1:]
                if len(rem) >= 4:
                    payload_len = (rem[0] << 8) | rem[1]
                    total_expected = 2 + payload_len + 2
                    if len(rem) >= total_expected:
                        extracted_bytes = bytes(rem[2:2 + payload_len])
                        header_bytes = bytes(rem[0:2])
                        received_crc = (rem[2 + payload_len] << 8) | rem[3 + payload_len]

                        expected_crc = crc16_ccitt(header_bytes + extracted_bytes)
                        if received_crc == expected_crc:
                            # Frame verified successfully!
                            avg_sig = sum(signal_energies) / max(1, len(signal_energies))
                            avg_noise = sum(noise_energies) / max(1, len(noise_energies))
                            snr = 10.0 * math.log10(max(1.0, avg_sig) / max(1e-9, avg_noise))

                            telemetry = {
                                "baud_rate": config.baud_rate,
                                "mark_frequency_hz": config.mark_freq,
                                "space_frequency_hz": config.space_freq,
                                "ultrasonic": config.ultrasonic,
                                "samples_per_bit": spb,
                                "payload_length_bytes": payload_len,
                                "crc_valid": True,
                                "crc16_hex": f"0x{received_crc:04X}",
                                "estimated_snr_db": round(snr, 2),
                                "bit_clock_offset_samples": phase_offset,
                                "raw_bits_processed": len(raw_bits)
                            }
                            return extracted_bytes, telemetry

    raise ValueError("Demodulation failed: No valid BFSK frame with matching CRC-16 found in audio buffer")
