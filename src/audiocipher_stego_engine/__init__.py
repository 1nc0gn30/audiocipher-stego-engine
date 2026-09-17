"""
audiocipher-stego-engine: Audio-Keyed Cryptography, PCM Steganography & Morse Spectrogram Synthesizer.
Zero external runtime dependencies.
"""

from __future__ import annotations

from audiocipher_stego_engine.crypto_core import (
    decrypt_payload,
    derive_audio_key,
    encrypt_payload,
)
from audiocipher_stego_engine.mcp_server import MCPServer, run_mcp_server
from audiocipher_stego_engine.spectrogram import (
    decode_dtmf_audio,
    synthesize_dtmf_audio,
    synthesize_morse_audio,
    synthesize_spectrogram_watermark,
    text_to_morse,
)
from audiocipher_stego_engine.steganalysis import (
    AudioSteganalysisReport,
    analyze_audio_steganography,
)
from audiocipher_stego_engine.stego_engine import StegoEngine
from audiocipher_stego_engine.wav_codec import AudioBuffer

__version__ = "0.1.0"
__author__ = "1nc0gn30"

__all__ = [
    "AudioBuffer",
    "derive_audio_key",
    "encrypt_payload",
    "decrypt_payload",
    "StegoEngine",
    "text_to_morse",
    "synthesize_morse_audio",
    "synthesize_spectrogram_watermark",
    "synthesize_dtmf_audio",
    "decode_dtmf_audio",
    "MCPServer",
    "run_mcp_server",
    "AudioSteganalysisReport",
    "analyze_audio_steganography",
]

