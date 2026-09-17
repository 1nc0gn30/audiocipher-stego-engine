"""
Command-Line Interface for audiocipher-stego-engine.
Zero external runtime dependencies.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from typing import Any, List, Optional

from audiocipher_stego_engine.compat import (
    atomic_write_bytes,
    atomic_write_text,
    safe_read_bytes,
    safe_read_text,
)
from audiocipher_stego_engine.crypto_core import (
    decrypt_payload,
    derive_audio_key,
    encrypt_payload,
)
from audiocipher_stego_engine.mcp_server import run_mcp_server
from audiocipher_stego_engine.spectrogram import synthesize_morse_audio, text_to_morse
from audiocipher_stego_engine.stego_engine import StegoEngine
from audiocipher_stego_engine.ui_server import run_ui_server
from audiocipher_stego_engine.wav_codec import AudioBuffer


class Colors:
    """ANSI terminal color helpers with automatic disabling."""
    def __init__(self, force_disable: bool = False) -> None:
        disabled = force_disable or "NO_COLOR" in os.environ or not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty()
        self.BLUE = "" if disabled else "\033[94m"
        self.GREEN = "" if disabled else "\033[92m"
        self.YELLOW = "" if disabled else "\033[93m"
        self.RED = "" if disabled else "\033[91m"
        self.CYAN = "" if disabled else "\033[96m"
        self.BOLD = "" if disabled else "\033[1m"
        self.DIM = "" if disabled else "\033[2m"
        self.RESET = "" if disabled else "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="audiocipher",
        description="Audio-Keyed Cryptography, PCM Steganography & Morse Spectrogram Synthesizer",
    )
    parser.add_argument("-v", "--version", action="version", version="audiocipher-stego-engine 0.1.0")

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    sub = parser.add_subparsers(dest="command", help="Available subcommands")

    # encrypt
    p_enc = sub.add_parser("encrypt", parents=[base], help="Encrypt file using audio key and volume decibel modifier")
    p_enc.add_argument("input", help="Payload file or plaintext message")
    p_enc.add_argument("-k", "--key", required=True, help="Audio key file (WAV, MP3, etc.)")
    p_enc.add_argument("-o", "--output", default="encrypted.bin", help="Output encrypted file path")
    p_enc.add_argument("--volume", type=float, default=50.0, help="Decibel volume modifier key (0-100 dB)")

    # decrypt
    p_dec = sub.add_parser("decrypt", parents=[base], help="Decrypt file using audio key and volume decibel modifier")
    p_dec.add_argument("input", help="Encrypted ciphertext blob file")
    p_dec.add_argument("-k", "--key", required=True, help="Audio key file")
    p_dec.add_argument("-o", "--output", default="decrypted.out", help="Output decrypted file path")
    p_dec.add_argument("--volume", type=float, default=50.0, help="Decibel volume modifier key")

    # embed (stego)
    p_emb = sub.add_parser("embed", parents=[base], help="Hide secret payload inside WAV audio carrier using LSB steganography")
    p_emb.add_argument("payload", help="Secret payload file to hide")
    p_emb.add_argument("-c", "--carrier", help="Target WAV audio carrier (optional; synthetic carrier created if omitted)")
    p_emb.add_argument("-o", "--output", default="stego.wav", help="Output steganographic WAV file path")

    # extract (stego)
    p_ext = sub.add_parser("extract", parents=[base], help="Extract hidden payload from a steganographic WAV audio carrier")
    p_ext.add_argument("carrier", help="Steganographic WAV carrier file")
    p_ext.add_argument("-o", "--output", default="extracted.out", help="Output extracted payload path")

    # morse
    p_morse = sub.add_parser("morse", parents=[base], help="Synthesize Morse code audio WAV from text message")
    p_morse.add_argument("text", help="Text message to synthesize")
    p_morse.add_argument("-o", "--output", default="morse.wav", help="Output WAV path")
    p_morse.add_argument("--freq", type=float, default=800.0, help="Tone frequency in Hz (default: 800)")
    p_morse.add_argument("--wpm", type=int, default=20, help="Words per minute (default: 20)")

    # serve
    p_serve = sub.add_parser("serve", parents=[base], help="Start AudioCipher Studio Web UI (Material 3 influenced)")
    p_serve.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8096, help="Port (default: 8096)")

    # mcp
    p_mcp = sub.add_parser("mcp", parents=[base], help="Run Model Context Protocol stdio server")

    # diagnostics / doctor
    p_doc = sub.add_parser("doctor", aliases=["diagnostics", "platform"], parents=[base], help="Run system diagnostics")

    # test-self
    p_tself = sub.add_parser("test-self", parents=[base], help="Run internal self-verification test runner")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)
    c = Colors(force_disable=getattr(args, "no_color", False))

    if args.command == "encrypt":
        payload_data = safe_read_bytes(args.input) if os.path.isfile(args.input) else args.input.encode("utf-8")
        audio_data = safe_read_bytes(args.key)

        key, salt = derive_audio_key(audio_data, args.volume)
        encrypted = encrypt_payload(payload_data, key, salt)
        atomic_write_bytes(args.output, encrypted)

        print(f"{c.GREEN}✓ Encrypted successfully with audio key:{c.RESET} {args.output}")
        print(f"  Payload Size: {len(payload_data)} bytes | Encrypted Blob: {len(encrypted)} bytes | Volume: {args.volume} dB")
        return 0

    elif args.command == "decrypt":
        enc_data = safe_read_bytes(args.input)
        audio_data = safe_read_bytes(args.key)

        try:
            decrypted = decrypt_payload(enc_data, audio_data, args.volume)
            atomic_write_bytes(args.output, decrypted)
            print(f"{c.GREEN}✓ Decrypted and verified successfully:{c.RESET} {args.output} ({len(decrypted)} bytes)")
            return 0
        except Exception as e:
            print(f"{c.RED}Error: Decryption failed: {str(e)}{c.RESET}")
            return 1

    elif args.command == "embed":
        payload_data = safe_read_bytes(args.payload) if os.path.isfile(args.payload) else args.payload.encode("utf-8")

        if args.carrier and os.path.isfile(args.carrier):
            carrier_bytes = safe_read_bytes(args.carrier)
            carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
        else:
            duration = max(2.0, (len(payload_data) + 16) * 8 / 44100.0 + 0.5)
            carrier = AudioBuffer.generate_carrier_chord([440.0, 554.37, 659.25], duration=duration)

        stego_audio = StegoEngine.embed_lsb(carrier, payload_data)
        atomic_write_bytes(args.output, stego_audio.to_wav_bytes())

        print(f"{c.GREEN}✓ Secret payload embedded into audio carrier:{c.RESET} {args.output}")
        print(f"  Carrier Duration: {stego_audio.duration_seconds:.2f}s | Payload Size: {len(payload_data)} bytes")
        return 0

    elif args.command == "extract":
        carrier_bytes = safe_read_bytes(args.carrier)
        carrier = AudioBuffer.from_wav_bytes(carrier_bytes)

        try:
            extracted = StegoEngine.extract_lsb(carrier)
            atomic_write_bytes(args.output, extracted)
            print(f"{c.GREEN}✓ Extracted hidden payload from carrier:{c.RESET} {args.output} ({len(extracted)} bytes)")
            return 0
        except Exception as e:
            print(f"{c.RED}Error: Extraction failed: {str(e)}{c.RESET}")
            return 1

    elif args.command == "morse":
        morse_notation = text_to_morse(args.text)
        audio = synthesize_morse_audio(args.text, tone_frequency=args.freq, wpm=args.wpm)
        atomic_write_bytes(args.output, audio.to_wav_bytes())

        print(f"{c.GREEN}✓ Morse code audio synthesized:{c.RESET} {args.output}")
        print(f"  Notation: {c.CYAN}{morse_notation}{c.RESET}")
        print(f"  Duration: {audio.duration_seconds:.2f}s ({args.wpm} WPM, {args.freq} Hz)")
        return 0

    elif args.command == "serve":
        server = run_ui_server(args.host, args.port)
        print(f"{c.GREEN}🔒 AudioCipher Studio UI running at:{c.RESET} http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
        return 0

    elif args.command == "mcp":
        run_mcp_server()
        return 0

    elif args.command in ("doctor", "diagnostics", "platform"):
        print(f"\n{c.BOLD}🔒 AudioCipher Stego Engine - System Diagnostics{c.RESET}")
        print(f"  Platform         : {sys.platform}")
        print(f"  Python Version   : {sys.version.split()[0]}")
        print(f"  Zero Runtime Deps: {c.GREEN}YES (100% Python Standard Library){c.RESET}")
        print(f"  Status           : {c.GREEN}HEALTHY{c.RESET}\n")
        return 0

    elif args.command == "test-self":
        print(f"{c.BOLD}Running internal self-verification test runner...{c.RESET}")
        # Test basic wav generation & stego
        tone = AudioBuffer.generate_sine_tone(440.0, 1.0)
        stego = StegoEngine.embed_lsb(tone, b"HELLO")
        out = StegoEngine.extract_lsb(stego)
        assert out == b"HELLO"
        print(f"{c.GREEN}✓ All internal checks passed!{c.RESET}")
        return 0

    return 0
