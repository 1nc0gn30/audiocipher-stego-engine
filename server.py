#!/usr/bin/env python3
"""
AudioCipher Stego Engine - Autonomous Standalone Web Workstation Server
Port :8096 | Zero External Runtime Dependencies
Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform
"""

import argparse
import json
import os
import sys

# Ensure src/ is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(SCRIPT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from audiocipher_stego_engine.ui_server import run_ui_server


def main():
    parser = argparse.ArgumentParser(description="AudioCipher Steganography & Acoustic Cryptography Workstation")
    parser.add_argument("--port", type=int, default=8096, help="Port to bind (default: 8096)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--status", action="store_true", help="Print daemon status and exit")
    parser.add_argument("--json", action="store_true", help="Output status as JSON")
    args = parser.parse_args()

    if args.status or args.json:
        payload = {
            "service": "audiocipher-stego-engine",
            "version": "2.5.0",
            "category": "Security & Audio",
            "port": args.port,
            "status": "READY",
            "free_open_access": True,
            "endpoints": [
                "/health",
                "/api/health",
                "/api/diagnostics",
                "/api/encrypt",
                "/api/decrypt",
                "/api/stego/embed",
                "/api/stego/extract",
                "/api/morse",
                "/api/dtmf/synthesize",
                "/api/dtmf/decode",
                "/api/steganalysis",
                "/api/fsk-modulate",
                "/api/fsk-demodulate"
            ]
        }
        print(json.dumps(payload, indent=2))
        return

    server = run_ui_server(host=args.host, port=args.port)
    print(f"✦ Starting AudioCipher Stego Engine on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AudioCipher Stego Engine...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
