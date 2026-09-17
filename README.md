# 🔒 AudioCipher Stego Engine

[![CI](https://github.com/1nc0gn30/audiocipher-stego-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/1nc0gn30/audiocipher-stego-engine/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20runtime-success.svg)](https://github.com/1nc0gn30/audiocipher-stego-engine)
[![MCP Server](https://img.shields.io/badge/MCP-FastMCP%202024--11--05-blueviolet.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Audio-Keyed Authenticated Cryptography, PCM Audio Steganography & Morse Spectrogram Synthesizer with Material 3 Web UI, Multi-OS CLI, FastMCP stdio server, and zero external runtime dependencies.**

---

## ✨ Features

- 🔒 **Audio-Keyed Authenticated Encryption**: Derives 256-bit cryptographic keys using PBKDF2-HMAC-SHA256 from raw acoustic waveforms and precise decibel/volume modifiers. Encrypts payloads using authenticated keystream cipher + HMAC-SHA256 integrity tags.
- 🛡️ **PCM Audio Steganography**: Embeds secret files and strings into the least significant bits (LSB) of uncompressed 16-bit PCM WAV audio carriers with CRC32 integrity checksum validation and magic header verification.
- 📻 **Acoustic Morse Code & Spectrogram Synthesizer**: Converts text messages into audible Morse code tone sequences and multi-frequency spectrogram visual patterns at configurable speed (WPM) and frequency (Hz).
- 🎨 **Google Material 3 Light Mode Web UI**: Real-time Web Audio API oscilloscope visualizer, interactive audio cipher ritual runner, drag-and-drop stego carrier injector, and 1-click WAV export.
- ⚡ **Zero Third-Party Runtime Dependencies**: 100% Python Standard Library runtime (`wave`, `struct`, `hashlib`, `hmac`, `math`, `zlib`, `http.server`, `urllib`, `argparse`).
- 🤖 **FastMCP Server Protocol**: Full Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for Claude Desktop, Cursor, Cline, and autonomous AI agents.

---

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/1nc0gn30/audiocipher-stego-engine.git
cd audiocipher-stego-engine

# Install in editable mode
pip install -e .
```

---

## 💻 CLI Usage

```bash
# Encrypt message using an audio file as key with 50 dB modifier
audiocipher encrypt "Sovereign Agent Directive #757" -k secret_track.wav --volume 50.0 -o encrypted.bin

# Decrypt payload using the exact audio key and volume level
audiocipher decrypt encrypted.bin -k secret_track.wav --volume 50.0 -o decrypted.txt

# Embed secret payload into a WAV audio carrier via LSB steganography
audiocipher embed secret_notes.txt -c carrier.wav -o stego.wav

# Extract hidden payload from steganographic WAV carrier
audiocipher extract stego.wav -o recovered_secret.txt

# Synthesize Morse code audio WAV from plaintext message
audiocipher morse "SOS SOVEREIGN AGENT 757" --freq 800 --wpm 20 -o morse.wav

# Launch Google Material 3 AudioCipher Studio Web UI
audiocipher serve --port 8096

# Start FastMCP stdio server for LLM agents
audiocipher mcp

# Run system diagnostics
audiocipher doctor
```

---

## 🤖 Model Context Protocol (MCP) Setup

Add `audiocipher-stego-engine` to your Claude Desktop or Cursor configuration:

```json
{
  "mcpServers": {
    "audiocipher": {
      "command": "python3",
      "args": ["-m", "audiocipher_stego_engine", "mcp"]
    }
  }
}
```

### Registered MCP Tools:
- `audio_encrypt`: Encrypt payload data using audio file bytes and decibel modifier.
- `audio_decrypt`: Decrypt payload data using audio file bytes and decibel modifier.
- `audio_stego_embed`: Hide payload inside a WAV carrier using LSB steganography.
- `audio_stego_extract`: Extract hidden payload from a WAV carrier.
- `audio_morse_synthesize`: Generate a synthesized Morse code WAV audio buffer from plaintext.
- `audio_diagnostics`: Platform and toolchain health check.

---

## 🧪 Running Tests

```bash
pytest -v
```

---

## 📜 License

MIT License © 2026 1nc0gn30
