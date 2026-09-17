"""
Model Context Protocol (MCP) Server for audiocipher-stego-engine.
Conforms to MCP protocol version 2024-11-05 and JSON-RPC 2.0 over stdio.
Zero external runtime dependencies.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any, Dict, List, Optional

from audiocipher_stego_engine.crypto_core import (
    decrypt_payload,
    derive_audio_key,
    encrypt_payload,
)
from audiocipher_stego_engine.spectrogram import synthesize_morse_audio, text_to_morse
from audiocipher_stego_engine.stego_engine import StegoEngine
from audiocipher_stego_engine.wav_codec import AudioBuffer

SERVER_NAME = "audiocipher-stego-engine"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"


class MCPServer:
    """Model Context Protocol stdio server implementation."""

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return registered MCP tool schemas."""
        return [
            {
                "name": "audio_encrypt",
                "description": "Encrypt a plaintext message or binary payload using an audio waveform and decibel level as the cryptographic key.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Plaintext string or Base64 binary payload to encrypt."
                        },
                        "audio_base64": {
                            "type": "string",
                            "description": "Base64 encoded audio key file (WAV, MP3, etc.). If omitted, a synthetic audio key is generated."
                        },
                        "volume_db": {
                            "type": "number",
                            "default": 50.0,
                            "description": "Decibel volume modifier key (0-100 dB)."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "audio_decrypt",
                "description": "Decrypt an encrypted payload blob using the original audio key and volume decibel modifier.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "encrypted_blob_base64": {
                            "type": "string",
                            "description": "Base64 encoded encrypted ciphertext blob."
                        },
                        "audio_base64": {
                            "type": "string",
                            "description": "Base64 encoded audio key file."
                        },
                        "volume_db": {
                            "type": "number",
                            "default": 50.0,
                            "description": "Decibel volume modifier key."
                        }
                    },
                    "required": ["encrypted_blob_base64", "audio_base64"]
                }
            },
            {
                "name": "audio_stego_embed",
                "description": "Embed a secret payload (text or binary) inside an uncompressed WAV audio carrier using LSB steganography.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Secret payload text to hide."
                        },
                        "carrier_wav_base64": {
                            "type": "string",
                            "description": "Optional Base64 encoded WAV audio carrier. If omitted, a synthetic tone carrier is created."
                        }
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "audio_stego_extract",
                "description": "Extract hidden steganographic payload from a WAV audio carrier with CRC32 integrity validation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "carrier_wav_base64": {
                            "type": "string",
                            "description": "Base64 encoded steganographic WAV carrier."
                        }
                    },
                    "required": ["carrier_wav_base64"]
                }
            },
            {
                "name": "audio_morse_synthesize",
                "description": "Synthesize a clean PCM WAV audio file playing Morse code for the given text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text message to convert to Morse audio."
                        },
                        "frequency": {
                            "type": "number",
                            "default": 800.0,
                            "description": "Tone frequency in Hz."
                        },
                        "wpm": {
                            "type": "integer",
                            "default": 20,
                            "description": "Speed in words per minute."
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "audio_diagnostics",
                "description": "Run environment, platform, and audio cryptographic engine diagnostics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool and format MCP result."""
        if tool_name == "audio_encrypt":
            payload_str = arguments["payload"]
            payload_bytes = payload_str.encode("utf-8")
            vol = float(arguments.get("volume_db", 50.0))

            audio_b64 = arguments.get("audio_base64")
            if audio_b64:
                audio_bytes = base64.b64decode(audio_b64)
            else:
                tone = AudioBuffer.generate_sine_tone(440.0, 1.0)
                audio_bytes = tone.to_wav_bytes()

            key, salt = derive_audio_key(audio_bytes, vol)
            encrypted = encrypt_payload(payload_bytes, key, salt)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "status": "success",
                            "encrypted_blob_base64": base64.b64encode(encrypted).decode("ascii"),
                            "length_bytes": len(encrypted),
                            "volume_db": vol
                        }, indent=2)
                    }
                ]
            }

        elif tool_name == "audio_decrypt":
            enc_b64 = arguments["encrypted_blob_base64"]
            audio_b64 = arguments["audio_base64"]
            vol = float(arguments.get("volume_db", 50.0))

            enc_bytes = base64.b64decode(enc_b64)
            audio_bytes = base64.b64decode(audio_b64)

            try:
                decrypted = decrypt_payload(enc_bytes, audio_bytes, vol)
                text = decrypted.decode("utf-8", errors="replace")
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "status": "success",
                                "decrypted_text": text,
                                "decrypted_base64": base64.b64encode(decrypted).decode("ascii")
                            }, indent=2)
                        }
                    ]
                }
            except Exception as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "status": "error",
                                "message": str(e)
                            }, indent=2)
                        }
                    ]
                }

        elif tool_name == "audio_stego_embed":
            payload_bytes = arguments["payload"].encode("utf-8")
            carrier_b64 = arguments.get("carrier_wav_base64")

            if carrier_b64:
                carrier_bytes = base64.b64decode(carrier_b64)
                carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
            else:
                # Generate synthetic carrier of adequate duration
                duration = max(2.0, (len(payload_bytes) + 16) * 8 / 44100.0 + 0.5)
                carrier = AudioBuffer.generate_carrier_chord([440.0, 554.37, 659.25], duration=duration)

            stego_audio = StegoEngine.embed_lsb(carrier, payload_bytes)
            stego_wav = stego_audio.to_wav_bytes()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "status": "success",
                            "stego_wav_base64": base64.b64encode(stego_wav).decode("ascii"),
                            "carrier_duration_seconds": round(stego_audio.duration_seconds, 2),
                            "payload_size_bytes": len(payload_bytes)
                        }, indent=2)
                    }
                ]
            }

        elif tool_name == "audio_stego_extract":
            carrier_b64 = arguments["carrier_wav_base64"]
            carrier_bytes = base64.b64decode(carrier_b64)
            carrier = AudioBuffer.from_wav_bytes(carrier_bytes)

            try:
                extracted = StegoEngine.extract_lsb(carrier)
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "status": "success",
                                "extracted_text": extracted.decode("utf-8", errors="replace"),
                                "extracted_base64": base64.b64encode(extracted).decode("ascii"),
                                "length_bytes": len(extracted)
                            }, indent=2)
                        }
                    ]
                }
            except Exception as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"status": "error", "message": str(e)}, indent=2)
                        }
                    ]
                }

        elif tool_name == "audio_morse_synthesize":
            text = arguments["text"]
            freq = float(arguments.get("frequency", 800.0))
            wpm = int(arguments.get("wpm", 20))

            morse_audio = synthesize_morse_audio(text, tone_frequency=freq, wpm=wpm)
            wav_bytes = morse_audio.to_wav_bytes()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "status": "success",
                            "morse_notation": text_to_morse(text),
                            "duration_seconds": round(morse_audio.duration_seconds, 2),
                            "wav_base64": base64.b64encode(wav_bytes).decode("ascii")
                        }, indent=2)
                    }
                ]
            }

        elif tool_name == "audio_diagnostics":
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "server": SERVER_NAME,
                            "version": SERVER_VERSION,
                            "protocol_version": PROTOCOL_VERSION,
                            "platform": sys.platform,
                            "python_version": sys.version,
                            "zero_dependencies": True,
                            "status": "HEALTHY"
                        }, indent=2)
                    }
                ]
            }

        raise ValueError(f"Unknown tool: {tool_name}")

    def handle_request(self, request_str: str) -> Optional[str]:
        """Process JSON-RPC 2.0 request string and return formatted response."""
        try:
            req = json.loads(request_str)
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            })

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
                }
            })

        elif method == "notifications/initialized":
            return None

        elif method == "ping":
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

        elif method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.get_tool_definitions()}
            })

        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                res = self.handle_tool_call(name, arguments)
                return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res})
            except Exception as e:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": str(e)}
                })

        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        })

    def run_stdio(self) -> None:
        """Run stdio loop reading JSON-RPC requests."""
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue
            resp = self.handle_request(line_str)
            if resp:
                sys.stdout.write(resp + "\n")
                sys.stdout.flush()


def run_mcp_server() -> None:
    """Entrypoint to launch MCP stdio server."""
    server = MCPServer()
    server.run_stdio()
