"""
Model Context Protocol (MCP) Server for audiocipher-stego-engine.
Conforms to MCP protocol version 2024-11-05 and JSON-RPC 2.0 over stdio.
Zero external runtime dependencies.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import sys
from typing import Any, Dict, List, Optional

from audiocipher_stego_engine.acoustic_modem import (
    FSKConfig,
    demodulate_fsk,
    modulate_fsk,
)
from audiocipher_stego_engine.crypto_core import (
    PBKDF2_ITERATIONS_V2,
    decrypt_payload,
    derive_audio_key,
    encrypt_payload,
)
from audiocipher_stego_engine.spectrogram import synthesize_morse_audio, text_to_morse
from audiocipher_stego_engine.stego_engine import StegoEngine
from audiocipher_stego_engine.wav_codec import AudioBuffer

SERVER_NAME = "audiocipher-stego-engine"
SERVER_VERSION = "2.6.0"
PROTOCOL_VERSION = "2024-11-05"


class InvalidParamsError(ValueError):
    """Raised when JSON-RPC tool arguments fail schema/type validation (-32602)."""


def _req_str(args: Dict[str, Any], key: str) -> str:
    if key not in args or args[key] is None:
        raise InvalidParamsError(f"Missing required parameter: '{key}'")
    val = args[key]
    if not isinstance(val, str):
        raise InvalidParamsError(f"Parameter '{key}' must be a string")
    return val


def _req_b64(args: Dict[str, Any], key: str) -> bytes:
    raw = _req_str(args, key)
    cleaned = "".join(raw.split())
    if not cleaned:
        raise InvalidParamsError(f"Parameter '{key}' must be non-empty base64")
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidParamsError(f"Parameter '{key}' contains invalid base64: {exc}") from exc


def _opt_float(args: Dict[str, Any], key: str, default: float) -> float:
    if key not in args or args[key] is None:
        return default
    val = args[key]
    if isinstance(val, bool):
        raise InvalidParamsError(f"Parameter '{key}' must be numeric")
    try:
        num = float(val)
    except (TypeError, ValueError) as exc:
        raise InvalidParamsError(f"Parameter '{key}' must be numeric") from exc
    if not math.isfinite(num):
        raise InvalidParamsError(f"Parameter '{key}' must be finite")
    return num


def _opt_int(args: Dict[str, Any], key: str, default: int) -> int:
    if key not in args or args[key] is None:
        return default
    val = args[key]
    if isinstance(val, bool):
        raise InvalidParamsError(f"Parameter '{key}' must be an integer")
    try:
        num = int(val)
    except (TypeError, ValueError) as exc:
        raise InvalidParamsError(f"Parameter '{key}' must be an integer") from exc
    return num


class MCPServer:
    """Model Context Protocol stdio server implementation."""

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return registered MCP tool schemas (9 tools)."""
        return [
            {
                "name": "audio_encrypt",
                "description": "Encrypt a plaintext message or binary payload using an audio waveform and decibel level as the cryptographic key (v2 key-separated PBKDF2-HMAC-SHA256).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Plaintext string or Base64 binary payload to encrypt.",
                        },
                        "audio_base64": {
                            "type": "string",
                            "description": "Base64 encoded audio key file (16-bit PCM WAV). If omitted, a synthetic audio key is generated.",
                        },
                        "volume_db": {
                            "type": "number",
                            "default": 50.0,
                            "description": "Decibel volume modifier key (0-100 dB).",
                        },
                    },
                    "required": ["payload"],
                },
            },
            {
                "name": "audio_decrypt",
                "description": "Decrypt an encrypted payload blob using the original audio key and volume decibel modifier.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "encrypted_blob_base64": {
                            "type": "string",
                            "description": "Base64 encoded encrypted ciphertext blob.",
                        },
                        "audio_base64": {
                            "type": "string",
                            "description": "Base64 encoded audio key file.",
                        },
                        "volume_db": {
                            "type": "number",
                            "default": 50.0,
                            "description": "Decibel volume modifier key.",
                        },
                    },
                    "required": ["encrypted_blob_base64", "audio_base64"],
                },
            },
            {
                "name": "audio_stego_embed",
                "description": "Embed a secret payload (text or binary) inside an uncompressed 16-bit PCM WAV audio carrier using LSB steganography with STEG header and CRC-32.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Secret payload text to hide.",
                        },
                        "carrier_wav_base64": {
                            "type": "string",
                            "description": "Optional Base64 encoded WAV audio carrier. If omitted, a synthetic tone carrier is created.",
                        },
                    },
                    "required": ["payload"],
                },
            },
            {
                "name": "audio_stego_extract",
                "description": "Extract hidden steganographic payload from a 16-bit PCM WAV audio carrier with CRC32 integrity validation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "carrier_wav_base64": {
                            "type": "string",
                            "description": "Base64 encoded steganographic WAV carrier.",
                        }
                    },
                    "required": ["carrier_wav_base64"],
                },
            },
            {
                "name": "audio_morse_synthesize",
                "description": "Synthesize a clean 16-bit PCM WAV audio file playing ITU Morse code for the given text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text message to convert to Morse audio.",
                        },
                        "frequency": {
                            "type": "number",
                            "default": 800.0,
                            "description": "Tone frequency in Hz.",
                        },
                        "wpm": {
                            "type": "integer",
                            "default": 20,
                            "description": "Speed in words per minute.",
                        },
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "audio_diagnostics",
                "description": "Run environment, platform, and audio cryptographic engine diagnostics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "audio_steganalysis",
                "description": "Perform forensic statistical steganalysis on a 16-bit PCM WAV audio carrier to detect LSB tampering, PoV equalization anomalies, and ultrasonic covert channels.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "carrier_wav_base64": {
                            "type": "string",
                            "description": "Base64 encoded WAV audio file to audit.",
                        }
                    },
                    "required": ["carrier_wav_base64"],
                },
            },
            {
                "name": "audio_modulate_fsk",
                "description": "Modulate data payload into an acoustic BFSK waveform with 0x55/0x7E framing and CRC-16 for transmission over sound (audible or ultrasonic).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Data payload text to transmit over acoustic modem.",
                        },
                        "baud_rate": {
                            "type": "integer",
                            "default": 300,
                            "description": "Transmission baud rate (e.g. 300 or 600).",
                        },
                        "ultrasonic": {
                            "type": "boolean",
                            "default": False,
                            "description": "Use inaudible ultrasonic carrier frequencies (>18kHz) for covert air-gap transfer.",
                        },
                        "mark_freq": {
                            "type": "number",
                            "description": "Optional custom mark frequency (Hz) for binary 1.",
                        },
                        "space_freq": {
                            "type": "number",
                            "description": "Optional custom space frequency (Hz) for binary 0.",
                        },
                    },
                    "required": ["payload"],
                },
            },
            {
                "name": "audio_demodulate_fsk",
                "description": "Demodulate an acoustic BFSK audio recording using matched-filter energy detection to recover the payload and verify CRC-16.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "audio_wav_base64": {
                            "type": "string",
                            "description": "Base64 encoded WAV audio file containing BFSK transmission.",
                        },
                        "baud_rate": {
                            "type": "integer",
                            "default": 300,
                            "description": "Transmission baud rate (e.g. 300 or 600).",
                        },
                        "ultrasonic": {
                            "type": "boolean",
                            "default": False,
                            "description": "Whether transmission used ultrasonic carrier frequencies.",
                        },
                        "mark_freq": {
                            "type": "number",
                            "description": "Optional custom mark frequency (Hz).",
                        },
                        "space_freq": {
                            "type": "number",
                            "description": "Optional custom space frequency (Hz).",
                        },
                    },
                    "required": ["audio_wav_base64"],
                },
            },
        ]

    def _validate_tool_arguments(self, tool_name: str, arguments: Any) -> Dict[str, Any]:
        if not isinstance(arguments, dict):
            raise InvalidParamsError("Tool 'arguments' must be a JSON object")
        defs = {d["name"]: d for d in self.get_tool_definitions()}
        if tool_name not in defs:
            raise InvalidParamsError(f"Unknown tool: {tool_name}")
        required = defs[tool_name].get("inputSchema", {}).get("required", [])
        missing = [k for k in required if k not in arguments or arguments[k] is None]
        if missing:
            raise InvalidParamsError(f"Missing required parameter(s) for {tool_name}: {', '.join(missing)}")
        return arguments

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool and format MCP result."""
        arguments = self._validate_tool_arguments(tool_name, arguments)

        if tool_name == "audio_encrypt":
            payload_str = _req_str(arguments, "payload")
            payload_bytes = payload_str.encode("utf-8")
            vol = _opt_float(arguments, "volume_db", 50.0)

            audio_b64 = arguments.get("audio_base64")
            if audio_b64:
                audio_bytes = _req_b64(arguments, "audio_base64")
            else:
                tone = AudioBuffer.generate_sine_tone(440.0, 1.0)
                audio_bytes = tone.to_wav_bytes()

            key, salt = derive_audio_key(audio_bytes, vol)
            encrypted = encrypt_payload(payload_bytes, key, salt)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "success",
                                "crypto_version": "v2",
                                "encrypted_blob_base64": base64.b64encode(encrypted).decode("ascii"),
                                "length_bytes": len(encrypted),
                                "volume_db": vol,
                            },
                            indent=2,
                        ),
                    }
                ]
            }

        if tool_name == "audio_decrypt":
            enc_bytes = _req_b64(arguments, "encrypted_blob_base64")
            audio_bytes = _req_b64(arguments, "audio_base64")
            vol = _opt_float(arguments, "volume_db", 50.0)

            try:
                decrypted = decrypt_payload(enc_bytes, audio_bytes, vol)
                text = decrypted.decode("utf-8", errors="replace")
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "success",
                                    "decrypted_text": text,
                                    "decrypted_base64": base64.b64encode(decrypted).decode("ascii"),
                                },
                                indent=2,
                            ),
                        }
                    ]
                }
            except Exception as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"status": "error", "message": str(e)}, indent=2),
                        }
                    ]
                }

        if tool_name == "audio_stego_embed":
            payload_bytes = _req_str(arguments, "payload").encode("utf-8")
            carrier_b64 = arguments.get("carrier_wav_base64")

            if carrier_b64:
                carrier_bytes = _req_b64(arguments, "carrier_wav_base64")
                try:
                    carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
                except ValueError as exc:
                    raise InvalidParamsError(str(exc)) from exc
            else:
                duration = max(2.0, (len(payload_bytes) + 16) * 8 / 44100.0 + 0.5)
                carrier = AudioBuffer.generate_carrier_chord([440.0, 554.37, 659.25], duration=duration)

            stego_audio = StegoEngine.embed_lsb(carrier, payload_bytes)
            stego_wav = stego_audio.to_wav_bytes()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "success",
                                "stego_wav_base64": base64.b64encode(stego_wav).decode("ascii"),
                                "carrier_duration_seconds": round(stego_audio.duration_seconds, 2),
                                "payload_size_bytes": len(payload_bytes),
                            },
                            indent=2,
                        ),
                    }
                ]
            }

        if tool_name == "audio_stego_extract":
            carrier_bytes = _req_b64(arguments, "carrier_wav_base64")
            try:
                carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
            except ValueError as exc:
                raise InvalidParamsError(str(exc)) from exc

            try:
                extracted = StegoEngine.extract_lsb(carrier)
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "success",
                                    "extracted_text": extracted.decode("utf-8", errors="replace"),
                                    "extracted_base64": base64.b64encode(extracted).decode("ascii"),
                                    "length_bytes": len(extracted),
                                },
                                indent=2,
                            ),
                        }
                    ]
                }
            except Exception as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"status": "error", "message": str(e)}, indent=2),
                        }
                    ]
                }

        if tool_name == "audio_morse_synthesize":
            text = _req_str(arguments, "text")
            freq = _opt_float(arguments, "frequency", 800.0)
            wpm = _opt_int(arguments, "wpm", 20)
            if freq < 50.0 or freq > 20000.0:
                raise InvalidParamsError("frequency must be between 50 and 20000 Hz")
            if wpm < 5 or wpm > 120:
                raise InvalidParamsError("wpm must be between 5 and 120")

            morse_audio = synthesize_morse_audio(text, tone_frequency=freq, wpm=wpm)
            wav_bytes = morse_audio.to_wav_bytes()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "success",
                                "morse_notation": text_to_morse(text),
                                "duration_seconds": round(morse_audio.duration_seconds, 2),
                                "wav_base64": base64.b64encode(wav_bytes).decode("ascii"),
                            },
                            indent=2,
                        ),
                    }
                ]
            }

        if tool_name == "audio_diagnostics":
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "server": SERVER_NAME,
                                "version": SERVER_VERSION,
                                "protocol_version": PROTOCOL_VERSION,
                                "platform": sys.platform,
                                "python_version": sys.version,
                                "zero_dependencies": True,
                                "crypto_format": "v2-key-separated",
                                "pbkdf2_iterations": PBKDF2_ITERATIONS_V2,
                                "tools_count": 9,
                                "status": "HEALTHY",
                            },
                            indent=2,
                        ),
                    }
                ]
            }

        if tool_name == "audio_steganalysis":
            from audiocipher_stego_engine.steganalysis import analyze_audio_steganography

            wav_bytes = _req_b64(arguments, "carrier_wav_base64")
            try:
                buf = AudioBuffer.from_wav_bytes(wav_bytes)
            except ValueError as exc:
                raise InvalidParamsError(str(exc)) from exc
            rep = analyze_audio_steganography(buf)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(rep.to_dict(), indent=2),
                    }
                ]
            }

        if tool_name == "audio_modulate_fsk":
            payload = _req_str(arguments, "payload")
            baud = _opt_int(arguments, "baud_rate", 300)
            ultra = bool(arguments.get("ultrasonic", False))

            cfg_kwargs: Dict[str, Any] = {"baud_rate": baud, "ultrasonic": ultra}
            if "mark_freq" in arguments and arguments["mark_freq"] is not None:
                cfg_kwargs["mark_freq"] = _opt_float(arguments, "mark_freq", 1200.0)
            if "space_freq" in arguments and arguments["space_freq"] is not None:
                cfg_kwargs["space_freq"] = _opt_float(arguments, "space_freq", 2200.0)

            try:
                cfg = FSKConfig(**cfg_kwargs)
            except ValueError as exc:
                raise InvalidParamsError(str(exc)) from exc

            audio = modulate_fsk(payload, cfg)
            wav_bytes = audio.to_wav_bytes()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "success",
                                "wav_base64": base64.b64encode(wav_bytes).decode("ascii"),
                                "duration_seconds": round(audio.duration_seconds, 2),
                                "baud_rate": baud,
                                "ultrasonic": ultra,
                                "mark_frequency_hz": cfg.mark_freq,
                                "space_frequency_hz": cfg.space_freq,
                                "total_samples": len(audio.samples),
                            },
                            indent=2,
                        ),
                    }
                ]
            }

        if tool_name == "audio_demodulate_fsk":
            wav_bytes = _req_b64(arguments, "audio_wav_base64")
            baud = _opt_int(arguments, "baud_rate", 300)
            ultra = bool(arguments.get("ultrasonic", False))

            cfg_kwargs: Dict[str, Any] = {"baud_rate": baud, "ultrasonic": ultra}
            if "mark_freq" in arguments and arguments["mark_freq"] is not None:
                cfg_kwargs["mark_freq"] = _opt_float(arguments, "mark_freq", 1200.0)
            if "space_freq" in arguments and arguments["space_freq"] is not None:
                cfg_kwargs["space_freq"] = _opt_float(arguments, "space_freq", 2200.0)

            try:
                cfg = FSKConfig(**cfg_kwargs)
                audio = AudioBuffer.from_wav_bytes(wav_bytes)
            except ValueError as exc:
                raise InvalidParamsError(str(exc)) from exc

            try:
                decoded_bytes, telemetry = demodulate_fsk(audio, cfg)
                text = decoded_bytes.decode("utf-8", errors="replace")
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "success",
                                    "decoded_text": text,
                                    "decoded_base64": base64.b64encode(decoded_bytes).decode("ascii"),
                                    "telemetry": telemetry,
                                },
                                indent=2,
                            ),
                        }
                    ]
                }
            except Exception as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"status": "error", "message": str(e)}, indent=2),
                        }
                    ],
                    "isError": True,
                }

        raise InvalidParamsError(f"Unknown tool: {tool_name}")

    def handle_request(self, request_str: str) -> Optional[str]:
        """Process JSON-RPC 2.0 request string and return formatted response."""
        try:
            req = json.loads(request_str)
        except Exception as e:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
            )

        if not isinstance(req, dict):
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: JSON-RPC request must be a JSON object"},
                }
            )

        req_id = req.get("id")
        method = req.get("method")
        if not isinstance(method, str) or not method:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32600, "message": "Invalid Request: 'method' must be a non-empty string"},
                }
            )

        params = req.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: 'params' must be a JSON object"},
                }
            )

        if method == "initialize":
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    },
                }
            )

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

        if method == "tools/list":
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": self.get_tool_definitions()},
                }
            )

        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Invalid params: 'name' must be a non-empty string"},
                    }
                )
            arguments = params.get("arguments", {})
            try:
                res = self.handle_tool_call(name, arguments)
                return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res})
            except InvalidParamsError as e:
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": f"Invalid params: {str(e)}"},
                    }
                )
            except Exception as e:
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32603, "message": str(e)},
                    }
                )

        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )

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
