"""
AudioCipher Studio UI & REST API Server.
Hardened loopback HTTP daemon with strict Origin/Host validation,
security headers, bounded POST body caps, and centralized JSON error boundaries.
Zero third-party runtime dependencies.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import struct
import sys
import time
import urllib.parse
import wave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

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
from audiocipher_stego_engine.spectrogram import (
    decode_dtmf_audio,
    synthesize_dtmf_audio,
    synthesize_morse_audio,
    text_to_morse,
)
from audiocipher_stego_engine.stego_engine import StegoEngine
from audiocipher_stego_engine.wav_codec import AudioBuffer

SERVER_VERSION = "2.6.0"
SERVER_START_TIME = time.time()
MAX_BODY_BYTES = 1_572_864  # 1.5 MiB cap (allows valid WAV stego uploads, blocks >=2 MiB DoS payloads)

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

MIME_TYPES: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".ttf": "font/ttf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".wav": "audio/wav",
}


def _safe_rel(raw: str) -> str:
    """Request path -> safe relative path inside a static dir; '' (index) if it
    tries to climb out with '..' or is absolute. Raw request paths are not normalised."""
    from urllib.parse import unquote
    rel = unquote(str(raw or "")).replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or ":" in (parts[0] if parts else ""):
        return ""
    return "/".join(parts)


def _has_traversal_syntax(raw_path: str) -> bool:
    """Detect path traversal attempts, backslashes, null bytes, or Windows drive prefixes."""
    if not raw_path:
        return False
    raw_lower = raw_path.lower()
    if (
        ".." in raw_path
        or "%2e" in raw_lower
        or "\\" in raw_path
        or "%5c" in raw_lower
        or "\x00" in raw_path
        or "%00" in raw_lower
    ):
        return True
    decoded = urllib.parse.unquote(raw_path)
    if ".." in decoded or "\\" in decoded or "\x00" in decoded:
        return True
    first_seg = decoded.lstrip("/").split("/", 1)[0]
    if ":" in first_seg:
        return True
    return False


def _is_local_origin(origin: Optional[str]) -> bool:
    """
    True for no Origin (CLI/curl/same-origin GET) or a strictly validated loopback Origin.
    Rejects port-suffix domain spoofs (e.g. http://127.0.0.1:8096.example.invalid),
    userinfo injection, non-loopback hosts, and invalid schemes.
    """
    if origin is None or origin == "":
        return True
    if not isinstance(origin, str):
        return False
    if any(ch.isspace() for ch in origin) or "@" in origin:
        return False
    try:
        u = urllib.parse.urlparse(origin)
    except Exception:
        return False
    if u.scheme not in ("http", "https"):
        return False
    if u.username is not None or u.password is not None:
        return False
    if u.path not in ("", "/") or u.params or u.query or u.fragment:
        return False
    hostname = (u.hostname or "").lower()
    if hostname not in LOOPBACK_HOSTS:
        return False
    try:
        port = u.port
    except ValueError:
        return False
    if port is not None and not (1 <= port <= 65535):
        return False
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    expected_netloc = f"{host_part}:{port}" if port is not None else host_part
    return u.netloc.lower() == expected_netloc


def _is_local_host(host_header: Optional[str]) -> bool:
    """Strict loopback Host header allowlist to block DNS rebinding."""
    if not host_header or not isinstance(host_header, str):
        return False
    host_val = host_header.strip()
    if not host_val or any(ch.isspace() for ch in host_val) or "@" in host_val or "/" in host_val:
        return False
    try:
        u = urllib.parse.urlparse(f"http://{host_val}")
    except Exception:
        return False
    if u.username is not None or u.password is not None:
        return False
    hostname = (u.hostname or "").lower()
    if hostname not in LOOPBACK_HOSTS:
        return False
    try:
        port = u.port
    except ValueError:
        return False
    if port is not None and not (1 <= port <= 65535):
        return False
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    expected_netloc = f"{host_part}:{port}" if port is not None else host_part
    return u.netloc.lower() == expected_netloc


def _strict_b64decode(val: Any, field_name: str, allow_empty: bool = False) -> bytes:
    """Strictly decode a base64 string field, raising ValueError on invalid input."""
    if not isinstance(val, str):
        raise ValueError(f"Field '{field_name}' must be a base64-encoded string.")
    cleaned = "".join(val.split())
    if not cleaned:
        if allow_empty:
            return b""
        raise ValueError(f"Field '{field_name}' must not be empty.")
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid base64 encoding in '{field_name}': {exc}") from exc


def _require_finite_float(val: Any, field_name: str, min_val: Optional[float] = None, max_val: Optional[float] = None) -> float:
    if isinstance(val, bool):
        raise ValueError(f"Field '{field_name}' must be numeric, not bool.")
    try:
        num = float(val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Field '{field_name}' must be a valid number.") from exc
    if not math.isfinite(num):
        raise ValueError(f"Field '{field_name}' must be finite (NaN/inf rejected).")
    if min_val is not None and num < min_val:
        raise ValueError(f"Field '{field_name}' must be >= {min_val}.")
    if max_val is not None and num > max_val:
        raise ValueError(f"Field '{field_name}' must be <= {max_val}.")
    return num


def _require_int(val: Any, field_name: str, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    if isinstance(val, bool):
        raise ValueError(f"Field '{field_name}' must be an integer, not bool.")
    try:
        if isinstance(val, float) and not val.is_integer():
            raise ValueError(f"Field '{field_name}' must be an integer.")
        num = int(val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Field '{field_name}' must be a valid integer.") from exc
    if min_val is not None and num < min_val:
        raise ValueError(f"Field '{field_name}' must be >= {min_val}.")
    if max_val is not None and num > max_val:
        raise ValueError(f"Field '{field_name}' must be <= {max_val}.")
    return num


def _require_str(val: Any, field_name: str) -> str:
    if not isinstance(val, str):
        raise ValueError(f"Field '{field_name}' must be a string.")
    return val


class AudioCipherHTTPHandler(BaseHTTPRequestHandler):
    """Hardened HTTP Request Handler for AudioCipher Studio Web UI and REST API."""

    def _send_security_and_cors_headers(self, allow_cors: bool = True) -> None:
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header(
            "Content-Security-Policy",
            "frame-ancestors 'self' http://127.0.0.1:3000 http://localhost:3000",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Vary", "Origin")

        if allow_cors:
            origin = self.headers.get("Origin", "")
            if origin and _is_local_origin(origin):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, data: Any, status: int = 200, head_only: bool = False, allow_cors: bool = True) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_and_cors_headers(allow_cors=allow_cors)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _check_host_and_origin(self, head_only: bool = False) -> bool:
        """Enforce loopback Host header and Origin allowlist on every request."""
        host_header = self.headers.get("Host")
        if host_header is not None and not _is_local_host(host_header):
            self._send_json(
                {"status": "error", "error": "Forbidden Host header (loopback only)"},
                status=403,
                head_only=head_only,
                allow_cors=False,
            )
            return False
        if host_header is None and getattr(self, "request_version", "") >= "HTTP/1.1":
            self._send_json(
                {"status": "error", "error": "Missing required Host header"},
                status=403,
                head_only=head_only,
                allow_cors=False,
            )
            return False

        origin = self.headers.get("Origin")
        if origin is not None and origin != "" and not _is_local_origin(origin):
            self._send_json(
                {"status": "error", "error": "Cross-origin request blocked"},
                status=403,
                head_only=head_only,
                allow_cors=False,
            )
            return False
        return True

    def do_OPTIONS(self) -> None:
        if not self._check_host_and_origin(head_only=False):
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._send_security_and_cors_headers(allow_cors=True)
        self.end_headers()

    def _serve_get_or_head(self, head_only: bool = False) -> None:
        if not self._check_host_and_origin(head_only=head_only):
            return

        raw_path_no_query = self.path.split("?", 1)[0]
        if _has_traversal_syntax(raw_path_no_query):
            self._send_json({"status": "error", "error": "Forbidden path traversal"}, status=403, head_only=head_only)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/api/health", "/health"):
            self._send_json(
                {
                    "status": "ok",
                    "service": "audiocipher-stego-engine",
                    "version": SERVER_VERSION,
                    "uptime_seconds": round(time.time() - SERVER_START_TIME, 2),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                status=200,
                head_only=head_only,
            )
            return

        if path == "/api/diagnostics":
            self._send_json(
                {
                    "service": "audiocipher-stego-engine",
                    "version": SERVER_VERSION,
                    "platform": sys.platform,
                    "python": sys.version,
                    "zero_dependencies": True,
                    "crypto_format": "v2-key-separated",
                    "pbkdf2_iterations": PBKDF2_ITERATIONS_V2,
                    "max_body_bytes": MAX_BODY_BYTES,
                    "mcp_tools_count": 9,
                    "uptime_seconds": round(time.time() - SERVER_START_TIME, 2),
                    "status": "HEALTHY",
                },
                status=200,
                head_only=head_only,
            )
            return

        if path.startswith("/api/"):
            self._send_json({"status": "error", "error": f"Endpoint not found: {path}"}, status=404, head_only=head_only)
            return

        # Serve UI & Static Assets strictly from public/
        public_dir = Path(__file__).resolve().parent.parent.parent / "public"
        public_resolved = public_dir.resolve()

        rel_path = _safe_rel(path)
        if not rel_path or rel_path in ("index.html", "studio"):
            rel_path = "index.html"

        candidate = public_dir / rel_path
        # Reject symlinks anywhere along the relative path
        check_path = public_dir
        for part in Path(rel_path).parts:
            check_path = check_path / part
            if check_path.is_symlink():
                self._send_json({"status": "error", "error": "Symlink access forbidden"}, status=403, head_only=head_only)
                return

        try:
            resolved_target = candidate.resolve()
        except OSError:
            self._send_json({"status": "error", "error": "Invalid file path"}, status=403, head_only=head_only)
            return

        if not resolved_target.is_relative_to(public_resolved):
            self._send_json({"status": "error", "error": "Forbidden path"}, status=403, head_only=head_only)
            return

        if not resolved_target.is_file():
            self._send_json({"status": "error", "error": f"Not found: {path}"}, status=404, head_only=head_only)
            return

        ext = resolved_target.suffix.lower()
        content_type = MIME_TYPES.get(ext, "application/octet-stream")

        if head_only:
            size = resolved_target.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self._send_security_and_cors_headers(allow_cors=True)
            self.end_headers()
            return

        content = resolved_target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self._send_security_and_cors_headers(allow_cors=True)
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        self._serve_get_or_head(head_only=False)

    def do_HEAD(self) -> None:
        self._serve_get_or_head(head_only=True)

    def do_POST(self) -> None:
        if not self._check_host_and_origin(head_only=False):
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Validate Content-Length strictly before reading into RAM
        raw_cl = self.headers.get("Content-Length")
        if raw_cl is None:
            length = 0
        else:
            try:
                length = int(raw_cl.strip())
            except ValueError:
                self._send_json({"status": "error", "error": "Invalid Content-Length header"}, status=400)
                return
            if length < 0:
                self._send_json({"status": "error", "error": "Negative Content-Length header"}, status=400)
                return
            if length > MAX_BODY_BYTES:
                self._send_json(
                    {
                        "status": "error",
                        "error": f"Payload too large: {length} bytes exceeds {MAX_BODY_BYTES} byte limit",
                        "max_body_bytes": MAX_BODY_BYTES,
                    },
                    status=413,
                )
                return

        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json({"status": "error", "error": "Invalid JSON body"}, status=400)
            return

        if not isinstance(body, dict):
            self._send_json({"status": "error", "error": "Request body must be a JSON object"}, status=400)
            return

        try:
            self._dispatch_post(path, body)
        except (ValueError, TypeError, KeyError, binascii.Error, wave.Error, struct.error, OverflowError) as exc:
            self._send_json({"status": "error", "error": str(exc), "message": str(exc)}, status=400)
        except Exception as exc:
            self._send_json({"status": "error", "error": str(exc), "message": str(exc)}, status=422)

    def _dispatch_post(self, path: str, body: Dict[str, Any]) -> None:
        if path == "/api/encrypt":
            payload_str = _require_str(body.get("payload", ""), "payload")
            payload_bytes = payload_str.encode("utf-8")
            vol = _require_finite_float(body.get("volume_db", 50.0), "volume_db")

            audio_b64 = body.get("audio_base64")
            if audio_b64 is not None and audio_b64 != "":
                audio_bytes = _strict_b64decode(audio_b64, "audio_base64")
            else:
                tone = AudioBuffer.generate_sine_tone(440.0, 1.0)
                audio_bytes = tone.to_wav_bytes()

            key, salt = derive_audio_key(audio_bytes, vol)
            encrypted = encrypt_payload(payload_bytes, key, salt)

            self._send_json(
                {
                    "status": "success",
                    "crypto_version": "v2",
                    "encrypted_blob_base64": base64.b64encode(encrypted).decode("ascii"),
                    "audio_key_base64": base64.b64encode(audio_bytes).decode("ascii"),
                    "length_bytes": len(encrypted),
                    "volume_db": vol,
                }
            )
            return

        if path == "/api/decrypt":
            enc_bytes = _strict_b64decode(body.get("encrypted_blob_base64", ""), "encrypted_blob_base64")
            audio_bytes = _strict_b64decode(body.get("audio_base64", ""), "audio_base64")
            vol = _require_finite_float(body.get("volume_db", 50.0), "volume_db")

            decrypted = decrypt_payload(enc_bytes, audio_bytes, vol)
            self._send_json(
                {
                    "status": "success",
                    "decrypted_text": decrypted.decode("utf-8", errors="replace"),
                    "decrypted_base64": base64.b64encode(decrypted).decode("ascii"),
                }
            )
            return

        if path == "/api/stego/embed":
            payload_str = _require_str(body.get("payload", ""), "payload")
            payload_bytes = payload_str.encode("utf-8")
            carrier_b64 = body.get("carrier_wav_base64")

            if carrier_b64 is not None and carrier_b64 != "":
                carrier_bytes = _strict_b64decode(carrier_b64, "carrier_wav_base64")
                carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
            else:
                duration = max(2.0, (len(payload_bytes) + 16) * 8 / 44100.0 + 0.5)
                carrier = AudioBuffer.generate_carrier_chord([440.0, 554.37, 659.25], duration=duration)

            stego_audio = StegoEngine.embed_lsb(carrier, payload_bytes)
            stego_wav = stego_audio.to_wav_bytes()

            self._send_json(
                {
                    "status": "success",
                    "stego_wav_base64": base64.b64encode(stego_wav).decode("ascii"),
                    "carrier_duration_seconds": round(stego_audio.duration_seconds, 2),
                    "payload_size_bytes": len(payload_bytes),
                }
            )
            return

        if path == "/api/stego/extract":
            carrier_bytes = _strict_b64decode(body.get("carrier_wav_base64", ""), "carrier_wav_base64")
            carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
            extracted = StegoEngine.extract_lsb(carrier)
            self._send_json(
                {
                    "status": "success",
                    "extracted_text": extracted.decode("utf-8", errors="replace"),
                    "extracted_base64": base64.b64encode(extracted).decode("ascii"),
                    "length_bytes": len(extracted),
                }
            )
            return

        if path == "/api/morse":
            text = _require_str(body.get("text", ""), "text")
            freq = _require_finite_float(body.get("frequency", 800.0), "frequency", min_val=50.0, max_val=20000.0)
            wpm = _require_int(body.get("wpm", 20), "wpm", min_val=5, max_val=120)

            morse_audio = synthesize_morse_audio(text, tone_frequency=freq, wpm=wpm)
            wav_bytes = morse_audio.to_wav_bytes()

            self._send_json(
                {
                    "status": "success",
                    "morse_notation": text_to_morse(text),
                    "duration_seconds": round(morse_audio.duration_seconds, 2),
                    "wav_base64": base64.b64encode(wav_bytes).decode("ascii"),
                }
            )
            return

        if path == "/api/dtmf/synthesize":
            digits = _require_str(body.get("digits", "1234#"), "digits")
            tone_dur = _require_finite_float(body.get("tone_duration", 0.1), "tone_duration", min_val=0.02, max_val=2.0)
            silence_dur = _require_finite_float(
                body.get("silence_duration", 0.05), "silence_duration", min_val=0.01, max_val=2.0
            )

            dtmf_audio = synthesize_dtmf_audio(digits, tone_duration=tone_dur, silence_duration=silence_dur)
            wav_bytes = dtmf_audio.to_wav_bytes()

            self._send_json(
                {
                    "status": "success",
                    "digits": digits.upper(),
                    "duration_seconds": round(dtmf_audio.duration_seconds, 2),
                    "wav_base64": base64.b64encode(wav_bytes).decode("ascii"),
                }
            )
            return

        if path == "/api/dtmf/decode":
            wav_bytes = _strict_b64decode(body.get("wav_base64", ""), "wav_base64")
            tone_dur = _require_finite_float(body.get("tone_duration", 0.1), "tone_duration", min_val=0.02, max_val=2.0)
            silence_dur = _require_finite_float(
                body.get("silence_duration", 0.05), "silence_duration", min_val=0.01, max_val=2.0
            )

            audio = AudioBuffer.from_wav_bytes(wav_bytes)
            decoded = decode_dtmf_audio(audio, tone_duration=tone_dur, silence_duration=silence_dur)

            self._send_json(
                {
                    "status": "success",
                    "decoded_digits": decoded,
                    "audio_duration_seconds": round(audio.duration_seconds, 2),
                }
            )
            return

        if path == "/api/steganalysis":
            from audiocipher_stego_engine.steganalysis import analyze_audio_steganography

            wav_b64 = body.get("carrier_wav_base64", "")
            if wav_b64 is None or wav_b64 == "":
                carrier = AudioBuffer.generate_sine_tone(440.0, 1.0)
            else:
                wav_bytes = _strict_b64decode(wav_b64, "carrier_wav_base64")
                carrier = AudioBuffer.from_wav_bytes(wav_bytes)

            rep = analyze_audio_steganography(carrier)
            self._send_json(rep.to_dict())
            return

        if path == "/api/fsk-modulate":
            payload = _require_str(body.get("payload", ""), "payload")
            baud = _require_int(body.get("baud_rate", 300), "baud_rate", min_val=10, max_val=4800)
            ultra = bool(body.get("ultrasonic", False))

            cfg_kwargs: Dict[str, Any] = {"baud_rate": baud, "ultrasonic": ultra}
            if "mark_freq" in body and body["mark_freq"] is not None:
                cfg_kwargs["mark_freq"] = _require_finite_float(body["mark_freq"], "mark_freq")
            if "space_freq" in body and body["space_freq"] is not None:
                cfg_kwargs["space_freq"] = _require_finite_float(body["space_freq"], "space_freq")

            cfg = FSKConfig(**cfg_kwargs)
            audio = modulate_fsk(payload, cfg)
            wav_bytes = audio.to_wav_bytes()

            self._send_json(
                {
                    "status": "success",
                    "wav_base64": base64.b64encode(wav_bytes).decode("ascii"),
                    "duration_seconds": round(audio.duration_seconds, 2),
                    "baud_rate": baud,
                    "ultrasonic": ultra,
                    "mark_frequency_hz": cfg.mark_freq,
                    "space_frequency_hz": cfg.space_freq,
                    "total_samples": len(audio.samples),
                }
            )
            return

        if path == "/api/fsk-demodulate":
            wav_bytes = _strict_b64decode(body.get("wav_base64", ""), "wav_base64")
            baud = _require_int(body.get("baud_rate", 300), "baud_rate", min_val=10, max_val=4800)
            ultra = bool(body.get("ultrasonic", False))

            cfg_kwargs: Dict[str, Any] = {"baud_rate": baud, "ultrasonic": ultra}
            if "mark_freq" in body and body["mark_freq"] is not None:
                cfg_kwargs["mark_freq"] = _require_finite_float(body["mark_freq"], "mark_freq")
            if "space_freq" in body and body["space_freq"] is not None:
                cfg_kwargs["space_freq"] = _require_finite_float(body["space_freq"], "space_freq")

            cfg = FSKConfig(**cfg_kwargs)
            audio = AudioBuffer.from_wav_bytes(wav_bytes)
            decoded_bytes, telemetry = demodulate_fsk(audio, cfg)
            text = decoded_bytes.decode("utf-8", errors="replace")

            self._send_json(
                {
                    "status": "success",
                    "decoded_text": text,
                    "decoded_base64": base64.b64encode(decoded_bytes).decode("ascii"),
                    "telemetry": telemetry,
                }
            )
            return

        self._send_json({"status": "error", "error": f"Endpoint not found: {path}"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_ui_server(host: str = "127.0.0.1", port: int = 8096) -> ThreadingHTTPServer:
    """Launch UI HTTP Server."""
    server = ThreadingHTTPServer((host, port), AudioCipherHTTPHandler)
    return server
