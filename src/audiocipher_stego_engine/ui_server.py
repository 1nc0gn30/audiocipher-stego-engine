"""
AudioCipher Studio UI & REST API Server (design influenced by Material 3 tokens).
Zero third-party runtime dependencies.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from audiocipher_stego_engine.crypto_core import (
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

SERVER_START_TIME = time.time()

EMBEDDED_STUDIO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AudioCipher Studio | Acoustic Cryptography & Steganography</title>
  <style>
    :root {
      --g-blue: #1a73e8;
      --g-blue-dark: #1557b0;
      --g-blue-light: #e8f0fe;
      --g-green: #1e8e3e;
      --g-green-light: #e6f4ea;
      --surface: #ffffff;
      --surface-variant: #f8f9fa;
      --border: #dadce0;
      --text: #202124;
      --text-secondary: #5f6368;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Google Sans", "Segoe UI", Roboto, sans-serif; background: var(--surface-variant); color: var(--text); height: 100vh; display: flex; flex-direction: column; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 0.75rem 1.5rem; display: flex; justify-content: space-between; align-items: center; }
    .brand { font-size: 1.15rem; font-weight: 600; color: var(--g-blue); display: flex; align-items: center; gap: 0.5rem; }
    .container { display: grid; grid-template-columns: 320px 1fr; flex: 1; overflow: hidden; }
    aside { background: var(--surface); border-right: 1px solid var(--border); padding: 1.25rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }
    main { padding: 1.5rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.25rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; }
    .btn { background: var(--g-blue); color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
    input, textarea { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid var(--border); border-radius: 6px; font-size: 0.95rem; }
  </style>
</head>
<body>
  <header>
    <div class="brand"><span>🔒</span> AudioCipher Studio</div>
  </header>
  <div class="container">
    <aside>
      <h3>Modes</h3>
      <button class="btn" style="width:100%;" onclick="setMode('encrypt')">Encrypt Payload</button>
      <button class="btn" style="width:100%; background:#5f6368;" onclick="setMode('stego')">Steganography Hide</button>
      <button class="btn" style="width:100%; background:#5f6368;" onclick="setMode('morse')">Morse Synthesizer</button>
    </aside>
    <main>
      <div class="card">
        <h3>Payload Text</h3>
        <textarea id="payload-input" rows="3">Top Secret Sovereign Agent Directive #757</textarea>
        <button class="btn" style="margin-top:0.75rem;" onclick="processPayload()">Process Audio Cipher</button>
      </div>
      <div class="card" id="result-box">
        <h3>Output Result</h3>
        <p id="result-text">Ready for operation.</p>
      </div>
    </main>
  </div>
  <script>
    let mode = 'encrypt';
    function setMode(m) { mode = m; }
    async function processPayload() {
      const text = document.getElementById('payload-input').value;
      if (mode === 'morse') {
        const resp = await fetch('/api/morse', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({text})
        });
        const data = await resp.json();
        document.getElementById('result-text').innerText = `Morse Code: ${data.morse_notation} (${data.duration_seconds}s Audio Generated)`;
      } else {
        const resp = await fetch('/api/encrypt', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({payload: text, volume_db: 50})
        });
        const data = await resp.json();
        document.getElementById('result-text').innerText = `Encrypted Ciphertext (${data.length_bytes} bytes): ${data.encrypted_blob_base64.slice(0, 32)}...`;
      }
    }
  </script>
</body>
</html>"""


class AudioCipherHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Studio Web UI and REST API."""

    def _set_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json({
                "status": "ok",
                "service": "audiocipher-stego-engine",
                "uptime_seconds": round(time.time() - SERVER_START_TIME, 2),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            return

        elif path == "/api/diagnostics":
            self._send_json({
                "platform": sys.platform,
                "python": sys.version,
                "zero_dependencies": True,
                "status": "HEALTHY"
            })
            return

        # Serve UI from public/index.html
        public_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "public"))
        index_file = os.path.join(public_dir, "index.html")

        if os.path.isfile(index_file) and path in ("/", "/index.html"):
            with open(index_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(content)
            return

        # Embedded UI fallback
        body = EMBEDDED_STUDIO_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Invalid JSON"}, status=400)
            return

        if path == "/api/encrypt":
            payload_str = body.get("payload", "")
            payload_bytes = payload_str.encode("utf-8")
            vol = float(body.get("volume_db", 50.0))

            audio_b64 = body.get("audio_base64")
            if audio_b64:
                audio_bytes = base64.b64decode(audio_b64)
            else:
                tone = AudioBuffer.generate_sine_tone(440.0, 1.0)
                audio_bytes = tone.to_wav_bytes()

            key, salt = derive_audio_key(audio_bytes, vol)
            encrypted = encrypt_payload(payload_bytes, key, salt)

            self._send_json({
                "status": "success",
                "encrypted_blob_base64": base64.b64encode(encrypted).decode("ascii"),
                "length_bytes": len(encrypted),
                "volume_db": vol
            })
            return

        elif path == "/api/decrypt":
            enc_b64 = body.get("encrypted_blob_base64", "")
            audio_b64 = body.get("audio_base64", "")
            vol = float(body.get("volume_db", 50.0))

            enc_bytes = base64.b64decode(enc_b64)
            audio_bytes = base64.b64decode(audio_b64)

            try:
                decrypted = decrypt_payload(enc_bytes, audio_bytes, vol)
                self._send_json({
                    "status": "success",
                    "decrypted_text": decrypted.decode("utf-8", errors="replace"),
                    "decrypted_base64": base64.b64encode(decrypted).decode("ascii")
                })
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=400)
            return

        elif path == "/api/stego/embed":
            payload_bytes = body.get("payload", "").encode("utf-8")
            carrier_b64 = body.get("carrier_wav_base64")

            if carrier_b64:
                carrier_bytes = base64.b64decode(carrier_b64)
                carrier = AudioBuffer.from_wav_bytes(carrier_bytes)
            else:
                duration = max(2.0, (len(payload_bytes) + 16) * 8 / 44100.0 + 0.5)
                carrier = AudioBuffer.generate_carrier_chord([440.0, 554.37, 659.25], duration=duration)

            stego_audio = StegoEngine.embed_lsb(carrier, payload_bytes)
            stego_wav = stego_audio.to_wav_bytes()

            self._send_json({
                "status": "success",
                "stego_wav_base64": base64.b64encode(stego_wav).decode("ascii"),
                "carrier_duration_seconds": round(stego_audio.duration_seconds, 2),
                "payload_size_bytes": len(payload_bytes)
            })
            return

        elif path == "/api/stego/extract":
            carrier_b64 = body.get("carrier_wav_base64", "")
            carrier_bytes = base64.b64decode(carrier_b64)
            carrier = AudioBuffer.from_wav_bytes(carrier_bytes)

            try:
                extracted = StegoEngine.extract_lsb(carrier)
                self._send_json({
                    "status": "success",
                    "extracted_text": extracted.decode("utf-8", errors="replace"),
                    "extracted_base64": base64.b64encode(extracted).decode("ascii"),
                    "length_bytes": len(extracted)
                })
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=400)
            return

        elif path == "/api/morse":
            text = body.get("text", "")
            freq = float(body.get("frequency", 800.0))
            wpm = int(body.get("wpm", 20))

            morse_audio = synthesize_morse_audio(text, tone_frequency=freq, wpm=wpm)
            wav_bytes = morse_audio.to_wav_bytes()

            self._send_json({
                "status": "success",
                "morse_notation": text_to_morse(text),
                "duration_seconds": round(morse_audio.duration_seconds, 2),
                "wav_base64": base64.b64encode(wav_bytes).decode("ascii")
            })
            return

        elif path == "/api/dtmf/synthesize":
            digits = body.get("digits", "1234#")
            tone_dur = float(body.get("tone_duration", 0.1))
            silence_dur = float(body.get("silence_duration", 0.05))

            dtmf_audio = synthesize_dtmf_audio(digits, tone_duration=tone_dur, silence_duration=silence_dur)
            wav_bytes = dtmf_audio.to_wav_bytes()

            self._send_json({
                "status": "success",
                "digits": digits.upper(),
                "duration_seconds": round(dtmf_audio.duration_seconds, 2),
                "wav_base64": base64.b64encode(wav_bytes).decode("ascii")
            })
            return

        elif path == "/api/dtmf/decode":
            wav_b64 = body.get("wav_base64", "")
            tone_dur = float(body.get("tone_duration", 0.1))
            silence_dur = float(body.get("silence_duration", 0.05))

            wav_bytes = base64.b64decode(wav_b64)
            audio = AudioBuffer.from_wav_bytes(wav_bytes)
            decoded = decode_dtmf_audio(audio, tone_duration=tone_dur, silence_duration=silence_dur)

            self._send_json({
                "status": "success",
                "decoded_digits": decoded,
                "audio_duration_seconds": round(audio.duration_seconds, 2)
            })
            return

        self._send_json({"error": f"Endpoint not found: {path}"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_ui_server(host: str = "0.0.0.0", port: int = 8096) -> ThreadingHTTPServer:
    """Launch UI HTTP Server."""
    server = ThreadingHTTPServer((host, port), AudioCipherHTTPHandler)
    return server
