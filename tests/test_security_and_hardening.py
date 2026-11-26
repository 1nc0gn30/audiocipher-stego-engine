"""Comprehensive regression tests for v2.6.0 security, crypto, WAV, HTTP, MCP & CLI hardening."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import math
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from audiocipher_stego_engine.crypto_core import (
    CRYPTO_MAGIC_V2,
    PBKDF2_ITERATIONS_V1,
    decrypt_payload,
    derive_audio_key,
    derive_subkeys,
    encrypt_payload,
)
from audiocipher_stego_engine.mcp_server import MCPServer
from audiocipher_stego_engine.ui_server import (
    MAX_BODY_BYTES,
    _is_local_host,
    _is_local_origin,
    run_ui_server,
)
from audiocipher_stego_engine.wav_codec import MAX_WAV_FRAMES, AudioBuffer

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def hardened_server():
    server = run_ui_server(host="127.0.0.1", port=8197)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.08)
    yield ("127.0.0.1", 8197)
    server.shutdown()
    server.server_close()


def _http_req(host: str, port: int, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    hdrs = dict(headers or {})
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, resp_headers, data


# ---------------------------------------------------------------------------
# 1. Origin & Host Validation (Port-Suffix Spoofs & DNS Rebinding)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_origin",
    [
        "http://127.0.0.1:8096.example.invalid",
        "http://localhost:8096.evil.com",
        "https://127.0.0.1:3000.attacker.tld",
        "http://user@127.0.0.1:8096",
        "http://127.0.0.1:8096/extra/path",
        "https://example.invalid",
        "null",
        "file://",
        "javascript:alert(1)",
        "http://127.0.0.1:99999",
    ],
)
def test_origin_guard_rejects_spoofs(bad_origin):
    assert _is_local_origin(bad_origin) is False


@pytest.mark.parametrize(
    "good_origin",
    [
        None,
        "",
        "http://127.0.0.1:8096",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "https://localhost",
        "http://[::1]:8096",
    ],
)
def test_origin_guard_allows_loopback(good_origin):
    assert _is_local_origin(good_origin) is True


@pytest.mark.parametrize(
    "bad_host",
    [
        "",
        "evil.example:8096",
        "127.0.0.1:8096.evil.example",
        "localhost.evil.com",
        "192.168.1.5:8096",
        "user@127.0.0.1:8096",
    ],
)
def test_host_guard_rejects_dns_rebinding(bad_host):
    assert _is_local_host(bad_host) is False


def test_live_origin_spoof_blocked_all_methods(hardened_server):
    h, p = hardened_server
    spoof = "http://127.0.0.1:8096.example.invalid"
    for method, path, body in [
        ("OPTIONS", "/api/encrypt", None),
        ("GET", "/api/diagnostics", None),
        ("POST", "/api/encrypt", b'{"payload":"hi"}'),
    ]:
        st, hdrs, data = _http_req(h, p, method, path, body=body, headers={"Origin": spoof, "Content-Type": "application/json"})
        assert st == 403, (method, path, st, data)
        assert "access-control-allow-origin" not in hdrs
        assert hdrs.get("vary") == "Origin"
        assert hdrs.get("x-frame-options") == "SAMEORIGIN"
        assert hdrs.get("x-content-type-options") == "nosniff"


def test_live_loopback_origin_allowed_with_vary(hardened_server):
    h, p = hardened_server
    studio_origin = "http://127.0.0.1:3000"
    st, hdrs, _ = _http_req(h, p, "OPTIONS", "/api/encrypt", headers={"Origin": studio_origin})
    assert st == 204
    assert hdrs.get("access-control-allow-origin") == studio_origin
    assert hdrs.get("vary") == "Origin"
    assert "frame-ancestors" in hdrs.get("content-security-policy", "")


def test_live_dns_rebinding_host_blocked(hardened_server):
    h, p = hardened_server
    for method, path in [("GET", "/health"), ("HEAD", "/health"), ("GET", "/api/diagnostics"), ("OPTIONS", "/api/encrypt"), ("POST", "/api/encrypt")]:
        st, hdrs, _ = _http_req(h, p, method, path, body=b"{}" if method == "POST" else None, headers={"Host": "evil.example:8096"})
        assert st == 403, (method, path, st)
        assert hdrs.get("vary") == "Origin"


# ---------------------------------------------------------------------------
# 2. Security Headers, HEAD, Unknown /api/* 404, Static MIME & Traversal
# ---------------------------------------------------------------------------
def test_head_and_security_headers(hardened_server):
    h, p = hardened_server
    for path in ["/", "/health", "/api/diagnostics"]:
        st, hdrs, data = _http_req(h, p, "HEAD", path)
        assert st == 200
        assert data == b""
        assert int(hdrs.get("content-length", "0")) > 0
        assert hdrs.get("x-frame-options") == "SAMEORIGIN"
        assert hdrs.get("x-content-type-options") == "nosniff"
        assert hdrs.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert hdrs.get("vary") == "Origin"


def test_unknown_api_get_returns_404_json(hardened_server):
    h, p = hardened_server
    st, hdrs, data = _http_req(h, p, "GET", "/api/nonexistent_route_xyz")
    assert st == 404
    assert "application/json" in hdrs.get("content-type", "")
    parsed = json.loads(data.decode("utf-8"))
    assert parsed["status"] == "error"


def test_static_mime_types_accurate(hardened_server):
    h, p = hardened_server
    expected = [
        ("/robots.txt", "text/plain"),
        ("/sitemap.xml", "application/xml"),
        ("/favicon.ico", "image/x-icon"),
        ("/og-banner.jpg", "image/jpeg"),
        ("/icon.png", "image/png"),
        ("/wave.css", "text/css"),
    ]
    for path, mime_prefix in expected:
        st, hdrs, data = _http_req(h, p, "GET", path)
        assert st == 200, (path, st)
        assert hdrs.get("content-type", "").startswith(mime_prefix), (path, hdrs.get("content-type"))
        assert len(data) > 0


def test_traversal_and_symlink_return_403(hardened_server):
    h, p = hardened_server
    for raw_path in ["/../../etc/passwd", "/..%2fserver.py", "/%2e%2e/server.py", "/a\\..\\server.py"]:
        with socket.create_connection((h, p), timeout=3) as s:
            req = f"GET {raw_path} HTTP/1.1\r\nHost: {h}:{p}\r\nConnection: close\r\n\r\n".encode()
            s.sendall(req)
            raw_resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw_resp += chunk
        assert raw_resp.startswith(b"HTTP/1.0 403") or raw_resp.startswith(b"HTTP/1.1 403"), (raw_path, raw_resp[:80])

    # Symlink rejection inside public/
    sym = REPO_ROOT / "public" / "_tmp_audit_symlink_test.txt"
    try:
        if sym.exists() or sym.is_symlink():
            sym.unlink()
        sym.symlink_to("/etc/hostname")
        st, _, _ = _http_req(h, p, "GET", "/_tmp_audit_symlink_test.txt")
        assert st == 403
    finally:
        if sym.exists() or sym.is_symlink():
            sym.unlink()


# ---------------------------------------------------------------------------
# 3. Body Cap (413) & Zero RemoteDisconnected on All 14 Malformed POST Cases
# ---------------------------------------------------------------------------
def test_oversized_body_returns_413_without_reading(hardened_server):
    h, p = hardened_server
    with socket.create_connection((h, p), timeout=3) as s:
        oversized = MAX_BODY_BYTES + 1024
        req = (
            f"POST /api/encrypt HTTP/1.1\r\n"
            f"Host: {h}:{p}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {oversized}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        raw_resp = s.recv(4096)
    assert b" 413 " in raw_resp


def test_bad_content_length_returns_400(hardened_server):
    h, p = hardened_server
    for cl in ["abc", "-5"]:
        with socket.create_connection((h, p), timeout=3) as s:
            req = (
                f"POST /api/encrypt HTTP/1.1\r\n"
                f"Host: {h}:{p}\r\n"
                f"Content-Length: {cl}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            s.sendall(req)
            raw_resp = s.recv(4096)
        assert b" 400 " in raw_resp, (cl, raw_resp)


@pytest.mark.parametrize(
    "path,raw_body",
    [
        ("/api/encrypt", b"{bad json"),
        ("/api/encrypt", b'["not","a","dict"]'),
        ("/api/encrypt", b"null"),
        ("/api/encrypt", b'{"payload":"hi","audio_base64":"!!!bad!!!"}'),
        ("/api/encrypt", b'{"payload":"hi","volume_db":"loud"}'),
        ("/api/encrypt", b'{"payload":"hi","volume_db":NaN}'),
        ("/api/decrypt", b'{"encrypted_blob_base64":"AAAA","audio_base64":"AAAA"}'),
        ("/api/stego/embed", b'{"payload":"hi","carrier_wav_base64":"bm90YXdhdg=="}'),
        ("/api/stego/extract", b'{"carrier_wav_base64":"bm90YXdhdg=="}'),
        ("/api/dtmf/decode", b'{"wav_base64":"bm90YXdhdg=="}'),
        ("/api/steganalysis", b'{"carrier_wav_base64":"bm90YXdhdg=="}'),
        ("/api/fsk-modulate", b'{"payload":"hi","baud_rate":0}'),
        ("/api/fsk-modulate", b'{"payload":"hi","mark_freq":30000}'),
        ("/api/fsk-demodulate", b'{"wav_base64":"bm90YXdhdg==","baud_rate":0}'),
        ("/api/morse", b'{"text":"SOS","wpm":"fast"}'),
    ],
)
def test_malformed_posts_return_clean_4xx_zero_socket_drop(hardened_server, path, raw_body):
    h, p = hardened_server
    st, hdrs, data = _http_req(h, p, "POST", path, body=raw_body, headers={"Content-Type": "application/json"})
    assert st in (400, 422), (path, raw_body, st, data)
    parsed = json.loads(data.decode("utf-8"))
    assert "error" in parsed or parsed.get("status") == "error"


def test_live_rest_stego_and_steganalysis_roundtrip(hardened_server):
    h, p = hardened_server
    st, _, data = _http_req(
        h, p, "POST", "/api/stego/embed",
        body=json.dumps({"payload": "AUDIT_016_STEGO_OK"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert st == 200
    wav_b64 = json.loads(data)["stego_wav_base64"]

    st2, _, data2 = _http_req(
        h, p, "POST", "/api/stego/extract",
        body=json.dumps({"carrier_wav_base64": wav_b64}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert st2 == 200
    assert json.loads(data2)["extracted_text"] == "AUDIT_016_STEGO_OK"

    st3, _, data3 = _http_req(
        h, p, "POST", "/api/steganalysis",
        body=json.dumps({"carrier_wav_base64": wav_b64}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert st3 == 200
    assert json.loads(data3)["stego_detected"] is True


# ---------------------------------------------------------------------------
# 4. Crypto Key Separation, Legacy v1 Compat, NaN/Inf Rejection & WAV Cap
# ---------------------------------------------------------------------------
def test_crypto_v2_key_separation_and_v1_backward_compat():
    audio = b"TEST_ACOUSTIC_CARRIER_2026"
    msg = b"Strict Key Separation Verified"
    master_key, salt = derive_audio_key(audio, volume_db=47.5)
    enc_key, mac_key = derive_subkeys(master_key)
    assert enc_key != mac_key
    assert enc_key != master_key
    assert mac_key != master_key

    blob_v2 = encrypt_payload(msg, master_key, salt)
    assert blob_v2.startswith(CRYPTO_MAGIC_V2)
    assert decrypt_payload(blob_v2, audio, volume_db=47.5) == msg

    # Construct a legacy v1 blob (10,000 PBKDF2 rounds, shared key) and verify seamless decryption
    legacy_salt = os.urandom(16)
    legacy_iv = os.urandom(16)
    v1_key, _ = derive_audio_key(audio, volume_db=47.5, salt=legacy_salt, iterations=PBKDF2_ITERATIONS_V1)
    # Generate v1 keystream
    from audiocipher_stego_engine.crypto_core import _generate_keystream
    ks = _generate_keystream(v1_key, legacy_iv, len(msg))
    ct = bytes(b ^ k for b, k in zip(msg, ks))
    tag = hmac.new(v1_key, legacy_salt + legacy_iv + ct, hashlib.sha256).digest()
    legacy_blob = legacy_salt + legacy_iv + ct + tag
    assert decrypt_payload(legacy_blob, audio, volume_db=47.5) == msg


@pytest.mark.parametrize("bad_vol", [float("nan"), float("inf"), float("-inf"), True])
def test_crypto_rejects_non_finite_volume(bad_vol):
    with pytest.raises(ValueError):
        derive_audio_key(b"abc", volume_db=bad_vol)


def test_wav_codec_rejects_header_bomb():
    # Craft a 44-byte RIFF/WAVE header claiming > MAX_WAV_FRAMES frames
    fake_frames = MAX_WAV_FRAMES + 500
    data_size = fake_frames * 2
    hdr = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF", 36 + min(data_size, 0x7FFFFFFF), b"WAVE",
        b"fmt ", 16, 1, 1, 44100, 88200, 2, 16,
        b"data", min(data_size, 0x7FFFFFFF),
    )
    with pytest.raises(ValueError, match="safety limit|Corrupted WAV"):
        AudioBuffer.from_wav_bytes(hdr)


# ---------------------------------------------------------------------------
# 5. MCP Hardening (-32600 non-dict, -32602 missing/invalid params)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw_json", ["[]", "null", "123", '"hello"'])
def test_mcp_rejects_non_dict_jsonrpc_with_32600(raw_json):
    server = MCPServer()
    res = json.loads(server.handle_request(raw_json))
    assert res["error"]["code"] == -32600


def test_mcp_missing_required_arg_returns_32602():
    server = MCPServer()
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": "audio_encrypt", "arguments": {}},
    })
    res = json.loads(server.handle_request(req))
    assert res["error"]["code"] == -32602
    assert "payload" in res["error"]["message"]


def test_mcp_version_and_all_9_tools():
    server = MCPServer()
    init = json.loads(server.handle_request(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})))
    assert init["result"]["serverInfo"]["version"] == "2.6.0"
    tools = json.loads(server.handle_request(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})))
    assert len(tools["result"]["tools"]) == 9


# ---------------------------------------------------------------------------
# 6. Unified CLI & Live Braille TUI Binaries
# ---------------------------------------------------------------------------
def test_cli_and_tui_wrappers():
    cli_bin = str(REPO_ROOT / "bin" / "audiocipher-stego-engine")
    tui_bin = str(REPO_ROOT / "bin" / "audiocipher-stego-engine-tui")

    r_ver = subprocess.run([sys.executable, cli_bin, "--version"], capture_output=True, text=True, check=True)
    assert "2.6.0" in r_ver.stdout

    r_json = subprocess.run([sys.executable, cli_bin, "--status", "--json"], capture_output=True, text=True, check=True)
    info = json.loads(r_json.stdout)
    assert info["version"] == "2.6.0"
    assert info["mcp_tools_count"] == 9

    r_tui_ver = subprocess.run([sys.executable, tui_bin, "--version"], capture_output=True, text=True, check=True)
    assert "2.6.0" in r_tui_ver.stdout

    r_tui_status = subprocess.run([sys.executable, tui_bin, "--status"], capture_output=True, text=True, check=True)
    assert "AUDIOCIPHER STEGO STUDIO v2.6.0" in r_tui_status.stdout

    r_tui_json = subprocess.run([sys.executable, tui_bin, "--json"], capture_output=True, text=True, check=True)
    snap = json.loads(r_tui_json.stdout)
    assert snap["tool"] == "audiocipher-stego-engine"
    assert snap["version"] == "2.6.0"
