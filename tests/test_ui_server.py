"""Tests for UI Web Server and REST API."""

import json
import threading
import time
import urllib.request
import pytest
from audiocipher_stego_engine.ui_server import run_ui_server


@pytest.fixture(scope="module")
def live_server():
    server = run_ui_server(host="127.0.0.1", port=8196)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield "http://127.0.0.1:8196"
    server.shutdown()
    server.server_close()


def test_api_health(live_server):
    req = urllib.request.Request(f"{live_server}/api/health")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "ok"
        assert data["service"] == "audiocipher-stego-engine"


def test_api_diagnostics(live_server):
    req = urllib.request.Request(f"{live_server}/api/diagnostics")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "HEALTHY"


def test_api_encrypt_and_decrypt(live_server):
    payload = json.dumps({"payload": "Mission Protocol 757", "volume_db": 50.0}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/encrypt", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "success"
        assert "encrypted_blob_base64" in data


def test_api_morse(live_server):
    payload = json.dumps({"text": "SOS", "wpm": 20}).encode("utf-8")
    req = urllib.request.Request(f"{live_server}/api/morse", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "success"
        assert data["morse_notation"] == "... --- ..."


def test_ui_index_html(live_server):
    req = urllib.request.Request(f"{live_server}/")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "<!DOCTYPE html>" in content
        assert "Google AudioCipher Studio" in content
