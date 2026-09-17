"""Tests for FastMCP JSON-RPC 2.0 stdio server."""

import base64
import json
import pytest
from audiocipher_stego_engine.mcp_server import MCPServer
from audiocipher_stego_engine.wav_codec import AudioBuffer


def test_mcp_initialize():
    server = MCPServer()
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    res = json.loads(server.handle_request(req))
    assert res["id"] == 1
    assert res["result"]["serverInfo"]["name"] == "audiocipher-stego-engine"


def test_mcp_tools_list():
    server = MCPServer()
    req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    res = json.loads(server.handle_request(req))
    tool_names = [t["name"] for t in res["result"]["tools"]]
    assert "audio_encrypt" in tool_names
    assert "audio_decrypt" in tool_names
    assert "audio_stego_embed" in tool_names
    assert "audio_stego_extract" in tool_names
    assert "audio_morse_synthesize" in tool_names
    assert "audio_diagnostics" in tool_names


def test_mcp_tool_encryption_and_decryption():
    server = MCPServer()
    audio = AudioBuffer.generate_sine_tone(440.0, 0.5)
    audio_b64 = base64.b64encode(audio.to_wav_bytes()).decode("ascii")

    # Encrypt
    req_enc = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "audio_encrypt",
            "arguments": {
                "payload": "Secret Sovereign Protocol",
                "audio_base64": audio_b64,
                "volume_db": 42.0
            }
        }
    })
    res_enc = json.loads(server.handle_request(req_enc))
    data_enc = json.loads(res_enc["result"]["content"][0]["text"])
    enc_blob_b64 = data_enc["encrypted_blob_base64"]

    # Decrypt
    req_dec = json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "audio_decrypt",
            "arguments": {
                "encrypted_blob_base64": enc_blob_b64,
                "audio_base64": audio_b64,
                "volume_db": 42.0
            }
        }
    })
    res_dec = json.loads(server.handle_request(req_dec))
    data_dec = json.loads(res_dec["result"]["content"][0]["text"])
    assert data_dec["status"] == "success"
    assert data_dec["decrypted_text"] == "Secret Sovereign Protocol"


def test_mcp_tool_stego():
    server = MCPServer()
    req_emb = json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "audio_stego_embed",
            "arguments": {"payload": "Hidden Agent Token"}
        }
    })
    res_emb = json.loads(server.handle_request(req_emb))
    data_emb = json.loads(res_emb["result"]["content"][0]["text"])
    stego_wav_b64 = data_emb["stego_wav_base64"]

    req_ext = json.dumps({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "audio_stego_extract",
            "arguments": {"carrier_wav_base64": stego_wav_b64}
        }
    })
    res_ext = json.loads(server.handle_request(req_ext))
    data_ext = json.loads(res_ext["result"]["content"][0]["text"])
    assert data_ext["status"] == "success"
    assert data_ext["extracted_text"] == "Hidden Agent Token"


def test_mcp_tool_morse():
    server = MCPServer()
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "audio_morse_synthesize",
            "arguments": {"text": "SOS", "wpm": 25}
        }
    })
    res = json.loads(server.handle_request(req))
    data = json.loads(res["result"]["content"][0]["text"])
    assert data["status"] == "success"
    assert data["morse_notation"] == "... --- ..."
