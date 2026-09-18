"""
Comprehensive tests for BFSK Acoustic Modem and Ultrasonic Air-Gap Transmission.
Zero external runtime dependencies.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict

import pytest

from audiocipher_stego_engine.acoustic_modem import (
    FSKConfig,
    crc16_ccitt,
    demodulate_fsk,
    modulate_fsk,
)
from audiocipher_stego_engine.cli import main as cli_main
from audiocipher_stego_engine.mcp_server import MCPServer
from audiocipher_stego_engine.ui_server import AudioCipherHTTPHandler
from audiocipher_stego_engine.wav_codec import AudioBuffer


def test_crc16_ccitt():
    """Verify standard CRC-16-CCITT implementation."""
    data = b"123456789"
    crc = crc16_ccitt(data)
    assert isinstance(crc, int)
    assert 0 <= crc <= 0xFFFF
    # Check repeatability
    assert crc16_ccitt(data) == crc
    # Check sensitivity
    assert crc16_ccitt(b"123456788") != crc


def test_fsk_config_validation():
    """Verify FSKConfig parameters and validations."""
    cfg = FSKConfig()
    assert cfg.baud_rate == 300
    assert cfg.mark_freq == 1200.0
    assert cfg.space_freq == 2200.0
    assert not cfg.ultrasonic

    # Ultrasonic mode should shift to >18kHz
    u_cfg = FSKConfig(ultrasonic=True)
    assert u_cfg.mark_freq == 18500.0
    assert u_cfg.space_freq == 20000.0

    # Invalid baud rate
    with pytest.raises(ValueError, match="baud_rate must be positive"):
        FSKConfig(baud_rate=-10)

    # Invalid sample rate
    with pytest.raises(ValueError, match="sample_rate must be positive"):
        FSKConfig(sample_rate=0)

    # Exceeding Nyquist frequency
    with pytest.raises(ValueError, match="Nyquist"):
        FSKConfig(sample_rate=8000, mark_freq=5000.0)


def test_audible_fsk_modulation_and_demodulation():
    """Test standard audible BFSK transmission roundtrip."""
    payload = b"NEO-AGENT-DIRECTIVE // TOP SECRET"
    cfg = FSKConfig(baud_rate=300)

    audio = modulate_fsk(payload, cfg)
    assert isinstance(audio, AudioBuffer)
    assert audio.sample_rate == 44100
    assert audio.channels == 1
    assert audio.duration_seconds > 0.5

    decoded, telemetry = demodulate_fsk(audio, cfg)
    assert decoded == payload
    assert telemetry["crc_valid"] is True
    assert telemetry["baud_rate"] == 300
    assert telemetry["payload_length_bytes"] == len(payload)
    assert telemetry["estimated_snr_db"] > 5.0
    assert telemetry["ultrasonic"] is False


def test_ultrasonic_fsk_modulation_and_demodulation():
    """Test covert ultrasonic air-gap transmission roundtrip (>18kHz)."""
    payload = b"AIRGAP_ULTRASONIC_PAYLOAD_99"
    cfg = FSKConfig(baud_rate=600, ultrasonic=True)

    audio = modulate_fsk(payload, cfg)
    assert audio.sample_rate == 44100

    decoded, telemetry = demodulate_fsk(audio, cfg)
    assert decoded == payload
    assert telemetry["crc_valid"] is True
    assert telemetry["ultrasonic"] is True
    assert telemetry["mark_frequency_hz"] == 18500.0
    assert telemetry["space_frequency_hz"] == 20000.0


def test_fsk_arbitrary_delay_resilience():
    """Verify bit clock recovery handles lead-in silence/offsets."""
    payload = b"CLOCK_SYNC_TEST"
    cfg = FSKConfig(baud_rate=300)
    audio = modulate_fsk(payload, cfg)

    # Prepend 73 samples of silence (roughly half a bit period)
    offset_samples = [0] * 73 + audio.samples + [0] * 50
    offset_audio = AudioBuffer(audio.sample_rate, audio.channels, audio.sample_width, offset_samples)

    decoded, telemetry = demodulate_fsk(offset_audio, cfg)
    assert decoded == payload
    assert telemetry["crc_valid"] is True


def test_fsk_multichannel_downmix():
    """Verify stereo audio buffer is gracefully handled."""
    payload = b"STEREO_TEST"
    cfg = FSKConfig(baud_rate=300)
    mono_audio = modulate_fsk(payload, cfg)

    # Convert to stereo by duplicating interleaved samples
    stereo_samples = []
    for s in mono_audio.samples:
        stereo_samples.extend([s, s])

    stereo_audio = AudioBuffer(mono_audio.sample_rate, 2, mono_audio.sample_width, stereo_samples)
    decoded, telemetry = demodulate_fsk(stereo_audio, cfg)
    assert decoded == payload
    assert telemetry["crc_valid"] is True


def test_fsk_corrupted_signal_rejection():
    """Verify corrupted audio or invalid CRC raises ValueError."""
    cfg = FSKConfig(baud_rate=300)
    audio = modulate_fsk(b"VALID_PACKET", cfg)

    # Mutate middle samples to noise
    corrupted_samples = list(audio.samples)
    for i in range(len(corrupted_samples) // 3, len(corrupted_samples) // 2):
        corrupted_samples[i] = 0
    corrupted_audio = AudioBuffer(audio.sample_rate, audio.channels, audio.sample_width, corrupted_samples)

    with pytest.raises(ValueError, match="Demodulation failed"):
        demodulate_fsk(corrupted_audio, cfg)


def test_mcp_fsk_tools():
    """Verify MCP tools for FSK modulation and demodulation."""
    server = MCPServer()
    defs = {t["name"]: t for t in server.get_tool_definitions()}
    assert "audio_modulate_fsk" in defs
    assert "audio_demodulate_fsk" in defs

    # 1. Modulate via MCP
    mod_res = server.handle_tool_call("audio_modulate_fsk", {
        "payload": "MCP_MODEM_TEST",
        "baud_rate": 300,
        "ultrasonic": False
    })
    mod_data = json.loads(mod_res["content"][0]["text"])
    assert mod_data["status"] == "success"
    assert "wav_base64" in mod_data
    assert mod_data["baud_rate"] == 300

    # 2. Demodulate via MCP
    demod_res = server.handle_tool_call("audio_demodulate_fsk", {
        "audio_wav_base64": mod_data["wav_base64"],
        "baud_rate": 300,
        "ultrasonic": False
    })
    demod_data = json.loads(demod_res["content"][0]["text"])
    assert demod_data["status"] == "success"
    assert demod_data["decoded_text"] == "MCP_MODEM_TEST"
    assert demod_data["telemetry"]["crc_valid"] is True


def test_cli_modem_commands(tmp_path, capsys):
    """Verify CLI modem subcommands for modulate and demodulate."""
    wav_out = str(tmp_path / "cli_modem.wav")
    dec_out = str(tmp_path / "cli_decoded.txt")

    # 1. Modulate
    ret1 = cli_main(["modem", "modulate", "CLI_AIRGAP_TEST", "-o", wav_out, "--baud", "300", "--json"])
    assert ret1 == 0
    assert os.path.exists(wav_out)

    captured = capsys.readouterr()
    res1 = json.loads(captured.out)
    assert res1["status"] == "success"
    assert res1["payload_length_bytes"] == len("CLI_AIRGAP_TEST")

    # 2. Demodulate
    ret2 = cli_main(["modem", "demodulate", wav_out, "-o", dec_out, "--baud", "300", "--json"])
    assert ret2 == 0
    assert os.path.exists(dec_out)

    captured2 = capsys.readouterr()
    res2 = json.loads(captured2.out)
    assert res2["status"] == "success"
    assert res2["decoded_text"] == "CLI_AIRGAP_TEST"
    assert res2["telemetry"]["crc_valid"] is True

    with open(dec_out, "rb") as f:
        assert f.read() == b"CLI_AIRGAP_TEST"


def test_ui_server_fsk_endpoints():
    """Verify REST endpoints /api/fsk-modulate and /api/fsk-demodulate."""
    from http.server import HTTPServer
    import io
    from unittest.mock import MagicMock

    # Create dummy handler to test do_POST dispatch
    handler = AudioCipherHTTPHandler.__new__(AudioCipherHTTPHandler)
    handler.headers = {"Content-Length": "0"}

    # Mock send_response and headers
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = io.BytesIO()

    # Test /api/fsk-modulate
    payload_body = json.dumps({
        "payload": "REST_API_MODEM_PAYLOAD",
        "baud_rate": 300,
        "ultrasonic": False
    }).encode("utf-8")
    handler.headers = {"Content-Length": str(len(payload_body))}
    handler.rfile = io.BytesIO(payload_body)
    handler.path = "/api/fsk-modulate"

    handler.do_POST()
    resp_body = handler.wfile.getvalue().decode("utf-8")
    resp_data = json.loads(resp_body)
    assert resp_data["status"] == "success"
    assert "wav_base64" in resp_data
    wav_b64 = resp_data["wav_base64"]

    # Test /api/fsk-demodulate
    demod_body = json.dumps({
        "wav_base64": wav_b64,
        "baud_rate": 300,
        "ultrasonic": False
    }).encode("utf-8")
    handler.wfile = io.BytesIO()
    handler.headers = {"Content-Length": str(len(demod_body))}
    handler.rfile = io.BytesIO(demod_body)
    handler.path = "/api/fsk-demodulate"

    handler.do_POST()
    demod_resp_body = handler.wfile.getvalue().decode("utf-8")
    demod_resp_data = json.loads(demod_resp_body)
    assert demod_resp_data["status"] == "success"
    assert demod_resp_data["decoded_text"] == "REST_API_MODEM_PAYLOAD"
    assert demod_resp_data["telemetry"]["crc_valid"] is True
