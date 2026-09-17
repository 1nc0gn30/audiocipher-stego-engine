"""Unit tests for Audio Steganalysis & Carrier Integrity Forensics Engine."""

import base64
import json
import os
import tempfile
import pytest

from audiocipher_stego_engine import (
    AudioBuffer,
    AudioSteganalysisReport,
    MCPServer,
    StegoEngine,
    analyze_audio_steganography,
)
from audiocipher_stego_engine.cli import main as cli_main


def test_clean_audio_steganalysis():
    # Clean 440 Hz sine tone carrier
    clean_audio = AudioBuffer.generate_sine_tone(frequency=440.0, duration=1.0, sample_rate=44100)
    report = analyze_audio_steganography(clean_audio)

    assert isinstance(report, AudioSteganalysisReport)
    assert report.stego_detected is False
    assert report.forensic_verdict == "NATURAL_UNALTERED_AUDIO"
    assert report.confidence_score < 50.0
    assert len(report.anomalies) > 0


def test_lsb_embedded_steganalysis():
    # Embed payload using LSB
    carrier = AudioBuffer.generate_sine_tone(frequency=440.0, duration=1.0, sample_rate=44100)
    secret_msg = b"Top Secret Sovereign Agent Directive #998"
    stego_audio = StegoEngine.embed_lsb(carrier, secret_msg)

    report = analyze_audio_steganography(stego_audio)
    assert report.stego_detected is True
    assert report.detected_technique == "LSB_PCM_INJECTION"
    assert report.confidence_score >= 95.0
    assert report.estimated_payload_bytes == len(secret_msg)
    assert any("STEG" in a for a in report.anomalies)


def test_parity_embedded_steganalysis():
    # Embed payload using Parity Steganography
    carrier = AudioBuffer.generate_sine_tone(frequency=523.25, duration=1.5, sample_rate=44100)
    secret_msg = b"ParityData"
    parity_audio = StegoEngine.embed_parity_stego(carrier, secret_msg, block_size=16)

    report = analyze_audio_steganography(parity_audio)
    assert report.stego_detected is True
    assert report.detected_technique == "PARITY_BLOCK_MODULATION"
    assert report.confidence_score >= 90.0


def test_ultrasonic_embedded_steganalysis():
    carrier = AudioBuffer.generate_sine_tone(frequency=440.0, duration=1.0, sample_rate=44100)
    watermarked = StegoEngine.embed_ultrasonic_watermark(carrier, "UltraMarker")

    report = analyze_audio_steganography(watermarked)
    # Ultrasonic watermark adds 19kHz-20kHz energy
    assert report.high_freq_energy_ratio > 0.05


def test_cli_steganalysis_subcommand(capsys):
    carrier = AudioBuffer.generate_sine_tone(frequency=440.0, duration=0.5, sample_rate=44100)
    stego = StegoEngine.embed_lsb(carrier, b"CLI_STEGO_TEST")

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_path = f.name
        f.write(stego.to_wav_bytes())

    try:
        ret = cli_main(["steganalysis", tmp_path, "--json"])
        assert ret == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["stego_detected"] is True
        assert data["detected_technique"] == "LSB_PCM_INJECTION"
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def test_mcp_audio_steganalysis_tool():
    mcp = MCPServer()
    carrier = AudioBuffer.generate_sine_tone(frequency=440.0, duration=0.5, sample_rate=44100)
    stego = StegoEngine.embed_lsb(carrier, b"MCP_STEGO_PROBE")
    wav_b64 = base64.b64encode(stego.to_wav_bytes()).decode("ascii")

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": "steg-mcp-1",
        "method": "tools/call",
        "params": {
            "name": "audio_steganalysis",
            "arguments": {"carrier_wav_base64": wav_b64}
        }
    })

    resp = json.loads(mcp.handle_request(req))
    assert "result" in resp
    content = json.loads(resp["result"]["content"][0]["text"])
    assert content["stego_detected"] is True
    assert content["detected_technique"] == "LSB_PCM_INJECTION"
