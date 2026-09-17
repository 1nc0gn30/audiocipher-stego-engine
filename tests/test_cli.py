"""Tests for CLI subcommands."""

import pytest
from audiocipher_stego_engine.cli import main
from audiocipher_stego_engine.wav_codec import AudioBuffer


def test_cli_help(capsys):
    ret = main([])
    assert ret == 0
    out = capsys.readouterr().out
    assert "audiocipher" in out

    with pytest.raises(SystemExit):
        main(["--help"])


def test_cli_encrypt_and_decrypt(tmp_path, capsys):
    key_wav = tmp_path / "key.wav"
    tone = AudioBuffer.generate_sine_tone(440.0, 0.5)
    key_wav.write_bytes(tone.to_wav_bytes())

    payload_file = tmp_path / "secret.txt"
    payload_file.write_text("Sovereign Protocol 757")

    enc_file = tmp_path / "enc.bin"
    dec_file = tmp_path / "dec.txt"

    ret_enc = main(["encrypt", str(payload_file), "-k", str(key_wav), "--volume", "40.0", "-o", str(enc_file)])
    assert ret_enc == 0
    assert enc_file.exists()

    ret_dec = main(["decrypt", str(enc_file), "-k", str(key_wav), "--volume", "40.0", "-o", str(dec_file)])
    assert ret_dec == 0
    assert dec_file.exists()
    assert dec_file.read_text() == "Sovereign Protocol 757"


def test_cli_embed_and_extract(tmp_path, capsys):
    payload_file = tmp_path / "data.txt"
    payload_file.write_text("Acoustic Stego Message")

    stego_wav = tmp_path / "stego.wav"
    extracted_file = tmp_path / "extracted.txt"

    ret_emb = main(["embed", str(payload_file), "-o", str(stego_wav)])
    assert ret_emb == 0
    assert stego_wav.exists()

    ret_ext = main(["extract", str(stego_wav), "-o", str(extracted_file)])
    assert ret_ext == 0
    assert extracted_file.exists()
    assert extracted_file.read_text() == "Acoustic Stego Message"


def test_cli_morse(tmp_path, capsys):
    morse_wav = tmp_path / "morse.wav"
    ret = main(["morse", "SOS 757", "-o", str(morse_wav)])
    assert ret == 0
    assert morse_wav.exists()


def test_cli_doctor(capsys):
    ret = main(["doctor"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "HEALTHY" in out


def test_cli_test_self(capsys):
    ret = main(["test-self"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "All internal checks passed" in out
