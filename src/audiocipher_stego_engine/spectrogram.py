"""
Morse Code Audio Synthesizer & Spectrogram Visual Pattern Generator.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import math
from typing import Dict, List

from audiocipher_stego_engine.wav_codec import AudioBuffer

MORSE_CODE_DICT: Dict[str, str] = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    "0": "-----", " ": "/", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "-": "-....-", "/": "-..-.", "@": ".--.-.", "!": "-.-.--"
}


def text_to_morse(text: str) -> str:
    """Convert plaintext into standard Morse code notation."""
    morse_chars = []
    for char in text.upper():
        if char in MORSE_CODE_DICT:
            morse_chars.append(MORSE_CODE_DICT[char])
    return " ".join(morse_chars)


def synthesize_morse_audio(
    text: str,
    tone_frequency: float = 800.0,
    wpm: int = 20,
    sample_rate: int = 44100,
    amplitude: float = 0.5
) -> AudioBuffer:
    """
    Synthesize an acoustic PCM WAV buffer playing Morse code for input text.
    Standard timing: dot = 1.2 / wpm seconds, dash = 3 * dot, intra-char gap = 1 dot, word gap = 7 dots.
    """
    dot_duration = 1.2 / max(5, wpm)
    dash_duration = 3 * dot_duration
    intra_char_gap = dot_duration
    inter_char_gap = 3 * dot_duration
    inter_word_gap = 7 * dot_duration

    morse_str = text_to_morse(text)
    samples: List[int] = []
    max_amp = 32767 * amplitude

    def append_tone(duration: float) -> None:
        num_samples = int(sample_rate * duration)
        for i in range(num_samples):
            t = i / sample_rate
            val = int(max_amp * math.sin(2.0 * math.pi * tone_frequency * t))
            samples.append(val)

    def append_silence(duration: float) -> None:
        num_samples = int(sample_rate * duration)
        samples.extend([0] * num_samples)

    for char_code in morse_str.split(" "):
        if char_code == "/":
            append_silence(inter_word_gap)
            continue

        for symbol in char_code:
            if symbol == ".":
                append_tone(dot_duration)
            elif symbol == "-":
                append_tone(dash_duration)
            append_silence(intra_char_gap)

        append_silence(inter_char_gap - intra_char_gap)

    return AudioBuffer(
        sample_rate=sample_rate,
        channels=1,
        sample_width=2,
        samples=samples
    )


def synthesize_spectrogram_watermark(
    glyph_bitmap: List[List[int]],
    freq_min: float = 5000.0,
    freq_max: float = 12000.0,
    pixel_duration: float = 0.04,
    sample_rate: int = 44100
) -> AudioBuffer:
    """
    Synthesize visual raster pattern into audio frequency spectrogram bands.
    glyph_bitmap: 2D array of 0s and 1s representing pixel grid.
    """
    rows = len(glyph_bitmap)
    if rows == 0:
        return AudioBuffer(sample_rate=sample_rate, channels=1, sample_width=2, samples=[])

    cols = len(glyph_bitmap[0])
    freq_step = (freq_max - freq_min) / max(1, rows - 1) if rows > 1 else 0

    samples_per_col = int(sample_rate * pixel_duration)
    samples: List[int] = []

    for c in range(cols):
        active_freqs = []
        for r in range(rows):
            # Invert Y so row 0 is at high frequency (top of spectrogram)
            if glyph_bitmap[r][c] == 1:
                freq = freq_max - r * freq_step
                active_freqs.append(freq)

        if not active_freqs:
            samples.extend([0] * samples_per_col)
            continue

        scale = (32767 * 0.4) / max(1, len(active_freqs))
        for i in range(samples_per_col):
            t = i / sample_rate
            val = int(scale * sum(math.sin(2.0 * math.pi * f * t) for f in active_freqs))
            samples.append(val)

    return AudioBuffer(
        sample_rate=sample_rate,
        channels=1,
        sample_width=2,
        samples=samples
    )


# DTMF (Dual-Tone Multi-Frequency) Keypad Matrix
DTMF_MAP: Dict[Tuple[int, int], str] = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
}
DTMF_FREQS: Dict[str, Tuple[int, int]] = {v: k for k, v in DTMF_MAP.items()}
DTMF_ROW_FREQS = [697, 770, 852, 941]
DTMF_COL_FREQS = [1209, 1336, 1477, 1633]


def synthesize_dtmf_audio(
    digits: str,
    tone_duration: float = 0.1,
    silence_duration: float = 0.05,
    sample_rate: int = 8000,
    amplitude: float = 0.5
) -> AudioBuffer:
    """
    Synthesize an acoustic PCM WAV buffer playing a DTMF telephone key sequence.
    digits: string of characters (0-9, A-D, *, #).
    """
    samples: List[int] = []
    max_amp = (32767 * amplitude) / 2.0
    tone_samples = int(sample_rate * max(0.02, tone_duration))
    silence_samples = int(sample_rate * max(0.01, silence_duration))

    for char in digits.upper():
        if char not in DTMF_FREQS:
            continue
        row_f, col_f = DTMF_FREQS[char]
        for i in range(tone_samples):
            t = i / sample_rate
            val = int(max_amp * (math.sin(2.0 * math.pi * row_f * t) + math.sin(2.0 * math.pi * col_f * t)))
            samples.append(val)
        samples.extend([0] * silence_samples)

    return AudioBuffer(
        sample_rate=sample_rate,
        channels=1,
        sample_width=2,
        samples=samples
    )


def goertzel_magnitude(samples: List[int], target_freq: float, sample_rate: int) -> float:
    """Compute relative energy at a target frequency using Goertzel algorithm (O(N) vs O(N log N) FFT)."""
    n = len(samples)
    if n == 0:
        return 0.0
    k = int(0.5 + (n * target_freq) / sample_rate)
    omega = (2.0 * math.pi * k) / n
    coeff = 2.0 * math.cos(omega)
    s_prev = 0.0
    s_prev2 = 0.0
    for s in samples:
        curr = s + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = curr
    return s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2


def decode_dtmf_audio(
    audio: AudioBuffer,
    tone_duration: float = 0.1,
    silence_duration: float = 0.05
) -> str:
    """
    Decode DTMF acoustic signals into digits using Goertzel dual-tone frequency detection.
    """
    sr = audio.sample_rate
    samples = audio.samples
    if not samples:
        return ""

    chunk_size = int(sr * (tone_duration + silence_duration))
    tone_len = int(sr * tone_duration)
    decoded: List[str] = []

    for offset in range(0, len(samples), chunk_size):
        chunk = samples[offset: offset + tone_len]
        if len(chunk) < 50:
            break
        avg_power = sum(s * s for s in chunk) / len(chunk)
        if avg_power < 500:  # Silence threshold
            continue

        row_powers = {f: goertzel_magnitude(chunk, f, sr) for f in DTMF_ROW_FREQS}
        col_powers = {f: goertzel_magnitude(chunk, f, sr) for f in DTMF_COL_FREQS}

        best_row = max(row_powers, key=row_powers.get)
        best_col = max(col_powers, key=col_powers.get)

        char = DTMF_MAP.get((best_row, best_col), "")
        if char:
            decoded.append(char)

    return "".join(decoded)

