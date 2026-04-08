"""Utility helpers for Vigenère cipher operations and statistics."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple, List, Optional
import json
import random

A, Z = ord('A'), ord('Z')
ALPH = [chr(A + i) for i in range(26)]


def clean_upper_letters(s: str) -> str:
    """Return only uppercase ASCII letters from ``s``."""
    return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')


def counts26(text: str) -> Tuple[List[int], int]:
    """Count uppercase letters in ``text``.

    Returns a pair ``(counts, total_letters)``.
    """
    counts = [0] * 26
    total = 0
    for ch in text:
        o = ord(ch)
        if A <= o <= Z:
            counts[o - A] += 1
            total += 1
    return counts, total


def encrypt_vigenere(text: str, key: str) -> str:
    key = key.upper()
    out: List[str] = []
    i = 0
    for ch in text:
        if 'A' <= ch.upper() <= 'Z':
            p = ord(ch.upper()) - A
            k = ord(key[i % len(key)]) - A
            out.append(chr(A + ((p + k) % 26)))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def decrypt_vigenere(text: str, key: str) -> str:
    key = key.upper()
    out: List[str] = []
    i = 0
    for ch in text:
        if 'A' <= ch.upper() <= 'Z':
            c = ord(ch.upper()) - A
            k = ord(key[i % len(key)]) - A
            out.append(chr(A + ((c - k) % 26)))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def random_key(length: int) -> str:
    import string
    return "".join(random.choice(string.ascii_uppercase) for _ in range(length))


@dataclass
class LanguageModel:
    name: str
    monograms: Dict[str, float]
    bigrams: Dict[str, float]
    trigrams: Dict[str, float]
    quadgrams: Dict[str, float]
    quintgrams: Dict[str, float]


def _upper_keys(data: Dict[str, float]) -> Dict[str, float]:
    return {k.upper(): float(v) for k, v in data.items()}


def load_language_data(path: Path | str = "language_data.json") -> LanguageModel:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return LanguageModel(
        name="english",
        monograms=_upper_keys(data["english_monograms"]),
        bigrams=_upper_keys(data.get("english_bigrams_1", {})),
        trigrams=_upper_keys(data["english_trigrams"]),
        quadgrams=_upper_keys(data["english_quadgrams"]),
        quintgrams=_upper_keys(data["english_quintgrams"]),
    )


