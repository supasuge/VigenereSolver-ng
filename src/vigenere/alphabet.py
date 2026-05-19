"""Alphabet primitives and Vigenere encrypt/decrypt.

Pure-Python, no numpy. The cipher functions preserve non-alphabetic characters
(spaces, punctuation, digits, newlines) and only shift A-Z. Case is normalized
to upper-case on output.
"""
from __future__ import annotations

import random
import string
from typing import Iterable, Iterator

A = ord("A")
ALPHABET = string.ascii_uppercase
SIZE = 26


def clean_letters(text: str) -> str:
    """Strip everything but ASCII letters and return upper-case."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def _key_shifts(key: str) -> list[int]:
    cleaned = clean_letters(key)
    if not cleaned:
        raise ValueError("key must contain at least one letter")
    return [ord(c) - A for c in cleaned]


def _transform(text: str, key: str, sign: int) -> str:
    shifts = _key_shifts(key)
    klen = len(shifts)
    out: list[str] = []
    i = 0
    for ch in text:
        up = ch.upper()
        if "A" <= up <= "Z":
            v = (ord(up) - A + sign * shifts[i % klen]) % SIZE
            out.append(chr(A + v))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt(text: str, key: str) -> str:
    """Vigenere encrypt - non-letters pass through, letters become upper-case."""
    return _transform(text, key, +1)


def decrypt(text: str, key: str) -> str:
    """Vigenere decrypt - inverse of encrypt()."""
    return _transform(text, key, -1)


def shift_only(letters: str, shift: int) -> str:
    """Caesar-shift a *letters-only* string by `shift` positions (decrypt direction)."""
    return "".join(chr(A + (ord(c) - A - shift) % SIZE) for c in letters)


def split_strips(letters: str, keylen: int) -> list[str]:
    """Split a letters-only string into `keylen` columns (strips)."""
    if keylen <= 0:
        raise ValueError("keylen must be positive")
    return ["".join(letters[i::keylen]) for i in range(keylen)]


def random_key(length: int, rng: random.Random | None = None) -> str:
    """Generate a uniformly random upper-case key of the given length."""
    if length <= 0:
        raise ValueError("length must be positive")
    r = rng or random
    return "".join(r.choice(ALPHABET) for _ in range(length))


def iter_letters(text: str) -> Iterator[str]:
    for ch in text.upper():
        if "A" <= ch <= "Z":
            yield ch
