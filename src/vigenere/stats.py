"""Distributional statistics: counts, histograms, IoC, JSD."""
from __future__ import annotations

from math import log
from typing import Sequence

from .alphabet import A, SIZE, clean_letters, split_strips


def counts(text: str) -> tuple[list[int], int]:
    """Return (per-letter counts of length 26, total letters)."""
    c = [0] * SIZE
    n = 0
    for ch in text:
        o = ord(ch.upper()) - A
        if 0 <= o < SIZE:
            c[o] += 1
            n += 1
    return c, n


def histogram(text: str) -> list[float]:
    """Normalized letter histogram of length 26."""
    c, n = counts(text)
    if n == 0:
        return [0.0] * SIZE
    inv = 1.0 / n
    return [x * inv for x in c]


def index_of_coincidence(text: str) -> float:
    """Per-text IoC normalized so a uniform alphabet ~= 1.0 and English ~= 1.73."""
    c, n = counts(text)
    if n < 2:
        return 0.0
    num = sum(x * (x - 1) for x in c)
    den = n * (n - 1) / SIZE
    return num / den if den else 0.0


def average_strip_ioc(text: str, keylen: int) -> float:
    """Mean per-strip IoC for the given hypothesized key length."""
    if keylen < 1:
        raise ValueError("keylen must be >= 1")
    letters = clean_letters(text)
    if not letters:
        return 0.0
    acc = 0.0
    cnt = 0
    for strip in split_strips(letters, keylen):
        v = index_of_coincidence(strip)
        if v:
            acc += v
            cnt += 1
    return acc / cnt if cnt else 0.0


def kl_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    s = 0.0
    for pi, qi in zip(p, q):
        if pi > 0.0 and qi > 0.0:
            s += pi * log(pi / qi)
    return s


def jensen_shannon(p: Sequence[float], q: Sequence[float]) -> float:
    """Symmetric divergence in [0, log 2]. Lower = more similar."""
    m = [(pi + qi) * 0.5 for pi, qi in zip(p, q)]
    return 0.5 * kl_divergence(p, m) + 0.5 * kl_divergence(q, m)
