"""FFT-based coincidence periodogram for key-length detection.

For each letter a in {A..Z}, build the indicator signal x_a[t] = [letter t == a].
The autocorrelation of x_a at lag k is sum_t x_a[t] * x_a[t+k]; summed across
all 26 letters this counts coincidences at lag k. We compute it efficiently
via the Wiener-Khinchin theorem (autocorrelation = IFFT of power spectrum)
and normalize by the number of overlapping positions n-k.

A peak at lag k means letters that are k apart agree more often than chance,
which is exactly what happens when k is (a multiple of) the Vigenere key length.
"""
from __future__ import annotations

import numpy as np

from ..alphabet import A, SIZE, clean_letters


def _letters_to_codes(text: str) -> np.ndarray:
    s = clean_letters(text)
    if not s:
        return np.zeros(0, dtype=np.int8)
    return np.frombuffer(s.encode("ascii"), dtype=np.uint8).astype(np.int8) - A


def coincidence_periodogram(text: str, kmax: int | None = None) -> np.ndarray:
    """Return length-(n) normalized autocorrelation; index k = coincidences at lag k.

    The first two entries (lag 0, 1) are dominated by trivial self-overlap and
    should not be interpreted as key-length evidence.
    """
    codes = _letters_to_codes(text)
    n = codes.size
    if n == 0:
        return np.zeros(1, dtype=np.float64)

    fft_len = 1 << ((2 * n - 1).bit_length())
    spec = np.zeros(fft_len // 2 + 1, dtype=np.float64)
    for a in range(SIZE):
        x = (codes == a).astype(np.float64)
        X = np.fft.rfft(x, fft_len)
        spec += (X.conj() * X).real
    corr = np.fft.irfft(spec, fft_len)[:n]
    denom = np.arange(n, 0, -1, dtype=np.float64)  # n, n-1, ..., 1
    per = corr / denom
    if kmax is not None:
        per = per[: kmax + 1]
    return per


def pick_periods(per: np.ndarray, kmax: int = 60, top: int = 10) -> list[tuple[int, float]]:
    """Return [(k, score)] sorted desc with non-maximum suppression on harmonics.

    Suppresses neighbours of local maxima and lightly penalizes 2k / 3k harmonics
    so the *fundamental* period dominates the ranking.
    """
    if per.size <= 2:
        return []
    end = min(kmax, per.size - 1)
    idx = np.arange(2, end + 1)
    scores = per[idx].astype(np.float64, copy=True)

    # NMS: dampen neighbours of strict local maxima
    for i in range(1, scores.size - 1):
        if scores[i] > scores[i - 1] and scores[i] > scores[i + 1]:
            scores[i - 1] = min(scores[i - 1], scores[i] * 0.5)
            scores[i + 1] = min(scores[i + 1], scores[i] * 0.5)

    # Harmonic suppression: a strong fundamental k discounts 2k, 3k
    base = scores.copy()
    for i, k in enumerate(idx):
        if base[i] <= 0:
            continue
        for mult in (2, 3):
            j = mult * int(k) - 2  # idx[j] corresponds to lag idx[j]+2
            if 0 <= j < scores.size:
                scores[j] *= 0.8

    pairs = list(zip(idx.tolist(), scores.tolist()))
    pairs.sort(key=lambda t: t[1], reverse=True)
    return pairs[:top]
