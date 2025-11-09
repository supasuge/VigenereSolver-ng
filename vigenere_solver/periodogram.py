"""Periodogram analysis for Vigenère key-length detection."""
from __future__ import annotations

try:  # pragma: no cover - optional dependency
    import numpy as np
except Exception:  # pragma: no cover
    np = None  # type: ignore


def letters_only_upper(s: str) -> np.ndarray:
    if np is None:
        raise ImportError("numpy is required for periodogram analysis")
    return np.fromiter((ord(c) - 65 for c in s.upper() if 'A' <= c <= 'Z'), dtype=np.uint8)


def coincidence_periodogram_fft(text: str, kmax: int | None = None) -> np.ndarray:
    if np is None:
        raise ImportError("numpy is required for periodogram analysis")
    ltr = letters_only_upper(text)
    n = len(ltr)
    if n == 0:
        return np.zeros(1, dtype=np.float64)
    L = 1 << (2 * n - 1).bit_length()
    spec = np.zeros(L // 2 + 1, dtype=np.float64)
    for a in range(26):
        x = (ltr == a).astype(np.float64)
        X = np.fft.rfft(x, L)
        spec += (X.conj() * X).real
    corr = np.fft.irfft(spec, L)[:n]
    denom = np.maximum(1, np.arange(n, 0, -1))
    per = corr / denom
    if kmax:
        per = per[: kmax + 1]
    return per


def pick_periods(sig: np.ndarray, kmax: int = 60, top: int = 10) -> list[tuple[int, float]]:
    if np is None:
        raise ImportError("numpy is required for periodogram analysis")
    idx = np.arange(2, min(kmax, len(sig)))
    scores = sig[idx].copy()

    for i in range(1, len(scores) - 1):
        if scores[i] > scores[i - 1] and scores[i] > scores[i + 1]:
            scores[i - 1] = min(scores[i - 1], scores[i] * 0.5)
            scores[i + 1] = min(scores[i + 1], scores[i] * 0.5)

    base = scores.copy()
    for i in range(len(base)):
        if base[i] <= 0:
            continue
        k = idx[i]
        for mult in (2, 3):
            j = mult * k - 2
            if 0 <= j < len(scores):
                scores[j] *= 0.8

    pairs = list(zip(idx.tolist(), scores.tolist()))
    pairs.sort(key=lambda t: t[1], reverse=True)
    return pairs[:top]



