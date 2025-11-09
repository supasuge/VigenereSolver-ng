"""Kasiski examination implementation."""
from __future__ import annotations

from typing import Dict, List
from collections import Counter


def clean_upper_letters(text: str) -> str:
    return "".join(ch for ch in text.upper() if 'A' <= ch <= 'Z')


def kasiski_examination(text: str, min_len: int = 3, max_len: int = 5, kmax: int = 60) -> List[int]:
    s = clean_upper_letters(text)
    positions: Dict[str, List[int]] = {}
    for length in range(min_len, max_len + 1):
        for i in range(0, len(s) - length + 1):
            sub = s[i : i + length]
            positions.setdefault(sub, []).append(i)
    distances: List[int] = []
    for xs in positions.values():
        if len(xs) < 2:
            continue
        for i in range(len(xs) - 1):
            d = xs[i + 1] - xs[i]
            if d > 1:
                distances.append(d)
    if not distances:
        return []

    def _factors(d: int) -> List[int]:
        out: List[int] = []
        for k in range(2, min(kmax, d) + 1):
            if d % k == 0:
                out.append(k)
        return out

    all_factors: List[int] = []
    for d in distances:
        all_factors.extend(_factors(d))
    counts = Counter(all_factors)
    return [k for (k, _) in counts.most_common()]


