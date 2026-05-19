"""Kasiski examination: factor-vote over repeated-substring distances."""
from __future__ import annotations

from collections import Counter, defaultdict

from ..alphabet import clean_letters


def _factors(d: int, kmax: int) -> list[int]:
    return [k for k in range(2, min(kmax, d) + 1) if d % k == 0]


def kasiski_examination(
    text: str,
    min_len: int = 3,
    max_len: int = 5,
    kmax: int = 60,
) -> list[tuple[int, int]]:
    """Return [(keylen_guess, vote_count)] sorted by vote desc.

    A repeated substring of length L at positions p1 < p2 implies that the key
    likely divides p2 - p1. We tabulate every divisor in [2, kmax] of every
    inter-occurrence distance and rank by frequency.
    """
    s = clean_letters(text)
    positions: dict[str, list[int]] = defaultdict(list)
    for L in range(min_len, max_len + 1):
        for i in range(len(s) - L + 1):
            positions[s[i : i + L]].append(i)

    votes: Counter[int] = Counter()
    for plist in positions.values():
        if len(plist) < 2:
            continue
        for i in range(len(plist) - 1):
            d = plist[i + 1] - plist[i]
            if d > 1:
                votes.update(_factors(d, kmax))

    return votes.most_common()
