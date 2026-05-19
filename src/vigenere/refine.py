"""Dictionary-assisted key refinement.

Given a candidate key with possibly a few wrong positions, slide every word in
a dictionary against the ciphertext. Whenever a word matches with at most
`max_mismatch` mismatched key positions, register a vote at each disagreeing
position for the shift value the word implies. After scanning, take the
majority vote per position.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from .alphabet import A, SIZE, clean_letters


def load_wordlist(
    path: str,
    min_len: int = 3,
    max_len: int = 12,
    limit: int | None = 50_000,
) -> list[str]:
    seen: set[str] = set()
    words: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = clean_letters(line.strip())
            if not w or w in seen:
                continue
            if min_len <= len(w) <= max_len:
                words.append(w)
                seen.add(w)
                if limit and len(words) >= limit:
                    break
    # Longer words give stronger constraints, score first.
    words.sort(key=lambda x: (-len(x), x))
    return words


def _majority(values: Iterable[int]) -> int:
    counts = Counter(v % SIZE for v in values)
    (value, _), *_ = counts.most_common(1)
    return value


def refine_key(
    ciphertext: str,
    key: str,
    words: list[str],
    *,
    max_iter: int = 2,
    max_mismatch: int = 1,
) -> str:
    """Iteratively refine `key` against the wordlist; return the corrected key."""
    C = clean_letters(ciphertext)
    if not C:
        return key
    key_clean = clean_letters(key)
    if not key_clean:
        return key
    m = len(key_clean)
    key_idx = [ord(c) - A for c in key_clean]

    for _ in range(max_iter):
        votes: dict[int, list[int]] = defaultdict(list)
        for w in words:
            L = len(w)
            if L > len(C):
                continue
            for i in range(len(C) - L + 1):
                miss = 0
                pending: list[tuple[int, int]] = []
                ok = True
                for j in range(L):
                    kp = (i + j) % m
                    need = (ord(C[i + j]) - A - (ord(w[j]) - A)) % SIZE
                    if need != key_idx[kp]:
                        miss += 1
                        if miss > max_mismatch:
                            ok = False
                            break
                    pending.append((kp, need))
                if ok:
                    for kp, need in pending:
                        votes[kp].append(need)

        changed = False
        for pos, vals in votes.items():
            v = _majority(vals)
            if v != key_idx[pos]:
                key_idx[pos] = v
                changed = True
        if not changed:
            break

    return "".join(chr(A + v) for v in key_idx)
