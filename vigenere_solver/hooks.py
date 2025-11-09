"""Dictionary-assisted key correction hooks."""
from __future__ import annotations

from typing import List, Dict, Iterable, Tuple
from collections import defaultdict, Counter

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def load_wordlist(path: str, min_len: int = 3, max_len: int = 12, limit: int | None = 50000) -> List[str]:
    words: List[str] = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = "".join(ch for ch in line.strip().upper() if 'A' <= ch <= 'Z')
            if not w or w in seen:
                continue
            if min_len <= len(w) <= max_len:
                words.append(w)
                seen.add(w)
                if limit and len(words) >= limit:
                    break
    words.sort(key=lambda x: (-len(x), x))
    return words


def _alpha_only_upper(s: str) -> str:
    return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')


def _majority(values: Iterable[int]) -> int:
    counts = Counter(v % 26 for v in values)
    (value, _), *_ = counts.most_common(1)
    return value


def correct_key_with_wordlist(
    ciphertext: str,
    key: str,
    words: List[str],
    max_iter: int = 2,
    max_mismatch: int = 1,
) -> str:
    """Use a sliding dictionary to refine the candidate key."""

    C = _alpha_only_upper(ciphertext)
    m = len(key)
    key_idx = [ord(c) - 65 for c in key.upper()]

    for _ in range(max_iter):
        constraints: Dict[int, List[int]] = defaultdict(list)
        for word in words:
            length = len(word)
            if length > len(C):
                continue
            for i in range(0, len(C) - length + 1):
                mismatches = 0
                req: List[Tuple[int, int]] = []
                for j in range(length):
                    kp = (i + j) % m
                    need = (ord(C[i + j]) - 65 - (ord(word[j]) - 65)) % 26
                    if need != key_idx[kp]:
                        mismatches += 1
                        if mismatches > max_mismatch:
                            break
                    req.append((kp, need))
                if mismatches <= max_mismatch:
                    for kp, need in req:
                        constraints[kp].append(need)

        changed = False
        for pos, vals in constraints.items():
            if not vals:
                continue
            v = _majority(vals)
            if v != key_idx[pos]:
                key_idx[pos] = v
                changed = True
        if not changed:
            break

    return "".join(chr(65 + v % 26) for v in key_idx)


