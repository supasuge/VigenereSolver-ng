"""Beam search over per-strip Caesar-shift candidates.

For a fixed key length k we:
  1. Slice the ciphertext into k columns (strips).
  2. For each strip, score all 26 possible shifts by comparing the decrypted
     letter histogram to the English unigram prior (negative JSD). Keep the
     top `strip_top` shifts.
  3. Beam-search across strips to build full-key candidates, scoring beams by
     the sum of per-strip shift scores.
"""
from __future__ import annotations

from .alphabet import A, SIZE, clean_letters, shift_only, split_strips
from .stats import histogram, jensen_shannon

Candidate = tuple[int, float]  # (shift, neg-JSD score)


def per_strip_candidates(
    ciphertext: str,
    keylen: int,
    prior: list[float],
    top_m: int = 6,
) -> list[list[Candidate]]:
    """Return [[(shift, score), ...], ...] - one list per strip, sorted desc."""
    letters = clean_letters(ciphertext)
    out: list[list[Candidate]] = []
    for strip in split_strips(letters, keylen):
        cands: list[Candidate] = []
        for shift in range(SIZE):
            dec = shift_only(strip, shift)
            cands.append((shift, -jensen_shannon(histogram(dec), prior)))
        cands.sort(key=lambda t: t[1], reverse=True)
        out.append(cands[:top_m])
    return out


def beam_search(
    per_strip: list[list[Candidate]],
    beam: int = 16,
) -> list[tuple[str, float]]:
    """Beam-search across strips. Returns [(key, score)] sorted desc."""
    beams: list[tuple[str, float]] = [("", 0.0)]
    for cands in per_strip:
        nxt: list[tuple[str, float]] = []
        for prefix, score in beams:
            for shift, sc in cands:
                nxt.append((prefix + chr(A + shift), score + sc))
        nxt.sort(key=lambda t: t[1], reverse=True)
        beams = nxt[:beam]
    return beams
