"""Key-match heuristics.

The recovered key can be:
  * **exact** — verbatim equal to the true key
  * **rotational** — a cyclic rotation of the true key (e.g. solver locked
    onto offset 2: ``MONLE`` vs ``LEMON``)
  * **multiple** — an integer repetition (``LEMONLEMON`` vs ``LEMON``);
    the *plaintext* is identical either way
  * **close** — within ``max_diff`` letter substitutions of the true key
    (or one of its rotations / multiples)

This module gives precise definitions and a single ``classify_match``
entry point used by tests, the bench harness, and the progress UI.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .alphabet import A, SIZE, clean_letters

MatchKind = Literal["exact", "rotation", "multiple", "close", "none"]


def hamming(a: str, b: str) -> int:
    """Number of positions where ``a`` and ``b`` differ (length-aligned)."""
    if len(a) != len(b):
        raise ValueError("hamming requires equal-length strings")
    return sum(1 for x, y in zip(a, b) if x != y)


def cyclic_distance(pred: str, true: str) -> int:
    """Min Hamming distance over all cyclic rotations of ``pred`` against ``true``.

    Inputs are normalized via :func:`clean_letters` before the length check,
    so ``cyclic_distance("le-mon", "LEMON")`` works as expected.
    Returns 0 iff (cleaned) ``pred`` is a rotation of (cleaned) ``true``.
    """
    pred = clean_letters(pred)
    true = clean_letters(true)
    if not pred or len(pred) != len(true):
        return max(len(pred), len(true))
    n = len(true)
    return min(hamming(pred[i:] + pred[:i], true) for i in range(n))


def expand_to(pred: str, target_len: int) -> str | None:
    """If ``pred`` is a repetition of a shorter key, expand/truncate to length.

    Returns ``None`` when expansion is impossible.
    """
    if not pred:
        return None
    if len(pred) == target_len:
        return pred
    if len(pred) % target_len == 0 and len(pred) > target_len:
        first = pred[:target_len]
        if pred == first * (len(pred) // target_len):
            return first
        return None
    if target_len % len(pred) == 0:
        return pred * (target_len // len(pred))
    return None


@dataclass(frozen=True)
class MatchResult:
    kind: MatchKind
    distance: int       # Hamming distance under the best alignment (0 = perfect)
    aligned_pred: str   # `pred` rotated/expanded to match `true`'s length
    note: str = ""

    @property
    def is_correct(self) -> bool:
        """True for exact / rotation / multiple (== plaintext is recovered)."""
        return self.kind in ("exact", "rotation", "multiple")

    @property
    def is_close(self) -> bool:
        return self.kind in ("exact", "rotation", "multiple", "close")


def classify_match(pred: str, true: str, max_diff: int = 2) -> MatchResult:
    """Compare a recovered key against a true key.

    Search order: exact ➔ multiple-rotation ➔ rotation ➔ close (Hamming ≤ N).
    """
    pred = clean_letters(pred)
    true = clean_letters(true)
    if not pred or not true:
        return MatchResult("none", max(len(pred), len(true)), pred,
                           "empty input")

    if pred == true:
        return MatchResult("exact", 0, pred, "")

    # Multiple of true key (e.g. LEMONLEMON ↔ LEMON). Requires strictly
    # more than one repetition so a same-length rotation falls through to
    # the dedicated rotation branch below.
    if len(pred) > len(true) and len(pred) % len(true) == 0:
        reps = len(pred) // len(true)
        for r in range(len(true)):
            rotated = true[r:] + true[:r]
            expanded = rotated * reps
            if expanded == pred:
                return MatchResult("multiple", 0, expanded,
                                   f"pred = (true rot{r}) x {reps}")

    # Pure rotation
    aligned = expand_to(pred, len(true))
    if aligned is not None and len(aligned) == len(true):
        d = cyclic_distance(aligned, true)
        if d == 0:
            return MatchResult("rotation", 0, aligned, "rotation match")
        if d <= max_diff:
            return MatchResult("close", d, aligned,
                               f"close: {d} mismatches under best rotation")

    # Same length but different shifts
    if len(pred) == len(true):
        d = cyclic_distance(pred, true)
        if d <= max_diff:
            return MatchResult("close", d, pred,
                               f"close: {d} mismatches under best rotation")
        return MatchResult("none", d, pred,
                           f"diverged: {d} mismatches under best rotation")

    return MatchResult("none", max(len(pred), len(true)), pred,
                       f"length mismatch (pred={len(pred)}, true={len(true)})")
