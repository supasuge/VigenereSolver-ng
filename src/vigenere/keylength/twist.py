"""Twist & Twist++ key-length scoring (Barr & Simoes, 2015).

For each candidate key length ``m``:

  1. Partition the ciphertext into ``m`` strips ("cosets") containing every
     m-th letter starting from offset 0..m-1.
  2. For each strip compute the per-letter frequency vector and sort it in
     **descending** order — this discards which letter is which but
     preserves the *shape* of the distribution.
  3. Average those sorted vectors across strips → :math:`\\bar P`. If every
     strip is a shifted English text, :math:`\\bar P` should look like the
     sorted English unigram distribution.
  4. The **twist** is:

       :math:`T(m) = \\sum_{i=0}^{12} \\bar P_i - \\sum_{i=13}^{25} \\bar P_i`

     equivalently :math:`T(m) = 1 - 2 \\sum_{i \\ge 13} \\bar P_i`.
     :math:`T \\in [0, 1]`. Uniform → 0, English ≈ 0.70.

The **twist++** variant subtracts the running mean of the smaller-k twists:

  :math:`T^{++}(m) = T(m) - \\tfrac{1}{m-1} \\sum_{j=1}^{m-1} T(j)`

This penalises harmonics of the true period: if :math:`m^\\star` is the true
key length, then :math:`2 m^\\star` also produces "shifted-English" strips
and would tie with :math:`m^\\star` under bare twist; subtracting the
running mean breaks the tie in favour of the fundamental.

References
----------
* Barr, T. H. and Simoes, A. J., 2015.
  "Cryptanalysis of the Vigenère cipher using the twist algorithm."
"""
from __future__ import annotations

from functools import lru_cache

from ..alphabet import A, SIZE, clean_letters, split_strips

HALF = SIZE // 2  # 13


def twist_score(text: str, k: int) -> float:
    """Basic twist score :math:`T(k)` for key length ``k``.

    Returns 0.0 for ``k < 1`` or empty input.
    """
    if k < 1:
        return 0.0
    letters = clean_letters(text)
    if not letters:
        return 0.0
    avg = [0.0] * SIZE
    valid = 0
    for strip in split_strips(letters, k):
        if not strip:
            continue
        counts = [0] * SIZE
        for ch in strip:
            counts[ord(ch) - A] += 1
        n = sum(counts)
        if n == 0:
            continue
        sorted_freqs = sorted((c / n for c in counts), reverse=True)
        for i, f in enumerate(sorted_freqs):
            avg[i] += f
        valid += 1
    if valid == 0:
        return 0.0
    avg = [x / valid for x in avg]
    return sum(avg[:HALF]) - sum(avg[HALF:])


def twist_table(text: str, max_k: int = 40) -> list[float]:
    """Return ``[T(1), T(2), ..., T(max_k)]`` (index 0 unused)."""
    out = [0.0] * (max_k + 1)
    for k in range(1, max_k + 1):
        out[k] = twist_score(text, k)
    return out


def twist_plus_plus_table(text: str, max_k: int = 40) -> list[float]:
    """Return ``[T++(1), ..., T++(max_k)]`` with the running-mean correction."""
    return list(_twist_plus_plus_cached(text, max_k))


@lru_cache(maxsize=8)
def _twist_plus_plus_cached(text: str, max_k: int) -> tuple[float, ...]:
    """Cached inner; tuple is hashable and cheap to copy."""
    raw = twist_table(text, max_k)
    out = [0.0] * (max_k + 1)
    cumsum = 0.0
    count = 0
    for k in range(1, max_k + 1):
        out[k] = raw[k] - (cumsum / count if count else 0.0)
        cumsum += raw[k]
        count += 1
    return tuple(out)


def twist_plus_plus_score(text: str, k: int, max_k: int = 40) -> float:
    """Single-k convenience wrapper around :func:`twist_plus_plus_table`.

    The full ``T++`` table is :math:`O(k_\\max^2)` to compute, but successive
    calls with the same ``text`` and ``max_k`` hit an LRU cache and return
    in :math:`O(1)`. If you need many ``k`` values for one text, prefer
    :func:`twist_plus_plus_table` to make the cost explicit.
    """
    if k < 1 or k > max_k:
        return 0.0
    return _twist_plus_plus_cached(text, max(max_k, k))[k]
