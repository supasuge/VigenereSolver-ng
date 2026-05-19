"""Hyperparameter tuning for the key-length posterior.

The combined posterior weights ``(w_ioc, w_kasiski, w_periodogram, w_twist)``
were originally hand-picked. This module learns them from labelled data.

Given a corpus of ``(ciphertext, true_keylen)`` pairs, we model the
posterior as a softmax over the four z-scored signals:

  :math:`P(k \\mid \\text{ct}; w) = \\dfrac{\\exp(w \\cdot s(k))}{\\sum_{k'} \\exp(w \\cdot s(k'))}`

and maximize the average log-likelihood of the true key length:

  :math:`L(w) = \\dfrac{1}{N} \\sum_{i=1}^{N} \\log P(k_i^\\star \\mid \\text{ct}_i; w)`

The gradient is closed-form:

  :math:`\\nabla_w L = \\dfrac{1}{N} \\sum_i \\big( s_i(k_i^\\star) - \\mathbb{E}_{P_i}[s_i(k)] \\big)`

We optimize with plain gradient ascent. No scipy dependency — numpy is
already required.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

from .alphabet import clean_letters
from .keylength.kasiski import kasiski_examination
from .keylength.periodogram import coincidence_periodogram, pick_periods
from .keylength.twist import twist_plus_plus_table
from .stats import average_strip_ioc


@dataclass
class TuneResult:
    weights: tuple[float, float, float, float]  # (ioc, kasiski, periodogram, twist)
    log_likelihood: float
    top1_acc: float    # fraction of examples where the true keylen ranks #1
    top3_acc: float    # ... ranks in top 3
    n_examples: int
    n_epochs: int


# ---------------------------------------------------------------------------
# Signal extraction
# ---------------------------------------------------------------------------

def _signal_matrix(text: str, max_k: int) -> tuple[np.ndarray, list[int]]:
    """Return (S, ks) where S is shape (n_k, 4) of z-scored signals.

    Columns: ``[z_ioc, kasiski_hit, z_periodogram, z_twist_pp]``.
    Rows are key lengths from 2..max_k (so n_k = max_k-1).
    """
    per = coincidence_periodogram(text, kmax=max_k)
    peaks = pick_periods(per, kmax=max_k, top=max(10, max_k // 2))

    ioc = np.zeros(max_k + 1, dtype=np.float64)
    for k in range(2, max_k + 1):
        ioc[k] = average_strip_ioc(text, k)
    twist_pp = np.asarray(twist_plus_plus_table(text, max_k), dtype=np.float64)

    kas_pairs = kasiski_examination(text, kmax=max_k)
    kas_topset = {k for k, _ in kas_pairs[: max(5, len(kas_pairs) // 4)]}

    # z-score IoC and twist over k in [2, max_k]; periodogram peaks are sparse
    def _z(arr: np.ndarray) -> np.ndarray:
        v = arr[2:]
        mu = float(v.mean())
        sd = float(v.std()) + 1e-9
        return (arr - mu) / sd

    zi = _z(ioc)
    zt = _z(twist_pp)
    zp = np.zeros(max_k + 1, dtype=np.float64)
    if per.size > 2:
        mu_p = float(per[2:].mean())
        sd_p = float(per[2:].std()) + 1e-9
        for k, score in peaks:
            if 2 <= k <= max_k:
                zp[k] = (score - mu_p) / sd_p

    ks = list(range(2, max_k + 1))
    S = np.zeros((len(ks), 4), dtype=np.float64)
    for i, k in enumerate(ks):
        S[i, 0] = zi[k]
        S[i, 1] = 1.0 if k in kas_topset else 0.0
        S[i, 2] = zp[k]
        S[i, 3] = zt[k]
    return S, ks


# ---------------------------------------------------------------------------
# Optimization
# ---------------------------------------------------------------------------

def tune_weights(
    examples: Iterable[tuple[str, int]],
    *,
    max_k: int = 40,
    epochs: int = 300,
    lr: float = 0.1,
    init_weights: Sequence[float] = (0.7, 0.9, 0.6, 1.0),
    l2: float = 1e-3,
    verbose: bool = False,
) -> TuneResult:
    """Fit posterior weights via gradient ascent on the log-likelihood.

    Parameters
    ----------
    examples : iterable of (ciphertext, true_keylen)
    max_k    : maximum key length to consider
    epochs   : number of full-batch updates
    lr       : learning rate
    init_weights : starting point (default = hand-tuned baseline)
    l2       : L2 regularization on weights (small, helps stability)
    """
    data: list[tuple[np.ndarray, int]] = []
    for ct, true_k in examples:
        if not clean_letters(ct) or not (2 <= true_k <= max_k):
            continue
        S, ks = _signal_matrix(ct, max_k)
        idx = ks.index(true_k)
        data.append((S, idx))

    if not data:
        raise ValueError("no usable examples; check keylens are in [2, max_k]")

    w = np.asarray(init_weights, dtype=np.float64).copy()
    if w.shape != (4,):
        raise ValueError("init_weights must have 4 entries")

    last_ll = float("-inf")
    for epoch in range(epochs):
        grad = np.zeros(4, dtype=np.float64)
        ll = 0.0
        for S, idx in data:
            logits = S @ w
            logits -= logits.max()
            p = np.exp(logits)
            p /= p.sum()
            ll += float(np.log(p[idx] + 1e-12))
            # ∇ log p[idx] = s[idx] - Σ p[k]·s[k]
            grad += S[idx] - p @ S
        ll /= len(data)
        grad /= len(data)
        grad -= 2 * l2 * w  # regularization
        w += lr * grad
        if verbose and (epoch + 1) % 50 == 0:
            print(f"epoch {epoch + 1}: ll={ll:.4f}  w={w.round(3).tolist()}")
        last_ll = ll

    # Compute final accuracies
    top1 = top3 = 0
    for S, idx in data:
        logits = S @ w
        rank = np.argsort(-logits)
        if int(rank[0]) == idx:
            top1 += 1
        if idx in rank[:3].tolist():
            top3 += 1

    return TuneResult(
        weights=tuple(float(x) for x in w),
        log_likelihood=last_ll,
        top1_acc=top1 / len(data),
        top3_acc=top3 / len(data),
        n_examples=len(data),
        n_epochs=epochs,
    )


# ---------------------------------------------------------------------------
# Convenience: tune on the bundled synthetic corpus
# ---------------------------------------------------------------------------

def synthetic_examples(
    n: int = 100, *,
    min_keylen: int = 4, max_keylen: int = 12,
    min_chars: int = 500, max_chars: int = 1500,
    seed: int = 0,
) -> list[tuple[str, int]]:
    """Generate ``n`` (ciphertext, true_keylen) pairs from the bundled corpus."""
    import random
    from .alphabet import encrypt, random_key
    from .data.corpus import CORPUS_ALL

    rng = random.Random(seed)
    src = clean_letters(CORPUS_ALL)
    out: list[tuple[str, int]] = []
    for _ in range(n):
        nchars = rng.randint(min_chars, max_chars)
        if nchars >= len(src):
            nchars = len(src) - 1
        start = rng.randint(0, len(src) - nchars)
        pt = src[start: start + nchars]
        klen = rng.randint(min_keylen, max_keylen)
        key = random_key(klen, rng)
        out.append((encrypt(pt, key), klen))
    return out
