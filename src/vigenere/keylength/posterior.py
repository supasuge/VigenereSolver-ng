"""Combine multiple key-length signals into a softmax posterior."""
from __future__ import annotations

from math import exp

import numpy as np

from ..stats import average_strip_ioc
from .kasiski import kasiski_examination
from .periodogram import coincidence_periodogram, pick_periods
from .twist import twist_plus_plus_table


def _z(values: list[float]) -> list[float]:
    """Z-score, ignoring leading two -inf placeholders (lags 0, 1)."""
    arr = np.asarray(values[2:], dtype=np.float64)
    if arr.size == 0:
        return [float("-inf")] * len(values)
    mu = float(arr.mean())
    sd = float(arr.std()) + 1e-9
    out = [float("-inf"), float("-inf")]
    out.extend(((arr - mu) / sd).tolist())
    return out


def keylength_posterior(
    text: str,
    max_k: int = 40,
    *,
    # Defaults learned via softmax gradient ascent on 150 random samples
    # (vigenere.tune.tune_weights, seed=0, epochs=400). On that data the
    # learned weights achieve top-1 accuracy 0.967 vs the hand-tuned
    # baseline; twist++ dominates, IoC contributes almost nothing on top.
    w_ioc: float = 0.014,
    w_kasiski: float = 2.60,
    w_periodogram: float = 0.79,
    w_twist: float = 4.46,
    return_table: bool = False,
):
    """Return ``[(k, prob)]`` over k in [2, max_k], sorted desc.

    Combines four z-scored signals via a weighted sum then softmax:
      * per-strip IoC averaged across the keylen columns
      * Kasiski factor-vote (binary: top quartile of voted divisors gets +1)
      * coincidence periodogram peaks (with NMS + harmonic suppression)
      * twist++ (Barr & Simoes, 2015) — handles harmonics natively

    With ``return_table=True``, also returns a dict of per-signal arrays
    indexed by k (useful for the progress UI's distribution panel).
    """
    per = coincidence_periodogram(text, kmax=max_k)
    peaks = pick_periods(per, kmax=max_k, top=max(10, max_k // 2))

    ioc = [0.0] * (max_k + 1)
    for k in range(2, max_k + 1):
        ioc[k] = average_strip_ioc(text, k)

    kas_pairs = kasiski_examination(text, kmax=max_k)
    kas_topset = {k for k, _ in kas_pairs[: max(5, len(kas_pairs) // 4)]}

    twist_pp = twist_plus_plus_table(text, max_k)

    zi = _z(ioc)
    zt = _z(twist_pp)
    zp = [float("-inf")] * (max_k + 1)
    if per.size > 2:
        mu_p = float(per[2:].mean())
        sd_p = float(per[2:].std()) + 1e-9
        for k, score in peaks:
            if 2 <= k <= max_k:
                zp[k] = (score - mu_p) / sd_p

    logits: list[float] = []
    keys: list[int] = []
    contrib: list[dict] = []
    for k in range(2, max_k + 1):
        zi_k = zi[k] if zi[k] != float("-inf") else 0.0
        zp_k = zp[k] if zp[k] != float("-inf") else 0.0
        zt_k = zt[k] if zt[k] != float("-inf") else 0.0
        kas_k = 1.0 if k in kas_topset else 0.0
        logit = (w_ioc * zi_k + w_kasiski * kas_k +
                 w_periodogram * zp_k + w_twist * zt_k)
        logits.append(logit)
        keys.append(k)
        contrib.append({
            "k": k, "z_ioc": zi_k, "z_periodogram": zp_k,
            "z_twist_pp": zt_k, "kasiski_hit": bool(kas_k),
            "logit": logit,
        })

    if not logits:
        posterior = [(2, 1.0)]
    else:
        mx = max(logits)
        ex = [exp(v - mx) for v in logits]
        z = sum(ex) or 1.0
        posterior = [(k, e / z) for k, e in zip(keys, ex)]
        posterior.sort(key=lambda t: t[1], reverse=True)

    if return_table:
        return posterior, {
            "ioc": ioc,
            "twist_pp": twist_pp,
            "kasiski_topset": sorted(kas_topset),
            "periodogram_peaks": peaks,
            "contrib": contrib,
        }
    return posterior
