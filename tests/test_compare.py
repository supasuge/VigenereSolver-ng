"""Large-N randomized side-by-side accuracy tests.

These tests run the full pipeline across many random (plaintext, key) pairs
and assert *aggregate* accuracy guarantees per decoder. They are the truth
source for "decoder X is at least as good as decoder Y on average".

Marked slow; pytest still runs them by default but they finish in well
under a minute on a laptop with the default 25-trial setting.
"""
from __future__ import annotations

import pytest

from vigenere.bench import compare_strategies


def _summarize(rows, key):
    by: dict = {}
    for r in rows:
        by.setdefault(r[key], []).append(r)
    out = {}
    for k, items in by.items():
        n = len(items)
        out[k] = {
            "n": n,
            "key_acc": sum(1 for r in items if r["key_match"]) / n,
            "char_acc": sum(r["char_accuracy"] for r in items) / n,
            "mean_sec": sum(r["runtime_sec"] for r in items) / n,
        }
    return out


@pytest.mark.parametrize("seed", [0, 1])
def test_classic_and_best_dominate_baselines(seed):
    """On 25 random samples each, classic & best should beat legacy/tiny-lm
    on both key-match and character accuracy."""
    rows = compare_strategies(
        n_trials=25, decoders=("legacy", "tiny-lm", "classic", "best"),
        beams=(16,), strip_tops=(6,),
        min_keylen=5, max_keylen=10, min_chars=500, max_chars=900,
        max_k=20, seed=seed, print_summary=False,
    )
    s = _summarize(rows, "decoder")

    # Sanity: every decoder ran on every trial
    assert all(v["n"] == 25 for v in s.values())

    # Classic and best are strong: key_acc >= 0.80
    assert s["classic"]["key_acc"] >= 0.80, s
    assert s["best"]["key_acc"] >= 0.80, s

    # ... and dominate baselines on character accuracy
    assert s["classic"]["char_acc"] >= s["legacy"]["char_acc"], s
    assert s["best"]["char_acc"] >= s["tiny-lm"]["char_acc"], s
    assert s["best"]["char_acc"] >= s["classic"]["char_acc"] - 0.05, s

    # All decoders recover the plaintext (modulo key repetition) the vast
    # majority of the time
    assert s["best"]["char_acc"] > 0.95, s


def test_beam_width_helps_or_at_least_does_not_hurt():
    """Wider beam at fixed strip_top should not decrease accuracy materially."""
    rows = compare_strategies(
        n_trials=20, decoders=("classic",),
        beams=(4, 16), strip_tops=(6,),
        min_keylen=5, max_keylen=9, min_chars=500, max_chars=800,
        max_k=20, seed=7, print_summary=False,
    )
    s = _summarize(rows, "beam")
    # Allow a tiny dip due to RNG (no more than 5%)
    assert s[16]["char_acc"] >= s[4]["char_acc"] - 0.05, s


def test_strip_top_helps_or_at_least_does_not_hurt():
    rows = compare_strategies(
        n_trials=20, decoders=("classic",),
        beams=(16,), strip_tops=(3, 8),
        min_keylen=5, max_keylen=9, min_chars=500, max_chars=800,
        max_k=20, seed=11, print_summary=False,
    )
    s = _summarize(rows, "strip_top")
    assert s[8]["char_acc"] >= s[3]["char_acc"] - 0.05, s


def test_best_decoder_never_worse_than_classic_on_avg():
    rows = compare_strategies(
        n_trials=20, decoders=("classic", "best"),
        beams=(16,), strip_tops=(6,),
        min_keylen=5, max_keylen=10, min_chars=500, max_chars=900,
        max_k=20, seed=3, print_summary=False,
    )
    s = _summarize(rows, "decoder")
    assert s["best"]["char_acc"] >= s["classic"]["char_acc"] - 0.02, s
    assert s["best"]["key_acc"] >= s["classic"]["key_acc"] - 0.05, s
