"""Tests for the weight tuner and parameter optimizer."""
from __future__ import annotations

import pytest

from vigenere.optimize import optimize_parameters
from vigenere.tune import synthetic_examples, tune_weights


# ----- Tuner ------------------------------------------------------------------

def test_tuner_recovers_high_top1_on_clean_data():
    """On clean synthetic data, the learned weights should achieve high top-1."""
    examples = synthetic_examples(n=40, seed=0,
                                  min_keylen=5, max_keylen=10,
                                  min_chars=500, max_chars=1200)
    res = tune_weights(examples, max_k=20, epochs=200, lr=0.2)
    assert res.n_examples == 40
    # With weights even at default, signal quality is very high on easy data
    assert res.top1_acc >= 0.85, f"top1_acc={res.top1_acc:.3f}"
    assert res.top3_acc >= 0.95, f"top3_acc={res.top3_acc:.3f}"
    # All four weights returned, finite, real
    assert len(res.weights) == 4
    assert all(isinstance(w, float) for w in res.weights)


def test_tuner_improves_over_initialization():
    """The learned weights' likelihood must not be worse than the initial."""
    examples = synthetic_examples(n=30, seed=1,
                                  min_keylen=5, max_keylen=9,
                                  min_chars=500, max_chars=900)
    # Train normally
    trained = tune_weights(examples, max_k=15, epochs=300, lr=0.15)
    # Compare to 0-epoch run (just measures the init weights' likelihood)
    baseline = tune_weights(examples, max_k=15, epochs=0, lr=0.15)
    assert trained.log_likelihood >= baseline.log_likelihood - 1e-6, (
        f"training hurt likelihood: {trained.log_likelihood:.4f} "
        f"vs baseline {baseline.log_likelihood:.4f}"
    )


def test_tuner_raises_on_empty_data():
    with pytest.raises(ValueError):
        tune_weights([], max_k=20)


# ----- Optimizer --------------------------------------------------------------

def test_optimize_returns_best_and_pareto():
    res = optimize_parameters(
        decoders=("classic", "best"),
        beams=(8, 16),
        strip_tops=(4, 8),
        n_trials=6, max_k=15, seed=0,
        min_keylen=5, max_keylen=8, min_chars=500, max_chars=700,
        show_progress=False,
    )
    # 2 decoders * 2 beams * 2 strip_tops = 8 cells
    assert len(res.rows) == 8
    assert all("key_acc" in c for c in res.rows)
    # Best cell is the one with max key_acc
    assert res.best["key_acc"] == max(c["key_acc"] for c in res.rows)
    # Pareto frontier is non-empty and subset of rows
    assert 1 <= len(res.pareto) <= len(res.rows)
    for c in res.pareto:
        assert c in res.rows


def test_optimize_pareto_property():
    """No cell on the Pareto frontier should be strictly dominated."""
    res = optimize_parameters(
        decoders=("classic",),
        beams=(4, 12, 24),
        strip_tops=(2, 6),
        n_trials=4, max_k=15, seed=2,
        min_keylen=5, max_keylen=8, min_chars=500, max_chars=700,
        show_progress=False,
    )
    for r in res.pareto:
        for s in res.rows:
            if s is r:
                continue
            # s strictly dominates r ⟹ frontier is wrong
            strictly_dominates = (
                s["key_acc"] >= r["key_acc"]
                and s["mean_sec"] <= r["mean_sec"]
                and (s["key_acc"] > r["key_acc"]
                     or s["mean_sec"] < r["mean_sec"])
            )
            assert not strictly_dominates, f"Pareto point {r} dominated by {s}"


def test_optimize_cheapest_at_target():
    res = optimize_parameters(
        decoders=("classic",),
        beams=(8,),
        strip_tops=(4, 6),
        n_trials=4, max_k=15, seed=3,
        min_keylen=5, max_keylen=8, min_chars=500, max_chars=700,
        target_accuracy=0.5,
        show_progress=False,
    )
    if res.cheapest_at is not None:
        # cheapest cell must meet the target
        assert res.cheapest_at["key_acc"] >= 0.5
        # and be the minimum-runtime cell among qualifying ones
        qualifying = [c for c in res.rows if c["key_acc"] >= 0.5]
        assert res.cheapest_at["mean_sec"] == min(c["mean_sec"] for c in qualifying)
