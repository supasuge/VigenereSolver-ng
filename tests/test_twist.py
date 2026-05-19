"""Tests for the twist / twist++ key-length signals."""
from __future__ import annotations

import pytest

from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.keylength import (
    keylength_posterior,
    twist_plus_plus_score,
    twist_plus_plus_table,
    twist_score,
    twist_table,
)


def test_twist_zero_for_invalid_input():
    assert twist_score("", 5) == 0.0
    assert twist_score("ABCDEFG", 0) == 0.0
    assert twist_score("ABCDEFG", -3) == 0.0


def test_twist_top_values_are_multiples_of_true_keylen():
    """Raw twist promotes the true keylen *and* its multiples (harmonics).
    Every entry in the top-3 should be a multiple of the true keylen."""
    key = "ENGLISH"  # 7
    ct = encrypt(SAMPLE_TEXT, key)
    tbl = twist_table(ct, max_k=30)
    ranked = sorted(range(2, 31), key=lambda k: tbl[k], reverse=True)
    top3 = ranked[:3]
    assert all(k % len(key) == 0 for k in top3), (
        f"top3 by raw twist not all multiples of {len(key)}: {top3}"
    )


def test_twist_plus_plus_recovers_fundamental():
    """twist++ should bring the *fundamental* key length into the top 3."""
    key = "ENGLISH"  # 7
    ct = encrypt(SAMPLE_TEXT, key)
    fix = twist_plus_plus_table(ct, max_k=30)
    ranked = sorted(range(2, 31), key=lambda k: fix[k], reverse=True)
    assert len(key) in ranked[:3], f"top3 by twist++: {ranked[:3]}"


def test_twist_plus_plus_breaks_harmonic_tie():
    """twist++ should prefer the fundamental period over its harmonics."""
    key = "FREEDOM"  # 7
    ct = encrypt(SAMPLE_TEXT, key)
    raw = twist_table(ct, max_k=30)
    fix = twist_plus_plus_table(ct, max_k=30)

    # Both true keylen 7 and a harmonic like 14 may rank highly under raw twist;
    # twist++ should put 7 strictly above 14 (the harmonic correction).
    assert fix[len(key)] > 0
    if raw[14] > 0:
        assert fix[len(key)] > fix[14], (
            f"twist++ failed harmonic discount: 7={fix[7]:.3f} vs 14={fix[14]:.3f}"
        )


def test_twist_score_is_bounded():
    """T(k) is bounded in [0, 1]. T(1) = English twist ~ 0.65 - 0.75."""
    ct = encrypt(SAMPLE_TEXT, "A")  # identity
    t1 = twist_score(ct, 1)
    assert 0.0 <= t1 <= 1.0
    # English unigrams: top-13 sum ≈ 0.85 → twist ≈ 0.70
    assert 0.55 < t1 < 0.85


def test_keylength_posterior_uses_twist():
    """`keylength_posterior` with return_table=True must expose twist_pp."""
    ct = encrypt(SAMPLE_TEXT, "LEMONADE")
    post, signals = keylength_posterior(ct, max_k=20, return_table=True)
    assert "twist_pp" in signals
    assert len(signals["twist_pp"]) == 21  # indices 0..20
    # True keylen 8 should be in top-3
    top3 = [k for k, _ in post[:3]]
    assert 8 in top3
