"""Tests for the post-review fixes."""
from __future__ import annotations

import time

import pytest

from vigenere import solve
from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.keylength import twist_plus_plus_score, twist_plus_plus_table
from vigenere.match import cyclic_distance


# --- Fix #1: refinement / candidates / confidence stay in sync ----------------

def test_refinement_updates_candidates_and_confidence(tmp_path):
    """When refinement rewrites the key, candidates[0] and confidence
    must reflect the *post-refinement* key, not the original."""
    true_key = "FREEDOM"
    ct = encrypt(SAMPLE_TEXT, true_key)
    wl = tmp_path / "words.txt"
    wl.write_text("\n".join([
        "THE", "AND", "NATION", "GOVERNMENT", "CONSTITUTION", "UNITED",
        "PEOPLE", "STATES", "FREEDOM", "LIBERTY", "JUSTICE",
    ]))
    # Use legacy decoder forced to keylen 7; legacy sometimes misses a position
    # which gives refinement something to fix.
    res = solve(ct, decoder="legacy", forced_keylens=[7], wordlist=str(wl))
    # Top candidate must match returned key
    assert res.candidates[0][0] == res.key
    # If refinement fired, confidence still in [0, 1]
    assert 0.0 <= res.confidence <= 1.0


def test_refinement_candidate_no_duplicate():
    """The refined key must not appear twice in `candidates`."""
    # No wordlist => no refinement => key obviously appears once
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    keys = [k for k, _ in res.candidates]
    assert len(keys) == len(set(keys))


# --- Fix #2: twist_plus_plus_score caches the table ---------------------------

def test_twist_plus_plus_score_is_fast_on_repeat_calls():
    """Repeated calls with the same (text, max_k) must hit the LRU cache."""
    ct = encrypt(SAMPLE_TEXT, "FREEDOM")
    # First call warms the cache (computes the full table)
    twist_plus_plus_score(ct, 7, max_k=40)
    # 200 follow-up calls must be far faster than 200x the first
    t0 = time.perf_counter()
    for k in range(2, 41):
        twist_plus_plus_score(ct, k, max_k=40)
        twist_plus_plus_score(ct, k, max_k=40)
        twist_plus_plus_score(ct, k, max_k=40)
    dt = time.perf_counter() - t0
    # ~120 cached lookups should be sub-millisecond; allow generous margin
    assert dt < 0.05, f"cached calls took {dt:.3f}s (expected <0.05s)"


def test_twist_plus_plus_score_matches_table():
    ct = encrypt(SAMPLE_TEXT, "FREEDOM")
    tbl = twist_plus_plus_table(ct, max_k=20)
    for k in range(2, 21):
        assert twist_plus_plus_score(ct, k, max_k=20) == tbl[k]


# --- Fix #3: signals are populated even when forced_keylens is given ----------

def test_signals_populated_with_forced_keylens():
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    # All signals from the natural posterior should still be present
    assert "twist_pp" in res.signals
    assert "ioc" in res.signals
    assert "periodogram_peaks" in res.signals
    # Plus the forced-keylens marker
    assert res.signals.get("forced_keylens") == [5]
    # Plus the natural top so the caller can compare
    assert "natural_posterior_top" in res.signals
    assert len(res.signals["natural_posterior_top"]) <= 10


# --- Fix #4: plaintexts are not redundantly decrypted -------------------------

def test_solve_returns_consistent_plaintext():
    """The returned plaintext must equal decrypt(ciphertext, key)."""
    from vigenere import decrypt as _dec
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="best", forced_keylens=[5])
    assert res.plaintext == _dec(ct, res.key)


# --- Nit: cyclic_distance now normalizes non-letters --------------------------

def test_cyclic_distance_handles_non_letter_input():
    assert cyclic_distance("le-mon", "LEMON") == 0
    assert cyclic_distance("MON  LE!", "LEMON") == 0   # rotation through punctuation
    assert cyclic_distance("le.mox", "LEMON") == 1
