"""Tests for SolveResult.confidence and result.match_against()."""
from __future__ import annotations

from vigenere import solve
from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT


def test_confidence_in_range():
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    assert 0.0 <= res.confidence <= 1.0


def test_confidence_higher_for_strong_match():
    """Plenty of text + a strong scorer should give high confidence."""
    ct = encrypt(SAMPLE_TEXT, "FREEDOM")
    res = solve(ct, decoder="classic", forced_keylens=[7])
    assert res.confidence > 0.1  # should be well separated from runner-up


def test_signals_exposed_when_not_forced():
    """When key length is not forced, signals dict should include twist_pp."""
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="classic", max_k=20)
    assert "twist_pp" in res.signals
    assert "ioc" in res.signals
    assert "periodogram_peaks" in res.signals


def test_match_against_recognizes_correct():
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    m = res.match_against("LEMON")
    assert m.is_correct


def test_match_against_recognizes_doubled_key():
    """`best` sometimes returns a multiple; classify_match handles it."""
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    # Force a doubled key length to provoke the multiple-key case
    res = solve(ct, decoder="legacy", forced_keylens=[10])
    m = res.match_against("LEMON")
    # Either exact, multiple, or close - never "none" for so much text
    assert m.is_close, f"match: {m}"


def test_pretty_includes_confidence():
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    p = res.pretty()
    assert "confidence" in p
