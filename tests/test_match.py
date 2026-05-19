"""Tests for key-match classification heuristics."""
from __future__ import annotations

import pytest

from vigenere.match import classify_match, cyclic_distance, hamming


def test_hamming_basic():
    assert hamming("ABC", "ABC") == 0
    assert hamming("ABC", "ABD") == 1
    assert hamming("ABCD", "WXYZ") == 4
    with pytest.raises(ValueError):
        hamming("AB", "ABC")


def test_cyclic_distance_recognizes_rotations():
    assert cyclic_distance("LEMON", "LEMON") == 0
    assert cyclic_distance("MONLE", "LEMON") == 0
    assert cyclic_distance("ONLEM", "LEMON") == 0
    assert cyclic_distance("LEMOX", "LEMON") == 1


def test_classify_exact():
    r = classify_match("LEMON", "LEMON")
    assert r.kind == "exact" and r.distance == 0
    assert r.is_correct and r.is_close


def test_classify_rotation():
    r = classify_match("MONLE", "LEMON")
    assert r.kind == "rotation"
    assert r.distance == 0
    assert r.is_correct


def test_classify_multiple():
    r = classify_match("LEMONLEMON", "LEMON")
    assert r.kind == "multiple"
    assert r.distance == 0
    assert r.is_correct


def test_classify_close():
    r = classify_match("LEMOX", "LEMON", max_diff=2)
    assert r.kind == "close"
    assert r.distance == 1
    assert r.is_close and not r.is_correct


def test_classify_diverged():
    r = classify_match("WXYZA", "LEMON", max_diff=2)
    assert r.kind == "none"
    assert not r.is_close


def test_classify_length_mismatch_returns_none():
    r = classify_match("ABC", "ABCDE")
    assert r.kind == "none"
    assert "length mismatch" in r.note


def test_classify_strips_non_letters():
    r = classify_match("le-mon!", "LEMON")
    assert r.kind == "exact"
