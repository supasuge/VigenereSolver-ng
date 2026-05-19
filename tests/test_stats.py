import math

import pytest

from vigenere.alphabet import encrypt
from vigenere.stats import (
    average_strip_ioc,
    counts,
    histogram,
    index_of_coincidence,
    jensen_shannon,
    kl_divergence,
)

ENGLISH = (
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. PACK MY BOX WITH FIVE DOZEN "
    "LIQUOR JUGS. THE BEST PREPARATION FOR TOMORROW IS DOING YOUR BEST TODAY. "
    "TIME WAITS FOR NO MAN AND NEITHER DOES TIDE." * 4
)


def test_counts_and_histogram_consistent():
    c, n = counts("ABCABC")
    assert n == 6
    assert c[0] == 2 and c[1] == 2 and c[2] == 2
    h = histogram("ABCABC")
    assert math.isclose(sum(h), 1.0)


def test_index_of_coincidence_uniform_close_to_one():
    # Uniform-ish text -> IoC ~ 1.0
    text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 50
    assert 0.95 <= index_of_coincidence(text) <= 1.05


def test_index_of_coincidence_english_well_above_one():
    assert index_of_coincidence(ENGLISH) > 1.4


def test_average_strip_ioc_drops_when_keylen_wrong():
    """Encrypting English with a 7-letter key should LOWER per-strip IoC for
    wrong key lengths and KEEP it high for the true key length (7)."""
    ct = encrypt(ENGLISH, "SECRETK")
    true_k = average_strip_ioc(ct, 7)
    wrong_k = average_strip_ioc(ct, 6)
    assert true_k > wrong_k
    assert true_k > 1.3  # close to English IoC


def test_jsd_self_is_zero():
    p = [1/26] * 26
    assert jensen_shannon(p, p) == pytest.approx(0.0, abs=1e-12)


def test_jsd_symmetric_and_nonnegative():
    p = [0.5, 0.5] + [0.0] * 24
    q = [0.1] + [0.9 / 25] * 25
    a = jensen_shannon(p, q)
    b = jensen_shannon(q, p)
    assert a >= 0
    assert math.isclose(a, b, rel_tol=1e-9)


def test_kl_handles_zero_entries():
    p = [0.5, 0.5, 0.0]
    q = [1/3, 1/3, 1/3]
    # KL should be finite (zeros in p contribute 0)
    assert kl_divergence(p, q) > 0
