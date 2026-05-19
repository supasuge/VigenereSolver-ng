import pytest

from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.keylength import (
    coincidence_periodogram,
    kasiski_examination,
    keylength_posterior,
    pick_periods,
)


@pytest.fixture(scope="module")
def long_ct():
    return encrypt(SAMPLE_TEXT, "LEMONADE")  # keylen = 8


def test_periodogram_finds_true_keylen(long_ct):
    per = coincidence_periodogram(long_ct, kmax=40)
    top = pick_periods(per, kmax=40, top=5)
    top_keys = {k for k, _ in top}
    # True keylen 8 should appear in the top 5
    assert 8 in top_keys


def test_periodogram_handles_empty():
    per = coincidence_periodogram("", kmax=10)
    assert per.size >= 1


def test_kasiski_returns_factor_votes(long_ct):
    out = kasiski_examination(long_ct, kmax=40)
    # Tuple format (k, votes), votes desc
    assert all(isinstance(t, tuple) and len(t) == 2 for t in out)
    if len(out) > 1:
        assert out[0][1] >= out[1][1]


def test_keylength_posterior_top_includes_true_keylen(long_ct):
    post = keylength_posterior(long_ct, max_k=40)
    top5 = [k for k, _ in post[:5]]
    assert 8 in top5
    # Probabilities sum (approximately) to 1
    total = sum(p for _, p in post)
    assert abs(total - 1.0) < 1e-6


def test_posterior_falls_back_for_tiny_input():
    post = keylength_posterior("ABCDE", max_k=10)
    assert post  # non-empty
