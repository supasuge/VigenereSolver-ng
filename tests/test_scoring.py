import random as _r

import pytest

from vigenere.alphabet import clean_letters, encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.scoring import (
    ClassicNGramScorer,
    LegacyJSDScorer,
    TinyLMScorer,
    get_scorer,
)

# Equal-length letters-only comparison strings, so log-prob sums are comparable.
_ENGLISH = clean_letters(SAMPLE_TEXT)[:1600]
_rng = _r.Random(0)
_NOISE = "".join(_rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=len(_ENGLISH)))


@pytest.mark.parametrize("scorer_factory", [
    lambda: LegacyJSDScorer(),
    lambda: TinyLMScorer(),
    lambda: ClassicNGramScorer(order=4),
])
def test_scorers_prefer_english_over_noise(scorer_factory):
    sc = scorer_factory()
    assert sc.score(_ENGLISH) > sc.score(_NOISE), f"failed: {sc.name}"


def test_scorers_prefer_plaintext_over_ciphertext():
    # Compare equal-length cipher/plain so length doesn't bias the sum.
    pt = _ENGLISH
    ct = encrypt(pt, "VIGENERE")
    for sc in (LegacyJSDScorer(), TinyLMScorer(), ClassicNGramScorer(order=4)):
        assert sc.score(pt) > sc.score(ct), f"failed: {sc.name}"


def test_get_scorer_factory():
    assert get_scorer("legacy").name == "legacy"
    assert get_scorer("tiny-lm").name == "tiny-lm"
    assert get_scorer("classic").name == "classic"
    with pytest.raises(ValueError):
        get_scorer("nope")


def test_classic_ngram_rejects_bad_order():
    with pytest.raises(ValueError):
        ClassicNGramScorer(order=1)
    with pytest.raises(ValueError):
        ClassicNGramScorer(order=6)


def test_classic_ngram_rejects_wrong_lambda_count():
    with pytest.raises(ValueError):
        ClassicNGramScorer(order=3, lambdas=[0.5, 0.5])  # need 3


def test_tiny_lm_empty_text():
    assert TinyLMScorer().score("") == float("-inf")
