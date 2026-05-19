import math

from vigenere.language import cached_language_model, load_language_model


def test_language_model_loads_and_normalizes():
    lm = load_language_model()
    assert lm.name == "english"
    # Monograms should sum to ~1
    assert math.isclose(sum(lm.monograms.values()), 1.0, rel_tol=1e-6)
    # Common English letters dominate
    assert lm.monograms["E"] > lm.monograms["Z"]
    vec = lm.monogram_vector()
    assert len(vec) == 26
    assert math.isclose(sum(vec), 1.0, rel_tol=1e-6)


def test_cached_language_model_returns_same_instance():
    a = cached_language_model()
    b = cached_language_model()
    assert a is b
