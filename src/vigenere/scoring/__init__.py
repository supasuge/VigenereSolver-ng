"""Scoring backends. All scorers return a "higher is better" score."""
from .base import Scorer
from .legacy_jsd import LegacyJSDScorer
from .tiny_lm import TinyLMScorer
from .classic_ngram import ClassicNGramScorer

__all__ = ["Scorer", "LegacyJSDScorer", "TinyLMScorer", "ClassicNGramScorer", "get_scorer"]


def get_scorer(name: str, **kwargs) -> Scorer:
    name = name.lower()
    if name in ("legacy", "jsd"):
        return LegacyJSDScorer(**kwargs)
    if name in ("tiny-lm", "tiny", "tinylm"):
        return TinyLMScorer()
    if name in ("classic", "ngram", "classic-ngram"):
        return ClassicNGramScorer(**kwargs)
    raise ValueError(f"unknown scorer: {name!r}")
