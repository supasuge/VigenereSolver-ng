"""Negative Jensen-Shannon divergence against English unigram prior."""
from __future__ import annotations

from ..language import LanguageModel, cached_language_model
from ..stats import histogram, jensen_shannon


class LegacyJSDScorer:
    name = "legacy"

    def __init__(self, language: LanguageModel | None = None) -> None:
        self.lm = language or cached_language_model()
        self.prior = self.lm.monogram_vector()

    def score(self, text: str) -> float:
        return -jensen_shannon(histogram(text), self.prior)
