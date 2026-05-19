"""Interpolated character n-gram language model from language_data.json."""
from __future__ import annotations

from math import log
from typing import Sequence

from ..language import LanguageModel, cached_language_model


class ClassicNGramScorer:
    """Linear interpolation of 1..order grams with additive smoothing."""

    name = "classic"

    def __init__(
        self,
        language: LanguageModel | None = None,
        order: int = 4,
        lambdas: Sequence[float] | None = None,
        alpha: float = 1e-3,
    ) -> None:
        if not 2 <= order <= 5:
            raise ValueError("order must be in [2, 5]")
        self.lm = language or cached_language_model()
        self.order = order
        self.alpha = max(1e-9, alpha)

        if lambdas is None:
            base = [0.05, 0.15, 0.30, 0.50, 0.0]
            lambdas = base[:order]
        if len(lambdas) != order:
            raise ValueError(f"need {order} lambdas, got {len(lambdas)}")
        s = sum(lambdas) or 1.0
        self.lambdas = [x / s for x in lambdas]

        self.tables = {n: self.lm.table(n) for n in range(1, 6)}

    def _p1(self, ch: str) -> float:
        if ch == " ":
            return 0.18
        return self.tables[1].get(ch, self.alpha)

    def _pn(self, gram: str) -> float:
        return self.tables.get(len(gram), {}).get(gram, self.alpha)

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        out: list[str] = []
        for ch in text.upper():
            if "A" <= ch <= "Z" or ch == " ":
                out.append(ch)
        return out

    def score(self, text: str) -> float:
        toks = self._tokenize(text)
        if not toks:
            return float("-inf")
        total = 0.0
        for i in range(len(toks)):
            mix = self.lambdas[0] * self._p1(toks[i])
            for n in range(2, self.order + 1):
                lo = i - n + 1
                if lo < 0:
                    break
                gram = "".join(ch for ch in toks[lo : i + 1] if ch != " ")
                if len(gram) != n:
                    continue
                mix += self.lambdas[n - 1] * self._pn(gram)
            total += log(max(mix, 1e-12))
        return total
