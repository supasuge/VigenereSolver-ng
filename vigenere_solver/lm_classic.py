"""Classic interpolated n-gram language model."""
from __future__ import annotations

from typing import Dict, List
from math import log
from pathlib import Path
import json

from .data import LanguageModel

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _upper_keys(data: Dict[str, float]) -> Dict[str, float]:
    return {k.upper(): float(v) for k, v in data.items()}


def load_language_tables(path: Path | str = "language_data.json") -> LanguageModel:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return LanguageModel(
        name="english",
        monograms=_upper_keys(data["english_monograms"]),
        bigrams=_upper_keys(data.get("english_bigrams_1", {})),
        trigrams=_upper_keys(data["english_trigrams"]),
        quadgrams=_upper_keys(data["english_quadgrams"]),
        quintgrams=_upper_keys(data["english_quintgrams"]),
    )


class ClassicNGramLM:
    """Interpolated character-level n-gram model."""

    def __init__(
        self,
        lang_tables: LanguageModel,
        order: int = 4,
        lambdas: List[float] | None = None,
        alpha: float = 1e-3,
    ) -> None:
        assert 2 <= order <= 5
        self.order = order
        self.alpha = max(1e-9, alpha)

        def _norm(table: Dict[str, float]) -> Dict[str, float]:
            total = sum(table.values()) or 1.0
            return {k: v / total for k, v in table.items()}

        self.tables = {
            1: _norm(lang_tables.monograms),
            2: _norm(lang_tables.bigrams),
            3: _norm(lang_tables.trigrams),
            4: _norm(lang_tables.quadgrams),
            5: _norm(lang_tables.quintgrams),
        }

        if lambdas is None:
            base = [0.05, 0.15, 0.30, 0.50, 0.0]
            lambdas = base[:order]
        total = sum(lambdas) or 1.0
        self.lambdas = [x / total for x in lambdas]

    def _tok(self, text: str) -> List[str]:
        out: List[str] = []
        for ch in text.upper():
            if 'A' <= ch <= 'Z':
                out.append(ch)
            elif ch == ' ':
                out.append(' ')
        return out

    def _p1(self, ch: str) -> float:
        if ch == ' ':
            return 0.18
        return self.tables[1].get(ch, self.alpha)

    def _pn(self, gram: str) -> float:
        n = len(gram)
        return self.tables.get(n, {}).get(gram, self.alpha)

    def score(self, text: str) -> float:
        tokens = self._tok(text)
        if not tokens:
            return float("-inf")
        score = 0.0
        for i in range(len(tokens)):
            mixture = 0.0
            mixture += self.lambdas[0] * self._p1(tokens[i])
            for n in range(2, self.order + 1):
                if i - n + 1 < 0:
                    break
                gram = "".join(ch for ch in tokens[i - n + 1 : i + 1] if ch != ' ')
                if len(gram) != n:
                    continue
                mixture += self.lambdas[n - 1] * self._pn(gram)
            score += log(max(mixture, 1e-12))
        return score


