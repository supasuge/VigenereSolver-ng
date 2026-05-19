"""Language model tables loaded from language_data.json.

The bundled JSON file ships with English n-gram tables (1..5 grams). The
loader normalizes each table into a probability distribution so downstream
scorers don't have to.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Mapping

from .alphabet import A, SIZE

# language_data.json lives at the repository root, two levels above this file
# (src/vigenere/language.py -> repo root).
DEFAULT_LANG_PATH = Path(__file__).resolve().parents[2] / "language_data.json"


def _norm(table: Mapping[str, float]) -> dict[str, float]:
    if not table:
        return {}
    total = sum(table.values())
    if total <= 0:
        return {k.upper(): 0.0 for k in table}
    inv = 1.0 / total
    return {k.upper(): float(v) * inv for k, v in table.items()}


@dataclass(frozen=True)
class LanguageModel:
    """Normalized n-gram probability tables (sum to 1 within each n)."""
    name: str
    monograms: dict[str, float] = field(default_factory=dict)
    bigrams: dict[str, float] = field(default_factory=dict)
    trigrams: dict[str, float] = field(default_factory=dict)
    quadgrams: dict[str, float] = field(default_factory=dict)
    quintgrams: dict[str, float] = field(default_factory=dict)

    def table(self, n: int) -> dict[str, float]:
        return {1: self.monograms, 2: self.bigrams, 3: self.trigrams,
                4: self.quadgrams, 5: self.quintgrams}[n]

    def monogram_vector(self) -> list[float]:
        """Length-26 probability vector indexed by ord(ch)-ord('A')."""
        v = [self.monograms.get(chr(A + i), 0.0) for i in range(SIZE)]
        s = sum(v)
        return [x / s for x in v] if s > 0 else v


def load_language_model(path: str | Path | None = None) -> LanguageModel:
    p = Path(path) if path else DEFAULT_LANG_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    return LanguageModel(
        name="english",
        monograms=_norm(data.get("english_monograms", {})),
        bigrams=_norm(data.get("english_bigrams_1", {}) or data.get("english_bigrams", {})),
        trigrams=_norm(data.get("english_trigrams", {})),
        quadgrams=_norm(data.get("english_quadgrams", {})),
        quintgrams=_norm(data.get("english_quintgrams", {})),
    )


@lru_cache(maxsize=4)
def cached_language_model(path: str | None = None) -> LanguageModel:
    return load_language_model(path)
