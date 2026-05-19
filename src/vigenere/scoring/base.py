"""Scorer protocol."""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Scorer(Protocol):
    """A text scorer where higher = more English-like."""

    name: str

    def score(self, text: str) -> float: ...
