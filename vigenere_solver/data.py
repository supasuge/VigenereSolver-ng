"""Shared dataclasses used across the solver."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class LanguageModel:
    name: str
    monograms: Dict[str, float]
    bigrams: Dict[str, float]
    trigrams: Dict[str, float]
    quadgrams: Dict[str, float]
    quintgrams: Dict[str, float]


@dataclass
class Term:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


@dataclass
class ClassicDecryptionResult:
    key_length: int
    key: str
    decrypted: str
    formatted: str
    flag: Optional[str]
    ioc: float
    score: float
    kasiski: float
    frequency: float


