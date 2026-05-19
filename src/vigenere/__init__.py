"""Vigenere cipher solver - refactored.

Public API:
    encrypt, decrypt   - cipher primitives
    solve              - end-to-end attack pipeline
    SolveResult        - dataclass returned by solve()
"""
from __future__ import annotations

from .alphabet import encrypt, decrypt, clean_letters, random_key
from .solver import solve, solve_auto, SolveResult

__all__ = [
    "encrypt",
    "decrypt",
    "clean_letters",
    "random_key",
    "solve",
    "solve_auto",
    "SolveResult",
]
__version__ = "0.1.0"
