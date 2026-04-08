"""Vigenère solver package."""
from __future__ import annotations

__all__ = ["solve", "explain", "encrypt"]


def solve(*args, **kwargs):  # pragma: no cover - thin wrapper
    from .solver import solve as _solve

    return _solve(*args, **kwargs)


def explain(*args, **kwargs):  # pragma: no cover
    from .solver import explain as _explain

    return _explain(*args, **kwargs)


def encrypt(*args, **kwargs):  # pragma: no cover
    from .solver import encrypt as _encrypt

    return _encrypt(*args, **kwargs)


