"""TOML configuration loader/merger."""
from __future__ import annotations

from typing import Any, Dict
from argparse import Namespace

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def load_toml_config(path: str | None) -> Dict[str, Any]:
    if not path:
        return {}
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def merge_section_into_args(args: Namespace, section: Dict[str, Any]) -> Namespace:
    if not section:
        return args
    for key, value in section.items():
        if not hasattr(args, key):
            continue
        current = getattr(args, key)
        if current in (None, ""):
            setattr(args, key, value)
    return args
