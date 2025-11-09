"""Language model scoring backends."""
from __future__ import annotations

from math import log

try:
    import kenlm  # type: ignore
except Exception:  # pragma: no cover
    kenlm = None

SPACE = "<sp>"


def _tok(text: str) -> str:
    out: list[str] = []
    for ch in text.upper():
        if 'A' <= ch <= 'Z':
            out.append(ch)
        elif ch == ' ':
            out.append(SPACE)
    return " ".join(out)


class CharKenLM:
    """KenLM character-level scorer."""

    def __init__(self, model_path: str):
        if kenlm is None:
            raise ImportError("kenlm is not installed. Install 'kenlm' to enable this decoder.")
        self.model = kenlm.Model(model_path)

    def nll(self, text: str) -> float:
        return -self.model.score(_tok(text), bos=True, eos=True) * log(10.0)


ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_UNI = {
    'E': 12.702, 'T': 9.056, 'A': 8.167, 'O': 7.507, 'I': 6.966, 'N': 6.749,
    'S': 6.327, 'H': 6.094, 'R': 5.987, 'D': 4.253, 'L': 4.025, 'C': 2.782,
    'U': 2.758, 'M': 2.406, 'W': 2.360, 'F': 2.228, 'G': 2.015, 'Y': 1.974,
    'P': 1.929, 'B': 1.492, 'V': 0.978, 'K': 0.772, 'J': 0.153, 'X': 0.150,
    'Q': 0.095, 'Z': 0.074,
}
SPACE_MASS = 18.0
SCALE = SPACE_MASS + sum(_UNI.values())
UNI_P = {c: _UNI[c] / SCALE for c in ALPH}
UNI_P[SPACE] = SPACE_MASS / SCALE
_BIGRAM_BONUS = {
    "TH": 0.60, "HE": 0.58, "IN": 0.52, "ER": 0.48, "AN": 0.46, "RE": 0.45, "ON": 0.44, "AT": 0.43, "EN": 0.42,
    "ND": 0.41, "TI": 0.40, "ES": 0.39, "OR": 0.38, "TE": 0.37, "OF": 0.37, "ED": 0.36, "IS": 0.36, "IT": 0.35,
    "AL": 0.34, "AR": 0.33, "ST": 0.33, "TO": 0.32, "NT": 0.31, "NG": 0.30,
}


def tiny_lm_score(text: str) -> float:
    tokens: list[str] = []
    for ch in text.upper():
        if 'A' <= ch <= 'Z':
            tokens.append(ch)
        elif ch == ' ':
            tokens.append(SPACE)
    if not tokens:
        return float("-inf")
    score = 0.0
    for ch in tokens:
        score += log(max(UNI_P.get(ch, 1e-8), 1e-12))
    for i in range(len(tokens) - 1):
        a, b = tokens[i], tokens[i + 1]
        if a == SPACE or b == SPACE:
            continue
        score += _BIGRAM_BONUS.get(a + b, 0.0)
    return score


