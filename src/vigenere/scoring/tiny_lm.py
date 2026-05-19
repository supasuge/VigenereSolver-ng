"""Tiny hardcoded unigram + bigram-bonus scorer (no language file needed)."""
from __future__ import annotations

from math import log

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SPACE = "<sp>"

# Standard English letter frequencies (percent)
_UNI = {
    "E": 12.702, "T": 9.056, "A": 8.167, "O": 7.507, "I": 6.966, "N": 6.749,
    "S": 6.327, "H": 6.094, "R": 5.987, "D": 4.253, "L": 4.025, "C": 2.782,
    "U": 2.758, "M": 2.406, "W": 2.360, "F": 2.228, "G": 2.015, "Y": 1.974,
    "P": 1.929, "B": 1.492, "V": 0.978, "K": 0.772, "J": 0.153, "X": 0.150,
    "Q": 0.095, "Z": 0.074,
}
_SPACE_MASS = 18.0
_TOTAL = _SPACE_MASS + sum(_UNI.values())
UNI_P: dict[str, float] = {c: _UNI[c] / _TOTAL for c in ALPH}
UNI_P[SPACE] = _SPACE_MASS / _TOTAL

# A small additive bonus when common bigrams appear back-to-back
_BIGRAM_BONUS = {
    "TH": 0.60, "HE": 0.58, "IN": 0.52, "ER": 0.48, "AN": 0.46, "RE": 0.45,
    "ON": 0.44, "AT": 0.43, "EN": 0.42, "ND": 0.41, "TI": 0.40, "ES": 0.39,
    "OR": 0.38, "TE": 0.37, "OF": 0.37, "ED": 0.36, "IS": 0.36, "IT": 0.35,
    "AL": 0.34, "AR": 0.33, "ST": 0.33, "TO": 0.32, "NT": 0.31, "NG": 0.30,
}


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    for ch in text.upper():
        if "A" <= ch <= "Z":
            out.append(ch)
        elif ch == " ":
            out.append(SPACE)
    return out


class TinyLMScorer:
    name = "tiny-lm"

    def score(self, text: str) -> float:
        toks = _tokenize(text)
        if not toks:
            return float("-inf")
        s = 0.0
        for t in toks:
            s += log(max(UNI_P.get(t, 1e-8), 1e-12))
        for i in range(len(toks) - 1):
            a, b = toks[i], toks[i + 1]
            if a == SPACE or b == SPACE:
                continue
            s += _BIGRAM_BONUS.get(a + b, 0.0)
        return s
