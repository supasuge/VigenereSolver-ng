"""Wrapper around SentencePiece + KenLM character models."""
from __future__ import annotations

import os
import re
import unicodedata
from typing import Dict

try:  # pragma: no cover - optional dependency
    import kenlm  # type: ignore
except Exception:  # pragma: no cover
    kenlm = None

try:  # pragma: no cover
    import sentencepiece  # type: ignore
except Exception:  # pragma: no cover
    sentencepiece = None


class SentencePiece:
    def __init__(self, model: str):
        if sentencepiece is None:
            raise ImportError("sentencepiece is required for KenLM decoding")
        self.sp = sentencepiece.SentencePieceProcessor()
        self.sp.load(str(model))

    def do(self, text: str) -> str:
        tokenized = self.sp.encode_as_pieces(text)
        return " ".join(tokenized)


class KenlmModel:
    digit_re: re.Pattern = re.compile(r"\d")
    unicode_punct: Dict[str, str] = {
        "，": ",",
        "。": ".",
        "、": ",",
        "„": '"',
        "”": '"',
        "“": '"',
        "«": '"',
        "»": '"',
        "１": '"',
        "」": '"',
        "「": '"',
        "《": '"',
        "》": '"',
        "´": "'",
        "∶": ":",
        "：": ":",
        "？": "?",
        "！": "!",
        "（": "(",
        "）": ")",
        "；": ";",
        "–": "-",
        "—": " - ",
        "．": ". ",
        "～": "~",
        "’": "'",
        "…": "...",
        "━": "-",
        "〈": "<",
        "〉": ">",
        "【": "[",
        "】": "]",
        "％": "%",
        "►": "-",
    }
    unicode_punct_re = re.compile(f"[{''.join(unicode_punct.keys())}]")
    non_printing_chars_re = re.compile(
        f"[{''.join(map(chr, list(range(0, 32)) + list(range(127, 160))))}]"
    )

    def __init__(
        self,
        model_dataset: str,
        language: str,
        lower_case: bool = False,
        remove_accents: bool = False,
        normalize_numbers: bool = True,
        punctuation: int = 1,
    ) -> None:
        model_path = os.path.join(model_dataset, f"{language}.arpa.bin")
        sp_path = os.path.join(model_dataset, f"{language}.sp.model")
        if not os.path.exists(model_path):
            raise FileNotFoundError(model_path)
        if not os.path.exists(sp_path):
            raise FileNotFoundError(sp_path)
        if kenlm is None:
            raise ImportError("kenlm is required for KenLM decoding")
        self.model = kenlm.Model(model_path)
        self.tokenizer = SentencePiece(sp_path)
        self.accent = remove_accents
        self.case = lower_case
        self.numbers = normalize_numbers
        self.punct = punctuation

    @classmethod
    def from_pretrained(cls, model_dataset: str, language: str):
        return cls(model_dataset, language, False, False, True, 1)

    def pp(self, log_score: float, length: int) -> float:
        return 10.0 ** (-log_score / max(length, 1))

    def get_perplexity(self, doc: str, normalize_cc_net: bool = True) -> float:
        if normalize_cc_net:
            doc = self.normalize(
                doc,
                accent=self.accent,
                case=self.case,
                numbers=self.numbers,
                punct=self.punct,
            )
        tokenized = self.tokenizer.do(doc)
        doc_log_score = 0.0
        doc_length = 0
        for line in tokenized.split("\n"):
            log_score = self.model.score(line)
            length = len(line.split()) + 1
            doc_log_score += log_score
            doc_length += length
        return round(self.pp(doc_log_score, doc_length), 1)

    def normalize(
        self,
        line: str,
        accent: bool = True,
        case: bool = True,
        numbers: bool = True,
        punct: int = 1,
    ) -> str:
        line = line.strip()
        if not line:
            return line
        if case:
            line = line.lower()
        if accent:
            line = self.strip_accents(line)
        if numbers:
            line = self.digit_re.sub("0", line)
        if punct == 1:
            line = self.replace_unicode_punct(line)
        elif punct == 2:
            line = self.remove_unicode_punct(line)
        line = self.remove_non_printing_char(line)
        return line

    def strip_accents(self, line: str) -> str:
        nfd = unicodedata.normalize("NFD", line)
        output = [c for c in nfd if unicodedata.category(c) != "Mn"]
        if len(output) == len(line):
            return line
        return "".join(output)

    def replace_unicode_punct(self, text: str) -> str:
        return "".join(self.unicode_punct.get(c, c) for c in text)

    def remove_unicode_punct(self, text: str) -> str:
        return self.unicode_punct_re.sub("", text)

    def remove_non_printing_char(self, text: str) -> str:
        return self.non_printing_chars_re.sub("", text)



