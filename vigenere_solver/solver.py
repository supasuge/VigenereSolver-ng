"""Full Vigenère solver pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Optional, List, Tuple
import json
import math
import random

from .utils import (
    clean_upper_letters,
    encrypt_vigenere,
    decrypt_vigenere,
    load_language_data,
)
from .periodogram import coincidence_periodogram_fft, pick_periods
from .kasiski import kasiski_examination
from .lm import CharKenLM, tiny_lm_score
from .lm_classic import ClassicNGramLM, load_language_tables
from .hooks import load_wordlist, correct_key_with_wordlist
from .kenlm_model import KenlmModel


def _hist(text: str) -> list[float]:
    s = clean_upper_letters(text)
    counts = [0] * 26
    for ch in s:
        counts[ord(ch) - 65] += 1
    total = max(1, sum(counts))
    return [x / total for x in counts]


def _jsd(p: list[float], q: list[float]) -> float:
    m = [(a + b) / 2 for a, b in zip(p, q)]

    def kl(a: list[float], b: list[float]) -> float:
        score = 0.0
        for ai, bi in zip(a, b):
            if ai > 0 and bi > 0:
                score += ai * math.log(ai / bi)
        return score

    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


def _split_strips(text: str, keylen: int) -> list[str]:
    s = clean_upper_letters(text)
    return ["".join(s[i::keylen]) for i in range(keylen)]


def _perstrip_candidates(
    ciphertext: str,
    keylen: int,
    prior_vec: list[float],
    top_m: int = 6,
) -> list[list[tuple[int, float]]]:
    perpos: list[list[tuple[int, float]]] = []
    strips = _split_strips(ciphertext, keylen)
    for strip in strips:
        cand: list[tuple[int, float]] = []
        for shift in range(26):
            dec = "".join(chr(65 + ((ord(ch) - 65 - shift) % 26)) for ch in strip)
            hist = _hist(dec)
            cand.append((shift, -_jsd(hist, prior_vec)))
        cand.sort(key=lambda t: t[1], reverse=True)
        perpos.append(cand[:top_m])
    return perpos


def _beam(perpos: list[list[tuple[int, float]]], beam: int = 16) -> list[tuple[str, float]]:
    beams: list[tuple[str, float]] = [("", 0.0)]
    for cands in perpos:
        nxt: list[tuple[str, float]] = []
        for prefix, score in beams:
            for shift, sc in cands:
                nxt.append((prefix + chr(65 + shift), score + sc))
        nxt.sort(key=lambda t: t[1], reverse=True)
        beams = nxt[:beam]
    return beams


DATA_ROOT = Path(__file__).resolve().parents[1]
LANG_DATA = DATA_ROOT / "language_data.json"


def explain(text: str, outdir: str, max_k: int = 40) -> None:
    import matplotlib.pyplot as plt

    output = Path(outdir)
    output.mkdir(parents=True, exist_ok=True)
    per = coincidence_periodogram_fft(text)
    plt.figure()
    plt.plot(per)
    plt.xlabel("lag")
    plt.ylabel("norm coincidence")
    plt.title("Coincidence periodogram (FFT)")
    plt.savefig(output / "periodogram.png", dpi=150)
    peaks = pick_periods(per, kmax=max_k, top=10)

    ioc: list[tuple[int, float]] = []
    s = clean_upper_letters(text)
    for k in range(2, max_k + 1):
        strips = _split_strips(s, k)
        acc = 0.0
        cnt = 0
        for strip in strips:
            counts = [0] * 26
            for ch in strip:
                counts[ord(ch) - 65] += 1
            n = len(strip)
            if n < 2:
                continue
            num = sum(x * (x - 1) for x in counts)
            den = n * (n - 1) / 26.0
            acc += (num / den) if den > 0 else 0.0
            cnt += 1
        ioc.append((k, acc / max(1, cnt)))
    kas = kasiski_examination(text, kmax=max_k)
    (output / "report.json").write_text(
        json.dumps(
            {
                "periodogram_top": peaks,
                "ioc_by_k": ioc,
                "kasiski": kas[:20],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def encrypt(pt: str, key: str) -> str:
    return encrypt_vigenere(pt, key)


def _prior_vec(lang_json_path: Path) -> list[float]:
    lm = load_language_data(lang_json_path)
    vec = [lm.monograms.get(chr(65 + i), 0.0) for i in range(26)]
    total = sum(vec) or 1.0
    return [x / total for x in vec]


def _keylength_posterior(text: str, max_k: int) -> list[tuple[int, float]]:
    import numpy as np

    per = coincidence_periodogram_fft(text, kmax=max_k)
    top = pick_periods(per, kmax=max_k, top=max(10, max_k // 2))

    s = clean_upper_letters(text)
    ioc = [0.0] * (max_k + 1)
    for k in range(2, max_k + 1):
        strips = _split_strips(s, k)
        acc = 0.0
        cnt = 0
        for strip in strips:
            counts = [0] * 26
            for ch in strip:
                counts[ord(ch) - 65] += 1
            n = len(strip)
            if n < 2:
                continue
            num = sum(x * (x - 1) for x in counts)
            den = n * (n - 1) / 26.0
            acc += (num / den) if den > 0 else 0.0
            cnt += 1
        ioc[k] = acc / max(1, cnt)
    kas = {k: 1.0 for k in kasiski_examination(text, kmax=max_k)}

    def z(values: list[float]) -> list[float]:
        arr = values[2:]
        if not arr:
            return [float("-inf")] * len(values)
        import numpy as np

        x = np.array(arr, dtype=np.float64)
        mu = float(np.mean(x))
        sd = float(np.std(x) + 1e-9)
        out = [float("-inf"), float("-inf")]
        out += [(v - mu) / sd for v in arr]
        return out

    Zi = z(ioc)
    Zp = [float("-inf")] * (max_k + 1)
    muP = float(per.mean())
    sdP = float(per.std() + 1e-9)
    for k, score in top:
        Zp[k] = (score - muP) / sdP

    posterior_score = [float("-inf")] * (max_k + 1)
    for k in range(2, max_k + 1):
        posterior_score[k] = 0.7 * Zi[k] + 0.9 * (1.0 if k in kas else 0.0) + 0.6 * Zp[k]

    logits = [s for s in posterior_score[2:]]
    if logits:
        mx = max(logits)
        ex = [math.exp(v - mx) for v in logits]
        denom = sum(ex) or 1.0
        post = list(zip(range(2, max_k + 1), [v / denom for v in ex]))
    else:
        post = [(2, 1.0)]
    post.sort(key=lambda t: t[1], reverse=True)
    return post


def solve(
    text: str,
    decoder: str = "tiny-lm",
    lm_path: Optional[str] = None,
    lang: str = "en",
    max_k: int = 40,
    passes: int = 6,
    topk: int = 5,
    seed: Optional[int] = None,
    show_progress: bool = True,
    wordlist: Optional[str] = None,
    classic_order: int = 4,
    classic_lambdas: Optional[list[float]] = None,
    classic_alpha: float = 1e-3,
    beam: int = 16,
    strip_top: int = 6,
    forced_keylens: Optional[list[int]] = None,
    explain_dir: Optional[str] = None,
) -> dict:
    if seed is not None:
        random.seed(seed)

    prior_vec = _prior_vec(LANG_DATA)

    if forced_keylens:
        kl_post = [(k, 1.0 / len(forced_keylens)) for k in forced_keylens]
    else:
        kl_post = _keylength_posterior(text, max_k=max_k)

    candidate_keys: list[str] = []
    seen: set[str] = set()
    for k, _ in kl_post[: min(5, len(kl_post))]:
        perpos = _perstrip_candidates(text, k, prior_vec, top_m=strip_top)
        for key, _ in _beam(perpos, beam=beam)[:topk]:
            if key not in seen:
                seen.add(key)
                candidate_keys.append(key)
    if not candidate_keys:
        raise RuntimeError("no candidate keys produced")

    classic = ClassicNGramLM(
        load_language_tables(LANG_DATA),
        order=max(2, min(5, classic_order)),
        lambdas=classic_lambdas,
        alpha=classic_alpha,
    )

    kenlm_char: Optional[CharKenLM] = None
    kenlm_dataset: Optional[KenlmModel] = None
    if decoder == "kenlm" and lm_path:
        path = Path(lm_path)
        if path.is_dir():
            kenlm_dataset = KenlmModel.from_pretrained(str(path), lang)
        else:
            kenlm_char = CharKenLM(str(path))
    elif decoder == "kenlm":
        raise ValueError("decoder=kenlm requires --lm-path pointing to a model directory or file")

    scored: list[tuple[str, float]] = []
    for key in candidate_keys:
        plaintext = decrypt_vigenere(text, key)
        if decoder == "kenlm":
            if kenlm_dataset:
                ppl = kenlm_dataset.get_perplexity(plaintext)
                score = -math.log(max(ppl, 1e-6))
            elif kenlm_char:
                score = -kenlm_char.nll(plaintext)
            else:
                raise RuntimeError("KenLM decoder misconfigured")
        elif decoder == "classic":
            score = classic.score(plaintext)
        elif decoder == "tiny-lm":
            score = tiny_lm_score(plaintext)
        elif decoder == "legacy":
            hist = _hist(plaintext)
            score = -_jsd(hist, prior_vec)
        else:
            raise ValueError(f"Unknown decoder: {decoder}")
        scored.append((key, score))
    scored.sort(key=lambda t: t[1], reverse=True)
    best_key = scored[0][0]

    if explain_dir:
        explain(text, explain_dir, max_k=max_k)

    if wordlist:
        words = load_wordlist(wordlist, min_len=3, max_len=12, limit=50000)
        corrected = correct_key_with_wordlist(text, best_key, words, max_iter=2, max_mismatch=1)
        if corrected != best_key:
            best_key = corrected

    plaintext = decrypt_vigenere(text, best_key)
    pretty = "\n".join(
        [
            f"[1] key-length posterior top: {kl_post[:5]}",
            f"[2] best key: {best_key}  (len={len(best_key)})",
            f"[3] top candidates: {scored[:topk]}",
            "---- PLAINTEXT ----",
            plaintext,
        ]
    )
    return {
        "key": best_key,
        "keylen": len(best_key),
        "plaintext": plaintext,
        "candidates": scored[:topk],
        "pretty": pretty,
    }



