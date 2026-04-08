"""Full Vigenère solver pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import json
import math
import random

from .utils import clean_upper_letters, encrypt_vigenere, decrypt_vigenere, load_language_data
from .periodogram import coincidence_periodogram_fft, pick_periods
from .kasiski import kasiski_examination
from .lm import CharKenLM, tiny_lm_score
from .lm_classic import ClassicNGramLM, load_language_tables
from .hooks import load_wordlist, correct_key_with_wordlist
from .kenlm_model import KenlmModel


DATA_ROOT = Path(__file__).resolve().parents[1]
LANG_DATA = DATA_ROOT / "language_data.json"


def _hist(text: str) -> list[float]:
    s = clean_upper_letters(text)
    counts = [0] * 26
    for ch in s:
        counts[ord(ch) - 65] += 1
    total = max(1, sum(counts))
    return [x / total for x in counts]


def _jsd(p: list[float], q: list[float]) -> float:
    m = [(a + b) / 2 for a, b in zip(p, q)]

    def _kl(a: list[float], b: list[float]) -> float:
        score = 0.0
        for ai, bi in zip(a, b):
            if ai > 0 and bi > 0:
                score += ai * math.log(ai / bi)
        return score

    return 0.5 * _kl(p, m) + 0.5 * _kl(q, m)


def _split_strips(text: str, keylen: int) -> list[str]:
    s = clean_upper_letters(text)
    return ["".join(s[i::keylen]) for i in range(keylen)]


def _perstrip_candidates(ciphertext: str, keylen: int, prior_vec: list[float], top_m: int = 6) -> list[list[tuple[int, float]]]:
    perpos: list[list[tuple[int, float]]] = []
    for strip in _split_strips(ciphertext, keylen):
        cand: list[tuple[int, float]] = []
        for shift in range(26):
            dec = "".join(chr(65 + ((ord(ch) - 65 - shift) % 26)) for ch in strip)
            cand.append((shift, -_jsd(_hist(dec), prior_vec)))
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


def _index_of_coincidence(text: str) -> float:
    s = clean_upper_letters(text)
    n = len(s)
    if n < 2:
        return 0.0
    counts = [0] * 26
    for ch in s:
        counts[ord(ch) - 65] += 1
    num = sum(v * (v - 1) for v in counts)
    den = n * (n - 1)
    return num / den if den else 0.0


def _englishness_bonus(text: str) -> float:
    up = text.upper()
    alpha = [c for c in up if "A" <= c <= "Z"]
    if not alpha:
        return -1.0
    common = ("THE", "AND", "ING", "ION", "ENT", "ED", "ER")
    hits = sum(up.count(tok) for tok in common)
    ratio = hits / max(len(alpha), 1)
    ioc_bias = -abs(_index_of_coincidence(text) - 0.066)
    return 6.0 * ratio + 2.0 * ioc_bias


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
            n = len(strip)
            if n < 2:
                continue
            counts = [0] * 26
            for ch in strip:
                counts[ord(ch) - 65] += 1
            acc += sum(x * (x - 1) for x in counts) / (n * (n - 1) / 26.0)
            cnt += 1
        ioc.append((k, acc / max(1, cnt)))

    kas = kasiski_examination(text, kmax=max_k)
    (output / "report.json").write_text(
        json.dumps({"periodogram_top": peaks, "ioc_by_k": ioc, "kasiski": kas[:20]}, indent=2),
        encoding="utf-8",
    )


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
            n = len(strip)
            if n < 2:
                continue
            counts = [0] * 26
            for ch in strip:
                counts[ord(ch) - 65] += 1
            acc += sum(x * (x - 1) for x in counts) / (n * (n - 1) / 26.0)
            cnt += 1
        ioc[k] = acc / max(1, cnt)

    kas = {k: 1.0 for k in kasiski_examination(text, kmax=max_k)}

    def _z(values: list[float]) -> list[float]:
        x = np.array(values[2:], dtype=np.float64)
        if x.size == 0:
            return [float("-inf")] * len(values)
        mu = float(np.mean(x))
        sd = float(np.std(x) + 1e-9)
        return [float("-inf"), float("-inf")] + [float((v - mu) / sd) for v in values[2:]]

    zi = _z(ioc)
    zp = [float("-inf")] * (max_k + 1)
    mu_p, sd_p = float(per.mean()), float(per.std() + 1e-9)
    for k, score in top:
        zp[k] = (score - mu_p) / sd_p

    logits = []
    for k in range(2, max_k + 1):
        logits.append((k, 0.7 * zi[k] + 0.9 * (1.0 if k in kas else 0.0) + 0.6 * zp[k]))

    mx = max(v for _, v in logits) if logits else 0.0
    ex = [(k, math.exp(v - mx)) for k, v in logits]
    total = sum(v for _, v in ex) or 1.0
    post = [(k, v / total) for k, v in ex]
    post.sort(key=lambda t: t[1], reverse=True)
    return post


def _build_decoder(
    decoder: str,
    lm_path: Optional[str],
    lang: str,
    classic_order: int,
    classic_lambdas: Optional[list[float]],
    classic_alpha: float,
) -> tuple[ClassicNGramLM, Optional[CharKenLM], Optional[KenlmModel]]:
    classic = ClassicNGramLM(
        load_language_tables(LANG_DATA),
        order=max(2, min(5, classic_order)),
        lambdas=classic_lambdas,
        alpha=classic_alpha,
    )

    kenlm_char: Optional[CharKenLM] = None
    kenlm_dataset: Optional[KenlmModel] = None
    if decoder == "kenlm":
        if not lm_path:
            raise ValueError("decoder=kenlm requires --lm-path pointing to a model directory or file")
        path = Path(lm_path)
        if path.is_dir():
            kenlm_dataset = KenlmModel.from_pretrained(str(path), lang)
        else:
            kenlm_char = CharKenLM(str(path))
    return classic, kenlm_char, kenlm_dataset


def _score_plaintext(
    plaintext: str,
    decoder: str,
    prior_vec: list[float],
    classic: ClassicNGramLM,
    kenlm_char: Optional[CharKenLM],
    kenlm_dataset: Optional[KenlmModel],
) -> float:
    if decoder == "kenlm":
        if kenlm_dataset:
            ppl = kenlm_dataset.get_perplexity(plaintext)
            base = -math.log(max(ppl, 1e-6))
        elif kenlm_char:
            base = -kenlm_char.nll(plaintext)
        else:
            raise RuntimeError("KenLM decoder misconfigured")
    elif decoder == "classic":
        base = classic.score(plaintext)
    elif decoder == "tiny-lm":
        base = tiny_lm_score(plaintext)
    elif decoder == "legacy":
        base = -_jsd(_hist(plaintext), prior_vec)
    else:
        raise ValueError(f"Unknown decoder: {decoder}")
    return base + _englishness_bonus(plaintext)


def _refine_key_local(
    ciphertext: str,
    key: str,
    passes: int,
    decoder: str,
    prior_vec: list[float],
    classic: ClassicNGramLM,
    kenlm_char: Optional[CharKenLM],
    kenlm_dataset: Optional[KenlmModel],
) -> tuple[str, float]:
    best_key = key
    best_pt = decrypt_vigenere(ciphertext, best_key)
    best_score = _score_plaintext(best_pt, decoder, prior_vec, classic, kenlm_char, kenlm_dataset)
    for _ in range(max(1, passes)):
        changed = False
        for i in range(len(best_key)):
            local_best_key = best_key
            local_best_score = best_score
            for shift in range(26):
                trial = best_key[:i] + chr(65 + shift) + best_key[i + 1 :]
                trial_pt = decrypt_vigenere(ciphertext, trial)
                trial_score = _score_plaintext(trial_pt, decoder, prior_vec, classic, kenlm_char, kenlm_dataset)
                if trial_score > local_best_score:
                    local_best_key = trial
                    local_best_score = trial_score
            if local_best_key != best_key:
                best_key = local_best_key
                best_score = local_best_score
                changed = True
        if not changed:
            break
    return best_key, best_score


def encrypt(pt: str, key: str) -> str:
    return encrypt_vigenere(pt, key)


def solve(
    text: str,
    decoder: str = "tiny-lm",
    lm_path: Optional[str] = None,
    lang: str = "en",
    max_k: int = 40,
    passes: int = 3,
    topk: int = 5,
    seed: Optional[int] = None,
    show_progress: bool = False,
    wordlist: Optional[str] = None,
    classic_order: int = 4,
    classic_lambdas: Optional[list[float]] = None,
    classic_alpha: float = 1e-3,
    beam: int = 16,
    strip_top: int = 6,
    forced_keylens: Optional[list[int]] = None,
    explain_dir: Optional[str] = None,
) -> dict:
    del show_progress  # currently unused, reserved for future UI progress hooks
    if seed is not None:
        random.seed(seed)

    prior_vec = _prior_vec(LANG_DATA)
    kl_post = (
        [(k, 1.0 / len(forced_keylens)) for k in forced_keylens]
        if forced_keylens
        else _keylength_posterior(text, max_k=max_k)
    )

    candidate_keys: list[str] = []
    seen: set[str] = set()
    for k, _ in kl_post[: min(6, len(kl_post))]:
        perpos = _perstrip_candidates(text, k, prior_vec, top_m=strip_top)
        for key, _ in _beam(perpos, beam=beam)[:topk]:
            if key not in seen:
                seen.add(key)
                candidate_keys.append(key)
    if not candidate_keys:
        raise RuntimeError("no candidate keys produced")

    classic, kenlm_char, kenlm_dataset = _build_decoder(decoder, lm_path, lang, classic_order, classic_lambdas, classic_alpha)

    scored: list[tuple[str, float]] = []
    for key in candidate_keys:
        refined_key, refined_score = _refine_key_local(
            text,
            key,
            passes=passes,
            decoder=decoder,
            prior_vec=prior_vec,
            classic=classic,
            kenlm_char=kenlm_char,
            kenlm_dataset=kenlm_dataset,
        )
        scored.append((refined_key, refined_score))
    scored.sort(key=lambda t: t[1], reverse=True)

    deduped: list[tuple[str, float]] = []
    used: set[str] = set()
    for key, score in scored:
        if key in used:
            continue
        used.add(key)
        deduped.append((key, score))

    best_key = deduped[0][0]

    if explain_dir:
        explain(text, explain_dir, max_k=max_k)

    if wordlist:
        words = load_wordlist(wordlist, min_len=3, max_len=12, limit=50000)
        corrected = correct_key_with_wordlist(text, best_key, words, max_iter=2, max_mismatch=1)
        if corrected != best_key:
            best_key = corrected

    plaintext = decrypt_vigenere(text, best_key)
    return {
        "key": best_key,
        "keylen": len(best_key),
        "plaintext": plaintext,
        "candidates": deduped[:topk],
        "pretty": "\n".join(
            [
                f"[1] key-length posterior top: {kl_post[:5]}",
                f"[2] best key: {best_key}  (len={len(best_key)})",
                f"[3] top candidates: {deduped[:topk]}",
                "---- PLAINTEXT ----",
                plaintext,
            ]
        ),
    }
