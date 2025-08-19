#!/usr/bin/env python3
# solver.py (Vigenère + KN LM decoder + auto window/step + rich tokenizer)
from __future__ import annotations
import argparse, concurrent.futures, os, time, json, unicodedata, math, random, string, signal
from typing import List, Optional, Tuple, Dict, Set
from dataclasses import dataclass
from pathlib import Path
from string import punctuation

from utils import (
    LanguageModel, DecryptionResult, load_language_data,
    CiphertextParser, encrypt_vigenere, decrypt_vigenere,
    VigenereStatsMixin, kasiski_examination, clean_upper_letters,
    generate_english_cipher_blocks, KneserNeyLM, WordSegmenter
)

class Term:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; MAGENTA = '\033[95m'; CYAN = '\033[96m'
    BOLD = '\033[1m'; END = '\033[0m'

# ---------------------------
# Rich token model
# ---------------------------
@dataclass
class Token:
    ch: str
    kind: str               # 'letter' | 'space' | 'digit' | 'punct' | 'other'
    was_upper: bool
    ascii_alpha: bool
    letter_index: Optional[int] = None

def _strip_diacritics(s: str) -> str:
    decomp = unicodedata.normalize('NFKD', s)
    return ''.join(c for c in decomp if not unicodedata.combining(c))

def _is_punct_like(ch: str) -> bool:
    return (ch in punctuation) or unicodedata.category(ch).startswith('P')

def tokenize_rich_text(text: str) -> Tuple[List[Token], str]:
    tokens: List[Token] = []
    letters: List[str] = []
    next_idx = 0
    for ch in text:
        if ch.isspace():
            tokens.append(Token(ch=ch, kind='space', was_upper=False, ascii_alpha=False))
            continue
        if ch.isdigit():
            tokens.append(Token(ch=ch, kind='digit', was_upper=False, ascii_alpha=False))
            continue
        base = _strip_diacritics(ch)
        folded = base.upper()[:1] if base else ''
        if folded and 'A' <= folded <= 'Z':
            was_upper = ch.isupper()
            tokens.append(Token(
                ch=ch, kind='letter', was_upper=was_upper, ascii_alpha=True, letter_index=next_idx
            ))
            letters.append(folded)
            next_idx += 1
        else:
            kind = 'punct' if _is_punct_like(ch) else 'other'
            tokens.append(Token(ch=ch, kind=kind, was_upper=False, ascii_alpha=False))
    return tokens, ''.join(letters)

def format_from_tokens(tokens: List[Token], letters_clean: str) -> str:
    out: List[str] = []
    for t in tokens:
        if t.ascii_alpha and t.letter_index is not None:
            ch = letters_clean[t.letter_index]
            out.append(ch if t.was_upper else ch.lower())
        else:
            out.append(t.ch)
    return ''.join(out)

def encrypt_with_meta(plaintext: str, key: str) -> Tuple[str, dict]:
    tokens, letters_stream = tokenize_rich_text(plaintext)
    letters_ct = encrypt_vigenere(letters_stream, key)
    ciphertext = format_from_tokens(tokens, letters_ct)
    meta = {
        "key_length": len(key),
        "letters_count": len(letters_stream),
        "tokens": [
            {
                "ch": t.ch,
                "kind": t.kind,
                "was_upper": t.was_upper,
                "ascii_alpha": t.ascii_alpha,
                "letter_index": t.letter_index
            } for t in tokens
        ]
    }
    return ciphertext, meta

# ---------------------------
# LM-driven key optimizer
# ---------------------------
def _letters_to_ints(s: str) -> List[int]:
    return [ord(ch) - ord('A') for ch in s]

def _ints_to_letters(v: List[int]) -> str:
    return ''.join(chr(ord('A') + (x % 26)) for x in v)

def _coset_positions(N: int, m: int, r: int) -> List[int]:
    return list(range(r, N, m))

def _windows_touching_positions(positions: List[int], N: int, L: int) -> List[int]:
    """Return sorted unique starts of L-gram windows that include any index in positions."""
    starts: Set[int] = set()
    max_start = N - L
    if max_start < 0:
        return []
    for j in positions:
        a = max(0, j - (L - 1))
        b = min(j, max_start)
        for s in range(a, b + 1):
            starts.add(s)
    return sorted(starts)

class LMKeyOptimizer:
    """
    Coordinate-descent optimizer for Vigenère key under a Kneser–Ney LM.
    Works on the cleaned uppercase A..Z stream.
    """
    def __init__(self, lm: KneserNeyLM, anneal: float = 0.0):
        self.lm = lm
        self.anneal = float(anneal)

    def optimize(self, ciphertext_clean: str, key_init: str, passes: int = 5, verbose: bool = False) -> str:
        C = _letters_to_ints(ciphertext_clean)
        N = len(C)
        m = len(key_init)
        K = _letters_to_ints(key_init)
        # current plaintext ints
        P = [(C[i] - K[i % m]) % 26 for i in range(N)]

        # Precompute windows for each coset and lengths 3/4/5
        coset_pos: List[List[int]] = [ _coset_positions(N, m, r) for r in range(m) ]
        W3 = [ _windows_touching_positions(coset_pos[r], N, 3) for r in range(m) ]
        W4 = [ _windows_touching_positions(coset_pos[r], N, 4) for r in range(m) ]
        W5 = [ _windows_touching_positions(coset_pos[r], N, 5) for r in range(m) ]

        def gram_str(start: int, L: int, override_coset: Optional[int], override_shift: Optional[int]) -> str:
            if start < 0 or start+L > N:
                return ""
            buf: List[int] = []
            for t in range(start, start+L):
                if override_coset is not None and (t % m) == override_coset and override_shift is not None:
                    new_pt = (C[t] - override_shift) % 26
                    buf.append(new_pt)
                else:
                    buf.append(P[t])
            return _ints_to_letters(buf)

        def local_neglog_for_coset(r: int, shift_alt: Optional[int]) -> float:
            total = 0.0
            # Windows size 5/4/3
            for s in W5[r]:
                g = gram_str(s, 5, r, shift_alt)
                total += self.lm.gram_logprob_fixed(g)
            for s in W4[r]:
                g = gram_str(s, 4, r, shift_alt)
                total += self.lm.gram_logprob_fixed(g)
            for s in W3[r]:
                g = gram_str(s, 3, r, shift_alt)
                total += self.lm.gram_logprob_fixed(g)
            return total

        # Baseline local score per coset (current key)
        base_local = [local_neglog_for_coset(r, K[r]) for r in range(m)]

        # Coordinate descent passes
        for p in range(1, passes+1):
            improved = False
            if verbose:
                print(f"{Term.MAGENTA}[LM] Pass {p}/{passes}{Term.END}")
            order = list(range(m))
            random.shuffle(order)  # random sweep often helps
            for r in order:
                best_s = K[r]
                best_val = base_local[r]
                # try all 26 shifts
                for s in range(26):
                    if s == K[r]:
                        continue
                    cand_val = local_neglog_for_coset(r, s)
                    if cand_val + 1e-12 < best_val:
                        best_val, best_s = cand_val, s
                    elif self.anneal > 0.0:
                        delta = cand_val - best_val
                        prob = math.exp(-delta / max(self.anneal, 1e-9))
                        if random.random() < prob:
                            best_val, best_s = cand_val, s
                if best_s != K[r]:
                    if verbose:
                        print(f"{Term.YELLOW}  [LM] coset {r:02d}: {chr(ord('A')+K[r])} -> {chr(ord('A')+best_s)} (Δlocal={base_local[r]-best_val:.3f}){Term.END}")
                    K[r] = best_s
                    for t in coset_pos[r]:
                        P[t] = (C[t] - best_s) % 26
                    base_local[r] = best_val
                    improved = True
            if not improved:
                if verbose:
                    print(f"{Term.CYAN}[LM] Converged after {p} passes.{Term.END}")
                break
        return _ints_to_letters(K)

# ---------------------------
# Solver
# ---------------------------
class VigenereSolver(VigenereStatsMixin):
    def __init__(self, lang_path: str = "language_data.json",
                 window: Optional[int] = None, step: Optional[int] = None,
                 use_windowed_keys: bool = True,
                 anneal: float = 0.0,
                 lm_weight: float = 0.65,
                 auto_ws: bool = True,
                 ws_beam: int = 6,
                 ws_passes: int = 2):
        lm: LanguageModel = load_language_data(lang_path)
        self.english_freqs = lm.monograms
        self.trigrams     = lm.trigrams
        self.quadgrams    = lm.quadgrams
        self.quintgrams   = lm.quintgrams
        self._prep_monogram_vec()
        self._tri_model   = self._prep_ngram_model(self.trigrams, 3)
        self._quad_model  = self._prep_ngram_model(self.quadgrams, 4)
        self._quint_model = self._prep_ngram_model(self.quintgrams, 5)

        # KN LM & key optimizer blend
        self.knlm = KneserNeyLM.from_language_model(lm, discount=0.75)
        self.lm_weight = float(lm_weight)
        self.anneal = float(anneal)

        # Window/step settings (auto by default)
        self.window = window if window is not None else 600
        self.step = step if step is not None else 150
        self.use_windowed_keys = use_windowed_keys
        self.auto_ws = bool(auto_ws)
        self.ws_beam = int(ws_beam)
        self.ws_passes = int(ws_passes)

        # Word segmentation for readability
        self.segmenter = WordSegmenter.load_default()

    # --- tokenizer hooks ---
    @staticmethod
    def parse_text_with_meta(text: str):
        tokens, cleaned = tokenize_rich_text(text)
        return tokens, cleaned

    @staticmethod
    def format_from_meta(parsed_tokens: List[Token], decrypted_clean: str) -> str:
        return format_from_tokens(parsed_tokens, decrypted_clean)

    # --- key length candidates ---
    def candidate_key_lengths(self, text: str, window: int, step: int) -> List[int]:
        s = clean_upper_letters(text)
        fried = int(round(self.estimate_key_length_friedman(s)))
        kas = kasiski_examination(s)
        period = self.windowed_coincidence_periodogram(s, max_lag=50, window=window, step=step)
        per_top = self.key_lengths_from_periodogram(period, topk=8, nms=1)
        pool = set(kas + per_top + [max(2, fried-2), max(2, fried-1), fried, fried+1, fried+2])
        return sorted(x for x in pool if 2 <= x <= 50)

    def _initial_key_for_m(self, s: str, m: int, window: int, step: int) -> str:
        if self.use_windowed_keys:
            return self.windowed_key_vote(s, m, window=window, step=step)
        else:
            cosets = [''.join(s[i::m]) for i in range(m)]
            key = ''.join(self.find_key_char(c)[0] for c in cosets)
            key, _ = self.refine_key(s, key, passes=2)
            return key

    def _blend_score(self, dec_text: str) -> float:
        # Combined fitness (lower is better). Mix LM NLL with legacy features.
        lm_nll = self.knlm.neglog_per_char(dec_text, order_max=5)
        legacy = self.plaintext_fitness(dec_text)
        w = self.lm_weight
        return w * lm_nll + (1.0 - w) * legacy

    # ---------------------------
    # Auto-tune window/step
    # ---------------------------
    def _periodogram_peakiness(self, period: List[float], topk: int = 4) -> float:
        if not period: return 0.0
        arr = sorted(period, reverse=True)
        top = sum(arr[:min(topk, len(arr))]) / max(1, min(topk, len(arr)))
        mean = sum(period)/len(period)
        # robust dispersion
        med = sorted(period)[len(period)//2]
        st = (sum((x-mean)*(x-mean) for x in period)/max(1,len(period)))**0.5
        return (top - med) / (st + 1e-9)

    def _overlap_score(self, s: str, window: int, step: int, max_lag: int = 50, topk: int = 4) -> float:
        # Split into thirds; compare top-lag overlap among segments for stability
        s = clean_upper_letters(s)
        n = len(s)
        if n < window*2:
            segs = [s]
        else:
            thirds = [s[:n//3], s[n//3: 2*n//3], s[2*n//3:]]
            segs = [x for x in thirds if len(x) >= max(50, window//2)]
        tops: List[Set[int]] = []
        for seg in segs:
            per = self.windowed_coincidence_periodogram(seg, max_lag=max_lag, window=max(window//2, 60), step=max(1, step//2))
            lags = sorted(range(1, max_lag+1), key=lambda L: per[L-1], reverse=True)[:topk]
            tops.append(set(lags))
        if len(tops) <= 1:
            return 0.0
        # average pairwise Jaccard
        pairs = 0
        tot = 0.0
        for i in range(len(tops)):
            for j in range(i+1, len(tops)):
                a, b = tops[i], tops[j]
                inter = len(a & b); uni = len(a | b) or 1
                tot += inter / uni
                pairs += 1
        return tot / max(1, pairs)

    def _ws_objective(self, text: str, window: int, step: int, fried_guess: int) -> float:
        # Ciphertext-only objective: peakiness + stability + weak prior toward multiples of fried_guess
        s = clean_upper_letters(text)
        period = self.windowed_coincidence_periodogram(s, max_lag=50, window=window, step=step)
        pk = self._periodogram_peakiness(period, topk=4)
        ov = self._overlap_score(s, window, step, max_lag=50, topk=4)
        # weak prior: if top lag is near a multiple of fried_guess reward
        top_lag = 1 + max(range(len(period)), key=lambda i: period[i]) if period else 1
        mult = 0.0
        if fried_guess >= 2:
            r = abs(top_lag - round(top_lag/fried_guess)*fried_guess)
            mult = 1.0 / (1.0 + r)
        # penalty for overly small/huge windows vs length
        N = len(s)
        util = min(1.0, window / max(1.0, 0.1*N)) * min(1.0, (0.8*N)/max(window, 1.0))
        return 0.55*pk + 0.30*ov + 0.10*mult + 0.05*util

    def _ws_refine_with_lm(self, text: str, window: int, step: int) -> float:
        """ Try top 2 candidate m for this (window,step) and measure best LM NLL. Lower is better -> return -NLL """
        s = clean_upper_letters(text)
        cands = self.candidate_key_lengths(text, window, step)[:2]
        if not cands:
            return -1e-6
        best = float('inf')
        for m in cands:
            k0 = self._initial_key_for_m(s, m, window, step)
            dec = decrypt_vigenere(s, k0)
            nll = self.knlm.neglog_per_char(dec, order_max=5)
            if nll < best: best = nll
        return -best

    def auto_tune_window_step(self, text: str) -> Tuple[int, int]:
        s = clean_upper_letters(text)
        N = len(s)
        fried = max(2, int(round(self.estimate_key_length_friedman(s))))
        # coarse seeds (multiples of fried), clipped
        Wmin = max(60, 6*fried)
        Wmax = min(2000, max(120, int(0.6*N)))
        if Wmin > Wmax: Wmin, Wmax = max(60, min(Wmin, N//2)), max(Wmin+40, min(N, Wmin+400))
        seeds = []
        for mult in (8, 10, 12, 16, 20, 24):
            w = mult * fried
            if Wmin <= w <= Wmax:
                seeds.append(w)
        if not seeds:
            seeds = [max(80, min(Wmax, int(N/6))), max(120, min(Wmax, int(N/4)))]
        # build (window,step) seed pairs
        seed_pairs = set()
        for w in seeds:
            for den in (8, 6, 5, 4):
                step = max(1, w // den)
                seed_pairs.add((w, step))
        # beam search with hill climbing
        def neighbors(w: int, st: int) -> List[Tuple[int,int]]:
            outs = []
            for dw in (-int(0.2*w), -int(0.1*w), int(0.1*w), int(0.2*w)):
                w2 = max(60, min(Wmax, w + dw))
                for ds in (-max(1, st//5), max(1, st//5)):
                    s2 = max(1, min(w2-1, st + ds))
                    outs.append((w2, s2))
            # also try recomputing step as w/k
            for den in (8,6,5,4):
                outs.append((w, max(1, w//den)))
            return list({x for x in outs})
        # score seeds (ciphertext-only objective)
        scored = []
        for (w, st) in seed_pairs:
            val = self._ws_objective(text, w, st, fried)
            scored.append(((w, st), val))
        scored.sort(key=lambda x: x[1], reverse=True)
        beam = [x[0] for x in scored[:self.ws_beam]]

        for _ in range(self.ws_passes):
            cand_pack = set(beam)
            for w, st in list(beam):
                cand_pack.update(neighbors(w, st))
            # evaluate all candidates with ciphertext-only objective
            scored = [ (ws, self._ws_objective(text, ws[0], ws[1], fried)) for ws in cand_pack ]
            scored.sort(key=lambda x: x[1], reverse=True)
            beam = [ws for (ws, _) in scored[:self.ws_beam]]
        # LM tie-break among top few
        best_ws = None
        best_val = -1e18
        for (w, st) in beam[:min(4, len(beam))]:
            lm_gain = self._ws_refine_with_lm(text, w, st)
            val = 0.7 * self._ws_objective(text, w, st, fried) + 0.3 * (lm_gain)
            if val > best_val:
                best_val, best_ws = val, (w, st)
        return best_ws if best_ws else (self.window, self.step)

    # ---------------------------
    # Try a key length
    # ---------------------------
    def try_key_length(self, original_text: str, key_len: int, window: int, step: int,
                       decoder: str, passes: int) -> DecryptionResult:
        parsed, cleaned = self.parse_text_with_meta(original_text)
        init_key = self._initial_key_for_m(cleaned, key_len, window, step)

        if decoder == "lm":
            opt = LMKeyOptimizer(self.knlm, anneal=self.anneal)
            key = opt.optimize(cleaned, init_key, passes=passes, verbose=False)
        else:
            key, _ = self.refine_key(cleaned, init_key, passes=passes)

        dec = decrypt_vigenere(cleaned, key)
        formatted = self.format_from_meta(parsed, dec)
        ioc = self.calculate_ioc(dec)
        kasiski_count = len(kasiski_examination(dec))
        final_score = self._blend_score(dec)
        return DecryptionResult(
            key_length=key_len, key=key, decrypted=dec, formatted=formatted,
            flag=None, ioc=ioc, score=final_score, kasiski=kasiski_count, frequency=0.0
        )

    def _readable_text(self, tokens: List[Token], dec_clean: str, formatted_from_tokens: str, enable_seg: bool) -> str:
        # If original had essentially no spaces, try word segmentation to produce a readable view.
        had_spaces = any(t.kind == 'space' for t in tokens)
        if had_spaces or not enable_seg:
            return formatted_from_tokens
        # Segment plain uppercase into words (lowercase for readability)
        segmented = self.segmenter.segment(dec_clean.lower())
        return segmented

    def solve_text(self, ciphertext: str, decoder: str = "lm", passes: int = 5,
                   max_workers: Optional[int] = None, enable_seg: bool = True) -> DecryptionResult:
        if max_workers is None:
            max_workers = max(1, os.cpu_count() or 1)

        # Auto-tune window/step if requested
        if self.auto_ws:
            w_opt, s_opt = self.auto_tune_window_step(ciphertext)
            self.window, self.step = w_opt, s_opt
            print(f"{Term.CYAN}[auto-ws] Selected window={w_opt}, step={s_opt}{Term.END}")
        else:
            w_opt, s_opt = self.window, self.step

        print(f"{Term.CYAN}Computing windowed periodogram / IoC profiles (window={w_opt}, step={s_opt})...{Term.END}")
        cands = self.candidate_key_lengths(ciphertext, window=w_opt, step=s_opt)
        print(f"{Term.CYAN}Testing key lengths: {cands}{Term.END}")

        best: Optional[DecryptionResult] = None
        best_score = float('inf')
        t0 = time.time()

        def _job(m):
            return self.try_key_length(ciphertext, m, window=w_opt, step=s_opt, decoder=decoder, passes=passes)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = [ex.submit(_job, m) for m in cands]
                for fut in concurrent.futures.as_completed(futs):
                    res = fut.result()
                    if res.score < best_score:
                        best, best_score = res, res.score
                        print(f"{Term.YELLOW}[*] New best m={res.key_length} key={res.key} score={res.score:.4f} IoC={res.ioc:.4f}{Term.END}")
        except KeyboardInterrupt:
            print(f"\n{Term.RED}[!] Interrupted. Returning best-so-far if any.{Term.END}")

        if not best:
            raise RuntimeError("No solution found")
        print(f"{Term.GREEN}[+] Done in {time.time()-t0:.2f}s | best m={best.key_length} key={best.key} score={best.score:.4f}{Term.END}")

        # Present a readable version too
        parsed, cleaned = self.parse_text_with_meta(ciphertext)
        dec = decrypt_vigenere(cleaned, best.key)
        formatted = self.format_from_meta(parsed, dec)
        readable = self._readable_text(parsed, dec, formatted, enable_seg)

        # Attach readable back to the result object for printing
        best.decrypted = dec
        best.formatted = readable
        return best

# ---------------------------
# CLI
# ---------------------------
def main():
    rng = random.SystemRandom()
    alphabet = string.ascii_uppercase
    ap = argparse.ArgumentParser(description="Vigenère solver (KN LM + auto window/step + tokenizer)")
    ap.add_argument("--lang", default="language_data.json", help="Path to language_data.json")
    ap.add_argument("--input", "-i", help="File with triple-quoted ciphertext blocks")
    ap.add_argument("--workers", type=int, default=None, help="Thread pool size")

    # Auto window/step
    ap.add_argument("--no-auto-ws", action="store_true", help="Disable auto-tuning of (window, step)")
    ap.add_argument("--window", type=int, default=None, help="(Override) window size")
    ap.add_argument("--step", type=int, default=None, help="(Override) step size")
    ap.add_argument("--ws-beam", type=int, default=6, help="Beam size for auto window/step search")
    ap.add_argument("--ws-passes", type=int, default=2, help="Beam passes for auto window/step search")

    # Decoder / LM parameters
    ap.add_argument("--decoder", choices=["lm","legacy"], default="lm", help="Key optimizer: KN LM or legacy")
    ap.add_argument("--passes", type=int, default=5, help="Max optimization passes per key length")
    ap.add_argument("--anneal", type=float, default=0.0, help="Simulated annealing temperature (LM decoder)")
    ap.add_argument("--lm-weight", type=float, default=0.65, help="Blend between KN-LM NLL and legacy score")

    # Generation
    ap.add_argument("--generate", "-g", type=int, help="Generate N test ciphertext blocks")
    ap.add_argument("--words", type=int, default=200, help="Words per generated chunk")
    ap.add_argument("--min-key", type=int, default=3, help="Min key length for generation")
    ap.add_argument("--max-key", type=int, default=50, help="Max key length for generation")
    ap.add_argument("--out", default="generated_ciphertexts.txt", help="Output path (for generation or encryption)")

    # Encryption of raw plaintext with meta
    ap.add_argument("--encrypt-file", help="Encrypt plaintext file and write triple-quoted ciphertext")
    ap.add_argument("--key", help="Vigenère key for --encrypt-file")

    # Post-processing / segmentation
    ap.add_argument("--no-seg", action="store_true", help="Disable LM word segmentation for blob plaintexts")

    # Optional reproducibility
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for generation")
    args = ap.parse_args()

    # Mode 1: Generate synthetic test ciphertexts
    if args.generate:
        cts, keys, plains = generate_english_cipher_blocks(
            num_chunks=args.generate, words_per_chunk=args.words,
            keylen_min=args.min_key, keylen_max=args.max_key,
            seed=args.seed, out_path=args.out
        )
        print(f"{Term.GREEN}[+] Wrote {len(cts)} ciphertext blocks to {args.out}{Term.END}")
        print(f"{Term.YELLOW}[*] Keys saved to {args.out}.keys.json{Term.END}")
        return

    # Mode 2: Encrypt a raw plaintext letter and emit meta
    if args.encrypt_file:
        if not args.key:
            length = rng.randint(3, 50)
            args.key = ''.join(rng.choice(alphabet) for _ in range(length))
        plaintext = Path(args.encrypt_file).read_text(encoding="utf-8")
        ciphertext, meta = encrypt_with_meta(plaintext, args.key)
        out_path = Path(args.out)
        out_path.write_text(f'"""\n{ciphertext}\n"""\n', encoding="utf-8")
        meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"{Term.GREEN}[+] Encrypted to {out_path}{Term.END}")
        print(f"{Term.YELLOW}[*] Meta written to {meta_path}{Term.END}")
        return

    # Mode 3: Solve ciphertext blocks
    if not args.input:
        ap.error("Either --generate N, --encrypt-file FILE --key KEY, or --input FILE must be provided.")

    solver = VigenereSolver(
        args.lang,
        window=args.window, step=args.step,
        use_windowed_keys=True,
        anneal=args.anneal, lm_weight=args.lm_weight,
        auto_ws=not args.no_auto_ws,
        ws_beam=args.ws_beam, ws_passes=args.ws_passes
    )
    blocks = CiphertextParser.parse_file(args.input)
    if not blocks:
        print(f"{Term.RED}[!] No ciphertext blocks found in {args.input}{Term.END}")
        return

    print(f"{Term.BLUE}Found {len(blocks)} ciphertext blocks.{Term.END}")
    for idx, ct in enumerate(blocks, 1):
        print(f"\n{Term.BOLD}=== Block {idx}/{len(blocks)} ==={Term.END}")
        res = solver.solve_text(ct, decoder=args.decoder, passes=args.passes, max_workers=args.workers, enable_seg=not args.no_seg)
        print(f"{Term.GREEN}KeyLen={res.key_length} Key={res.key}{Term.END}")
        print(f"IoC={res.ioc:.4f} Score={res.score:.4f} KasiskiCount={res.kasiski}")
        print("\nDecrypted (readable):")
        print(res.formatted[:1200] + ("..." if len(res.formatted) > 1200 else ""))

if __name__ == "__main__":
    main()
