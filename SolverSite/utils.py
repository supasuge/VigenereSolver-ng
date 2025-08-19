#!/usr/bin/env python3
# utils.py (LLM-style KN language model + word segmenter + helpers)
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Iterable
from pathlib import Path
from collections import Counter, defaultdict
import json, math, random, re

A, Z = ord('A'), ord('Z')
ALPH = [chr(A+i) for i in range(26)]
ALPH_SET = set(ALPH)

# -------------------------------
# Data models
# -------------------------------
@dataclass
class LanguageModel:
    name: str
    monograms: Dict[str, float]
    bigrams: Dict[str, float]
    trigrams: Dict[str, float]
    quadgrams: Dict[str, float]
    quintgrams: Dict[str, float]

@dataclass
class DecryptionResult:
    key_length: int
    key: str
    decrypted: str
    formatted: str
    flag: Optional[str]
    ioc: float
    score: float
    kasiski: float
    frequency: float

def _upper_keys(d: Dict[str, float]) -> Dict[str, float]:
    return {k.upper(): float(v) for k, v in d.items()}

def load_language_data(path: Path | str = "language_data.json") -> LanguageModel:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Optional dictionary for segmenter
    globals()['_WORD_LIST'] = [w.strip().upper() for w in data.get("english_words", []) if isinstance(w, str) and w.strip()]
    return LanguageModel(
        name="english",
        monograms=_upper_keys(data["english_monograms"]),
        bigrams=_upper_keys(data.get("english_bigrams_1", {})),
        trigrams=_upper_keys(data["english_trigrams"]),
        quadgrams=_upper_keys(data["english_quadgrams"]),
        quintgrams=_upper_keys(data["english_quintgrams"]),
    )

def clean_upper_letters(text: str) -> str:
    """Uppercase and keep only A..Z."""
    return ''.join(ch for ch in text.upper() if 'A' <= ch <= 'Z')

def counts26(text: str) -> Tuple[List[int], int]:
    c = [0]*26
    n = 0
    for ch in text:
        o = ord(ch)
        if A <= o <= Z:
            c[o - A] += 1
            n += 1
    return c, n

class CiphertextParser:
    """
    Extract ciphertext blocks surrounded by triple quotes:
    """
    QUOTE_RX = re.compile(r'"""(.*?)"""', re.DOTALL)

    @staticmethod
    def parse_file(filename: str) -> List[str]:
        try:
            data = Path(filename).read_text(encoding="utf-8", errors="ignore")
        except FileNotFoundError:
            print(f"[!] File not found: {filename}")
            return []
        blocks = CiphertextParser.QUOTE_RX.findall(data)
        return [blk.strip() for blk in blocks if blk.strip()]

    @staticmethod
    def parse_text(data: str) -> List[str]:
        blocks = CiphertextParser.QUOTE_RX.findall(data or "")
        return [blk.strip() for blk in blocks if blk.strip()]

    @staticmethod
    def parse_string(data: str) -> List[str]:
        blocks = CiphertextParser.QUOTE_RX.findall(data or "")
        if not blocks:
            # If no triple-quoted blocks found, treat the entire text as a single block
            return [data.strip()] if data.strip() else []
        return [blk.strip() for blk in blocks if blk.strip()]


def encrypt_vigenere(text: str, key: str) -> str:
    key = key.upper()
    out, i = [], 0
    for ch in text:
        if ch.isalpha():
            p = ord(ch.upper()) - A
            k = ord(key[i % len(key)]) - A
            out.append(chr(A + ((p + k) % 26)))
            i += 1
        else:
            out.append(ch)
    return ''.join(out)

def decrypt_vigenere(text: str, key: str) -> str:
    key = key.upper()
    out, i = [], 0
    for ch in text:
        if ch.isalpha():
            c = ord(ch.upper()) - A
            k = ord(key[i % len(key)]) - A
            out.append(chr(A + ((c - k) % 26)))
            i += 1
        else:
            out.append(ch)
    return ''.join(out)

def random_key(length: int) -> str:
    return ''.join(chr(A + random.randrange(26)) for _ in range(length))

class KneserNeyLM:
    """
    Interpolated KN over uppercase A..Z text, using n=3..5 tables from language_data.json.
    Uses absolute discounting with D=0.75 and continuation probabilities derived from unique
    continuations/predecessors computed from bigram+/higher tables.
    """
    def __init__(self,
                 counts_3: Dict[str, float],
                 counts_4: Dict[str, float],
                 counts_5: Dict[str, float],
                 counts_2: Optional[Dict[str, float]] = None,
                 counts_1: Optional[Dict[str, float]] = None,
                 discount: float = 0.75):
        # Validate keys
        self.c3 = {k: float(v) for k, v in counts_3.items() if len(k) == 3 and set(k) <= ALPH_SET}
        self.c4 = {k: float(v) for k, v in counts_4.items() if len(k) == 4 and set(k) <= ALPH_SET}
        self.c5 = {k: float(v) for k, v in counts_5.items() if len(k) == 5 and set(k) <= ALPH_SET}
        self.c2 = {k: float(v) for k, v in (counts_2 or {}).items() if len(k) == 2 and set(k) <= ALPH_SET}
        self.c1 = {k: float(v) for k, v in (counts_1 or {}).items() if len(k) == 1 and set(k) <= ALPH_SET}

        self.D = float(discount)
        # Precompute prefix sums and unique continuation counts
        self._prep_prefix_structs()

    @classmethod
    def from_language_model(cls, lm: LanguageModel, discount: float = 0.75) -> "KneserNeyLM":
        return cls(
            counts_3=lm.trigrams,
            counts_4=lm.quadgrams,
            counts_5=lm.quintgrams,
            counts_2=lm.bigrams,
            counts_1=lm.monograms,
            discount=discount
        )

    def _pref_counts_unique(self, counts_n: Dict[str, float], n: int):
        """Return (prefix_count_sum, unique_continuations_count) for order n counts."""
        pref_sum: Dict[str, float] = defaultdict(float)
        unique_next: Dict[str, int] = defaultdict(int)
        seen: Dict[str, set] = defaultdict(set)
        for g, cnt in counts_n.items():
            prefix, nxt = g[:-1], g[-1]
            pref_sum[prefix] += cnt
            if nxt not in seen[prefix]:
                seen[prefix].add(nxt)
        for p, s in seen.items():
            unique_next[p] = len(s)
        return dict(pref_sum), dict(unique_next)

    def _unique_predecessors_for_unigram(self, bigrams: Dict[str, float]) -> Tuple[Dict[str, int], int]:
        # N1+(* w) for each token; and total unique bigrams N1+(* *)
        lefts: Dict[str, set] = defaultdict(set)
        for bg, cnt in bigrams.items():
            if cnt <= 0: continue
            left, right = bg[0], bg[1]
            lefts[right].add(left)
        uniq_left = {w: len(s) for w, s in lefts.items()}
        total_unique_bigrams = sum(1 for _ in bigrams.keys()) if bigrams else 26*26
        return uniq_left, total_unique_bigrams if total_unique_bigrams > 0 else 1

    def _prep_prefix_structs(self):
        self.pref3, self.ucont3 = self._pref_counts_unique(self.c3, 3)
        self.pref4, self.ucont4 = self._pref_counts_unique(self.c4, 4)
        self.pref5, self.ucont5 = self._pref_counts_unique(self.c5, 5)
        self.uniq_left_unigram, self.total_uniq_bigrams = self._unique_predecessors_for_unigram(self.c2 if self.c2 else {})

        # For fallback unigram probs if KN base is zero
        total_uni = sum(self.c1.values()) if self.c1 else 0.0
        if total_uni > 0:
            self.unigram_mle = {ch: self.c1.get(ch, 0.0)/total_uni for ch in ALPH}
        else:
            self.unigram_mle = {ch: 1.0/26.0 for ch in ALPH}

    # ---- KN probability primitives ----
    def _p_cont_unigram(self, w: str) -> float:
        # Continuation prob for unigram: N1+(* w) / N1+(* *)
        num = self.uniq_left_unigram.get(w, 0)
        den = self.total_uniq_bigrams
        if den <= 0:
            return 1.0/26.0
        p = num / den
        if p == 0.0:
            return 1.0/26.0
        return p

    def _p_kn(self, ctx: str, w: str) -> float:
        """
        KN with interpolation, max order = len(ctx)+1 up to 5.
        ctx and w are uppercase letters.
        """
        L = len(ctx)
        if L >= 4:
            prefix = ctx[-4:]
            c_pref = self.pref5.get(prefix, 0.0)
            c_ng   = self.c5.get(prefix + w, 0.0)
            if c_pref > 0:
                D = self.D
                n1 = self.ucont5.get(prefix, 0)
                lam = (D * n1) / c_pref
                base = max(c_ng - D, 0.0) / c_pref
                return base + lam * self._p_kn(ctx[1:], w)
            else:
                return self._p_kn(ctx[1:], w)
        elif L == 3:
            prefix = ctx
            c_pref = self.pref4.get(prefix, 0.0)
            c_ng   = self.c4.get(prefix + w, 0.0)
            if c_pref > 0:
                D = self.D
                n1 = self.ucont4.get(prefix, 0)
                lam = (D * n1) / c_pref
                base = max(c_ng - D, 0.0) / c_pref
                return base + lam * self._p_kn(ctx[1:], w)
            else:
                return self._p_kn(ctx[1:], w)
        elif L == 2:
            prefix = ctx
            c_pref = self.pref3.get(prefix, 0.0)
            c_ng   = self.c3.get(prefix + w, 0.0)
            if c_pref > 0:
                D = self.D
                n1 = self.ucont3.get(prefix, 0)
                lam = (D * n1) / c_pref
                base = max(c_ng - D, 0.0) / c_pref
                return base + lam * self._p_kn(ctx[1:], w)
            else:
                return self._p_kn(ctx[1:], w)
        elif L == 1:
            if self.c2:
                return self._p_cont_unigram(w)
            return self.unigram_mle.get(w, 1.0/26.0)
        else:
            return self._p_cont_unigram(w)

    def neglog_per_char(self, text: str, order_max: int = 5) -> float:
        s = clean_upper_letters(text)
        if not s:
            return float('inf')
        total = 0.0
        for i, w in enumerate(s):
            k = min(order_max-1, i)
            ctx = s[i-k:i]
            p = self._p_kn(ctx, w)
            if p <= 0.0:
                p = 1e-12
            total += -math.log(p)
        return total / len(s)

    def gram_logprob_fixed(self, gram: str) -> float:
        L = len(gram)
        if L < 1:
            return 0.0
        s = gram
        total = 0.0
        for i, w in enumerate(s):
            k = min(L-1, i)
            ctx = s[i-k:i]
            p = self._p_kn(ctx, w)
            if p <= 0.0: p = 1e-12
            total += -math.log(p)
        return total


class VigenereStatsMixin:
    english_freqs: Dict[str, float]
    trigrams: Dict[str, float]
    quadgrams: Dict[str, float]
    quintgrams: Dict[str, float]

    def _prep_monogram_vec(self):
        self._eng_vec = [self.english_freqs.get(chr(A+i), 0.0) for i in range(26)]
        s = sum(self._eng_vec) or 1.0
        self._eng_vec = [x / s for x in self._eng_vec]
        self._ioc_eng = sum(p*p for p in self._eng_vec)   # ~0.066
        self._ioc_rand = 1.0 / 26.0                       # ~0.03846

    def chi2_reduced(self, text: str) -> float:
        text = clean_upper_letters(text)
        counts, n = counts26(text)
        if n == 0:
            return float('inf')
        chi2 = 0.0
        for i in range(26):
            exp = self._eng_vec[i] * n
            obs = counts[i]
            if exp <= 0: continue
            chi2 += (obs - exp) ** 2 / exp
        return chi2 / 25.0

    def js_divergence(self, text: str) -> float:
        text = clean_upper_letters(text)
        counts, n = counts26(text)
        if n == 0:
            return float('inf')
        p = [c/n for c in counts]
        q = self._eng_vec
        m = [(pi+qi)/2.0 for pi, qi in zip(p, q)]
        def _kl(a, b):
            s = 0.0
            for ai, bi in zip(a, b):
                if ai > 0.0 and bi > 0.0:
                    s += ai * math.log(ai / bi)
            return s
        return 0.5*_kl(p, m) + 0.5*_kl(q, m)

    def calculate_ioc(self, text: str) -> float:
        text = clean_upper_letters(text)
        counts, n = counts26(text)
        if n <= 1:
            return 0.0
        return sum(f*(f-1) for f in counts) / (n*(n-1))

    def estimate_key_length_friedman(self, text: str) -> float:
        Ic = self.calculate_ioc(text)
        num = (self._ioc_eng - self._ioc_rand)
        den = max(Ic - self._ioc_rand, 1e-9)
        return max(1.0, num / den)

    def _prep_ngram_model(self, table: Dict[str, float], n: int):
        total = sum(table.values()) or 1.0
        probs = {k.upper(): (v / total) for k, v in table.items()}
        min_p = min(probs.values()) if probs else 1e-9
        eps = min_p * 0.01
        return probs, eps, n

    def ngram_log_score(self, text: str, model_name: str = "trigram") -> float:
        text = clean_upper_letters(text)
        if model_name == "trigram":
            table, eps, n = self._tri_model
        elif model_name == "quadgram":
            table, eps, n = self._quad_model
        else:
            table, eps, n = self._quint_model

        if len(text) < n:
            return float('inf')
        ll, cnt = 0.0, 0
        for i in range(len(text) - n + 1):
            gram = text[i:i+n]
            p = table.get(gram, eps)
            ll += math.log(p)
            cnt += 1
        return -ll / cnt  # average surprisal

    def plaintext_fitness(self, text: str) -> float:
        chi = self.chi2_reduced(text)
        jsd = self.js_divergence(text)
        tri = self.ngram_log_score(text, "trigram")
        q4  = self.ngram_log_score(text, "quadgram")
        return 0.35*chi + 0.25*jsd + 0.25*tri + 0.15*q4

    def find_key_char(self, coset_text: str) -> Tuple[str, float]:
        coset = clean_upper_letters(coset_text)
        counts, n = counts26(coset)
        if n == 0:
            return 'A', float('inf')
        best_s, best_corr = 0, -1.0
        for s in range(26):
            corr = 0.0
            for k in range(26):
                corr += self._eng_vec[k] * counts[(k + s) % 26]
            if corr > best_corr:
                best_corr, best_s = corr, s
        return chr(A + best_s), -best_corr / n

    def refine_key(self, cleaned_text: str, key: str, passes: int = 2) -> Tuple[str, float]:
        best_key = key
        best_score = self.plaintext_fitness(decrypt_vigenere(cleaned_text, best_key))
        for _ in range(passes):
            improved = False
            for i in range(len(best_key)):
                cur_best_char = best_key[i]
                cur_best = best_score
                for s in range(26):
                    cand = best_key[:i] + chr(A+s) + best_key[i+1:]
                    sc = self.plaintext_fitness(decrypt_vigenere(cleaned_text, cand))
                    if sc < cur_best:
                        cur_best, cur_best_char = sc, chr(A+s)
                if cur_best_char != best_key[i]:
                    best_key = best_key[:i] + cur_best_char + best_key[i+1:]
                    best_score = cur_best
                    improved = True
            if not improved:
                break
        return best_key, best_score

    # ---------- Sliding windows / periodogram ----------
    def _sliding_segments(self, text: str, window: int, step: int):
        s = clean_upper_letters(text)
        if window <= 0 or step <= 0 or len(s) == 0:
            return
        end = max(0, len(s) - window)
        for start in range(0, end + 1, step):
            yield start, s[start:start+window]

    def ioc_profile(self, text: str, window: int = 600, step: int = 150) -> List[Tuple[int,float]]:
        return [(start, self.calculate_ioc(seg)) for start, seg in self._sliding_segments(text, window, step)]

    def jsd_profile(self, text: str, window: int = 600, step: int = 150) -> List[Tuple[int,float]]:
        return [(start, self.js_divergence(seg)) for start, seg in self._sliding_segments(text, window, step)]

    def coincidence_periodogram(self, s: str, max_lag: int = 50) -> List[float]:
        s = clean_upper_letters(s)
        N = len(s)
        out = [0.0]*max_lag
        for lag in range(1, max_lag+1):
            M = N - lag
            if M <= 0:
                out[lag-1] = 0.0
                continue
            matches = 0
            for i in range(M):
                if s[i] == s[i+lag]:
                    matches += 1
            out[lag-1] = matches / M
        return out

    def windowed_coincidence_periodogram(self, text: str, max_lag: int = 50, window: int = 600, step: int = 150) -> List[float]:
        acc = [0.0]*max_lag
        ct = 0
        for _, seg in self._sliding_segments(text, window, step):
            per = self.coincidence_periodogram(seg, max_lag)
            acc = [a + b for a, b in zip(acc, per)]
            ct += 1
        if ct == 0:
            return acc
        return [a / ct for a in acc]

    def key_lengths_from_periodogram(self, period: List[float], topk: int = 8, nms: int = 1) -> List[int]:
        cands = sorted([(i+1, s) for i, s in enumerate(period)], key=lambda x: x[1], reverse=True)
        out: List[int] = []
        for lag, _ in cands:
            if any(abs(lag - x) <= nms for x in out):
                continue
            out.append(lag)
            if len(out) >= topk:
                break
        return out

    def windowed_key_vote(self, text: str, key_len: int, window: int = 600, step: int = 150) -> str:
        s = clean_upper_letters(text)
        from collections import Counter as Cnt
        votes = [Cnt() for _ in range(key_len)]
        for _, seg in self._sliding_segments(s, window, step):
            cosets = [''.join(seg[i::key_len]) for i in range(key_len)]
            jsd = self.js_divergence(seg)
            w = 1.0 / max(jsd, 1e-6)
            for i, coset in enumerate(cosets):
                ch, _ = self.find_key_char(coset)
                votes[i][ch] += w
        key = ''.join(v.most_common(1)[0][0] if v else 'A' for v in votes)
        key, _ = self.refine_key(s, key, passes=2)
        return key


def kasiski_examination(text: str, min_len: int = 3, max_len: int = 5) -> List[int]:
    s = clean_upper_letters(text)
    positions: Dict[str, List[int]] = {}
    for L in range(min_len, max_len+1):
        for i in range(len(s) - L):
            seq = s[i:i+L]
            positions.setdefault(seq, []).append(i)
    distances = []
    for pos in positions.values():
        if len(pos) >= 2:
            for i in range(len(pos) - 1):
                d = pos[i+1] - pos[i]
                if d > 5:
                    distances.append(d)
    if not distances:
        return list(range(6, 31, 2))
    def _factors(d: int) -> List[int]:
        out = []
        for i in range(2, min(31, d+1)):
            if d % i == 0:
                out.append(i)
        return out
    allf = []
    for d in distances:
        allf.extend(_factors(d))
    cnt = Counter(allf)
    cands = [k for k, _ in cnt.most_common() if 2 <= k <= 30]
    return cands[:8] if cands else list(range(6,31,2))

# -------------------------------
# Generator: English-ish plaintext -> ciphertext blocks
# -------------------------------
def _ensure_nltk() -> Optional[object]:
    try:
        import nltk
        return nltk
    except Exception:
        return None

def _try_download(nltk, pkg: str):
    try:
        nltk.data.find(f'corpora/{pkg}')
    except LookupError:
        nltk.download(pkg, quiet=True)

def generate_english_cipher_blocks(
    num_chunks: int = 5,
    words_per_chunk: int = 200,
    keylen_min: int = 3,
    keylen_max: int = 50,
    seed: Optional[int] = None,
    out_path: Optional[str] = None
) -> Tuple[List[str], List[str], List[str]]:
    if seed is not None:
        random.seed(seed)

    nltk = _ensure_nltk()
    words: List[str] = []
    if nltk:
        from nltk.corpus import gutenberg, brown, reuters
        for corp in ("gutenberg", "brown", "reuters"):
            try:
                _try_download(nltk, corp)
                corpus_mod = {"gutenberg": gutenberg, "brown": brown, "reuters": reuters}[corp]
                words = list(corpus_mod.words())
                if len(words) > 10000:
                    break
            except Exception:
                continue

    if not words:
        words = ("the of and to in a is that be it for on as with by this you not "
                 "are or have from at which one had were all we can her has there").upper().split()

    plains, keys, ciphers = [], [], []
    for _ in range(num_chunks):
        chunk_words = []
        while len(chunk_words) < words_per_chunk:
            w = random.choice(words)
            w = re.sub(r'[^A-Za-z]', '', w).upper()
            if w:
                chunk_words.append(w)
        plain = ' '.join(chunk_words)
        klen = random.randint(keylen_min, keylen_max)
        key = random_key(klen)
        cipher = encrypt_vigenere(plain, key)
        plains.append(plain); keys.append(key); ciphers.append(cipher)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            for ct in ciphers:
                f.write('"""\n'); f.write(ct); f.write('\n"""\n\n')
        side = Path(out_path).with_suffix(".keys.json")
        with open(side, "w", encoding="utf-8") as sf:
            json.dump({"keys": keys}, sf, indent=2)
    return ciphers, keys, plains

# -------------------------------
# Word segmentation (readability post-processing)
# -------------------------------
class WordSegmenter:
    """
    Simple DP (Viterbi-style) word segmenter for uppercase A..Z strings.
    Uses a word list from language_data.json["english_words"] if present,
    otherwise falls back to a built-in top-words list.
    """
    def __init__(self, vocab: List[str]):
        vocab = [w for w in vocab if w.isalpha()]
        # Build rank-based cost (Zipf-ish): cost ~ log(rank)
        # Ensure common words are cheaper.
        self.vocab = sorted(set(w.upper() for w in vocab), key=len, reverse=True)
        if not self.vocab:
            self.vocab = [w.upper() for w in """
            THE OF AND TO IN A IS THAT IT FOR ON AS WITH BY THIS YOU NOT ARE OR HAVE FROM AT WHICH
            ONE HAD WERE ALL WE CAN HER HAS THERE THEIR MORE BE WOULD WHEN WHO WILL NO IF ABOUT OUT
            UP SO WHAT SOME INTO COULD THEM TIME ONLY YEAR OVER NEW OTHER PEOPLE THAN FIRST WATER
            LIKE THEN NOW LOOK ALSO EVEN BACK AFTER USE TWO HOW OUR WORK WAY WELL LIFE KNOW
            """.split()]
        self.max_len = max(len(w) for w in self.vocab)
        self.cost = {w: math.log(1 + i) for i, w in enumerate(self.vocab)}

    @classmethod
    def load_default(cls) -> "WordSegmenter":
        wl = globals().get('_WORD_LIST', [])
        return cls(wl or [])

    def segment(self, text_lower: str) -> str:
        s = ''.join(ch for ch in text_lower if 'a' <= ch <= 'z' or 'A' <= ch <= 'Z').upper()
        n = len(s)
        if n == 0:
            return ""
        # DP over positions, store (cost, last_len)
        dp_cost = [1e18]*(n+1); dp_cost[0] = 0.0
        last_len = [0]*(n+1)
        for i in range(1, n+1):
            best_c = 1e18; best_k = 1
            # try up to max_len
            start = max(0, i - self.max_len)
            for j in range(start, i):
                w = s[j:i]
                base = dp_cost[j]
                # in-vocab cheap, else penalty ~ length
                add = self.cost.get(w, 1.5 + 0.6*len(w))
                c = base + add
                if c < best_c:
                    best_c, best_k = c, i - j
            dp_cost[i] = best_c; last_len[i] = best_k
        # reconstruct
        out = []
        i = n
        while i > 0:
            k = last_len[i]
            out.append(s[i-k:i])
            i -= k
        out.reverse()
        return ' '.join(w.lower() for w in out)
