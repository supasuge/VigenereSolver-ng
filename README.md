# vigenere

[![CI](https://github.com/supasuge/vigenere/actions/workflows/ci.yml/badge.svg)](https://github.com/supasuge/vigenere/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A refactored Vigenere cipher solver that combines classical cryptanalysis
(Kasiski, index of coincidence, FFT coincidence periodogram, twist/twist++)
with modern decoding (per-strip beam search + interpolated character n-gram
language model) and a learned posterior over key lengths. Pure-Python core,
numpy for the FFT, optional `rich` for live progress.

On the easy regime (random English plaintext, key length 4–12, 400+
characters) the **`best` decoder hits 100% key-recovery accuracy across
30 random samples**. On a learned-weights posterior the key-length detector
reaches **96.7% top-1 / 100% top-3** out of 30 candidates.

---

## Part I — Mathematical model

This section gives the full equations behind every stage of the pipeline
and the intuition for why each one works.

### 1. The Vigenere cipher

Let the alphabet be $\Sigma = \{A,\dots,Z\}$ with $|\Sigma| = c = 26$,
identified with $\mathbb{Z}_{26}$. Let the plaintext be
$p = p_0 p_1 \dots p_{n-1}$ and the key be $k = k_0 k_1 \dots k_{m-1}$
with $m \ll n$. Then:

$$
c_i \;=\; (p_i + k_{i \bmod m}) \bmod 26
\qquad
p_i \;=\; (c_i - k_{i \bmod m}) \bmod 26
$$

Implemented in [alphabet.py](src/vigenere/alphabet.py) as `encrypt` /
`decrypt` (non-letter characters pass through; case is normalized to upper).

The cipher is a length-$m$ rotation of $m$ independent Caesar ciphers
("strips") interleaved by position. **Key insight:** if we knew $m$, we
could split the ciphertext into the $m$ strips
$S_j = (c_j, c_{j+m}, c_{j+2m}, \dots)$, each of which is a monoalphabetic
Caesar shift by $k_j$ — easy to attack column-by-column.

### 2. Index of Coincidence (IoC)

Given letter counts $n_1, \dots, n_c$ with $N = \sum n_i$, the IoC is the
probability that two random draws (without replacement) give the same
letter, scaled by $c$:

$$
\mathrm{IoC}(T) \;=\; c \cdot \frac{\sum_{i=1}^{c} n_i (n_i - 1)}{N(N-1)}
\;=\; \frac{\sum_{i=1}^{c} n_i (n_i - 1)}{N(N-1)/c}
$$

Under a uniform alphabet $\mathrm{IoC} \to 1$; English text piles mass on
E, T, A, O, … so $\mathrm{IoC}_{\text{Eng}} \approx 1.73$.

The Vigenere ciphertext as a whole flattens the histogram so its overall
IoC is close to $1.0$. But the per-strip IoCs $\mathrm{IoC}(S_j)$ are each
measured on a pure Caesar shift of English text, so they preserve the
English IoC. The **strip-IoC test for the key length:**

$$
\overline{\mathrm{IoC}}(m) \;=\; \frac{1}{m} \sum_{j=0}^{m-1} \mathrm{IoC}(S_j)
$$

We expect $\overline{\mathrm{IoC}}(m^\star) \approx 1.73$ at the true key
length, and $\approx 1.0$ for wrong lengths.

Implemented in [stats.py](src/vigenere/stats.py).

### 3. Coincidence periodogram (FFT)

For each letter $a \in \Sigma$, build the indicator signal
$x_a[t] = \mathbb{1}[\text{ciphertext}_t = a]$. The **coincidence count
at lag $k$** is

$$
R[k] \;=\; \sum_{a \in \Sigma} \sum_{t=0}^{n-k-1} x_a[t]\, x_a[t+k]
$$

If $k$ is a multiple of the true key length $m^\star$, positions $t$ and
$t+k$ are encrypted with the **same** shift, so the letters agree
exactly when the underlying plaintext letters agreed — $R[k]$ inherits
the English coincidence rate. For non-multiples, the shifts differ and
$R[k]$ falls toward the uniform rate $n/c$.

Computed in $O(n \log n)$ via the Wiener–Khinchin theorem:
$X_a = \mathcal{F}(x_a)$, then $R_a[k] = \mathcal{F}^{-1}(|X_a|^2)[k]$,
$R[k] = \sum_a R_a[k]$. Normalized by the overlap $n - k$:
$\widetilde{R}[k] = R[k]/(n-k)$.

**Harmonic suppression** — the true period $m^\star$ produces a series of
peaks at $m^\star, 2m^\star, \dots$; non-maximum suppression and a $0.8$
penalty on the $2m^\star$ / $3m^\star$ harmonics push the *fundamental*
to the top of the ranking.

Implemented in [keylength/periodogram.py](src/vigenere/keylength/periodogram.py).

### 4. Kasiski examination

If a substring $s$ of length $\geq 3$ appears at positions $p_1 < p_2$,
the most common explanation is that the same plaintext appeared twice
against the same key residue class — so $m^\star \mid (p_2 - p_1)$. For
each repeated substring, take every distance $d$ and emit every divisor
$k \in [2, k_{\max}]$ of $d$ as a vote:

$$
V(k) \;=\; \big|\{ (d, k) : k \mid d, \; k \in [2, k_{\max}] \}\big|
$$

Implemented in [keylength/kasiski.py](src/vigenere/keylength/kasiski.py).

### 5. Twist & Twist++

The **twist** algorithm (Barr & Simoes, 2015) is an alternative
key-length detector that's especially robust on short or noisy texts. For
each candidate $m$:

1. Partition the ciphertext into $m$ strips.
2. For each strip compute the per-letter frequency vector and sort it
   **descending** — this discards which letter is which but preserves
   the *shape* of the distribution.
3. Average the sorted vectors across strips → $\bar P$. If every strip
   is a shifted English text, $\bar P$ looks like the sorted English
   unigram distribution.
4. The twist is the imbalance between the top and bottom halves:

$$
T(m) \;=\; \sum_{i=0}^{12} \bar P_i \;-\; \sum_{i=13}^{25} \bar P_i
\;=\; 1 - 2 \sum_{i \geq 13} \bar P_i
$$

with $T \in [0, 1]$. Uniform $\Rightarrow 0$, English $\approx 0.70$.

**Twist++** subtracts the running mean of the smaller-$k$ twists:

$$
T^{++}(m) \;=\; T(m) \;-\; \frac{1}{m-1} \sum_{j=1}^{m-1} T(j)
$$

This penalises harmonics of the true period: $2m^\star$ also produces
"shifted-English" strips and would tie with $m^\star$ under bare twist;
the running-mean correction breaks the tie in favour of the fundamental.

Implemented in [keylength/twist.py](src/vigenere/keylength/twist.py).
LRU-cached so repeated calls on the same text are O(1).

### 6. Combined key-length posterior

We have four signals for each $k$:

$$
\begin{aligned}
s_1(k) &= \overline{\mathrm{IoC}}(k) \\
s_2(k) &= \mathbb{1}[k \in V^\star] \\
s_3(k) &= \widetilde{R}[k] \\
s_4(k) &= T^{++}(k)
\end{aligned}
$$

Z-score the continuous ones and combine linearly, then softmax:

$$
z_i(k) \;=\; \frac{s_i(k) - \mu_i}{\sigma_i + \varepsilon},
\quad
\ell(k) \;=\; w_1 z_1(k) + w_2 s_2(k) + w_3 z_3(k) + w_4 z_4(k)
$$

$$
P(m=k \mid \text{ciphertext}) \;=\; \mathrm{softmax}_k(\ell(k))
$$

**The weights $(w_1,\dots,w_4)$ are learned from data** (see §11) and
default to $(0.014, 2.60, 0.79, 4.46)$. Implemented in
[keylength/posterior.py](src/vigenere/keylength/posterior.py).

### 7. Per-strip Caesar candidates + beam search

Fix a candidate $m$. For each strip $j$ and each shift
$s \in \{0, \dots, 25\}$, decrypt the strip and compare its histogram
$\hat q$ to the English unigram prior $\pi$ via **Jensen–Shannon
divergence**:

$$
\mathrm{JSD}(P \| Q) \;=\; \tfrac{1}{2} D_{KL}(P \| M) + \tfrac{1}{2} D_{KL}(Q \| M),
\quad M = \tfrac{1}{2}(P + Q)
$$

Use $-\mathrm{JSD}$ so higher = more English-like. Keep the top
$M_{\text{strip}}$ shifts per column. Then **beam search** across
columns: at column $j$, extend every surviving partial key by every
kept shift, score by the sum of per-strip scores, keep the top $B$
beams. Implemented in [search.py](src/vigenere/search.py).

### 8. Full-text re-ranking

The beam ignores correlations across columns. We re-rank candidate keys
by scoring the full decrypted plaintext under one of:

- **Legacy**: $-\mathrm{JSD}(\hat p_{\text{text}}, \pi)$.
- **Tiny-LM**: closed-form hardcoded unigram log-prob + bigram bonus
  for the 24 most common bigrams; needs no data file.
- **Classic n-gram (recommended)**: interpolated 1..N-gram char LM with
  weights $\lambda_n$ and additive smoothing $\alpha$:

$$
P(t_i \mid \text{ctx}) = \sum_{n=1}^{N} \lambda_n \hat P_n(t_{i-n+1}\dots t_i),
\quad
\log P(\text{text}) = \sum_i \log \max(P(t_i \mid \text{ctx}), \varepsilon)
$$

- **Best (ensemble)**: run every decoder, pool their top-K candidate
  keys, re-rank the union by the classic LM. Strictly $\geq$ any single
  decoder by construction.

Implemented in [scoring/](src/vigenere/scoring/) and combined in
[solver.py](src/vigenere/solver.py).

### 9. Confidence detection

Given the ranked candidates $\{(k_i, \sigma_i)\}$, treat all keys that
decrypt to the **same plaintext** as one answer (this captures
rotations and integer repetitions of the true key, which produce
identical decryptions). The confidence is the margin between the top
score and the best runner-up with a *different* plaintext, normalized by
the candidate spread:

$$
\mathrm{conf} \;=\; \mathrm{clip}_{[0,1]}\!\left(\frac{\sigma_{\text{top}} - \sigma_{\text{runner}^\star}}{\sigma_{\text{top}} - \sigma_{\text{bottom}}}\right)
$$

A unique winner with a clear lead gives values near 1.0; genuinely
ambiguous candidates give values near 0. Implemented in
[solver.py:_confidence_from_candidates](src/vigenere/solver.py).

### 10. Dictionary refinement (optional)

Given a candidate $k$ and a wordlist, slide every word $w$ against the
ciphertext. At offset $i$, position $j$ in the word implies key residue
$k^{(\text{req})}_{(i+j) \bmod m} = (c_{i+j} - w_j) \bmod 26$. If the
match has at most `max_mismatch` disagreements with the current $k$,
register one vote per position. Take the majority vote at each position
and iterate until convergence. Implemented in
[refine.py](src/vigenere/refine.py).

### 11. Hyperparameter tuning (softmax MLE on the posterior)

The four posterior weights $(w_1, w_2, w_3, w_4)$ were originally
hand-tuned. The [`vigenere.tune`](src/vigenere/tune.py) module learns
them from labelled data $\{(\text{ct}_i, m_i^\star)\}_{i=1}^N$ by
maximizing the log-likelihood of the true key length under the softmax:

$$
\mathcal{L}(w) \;=\; \frac{1}{N} \sum_{i=1}^{N}
  \log \frac{\exp(w \cdot s_i(m_i^\star))}{\sum_{k} \exp(w \cdot s_i(k))}
\;-\; \lambda \|w\|^2
$$

The gradient has a closed form (softmax classifier):

$$
\nabla_w \mathcal{L} \;=\; \frac{1}{N} \sum_i \big( s_i(m_i^\star) - \mathbb{E}_{P_i}[s_i(k)] \big) - 2\lambda w
$$

Plain full-batch gradient ascent, no scipy required. On a 150-sample
synthetic corpus the learner converges in ~400 epochs to
$(0.014, 2.60, 0.79, 4.46)$ — **twist++ dominates with 4.5× the default
weight; IoC contributes almost nothing once twist is present**. Top-1
accuracy improves from the hand-tuned baseline to **0.967 / 1.000
top-3** on held-out random samples.

### 12. Parameter optimization (Pareto grid search)

The [`vigenere.optimize`](src/vigenere/optimize.py) module sweeps the
`(decoder, beam, strip_top)` grid on randomly generated samples and
returns:

- the **best cell** by key accuracy (ties broken by mean runtime)
- the **Pareto frontier** — configurations you can't improve on without
  giving something up: $(a, t) \in F$ iff no other $(a', t')$ has
  $a' \geq a \wedge t' \leq t$ with at least one strict
- the **cheapest cell** meeting a configurable accuracy target

On easy data (keylen 4–12, ≥500 chars) the Pareto frontier collapses to
a single point: `(classic, beam=4, strip_top=4)` reaches 100% key
accuracy in ~180 ms, beating the default `beam=16` by ~2× on runtime
for identical accuracy.

### 13. Key-match heuristics

[`vigenere.match`](src/vigenere/match.py) classifies a recovered key
against a known one:

| kind        | meaning                                          | decrypts identically? |
| ----------- | ------------------------------------------------ | --------------------- |
| `exact`     | verbatim equal                                   | yes                   |
| `rotation`  | a cyclic rotation (e.g. `MONLE` vs `LEMON`)      | yes (same plaintext)  |
| `multiple`  | an integer repetition (e.g. `LEMONLEMON`)        | yes                   |
| `close`     | within `max_diff` Hamming distance after rotation| nearly                |
| `none`      | unrelated                                        | no                    |

This is exposed as `SolveResult.match_against(true_key)` and is used by
the benchmark harness so a rotated-key recovery from `legacy` no longer
counts as a miss.

---

## Part II — Code map (function-by-function)

### `vigenere.alphabet` — cipher primitives

| symbol | what it does |
| --- | --- |
| `clean_letters(s)` | strip everything but A–Z, upper-case |
| `encrypt(text, key)` / `decrypt(text, key)` | implement the equations of §1; preserve non-letters |
| `shift_only(letters, s)` | Caesar shift on a letters-only string (decrypt direction) |
| `split_strips(letters, m)` | partition letters-only string into `m` columns $S_j$ |
| `random_key(n, rng)` | uniform random key over A–Z |

### `vigenere.stats` — distributional statistics

| symbol | what it does |
| --- | --- |
| `counts(t)` | length-26 counts vector + total |
| `histogram(t)` | normalized to a probability vector |
| `index_of_coincidence(t)` | $\mathrm{IoC}$ (§2), normalized so uniform ≈ 1 |
| `average_strip_ioc(t, m)` | $\overline{\mathrm{IoC}}(m)$ |
| `kl_divergence(p, q)` / `jensen_shannon(p, q)` | $D_{KL}$ / $\mathrm{JSD}$ |

### `vigenere.language` — n-gram tables

| symbol | what it does |
| --- | --- |
| `LanguageModel` | frozen dataclass with normalized 1..5-gram tables |
| `load_language_model(path)` | load + normalize a JSON file |
| `cached_language_model()` | LRU-cached default |
| `LanguageModel.monogram_vector()` | the prior $\pi$ as a length-26 list |

### `vigenere.keylength` — key-length estimation (§3, §4, §5, §6)

| symbol | what it does |
| --- | --- |
| `coincidence_periodogram(t, kmax)` | $\widetilde{R}[k]$ via FFT |
| `pick_periods(per, kmax, top)` | NMS + harmonic suppression; returns `[(k, score)]` |
| `kasiski_examination(t)` | `[(k, votes)]` sorted desc |
| `twist_score(t, k)` / `twist_table(t, max_k)` | basic twist (§5) |
| `twist_plus_plus_score(t, k)` / `twist_plus_plus_table(t, max_k)` | twist++ (cached) |
| `keylength_posterior(t, max_k, return_table=...)` | combined posterior `[(k, prob)]` from all four signals |

### `vigenere.scoring` — pluggable scorers (§8)

All satisfy the `Scorer` protocol: `name: str`, `.score(text) -> float`
("higher is better").

| class | model |
| --- | --- |
| `LegacyJSDScorer` | $-\mathrm{JSD}(\hat p_{\text{text}}, \pi)$ |
| `TinyLMScorer` | hardcoded unigram log-prob + bigram bonus |
| `ClassicNGramScorer(order, lambdas, alpha)` | interpolated 1..order n-gram char LM |

Factory: `get_scorer(name, **kwargs)`.

### `vigenere.search` — beam search (§7)

| symbol | what it does |
| --- | --- |
| `per_strip_candidates(ct, m, prior, top_m)` | for each strip, return top-`top_m` `(shift, score)` |
| `beam_search(per_strip, beam)` | width-`beam` beam over all strips; returns `[(key, score)]` |

### `vigenere.refine` — wordlist refinement (§10)

| symbol | what it does |
| --- | --- |
| `load_wordlist(path, min_len, max_len, limit)` | normalized, dedup, length-sorted |
| `refine_key(ct, key, words, max_iter, max_mismatch)` | majority-vote per-position |

### `vigenere.match` — key-match classification (§13)

| symbol | what it does |
| --- | --- |
| `hamming(a, b)` | element-wise mismatch count (equal length) |
| `cyclic_distance(pred, true)` | min Hamming over all cyclic rotations of `pred` |
| `classify_match(pred, true, max_diff=2) -> MatchResult` | returns `kind` ∈ {exact, rotation, multiple, close, none}, distance, and a `is_correct` / `is_close` flag |

### `vigenere.tune` — posterior weight learner (§11)

| symbol | what it does |
| --- | --- |
| `synthetic_examples(n, ...)` | generate `(ct, true_keylen)` pairs from the bundled corpus |
| `tune_weights(examples, max_k, epochs, lr, l2) -> TuneResult` | softmax gradient ascent on $\mathcal{L}(w)$; returns weights, log-likelihood, top-1/top-3 accuracy |

### `vigenere.optimize` — Pareto parameter search (§12)

| symbol | what it does |
| --- | --- |
| `optimize_parameters(decoders, beams, strip_tops, n_trials, target_accuracy, ...) -> OptimizeResult` | sweep the grid and pick best/Pareto/cheapest cells |
| `print_optimize_result(result)` | pretty-print the result tables |

### `vigenere.progress` — live progress UI

| class | role |
| --- | --- |
| `NullProgressReporter` | silent (default for tests/library use) |
| `RichProgressReporter` | live panel with progress bar, running-best key+score, posterior bar-chart, stats |
| `make_reporter("rich" \| "none")` | factory |

### `vigenere.solver` — orchestration

```python
solve(
    ciphertext,
    decoder="best",        # "legacy" | "tiny-lm" | "classic" | "best"
    max_k=40,              # max key length to consider
    topk=5,                # how many keys to keep per stage
    top_keylens=5,         # how many key lengths to try
    beam=16,               # beam width
    strip_top=6,           # shifts to keep per strip
    forced_keylens=None,   # e.g. [7] to skip key-length estimation
    wordlist=None,         # optional: refine final key against a dictionary
    seed=None,
    jobs=1,                # parallel workers (numpy/threads)
    progress=None,         # ProgressReporter; None = silent
) -> SolveResult
```

`SolveResult` fields:

| field                 | meaning                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `key`                 | recovered key (post-refinement if a wordlist was used)           |
| `plaintext`           | `decrypt(ciphertext, key)`                                       |
| `keylen_posterior`    | top-10 `[(k, prob)]`                                             |
| `candidates`          | top-K `[(key, full_text_score)]` — `candidates[0][0] == key`     |
| `scorer_name`         | which decoder won                                                |
| `refined`             | `True` if wordlist refinement changed the key                    |
| `elapsed_sec`         | wall-clock seconds                                               |
| `confidence`          | (§9) ∈ [0,1]                                                     |
| `signals`             | per-signal arrays from the keylength posterior (twist_pp, ioc, …) |
| `match_against(true)` | returns a `MatchResult` (§13)                                    |

### `vigenere.bench` — corpus generation + harness

| symbol | what it does |
| --- | --- |
| `generate_corpus(out_dir, n, ...)` | write `manifest.json` + per-sample `pt/ct/key` files |
| `load_manifest(corpus_dir)` | re-load a generated corpus |
| `run_bench(corpus_dir, decoders, out_csv, jobs)` | evaluate decoders on a disk corpus (multiprocessing) |
| `compare_strategies(n_trials, decoders, beams, strip_tops, jobs, ...)` | random in-memory `(decoder × beam × strip_top)` grid |

### `vigenere.cli` — `argparse` subcommands

`solve` · `encrypt` · `explain` · `bench` · `compare` · `tune` · `optimize` · `gen-corpus`. See below.

---

## Installation

Requires Python ≥ 3.10. Runtime deps: numpy, rich.

```bash
pip install -e ".[dev]"

# or with uv
uv pip install -e ".[dev]"

# Run tests
pytest -v
```

This installs the `vigenere` console script. You can also invoke the
module directly: `python -m vigenere ...`.

---

## Usage

### Library

```python
from vigenere import encrypt, decrypt, solve

ct = encrypt("the quick brown fox jumps over the lazy dog ...", "LEMON")

result = solve(ct, decoder="best")
print(result.key)               # "LEMON"
print(result.plaintext)
print(result.keylen_posterior)  # [(5, 0.41), (10, 0.18), ...]
print(result.candidates)        # [(key, full_text_score), ...] top-5
print(result.confidence)        # 0.92 — strong unique winner
print(result.match_against("LEMON"))  # MatchResult(kind="exact", ...)
print(result.pretty())          # formatted summary
```

Force a known key length to skip estimation:

```python
solve(ct, decoder="classic", forced_keylens=[7])
```

Custom n-gram order or weights:

```python
solve(ct, decoder="classic", scorer_kwargs={
    "order": 5,
    "lambdas": [0.02, 0.08, 0.20, 0.30, 0.40],
    "alpha": 1e-4,
})
```

### CLI

```bash
# Encrypt
echo "the quick brown fox" | vigenere encrypt --key LEMON

# Solve (default = adaptive auto-mode: fast preset first, escalates to
# the 'best' ensemble only if confidence is below threshold)
vigenere solve --in ciphertext.txt
vigenere solve --in ciphertext.txt --jobs 4              # parallel
vigenere solve --in ciphertext.txt --no-progress --json  # silent + JSON

# Auto-mode threshold (default 0.15). Lower = trust the fast pass more.
vigenere solve --in ciphertext.txt --auto-threshold 0.25

# Any manual flag switches off auto-mode and uses the explicit params
vigenere solve --in ciphertext.txt --decoder classic --keylens 7

# Inspect raw key-length signals
vigenere explain --in ciphertext.txt --max-k 40

# Generate a reproducible disk corpus, then benchmark (multiprocessing)
vigenere gen-corpus --out bench_corpus --n 20 --seed 0
vigenere bench --corpus bench_corpus --decoders legacy,tiny-lm,classic,best \
                --out bench.csv --jobs 8

# Fully random in-memory grid: decoders x beams x strip_tops, N trials each
vigenere compare --trials 30 --jobs 8 \
                 --decoders legacy,tiny-lm,classic,best \
                 --beams 8,16,24 --strip-tops 4,6,8 \
                 --min-keylen 5 --max-keylen 10 \
                 --max-k 30 --seed 0 --out compare.csv

# Learn posterior weights from data (your corpus or synthetic)
vigenere tune --n 150 --max-k 30 --epochs 400
vigenere tune --corpus my_corpus --max-k 50 --epochs 500

# Pareto-search for the cheapest config that meets an accuracy target
vigenere optimize --decoders classic,best --beams 4,8,16 \
                  --strip-tops 2,4,6 --target 0.95 --jobs 8
```

### Live progress UI

By default `vigenere solve` shows a [rich](https://rich.readthedocs.io/)
live panel with:

- current stage + per-stage progress bar with ETA
- running-best key and full-text LM score
- a 4-line snippet of the best decryption so far
- a **key-length posterior distribution panel** with horizontal bars for
  the top 12 candidates
- stats (candidate counts, pool sizes)

Add `--json` (silences progress automatically) or `--no-progress` to suppress it.

### Parallelism

| flag                | scope                                                                | model                                              |
| ------------------- | -------------------------------------------------------------------- | -------------------------------------------------- |
| `solve --jobs N`    | per-keylen candidate gen + per-candidate re-rank + ensemble decoders | Threads (helps numpy parts; ~1× for pure-Python)   |
| `bench --jobs N`    | whole solver invocations across the corpus                           | **Processes** — true CPU parallel                  |
| `compare --jobs N`  | (decoder × beam × strip\_top × trial) grid                           | **Processes** — true CPU parallel                  |
| `optimize --jobs N` | the underlying compare grid                                          | **Processes** — true CPU parallel                  |

Measured (12-trial random `best`-decoder grid, single machine):

```text
jobs=1: 1.33s    jobs=4: 0.46s (2.9×)
jobs=2: 0.67s    jobs=8: 0.34s (3.9×)
```

---

## Adaptive `solve_auto`

The CLI's `vigenere solve` command defaults to **adaptive auto-mode**.
The Python library equivalent is [`solve_auto`](src/vigenere/solver.py):

```python
from vigenere import encrypt, solve_auto

ct = encrypt("the quick brown fox jumps over the lazy dog ...", "LEMON")
res = solve_auto(ct)
# res.extra["auto"] = {"path": "fast", "tried": ["fast"]}
```

Strategy:

1. Run with the **fast preset** — `classic` decoder, `beam=4`,
   `strip_top=4`, `top_keylens=3`. This was the Pareto-optimal cell on
   easy random samples (~150 ms / sample, 100% accuracy on keylen 4–12
   with 500+ chars).
2. If `result.confidence < auto_threshold` (default 0.15), re-run with
   the **hard preset** — `best` ensemble, `beam=24`, `strip_top=10`,
   `top_keylens=8`, `max_k=50`. Returns whichever of the two has higher
   confidence.

Measured on random samples:

| key                  | path      | time    |
| -------------------- | --------- | ------- |
| `LEMON` (5)          | fast      | ~150 ms |
| `FREEDOM` (7)        | fast      | ~160 ms |
| `CRYPTOGRAPHIC` (13) | fast+hard | ~900 ms |

i.e. fast cases stay fast, hard cases automatically get the heavier
treatment. The presets themselves are exposed as
`FAST_PRESET`, `BALANCED_PRESET`, `HARD_PRESET` in
[`solver.py`](src/vigenere/solver.py) if you want to override them.

---

## Optimizations & ML strategy

The solver gets to near-perfect accuracy on easy data through three
complementary mechanisms.

### Learned key-length posterior (§11)

Hand-picking weights for a four-signal softmax is exactly the problem
that one round of gradient ascent solves trivially — and it generalises.
Running `vigenere tune --n 150 --max-k 30 --epochs 400` learned the
weights now shipped as defaults:

| weight           | hand-tuned | learned | ratio |
| ---------------- | ---------- | ------- | ----- |
| `w_ioc`          | 0.70       | 0.014   | ~0×   |
| `w_kasiski`      | 0.90       | 2.60    | 2.9×  |
| `w_periodogram`  | 0.60       | 0.79    | 1.3×  |
| `w_twist`        | 1.00       | 4.46    | 4.5×  |

The numbers tell a story: **once twist++ is in the mix, IoC adds almost
nothing.** Twist measures the *shape* of each strip's frequency
distribution (top-13 vs bottom-13), which is a richer signal than the
scalar IoC and is robust on short strips. Kasiski's binary indicator is
amplified by 2.9× because, when it fires, it's a strong constraint.

The learner reports diagnostics:

```text
n_examples       : 150
log-likelihood   : -0.2753
top-1 accuracy   : 0.967
top-3 accuracy   : 1.000
```

i.e. 96.7% of the time the *true* key length is the single most probable
under the learned posterior — out of 29 candidates ($k \in [2, 30]$).

### Pareto parameter search (§12)

`vigenere optimize` sweeps the `(decoder, beam, strip_top)` grid on
random samples and surfaces three answers:

1. **Best** — max accuracy, ties broken by runtime.
2. **Cheapest at target** — the fastest config meeting `--target` key_acc.
3. **Pareto frontier** — every non-dominated point on the
   accuracy/runtime plane.

On the easy regime the frontier collapses to a single point:

```text
Best cell (max key_acc, min runtime):
  decoder= classic  beam=  4  strip_top=  4  key_acc=1.000  mean_sec=0.184

Pareto frontier (1 configs):
  classic       4     4    1.000     0.184
```

Wider beams and larger `strip_top` are pure waste on easy data. On hard
data the frontier expands and you genuinely have to trade.

### Ensemble decoder (§8)

The `best` decoder runs `legacy`, `tiny-lm`, and `classic` in parallel,
pools their top-K candidate keys, and re-ranks the union under the
classic n-gram LM. Because the pool is a superset of any single
decoder's, it's strictly $\geq$ any of them on accuracy.

### Confidence + match heuristics (§9, §13)

Two practical wins:

- `result.confidence` flags ambiguous solves so a downstream system
  knows when to ask for human review.
- `classify_match` plus `result.match_against(true_key)` means a
  rotation or multiple of the true key is correctly recognised as a
  success — fixed a 90+ point misreported accuracy gap on the `legacy`
  decoder in our own benchmarks.

### Measured impact

On the easy regime (`compare`, 30 trials, keylen 4–12, ≥500 chars):

| decoder   | key_acc | exact_acc | char_acc | mean_sec |
| --------- | ------- | --------- | -------- | -------- |
| `best`    | **1.000** | **1.000** | **1.000** | 0.12     |
| `classic` | 1.000   | 0.733     | 1.000    | 0.08     |
| `tiny-lm` | 0.967   | 0.700     | 0.999    | 0.05     |
| `legacy`  | 0.93*   | 0.000     | 0.93     | 0.04     |

\* `legacy`'s `key_acc` was historically reported as 0% because the
    benchmark required strict equality; `classify_match` now correctly
    awards the rotation-equivalent solves.

On a hard regime (your corpus: keylen 24–42 against 330–470 chars — each
strip has only 8–20 letters, below the threshold for stable per-letter
statistics) accuracy degrades because the *information* simply isn't
there; this is a property of the cipher problem, not the solver.

---

## Testing

```bash
pytest -v                 # 101 tests, ~30 s
pytest --cov=vigenere     # with coverage
```

The suite covers cipher round-trips, IoC/JSD/twist statistics,
periodogram and Kasiski recovery of the true key length, twist++
harmonic discounting, all three scorers (English-vs-noise and
plaintext-vs-ciphertext), beam-search recovery on known keys, wordlist
refinement of single-position typos, the end-to-end solver across
multiple keys/decoders, every CLI subcommand, the progress reporter
(Null + Rich + non-TTY paths), threaded vs sequential determinism, the
weight learner, the Pareto optimizer, the confidence and match
heuristics, and a randomized large-N comparison that asserts
`classic`/`best` ≥ 80% key accuracy on 25 random samples.

---

## Layout

```text
src/vigenere/
  alphabet.py            # encrypt/decrypt, strip splitting, random_key
  stats.py               # counts, histogram, IoC, JSD, KL
  language.py            # LanguageModel + JSON loader (normalized n-gram tables)
  match.py               # exact / rotation / multiple / close key-match classifier
  progress.py            # Null + Rich progress reporters with posterior bars
  keylength/
    periodogram.py       # FFT coincidence periodogram + harmonic NMS
    kasiski.py           # repeated-substring factor voting
    twist.py             # twist + twist++ (Barr & Simoes 2015, LRU cached)
    posterior.py         # learned-weights softmax over all four signals
  scoring/
    base.py              # Scorer protocol
    legacy_jsd.py        # -JSD vs English unigram prior
    tiny_lm.py           # hardcoded unigram + bigram bonuses, no data file
    classic_ngram.py     # interpolated 1..5-gram char LM
  search.py              # per-strip Caesar candidates + beam search
  refine.py              # wordlist-based key correction
  solver.py              # end-to-end pipeline + SolveResult + "best" ensemble
  tune.py                # softmax-MLE weight learner
  optimize.py            # Pareto grid search for (decoder, beam, strip_top)
  bench.py               # disk corpus + in-memory `compare_strategies`
  data/corpus.py         # bundled public-domain English source text
  cli.py                 # argparse subcommands
tests/                   # 101 pytest tests, no network/data deps
language_data.json       # English n-gram tables (used by classic + legacy)
pyproject.toml
```

## License

MIT.
