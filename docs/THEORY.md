# Theory & Mathematical Model

This document gives the full equations behind every stage of the pipeline
and the intuition for why each one works. For the public API surface see
[`API.md`](API.md); for the command-line tool see [`CLI.md`](CLI.md).

- [1. The Vigenere cipher](#1-the-vigenere-cipher)
- [2. Index of Coincidence (IoC)](#2-index-of-coincidence-ioc)
- [3. Coincidence periodogram (FFT)](#3-coincidence-periodogram-fft)
- [4. Kasiski examination](#4-kasiski-examination)
- [5. Twist & Twist++](#5-twist--twist)
- [6. Combined key-length posterior](#6-combined-key-length-posterior)
- [7. Per-strip Caesar candidates + beam search](#7-per-strip-caesar-candidates--beam-search)
- [8. Full-text re-ranking](#8-full-text-re-ranking)
- [9. Confidence detection](#9-confidence-detection)
- [10. Dictionary refinement (optional)](#10-dictionary-refinement-optional)
- [11. Hyperparameter tuning (softmax MLE)](#11-hyperparameter-tuning-softmax-mle-on-the-posterior)
- [12. Parameter optimization (Pareto grid search)](#12-parameter-optimization-pareto-grid-search)
- [13. Key-match heuristics](#13-key-match-heuristics)

## 1. The Vigenere cipher

Let the alphabet be $\Sigma = \{A,\dots,Z\}$ with $|\Sigma| = c = 26$,
identified with $\mathbb{Z}_{26}$. Let the plaintext be
$p = p_0 p_1 \dots p_{n-1}$ and the key be $k = k_0 k_1 \dots k_{m-1}$
with $m \ll n$. Then:

$$
c_i \\;=\\; (p_i + k_{i \bmod m}) \bmod 26
\qquad
p_i \\;=\\; (c_i - k_{i \bmod m}) \bmod 26
$$

Implemented in [`alphabet.py`](../src/vigenere/alphabet.py) as `encrypt` /
`decrypt` (non-letter characters pass through; case is normalized to upper).

The cipher is a length-$m$ rotation of $m$ independent Caesar ciphers
("strips") interleaved by position. **Key insight:** if we knew $m$, we
could split the ciphertext into the $m$ strips
$S_j = (c_j, c_{j+m}, c_{j+2m}, \dots)$, each of which is a monoalphabetic
Caesar shift by $k_j$ — easy to attack column-by-column.

## 2. Index of Coincidence (IoC)

Given letter counts $n_1, \dots, n_c$ with $N = \sum n_i$, the IoC is the
probability that two random draws (without replacement) give the same
letter, scaled by $c$:

$$
\mathrm{IoC}(T) \\;=\\; c \cdot \frac{\sum_{i=1}^{c} n_i (n_i - 1)}{N(N-1)}
\\;=\\; \frac{\sum_{i=1}^{c} n_i (n_i - 1)}{N(N-1)/c}
$$

Under a uniform alphabet $\mathrm{IoC} \to 1$; English text piles mass on
E, T, A, O, … so $\mathrm{IoC}_{\text{Eng}} \approx 1.73$.

The Vigenere ciphertext as a whole flattens the histogram so its overall
IoC is close to $1.0$. But the per-strip IoCs $\mathrm{IoC}(S_j)$ are each
measured on a pure Caesar shift of English text, so they preserve the
English IoC. The **strip-IoC test for the key length:**

$$
\overline{\mathrm{IoC}}(m) \\;=\\; \frac{1}{m} \sum_{j=0}^{m-1} \mathrm{IoC}(S_j)
$$

We expect $\overline{\mathrm{IoC}}(m^\star) \approx 1.73$ at the true key
length, and $\approx 1.0$ for wrong lengths. Implemented in
[`stats.py`](../src/vigenere/stats.py).

## 3. Coincidence periodogram (FFT)

For each letter $a \in \Sigma$, build the indicator signal
$x_a[t] = \mathbb{1}[\text{ciphertext}_t = a]$. The **coincidence count
at lag $k$** is

$$
R[k] \\;=\\; \sum_{a \in \Sigma} \sum_{t=0}^{n-k-1} x_a[t]\, x_a[t+k]
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
to the top of the ranking. Implemented in
[`keylength/periodogram.py`](../src/vigenere/keylength/periodogram.py).

## 4. Kasiski examination

If a substring $s$ of length $\geq 3$ appears at positions $p_1 < p_2$,
the most common explanation is that the same plaintext appeared twice
against the same key residue class — so $m^\star \mid (p_2 - p_1)$. For
each repeated substring, take every distance $d$ and emit every divisor
$k \in [2, k_{\max}]$ of $d$ as a vote:

$$
V(k) \\;=\\; \big|\{ (d, k) : k \mid d, \\; k \in [2, k_{\max}] \}\big|
$$

Implemented in [`keylength/kasiski.py`](../src/vigenere/keylength/kasiski.py).

## 5. Twist & Twist++

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
T(m) \\;=\\; \sum_{i=0}^{12} \bar P_i \\;-\\; \sum_{i=13}^{25} \bar P_i
\\;=\\; 1 - 2 \sum_{i \geq 13} \bar P_i
$$

with $T \in [0, 1]$. Uniform $\Rightarrow 0$, English $\approx 0.70$.

**Twist++** subtracts the running mean of the smaller-$k$ twists:

$$
T^{++}(m) \\;=\\; T(m) \\;-\\; \frac{1}{m-1} \sum_{j=1}^{m-1} T(j)
$$

This penalises harmonics of the true period: $2m^\star$ also produces
"shifted-English" strips and would tie with $m^\star$ under bare twist;
the running-mean correction breaks the tie in favour of the fundamental.

Implemented in [`keylength/twist.py`](../src/vigenere/keylength/twist.py).
LRU-cached so repeated calls on the same text are $O(1)$.

## 6. Combined key-length posterior

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
z_i(k) \\;=\\; \frac{s_i(k) - \mu_i}{\sigma_i + \varepsilon},
\quad
\ell(k) \\;=\\; w_1 z_1(k) + w_2 s_2(k) + w_3 z_3(k) + w_4 z_4(k)
$$

$$
P(m=k \mid \text{ciphertext}) \\;=\\; \mathrm{softmax}_k(\ell(k))
$$

**The weights $(w_1,\dots,w_4)$ are learned from data** (see §11) and
default to $(0.014, 2.60, 0.79, 4.46)$. Implemented in
[`keylength/posterior.py`](../src/vigenere/keylength/posterior.py).

## 7. Per-strip Caesar candidates + beam search

Fix a candidate $m$. For each strip $j$ and each shift
$s \in \{0, \dots, 25\}$, decrypt the strip and compare its histogram
$\hat q$ to the English unigram prior $\pi$ via **Jensen–Shannon
divergence**:

$$
\mathrm{JSD}(P \| Q) \\;=\\; \tfrac{1}{2} D_{KL}(P \| M) + \tfrac{1}{2} D_{KL}(Q \| M),
\quad M = \tfrac{1}{2}(P + Q)
$$

Use $-\mathrm{JSD}$ so higher = more English-like. Keep the top
$M_{\text{strip}}$ shifts per column. Then **beam search** across
columns: at column $j$, extend every surviving partial key by every
kept shift, score by the sum of per-strip scores, keep the top $B$
beams. Implemented in [`search.py`](../src/vigenere/search.py).

## 8. Full-text re-ranking

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

Implemented in [`scoring/`](../src/vigenere/scoring/) and combined in
[`solver.py`](../src/vigenere/solver.py).

## 9. Confidence detection

Given the ranked candidates $\{(k_i, \sigma_i)\}$, treat all keys that
decrypt to the **same plaintext** as one answer (this captures
rotations and integer repetitions of the true key, which produce
identical decryptions). The confidence is the margin between the top
score and the best runner-up with a *different* plaintext, normalized by
the candidate spread:

$$
\mathrm{conf} \\;=\\; \mathrm{clip}_{[0,1]}\!\left(\frac{\sigma_{\text{top}} - \sigma_{\text{runner}^\star}}{\sigma_{\text{top}} - \sigma_{\text{bottom}}}\right)
$$

A unique winner with a clear lead gives values near 1.0; genuinely
ambiguous candidates give values near 0.

## 10. Dictionary refinement (optional)

Given a candidate $k$ and a wordlist, slide every word $w$ against the
ciphertext. At offset $i$, position $j$ in the word implies key residue
$k^{(\text{req})}_{(i+j) \bmod m} = (c_{i+j} - w_j) \bmod 26$. If the
match has at most `max_mismatch` disagreements with the current $k$,
register one vote per position. Take the majority vote at each position
and iterate until convergence. Implemented in
[`refine.py`](../src/vigenere/refine.py).

## 11. Hyperparameter tuning (softmax MLE on the posterior)

The four posterior weights $(w_1, w_2, w_3, w_4)$ were originally
hand-tuned. The [`vigenere.tune`](../src/vigenere/tune.py) module learns
them from labelled data $\{(\text{ct}_i, m_i^\star)\}_{i=1}^N$ by
maximizing the log-likelihood of the true key length under the softmax:

$$
\mathcal{L}(w) \\;=\\; \frac{1}{N} \sum_{i=1}^{N}
  \log \frac{\exp(w \cdot s_i(m_i^\star))}{\sum_{k} \exp(w \cdot s_i(k))}
\\;-\\; \lambda \|w\|^2
$$

The gradient has a closed form (softmax classifier):

$$
\nabla_w \mathcal{L} \\;=\\; \frac{1}{N} \sum_i \big( s_i(m_i^\star) - \mathbb{E}_{P_i}[s_i(k)] \big) - 2\lambda w
$$

Plain full-batch gradient ascent, no scipy required. On a 150-sample
synthetic corpus the learner converges in ~400 epochs to
$(0.014, 2.60, 0.79, 4.46)$ — **twist++ dominates with 4.5× the default
weight; IoC contributes almost nothing once twist is present**. Top-1
accuracy improves from the hand-tuned baseline to **0.967 / 1.000
top-3** on held-out random samples.

## 12. Parameter optimization (Pareto grid search)

The [`vigenere.optimize`](../src/vigenere/optimize.py) module sweeps the
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

## 13. Key-match heuristics

[`vigenere.match`](../src/vigenere/match.py) classifies a recovered key
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
