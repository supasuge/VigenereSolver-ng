# API Reference

Function-by-function reference for every public module in
`src/vigenere/`. Section references (§N) point at the matching
derivation in [`THEORY.md`](THEORY.md).

For a runnable end-to-end usage example see
[`../src/core/cipher.py`](../src/core/cipher.py).

## `vigenere.alphabet` — cipher primitives

| symbol | what it does |
| --- | --- |
| `clean_letters(s)` | strip everything but A–Z, upper-case |
| `encrypt(text, key)` / `decrypt(text, key)` | implement the equations of §1; preserve non-letters |
| `shift_only(letters, s)` | Caesar shift on a letters-only string (decrypt direction) |
| `split_strips(letters, m)` | partition letters-only string into `m` columns $S_j$ |
| `random_key(n, rng)` | uniform random key over A–Z |

## `vigenere.stats` — distributional statistics

| symbol | what it does |
| --- | --- |
| `counts(t)` | length-26 counts vector + total |
| `histogram(t)` | normalized to a probability vector |
| `index_of_coincidence(t)` | $\mathrm{IoC}$ (§2), normalized so uniform ≈ 1 |
| `average_strip_ioc(t, m)` | $\overline{\mathrm{IoC}}(m)$ |
| `kl_divergence(p, q)` / `jensen_shannon(p, q)` | $D_{KL}$ / $\mathrm{JSD}$ |

## `vigenere.language` — n-gram tables

| symbol | what it does |
| --- | --- |
| `LanguageModel` | frozen dataclass with normalized 1..5-gram tables |
| `load_language_model(path)` | load + normalize a JSON file |
| `cached_language_model()` | LRU-cached default |
| `LanguageModel.monogram_vector()` | the prior $\pi$ as a length-26 list |

## `vigenere.keylength` — key-length estimation (§3, §4, §5, §6)

| symbol | what it does |
| --- | --- |
| `coincidence_periodogram(t, kmax)` | $\widetilde{R}[k]$ via FFT |
| `pick_periods(per, kmax, top)` | NMS + harmonic suppression; returns `[(k, score)]` |
| `kasiski_examination(t)` | `[(k, votes)]` sorted desc |
| `twist_score(t, k)` / `twist_table(t, max_k)` | basic twist (§5) |
| `twist_plus_plus_score(t, k)` / `twist_plus_plus_table(t, max_k)` | twist++ (cached) |
| `keylength_posterior(t, max_k, return_table=...)` | combined posterior `[(k, prob)]` from all four signals |

## `vigenere.scoring` — pluggable scorers (§8)

All satisfy the `Scorer` protocol: `name: str`, `.score(text) -> float`
("higher is better").

| class | model |
| --- | --- |
| `LegacyJSDScorer` | $-\mathrm{JSD}(\hat p_{\text{text}}, \pi)$ |
| `TinyLMScorer` | hardcoded unigram log-prob + bigram bonus |
| `ClassicNGramScorer(order, lambdas, alpha)` | interpolated 1..order n-gram char LM |

Factory: `get_scorer(name, **kwargs)`.

## `vigenere.search` — beam search (§7)

| symbol | what it does |
| --- | --- |
| `per_strip_candidates(ct, m, prior, top_m)` | for each strip, return top-`top_m` `(shift, score)` |
| `beam_search(per_strip, beam)` | width-`beam` beam over all strips; returns `[(key, score)]` |

## `vigenere.refine` — wordlist refinement (§10)

| symbol | what it does |
| --- | --- |
| `load_wordlist(path, min_len, max_len, limit)` | normalized, dedup, length-sorted |
| `refine_key(ct, key, words, max_iter, max_mismatch)` | majority-vote per-position |

## `vigenere.match` — key-match classification (§13)

| symbol | what it does |
| --- | --- |
| `hamming(a, b)` | element-wise mismatch count (equal length) |
| `cyclic_distance(pred, true)` | min Hamming over all cyclic rotations of `pred` |
| `classify_match(pred, true, max_diff=2) -> MatchResult` | returns `kind` ∈ {exact, rotation, multiple, close, none}, distance, and a `is_correct` / `is_close` flag |

## `vigenere.tune` — posterior weight learner (§11)

| symbol | what it does |
| --- | --- |
| `synthetic_examples(n, ...)` | generate `(ct, true_keylen)` pairs from the bundled corpus |
| `tune_weights(examples, max_k, epochs, lr, l2) -> TuneResult` | softmax gradient ascent on $\mathcal{L}(w)$; returns weights, log-likelihood, top-1/top-3 accuracy |

## `vigenere.optimize` — Pareto parameter search (§12)

| symbol | what it does |
| --- | --- |
| `optimize_parameters(decoders, beams, strip_tops, n_trials, target_accuracy, ...) -> OptimizeResult` | sweep the grid and pick best/Pareto/cheapest cells |
| `print_optimize_result(result)` | pretty-print the result tables |

## `vigenere.progress` — live progress UI

| class | role |
| --- | --- |
| `NullProgressReporter` | silent (default for tests/library use) |
| `RichProgressReporter` | live panel with progress bar, running-best key+score, posterior bar-chart, stats |
| `make_reporter("rich" \| "none")` | factory |

## `vigenere.solver` — orchestration

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

### Adaptive `solve_auto`

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

Presets are exposed as `FAST_PRESET`, `BALANCED_PRESET`, `HARD_PRESET`
in [`solver.py`](../src/vigenere/solver.py) if you want to override them.

## `vigenere.bench` — corpus generation + harness

| symbol | what it does |
| --- | --- |
| `generate_corpus(out_dir, n, ...)` | write `manifest.json` + per-sample `pt/ct/key` files |
| `load_manifest(corpus_dir)` | re-load a generated corpus |
| `run_bench(corpus_dir, decoders, out_csv, jobs)` | evaluate decoders on a disk corpus (multiprocessing) |
| `compare_strategies(n_trials, decoders, beams, strip_tops, jobs, ...)` | random in-memory `(decoder × beam × strip_top)` grid |

## `vigenere.cli` — `argparse` subcommands

`solve` · `encrypt` · `explain` · `bench` · `compare` · `tune` ·
`optimize` · `gen-corpus`. See [`CLI.md`](CLI.md).
