# Benchmark Results and Solver Weak Points

This document records solver behavior across multiple benchmark styles. The goal is not only to report headline accuracy, but also to identify where the solver is robust and where it is brittle.

All runs below were executed on the current codebase with `PYTHONPATH=src`. Every benchmark in this file uses the requested key-length range of 3-50 (`min_keylen=3`, `max_keylen=50`, `max_k=50`). Timings are wall-clock seconds per solve on this container, so they are most useful for comparing rows within the same run rather than as absolute performance guarantees.
All runs below were executed on the current codebase with `PYTHONPATH=src`. Timings are wall-clock seconds per solve on this container, so they are most useful for comparing rows within the same run rather than as absolute performance guarantees.

## Dataset modes

The benchmark harness now supports two plaintext sampling modes:

- `window`: contiguous windows from the bundled public-domain English corpus.
- `random-english`: fully randomized i.i.d. English-like letter streams drawn from corpus-derived unigram frequencies. This preserves English letter-frequency bias while destroying word, phrase, and higher-order character structure.

`random-english` is intentionally harsher for decoders that rely on n-gram language-model reranking, because the generated text is English-like at the unigram level but not real English.

## Commands used

### Balanced corpus-window baseline

```bash
PYTHONPATH=src python - <<'PY'
from vigenere.bench import compare_strategies
compare_strategies(
    n_trials=20,
    decoders=("legacy", "tiny-lm", "classic", "best"),
    beams=(16,),
    strip_tops=(6,),
    min_keylen=3,
    max_keylen=50,
    min_chars=800,
    max_chars=1600,
    max_k=50,
    seed=111,
    min_keylen=4,
    max_keylen=12,
    min_chars=500,
    max_chars=1000,
    max_k=30,
    seed=101,
    dataset="window",
    print_summary=True,
    show_progress=False,
)
PY
```

### Balanced fully-random English-like benchmark

```bash
PYTHONPATH=src python - <<'PY'
from vigenere.bench import compare_strategies
compare_strategies(
    n_trials=20,
    decoders=("legacy", "tiny-lm", "classic", "best"),
    beams=(16,),
    strip_tops=(6,),
    min_keylen=3,
    max_keylen=50,
    min_chars=800,
    max_chars=1600,
    max_k=50,
    seed=222,
    min_keylen=4,
    max_keylen=12,
    min_chars=500,
    max_chars=1000,
    max_k=30,
    seed=101,
    dataset="random-english",
    print_summary=True,
    show_progress=False,
)
PY
```

### Short-text / long-key stress test

```bash
PYTHONPATH=src python - <<'PY'
from vigenere.bench import compare_strategies
compare_strategies(
    n_trials=20,
    decoders=("legacy", "tiny-lm", "classic", "best"),
    beams=(16,),
    strip_tops=(6,),
    min_keylen=3,
    max_keylen=50,
    min_chars=180,
    max_chars=400,
    max_k=50,
    seed=333,
    min_keylen=12,
    max_keylen=20,
    min_chars=180,
    max_chars=320,
    max_k=30,
    seed=202,
    dataset="random-english",
    print_summary=True,
    show_progress=False,
)
PY
```

### Long-text / long-key recovery test

```bash
PYTHONPATH=src python - <<'PY'
from vigenere.bench import compare_strategies
compare_strategies(
    n_trials=20,
    decoders=("legacy", "tiny-lm", "classic", "best"),
    beams=(16,),
    strip_tops=(6,),
    min_keylen=3,
    max_keylen=50,
    min_chars=2500,
    max_chars=4000,
    max_k=50,
    seed=444,
    min_keylen=12,
    max_keylen=20,
    min_chars=1200,
    max_chars=1800,
    max_k=30,
    seed=303,
    dataset="random-english",
    print_summary=True,
    show_progress=False,
)
PY
```

### Classic decoder parameter sweep

```bash
PYTHONPATH=src python - <<'PY'
from vigenere.bench import compare_strategies
compare_strategies(
    n_trials=15,
    decoders=("classic",),
    beams=(4, 8, 16),
    strip_tops=(2, 4, 6),
    min_keylen=8,
    max_keylen=14,
    min_chars=400,
    max_chars=700,
    max_k=25,
    seed=404,
    dataset="random-english",
    print_summary=True,
    show_progress=False,
)
PY
```

## Summary tables

### 1. Balanced corpus-window baseline

Regime: `dataset=window`, key length 3-50, ciphertext length 800-1600, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `best` | 1.000 | 1.000 | 1.000 | 0.570 | 0.718 | Highest accuracy, slowest. |
| `classic` | 1.000 | 1.000 | 1.000 | 0.366 | 0.451 | Same accuracy as `best`, faster. |
| `tiny-lm` | 1.000 | 1.000 | 1.000 | 0.206 | 0.266 | Same accuracy as `best`, fastest successful decoder. |
| `legacy` | 0.000 | 0.000 | 0.963 | 0.218 | 0.255 | Weak key recovery despite readable plaintext. |

**Takeaway:** On real corpus windows, `classic` and `best` are excellent. `best` is more expensive but does not improve this easy regime. `legacy` should be treated as a baseline only.

### 2. Balanced fully-random English-like benchmark

Regime: `dataset=random-english`, key length 3-50, ciphertext length 800-1600, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `tiny-lm` | 0.750 | 0.750 | 0.992 | 0.202 | 0.276 | Best in this synthetic unigram-only setting. |
| `best` | 0.400 | 0.400 | 0.981 | 0.592 | 0.751 | Lower key recovery than expected; still high plaintext accuracy. |
| `classic` | 0.400 | 0.400 | 0.981 | 0.382 | 0.499 | Similar to `best`, faster. |
| `legacy` | 0.000 | 0.000 | 0.961 | 0.208 | 0.249 | Baseline remains weak. |

**Takeaway:** Fully random English-like text exposes a mismatch between the solver's rerankers and i.i.d. unigram text. `tiny-lm` handles this regime better than the `classic`/`best` path in this sample, likely because the heavier reranking expects higher-order English structure that the dataset deliberately removes.

### 3. Short-text / long-key stress test

Regime: `dataset=random-english`, key length 3-50, ciphertext length 180-400, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `tiny-lm` | 0.350 | 0.300 | 0.595 | 0.072 | 0.096 | Best of a hard regime, but unreliable. |
| `best` | 0.150 | 0.150 | 0.597 | 0.163 | 0.253 | Struggles when strips are short. |
| `classic` | 0.150 | 0.150 | 0.597 | 0.112 | 0.181 | Similar to `best`, faster. |
| `legacy` | 0.000 | 0.000 | 0.558 | 0.082 | 0.108 | Weak. |

**Takeaway:** This is the primary weak point. With 180-400 characters and keys up to length 50, each Caesar strip can have fewer than 10 observations at the high end. That is often not enough evidence for stable shift or key-length recovery, especially on unigram-only synthetic text.

### 4. Long-text / long-key recovery test

Regime: `dataset=random-english`, key length 3-50, ciphertext length 2500-4000, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `best` | 1.000 | 1.000 | 1.000 | 1.388 | 1.637 | Perfect, but slowest. |
| `classic` | 1.000 | 1.000 | 1.000 | 0.831 | 1.064 | Perfect and faster than `best`. |
| `tiny-lm` | 1.000 | 1.000 | 1.000 | 0.379 | 0.468 | Perfect and fastest successful decoder. |
| `legacy` | 0.000 | 0.000 | 0.965 | 0.391 | 0.476 | Still poor key recovery. |
Regime: `dataset=random-english`, key length 12-20, ciphertext length 180-320, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `tiny-lm` | 0.450 | 0.450 | 0.801 | 0.057 | 0.068 | Best of a hard regime, but unreliable. |
| `best` | 0.200 | 0.200 | 0.776 | 0.133 | 0.154 | Struggles when strips are short. |
| `classic` | 0.200 | 0.200 | 0.776 | 0.091 | 0.106 | Similar to `best`, faster. |
| `legacy` | 0.050 | 0.050 | 0.744 | 0.059 | 0.073 | Weak. |

**Takeaway:** This is the primary weak point. With 180-320 characters and 12-20 key letters, each Caesar strip can have only about 9-27 observations. That is often not enough evidence for stable shift or key-length recovery, especially on unigram-only synthetic text.

### 4. Long-text / long-key recovery test

Regime: `dataset=random-english`, key length 12-20, ciphertext length 1200-1800, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `best` | 1.000 | 1.000 | 1.000 | 0.588 | 0.690 | Perfect, but slowest. |
| `classic` | 1.000 | 1.000 | 1.000 | 0.353 | 0.427 | Perfect and faster than `best`. |
| `tiny-lm` | 1.000 | 1.000 | 1.000 | 0.164 | 0.193 | Perfect and fastest successful decoder. |
| `legacy` | 0.100 | 0.100 | 0.957 | 0.160 | 0.189 | Still poor key recovery. |

**Takeaway:** The short-text / long-key failure is data scarcity rather than a fundamental inability to solve long keys. Once each strip receives enough observations, all non-legacy decoders recover perfectly on this sample.

### 5. Classic decoder parameter sweep

Regime: `dataset=random-english`, key length 3-50, ciphertext length 800-1600, 12 trials per cell.

| beam | strip_top | key_acc | exact_acc | char_acc | mean_sec | p95_sec |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 0.500 | 0.500 | 0.976 | 0.332 | 0.460 |
| 4 | 4 | 0.500 | 0.500 | 0.976 | 0.306 | 0.421 |
| 4 | 6 | 0.500 | 0.500 | 0.976 | 0.305 | 0.420 |
| 8 | 2 | 0.417 | 0.417 | 0.973 | 0.344 | 0.470 |
| 8 | 4 | 0.500 | 0.500 | 0.976 | 0.348 | 0.490 |
| 8 | 6 | 0.500 | 0.500 | 0.976 | 0.349 | 0.520 |
| 16 | 2 | 0.417 | 0.417 | 0.973 | 0.338 | 0.480 |
| 16 | 4 | 0.500 | 0.500 | 0.976 | 0.347 | 0.474 |
| 16 | 6 | 0.500 | 0.500 | 0.976 | 0.357 | 0.506 |

**Takeaway:** Larger beams do not automatically improve accuracy in this regime. `strip_top=4` or `6` improves character accuracy over `strip_top=2`, but the gains are small. The cheapest useful settings are likely `beam=4, strip_top=4` for quick checks or `beam=8, strip_top=4` when a small character-accuracy improvement matters.

## Weak points and recommendations

1. **Short ciphertexts with long keys are the dominant weak point.** The solver needs enough letters per key position. Below roughly 20-25 letters per strip, which is common in the upper half of the 3-50 key-length range for short ciphertexts, recovery becomes unstable.
2. **`best` is not always best on fully-random unigram text.** It remains a strong default for realistic English, but its higher-order reranking can be mismatched to i.i.d. random-English data.
3. **`legacy` should stay a baseline, not a recommended decoder.** It often preserves a high plaintext character score but rarely recovers the correct key.
4. **Use `tiny-lm` or `classic` for fast benchmark sweeps.** In these runs, `tiny-lm` was especially strong on random-English data, while `classic` was excellent on corpus windows and long enough random-English texts.
5. **Use longer samples for trustworthy long-key evaluation.** The long-key regime becomes reliable once ciphertext length increases to 2500-4000 characters.
6. **Treat small-N key-length breakouts cautiously.** Per-key-length slices from random trials can be small; use them for diagnosis, not final claims.

## Suggested future work

- Add an automated benchmark matrix command that writes Markdown summaries directly.
- Add per-key-length and letters-per-strip rollups to CSV summaries.
- Teach `best` to adapt reranking to dataset style or confidence signals so it can avoid over-weighting higher-order language structure on unigram-only plaintexts.
- Report top key-length posterior rank of the true key length to separate key-length failures from shift-search failures.
