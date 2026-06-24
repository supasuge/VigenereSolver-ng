# Benchmark Results and Solver Weak Points

This document records solver behavior across multiple benchmark styles. The goal is not only to report headline accuracy, but also to identify where the solver is robust and where it is brittle.

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

Regime: `dataset=window`, key length 4-12, ciphertext length 500-1000, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `best` | 1.000 | 1.000 | 1.000 | 0.330 | 0.525 | Highest accuracy, slowest. |
| `classic` | 1.000 | 1.000 | 1.000 | 0.202 | 0.241 | Same accuracy as `best`, faster. |
| `tiny-lm` | 0.900 | 0.900 | 0.995 | 0.106 | 0.120 | Good plaintext recovery, occasional key misses. |
| `legacy` | 0.000 | 0.000 | 0.936 | 0.109 | 0.129 | Weak key recovery despite readable plaintext. |

**Takeaway:** On real corpus windows, `classic` and `best` are excellent. `best` is more expensive but does not improve this easy regime. `legacy` should be treated as a baseline only.

### 2. Balanced fully-random English-like benchmark

Regime: `dataset=random-english`, key length 4-12, ciphertext length 500-1000, 20 trials per decoder.

| decoder | key_acc | exact_acc | char_acc | mean_sec | p95_sec | readout |
|---|---:|---:|---:|---:|---:|---|
| `tiny-lm` | 0.900 | 0.800 | 0.996 | 0.104 | 0.137 | Best in this synthetic unigram-only setting. |
| `best` | 0.500 | 0.500 | 0.979 | 0.313 | 0.385 | Lower key recovery than expected; still high plaintext accuracy. |
| `classic` | 0.500 | 0.400 | 0.979 | 0.198 | 0.263 | Similar to `best`, faster. |
| `legacy` | 0.050 | 0.050 | 0.939 | 0.102 | 0.128 | Baseline remains weak. |

**Takeaway:** Fully random English-like text exposes a mismatch between the solver's rerankers and i.i.d. unigram text. `tiny-lm` handles this regime better than the `classic`/`best` path in this sample, likely because the heavier reranking expects higher-order English structure that the dataset deliberately removes.

### 3. Short-text / long-key stress test

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

Regime: `dataset=random-english`, key length 8-14, ciphertext length 400-700, 15 trials per cell.

| beam | strip_top | key_acc | exact_acc | char_acc | mean_sec | p95_sec |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 0.733 | 0.667 | 0.985 | 0.144 | 0.182 |
| 4 | 4 | 0.733 | 0.667 | 0.985 | 0.139 | 0.180 |
| 4 | 6 | 0.733 | 0.667 | 0.985 | 0.140 | 0.199 |
| 8 | 2 | 0.667 | 0.600 | 0.978 | 0.160 | 0.225 |
| 8 | 4 | 0.733 | 0.667 | 0.988 | 0.158 | 0.226 |
| 8 | 6 | 0.733 | 0.667 | 0.988 | 0.156 | 0.204 |
| 16 | 2 | 0.667 | 0.600 | 0.978 | 0.154 | 0.201 |
| 16 | 4 | 0.733 | 0.667 | 0.988 | 0.155 | 0.197 |
| 16 | 6 | 0.733 | 0.667 | 0.988 | 0.157 | 0.201 |

**Takeaway:** Larger beams do not automatically improve accuracy in this regime. `strip_top=4` or `6` improves character accuracy over `strip_top=2`, but the gains are small. The cheapest useful settings are likely `beam=4, strip_top=4` for quick checks or `beam=8, strip_top=4` when a small character-accuracy improvement matters.

## Weak points and recommendations

1. **Short ciphertexts with long keys are the dominant weak point.** The solver needs enough letters per key position. Below roughly 20-25 letters per strip, recovery becomes unstable.
2. **`best` is not always best on fully-random unigram text.** It remains a strong default for realistic English, but its higher-order reranking can be mismatched to i.i.d. random-English data.
3. **`legacy` should stay a baseline, not a recommended decoder.** It often preserves a high plaintext character score but rarely recovers the correct key.
4. **Use `tiny-lm` or `classic` for fast benchmark sweeps.** In these runs, `tiny-lm` was especially strong on random-English data, while `classic` was excellent on corpus windows and long enough random-English texts.
5. **Use longer samples for trustworthy long-key evaluation.** The long-key regime becomes reliable once ciphertext length increases to 1200-1800 characters.
6. **Treat small-N key-length breakouts cautiously.** Per-key-length slices from random trials can be small; use them for diagnosis, not final claims.

## Suggested future work

- Add an automated benchmark matrix command that writes Markdown summaries directly.
- Add per-key-length and letters-per-strip rollups to CSV summaries.
- Teach `best` to adapt reranking to dataset style or confidence signals so it can avoid over-weighting higher-order language structure on unigram-only plaintexts.
- Report top key-length posterior rank of the true key length to separate key-length failures from shift-search failures.
