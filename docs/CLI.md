# Command-line Reference

After installation `vigenere` is on `PATH`. You can also invoke the
module form: `python -m vigenere ...`.

```text
vigenere {solve,encrypt,explain,bench,compare,tune,optimize,gen-corpus} ...
```

## `solve` — break a ciphertext

```bash
# Default = adaptive auto-mode: fast preset first, escalates to the 'best'
# ensemble only if confidence is below threshold.
vigenere solve --in ciphertext.txt
vigenere solve --in ciphertext.txt --jobs 4              # parallel
vigenere solve --in ciphertext.txt --no-progress --json  # silent + JSON

# Auto-mode threshold (default 0.15). Lower = trust the fast pass more.
vigenere solve --in ciphertext.txt --auto-threshold 0.25

# Any manual flag switches off auto-mode and uses the explicit params.
vigenere solve --in ciphertext.txt --decoder classic --keylens 7
```

## `encrypt` — encrypt stdin

```bash
echo "the quick brown fox" | vigenere encrypt --key LEMON
```

## `explain` — inspect raw key-length signals

```bash
vigenere explain --in ciphertext.txt --max-k 40
```

## `gen-corpus` + `bench` — disk benchmarks (multiprocessing)

```bash
vigenere gen-corpus --out bench_corpus --n 20 --seed 0
# Fully randomized English-like plaintexts (corpus-derived unigram frequencies):
vigenere gen-corpus --out random_english_corpus --n 20 --dataset random-english --seed 0
vigenere bench --corpus bench_corpus \
               --decoders legacy,tiny-lm,classic,best \
               --out bench.csv --jobs 8
```

## `compare` — in-memory parameter grid

```bash
vigenere compare --trials 30 --jobs 8 \
                 --decoders legacy,tiny-lm,classic,best \
                 --beams 8,16,24 --strip-tops 4,6,8 \
                 --min-keylen 5 --max-keylen 10 \
                 --max-k 30 --seed 0 --out compare.csv
# Use --dataset random-english to benchmark i.i.d. English-like plaintexts
# instead of contiguous windows from the bundled corpus.
```

## `tune` — learn posterior weights

```bash
vigenere tune --n 150 --max-k 30 --epochs 400
vigenere tune --corpus my_corpus --max-k 50 --epochs 500
```

## `optimize` — Pareto search for the cheapest config at a target

```bash
vigenere optimize --decoders classic,best --beams 4,8,16 \
                  --strip-tops 2,4,6 --target 0.95 --jobs 8
```

## Live progress UI

By default `vigenere solve` shows a [rich](https://rich.readthedocs.io/)
live panel with:

- current stage + per-stage progress bar with ETA
- running-best key and full-text LM score
- a 4-line snippet of the best decryption so far
- a key-length posterior distribution panel with horizontal bars for the
  top 12 candidates
- candidate counts and pool sizes

Add `--json` (silences progress automatically) or `--no-progress` to
suppress it.

## Parallelism flags

| flag                | scope                                                                | model                                              |
| ------------------- | -------------------------------------------------------------------- | -------------------------------------------------- |
| `solve --jobs N`    | per-keylen candidate gen + per-candidate re-rank + ensemble decoders | Threads (helps numpy parts; ~1× for pure-Python)   |
| `bench --jobs N`    | whole solver invocations across the corpus                           | **Processes** — true CPU parallel                  |
| `compare --jobs N`  | (decoder × beam × strip_top × trial) grid                            | **Processes** — true CPU parallel                  |
| `optimize --jobs N` | the underlying compare grid                                          | **Processes** — true CPU parallel                  |

Measured (12-trial random `best`-decoder grid, single machine):

```text
jobs=1: 1.33s    jobs=4: 0.46s (2.9×)
jobs=2: 0.67s    jobs=8: 0.34s (3.9×)
```
