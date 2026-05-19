# vigenere

[![PyPI](https://img.shields.io/pypi/v/vigenere.svg)](https://pypi.org/project/vigenere/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A production-grade Vigenere cipher solver that combines classical
cryptanalysis (Kasiski, index of coincidence, FFT coincidence
periodogram, twist / twist++) with modern decoding (per-strip beam
search guided by an interpolated character n-gram language model) and a
**learned** softmax posterior over key lengths. Pure-Python core, numpy
for the FFT, optional `rich` for live progress.

On the easy regime (random English plaintext, key length 4–12, 400+
characters) the `best` decoder hits **100 % key recovery on 30 random
samples** and the learned key-length posterior reaches **96.7 % top-1 /
100 % top-3** out of 29 candidates.

- **PyPI**: <https://pypi.org/project/vigenere-solver-ng/>
- **Source**: <https://github.com/supasuge/VigenereSolver-ng>
- **Docs**: [`docs/THEORY.md`](docs/THEORY.md) ·
  [`docs/API.md`](docs/API.md) · [`docs/CLI.md`](docs/CLI.md) ·
  [`docs/BUILDING.md`](docs/BUILDING.md)

## Install

```bash
# from PyPI (recommended)
pip install vigenere-solver-ng
# or
uv pip install vigenere-solver-ng
uv tool install vigenere-solver-ng

# as a globally available CLI via git clone locally
git clone https://github.com/supasuge/VigenereSolver-ng
cd VigenereSolver-ng
uv tool install . -e
```

Requires Python ≥ 3.10. Runtime deps: `numpy`, `rich`.

For a dev install (editable, with tests), see
[`docs/BUILDING.md`](docs/BUILDING.md).

## Quickstart — library

```python
from vigenere import encrypt, decrypt, solve

ct = encrypt("the quick brown fox jumps over the lazy dog ...", "LEMON")

result = solve(ct, decoder="best")
print(result.key)               # "LEMON"
print(result.plaintext)
print(result.keylen_posterior)  # [(5, 0.41), (10, 0.18), ...]
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

For a full end-to-end CTF-style walkthrough (Base64-wrapped ciphertext →
clean → solve → round-trip verification) see
[`src/core/cipher.py`](src/core/cipher.py) — runnable with
`python -m core.cipher`.

## Quickstart — CLI

```bash
# Encrypt
echo "the quick brown fox" | vigenere encrypt --key LEMON

# Solve (adaptive auto-mode: fast preset first, escalates only if confidence
# is below threshold).
vigenere solve --in ciphertext.txt
vigenere solve --in ciphertext.txt --no-progress --json
vigenere solve --in ciphertext.txt --decoder classic --keylens 7

# Inspect raw key-length signals
vigenere explain --in ciphertext.txt --max-k 40
```

Full subcommand reference (including `bench`, `compare`, `tune`,
`optimize`, `gen-corpus`) lives in [`docs/CLI.md`](docs/CLI.md).

## Public API at a glance

```python
from vigenere import (
    encrypt, decrypt,
    clean_letters, random_key,
    solve, solve_auto,
    SolveResult,
)
```

| symbol         | what it does                                                  |
| -------------- | ------------------------------------------------------------- |
| `encrypt`      | Vigenere encryption; preserves non-letters, normalizes case   |
| `decrypt`      | inverse                                                       |
| `clean_letters`| strip non-A–Z, upper-case (use this on raw challenge input)   |
| `random_key`   | uniform random A–Z key (deterministic with a seeded `Random`) |
| `solve`        | full attack pipeline → `SolveResult`                          |
| `solve_auto`   | fast preset, escalates to `best` ensemble only if low confidence |
| `SolveResult`  | dataclass: `key`, `plaintext`, `keylen_posterior`, `candidates`, `confidence`, `match_against`, … |

Detailed signatures and every internal module: [`docs/API.md`](docs/API.md).

## How it works (one-paragraph summary)

For each candidate key length $k$ the solver computes four signals —
average per-strip IoC, Kasiski divisor votes, FFT coincidence
periodogram with harmonic suppression, and twist++ (Barr & Simoes 2015)
— z-scores them, combines them with **learned** weights, and softmaxes
to a posterior $P(m=k \mid \text{ct})$. The top key lengths feed a
per-strip Caesar beam search guided by Jensen–Shannon divergence
against the English unigram prior; the top keys per beam are re-ranked
under an interpolated 1..5-gram character LM. The `best` decoder runs
every scorer, pools their candidates, and re-ranks the union under the
n-gram LM — strictly $\geq$ any single decoder on accuracy. Full
derivations: [`docs/THEORY.md`](docs/THEORY.md).

## Measured impact

`compare` harness, 30 trials, key length 4–12, ≥500 chars:

| decoder   | key_acc | exact_acc | char_acc | mean_sec |
| --------- | ------- | --------- | -------- | -------- |
| `best`    | **1.000** | **1.000** | **1.000** | 0.12     |
| `classic` | 1.000   | 0.733     | 1.000    | 0.08     |
| `tiny-lm` | 0.967   | 0.700     | 0.999    | 0.05     |
| `legacy`  | 0.93    | 0.000     | 0.93     | 0.04     |

On harder regimes (very long keys against short ciphertexts — each
strip has <20 letters) accuracy degrades because the *information*
isn't there; that's a property of the cipher problem, not the solver.

## Build, test, release

See [`docs/BUILDING.md`](docs/BUILDING.md) for editable installs,
running the test suite (`pytest -v` — ~101 tests), building wheels
(`uv build`), and publishing to PyPI (`twine upload dist/*`).

## License

MIT. See [`LICENSE`](LICENSE).
