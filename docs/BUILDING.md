# Building, Testing & Releasing

This project uses **hatchling** (PEP 517 backend) driven by
`pyproject.toml`. A legacy `setup.py` shim exists for tools that still
shell out to `python setup.py …`; all real metadata lives in
`pyproject.toml`.

## Dev install

```bash
git clone https://github.com/supasuge/VigenereSolver-ng.git
cd VigenereSolver-ng

# uv (recommended)
uv pip install -e ".[dev]"

# or vanilla pip
pip install -e ".[dev]"

# or install globally as a CLI tool
uv tool install -e .
```

## Tests

```bash
pytest -v                 # ~101 tests, ~30 s
pytest --cov=vigenere     # with coverage
```

The suite covers cipher round-trips, IoC/JSD/twist statistics,
periodogram and Kasiski recovery of the true key length, twist++
harmonic discounting, all three scorers (English-vs-noise and
plaintext-vs-ciphertext), beam-search recovery on known keys, wordlist
refinement, the end-to-end solver across multiple keys/decoders, every
CLI subcommand, the progress reporter (Null + Rich + non-TTY paths),
threaded vs sequential determinism, the weight learner, the Pareto
optimizer, the confidence and match heuristics, and a randomized
large-N comparison that asserts `classic`/`best` ≥ 80% key accuracy on
25 random samples.

## Build distribution artifacts

```bash
# uv
uv build                  # produces dist/*.whl and dist/*.tar.gz

# or the standard PyPA flow
python -m pip install --upgrade build
python -m build
```

The wheel bundles `language_data.json` at
`vigenere/data/language_data.json` via
`[tool.hatch.build.targets.wheel.force-include]`. The runtime loader
([`src/vigenere/language.py`](../src/vigenere/language.py)) prefers the
installed copy and falls back to the repo-root file for source checkouts.

## Publish to PyPI

```bash
python -m pip install --upgrade twine
python -m twine check dist/*
python -m twine upload dist/*           # production
python -m twine upload --repository testpypi dist/*   # test run first
```

Credentials are read from `~/.pypirc` or `TWINE_USERNAME` /
`TWINE_PASSWORD` env vars (use `__token__` + an API token for both).

## Cutting a release

1. Bump `[project].version` in `pyproject.toml` **and**
   `__version__` in `src/vigenere/__init__.py` (keep them in lock-step).
2. Update [`CHANGELOG.md`](../CHANGELOG.md).
3. Commit, tag, push:
   ```bash
   git commit -am "Release vX.Y.Z"
   git tag vX.Y.Z
   git push && git push --tags
   ```
4. `uv build && python -m twine upload dist/*`.

## Layout

```text
src/vigenere/
  alphabet.py            # encrypt/decrypt, strip splitting, random_key
  stats.py               # counts, histogram, IoC, JSD, KL
  language.py            # LanguageModel + JSON loader
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
  data/
    corpus.py            # bundled public-domain English source text
    language_data.json   # English n-gram tables (bundled into wheel)
  cli.py                 # argparse subcommands
src/core/
  cipher.py              # full CTF-style end-to-end API usage example
tests/                   # ~101 pytest tests, no network/data deps
docs/                    # THEORY.md, API.md, CLI.md, BUILDING.md
language_data.json       # dev-mode copy (also bundled into the wheel)
pyproject.toml           # PEP 621 metadata, hatchling build config
setup.py                 # legacy shim — real metadata is in pyproject.toml
```
