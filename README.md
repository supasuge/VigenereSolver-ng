# VigenereSolver-ng

This repository provides a production-quality Vigenère solver that fuses classical statistics, beam-search heuristics, and modern language-model scoring.  It can
recover keys, decrypt ciphertexts, visualise key-length evidence, and benchmark different decoder backends — including KenLM character models.

## Highlights

- **Robust key-length inference**: FFT-based coincidence periodogram with non-maximum suppression, Jensen–Shannon strip scoring, and Kasiski factor voting.
- **Multiple decoders**: choose between a tiny heuristic LM, an interpolated 5-gram character model, KenLM perplexity scoring, or a legacy JSD baseline.
- **Dictionary refinement**: optional wordlist sweep to patch near-miss keys.
- **Explainability**: export periodogram plots and IoC summaries to inspect hypotheses.
- **Benchmark harness**: compare decoders on an auto-generated corpus of plaintext/ciphertext/key triplets.
- **Configurable CLI**: every command can be driven from a `config.toml` file for reproducible experiments.

## Installation

The project targets **Python 3.11+**.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

KenLM support requires the `kenlm` and `sentencepiece` packages plus a model directory containing `en.arpa.bin` and `en.sp.model`.  The easiest way to experiment is to build KenLM from source and convert the `test.arpa` provided in the upstream repository:

```bash
# From within the KenLM repo
./build/bin/build_binary -a 255 -q 8 trie data/test.arpa /path/to/model/en.arpa.bin
# Train a simple SentencePiece model on plaintext of your choice
spm_train --input=my_corpus.txt --model_prefix=en --vocab_size=8000
# Copy en.arpa.bin and en.sp.model into e.g. models/en/
```

Point the solver at the directory via `--lm-path models/en`.

## Command line interface

```
python -m vigenere_solver.cli --help
```

### Solve

```bash
python -m vigenere_solver.cli solve --in ciphertext.txt --decoder tiny-lm
```

Useful flags:

- `--decoder`: `tiny-lm`, `classic`, `kenlm`, or `legacy`.
- `--wordlist`: dictionary path for automatic post-correction.
- `--bm-keylens`: comma-separated key lengths to force (skips key-length inference).
- `--explain-dir`: folder receiving a periodogram plot and JSON summary.

### Encrypt

```bash
python -m vigenere_solver.cli encrypt --in plaintext.txt --key SECRET
```

### Explain (analysis only)

```bash
python -m vigenere_solver.cli explain --in ciphertext.txt --outdir reports/
```

### Benchmark

```bash
python -m vigenere_solver.cli bench --corpus bench_corpus --decoders tiny-lm,classic,legacy --out results.csv
```

Use `--lm-path` when including the KenLM decoder.

## Configuration file

A sample `config.toml` is shipped in the repository.  Each CLI sub-command reads its matching section.  CLI arguments always win when both are present.

```toml
[solve]
decoder = "classic"
max_k = 32
bm_beam = 24
wordlist = "english_data/top_english_words_mixed_500000.txt"

[bench]
corpus = "bench_corpus"
decoders = "tiny-lm,classic,kenlm"
out = "bench/results.csv"
```

## Benchmark corpus

`bench_corpus/` contains eight automatically generated samples, each with:

- `plaintext.txt`
- `ciphertext.txt`
- `key.txt`

The manifest at `bench_corpus/manifest.json` enumerates all samples.  To regenerate the corpus, run:

```bash
python scripts/generate_corpus.py
```

## Module overview

- `vigenere_solver/solver.py`: orchestrates periodogram analysis, beam search, language-model rescoring, and dictionary refinement.
- `vigenere_solver/lm_classic.py`: interpolated n-gram character model backed by `language_data.json`.
- `vigenere_solver/kenlm_model.py`: SentencePiece-driven KenLM perplexity wrapper.
- `vigenere_solver/bench.py`: benchmarking harness writing CSV summaries.
- `scripts/generate_corpus.py`: regenerates the benchmark triplets.

## License

This project retains the original MIT license.


