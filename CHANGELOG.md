# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-19

Initial release. Refactored from `supasuge/VigenereSolver-ng` into a clean,
typed, tested package.

### Added

- **Cipher primitives** (`vigenere.alphabet`): `encrypt`, `decrypt`,
  `clean_letters`, `random_key`, `split_strips`, `shift_only`.
- **Statistics** (`vigenere.stats`): Index of Coincidence, Jensen-Shannon
  divergence, per-strip IoC.
- **Key-length estimation** (`vigenere.keylength`):
  - FFT coincidence periodogram with non-maximum suppression + harmonic
    discount.
  - Kasiski examination via factor voting.
  - **Twist + Twist++** (Barr & Simoes 2015), LRU-cached.
  - Combined softmax posterior over all four signals, with weights
    learned from data.
- **Scoring backends** (`vigenere.scoring`): `LegacyJSDScorer`,
  `TinyLMScorer`, `ClassicNGramScorer` (interpolated 1..5-gram char LM).
- **Beam search** (`vigenere.search`): per-strip Caesar candidates +
  width-B beam across columns.
- **Wordlist refinement** (`vigenere.refine`): iterative majority-vote
  key correction.
- **Ensemble decoder** (`"best"`): runs every decoder, pools their
  candidates, re-ranks with the classic LM.
- **Match heuristics** (`vigenere.match`): exact / rotation / multiple /
  close classification with cyclic Hamming distance.
- **Confidence detection** (`SolveResult.confidence`): margin-based,
  aware of plaintext-equivalent candidates.
- **Hyperparameter tuning** (`vigenere.tune`): softmax MLE on posterior
  weights via gradient ascent. Shipped weights learned from 150 random
  samples (top-1 = 96.7%).
- **Pareto parameter optimizer** (`vigenere.optimize`): grid search over
  `(decoder, beam, strip_top)` returning best/cheapest/Pareto cells.
- **Adaptive solver** (`solve_auto`): cheap params first, escalate to
  the `best` ensemble if confidence is below threshold.
- **Live progress UI** (`vigenere.progress`): rich-based panel with
  posterior bar chart, running-best key, plaintext snippet.
- **CLI**: `solve` (with auto-mode default), `encrypt`, `explain`,
  `bench`, `compare`, `tune`, `optimize`, `gen-corpus`.
- **Benchmark harness** (`vigenere.bench`): disk corpus + in-memory
  `compare_strategies`, both with ProcessPoolExecutor parallelism.
- **Standalone benchmark script** (`scripts/full_benchmark.py`):
  tune → optimize → bench, all from `secrets.SystemRandom`.
- **101 pytest tests** covering every public symbol and a randomized
  large-N accuracy comparison.
- **GitHub Actions CI** running tests against Python 3.10, 3.11, 3.12, 3.13.

[0.1.0]: https://github.com/supasuge/vigenere/releases/tag/v0.1.0
