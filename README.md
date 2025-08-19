# VigenereSolver-ng

VigenereSolver-ng is an advanced toolkit for analyzing and breaking Vigenère ciphers, designed for cryptanalysis research and educational purposes. It combines classical statistical attacks with modern, language-model-based techniques to robustly estimate key length and recover the key, even on challenging ciphertexts.


## Table of Contents
*See full README/documentation on how each section works in the [PDF document here](https://github.com/supasuge/VigenereSolver-ng/blob/main/VigenereSolver-ng~%20How%20it%20works.pdf)*.
- [VigenereSolver-ng](#vigeneresolver-ng)
  - [Table of Contents](#table-of-contents)
  - [Key features and novel techniques](#key-features-and-novel-techniques)
  - [How to use](#how-to-use)
    - [Solve ciphertexts (the usual thing)](#solve-ciphertexts-the-usual-thing)
    - [Generate test data](#generate-test-data)
    - [Encrypt a plaintext file](#encrypt-a-plaintext-file)
    - [Practical tuning knobs](#practical-tuning-knobs)
    - [Troubleshooting quick refs](#troubleshooting-quick-refs)
  - [1) Model of the cipher and the text](#1-model-of-the-cipher-and-the-text)
  - [2) Coincidence, the periodogram, and key-length detection](#2-coincidence-the-periodogram-and-key-length-detection)
    - [2.1 Coincidence probability at lag ell](#21-coincidence-probability-at-lag-ell)
    - [2.2 Windowed periodogram and variance reduction](#22-windowed-periodogram-and-variance-reduction)
    - [2.3 Peakiness and stability objective for wt](#23-peakiness-and-stability-objective-for-wt)
  - [3) Friedman estimate and candidate key lengths](#3-friedman-estimate-and-candidate-key-lengths)
  - [4) Initial key by coset correlation (per m)](#4-initial-key-by-coset-correlation-per-m)
  - [5) Language model and the decryption objective](#5-language-model-and-the-decryption-objective)
    - [5.1 Interpolated Kneser–Ney (KN) probabilities](#51-interpolated-kneserney-kn-probabilities)
    - [5.2 Per-character negative log-likelihood (NLL)](#52-per-character-negative-log-likelihood-nll)
    - [5.3 Legacy fitness and blended score](#53-legacy-fitness-and-blended-score)
  - [6) Coordinate-wise optimization over the key](#6-coordinate-wise-optimization-over-the-key)
    - [6.1 Decomposition of local influence](#61-decomposition-of-local-influence)
    - [6.2 Monotone descent and convergence](#62-monotone-descent-and-convergence)
  - [7) Effectiveness guarantees](#7-effectiveness-guarantees)
    - [7.1 Consistency of key-length detection](#71-consistency-of-key-length-detection)
    - [7.2 Correctness of coset shifts (initial key)](#72-correctness-of-coset-shifts-initial-key)
    - [7.3 Optimality of the LM objective at the true key](#73-optimality-of-the-lm-objective-at-the-true-key)
    - [7.4 Convergence of the key optimizer](#74-convergence-of-the-key-optimizer)
  - [8) Auto-tuned window/step with LM tie-break](#8-auto-tuned-windowstep-with-lm-tie-break)
  - [9) Readability segmentation (post-processing)](#9-readability-segmentation-post-processing)
  - [10) Summary of guarantees](#10-summary-of-guarantees)

---

## Key features and novel techniques

* **Language Model Integration:** Uses high-order n-gram language models (up to 5-gram) for scoring candidate plaintexts and keys, providing much greater accuracy than traditional frequency analysis.
* **Windowed Coincidence Periodogram:** Introduces a windowed version of the coincidence periodogram, which computes coincidence rates over sliding windows to localize and stabilize key-length signals, especially on heterogeneous or short texts.
* **Key-Length Voting and Non-Maximum Suppression:** Implements a voting mechanism across windows and applies non-maximum suppression to robustly select likely key lengths, reducing false positives from harmonics and noise.
* **Jensen-Shannon Divergence Scoring:** Uses JS divergence between observed and English letter distributions to weight key character votes, improving key recovery in the presence of uneven letter frequencies.
* **Kasiski Examination with Factor Analysis:** Augments classical Kasiski examination by aggregating factors of repeated-sequence spacings, then ranks candidate key lengths by their frequency as divisors.
* **Plaintext Generator for Testing:** Includes a generator for English-like plaintexts using real language data, enabling realistic benchmarking of attacks.

These innovations make VigenereSolver-ng more effective and reliable than standard Vigenère solvers, especially on real-world ciphertexts with non-uniform content or formatting.

---

## How to use

> Requires Python 3.11+ and the project's `requirements.txt`.

### Solve ciphertexts (the usual thing)

1. **Install & activate env**

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2. **Put your ciphertext in a file** using triple quotes (you can have multiple blocks):

```txt
"""
PXWZB ... ZQL
"""

"""
ANOTHER CIPHERTEXT BLOCK...
"""
```

3. **Run the solver**

```bash
python SolverSite/solver.py --input ciphertexts/tests.txt --passes 6 --decoder lm
```

* The solver auto-tunes the window/step, tests several key lengths in parallel, and prints the best key with IoC and score.
* Output includes a **readable plaintext** (with optional word segmentation when the original had no spaces).

**Speed tip:** Add `--workers <N>` to control parallelism across candidate key lengths (defaults to CPU count).

**Determinism tip:** For reproducible generation experiments, use `--seed <int>`; solving itself is mostly deterministic aside from small randomization in sweeps.

---

### Generate test data

Create realistic test ciphertexts (plus sidecar keys JSON):

```bash
python SolverSite/solver.py --generate 5 --words 200 --out generated_ciphertexts.txt
# -> ciphertexts in triple-quoted blocks
# -> keys in generated_ciphertexts.txt.keys.json
```

Tweak key-length range with `--min-key` / `--max-key`.

---

### Encrypt a plaintext file

Turn a plaintext into Vigenère ciphertext while **preserving original layout** (spacing, punctuation, case):

```bash
python SolverSite/solver.py --encrypt-file raw_text/kafka.txt --key SECRET --out ciphertexts/kafka_ct.txt
# If --key is omitted, a random key length [3..50] is chosen.
```

---

### Practical tuning knobs

* **Decoder:** `--decoder lm` (default, KN 3–5-gram LM) or `--decoder legacy` (χ²/JSD/ngram blend).
* **Optimization budget:** `--passes 4..8` — more passes = more key refinement (diminishing returns beyond ~6–8).
* **Auto window/step:** on by default; to **fix** them:
  `--no-auto-ws --window 600 --step 150`
* **Annealing (escape plateaus):** `--anneal 0.05` (small positive) occasionally accepts worse local moves to avoid shallow minima.
* **LM blend weight:** `--lm-weight 0.65` mixes LM NLL with legacy fitness for final ranking.
* **Segmentation off:** if you prefer raw, unsegmented output: `--no-seg`.

---

### Troubleshooting quick refs

* **"No ciphertext found"** → Ensure blocks are wrapped in `""" ... """` or pass raw text as a single block.
* **Slow on huge inputs** → Lower `--passes`, use `--workers`, or temporarily `--no-auto-ws`.
* **Weird characters** → Save files as UTF-8. Only A–Z are analyzed; other chars are preserved in-place when formatting.

---

### How it Works

* For information on how this solver works, as well as improvement's made please see the [PDF document here](https://github.com/supasuge/VigenereSolver-ng/blob/main/VigenereSolver-ng~%20How%20it%20works.pdf)
  * I was having trouble getting the equation's to render correctly when transferring from obsidian $\to$ [README.md](https://github.com/supasuge/VigenereSolver-ng/tree/main) so I instead simply exported the documentation to a PDF and uploaded it here :)
 
### Web UI (In-Progress)
- [x] **Light/Dark mode toggle**.
- [x] **How to use**
- [x] **How it works**

<img width="2556" height="1238" alt="image" src="https://github.com/user-attachments/assets/9350fab7-d98c-48ed-86d9-791f7ff72502" />

<img width="1153" height="1149" alt="image" src="https://github.com/user-attachments/assets/e87a1ff4-6e14-4cd0-b537-7e20392bcb90" />

*Meanwhile in the background*

<img width="949" height="264" alt="image" src="https://github.com/user-attachments/assets/c7c6adde-52e8-4f1b-86ac-8b3cb2993ec1" />

<img width="1235" height="453" alt="image" src="https://github.com/user-attachments/assets/197dbf80-9554-43c5-8143-11a4d5bd8ed3" />

<img width="2551" height="1229" alt="image" src="https://github.com/user-attachments/assets/b0c939b6-e657-42f1-acd3-5e662dd8292e" />

<img width="1363" height="1021" alt="image" src="https://github.com/user-attachments/assets/8a3b0062-2966-41bb-aced-702a8a4801d0" />

<img width="874" height="1063" alt="image" src="https://github.com/user-attachments/assets/c7d7d886-39cc-4b1a-89b3-6a65751484af" />

<img width="2548" height="1234" alt="image" src="https://github.com/user-attachments/assets/dc6af2c8-b7b6-4e4f-b776-e01a8d5c88ed" />


Try it out yourself! 

```bash
git clone https://github.com/supasuge/VigenereSolver-ng.git
```

#### TODO
- [ ] Better parsing/normalization where possible
- [ ] Show top $k$ plaintext candidates
- [ ] Better statistics display UI/UX
- [ ] Better documentation on the "how it works page", fully describe how the pipeline works and mathematics involved at each step, turn, twist, and knob.
- [ ] Debug `Dockerfile`/`docker-compose.yml`
