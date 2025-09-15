# VigenereSolver-ng

VigenereSolver-ng is an advanced toolkit for analyzing and breaking Vigenère ciphers, designed for cryptanalysis research and educational purposes. It combines classical statistical attacks with modern, language-model-based techniques to robustly estimate key length and recover the key, even on challenging ciphertexts.

A lot of the more advanced mechanisms were fully coded by ChatGPT, however it worked surprisingly well (Windowed coincidence periodogram, Jensen-Shannon divergence scoring).

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
