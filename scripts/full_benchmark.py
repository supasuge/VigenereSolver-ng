#!/usr/bin/env python3
"""Full automated benchmark pipeline.

Three phases:
  1. **Tune** the key-length posterior weights from cryptographically
     random samples (via secrets.SystemRandom).
  2. **Optimize** solver parameters with a Pareto grid search.
  3. **Benchmark** every decoder side-by-side at the chosen parameters,
     using fresh cryptographically random samples and per-keylen splits
     so the results aren't biased toward easy cases.

Why secrets.SystemRandom?
  - random.Random(seed) is a PRNG: same seed -> same samples, useful for
    reproducibility but biased if you reuse a hot seed.
  - secrets.SystemRandom draws from the OS CSPRNG (urandom). Each run
    samples a fresh, uncorrelated subset of the keyspace and plaintext
    windows. This gives the most honest accuracy measurement available
    without an external corpus.

Run:
  python scripts/full_benchmark.py
  python scripts/full_benchmark.py --quick                      # smaller run
  python scripts/full_benchmark.py --keylens 5,8,12,16 --n-per-keylen 30
  python scripts/full_benchmark.py --jobs 8 --out results/

Outputs:
  - <out>/tune.json     : learned posterior weights + diagnostics
  - <out>/optimize.json : Pareto frontier + best/cheapest cells
  - <out>/bench.csv     : per-trial detail rows
  - <out>/summary.json  : per-decoder rolled-up stats
  - <out>/summary.txt   : pretty-printed final table
"""
from __future__ import annotations

import argparse
import csv
import json
import secrets
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

# Make `import vigenere` work when running this script from anywhere.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vigenere import decrypt, encrypt, solve  # noqa: E402
from vigenere.alphabet import clean_letters, random_key  # noqa: E402
from vigenere.data.corpus import CORPUS_ALL  # noqa: E402
from vigenere.match import classify_match  # noqa: E402
from vigenere.optimize import optimize_parameters  # noqa: E402
from vigenere.tune import tune_weights  # noqa: E402

# ---------------------------------------------------------------------------
# Cryptographic random sampling
# ---------------------------------------------------------------------------

SYSRAND = secrets.SystemRandom()
SOURCE = clean_letters(CORPUS_ALL)


@dataclass(frozen=True)
class Sample:
    sid: str
    plaintext: str
    ciphertext: str
    key: str
    keylen: int
    nchars: int


def make_random_sample(
    keylen: int,
    nchars: int,
    sid: str,
) -> Sample:
    """Cryptographically random sample: random window from the bundled
    corpus, uniform random key over A..Z of length `keylen`."""
    if nchars >= len(SOURCE):
        nchars = len(SOURCE) - 1
    start = SYSRAND.randint(0, len(SOURCE) - nchars)
    pt = SOURCE[start: start + nchars]
    key = random_key(keylen, SYSRAND)
    return Sample(sid=sid, plaintext=pt, ciphertext=encrypt(pt, key),
                  key=key, keylen=keylen, nchars=nchars)


def make_sample_grid(
    keylens: Sequence[int],
    nchars: int,
    n_per_keylen: int,
) -> list[Sample]:
    """Produce a balanced grid: `n_per_keylen` samples per requested keylen."""
    out: list[Sample] = []
    for k in keylens:
        for i in range(n_per_keylen):
            out.append(make_random_sample(k, nchars, f"k{k:02d}_{i:03d}"))
    return out


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _evaluate(args) -> dict:
    sample, decoder, max_k, beam, strip_top = args
    t0 = time.perf_counter()
    try:
        res = solve(
            sample.ciphertext, decoder=decoder,
            max_k=max_k, beam=beam, strip_top=strip_top,
        )
        dt = time.perf_counter() - t0
        m = classify_match(res.key, sample.key)
        pt_match = res.plaintext == sample.plaintext
        return {
            "id": sample.sid, "decoder": decoder,
            "keylen": sample.keylen, "nchars": sample.nchars,
            "runtime_sec": round(dt, 4),
            "key_true": sample.key, "key_pred": res.key,
            "match_kind": m.kind,
            "match_distance": m.distance,
            "key_match": m.is_correct,
            "key_close": m.is_close,
            "exact_key": res.key == sample.key,
            "plaintext_match": pt_match,
            "confidence": round(res.confidence, 4),
            "error": "",
        }
    except Exception as exc:
        return {
            "id": sample.sid, "decoder": decoder,
            "keylen": sample.keylen, "nchars": sample.nchars,
            "runtime_sec": round(time.perf_counter() - t0, 4),
            "key_true": sample.key, "key_pred": "<error>",
            "match_kind": "error", "match_distance": -1,
            "key_match": False, "key_close": False, "exact_key": False,
            "plaintext_match": False, "confidence": 0.0,
            "error": repr(exc),
        }


def run_evaluation(
    samples: list[Sample],
    decoders: Sequence[str],
    max_k: int,
    beam: int,
    strip_top: int,
    jobs: int,
) -> list[dict]:
    tasks = [(s, d, max_k, beam, strip_top) for s in samples for d in decoders]
    rows: list[dict] = []
    if jobs > 1:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            futures = {pool.submit(_evaluate, t): t for t in tasks}
            done = 0
            for f in as_completed(futures):
                rows.append(f.result())
                done += 1
                if done % max(1, len(tasks) // 20) == 0 or done == len(tasks):
                    _stderr(f"  evaluated {done:>5}/{len(tasks):>5}")
    else:
        for i, t in enumerate(tasks, 1):
            rows.append(_evaluate(t))
            if i % max(1, len(tasks) // 20) == 0 or i == len(tasks):
                _stderr(f"  evaluated {i:>5}/{len(tasks):>5}")
    return rows


# ---------------------------------------------------------------------------
# Summarisation
# ---------------------------------------------------------------------------

def summarize(rows: list[dict]) -> dict:
    """Per-decoder, per-keylen rollups + overall numbers."""
    by_decoder: dict[str, list[dict]] = {}
    by_dec_kl: dict[tuple[str, int], list[dict]] = {}
    for r in rows:
        by_decoder.setdefault(r["decoder"], []).append(r)
        by_dec_kl.setdefault((r["decoder"], r["keylen"]), []).append(r)

    def _agg(items: list[dict]) -> dict:
        n = len(items)
        if n == 0:
            return {}
        key_acc = sum(1 for r in items if r["key_match"]) / n
        exact_acc = sum(1 for r in items if r["exact_key"]) / n
        close_acc = sum(1 for r in items if r["key_close"]) / n
        pt_acc = sum(1 for r in items if r["plaintext_match"]) / n
        times = [r["runtime_sec"] for r in items]
        conf_correct = [r["confidence"] for r in items if r["key_match"]]
        conf_wrong = [r["confidence"] for r in items if not r["key_match"]]
        return {
            "n": n,
            "key_acc": round(key_acc, 4),
            "exact_acc": round(exact_acc, 4),
            "close_acc": round(close_acc, 4),
            "plaintext_acc": round(pt_acc, 4),
            "mean_sec": round(statistics.mean(times), 4),
            "p50_sec": round(statistics.median(times), 4),
            "p95_sec": round(statistics.quantiles(times, n=20)[-1], 4)
                if len(times) > 1 else round(times[0], 4),
            "mean_conf_correct": round(statistics.mean(conf_correct), 4)
                if conf_correct else None,
            "mean_conf_wrong": round(statistics.mean(conf_wrong), 4)
                if conf_wrong else None,
        }

    return {
        "by_decoder": {d: _agg(items) for d, items in by_decoder.items()},
        "by_decoder_keylen": {
            f"{d}|k={kl}": _agg(items) for (d, kl), items in by_dec_kl.items()
        },
    }


def pretty_table(summary: dict, keylens: Sequence[int],
                 decoders: Sequence[str]) -> str:
    """Pretty side-by-side text table for the terminal."""
    lines: list[str] = []
    lines.append("\n=== Per-decoder summary ===\n")
    head = (f"{'decoder':<10} {'n':>5} {'key_acc':>8} {'exact':>7} "
            f"{'close':>7} {'pt_acc':>8} {'mean_s':>7} {'p95_s':>7} "
            f"{'conf(ok)':>9} {'conf(no)':>9}")
    lines.append(head)
    lines.append("-" * len(head))
    for d in decoders:
        s = summary["by_decoder"].get(d)
        if not s:
            continue
        c_ok = "—" if s["mean_conf_correct"] is None else f"{s['mean_conf_correct']:.3f}"
        c_no = "—" if s["mean_conf_wrong"] is None else f"{s['mean_conf_wrong']:.3f}"
        lines.append(
            f"{d:<10} {s['n']:>5} {s['key_acc']:>8.3f} {s['exact_acc']:>7.3f} "
            f"{s['close_acc']:>7.3f} {s['plaintext_acc']:>8.3f} "
            f"{s['mean_sec']:>7.3f} {s['p95_sec']:>7.3f} "
            f"{c_ok:>9} {c_no:>9}"
        )

    lines.append("\n=== Per-decoder x keylen (key_acc) ===\n")
    head = "keylen  " + "  ".join(f"{d:>10}" for d in decoders)
    lines.append(head)
    lines.append("-" * len(head))
    for k in keylens:
        cells = []
        for d in decoders:
            s = summary["by_decoder_keylen"].get(f"{d}|k={k}")
            cells.append(f"{s['key_acc']:>10.3f}" if s else f"{'—':>10}")
        lines.append(f"  {k:<5}  " + "  ".join(cells))
    return "\n".join(lines)


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="bench_results", help="Output directory")
    p.add_argument("--quick", action="store_true",
                   help="Smaller, faster run (good for smoke-testing the pipeline)")
    p.add_argument("--keylens", default=None,
                   help="CSV of key lengths to test (default: 4,6,8,10,12)")
    p.add_argument("--n-per-keylen", type=int, default=None,
                   help="Samples per key length (default: 25, or 8 with --quick)")
    p.add_argument("--nchars", type=int, default=1000,
                   help="Plaintext window size (chars). Larger = easier.")
    p.add_argument("--decoders", default="legacy,tiny-lm,classic,best",
                   help="CSV of decoders to compare")
    p.add_argument("--tune-n", type=int, default=None,
                   help="Samples for tuning (default: 150, or 40 with --quick)")
    p.add_argument("--tune-epochs", type=int, default=None,
                   help="Tuning epochs (default: 400, or 150 with --quick)")
    p.add_argument("--max-k", type=int, default=30,
                   help="Maximum candidate key length")
    p.add_argument("--jobs", type=int, default=4,
                   help="Parallel worker processes")
    p.add_argument("--skip-tune", action="store_true",
                   help="Use the package-default posterior weights (already learned)")
    p.add_argument("--skip-optimize", action="store_true",
                   help="Use the package-default (beam, strip_top); skip the grid search")
    args = p.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    keylens = (
        [int(x) for x in args.keylens.split(",")] if args.keylens
        else ([4, 6, 8, 10, 12] if not args.quick else [5, 8, 11])
    )
    n_per_kl = args.n_per_keylen or (8 if args.quick else 25)
    tune_n = args.tune_n or (40 if args.quick else 150)
    tune_epochs = args.tune_epochs or (150 if args.quick else 400)
    decoders = [d.strip() for d in args.decoders.split(",") if d.strip()]

    _stderr(f"vigenere full_benchmark.py")
    _stderr(f"  out          = {out}")
    _stderr(f"  keylens      = {keylens}  ({n_per_kl} samples each = {len(keylens)*n_per_kl} total)")
    _stderr(f"  nchars       = {args.nchars}")
    _stderr(f"  decoders     = {decoders}")
    _stderr(f"  max_k        = {args.max_k}")
    _stderr(f"  jobs         = {args.jobs}")

    # ---- Phase 1: tune posterior weights ----
    weights = None
    if not args.skip_tune:
        _stderr(f"\n[1/3] Tuning posterior weights ({tune_n} samples, "
                f"{tune_epochs} epochs)...")
        tune_examples = [
            (s.ciphertext, s.keylen)
            for s in make_sample_grid(keylens, args.nchars, max(1, tune_n // len(keylens)))
        ]
        # Top up to tune_n with extra random samples
        while len(tune_examples) < tune_n:
            k = SYSRAND.choice(keylens)
            s = make_random_sample(k, args.nchars, f"tune_extra_{len(tune_examples)}")
            tune_examples.append((s.ciphertext, s.keylen))

        t_res = tune_weights(
            tune_examples, max_k=args.max_k,
            epochs=tune_epochs, lr=0.1, verbose=False,
        )
        weights = t_res.weights
        tune_payload = {
            "n_examples": t_res.n_examples,
            "epochs": t_res.n_epochs,
            "log_likelihood": t_res.log_likelihood,
            "top1_accuracy": t_res.top1_acc,
            "top3_accuracy": t_res.top3_acc,
            "weights": {
                "w_ioc": t_res.weights[0],
                "w_kasiski": t_res.weights[1],
                "w_periodogram": t_res.weights[2],
                "w_twist": t_res.weights[3],
            },
        }
        (out / "tune.json").write_text(json.dumps(tune_payload, indent=2))
        _stderr(f"  log-likelihood = {t_res.log_likelihood:.4f}")
        _stderr(f"  top-1 / top-3  = {t_res.top1_acc:.3f} / {t_res.top3_acc:.3f}")
        _stderr(f"  weights        = ioc={weights[0]:+.3f}, "
                f"kas={weights[1]:+.3f}, per={weights[2]:+.3f}, twist={weights[3]:+.3f}")
        _stderr(f"  -> {out / 'tune.json'}")

    # ---- Phase 2: Pareto parameter optimization ----
    beam = 16
    strip_top = 6
    if not args.skip_optimize:
        _stderr(f"\n[2/3] Pareto search over (beam, strip_top)...")
        opt = optimize_parameters(
            decoders=("classic",),
            beams=(4, 8, 16),
            strip_tops=(2, 4, 6, 8),
            n_trials=8 if args.quick else 15,
            min_keylen=min(keylens), max_keylen=max(keylens),
            min_chars=args.nchars, max_chars=args.nchars,
            max_k=args.max_k, seed=SYSRAND.randint(0, 2**31),
            jobs=args.jobs, target_accuracy=0.95,
            show_progress=False,
        )
        beam = opt.best["beam"]
        strip_top = opt.best["strip_top"]
        if opt.cheapest_at is not None:
            beam = opt.cheapest_at["beam"]
            strip_top = opt.cheapest_at["strip_top"]
        opt_payload = {
            "best": opt.best, "cheapest_at": opt.cheapest_at,
            "pareto": opt.pareto, "target_accuracy": opt.target_accuracy,
            "chosen": {"beam": beam, "strip_top": strip_top},
        }
        (out / "optimize.json").write_text(json.dumps(opt_payload, indent=2))
        _stderr(f"  best        = beam={opt.best['beam']}, "
                f"strip_top={opt.best['strip_top']}, "
                f"key_acc={opt.best['key_acc']:.3f}")
        if opt.cheapest_at is not None:
            _stderr(f"  cheapest@95 = beam={opt.cheapest_at['beam']}, "
                    f"strip_top={opt.cheapest_at['strip_top']}, "
                    f"mean_sec={opt.cheapest_at['mean_sec']:.3f}")
        _stderr(f"  chosen      = beam={beam}, strip_top={strip_top}")
        _stderr(f"  -> {out / 'optimize.json'}")

    # ---- Phase 3: full side-by-side benchmark ----
    samples = make_sample_grid(keylens, args.nchars, n_per_kl)
    _stderr(f"\n[3/3] Side-by-side benchmark: "
            f"{len(samples)} samples x {len(decoders)} decoders "
            f"= {len(samples)*len(decoders)} trials...")
    rows = run_evaluation(samples, decoders, args.max_k, beam, strip_top, args.jobs)

    fieldnames = [
        "id", "decoder", "keylen", "nchars", "runtime_sec",
        "key_true", "key_pred", "match_kind", "match_distance",
        "key_match", "exact_key", "key_close", "plaintext_match",
        "confidence", "error",
    ]
    with (out / "bench.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    _stderr(f"  -> {out / 'bench.csv'}")

    summary = summarize(rows)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    txt = pretty_table(summary, keylens, decoders)
    (out / "summary.txt").write_text(txt + "\n")
    print(txt)
    _stderr(f"\n  -> {out / 'summary.json'}")
    _stderr(f"  -> {out / 'summary.txt'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
