"""Benchmark harness + synthetic corpus generator.

Two complementary entry points:

* :func:`generate_corpus` / :func:`run_bench` — write a reproducible
  on-disk corpus (plaintext/ciphertext/key triples + manifest.json) and
  evaluate any subset of decoders against it. Results are written as CSV.

* :func:`compare_strategies` — fully in-memory, fully random side-by-side
  evaluation across a Cartesian grid of (decoder, beam, strip_top) and a
  configurable number of trials per cell. Prints a ranking summary and
  returns the per-trial rows.

Plaintext is sampled from :mod:`vigenere.data.corpus` (public-domain
English). Keys are uniformly random over A..Z with a uniformly random
length in the configured range.
"""
from __future__ import annotations

import csv
import json
import random
import statistics
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import product, zip_longest
from pathlib import Path
from typing import Sequence

from . import solve
from .alphabet import clean_letters, decrypt, encrypt, random_key
from .data.corpus import CORPUS_ALL
from .match import classify_match

# Re-export for tests that historically imported SAMPLE_TEXT from here.
SAMPLE_TEXT = CORPUS_ALL


@dataclass
class Sample:
    sid: str
    plaintext: str
    ciphertext: str
    key: str


# ---------------------------------------------------------------------------
# Disk corpus
# ---------------------------------------------------------------------------

def generate_corpus(
    out_dir: str | Path,
    n_samples: int = 20,
    min_keylen: int = 4,
    max_keylen: int = 12,
    min_chars: int = 400,
    max_chars: int = 1200,
    seed: int = 0,
) -> int:
    """Write `n_samples` plaintext/ciphertext/key triples + manifest.json."""
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    source = clean_letters(CORPUS_ALL)
    if len(source) < max_chars:
        raise ValueError(
            f"corpus source too short ({len(source)}) for max_chars={max_chars}"
        )

    entries: list[dict] = []
    for i in range(1, n_samples + 1):
        sid = f"sample_{i:03d}"
        sdir = out / sid
        sdir.mkdir(exist_ok=True)
        nchars = rng.randint(min_chars, max_chars)
        start = rng.randint(0, len(source) - nchars)
        pt = source[start : start + nchars]
        klen = rng.randint(min_keylen, max_keylen)
        key = random_key(klen, rng)
        ct = encrypt(pt, key)
        (sdir / "plaintext.txt").write_text(pt, encoding="utf-8")
        (sdir / "ciphertext.txt").write_text(ct, encoding="utf-8")
        (sdir / "key.txt").write_text(key, encoding="utf-8")
        entries.append({
            "id": sid, "plaintext": f"{sid}/plaintext.txt",
            "ciphertext": f"{sid}/ciphertext.txt",
            "key": key, "keylen": klen, "nchars": nchars,
        })

    (out / "manifest.json").write_text(
        json.dumps({"samples": entries}, indent=2), encoding="utf-8"
    )
    return len(entries)


def load_manifest(corpus_dir: str | Path) -> list[Sample]:
    corpus_dir = Path(corpus_dir)
    data = json.loads((corpus_dir / "manifest.json").read_text(encoding="utf-8"))
    return [
        Sample(
            sid=str(e["id"]),
            plaintext=(corpus_dir / e["plaintext"]).read_text(encoding="utf-8"),
            ciphertext=(corpus_dir / e["ciphertext"]).read_text(encoding="utf-8"),
            key=str(e["key"]).upper(),
        )
        for e in data["samples"]
    ]


# ---------------------------------------------------------------------------
# Accuracy helpers
# ---------------------------------------------------------------------------

def _char_accuracy(pred: str, target: str) -> float:
    if not target:
        return 0.0
    matches = sum(1 for a, b in zip_longest(pred, target) if a == b)
    return matches / max(len(target), 1)


def _key_match(pred_key: str, true_key: str) -> bool:
    """Accept exact, rotation, or multiple (any of which decrypt identically).

    Uses :func:`vigenere.match.classify_match` so that a key like ``MONLE``
    (rotation of ``LEMON``) or ``LEMONLEMON`` (multiple) is recognized as
    a correct recovery.
    """
    return classify_match(pred_key, true_key).is_correct


def _evaluate_task(args) -> dict:
    """Top-level worker function for ProcessPoolExecutor (must be picklable)."""
    sample, decoder, max_k, beam, strip_top = args
    return _evaluate_sample(sample, decoder, max_k, beam, strip_top)


def _evaluate_sample(
    sample: Sample, decoder: str, max_k: int, beam: int, strip_top: int,
    top_keylens: int = 5,
) -> dict:
    t0 = time.perf_counter()
    try:
        res = solve(
            sample.ciphertext,
            decoder=decoder, max_k=max_k, beam=beam, strip_top=strip_top,
            top_keylens=top_keylens,
        )
        dt = time.perf_counter() - t0
        return {
            "id": sample.sid, "decoder": decoder,
            "beam": beam, "strip_top": strip_top,
            "runtime_sec": round(dt, 4),
            "key_true": sample.key, "key_pred": res.key,
            "key_match": _key_match(res.key, sample.key),
            "exact_key": res.key == sample.key,
            "keylen_match": (len(res.key) % len(sample.key) == 0),
            "char_accuracy": round(_char_accuracy(res.plaintext, sample.plaintext), 4),
            "score": res.candidates[0][1] if res.candidates else None,
            "error": "",
        }
    except Exception as exc:
        return {
            "id": sample.sid, "decoder": decoder,
            "beam": beam, "strip_top": strip_top,
            "runtime_sec": round(time.perf_counter() - t0, 4),
            "key_true": sample.key, "key_pred": "<error>",
            "key_match": False, "exact_key": False, "keylen_match": False,
            "char_accuracy": 0.0, "score": None, "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Disk-bench
# ---------------------------------------------------------------------------

def run_bench(
    corpus_dir: str,
    decoders: Sequence[str],
    out_csv: str,
    *,
    limit: int = 0,
    max_k: int = 40,
    beam: int = 16,
    strip_top: int = 6,
    jobs: int = 0,
    show_progress: bool = True,
) -> int:
    samples = load_manifest(corpus_dir)
    if limit > 0:
        samples = samples[:limit]
    tasks = [(s, d) for s in samples for d in decoders]

    rows = _run_tasks(tasks, max_k, beam, strip_top, jobs, show_progress,
                      label="bench")
    _write_csv(rows, out_csv)
    _print_summary(rows, group_by=("decoder",))
    return 0


def _run_tasks(
    tasks: list, max_k: int, beam: int, strip_top: int,
    jobs: int, show_progress: bool, label: str,
    use_processes: bool = True,
) -> list[dict]:
    """Run (sample, decoder, [beam, strip_top]) tasks with live progress.

    Defaults to a ProcessPoolExecutor (true parallel CPU speedup, bypasses
    the GIL). Pass ``use_processes=False`` to use threads instead.
    """
    from contextlib import ExitStack

    progress = None
    task_id = None
    if show_progress:
        try:
            from rich.console import Console
            from rich.progress import (
                BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
                TextColumn, TimeElapsedColumn, TimeRemainingColumn,
            )
            console = Console(stderr=True)
            progress = Progress(
                SpinnerColumn(),
                TextColumn(f"[bold blue]{label}"),
                BarColumn(bar_width=None),
                MofNCompleteColumn(),
                TextColumn("•"),
                TextColumn("solved={task.fields[solved]}/{task.fields[done]}"),
                TextColumn("•"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
            )
        except ImportError:
            progress = None

    rows: list[dict] = []
    solved = 0
    done = 0

    # Normalize each task to (sample, decoder, max_k, beam, strip_top).
    norm_tasks = [
        (t[0], t[1], max_k,
         t[2] if len(t) > 2 else beam,
         t[3] if len(t) > 3 else strip_top)
        for t in tasks
    ]

    with ExitStack() as stack:
        if progress is not None:
            stack.enter_context(progress)
            task_id = progress.add_task("", total=len(norm_tasks),
                                        solved=0, done=0)

        if jobs and jobs > 1:
            Pool = ProcessPoolExecutor if use_processes else ThreadPoolExecutor
            with Pool(max_workers=jobs) as pool:
                futs = {pool.submit(_evaluate_task, t): t for t in norm_tasks}
                for f in as_completed(futs):
                    r = f.result()
                    rows.append(r)
                    done += 1
                    solved += int(bool(r.get("key_match")))
                    if progress is not None:
                        progress.update(task_id, advance=1, solved=solved, done=done)
        else:
            for t in norm_tasks:
                r = _evaluate_task(t)
                rows.append(r)
                done += 1
                solved += int(bool(r.get("key_match")))
                if progress is not None:
                    progress.update(task_id, advance=1, solved=solved, done=done)

    return rows


# ---------------------------------------------------------------------------
# Online side-by-side grid
# ---------------------------------------------------------------------------

def _random_sample(rng: random.Random, sid: str,
                   min_chars: int, max_chars: int,
                   min_keylen: int, max_keylen: int) -> Sample:
    source = clean_letters(CORPUS_ALL)
    nchars = rng.randint(min_chars, max_chars)
    start = rng.randint(0, len(source) - nchars)
    pt = source[start : start + nchars]
    klen = rng.randint(min_keylen, max_keylen)
    key = random_key(klen, rng)
    ct = encrypt(pt, key)
    return Sample(sid=sid, plaintext=pt, ciphertext=ct, key=key)


def compare_strategies(
    *,
    n_trials: int = 30,
    decoders: Sequence[str] = ("legacy", "tiny-lm", "classic", "best"),
    beams: Sequence[int] = (16,),
    strip_tops: Sequence[int] = (6,),
    min_keylen: int = 4,
    max_keylen: int = 12,
    min_chars: int = 400,
    max_chars: int = 1200,
    max_k: int = 40,
    seed: int | None = None,
    jobs: int = 0,
    out_csv: str | None = None,
    print_summary: bool = True,
    show_progress: bool = True,
) -> list[dict]:
    """Run an in-memory grid of (decoder x beam x strip_top) x n_trials.

    Live rich progress shows tasks completed and key-match rate so far.
    """
    rng = random.Random(seed)
    samples = [_random_sample(rng, f"trial_{i:04d}",
                              min_chars, max_chars, min_keylen, max_keylen)
               for i in range(n_trials)]

    grid = list(product(decoders, beams, strip_tops))
    tasks = [(s, d, b, st) for s in samples for d, b, st in grid]

    rows = _run_tasks(tasks, max_k=max_k, beam=16, strip_top=6,
                      jobs=jobs, show_progress=show_progress, label="compare")

    if out_csv:
        _write_csv(rows, out_csv)
    if print_summary:
        _print_summary(rows, group_by=("decoder", "beam", "strip_top"))
    return rows


# ---------------------------------------------------------------------------
# IO + summaries
# ---------------------------------------------------------------------------

_FIELDNAMES = [
    "id", "decoder", "beam", "strip_top", "runtime_sec",
    "key_true", "key_pred", "key_match", "exact_key", "keylen_match",
    "char_accuracy", "score", "error",
]


def _write_csv(rows: list[dict], out_csv: str) -> None:
    out_path = Path(out_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_FIELDNAMES, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _print_summary(rows: list[dict], group_by: Sequence[str]) -> None:
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r[k] for k in group_by), []).append(r)

    cols = list(group_by) + ["n", "key_acc", "exact_acc", "char_acc",
                              "mean_sec", "p95_sec"]
    widths = [max(8, len(c)) for c in cols]
    print()
    print("  ".join(c.rjust(w) for c, w in zip(cols, widths)))
    print("  ".join("-" * w for w in widths))

    summary_rows = []
    for key, items in groups.items():
        n = len(items)
        key_acc = sum(1 for r in items if r["key_match"]) / n
        exact = sum(1 for r in items if r.get("exact_key")) / n
        char_acc = sum(r["char_accuracy"] for r in items) / n
        times = [r["runtime_sec"] for r in items]
        p95 = statistics.quantiles(times, n=20)[-1] if len(times) > 1 else times[0]
        summary_rows.append((key, n, key_acc, exact, char_acc,
                             statistics.mean(times), p95))

    # Sort by key_acc desc, then mean_sec asc
    summary_rows.sort(key=lambda r: (-r[2], r[5]))
    for key, n, key_acc, exact, char_acc, mean_t, p95 in summary_rows:
        vals = [str(x) for x in key] + [
            str(n),
            f"{key_acc:.3f}",
            f"{exact:.3f}",
            f"{char_acc:.3f}",
            f"{mean_t:.3f}",
            f"{p95:.3f}",
        ]
        print("  ".join(v.rjust(w) for v, w in zip(vals, widths)))
