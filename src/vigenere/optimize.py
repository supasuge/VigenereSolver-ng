"""Parameter optimization for the solver pipeline.

Given a synthetic or disk corpus and a parameter grid, evaluate every cell
and report:

* the best cell by **key accuracy** (ties broken by runtime)
* the Pareto frontier of (accuracy, runtime) — the set of cells you can't
  improve on without giving something up
* the **cheapest cell** that hits a configurable accuracy threshold

Usage:

    from vigenere.optimize import optimize_parameters
    result = optimize_parameters(
        decoders=("classic", "best"),
        beams=(4, 8, 16, 24),
        strip_tops=(2, 4, 6, 8),
        n_trials=20, seed=0,
    )
    print(result.best)         # (decoder, beam, strip_top, key_acc, mean_sec)
    print(result.pareto)       # list of dominant configs
    print(result.cheapest_at)  # min-runtime config meeting target_accuracy
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Sequence

from .bench import compare_strategies

Config = tuple[str, int, int]  # (decoder, beam, strip_top)


@dataclass
class OptimizeResult:
    rows: list[dict]            # per-cell summary: decoder, beam, strip_top, key_acc, mean_sec
    best: dict                  # max key_acc, ties -> min mean_sec
    pareto: list[dict]          # Pareto frontier (key_acc up, mean_sec down)
    cheapest_at: dict | None    # cheapest cell meeting target_accuracy, or None
    target_accuracy: float


def _summarize(rows: list[dict]) -> list[dict]:
    """Roll up per-trial rows into per-cell summaries."""
    groups: dict[Config, list[dict]] = {}
    for r in rows:
        key = (r["decoder"], r["beam"], r["strip_top"])
        groups.setdefault(key, []).append(r)
    out: list[dict] = []
    for (decoder, beam, strip_top), items in groups.items():
        n = len(items)
        key_acc = sum(1 for r in items if r["key_match"]) / n
        exact_acc = sum(1 for r in items if r["exact_key"]) / n
        char_acc = sum(r["char_accuracy"] for r in items) / n
        mean_sec = sum(r["runtime_sec"] for r in items) / n
        out.append({
            "decoder": decoder, "beam": beam, "strip_top": strip_top, "n": n,
            "key_acc": key_acc, "exact_acc": exact_acc, "char_acc": char_acc,
            "mean_sec": mean_sec,
        })
    return out


def _pareto_frontier(rows: list[dict]) -> list[dict]:
    """Keep rows that aren't strictly dominated on (accuracy ↑, time ↓)."""
    front: list[dict] = []
    for r in rows:
        dominated = False
        for s in rows:
            if s is r:
                continue
            # s dominates r iff s is at least as good on both and strictly
            # better on at least one
            if (s["key_acc"] >= r["key_acc"] and s["mean_sec"] <= r["mean_sec"]
                    and (s["key_acc"] > r["key_acc"] or s["mean_sec"] < r["mean_sec"])):
                dominated = True
                break
        if not dominated:
            front.append(r)
    front.sort(key=lambda r: (-r["key_acc"], r["mean_sec"]))
    return front


def optimize_parameters(
    *,
    decoders: Sequence[str] = ("classic", "best"),
    beams: Sequence[int] = (4, 8, 16, 24),
    strip_tops: Sequence[int] = (2, 4, 6, 8),
    n_trials: int = 20,
    min_keylen: int = 4, max_keylen: int = 12,
    min_chars: int = 500, max_chars: int = 1500,
    max_k: int = 30,
    seed: int = 0,
    jobs: int = 0,
    target_accuracy: float = 0.95,
    show_progress: bool = True,
) -> OptimizeResult:
    """Sweep the (decoder × beam × strip_top) grid and pick the winner."""
    rows = compare_strategies(
        n_trials=n_trials, decoders=tuple(decoders),
        beams=tuple(beams), strip_tops=tuple(strip_tops),
        min_keylen=min_keylen, max_keylen=max_keylen,
        min_chars=min_chars, max_chars=max_chars,
        max_k=max_k, seed=seed, jobs=jobs,
        show_progress=show_progress, print_summary=False,
    )
    cells = _summarize(rows)

    # Best by accuracy, ties broken by mean_sec
    best = max(cells, key=lambda c: (c["key_acc"], -c["mean_sec"]))

    pareto = _pareto_frontier(cells)

    # Cheapest cell meeting accuracy target
    qualifying = [c for c in cells if c["key_acc"] >= target_accuracy]
    cheapest = min(qualifying, key=lambda c: c["mean_sec"]) if qualifying else None

    return OptimizeResult(
        rows=cells, best=best, pareto=pareto,
        cheapest_at=cheapest, target_accuracy=target_accuracy,
    )


def print_optimize_result(r: OptimizeResult) -> None:
    """Pretty-print the result to stdout."""
    print(f"\nBest cell (max key_acc, min runtime):")
    print(f"  decoder={r.best['decoder']!s:>8}  beam={r.best['beam']:>3}  "
          f"strip_top={r.best['strip_top']:>3}  "
          f"key_acc={r.best['key_acc']:.3f}  "
          f"mean_sec={r.best['mean_sec']:.3f}")

    if r.cheapest_at is not None:
        c = r.cheapest_at
        print(f"\nCheapest cell meeting key_acc >= {r.target_accuracy:.2f}:")
        print(f"  decoder={c['decoder']!s:>8}  beam={c['beam']:>3}  "
              f"strip_top={c['strip_top']:>3}  "
              f"key_acc={c['key_acc']:.3f}  "
              f"mean_sec={c['mean_sec']:.3f}")
    else:
        print(f"\nNo cell met key_acc >= {r.target_accuracy:.2f}")

    print(f"\nPareto frontier ({len(r.pareto)} configs):")
    print(f"  {'decoder':<10} {'beam':>4} {'strip':>5} {'key_acc':>8} {'mean_sec':>9}")
    for c in r.pareto:
        print(f"  {c['decoder']:<10} {c['beam']:>4} {c['strip_top']:>5} "
              f"{c['key_acc']:>8.3f} {c['mean_sec']:>9.3f}")
