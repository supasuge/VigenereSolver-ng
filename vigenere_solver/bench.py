"""Benchmark harness for comparing decoder strategies."""
from __future__ import annotations

import csv
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

from . import solver


@dataclass
class Sample:
    sid: str
    plaintext_path: Path
    ciphertext_path: Path
    key: str

    def plaintext(self) -> str:
        return self.plaintext_path.read_text(encoding="utf-8")

    def ciphertext(self) -> str:
        return self.ciphertext_path.read_text(encoding="utf-8")


def load_manifest(corpus_dir: str | Path) -> List[Sample]:
    corpus_dir = Path(corpus_dir)
    manifest_path = corpus_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return [
        Sample(
            sid=str(entry["id"]),
            plaintext_path=corpus_dir / entry["plaintext"],
            ciphertext_path=corpus_dir / entry["ciphertext"],
            key=str(entry["key"]).upper(),
        )
        for entry in data["samples"]
    ]


def _evaluate(sample: Sample, decoder: str, lm_path: str | None, max_k: int, passes: int, beam: int, strip_top: int) -> dict:
    start = time.perf_counter()
    try:
        res = solver.solve(
            sample.ciphertext(),
            decoder=decoder,
            lm_path=lm_path,
            max_k=max_k,
            passes=passes,
            topk=5,
            beam=beam,
            strip_top=strip_top,
            forced_keylens=[len(sample.key)],
            show_progress=False,
        )
        elapsed = time.perf_counter() - start
        plaintext = res["plaintext"]
        target = sample.plaintext()
        from itertools import zip_longest

        correct = sum(1 for a, b in zip_longest(plaintext, target) if a == b)
        length = max(len(target), 1)
        return {
            "id": sample.sid,
            "decoder": decoder,
            "runtime_sec": elapsed,
            "key_pred": res["key"],
            "key_true": sample.key,
            "key_match": res["key"].upper() == sample.key.upper(),
            "char_accuracy": correct / length,
            "score": res["candidates"][0][1] if res["candidates"] else None,
            "error": "",
        }
    except Exception as exc:  # pragma: no cover
        return {
            "id": sample.sid,
            "decoder": decoder,
            "runtime_sec": time.perf_counter() - start,
            "key_pred": "<error>",
            "key_true": sample.key,
            "key_match": False,
            "char_accuracy": 0.0,
            "score": None,
            "error": str(exc),
        }


def _summarize(rows: list[dict]) -> dict:
    by_decoder: dict[str, list[dict]] = {}
    for row in rows:
        by_decoder.setdefault(row["decoder"], []).append(row)

    summary: dict[str, dict] = {}
    for dec, dec_rows in by_decoder.items():
        kacc = [1.0 if r["key_match"] else 0.0 for r in dec_rows]
        cacc = [float(r["char_accuracy"]) for r in dec_rows]
        runt = [float(r["runtime_sec"]) for r in dec_rows]
        summary[dec] = {
            "samples": len(dec_rows),
            "key_accuracy": sum(kacc) / max(len(kacc), 1),
            "char_accuracy_mean": statistics.mean(cacc) if cacc else 0.0,
            "char_accuracy_median": statistics.median(cacc) if cacc else 0.0,
            "runtime_sec_mean": statistics.mean(runt) if runt else 0.0,
            "runtime_sec_p95": sorted(runt)[max(0, int(0.95 * len(runt)) - 1)] if runt else 0.0,
            "errors": sum(1 for r in dec_rows if r.get("error")),
        }
    return summary


def _write_summary(report_path: Path, summary: dict[str, dict]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md_path = report_path.with_suffix(".md")
    lines = ["# Benchmark Summary", "", "| Decoder | Samples | Key Accuracy | Mean Char Accuracy | Mean Runtime (s) | Errors |", "|---|---:|---:|---:|---:|---:|"]
    for decoder, stats in sorted(summary.items()):
        lines.append(
            f"| {decoder} | {stats['samples']} | {stats['key_accuracy']:.3f} | {stats['char_accuracy_mean']:.3f} | {stats['runtime_sec_mean']:.4f} | {stats['errors']} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_bench(
    corpus_dir: str,
    decoders: Sequence[str],
    lm_path: str | None,
    jobs: int,
    out_csv: str,
    limit: int = 0,
    max_k: int = 40,
    passes: int = 6,
    beam: int = 16,
    strip_top: int = 6,
    report_out: str | None = None,
) -> dict[str, dict]:
    samples = load_manifest(corpus_dir)
    if limit > 0:
        samples = samples[:limit]

    tasks = [(sample, decoder) for sample in samples for decoder in decoders]
    for _, decoder in tasks:
        if decoder == "kenlm" and not lm_path:
            raise ValueError("kenlm decoder requested but --lm-path is missing")

    results: List[dict] = []
    if jobs and jobs > 1:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futs = [
                pool.submit(_evaluate, sample, decoder, lm_path, max_k, passes, beam, strip_top)
                for sample, decoder in tasks
            ]
            for future in as_completed(futs):
                results.append(future.result())
    else:
        for sample, decoder in tasks:
            results.append(_evaluate(sample, decoder, lm_path, max_k, passes, beam, strip_top))

    out_path = Path(out_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["id", "decoder", "runtime_sec", "key_true", "key_pred", "key_match", "char_accuracy", "score", "error"],
        )
        writer.writeheader()
        writer.writerows(results)

    summary = _summarize(results)
    if report_out:
        _write_summary(Path(report_out), summary)
    return summary
