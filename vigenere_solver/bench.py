"""Benchmark harness for comparing decoder strategies."""
from __future__ import annotations

import csv
import json
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
    samples: List[Sample] = []
    for entry in data["samples"]:
        samples.append(
            Sample(
                sid=str(entry["id"]),
                plaintext_path=corpus_dir / entry["plaintext"],
                ciphertext_path=corpus_dir / entry["ciphertext"],
                key=str(entry["key"]).upper(),
            )
        )
    return samples


def _evaluate(
    sample: Sample,
    decoder: str,
    lm_path: str | None,
    max_k: int,
    passes: int,
    beam: int,
    strip_top: int,
) -> dict:
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
        match = res["key"].upper() == sample.key.upper()
        length = max(len(target), 1)
        from itertools import zip_longest

        char_acc = sum(1 for a, b in zip_longest(plaintext, target) if a == b) / length
        return {
            "id": sample.sid,
            "decoder": decoder,
            "runtime_sec": elapsed,
            "key_pred": res["key"],
            "key_true": sample.key,
            "key_match": match,
            "char_accuracy": char_acc,
            "score": res["candidates"][0][1] if res["candidates"] else None,
        }
    except Exception as exc:  # pragma: no cover - best effort logging
        elapsed = time.perf_counter() - start
        return {
            "id": sample.sid,
            "decoder": decoder,
            "runtime_sec": elapsed,
            "key_pred": "<error>",
            "key_true": sample.key,
            "key_match": False,
            "char_accuracy": 0.0,
            "score": None,
            "error": str(exc),
        }


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
) -> None:
    samples = load_manifest(corpus_dir)
    if limit > 0:
        samples = samples[:limit]

    tasks: List[tuple[Sample, str]] = []
    for sample in samples:
        for decoder in decoders:
            if decoder == "kenlm" and not lm_path:
                raise ValueError("kenlm decoder requested but --lm-path is missing")
            tasks.append((sample, decoder))

    results: List[dict] = []
    if jobs and jobs > 1:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            future_map = {
                pool.submit(_evaluate, sample, decoder, lm_path, max_k, passes, beam, strip_top): (sample, decoder)
                for sample, decoder in tasks
            }
            for future in as_completed(future_map):
                results.append(future.result())
    else:
        for sample, decoder in tasks:
            results.append(_evaluate(sample, decoder, lm_path, max_k, passes, beam, strip_top))

    fieldnames = [
        "id",
        "decoder",
        "runtime_sec",
        "key_true",
        "key_pred",
        "key_match",
        "char_accuracy",
        "score",
        "error",
    ]

    out_path = Path(out_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            if "error" not in row:
                row.setdefault("error", "")
            writer.writerow(row)



