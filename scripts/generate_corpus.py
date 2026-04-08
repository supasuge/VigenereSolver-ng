#!/usr/bin/env python3
"""Generate benchmark corpus with plaintext/ciphertext/key triplets."""
from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vigenere_solver.utils import encrypt_vigenere, random_key

RAW_SOURCES = [ROOT / "raw_text" / "kafka.txt", ROOT / "raw_text" / "letter-raw.txt"]
FALLBACK_SENTENCES = [
    "Knowledge itself is power when guarded by careful hands.",
    "Cryptography rewards the patient mind and the persistent analyst.",
    "Statistical language models guide the search through noisy clues.",
]


def _normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _load_segments(min_chars: int = 140, max_chars: int = 420) -> list[str]:
    segments: list[str] = []
    for src in RAW_SOURCES:
        if not src.exists():
            continue
        clean = _normalize_ws(src.read_text(encoding="utf-8", errors="ignore"))
        cursor = 0
        while cursor < len(clean):
            width = random.randint(min_chars, max_chars)
            chunk = clean[cursor : cursor + width].strip()
            cursor += width
            if len(chunk) >= min_chars:
                segments.append(chunk)
    if not segments:
        segments = FALLBACK_SENTENCES.copy()
    return segments


def build_sample(idx: int, text: str, out_dir: Path, key_length: int) -> dict:
    key = random_key(key_length)
    ciphertext = encrypt_vigenere(text, key)
    sample_dir = out_dir / f"sample_{idx:03d}"
    sample_dir.mkdir(parents=True, exist_ok=True)
    pt_path = sample_dir / "plaintext.txt"
    ct_path = sample_dir / "ciphertext.txt"
    key_path = sample_dir / "key.txt"
    pt_path.write_text(text, encoding="utf-8")
    ct_path.write_text(ciphertext, encoding="utf-8")
    key_path.write_text(key, encoding="utf-8")
    return {
        "id": f"sample_{idx:03d}",
        "plaintext": str(pt_path.relative_to(out_dir)),
        "ciphertext": str(ct_path.relative_to(out_dir)),
        "keyfile": str(key_path.relative_to(out_dir)),
        "key": key,
        "key_length": len(key),
        "plaintext_length": len(text),
    }


def main() -> None:
    random.seed(20260408)
    out_dir = ROOT / "bench_corpus"
    out_dir.mkdir(parents=True, exist_ok=True)

    segments = _load_segments()
    random.shuffle(segments)
    sample_count = min(24, len(segments))

    samples = []
    for idx in range(1, sample_count + 1):
        key_length = random.randint(4, 14)
        samples.append(build_sample(idx, segments[idx - 1], out_dir, key_length))

    manifest = {
        "metadata": {
            "seed": 20260408,
            "sample_count": len(samples),
            "key_length_range": [4, 14],
            "sources": [str(p.relative_to(ROOT)) for p in RAW_SOURCES if p.exists()],
        },
        "samples": samples,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(samples)} samples to {out_dir}")


if __name__ == "__main__":
    main()
