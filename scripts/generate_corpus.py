#!/usr/bin/env python3
"""Generate benchmark corpus with plaintext/ciphertext/key triplets."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vigenere_solver.utils import encrypt_vigenere, random_key

SENTENCES = [
    "Knowledge itself is power when guarded by careful hands.",
    "Cryptography rewards the patient mind and the persistent analyst.",
    "Mathematics whispers its truths in patterns and frequencies.",
    "Historical ciphers often hide in plain sight awaiting discovery.",
    "Automation accelerates classical attacks beyond human endurance.",
    "Elegant code transforms tedious deciphering into crafted insight.",
    "Statistical language models guide the search through noisy clues.",
    "Open data empowers researchers to validate cryptanalytic ideas.",
]


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
    }


def main() -> None:
    random.seed(2024)
    out_dir = ROOT / "bench_corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    samples = []
    for idx, sentence in enumerate(SENTENCES, start=1):
        key_length = random.randint(4, 10)
        samples.append(build_sample(idx, sentence, out_dir, key_length))
    manifest = {"samples": samples}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(samples)} samples to {out_dir}")


if __name__ == "__main__":
    main()


