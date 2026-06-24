import json
import random

from vigenere.bench import generate_corpus, random_english_letters, compare_strategies
from vigenere.cli import main


def test_random_english_letters_are_reproducible_and_sized():
    rng1 = random.Random(123)
    rng2 = random.Random(123)
    a = random_english_letters(200, rng1)
    b = random_english_letters(200, rng2)
    assert a == b
    assert len(a) == 200
    assert a.isalpha() and a.isupper()


def test_generate_random_english_corpus_manifest(tmp_path):
    out = tmp_path / "corpus"
    n = generate_corpus(out, n_samples=2, min_chars=80, max_chars=90,
                        min_keylen=3, max_keylen=4, seed=7,
                        dataset="random-english")
    assert n == 2
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["dataset"] == "random-english"
    assert all(e["dataset"] == "random-english" for e in manifest["samples"])


def test_compare_random_english_dataset_smoke():
    rows = compare_strategies(n_trials=2, decoders=("classic",), beams=(4,),
                              strip_tops=(3,), min_keylen=3, max_keylen=4,
                              min_chars=120, max_chars=140, max_k=8, seed=9,
                              print_summary=False, show_progress=False,
                              dataset="random-english")
    assert len(rows) == 2
    assert all(r["decoder"] == "classic" for r in rows)


def test_cli_compare_accepts_random_english_dataset(tmp_path):
    out_csv = tmp_path / "compare.csv"
    rc = main(["compare", "--trials", "1", "--decoders", "classic",
               "--beams", "4", "--strip-tops", "3", "--seed", "0",
               "--min-keylen", "3", "--max-keylen", "3",
               "--min-chars", "100", "--max-chars", "100",
               "--max-k", "6", "--dataset", "random-english",
               "--no-progress", "--out", str(out_csv)])
    assert rc == 0
    assert out_csv.exists()
