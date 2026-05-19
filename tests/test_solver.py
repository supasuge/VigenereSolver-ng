import json

import pytest

from vigenere import solve
from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT, generate_corpus, load_manifest, run_bench


@pytest.mark.parametrize("key,decoder", [
    ("LEMON", "classic"),
    ("VIGENERE", "classic"),
    ("ZEBRAS", "classic"),
    ("SECRETKEY", "classic"),
    ("LIBERTY", "classic"),
])
def test_solve_recovers_known_keys_classic(key, decoder):
    """Accept exact match or an integer repetition (KEYKEY decrypts identically)."""
    ct = encrypt(SAMPLE_TEXT, key)
    res = solve(ct, decoder=decoder, max_k=20, beam=24, strip_top=8)
    assert len(res.key) % len(key) == 0
    assert res.key == key * (len(res.key) // len(key)), f"got {res.key!r}, expected multiple of {key!r}"
    assert len(res.candidates) > 0
    assert res.scorer_name == decoder
    # Plaintext must round-trip
    from vigenere import decrypt as _dec
    assert _dec(ct, res.key) == _dec(ct, key)


@pytest.mark.parametrize("key,decoder", [
    ("ZEBRAS", "tiny-lm"),
    ("LIBERTY", "legacy"),
])
def test_weaker_decoders_recover_plaintext(key, decoder):
    """Weaker scorers may land on a duplicated key (e.g. KEYKEY) but the
    plaintext must still match exactly."""
    from vigenere import decrypt as _dec
    ct = encrypt(SAMPLE_TEXT, key)
    res = solve(ct, decoder=decoder, max_k=20, beam=24, strip_top=8)
    # Recovered key must be a positive integer repetition of the true key
    assert len(res.key) % len(key) == 0 and res.key == key * (len(res.key) // len(key)), (
        f"{res.key!r} is not a repeat of {key!r}"
    )
    # Decryption with the recovered key must equal decryption with the true key
    assert _dec(ct, res.key) == _dec(ct, key)


def test_solve_with_forced_keylen():
    ct = encrypt(SAMPLE_TEXT, "ABCDEF")
    res = solve(ct, decoder="classic", forced_keylens=[6], beam=20)
    assert res.key == "ABCDEF"


def test_solve_raises_on_empty_input():
    with pytest.raises(RuntimeError):
        solve("", decoder="classic")


def test_solve_pretty_contains_key_and_plaintext():
    ct = encrypt(SAMPLE_TEXT[:600], "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    p = res.pretty()
    assert "LEMON" in p
    assert "plaintext" in p.lower()


def test_corpus_generation_and_bench(tmp_path):
    corpus = tmp_path / "corpus"
    n = generate_corpus(corpus, n_samples=5, min_keylen=5, max_keylen=8,
                       min_chars=500, max_chars=700, seed=42)
    assert n == 5
    samples = load_manifest(corpus)
    assert len(samples) == 5
    out_csv = tmp_path / "bench.csv"
    rc = run_bench(str(corpus), ["tiny-lm", "classic"], str(out_csv), max_k=20, beam=16)
    assert rc == 0
    content = out_csv.read_text()
    assert "decoder" in content and "key_match" in content
    # Most samples should be solved correctly by the classic decoder
    lines = [l for l in content.splitlines()[1:] if l]
    classic_rows = [l for l in lines if ",classic," in l]
    matches = sum(1 for l in classic_rows if ",True," in l)
    assert matches >= 3, f"classic only solved {matches}/{len(classic_rows)}"
