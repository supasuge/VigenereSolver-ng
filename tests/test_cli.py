import json
import sys
from io import StringIO

import pytest

from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.cli import main


def test_cli_encrypt(tmp_path, capsys):
    pt = tmp_path / "pt.txt"
    pt.write_text("hello world")
    rc = main(["encrypt", "--in", str(pt), "--key", "LEMON"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out == encrypt("hello world", "LEMON")


def test_cli_solve_json(tmp_path, capsys):
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    f = tmp_path / "ct.txt"
    f.write_text(ct)
    rc = main(["solve", "--in", str(f), "--decoder", "classic",
               "--keylens", "5", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["key"] == "LEMON"
    assert payload["scorer"] == "classic"


def test_cli_explain(tmp_path, capsys):
    ct = encrypt(SAMPLE_TEXT, "ZEBRA")
    f = tmp_path / "ct.txt"
    f.write_text(ct)
    rc = main(["explain", "--in", str(f), "--max-k", "20"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "periodogram" in payload and "keylen_posterior" in payload


def test_cli_compare(tmp_path, capsys):
    out_csv = tmp_path / "compare.csv"
    rc = main(["compare", "--trials", "4", "--decoders", "classic,best",
               "--beams", "16", "--strip-tops", "6", "--seed", "0",
               "--min-keylen", "5", "--max-keylen", "7",
               "--min-chars", "400", "--max-chars", "500",
               "--max-k", "15", "--out", str(out_csv)])
    assert rc == 0
    assert out_csv.exists()
    text = out_csv.read_text()
    assert "decoder" in text and "best" in text and "classic" in text
    # Summary printed to stdout
    cap = capsys.readouterr().out
    assert "key_acc" in cap and "char_acc" in cap


def test_cli_solve_best_decoder(tmp_path, capsys):
    from vigenere.alphabet import encrypt
    from vigenere.bench import SAMPLE_TEXT
    ct = encrypt(SAMPLE_TEXT[:600], "LEMON")
    f = tmp_path / "ct.txt"
    f.write_text(ct)
    rc = main(["solve", "--in", str(f), "--decoder", "best",
               "--keylens", "5", "--json"])
    assert rc == 0
    import json as _j
    payload = _j.loads(capsys.readouterr().out)
    assert payload["key"] == "LEMON"
    assert payload["scorer"] == "best"


def test_cli_gen_corpus(tmp_path, capsys):
    out = tmp_path / "corpus"
    rc = main(["gen-corpus", "--out", str(out), "--n", "3", "--seed", "1",
               "--min-keylen", "5", "--max-keylen", "7",
               "--min-chars", "400", "--max-chars", "500"])
    assert rc == 0
    assert (out / "manifest.json").exists()
    assert (out / "sample_001" / "ciphertext.txt").exists()
