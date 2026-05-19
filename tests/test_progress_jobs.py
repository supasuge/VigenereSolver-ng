"""Tests for the progress reporter + multithreading paths."""
from __future__ import annotations

import io

from vigenere import solve
from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.progress import (
    NullProgressReporter,
    RichProgressReporter,
    make_reporter,
)


def test_null_reporter_is_silent(capsys):
    r = make_reporter("none")
    assert isinstance(r, NullProgressReporter)
    with r:
        r.stage("x", total=2)
        r.advance(1, best_key="LEMON", best_score=-1.0, snippet="HELLO")
        r.advance(1)
        r.finish_stage()
        r.stat("k", 5)
        r.log("note")
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_rich_reporter_non_tty_writes_summary():
    buf = io.StringIO()
    r = RichProgressReporter(file=buf, force_tty=False)
    with r:
        r.stage("test stage", total=3)
        for i in range(3):
            r.advance(1, best_key=f"K{i}", best_score=-float(i),
                      snippet="snippet")
        r.finish_stage()
        r.stat("foo", "bar")
    output = buf.getvalue()
    assert "test stage" in output
    assert "foo" in output and "bar" in output
    assert "done" in output


def test_solve_with_rich_progress_does_not_crash():
    ct = encrypt(SAMPLE_TEXT[:600], "LEMON")
    buf = io.StringIO()
    reporter = RichProgressReporter(file=buf, force_tty=False)
    res = solve(ct, decoder="best", forced_keylens=[5], progress=reporter, jobs=1)
    assert res.key == "LEMON"
    out = buf.getvalue()
    assert "key-length" in out and "candidate generation" in out


def test_solve_threaded_matches_sequential():
    """jobs>1 must produce identical results to jobs=1."""
    ct = encrypt(SAMPLE_TEXT, "ZEBRAS")
    seq = solve(ct, decoder="classic", forced_keylens=[6], jobs=1)
    par = solve(ct, decoder="classic", forced_keylens=[6], jobs=4)
    assert seq.key == par.key
    # Candidate scores should match (same algorithm, deterministic)
    assert seq.candidates[0][1] == par.candidates[0][1]


def test_solve_ensemble_threaded():
    ct = encrypt(SAMPLE_TEXT, "FREEDOM")
    res = solve(ct, decoder="best", forced_keylens=[7], jobs=4)
    assert res.key == "FREEDOM"
    assert res.scorer_name == "best"
    assert res.elapsed_sec > 0


def test_solve_records_elapsed_sec():
    ct = encrypt(SAMPLE_TEXT[:500], "LEMON")
    res = solve(ct, decoder="classic", forced_keylens=[5])
    assert res.elapsed_sec > 0.0


def test_bench_threaded(tmp_path):
    from vigenere.bench import generate_corpus, run_bench
    corpus = tmp_path / "c"
    generate_corpus(corpus, n_samples=3, min_keylen=5, max_keylen=7,
                    min_chars=400, max_chars=500, seed=0)
    out = tmp_path / "b.csv"
    rc = run_bench(str(corpus), ["classic"], str(out), jobs=3,
                   show_progress=False)
    assert rc == 0
    assert out.exists()
