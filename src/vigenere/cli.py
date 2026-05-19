"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import encrypt, solve, solve_auto
from .keylength import coincidence_periodogram, keylength_posterior
from .progress import make_reporter
from .solver import AUTO_CONFIDENCE_THRESHOLD


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _parse_csv_ints(s: str | None) -> list[int] | None:
    if not s:
        return None
    return [int(x) for x in s.split(",") if x.strip()]


def _cmd_solve(args: argparse.Namespace) -> int:
    text = _read(args.infile)
    progress_kind = "none" if (args.no_progress or args.json) else args.progress
    reporter = make_reporter(progress_kind)

    # If the user explicitly set any of the manual parameters, fall back to
    # the explicit `solve()` path. Otherwise use the adaptive `solve_auto`
    # which picks fast/hard presets based on confidence.
    manual = (args.decoder is not None or args.beam is not None
              or args.strip_top is not None or args.top_keylens is not None
              or args.keylens is not None or args.max_k is not None
              or args.no_auto)

    if manual:
        result = solve(
            text,
            decoder=args.decoder or "best",
            max_k=args.max_k or 40,
            topk=args.topk,
            top_keylens=args.top_keylens or 5,
            beam=args.beam or 16,
            strip_top=args.strip_top or 6,
            forced_keylens=_parse_csv_ints(args.keylens),
            wordlist=args.wordlist,
            seed=args.seed,
            jobs=args.jobs,
            progress=reporter,
        )
    else:
        result = solve_auto(
            text,
            confidence_threshold=args.auto_threshold,
            wordlist=args.wordlist,
            jobs=args.jobs,
            progress=reporter,
            seed=args.seed,
        )

    if args.json:
        payload = {
            "key": result.key,
            "scorer": result.scorer_name,
            "refined": result.refined,
            "confidence": result.confidence,
            "elapsed_sec": result.elapsed_sec,
            "keylen_posterior": result.keylen_posterior,
            "candidates": result.candidates,
            "plaintext": result.plaintext,
            "auto": result.extra.get("auto"),
        }
        print(json.dumps(payload, indent=2))
    else:
        print(result.pretty())
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    text = _read(args.infile)
    sys.stdout.write(encrypt(text, args.key))
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    text = _read(args.infile)
    per = coincidence_periodogram(text, kmax=args.max_k)
    post = keylength_posterior(text, max_k=args.max_k)
    out = {
        "periodogram": [float(x) for x in per.tolist()],
        "keylen_posterior": post,
    }
    print(json.dumps(out, indent=2))
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_bench

    return run_bench(
        corpus_dir=args.corpus,
        decoders=[d.strip() for d in args.decoders.split(",") if d.strip()],
        out_csv=args.out,
        limit=args.limit,
        max_k=args.max_k,
        beam=args.beam,
        strip_top=args.strip_top,
        jobs=args.jobs,
        show_progress=not args.no_progress,
    )


def _cmd_compare(args: argparse.Namespace) -> int:
    from .bench import compare_strategies

    compare_strategies(
        n_trials=args.trials,
        decoders=tuple(d.strip() for d in args.decoders.split(",") if d.strip()),
        beams=tuple(int(x) for x in args.beams.split(",") if x.strip()),
        strip_tops=tuple(int(x) for x in args.strip_tops.split(",") if x.strip()),
        min_keylen=args.min_keylen, max_keylen=args.max_keylen,
        min_chars=args.min_chars, max_chars=args.max_chars,
        max_k=args.max_k, seed=args.seed, jobs=args.jobs,
        out_csv=args.out,
        show_progress=not args.no_progress,
    )
    return 0


def _cmd_tune(args: argparse.Namespace) -> int:
    from .bench import load_manifest
    from .tune import synthetic_examples, tune_weights

    if args.corpus:
        samples = load_manifest(args.corpus)
        examples = [(s.ciphertext, len(s.key)) for s in samples]
    else:
        examples = synthetic_examples(
            n=args.n, min_keylen=args.min_keylen, max_keylen=args.max_keylen,
            min_chars=args.min_chars, max_chars=args.max_chars, seed=args.seed,
        )
    res = tune_weights(
        examples, max_k=args.max_k, epochs=args.epochs, lr=args.lr,
        verbose=not args.quiet,
    )
    print()
    print(f"  n_examples       : {res.n_examples}")
    print(f"  epochs           : {res.n_epochs}")
    print(f"  log-likelihood   : {res.log_likelihood:.4f}")
    print(f"  top-1 accuracy   : {res.top1_acc:.3f}")
    print(f"  top-3 accuracy   : {res.top3_acc:.3f}")
    print(f"  learned weights  :")
    for name, w in zip(("w_ioc", "w_kasiski", "w_periodogram", "w_twist"),
                       res.weights):
        print(f"    {name:<16} = {w:+.4f}")
    print()
    print("Apply via:")
    print("  from vigenere.keylength.posterior import keylength_posterior")
    print("  keylength_posterior(ct, max_k=K,")
    print(f"      w_ioc={res.weights[0]:+.4f}, w_kasiski={res.weights[1]:+.4f},")
    print(f"      w_periodogram={res.weights[2]:+.4f}, w_twist={res.weights[3]:+.4f})")
    return 0


def _cmd_optimize(args: argparse.Namespace) -> int:
    from .optimize import optimize_parameters, print_optimize_result

    res = optimize_parameters(
        decoders=tuple(d.strip() for d in args.decoders.split(",") if d.strip()),
        beams=tuple(int(x) for x in args.beams.split(",") if x.strip()),
        strip_tops=tuple(int(x) for x in args.strip_tops.split(",") if x.strip()),
        n_trials=args.trials,
        min_keylen=args.min_keylen, max_keylen=args.max_keylen,
        min_chars=args.min_chars, max_chars=args.max_chars,
        max_k=args.max_k, seed=args.seed, jobs=args.jobs,
        target_accuracy=args.target,
        show_progress=not args.no_progress,
    )
    print_optimize_result(res)
    return 0


def _cmd_gen_corpus(args: argparse.Namespace) -> int:
    from .bench import generate_corpus

    n = generate_corpus(
        out_dir=args.out,
        n_samples=args.n,
        min_keylen=args.min_keylen,
        max_keylen=args.max_keylen,
        min_chars=args.min_chars,
        max_chars=args.max_chars,
        seed=args.seed,
    )
    print(f"wrote {n} samples to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("vigenere", description="Refactored Vigenere solver")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser(
        "solve",
        help="Decrypt Vigenere ciphertext (defaults to auto-mode)",
        description=(
            "Decrypt Vigenere ciphertext. With no parameters, runs the "
            "adaptive solver: cheap pass first, escalates to the heavy "
            "'best' ensemble if confidence is below the threshold. "
            "Any manual parameter switches off auto-mode."
        ),
    )
    ps.add_argument("--in", dest="infile", default="-")
    # All parameter defaults are None so we can detect when the user
    # explicitly overrode them (in which case we drop out of auto-mode).
    ps.add_argument("--decoder", choices=["legacy", "tiny-lm", "classic", "best"],
                    default=None,
                    help="(manual) Re-rank decoder. Setting this disables --auto.")
    ps.add_argument("--max-k", type=int, default=None,
                    help="(manual) Maximum candidate key length.")
    ps.add_argument("--topk", type=int, default=5,
                    help="How many top candidate keys to report.")
    ps.add_argument("--top-keylens", type=int, default=None,
                    help="(manual) How many key-length candidates to search.")
    ps.add_argument("--beam", type=int, default=None,
                    help="(manual) Beam width.")
    ps.add_argument("--strip-top", type=int, default=None,
                    help="(manual) Shifts kept per strip.")
    ps.add_argument("--keylens", default=None,
                    help="(manual) CSV of forced key lengths (skips estimation).")
    ps.add_argument("--wordlist", default=None,
                    help="Optional wordlist for majority-vote refinement.")
    ps.add_argument("--seed", type=int, default=None)
    ps.add_argument("--jobs", type=int, default=1,
                    help="Parallel workers for per-keylen + per-candidate work")
    ps.add_argument("--auto-threshold", type=float, default=AUTO_CONFIDENCE_THRESHOLD,
                    help="Confidence below which auto-mode escalates to 'best' "
                         "(default: %(default)s).")
    ps.add_argument("--no-auto", action="store_true",
                    help="Force the explicit-params path (uses defaults if no "
                         "params given).")
    ps.add_argument("--progress", choices=["rich", "none"], default="rich",
                    help="Live progress UI (rich) or silent (none). Auto-disabled with --json.")
    ps.add_argument("--no-progress", action="store_true",
                    help="Shortcut for --progress none")
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=_cmd_solve)

    pe = sub.add_parser("encrypt", help="Encrypt plaintext with key")
    pe.add_argument("--in", dest="infile", default="-")
    pe.add_argument("--key", required=True)
    pe.set_defaults(func=_cmd_encrypt)

    px = sub.add_parser("explain", help="Dump periodogram + key-length posterior as JSON")
    px.add_argument("--in", dest="infile", default="-")
    px.add_argument("--max-k", type=int, default=40)
    px.set_defaults(func=_cmd_explain)

    pb = sub.add_parser("bench", help="Run benchmark against a corpus directory")
    pb.add_argument("--corpus", required=True)
    pb.add_argument("--decoders", default="legacy,tiny-lm,classic")
    pb.add_argument("--out", default="bench_results.csv")
    pb.add_argument("--limit", type=int, default=0)
    pb.add_argument("--max-k", type=int, default=40)
    pb.add_argument("--beam", type=int, default=16)
    pb.add_argument("--strip-top", type=int, default=6)
    pb.add_argument("--jobs", type=int, default=0)
    pb.add_argument("--no-progress", action="store_true")
    pb.set_defaults(func=_cmd_bench)

    pc = sub.add_parser("compare", help="Random side-by-side grid of decoders x params")
    pc.add_argument("--trials", type=int, default=30)
    pc.add_argument("--decoders", default="legacy,tiny-lm,classic,best")
    pc.add_argument("--beams", default="16")
    pc.add_argument("--strip-tops", default="6")
    pc.add_argument("--min-keylen", type=int, default=4)
    pc.add_argument("--max-keylen", type=int, default=12)
    pc.add_argument("--min-chars", type=int, default=400)
    pc.add_argument("--max-chars", type=int, default=1200)
    pc.add_argument("--max-k", type=int, default=40)
    pc.add_argument("--seed", type=int, default=None)
    pc.add_argument("--jobs", type=int, default=0)
    pc.add_argument("--out", default=None, help="Optional CSV path for per-trial rows")
    pc.add_argument("--no-progress", action="store_true")
    pc.set_defaults(func=_cmd_compare)

    pt = sub.add_parser("tune", help="Learn key-length posterior weights from labelled data")
    pt.add_argument("--corpus", default=None,
                    help="Disk corpus dir (else synthetic samples are used)")
    pt.add_argument("--n", type=int, default=120, help="Synthetic samples if no --corpus")
    pt.add_argument("--min-keylen", type=int, default=4)
    pt.add_argument("--max-keylen", type=int, default=12)
    pt.add_argument("--min-chars", type=int, default=500)
    pt.add_argument("--max-chars", type=int, default=1500)
    pt.add_argument("--max-k", type=int, default=30)
    pt.add_argument("--epochs", type=int, default=300)
    pt.add_argument("--lr", type=float, default=0.1)
    pt.add_argument("--seed", type=int, default=0)
    pt.add_argument("--quiet", action="store_true")
    pt.set_defaults(func=_cmd_tune)

    po = sub.add_parser("optimize", help="Pareto grid-search over solver parameters")
    po.add_argument("--decoders", default="classic,best")
    po.add_argument("--beams", default="4,8,16,24")
    po.add_argument("--strip-tops", default="2,4,6,8")
    po.add_argument("--trials", type=int, default=20)
    po.add_argument("--min-keylen", type=int, default=4)
    po.add_argument("--max-keylen", type=int, default=12)
    po.add_argument("--min-chars", type=int, default=500)
    po.add_argument("--max-chars", type=int, default=1500)
    po.add_argument("--max-k", type=int, default=30)
    po.add_argument("--target", type=float, default=0.95,
                    help="Minimum key_acc for the 'cheapest qualifying' pick")
    po.add_argument("--seed", type=int, default=0)
    po.add_argument("--jobs", type=int, default=0)
    po.add_argument("--no-progress", action="store_true")
    po.set_defaults(func=_cmd_optimize)

    pg = sub.add_parser("gen-corpus", help="Generate a synthetic benchmark corpus")
    pg.add_argument("--out", required=True)
    pg.add_argument("--n", type=int, default=20)
    pg.add_argument("--min-keylen", type=int, default=4)
    pg.add_argument("--max-keylen", type=int, default=12)
    pg.add_argument("--min-chars", type=int, default=400)
    pg.add_argument("--max-chars", type=int, default=1200)
    pg.add_argument("--seed", type=int, default=0)
    pg.set_defaults(func=_cmd_gen_corpus)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
