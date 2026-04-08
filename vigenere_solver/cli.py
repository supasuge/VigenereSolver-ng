"""Command-line interface for the Vigenère solver."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

try:  # pragma: no cover - optional rich dependency
    from rich.console import Console
    from rich.panel import Panel
except Exception:  # pragma: no cover
    Console = None  # type: ignore
    Panel = None  # type: ignore

from . import solver
from .config import load_toml_config, merge_section_into_args

console = Console() if Console else None


def _read(path: str) -> str:
    return sys.stdin.read() if path == "-" else pathlib.Path(path).read_text(encoding="utf-8")


def _dump_json(obj, out_path: str | None, echo: bool) -> None:
    payload = json.dumps(obj, indent=2)
    if out_path:
        pathlib.Path(out_path).write_text(payload, encoding="utf-8")
    if echo:
        print(payload)


def main() -> None:
    parser = argparse.ArgumentParser("vigenere-ng", description="Vigenère solver (statistics + LM heuristics)")
    parser.add_argument("--config", default=None, help="TOML config with [solve], [encrypt], [explain], [bench] sections")

    sub = parser.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("solve", help="Decrypt Vigenère ciphertext")
    ps.add_argument("--in", dest="infile", default="-", help="Ciphertext path or '-' for stdin")
    ps.add_argument(
        "--decoder",
        choices=["tiny-lm", "kenlm", "classic", "legacy"],
        default="tiny-lm",
        help="Scoring backend for re-ranking",
    )
    ps.add_argument("--lm-path", default=None, help="KenLM model dir/file (required if decoder=kenlm)")
    ps.add_argument("--lang", default="en")
    ps.add_argument("--max-k", type=int, default=40)
    ps.add_argument("--passes", type=int, default=6)
    ps.add_argument("--topk", type=int, default=5)
    ps.add_argument("--seed", type=int, default=None)
    ps.add_argument("--no-progress", action="store_true")
    ps.add_argument("--json", action="store_true")
    ps.add_argument("--out", default=None, help="Write JSON result to this path")
    ps.add_argument("--wordlist", default=None, help="Path to large English wordlist for autocorrection")
    ps.add_argument("--classic-ngram-order", type=int, default=4)
    ps.add_argument("--classic-lambdas", default=None, help="CSV weights for 1..N (e.g. 0.05,0.15,0.30,0.50)")
    ps.add_argument("--classic-alpha", type=float, default=1e-3)
    ps.add_argument("--bm-beam", type=int, default=16)
    ps.add_argument("--bm-strip-top", type=int, default=6)
    ps.add_argument("--bm-keylens", default=None, help="CSV of key lengths to force (e.g. 5,7,9)")
    ps.add_argument("--explain-dir", default=None, help="If set, dump periodogram + report here")

    pe = sub.add_parser("encrypt", help="Encrypt plaintext with key")
    pe.add_argument("--in", dest="infile", default="-")
    pe.add_argument("--key", required=True)

    px = sub.add_parser("explain", help="Export periodogram + key-length posterior")
    px.add_argument("--in", dest="infile", default="-")
    px.add_argument("--outdir", required=True)
    px.add_argument("--max-k", type=int, default=40)

    pb = sub.add_parser("bench", help="Run accuracy/time comparisons across decoders")
    pb.add_argument("--corpus", required=True, help="Directory with pt/ct/key and manifest.json")
    pb.add_argument("--decoders", default="tiny-lm,classic,kenlm,legacy", help="CSV of decoders to compare")
    pb.add_argument("--lm-path", default=None, help="KenLM model path if 'kenlm' is included")
    pb.add_argument("--jobs", type=int, default=0, help="Parallel workers (0=auto)")
    pb.add_argument("--limit", type=int, default=0, help="Limit #samples (0=all)")
    pb.add_argument("--out", default="bench_results.csv")
    pb.add_argument("--max-k", type=int, default=40)
    pb.add_argument("--passes", type=int, default=6)
    pb.add_argument("--bm-beam", type=int, default=16)
    pb.add_argument("--bm-strip-top", type=int, default=6)
    pb.add_argument("--report-out", default="bench_summary.json", help="Path for aggregate benchmark summary JSON (+ .md)")

    args = parser.parse_args()

    cfg = load_toml_config(getattr(args, "config", None)) if getattr(args, "config", None) else {}
    section = args.cmd.replace("-", "_")
    args = merge_section_into_args(args, cfg.get(section, {}))

    try:
        if args.cmd in {"solve", "explain"}:
            text = _read(args.infile)

        if args.cmd == "solve":
            lambdas = None
            if args.classic_lambdas:
                lambdas = [float(x) for x in str(args.classic_lambdas).split(",") if x.strip()]
            forced = None
            if args.bm_keylens:
                forced = [int(x) for x in str(args.bm_keylens).split(",") if x.strip()]

            res = solver.solve(
                text,
                decoder=args.decoder,
                lm_path=args.lm_path,
                lang=args.lang,
                max_k=args.max_k,
                passes=args.passes,
                topk=args.topk,
                seed=args.seed,
                show_progress=not args.no_progress,
                wordlist=args.wordlist,
                classic_order=max(2, min(5, args.classic_ngram_order)),
                classic_lambdas=lambdas,
                classic_alpha=args.classic_alpha,
                beam=args.bm_beam,
                strip_top=args.bm_strip_top,
                forced_keylens=forced,
                explain_dir=args.explain_dir,
            )
            if args.json or args.out:
                _dump_json(res, args.out, args.json)
            else:
                if console and Panel:
                    console.print(Panel.fit(res["pretty"], title="Vigenère Solver"))
                else:
                    print(res["pretty"])  # pragma: no cover - plain fallback

        elif args.cmd == "encrypt":
            pt = _read(args.infile)
            print(solver.encrypt(pt, args.key))

        elif args.cmd == "explain":
            solver.explain(text, outdir=args.outdir, max_k=args.max_k)
            msg = "Explain artifacts written to " + args.outdir
            if console:
                console.print(f"[green]{msg}[/]")
            else:
                print(msg)

        elif args.cmd == "bench":
            from .bench import run_bench

            summary = run_bench(
                corpus_dir=args.corpus,
                decoders=[d.strip() for d in args.decoders.split(",") if d.strip()],
                lm_path=args.lm_path,
                jobs=args.jobs,
                out_csv=args.out,
                limit=args.limit,
                max_k=args.max_k,
                passes=args.passes,
                beam=args.bm_beam,
                strip_top=args.bm_strip_top,
                report_out=args.report_out,
            )
            msg = f"Bench results written to {args.out}; summary: {args.report_out}"
            if console:
                console.print(f"[green]{msg}[/]")
            else:
                print(msg)

    except FileNotFoundError as exc:
        if console:
            console.print(f"[red]File error:[/] {exc}")
        else:
            print(f"File error: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        if console:
            console.print(f"[red]Fatal error:[/] {exc}")
        else:
            print(f"Fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()



