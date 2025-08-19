#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify
)

from solver import VigenereSolver
from utils import CiphertextParser


def _available_cpus() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except Exception:
        pass
    try:
        import multiprocessing as mp
        return max(1, mp.cpu_count())
    except Exception:
        return 1


def _thread_budget() -> int:
    cap = int(os.environ.get("SOLVER_THREADS_MAX", "2"))
    return max(1, min(_available_cpus(), cap))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", os.urandom(24).hex())
    app.config["LANG_PATH"] = os.environ.get("LANG_PATH", "language_data.json")

    @app.get("/")
    def index():
        # default configuration values for the solver
        defaults = {
            "decoder": "lm",
            "passes": 5,
            "lm_weight": 0.65,
            "anneal": 0.0,
            "auto_ws": True,
            "window": "",
            "step": "",
            "ws_beam": 6,
            "ws_passes": 2,
            "no_seg": False,
        }
        return render_template("index.html", defaults=defaults)

    @app.get("/how-it-works")
    def how_it_works():
        # how it works page
        return render_template("how.html")

    @app.get("/how-to-use")
    def how_to_use():
        # how to use page
        return render_template("howto.html")

    @app.post("/solve")
    def solve():
        # solve page
        raw_text = (request.form.get("ciphertext") or "").strip()
        if not raw_text:
            flash("Ciphertext is required.", "warning")
            return redirect(url_for("index"))

        decoder = request.form.get("decoder", "lm")
        passes = _int(request.form.get("passes"), default=5)
        lm_weight = _float(request.form.get("lm_weight"), default=0.65)
        anneal = _float(request.form.get("anneal"), default=0.0)
        auto_ws = bool(request.form.get("auto_ws") == "on")
        window = _int_opt(request.form.get("window"))
        step = _int_opt(request.form.get("step"))
        ws_beam = _int(request.form.get("ws_beam"), default=6)
        ws_passes = _int(request.form.get("ws_passes"), default=2)
        no_seg = bool(request.form.get("no_seg") == "on")

        t0 = time.time()
        solver = VigenereSolver(
            app.config["LANG_PATH"],
            window=window, step=step,
            use_windowed_keys=True,
            anneal=anneal, lm_weight=lm_weight,
            auto_ws=auto_ws,
            ws_beam=ws_beam, ws_passes=ws_passes
        )

        blocks = CiphertextParser.parse_string(raw_text)
        if not blocks:
            flash('No ciphertext found. You can use triple-quoted blocks like """ your text """ or paste raw text directly.', "warning")
            return redirect(url_for("index"))

        workers = _thread_budget()

        per_block_results: List[Dict[str, Any]] = []
        for idx, ct in enumerate(blocks, 1):
            start = time.time()
            res = solver.solve_text(
                ct,
                decoder=decoder,
                passes=passes,
                max_workers=workers,
                enable_seg=not no_seg
            )
            elapsed = time.time() - start
            per_block_results.append({
                "index": idx,
                "key_length": res.key_length,
                "key": res.key,
                "ioc": res.ioc,
                "score": res.score,
                "kasiski": res.kasiski,
                "preview": (res.formatted[:1600] + ("…" if len(res.formatted) > 1600 else "")),
                "full": res.formatted,
                "elapsed": elapsed
            })

        total_elapsed = time.time() - t0
        meta = {
            "decoder": decoder,
            "passes": passes,
            "lm_weight": lm_weight,
            "anneal": anneal,
            "auto_ws": auto_ws,
            "window": solver.window,
            "step": solver.step,
            "ws_beam": ws_beam,
            "ws_passes": ws_passes,
            "no_seg": no_seg,
            "blocks_count": len(blocks),
            "total_elapsed": total_elapsed,
            "workers_used": workers,
        }

        return render_template("results.html", results=per_block_results, meta=meta)

    @app.post("/api/solve")
    def api_solve():
        # api solve page
        data = request.get_json(silent=True) or {}
        text = (data.get("ciphertext") or "").strip()
        if not text:
            return jsonify({"error": "ciphertext required"}), 400

        params = {
            "decoder": data.get("decoder", "lm"),
            "passes": int(data.get("passes", 5)),
            "lm_weight": float(data.get("lm_weight", 0.65)),
            "anneal": float(data.get("anneal", 0.0)),
            "auto_ws": bool(data.get("auto_ws", True)),
            "window": data.get("window", None),
            "step": data.get("step", None),
            "ws_beam": int(data.get("ws_beam", 6)),
            "ws_passes": int(data.get("ws_passes", 2)),
            "no_seg": bool(data.get("no_seg", False)),
        }

        solver = VigenereSolver(
            app.config["LANG_PATH"],
            window=params["window"], step=params["step"],
            use_windowed_keys=True,
            anneal=params["anneal"], lm_weight=params["lm_weight"],
            auto_ws=params["auto_ws"],
            ws_beam=params["ws_beam"], ws_passes=params["ws_passes"]
        )

        blocks = CiphertextParser.parse_string(text)
        if not blocks:
            return jsonify({"error": "no ciphertext found"}), 400

        workers = _thread_budget()
        out = []
        for ct in blocks:
            res = solver.solve_text(
                ct,
                decoder=params["decoder"],
                passes=params["passes"],
                max_workers=workers,
                enable_seg=not params["no_seg"]
            )
            out.append({
                "key_length": res.key_length,
                "key": res.key,
                "ioc": res.ioc,
                "score": res.score,
                "kasiski": res.kasiski,
                "plaintext": res.formatted
            })
        return jsonify({
            "params": {**params, "window": solver.window, "step": solver.step, "workers_used": workers},
            "results": out
        }), 200

    return app


def _int(s: Optional[str], default: int) -> int:
    try:
        return int(s) if s is not None and s != "" else default
    except Exception:
        return default


def _float(s: Optional[str], default: float) -> float:
    try:
        return float(s) if s is not None and s != "" else default
    except Exception:
        return default


def _int_opt(s: Optional[str]) -> Optional[int]:
    try:
        s = (s or "").strip()
        return int(s) if s else None
    except Exception:
        return None


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
