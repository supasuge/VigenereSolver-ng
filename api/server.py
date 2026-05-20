"""Minimal HTTP API around the vigenere-solver-ng Python package.

Run:
    uv run --with fastapi --with uvicorn python -m api.server
    # or
    uv run uvicorn api.server:app --reload --port 8000
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Optional, Sequence

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from vigenere import decrypt, encrypt, solve, solve_auto

app = FastAPI(title="Vigenere Solver API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


class KeyedRequest(BaseModel):
    text: str
    key: str


class SolveRequest(BaseModel):
    text: str
    auto: bool = True
    decoder: str = "best"
    max_k: int = 40
    topk: int = 5
    top_keylens: int = 5
    beam: int = 16
    strip_top: int = 6
    forced_keylens: Optional[Sequence[int]] = None
    seed: Optional[int] = None
    jobs: int = 1
    auto_threshold: float = 0.15


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/encrypt")
def api_encrypt(req: KeyedRequest) -> dict:
    if not req.key.strip():
        raise HTTPException(400, "key required")
    return {"ciphertext": encrypt(req.text, req.key)}


@app.post("/decrypt")
def api_decrypt(req: KeyedRequest) -> dict:
    if not req.key.strip():
        raise HTTPException(400, "key required")
    return {"plaintext": decrypt(req.text, req.key)}


@app.post("/solve")
def api_solve(req: SolveRequest) -> dict:
    try:
        if req.auto and not req.forced_keylens:
            result = solve_auto(
                req.text,
                confidence_threshold=req.auto_threshold,
                jobs=req.jobs,
                seed=req.seed,
            )
        else:
            result = solve(
                req.text,
                decoder=req.decoder,
                max_k=req.max_k,
                topk=req.topk,
                top_keylens=req.top_keylens,
                beam=req.beam,
                strip_top=req.strip_top,
                forced_keylens=req.forced_keylens,
                seed=req.seed,
                jobs=req.jobs,
            )
    except RuntimeError as e:
        raise HTTPException(400, str(e))

    d = asdict(result)
    d.pop("signals", None)
    return d


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
