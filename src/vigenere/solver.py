"""End-to-end Vigenere attack pipeline.

Pipeline (see README §1–§8 for the math):

    1. Estimate the key-length posterior (or use `forced_keylens`).
    2. For each top-N key length, generate candidate keys via per-strip
       Caesar scoring + beam search.
    3. Re-rank all unique candidates with the chosen full-text scorer
       (``legacy`` / ``tiny-lm`` / ``classic``), or ensemble re-rank under
       the ``best`` decoder.
    4. Optionally refine the best key against a wordlist.

All stages emit live progress through a :class:`ProgressReporter` (no-op
by default) and can be parallelized via the ``jobs`` parameter.
"""
from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Sequence

from .alphabet import clean_letters, decrypt
from .keylength import keylength_posterior
from .language import LanguageModel, cached_language_model
from .match import MatchResult, classify_match
from .progress import NullProgressReporter, ProgressReporter
from .refine import load_wordlist, refine_key
from .scoring import ClassicNGramScorer, Scorer, get_scorer
from .search import beam_search, per_strip_candidates

ENSEMBLE_DECODER = "best"
ALL_DECODERS: tuple[str, ...] = ("legacy", "tiny-lm", "classic")


# ---------------------------------------------------------------------------
# Default presets (Pareto-optimal from `vigenere optimize` on random samples).
# `solve_auto` starts at FAST and only escalates to HARD if confidence is low.
# ---------------------------------------------------------------------------
FAST_PRESET = dict(decoder="classic", beam=4, strip_top=4, top_keylens=3, max_k=30)
BALANCED_PRESET = dict(decoder="best",    beam=8, strip_top=6, top_keylens=5, max_k=40)
HARD_PRESET = dict(decoder="best",    beam=24, strip_top=10, top_keylens=8, max_k=50)

# Confidence below which `solve_auto` re-runs with HARD_PRESET.
AUTO_CONFIDENCE_THRESHOLD = 0.15


@dataclass
class SolveResult:
    key: str
    plaintext: str
    keylen_posterior: list[tuple[int, float]]  # (k, prob), sorted desc
    candidates: list[tuple[str, float]]        # (key, full-text score), sorted desc
    scorer_name: str
    refined: bool = False
    elapsed_sec: float = 0.0
    confidence: float = 0.0
    signals: dict = field(default_factory=dict)  # per-signal contributions (twist, ioc, ...)
    extra: dict = field(default_factory=dict)

    def match_against(self, true_key: str, max_diff: int = 2) -> MatchResult:
        """Compare the recovered key against a known true key."""
        return classify_match(self.key, true_key, max_diff=max_diff)

    def pretty(self, max_lines: int = 8) -> str:
        kl = ", ".join(f"{k}:{p:.3f}" for k, p in self.keylen_posterior[:5])
        cand = "\n  ".join(f"{k!r}  score={s:.3f}" for k, s in self.candidates[:5])
        snippet = "\n".join(self.plaintext.splitlines()[:max_lines])
        return (
            f"key        : {self.key!r}  (len={len(self.key)})\n"
            f"scorer     : {self.scorer_name}{'  +refine' if self.refined else ''}\n"
            f"confidence : {self.confidence:.3f}\n"
            f"keylen p   : {kl}\n"
            f"top cands  :\n  {cand}\n"
            f"---- plaintext ----\n{snippet}"
        )


def _map(jobs: int, func, items):
    """Sequential map for jobs<=1, ThreadPoolExecutor.map otherwise.

    Threads are used (not processes) because their overhead is bounded and
    the numpy parts of the pipeline release the GIL. For pure-Python parts
    the speedup is modest, but threading still wins on multi-keylen and
    multi-decoder ensemble runs.
    """
    items = list(items)
    if jobs and jobs > 1 and len(items) > 1:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            return list(pool.map(func, items))
    return [func(x) for x in items]


def _candidates_for_keylen(
    text: str, k: int, prior: list[float],
    strip_top: int, beam: int, topk: int,
) -> list[str]:
    per_strip = per_strip_candidates(text, k, prior, top_m=strip_top)
    return [key for key, _ in beam_search(per_strip, beam=beam)[:topk] if key]


def solve(
    ciphertext: str,
    *,
    decoder: str = "best",
    language: LanguageModel | None = None,
    max_k: int = 40,
    topk: int = 5,
    top_keylens: int = 5,
    beam: int = 16,
    strip_top: int = 6,
    forced_keylens: Sequence[int] | None = None,
    wordlist: str | None = None,
    seed: int | None = None,
    scorer_kwargs: dict | None = None,
    jobs: int = 1,
    progress: ProgressReporter | None = None,
) -> SolveResult:
    """Attack ``ciphertext`` end-to-end.

    Parameters
    ----------
    decoder : "legacy" | "tiny-lm" | "classic" | "best"
        Full-text re-ranking model. ``"best"`` runs every decoder and pools
        their top candidates, then re-ranks the union with the classic LM.
    jobs : int
        Worker thread count. ``jobs=1`` is sequential; larger values
        parallelize candidate-generation across key lengths, full-text
        scoring across candidates, and (for ``best``) per-decoder runs.
    progress : ProgressReporter
        Live-progress sink. ``None`` = silent. See :mod:`vigenere.progress`.
    """
    import time as _time
    t_start = _time.perf_counter()
    pr = progress or NullProgressReporter()

    if seed is not None:
        random.seed(seed)

    if len(clean_letters(ciphertext)) < 4:
        raise RuntimeError("ciphertext too short (need at least 4 letters)")

    lm = language or cached_language_model()
    prior = lm.monogram_vector()

    signals: dict = {}
    with pr:
        # ----- Stage 1: key-length posterior -----
        pr.stage("key-length estimation (IoC + Kasiski + periodogram + twist++)",
                 total=1)
        # Always compute signals - they're useful diagnostics even when
        # the user has forced a specific key length.
        natural_post, signals = keylength_posterior(
            ciphertext, max_k=max_k, return_table=True
        )
        if forced_keylens:
            kl_post: list[tuple[int, float]] = [
                (int(k), 1.0 / len(forced_keylens)) for k in forced_keylens
            ]
            signals["forced_keylens"] = list(forced_keylens)
            signals["natural_posterior_top"] = natural_post[:10]
            pr.stat("forced keylens", list(forced_keylens))
        else:
            kl_post = natural_post
        pr.posterior(kl_post, top=12)
        pr.advance(1)
        pr.finish_stage()

        # ----- Stage 2: per-keylen candidate generation -----
        keylens = [k for k, _ in kl_post[: max(1, top_keylens)]]
        pr.stage("candidate generation", total=len(keylens))

        def _gen(k: int) -> tuple[int, list[str]]:
            cands = _candidates_for_keylen(ciphertext, k, prior, strip_top, beam, topk)
            pr.advance(1, note=f"keylen={k}: {len(cands)} candidates",
                       best_key=cands[0] if cands else None)
            return k, cands

        gen_results = _map(jobs, _gen, keylens)

        seen: set[str] = set()
        candidate_keys: list[str] = []
        for _, cands in gen_results:
            for c in cands:
                if c not in seen:
                    seen.add(c)
                    candidate_keys.append(c)
        pr.stat("candidate keys", len(candidate_keys))
        pr.finish_stage()

        if not candidate_keys:
            raise RuntimeError("no candidate keys produced (ciphertext too short?)")

        # ----- Stage 3: full-text re-rank -----
        scored, scorer_name, plaintexts = _rerank(
            ciphertext, candidate_keys, decoder, lm, topk, jobs, pr,
            scorer_kwargs=scorer_kwargs,
        )

        best_key, best_score = scored[0]
        plaintext = plaintexts[best_key]
        pr.advance(0, best_key=best_key, best_score=best_score, snippet=plaintext)

        # ----- Stage 4: optional wordlist refinement -----
        refined = False
        if wordlist:
            pr.stage("dictionary refinement", total=1)
            words = load_wordlist(wordlist)
            pr.stat("wordlist size", len(words))
            new_key = refine_key(ciphertext, best_key, words)
            if new_key != best_key:
                # Score the refined key under the same scorer used for
                # re-rank and splice it into `scored` so that `candidates`
                # and `confidence` reflect the actual returned key.
                rerank_scorer = (ClassicNGramScorer(language=lm)
                                 if decoder == ENSEMBLE_DECODER
                                 else _build_scorer(decoder, lm, scorer_kwargs))
                refined_plaintext = decrypt(ciphertext, new_key)
                refined_score = rerank_scorer.score(refined_plaintext)
                plaintexts[new_key] = refined_plaintext
                scored = [(new_key, refined_score)] + [
                    (k, s) for k, s in scored if k != new_key
                ]
                scored.sort(key=lambda t: t[1], reverse=True)
                best_key = new_key
                plaintext = refined_plaintext
                refined = True
                pr.advance(1, best_key=best_key, snippet=plaintext,
                           note="key refined via wordlist majority vote")
            else:
                pr.advance(1, note="no change after refinement")
            pr.finish_stage()

    elapsed = _time.perf_counter() - t_start
    confidence = _confidence_from_candidates(scored, plaintexts)
    return SolveResult(
        key=best_key,
        plaintext=plaintext,
        keylen_posterior=kl_post[:10],
        candidates=scored[:topk],
        scorer_name=scorer_name,
        refined=refined,
        elapsed_sec=elapsed,
        confidence=confidence,
        signals=signals,
    )


def solve_auto(
    ciphertext: str,
    *,
    confidence_threshold: float = AUTO_CONFIDENCE_THRESHOLD,
    wordlist: str | None = None,
    jobs: int = 1,
    progress: ProgressReporter | None = None,
    seed: int | None = None,
) -> SolveResult:
    """Adaptive solver: cheap params first, escalate to ``best`` if uncertain.

    Pipeline:

    1. Run :func:`solve` with :data:`FAST_PRESET` (``classic`` decoder, tight
       beam / strip / keylen). If ``result.confidence >= confidence_threshold``,
       return it.
    2. Otherwise re-run with :data:`HARD_PRESET` (``best`` ensemble + wider
       beam, more strips, larger ``max_k``). Always return the higher-
       confidence of the two.

    Empirically this gives ~classic-speed performance on easy ciphertexts
    while not sacrificing accuracy on hard ones.
    """
    pr = progress or NullProgressReporter()
    fast = solve(ciphertext, wordlist=wordlist, jobs=jobs, progress=pr,
                 seed=seed, **FAST_PRESET)
    if fast.confidence >= confidence_threshold:
        fast.extra["auto"] = {"path": "fast", "tried": ["fast"]}
        return fast

    hard = solve(ciphertext, wordlist=wordlist, jobs=jobs, progress=pr,
                 seed=seed, **HARD_PRESET)
    # Pick whichever has higher confidence; on ties prefer the harder run
    chosen = hard if hard.confidence >= fast.confidence else fast
    chosen.extra["auto"] = {
        "path": "fast+hard" if chosen is hard else "fast(fallback)",
        "tried": ["fast", "hard"],
        "fast_confidence": fast.confidence,
        "hard_confidence": hard.confidence,
    }
    return chosen


def _confidence_from_candidates(
    scored: list[tuple[str, float]],
    plaintexts: dict[str, str],
) -> float:
    """Margin-based confidence in [0, 1].

    The gap is measured between the top candidate and the best runner-up
    that *decrypts to a different plaintext*. This treats key rotations
    and multiples (which produce identical plaintexts) as the same answer
    so confidence reflects genuine plaintext ambiguity.

    The ``plaintexts`` dict must map every key in ``scored`` to its
    decryption (no redundant ``decrypt`` calls here).
    """
    if not scored:
        return 0.0
    top_key, top_score = scored[0]
    top_pt = plaintexts[top_key]
    runner_score: float | None = None
    bottom_score = scored[-1][1]
    for k, sc in scored[1:]:
        if plaintexts[k] != top_pt:
            runner_score = sc
            break
    if runner_score is None:
        # All candidates yield the same plaintext - maximally confident.
        return 1.0
    spread = top_score - bottom_score
    if spread <= 0:
        return 0.0
    return max(0.0, min(1.0, (top_score - runner_score) / spread))


def _build_scorer(decoder: str, lm: LanguageModel, kwargs: dict | None) -> Scorer:
    sk = dict(kwargs or {})
    if decoder in ("classic", "legacy", "jsd"):
        sk.setdefault("language", lm)
    return get_scorer(decoder, **sk)


def _rerank(
    ciphertext: str,
    candidate_keys: list[str],
    decoder: str,
    lm: LanguageModel,
    topk: int,
    jobs: int,
    pr: ProgressReporter,
    *,
    scorer_kwargs: dict | None = None,
) -> tuple[list[tuple[str, float]], str, dict[str, str]]:
    """Score and rank candidate keys.

    Returns ``(scored_desc, scorer_name, plaintexts)`` where ``plaintexts``
    maps every candidate key in ``scored_desc`` to its decryption. The
    caller can reuse this dict instead of re-decrypting.
    """
    # Decrypt once per candidate, used by every downstream consumer.
    plaintexts: dict[str, str] = {k: decrypt(ciphertext, k) for k in candidate_keys}

    if decoder == ENSEMBLE_DECODER:
        pr.stage(f"ensemble: {len(ALL_DECODERS)} decoders x {len(candidate_keys)} keys",
                 total=len(ALL_DECODERS))

        def _vote(name: str) -> list[str]:
            scorer = _build_scorer(name, lm, None)
            ranked = sorted(
                ((k, scorer.score(plaintexts[k])) for k in candidate_keys),
                key=lambda t: t[1], reverse=True,
            )
            top = [k for k, _ in ranked[:topk]]
            pr.advance(1, note=f"{name}: best={top[0] if top else '?'}",
                       best_key=top[0] if top else None)
            return top

        votes = _map(jobs, _vote, ALL_DECODERS)
        pool: set[str] = set(candidate_keys)
        for v in votes:
            pool.update(v)
        # Decrypt any newly-pooled candidate exactly once.
        for k in pool - plaintexts.keys():
            plaintexts[k] = decrypt(ciphertext, k)
        pr.stat("pooled candidates", len(pool))
        pr.finish_stage()

        pr.stage("final re-rank (classic LM)", total=len(pool))
        rerank_scorer = ClassicNGramScorer(language=lm)

        def _score(k: str) -> tuple[str, float]:
            sc = rerank_scorer.score(plaintexts[k])
            pr.advance(1, best_key=k, best_score=sc, snippet=plaintexts[k])
            return k, sc

        scored = _map(jobs, _score, sorted(pool))
        scored.sort(key=lambda t: t[1], reverse=True)
        pr.finish_stage()
        return scored, "best", plaintexts

    # Single-decoder
    pr.stage(f"re-rank ({decoder})", total=len(candidate_keys))
    scorer = _build_scorer(decoder, lm, scorer_kwargs)

    def _score(k: str) -> tuple[str, float]:
        sc = scorer.score(plaintexts[k])
        pr.advance(1, best_key=k, best_score=sc, snippet=plaintexts[k])
        return k, sc

    scored = _map(jobs, _score, candidate_keys)
    scored.sort(key=lambda t: t[1], reverse=True)
    pr.finish_stage()
    return scored, scorer.name, plaintexts
