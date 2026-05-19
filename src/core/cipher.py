"""End-to-end Vigenere API usage example (CTF-style walkthrough).

This module is intentionally executable as a script — it doubles as living
documentation for the public ``vigenere`` API. Run it directly to see every
step of a realistic CTF break:

    python -m core.cipher
    # or, after `pip install vigenere`:
    python -c "from core.cipher import demo; demo()"

The scenario mirrors a typical "classical crypto" CTF challenge:

    1. We are handed a ciphertext blob (Base64-wrapped, mixed case, with
       punctuation and whitespace — exactly how a flag dump usually arrives).
    2. We don't know the key, the key length, or even that the plaintext is
       English (we'll let the solver confirm it).
    3. We run the full attack pipeline (FFT periodogram + Kasiski + twist
       keylength voting, then beam search guided by an interpolated character
       n-gram language model) and recover both the key and the plaintext.
    4. We verify the recovery round-trips through ``encrypt``/``decrypt``.

The example is deliberately self-contained: no network, no files, no
external corpora — just the public API surface exported from
``vigenere.__init__``.
"""
from __future__ import annotations

import base64
from dataclasses import asdict

from vigenere import (
    SolveResult,
    clean_letters,
    decrypt,
    encrypt,
    solve,
)


# ---------------------------------------------------------------------------
# 1. Challenge setup — what a CTF player would actually receive.
# ---------------------------------------------------------------------------

# A realistic-length English passage. In a real challenge this would be the
# unknown plaintext; here we keep it so we can sanity-check the recovery.
_PLAINTEXT_SOURCE = (
    "When in the course of human events it becomes necessary for one people "
    "to dissolve the political bands which have connected them with another "
    "and to assume among the powers of the earth the separate and equal "
    "station to which the laws of nature and of natures god entitle them a "
    "decent respect to the opinions of mankind requires that they should "
    "declare the causes which impel them to the separation we hold these "
    "truths to be self evident that all men are created equal that they are "
    "endowed by their creator with certain unalienable rights that among "
    "these are life liberty and the pursuit of happiness"
)

# The flag-bearing key. In a CTF this is what you're trying to recover — it
# often spells out the flag or a hint toward it.
_SECRET_KEY = "FLAGISVIGENERE"


def _build_challenge_blob() -> str:
    """Produce the ciphertext exactly as a CTF would hand it to you.

    Real challenges almost never give you a clean A-Z stream — they wrap it
    in Base64, mix case, sprinkle punctuation, etc. We replicate that so the
    example also demonstrates the ``clean_letters`` normalization step.
    """
    ct = encrypt(_PLAINTEXT_SOURCE, _SECRET_KEY)
    # Wrap it the way a challenge author might:
    return base64.b64encode(ct.encode("ascii")).decode("ascii")


# ---------------------------------------------------------------------------
# 2. Attack pipeline — the part a player actually writes.
# ---------------------------------------------------------------------------

def break_challenge(blob: str) -> SolveResult:
    """Recover key + plaintext from a CTF-style ciphertext blob.

    Steps:

    * Base64-decode the wrapper (challenge-specific).
    * ``clean_letters`` strips everything but A-Z and upper-cases.
    * ``solve`` runs the full ensemble: keylength voting (FFT periodogram,
      Kasiski factor histogram, twist/twist+ statistics), per-column
      chi-square key seeding, then beam search refined by an interpolated
      1..5-gram language model with learned posterior weights.
    """
    raw = base64.b64decode(blob).decode("ascii")
    ciphertext = clean_letters(raw)

    # ``solve`` is the headline entry point. With no extra args it uses the
    # adaptive "best" profile, which is what you want for blind CTF input.
    return solve(ciphertext)


# ---------------------------------------------------------------------------
# 3. Verification — what the writeup would show.
# ---------------------------------------------------------------------------

def demo() -> SolveResult:
    """Run the whole walkthrough and print a CTF-style writeup."""
    blob = _build_challenge_blob()

    print("=" * 60)
    print("CTF challenge: Vigenere")
    print("=" * 60)
    print(f"Ciphertext (Base64, {len(blob)} chars):")
    print(f"  {blob[:72]}{'…' if len(blob) > 72 else ''}")
    print()

    result = break_challenge(blob)

    top_score = result.candidates[0][1] if result.candidates else float("nan")
    print(f"Recovered key   : {result.key!r}")
    print(f"Recovered length: {len(result.key)}")
    print(f"Plaintext head  : {result.plaintext[:72]}…")
    print(f"Scorer          : {result.scorer_name}")
    print(f"Top cand. score : {top_score:.4f}")
    print(f"Confidence      : {result.confidence:.4f}")
    print(f"Elapsed         : {result.elapsed_sec:.3f}s")
    print()

    # Round-trip sanity check: re-encrypt the recovered plaintext under the
    # recovered key and confirm it matches the original cleaned ciphertext.
    reencrypted = encrypt(result.plaintext, result.key)
    original_ct = clean_letters(base64.b64decode(blob).decode("ascii"))
    assert reencrypted == original_ct, "round-trip mismatch — broken recovery"

    # And the cleartext we built the challenge from must match (modulo
    # whitespace/punctuation removed by ``clean_letters``).
    assert result.plaintext == clean_letters(_PLAINTEXT_SOURCE), (
        "plaintext mismatch — solver returned a near-miss"
    )

    print("[+] Round-trip verified: encrypt(plaintext, key) == ciphertext")
    print(f"[+] Key matches secret  : {result.key == _SECRET_KEY}")
    print()
    print("Full SolveResult fields:")
    for k, v in asdict(result).items():
        preview = v if not isinstance(v, str) else (v[:60] + ("…" if len(v) > 60 else ""))
        print(f"  - {k}: {preview!r}")

    return result


if __name__ == "__main__":
    demo()
