from vigenere.alphabet import decrypt, encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.language import cached_language_model
from vigenere.search import beam_search, per_strip_candidates


def test_beam_search_recovers_short_key():
    key = "ZEBRA"
    ct = encrypt(SAMPLE_TEXT, key)
    prior = cached_language_model().monogram_vector()
    per = per_strip_candidates(ct, len(key), prior, top_m=6)
    assert len(per) == len(key)
    for cands in per:
        assert len(cands) <= 6
    beams = beam_search(per, beam=16)
    keys = [k for k, _ in beams]
    assert key in keys, f"true key not in beam; got top5={keys[:5]}"


def test_beam_returns_keys_of_right_length():
    ct = encrypt(SAMPLE_TEXT, "LEMON")
    prior = cached_language_model().monogram_vector()
    per = per_strip_candidates(ct, 5, prior, top_m=4)
    beams = beam_search(per, beam=8)
    for k, _ in beams:
        assert len(k) == 5
