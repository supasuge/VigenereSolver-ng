from vigenere.alphabet import encrypt
from vigenere.bench import SAMPLE_TEXT
from vigenere.refine import refine_key


WORDS = [
    "THE", "AND", "NATION", "GOVERNMENT", "CONSTITUTION", "UNITED",
    "PEOPLE", "STATES", "ARE", "FROM", "THAT", "WITH", "HAVE", "WERE",
    "DEDICATED", "BATTLE", "FIELD", "LIBERTY",
]


def test_refine_recovers_single_position_typo():
    true_key = "FREEDOM"
    ct = encrypt(SAMPLE_TEXT, true_key)
    # Corrupt one position
    bad = "FREZDOM"
    fixed = refine_key(ct, bad, WORDS, max_iter=3, max_mismatch=1)
    assert fixed == true_key


def test_refine_no_change_when_already_correct():
    true_key = "LEMONADE"
    ct = encrypt(SAMPLE_TEXT, true_key)
    assert refine_key(ct, true_key, WORDS) == true_key


def test_refine_handles_empty_inputs():
    assert refine_key("", "ABC", WORDS) == "ABC"
    assert refine_key("HELLO", "", WORDS) == ""
