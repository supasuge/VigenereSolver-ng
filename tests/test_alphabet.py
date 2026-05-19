import random

import pytest

from vigenere.alphabet import (
    clean_letters,
    decrypt,
    encrypt,
    random_key,
    shift_only,
    split_strips,
)


def test_clean_letters_strips_non_alpha():
    assert clean_letters("Hello, World! 123") == "HELLOWORLD"
    assert clean_letters("") == ""
    assert clean_letters("?!.") == ""


def test_encrypt_decrypt_roundtrip_preserves_text():
    pt = "Attack at dawn! The eagle flies at midnight.\nNew line here."
    key = "Lemon"
    ct = encrypt(pt, key)
    # Non-letters preserved
    assert "!" in ct and "\n" in ct and ct.count(" ") == pt.count(" ")
    # Output letters all uppercase
    for ch in ct:
        if ch.isalpha():
            assert ch.isupper()
    # Round-trip recovers letters
    rec = decrypt(ct, key)
    assert clean_letters(rec) == clean_letters(pt).upper()


@pytest.mark.parametrize("key", ["A", "AAA", "Z", "VIGENERE"])
def test_encrypt_with_a_only_key_is_identity_on_letters(key):
    pt = "hello world"
    ct = encrypt(pt, key)
    if set(clean_letters(key)) == {"A"}:
        assert clean_letters(ct) == clean_letters(pt).upper()


def test_random_key_length_and_alphabet():
    rng = random.Random(0)
    k = random_key(10, rng)
    assert len(k) == 10
    assert all("A" <= c <= "Z" for c in k)


def test_random_key_rejects_bad_length():
    with pytest.raises(ValueError):
        random_key(0)


def test_split_strips_partitions_correctly():
    s = "ABCDEFGHIJ"
    assert split_strips(s, 3) == ["ADGJ", "BEH", "CFI"]
    assert split_strips(s, 1) == [s]


def test_shift_only_caesar():
    # 'A' shifted by 0 stays 'A'; shifted by 1 in *decrypt* direction -> 'Z'
    assert shift_only("ABC", 0) == "ABC"
    assert shift_only("ABC", 1) == "ZAB"
    assert shift_only("ABC", 3) == "XYZ"


def test_encrypt_rejects_empty_key():
    with pytest.raises(ValueError):
        encrypt("hello", "")
