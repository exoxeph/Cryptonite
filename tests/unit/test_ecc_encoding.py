import json

import pytest

from crypto import ecc_encoding
from crypto.ecc import ecc_generate_keypair
from crypto.ecc_curve import G, scalar_multiply


@pytest.fixture
def ecc_keys():
    return ecc_generate_keypair()


def test_all_byte_values_have_distinct_reversible_points():
    points = [ecc_encoding.byte_to_point(value) for value in range(256)]
    assert len(set(points)) == 256
    assert [ecc_encoding.point_to_byte(point) for point in points] == list(range(256))
    assert ecc_encoding.byte_to_point(0) == scalar_multiply(1, G)
    assert ecc_encoding.byte_to_point(255) == scalar_multiply(256, G)


@pytest.mark.parametrize("value", [-1, 256, True])
def test_invalid_byte_rejected(value):
    with pytest.raises(ValueError):
        ecc_encoding.byte_to_point(value)


def test_unmapped_point_rejected():
    with pytest.raises(ValueError):
        ecc_encoding.point_to_byte(None)


def test_ecc_byte_round_trip_for_binary_and_text(ecc_keys):
    plaintext = b"Authority Bridged\x00\xff" + bytes(range(256)) + "\u4f60\u597d".encode("utf-8")
    ciphertext = ecc_encoding.ecc_encrypt_bytes(plaintext, ecc_keys["public"])
    assert ecc_encoding.ecc_decrypt_bytes(ciphertext, ecc_keys["private"]) == plaintext


def test_empty_ecc_byte_round_trip(ecc_keys):
    assert ecc_encoding.ecc_encrypt_bytes(b"", ecc_keys["public"]) == []
    assert ecc_encoding.ecc_decrypt_bytes([], ecc_keys["private"]) == b""


def test_same_plaintext_normally_encrypts_differently(ecc_keys):
    first = ecc_encoding.ecc_encrypt_bytes(b"same", ecc_keys["public"])
    second = ecc_encoding.ecc_encrypt_bytes(b"same", ecc_keys["public"])
    assert first != second


def test_ecc_ciphertext_serialization_round_trip(ecc_keys):
    ciphertext = ecc_encoding.ecc_encrypt_bytes(b"hello", ecc_keys["public"])
    serialized = ecc_encoding.serialize_ecc_ciphertext(ciphertext)
    assert json.loads(serialized)
    assert ecc_encoding.deserialize_ecc_ciphertext(serialized) == ciphertext


@pytest.mark.parametrize(
    "serialized",
    [
        "not-json",
        "{}",
        "[[1, 2, 3]]",
        "[[1, 2, 3, 4, 5]]",
        "[[true, 2, 3, 4]]",
        "[[0, 0, 1, 1]]",
    ],
)
def test_malformed_ecc_ciphertext_rejected(serialized):
    with pytest.raises((TypeError, ValueError)):
        ecc_encoding.deserialize_ecc_ciphertext(serialized)


def test_infinity_c2_retries_with_fresh_encryption(ecc_keys, monkeypatch):
    original = ecc_encoding.ecc_encrypt_point
    calls = 0

    def force_one_infinity(m_point, public_key):
        nonlocal calls
        calls += 1
        if calls == 1:
            return G, None
        return original(m_point, public_key)

    monkeypatch.setattr(ecc_encoding, "ecc_encrypt_point", force_one_infinity)
    ciphertext = ecc_encoding.ecc_encrypt_bytes(b"x", ecc_keys["public"])
    assert calls == 2
    assert ecc_encoding.ecc_decrypt_bytes(ciphertext, ecc_keys["private"]) == b"x"


def test_infinity_c2_retry_limit_is_bounded(ecc_keys, monkeypatch):
    calls = 0

    def always_infinity(_m_point, _public_key):
        nonlocal calls
        calls += 1
        return G, None

    monkeypatch.setattr(ecc_encoding, "ecc_encrypt_point", always_infinity)
    with pytest.raises(ValueError, match="repeated retries"):
        ecc_encoding.ecc_encrypt_bytes(b"x", ecc_keys["public"])
    assert calls == ecc_encoding.MAX_ECC_ENCRYPT_RETRIES
