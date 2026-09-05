import json

import pytest

from crypto.bigint_utils import gcd, generate_prime, mod_inverse, mod_pow
from crypto.rsa import (
    RSA_PUBLIC_EXPONENT,
    TEXTBOOK_FORMAT,
    rsa_decrypt,
    rsa_decrypt_bytes,
    rsa_encrypt,
    rsa_encrypt_bytes,
    rsa_generate_keypair,
)


@pytest.fixture(scope="module")
def keypair():
    return rsa_generate_keypair(128)


def test_mod_pow_known_cases():
    assert mod_pow(2, 10, 1000) == 24
    assert mod_pow(7, 0, 13) == 1
    assert mod_pow(123456, 789, 97) == pow(123456, 789, 97)


@pytest.mark.parametrize(("a", "b", "expected"), [(0, 5, 5), (54, 24, 6), (-12, 18, 6)])
def test_gcd(a, b, expected):
    assert gcd(a, b) == expected


def test_mod_inverse_and_missing_inverse():
    assert (17 * mod_inverse(17, 3120)) % 3120 == 1
    with pytest.raises(ValueError, match="does not exist"):
        mod_inverse(6, 15)


@pytest.mark.parametrize("number", [2, 3, 7919, 32416190071])
def test_miller_rabin_obvious_primes(number):
    from crypto.bigint_utils import is_probable_prime
    assert is_probable_prime(number)


@pytest.mark.parametrize("number", [0, 1, 4, 9, 221, 341, 32416190070])
def test_miller_rabin_obvious_composites(number):
    from crypto.bigint_utils import is_probable_prime
    assert not is_probable_prime(number)


def test_generated_prime_is_probable_prime():
    prime = generate_prime(128)
    assert prime.bit_length() == 128


def test_keypair_uses_course_exponent_and_round_trips(keypair):
    e, n = keypair["public"]
    d, private_n = keypair["private"]
    assert e == RSA_PUBLIC_EXPONENT == 11
    assert n == private_n
    assert 250 <= n.bit_length() <= 256
    assert rsa_decrypt(rsa_encrypt(42, (e, n)), (d, n)) == 42


def test_raw_integer_boundaries(keypair):
    public_key = keypair["public"]
    private_key = keypair["private"]
    n = public_key[1]
    assert rsa_decrypt(rsa_encrypt(0, public_key), private_key) == 0
    assert rsa_decrypt(rsa_encrypt(n - 1, public_key), private_key) == n - 1
    with pytest.raises(ValueError, match="plaintext"):
        rsa_encrypt(n, public_key)
    with pytest.raises(ValueError, match="ciphertext"):
        rsa_decrypt(n, private_key)


def test_textbook_math_is_explicit():
    p, q, e = 61, 53, 17
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    message = 65
    ciphertext = rsa_encrypt(message, (e, n))
    assert gcd(e, phi) == 1
    assert (e * d) % phi == 1
    assert ciphertext == mod_pow(message, e, n)
    assert rsa_decrypt(ciphertext, (d, n)) == mod_pow(ciphertext, d, n) == message


@pytest.mark.parametrize("data", [b"", b"A", b"Secret", b"\x00", b"\x00ABC", b"ABC\x00", bytes(range(256))])
def test_byte_roundtrip_exact(data, keypair):
    assert rsa_decrypt_bytes(rsa_encrypt_bytes(data, keypair["public"]), keypair["private"]) == data


def test_container_preserves_boundaries_and_leading_zeroes(keypair):
    chunk_size = (keypair["public"][1].bit_length() - 1) // 8
    data = b"\x00\x00ABC" + bytes(range(256)) + b"\x00" * chunk_size
    container = rsa_encrypt_bytes(data, keypair["public"])
    assert container["format"] == TEXTBOOK_FORMAT
    assert container["chunk_size"] == chunk_size
    assert container["block_count"] == (len(data) + chunk_size - 1) // chunk_size
    assert rsa_decrypt_bytes(container, keypair["private"]) == data


def test_textbook_rsa_is_deterministic(keypair):
    data = b"same plaintext"
    assert rsa_encrypt_bytes(data, keypair["public"]) == rsa_encrypt_bytes(data, keypair["public"])


@pytest.mark.parametrize("bad", [
    {},
    {"format": "OAEP", "length": 1, "chunk_size": 1, "block_count": 1, "blocks": [1]},
    {"format": TEXTBOOK_FORMAT, "length": -1, "chunk_size": 31, "block_count": 0, "blocks": []},
    {"format": TEXTBOOK_FORMAT, "length": 1, "chunk_size": 30, "block_count": 1, "blocks": [1]},
    {"format": TEXTBOOK_FORMAT, "length": 1, "chunk_size": 31, "block_count": 2, "blocks": [1]},
])
def test_malformed_containers_rejected(bad, keypair):
    with pytest.raises(ValueError):
        rsa_decrypt_bytes(bad, keypair["private"])


def test_out_of_range_block_rejected(keypair):
    container = rsa_encrypt_bytes(b"x", keypair["public"])
    container["blocks"][0] = keypair["public"][1]
    with pytest.raises(ValueError):
        rsa_decrypt_bytes(container, keypair["private"])


def test_container_is_json_serializable(keypair):
    assert json.loads(json.dumps(rsa_encrypt_bytes(b"json", keypair["public"])))
