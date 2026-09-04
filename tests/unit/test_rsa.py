import pytest

from crypto.bigint_utils import gcd, generate_prime, is_probable_prime, mod_inverse, mod_pow
from crypto.rsa import (
    SHA256_LENGTH,
    max_oaep_chunk_size,
    rsa_decrypt,
    rsa_decrypt_bytes,
    rsa_encrypt,
    rsa_encrypt_bytes,
    rsa_generate_keypair,
)


@pytest.fixture(scope="module")
def keypair():
    # 1024 bits retains a 62-byte SHA-256 OAEP capacity while keeping tests fast.
    return rsa_generate_keypair(1024)


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
    assert is_probable_prime(number)


@pytest.mark.parametrize("number", [0, 1, 4, 9, 221, 341, 32416190070])
def test_miller_rabin_obvious_composites(number):
    assert not is_probable_prime(number)


def test_generated_prime_is_probable_prime():
    prime = generate_prime(128)
    assert prime.bit_length() == 128
    assert is_probable_prime(prime)


def test_keypair_validity_and_requested_size(keypair):
    e, n = keypair["public"]
    d, private_n = keypair["private"]
    assert n == private_n
    assert n.bit_length() == 1024
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


def test_raw_ciphertext_differs_from_plaintext(keypair):
    ciphertext = rsa_encrypt(42, keypair["public"])
    assert ciphertext != 42


def test_oaep_capacity_for_test_key(keypair):
    block_size = (keypair["public"][1].bit_length() + 7) // 8
    assert block_size == 128
    assert max_oaep_chunk_size(block_size) == 128 - 2 * SHA256_LENGTH - 2 == 62


@pytest.mark.parametrize("data", [b"", b"A", b"ordinary text", b"\x00\xff\x00binary\x80"])
def test_byte_roundtrip_common_values(data, keypair):
    assert rsa_decrypt_bytes(rsa_encrypt_bytes(data, keypair["public"]), keypair["private"]) == data


def test_byte_roundtrip_at_and_above_oaep_capacity(keypair):
    block_size = (keypair["public"][1].bit_length() + 7) // 8
    capacity = max_oaep_chunk_size(block_size)
    exact = bytes(range(capacity))
    above = exact + b"!"
    # The first block is an OAEP-encrypted length/count header, followed by data.
    assert len(rsa_encrypt_bytes(exact, keypair["public"])) == 2
    assert len(rsa_encrypt_bytes(above, keypair["public"])) == 3
    assert rsa_decrypt_bytes(rsa_encrypt_bytes(exact, keypair["public"]), keypair["private"]) == exact
    assert rsa_decrypt_bytes(rsa_encrypt_bytes(above, keypair["public"]), keypair["private"]) == above


def test_multi_block_and_randomized_ciphertext(keypair):
    data = b"CSE447 RSA OAEP " * 20
    first = rsa_encrypt_bytes(data, keypair["public"])
    second = rsa_encrypt_bytes(data, keypair["public"])
    assert len(first) > 1
    assert first != second
    assert rsa_decrypt_bytes(first, keypair["private"]) == data


def test_wrong_key_corruption_and_truncation_do_not_recover_original(keypair):
    other_keypair = rsa_generate_keypair(1024)
    data = b"A multi-block message requires every ciphertext block." * 3
    blocks = rsa_encrypt_bytes(data, keypair["public"])

    with pytest.raises(ValueError):
        rsa_decrypt_bytes(blocks, other_keypair["private"])
    with pytest.raises(ValueError):
        rsa_decrypt_bytes([blocks[0] + 1, *blocks[1:]], keypair["private"])

    with pytest.raises(ValueError, match="truncated"):
        rsa_decrypt_bytes(blocks[:-1], keypair["private"])


def test_too_small_key_is_rejected_for_sha256_oaep():
    with pytest.raises(ValueError, match="too small"):
        max_oaep_chunk_size(64)
