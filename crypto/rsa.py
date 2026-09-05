"""Educational textbook RSA implemented from scratch for CSE447.

This module intentionally uses approximately 128-bit primes and textbook RSA
without modern padding so the mathematical process taught in the course can
be demonstrated directly. It is deterministic, malleable, and not suitable
for production cryptography.
"""

from crypto.bigint_utils import gcd, generate_prime

RSA_PRIME_BITS = 128
RSA_PUBLIC_EXPONENT = 11
TEXTBOOK_FORMAT = "TBR1"


def rsa_generate_keypair(prime_bits: int = RSA_PRIME_BITS, public_exponent: int = RSA_PUBLIC_EXPONENT) -> dict:
    """Generate RSA keys from two distinct primes of the requested size."""
    if not isinstance(prime_bits, int) or prime_bits < 16:
        raise ValueError("RSA prime size must be at least 16 bits")
    if not isinstance(public_exponent, int) or public_exponent <= 1:
        raise ValueError("RSA public exponent must be greater than 1")
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(public_exponent, phi) == 1:
            break
    d = pow(public_exponent, -1, phi)
    return {"public": (public_exponent, n), "private": (d, n)}


def rsa_encrypt(message: int, public_key: tuple[int, int]) -> int:
    """Compute C = M^e mod n for one textbook RSA message integer."""
    exponent, modulus = _validate_key(public_key)
    if type(message) is not int or not 0 <= message < modulus:
        raise ValueError("RSA plaintext integer must satisfy 0 <= M < n")
    return pow(message, exponent, modulus)


def rsa_decrypt(ciphertext: int, private_key: tuple[int, int]) -> int:
    """Compute M = C^d mod n for one textbook RSA ciphertext integer."""
    exponent, modulus = _validate_key(private_key)
    if type(ciphertext) is not int or not 0 <= ciphertext < modulus:
        raise ValueError("RSA ciphertext integer must satisfy 0 <= C < n")
    return pow(ciphertext, exponent, modulus)


def rsa_encrypt_int(message: int, public_key: tuple[int, int]) -> int:
    return rsa_encrypt(message, public_key)


def rsa_decrypt_int(ciphertext: int, private_key: tuple[int, int]) -> int:
    return rsa_decrypt(ciphertext, private_key)


def rsa_encrypt_bytes(data: bytes, public_key: tuple[int, int]) -> dict:
    """Encrypt bytes in safe textbook-RSA chunks with reconstruction metadata."""
    if not isinstance(data, bytes):
        raise TypeError("RSA byte encryption requires bytes")
    _, modulus = _validate_key(public_key)
    chunk_size = _chunk_size(modulus)
    blocks = [
        rsa_encrypt(int.from_bytes(data[start : start + chunk_size], "big"), public_key)
        for start in range(0, len(data), chunk_size)
    ]
    return {
        "format": TEXTBOOK_FORMAT,
        "length": len(data),
        "chunk_size": chunk_size,
        "block_count": len(blocks),
        "blocks": blocks,
    }


def rsa_decrypt_bytes(container, private_key: tuple[int, int]) -> bytes:
    """Validate and decrypt a textbook-RSA byte container exactly."""
    if not isinstance(container, dict):
        raise ValueError("RSA ciphertext container must be an object")
    _, modulus = _validate_key(private_key)
    if container.get("format") != TEXTBOOK_FORMAT:
        raise ValueError("invalid RSA ciphertext format")
    length = container.get("length")
    chunk_size = container.get("chunk_size")
    block_count = container.get("block_count")
    blocks = container.get("blocks")
    expected_chunk_size = _chunk_size(modulus)
    if (
        type(length) is not int or length < 0
        or type(chunk_size) is not int or chunk_size != expected_chunk_size
        or type(block_count) is not int or block_count < 0
        or not isinstance(blocks, list) or len(blocks) != block_count
    ):
        raise ValueError("malformed RSA ciphertext container")
    if block_count != (length + chunk_size - 1) // chunk_size:
        raise ValueError("RSA ciphertext block count does not match length")
    plaintext = bytearray()
    for index, block in enumerate(blocks):
        if type(block) is not int or not 0 <= block < modulus:
            raise ValueError("RSA ciphertext block is outside modulus")
        expected_length = min(chunk_size, length - index * chunk_size)
        message = rsa_decrypt(block, private_key)
        try:
            plaintext.extend(message.to_bytes(expected_length, "big"))
        except OverflowError as exc:
            raise ValueError("RSA plaintext block is too large") from exc
    if len(plaintext) != length:
        raise ValueError("RSA ciphertext length mismatch")
    return bytes(plaintext)


def _chunk_size(modulus: int) -> int:
    if not isinstance(modulus, int) or modulus <= 1:
        raise ValueError("RSA modulus must be positive")
    size = (modulus.bit_length() - 1) // 8
    if size < 1:
        raise ValueError("RSA modulus is too small for byte chunking")
    return size


def _validate_key(key: tuple[int, int]) -> tuple[int, int]:
    if (
        not isinstance(key, tuple)
        or len(key) != 2
        or type(key[0]) is not int
        or type(key[1]) is not int
        or key[0] <= 1
        or key[1] <= 1
    ):
        raise ValueError("invalid RSA key")
    return key
