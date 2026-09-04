"""Educational RSA with manually implemented OAEP-style SHA-256 padding.

This module is deliberately independent from Flask, SQLite, and application key
storage so it can be reused for each RSA-protected application data purpose.
"""

import hashlib
import secrets

from crypto.bigint_utils import gcd, generate_prime, mod_inverse, mod_pow


SHA256_LENGTH = hashlib.sha256().digest_size
_SEQUENCE_MAGIC = b"ABR1"
_SEQUENCE_HEADER_LENGTH = 16


def rsa_generate_keypair(bit_length: int) -> dict:
    """Generate an RSA keypair from two probable primes.

    RSA uses ``phi(n) = (p - 1)(q - 1)`` so that the private exponent ``d`` is
    the modular inverse of the public exponent ``e`` modulo ``phi(n)``.
    """
    if bit_length < 16:
        raise ValueError("RSA bit length must be at least 16")

    prime_bits = bit_length // 2
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(bit_length - prime_bits)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bit_length:
            continue
        phi = (p - 1) * (q - 1)
        e = 65537
        if gcd(e, phi) == 1:
            break

    d = mod_inverse(e, phi)
    return {"public": (e, n), "private": (d, n)}


def rsa_encrypt(m_int: int, public_key: tuple[int, int]) -> int:
    """Apply the raw RSA public operation to an integer in ``[0, n)``."""
    e, n = public_key
    if not 0 <= m_int < n:
        raise ValueError("RSA plaintext integer must satisfy 0 <= m < n")
    return mod_pow(m_int, e, n)


def rsa_decrypt(c_int: int, private_key: tuple[int, int]) -> int:
    """Apply the raw RSA private operation to an integer in ``[0, n)``."""
    d, n = private_key
    if not 0 <= c_int < n:
        raise ValueError("RSA ciphertext integer must satisfy 0 <= c < n")
    return mod_pow(c_int, d, n)


def mgf1(seed: bytes, length: int) -> bytes:
    """Mask Generation Function 1 using SHA-256 and a four-byte counter."""
    if length < 0:
        raise ValueError("MGF1 output length must be non-negative")
    if length > (2**32) * SHA256_LENGTH:
        raise ValueError("MGF1 requested output is too long")

    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def max_oaep_chunk_size(block_size: int) -> int:
    """Return OAEP payload capacity: ``k - 2*hLen - 2`` bytes."""
    capacity = block_size - (2 * SHA256_LENGTH) - 2
    if capacity < 1:
        raise ValueError("RSA modulus is too small for SHA-256 OAEP-style padding")
    return capacity


def pad_block(data: bytes, block_size: int, label: bytes = b"") -> bytes:
    """OAEP-style encode a chunk into one RSA-sized encoded message.

    MGF1 masks both the data block and a fresh random seed. This randomized
    padding makes identical plaintext chunks encrypt to different ciphertexts.
    """
    max_oaep_chunk_size(block_size)
    if len(data) > block_size - (2 * SHA256_LENGTH) - 2:
        raise ValueError("plaintext chunk exceeds OAEP-style capacity")

    label_hash = hashlib.sha256(label).digest()
    padding = b"\x00" * (block_size - len(data) - 2 * SHA256_LENGTH - 2)
    data_block = label_hash + padding + b"\x01" + data
    seed = secrets.token_bytes(SHA256_LENGTH)
    db_mask = mgf1(seed, block_size - SHA256_LENGTH - 1)
    masked_data_block = _xor_bytes(data_block, db_mask)
    seed_mask = mgf1(masked_data_block, SHA256_LENGTH)
    masked_seed = _xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_data_block


def unpad_block(encoded_message: bytes, label: bytes = b"") -> bytes:
    """Validate and reverse OAEP-style encoding, rejecting malformed padding."""
    block_size = len(encoded_message)
    max_oaep_chunk_size(block_size)
    if encoded_message[0] != 0:
        raise ValueError("invalid OAEP-style leading byte")

    masked_seed = encoded_message[1 : 1 + SHA256_LENGTH]
    masked_data_block = encoded_message[1 + SHA256_LENGTH :]
    seed_mask = mgf1(masked_data_block, SHA256_LENGTH)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, len(masked_data_block))
    data_block = _xor_bytes(masked_data_block, db_mask)

    expected_label_hash = hashlib.sha256(label).digest()
    if data_block[:SHA256_LENGTH] != expected_label_hash:
        raise ValueError("invalid OAEP-style label hash")
    separator = data_block.find(b"\x01", SHA256_LENGTH)
    if separator == -1 or any(data_block[SHA256_LENGTH:separator]):
        raise ValueError("invalid OAEP-style padding structure")
    return data_block[separator + 1 :]


def rsa_encrypt_bytes(data: bytes, public_key: tuple[int, int]) -> list[int]:
    """Encrypt arbitrary bytes as independently padded RSA blocks.

    Chunking is necessary because RSA can only encrypt values smaller than its
    modulus; OAEP further reserves bytes for hashes and randomized masking.
    """
    if not isinstance(data, bytes):
        raise TypeError("RSA byte encryption requires bytes")
    _, n = public_key
    block_size = _modulus_byte_length(n)
    chunk_size = max_oaep_chunk_size(block_size)
    chunk_count = (len(data) + chunk_size - 1) // chunk_size
    header = (
        _SEQUENCE_MAGIC
        + len(data).to_bytes(8, "big")
        + chunk_count.to_bytes(4, "big")
    )
    ciphertexts = [rsa_encrypt(int.from_bytes(pad_block(header, block_size), "big"), public_key)]
    for start in range(0, len(data), chunk_size):
        encoded = pad_block(data[start : start + chunk_size], block_size)
        ciphertexts.append(rsa_encrypt(int.from_bytes(encoded, "big"), public_key))
    return ciphertexts


def rsa_decrypt_bytes(blocks: list[int], private_key: tuple[int, int]) -> bytes:
    """Decrypt and OAEP-validate a sequence of RSA ciphertext blocks."""
    if not isinstance(blocks, list) or not all(isinstance(block, int) for block in blocks):
        raise TypeError("RSA ciphertext blocks must be a list of integers")
    if not blocks:
        raise ValueError("RSA ciphertext block sequence is missing its header")

    _, n = private_key
    block_size = _modulus_byte_length(n)
    max_oaep_chunk_size(block_size)
    header_integer = rsa_decrypt(blocks[0], private_key)
    header = unpad_block(header_integer.to_bytes(block_size, "big"))
    if len(header) != _SEQUENCE_HEADER_LENGTH or header[:4] != _SEQUENCE_MAGIC:
        raise ValueError("invalid RSA ciphertext sequence header")
    expected_length = int.from_bytes(header[4:12], "big")
    expected_chunk_count = int.from_bytes(header[12:16], "big")
    if len(blocks) - 1 != expected_chunk_count:
        raise ValueError("RSA ciphertext block sequence is truncated or malformed")

    plaintext = bytearray()
    for block in blocks[1:]:
        decoded_integer = rsa_decrypt(block, private_key)
        encoded = decoded_integer.to_bytes(block_size, "big")
        plaintext.extend(unpad_block(encoded))
    if len(plaintext) != expected_length:
        raise ValueError("RSA ciphertext block sequence has an invalid plaintext length")
    return bytes(plaintext)


def _modulus_byte_length(n: int) -> int:
    if n <= 0:
        raise ValueError("RSA modulus must be positive")
    return (n.bit_length() + 7) // 8


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("cannot XOR byte strings with different lengths")
    return bytes(a ^ b for a, b in zip(left, right))
