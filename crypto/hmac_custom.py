"""Hand-built HMAC-SHA256 for message integrity and authentication.

HMAC provides integrity/authentication, not confidentiality. For normalized
key K' and message m, this module computes:
H((K' XOR opad) || H((K' XOR ipad) || m)).
"""

import hashlib
import hmac


HASH_BLOCK_SIZE = 64
MAC_LENGTH = hashlib.sha256().digest_size


def _normalize_key(key: bytes, block_size: int = HASH_BLOCK_SIZE) -> bytes:
    """Hash long keys, then zero-pad every key to SHA-256's block size."""
    _require_bytes(key, "key")
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    return key + b"\x00" * (block_size - len(key))


def generate_mac(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256 with explicit ipad and opad construction."""
    _require_bytes(key, "key")
    _require_bytes(message, "message")
    normalized_key = _normalize_key(key)
    inner_key = bytes(byte ^ 0x36 for byte in normalized_key)
    outer_key = bytes(byte ^ 0x5C for byte in normalized_key)
    inner = hashlib.sha256(inner_key + message).digest()
    return hashlib.sha256(outer_key + inner).digest()


def verify_mac(key: bytes, message: bytes, received_mac: bytes) -> bool:
    """Verify a MAC with constant-time comparison and strict input validation."""
    _require_bytes(key, "key")
    _require_bytes(message, "message")
    _require_bytes(received_mac, "received_mac")
    if len(received_mac) != MAC_LENGTH:
        return False
    return hmac.compare_digest(generate_mac(key, message), received_mac)


def _require_bytes(value: object, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
