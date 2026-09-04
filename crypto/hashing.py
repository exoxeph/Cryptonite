"""Password hashing helpers used by the authentication layer."""

import hashlib
import secrets


def generate_salt(length_bytes: int = 16) -> bytes:
    """Generate a fresh cryptographically random password salt."""
    if not isinstance(length_bytes, int) or length_bytes <= 0:
        raise ValueError("salt length must be a positive integer")
    return secrets.token_bytes(length_bytes)


def hash_password(password: str, salt: bytes) -> bytes:
    """Return SHA256(salt || UTF-8 password).

    Production systems normally use a password-specific KDF such as Argon2,
    bcrypt, or PBKDF2; this project follows the frozen SHA-256 course design.
    """
    _require_password(password)
    _require_salt(salt)
    return hashlib.sha256(salt + password.encode("utf-8")).digest()


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """Verify a password against its salted SHA-256 digest."""
    _require_password(password)
    _require_salt(salt)
    if not isinstance(expected_hash, bytes):
        raise TypeError("expected_hash must be bytes")
    if len(expected_hash) != hashlib.sha256().digest_size:
        return False
    return hashlib.sha256(salt + password.encode("utf-8")).digest() == expected_hash


def _require_password(password: str) -> None:
    if not isinstance(password, str):
        raise TypeError("password must be a string")


def _require_salt(salt: bytes) -> None:
    if not isinstance(salt, bytes) or not salt:
        raise ValueError("salt must be non-empty bytes")
