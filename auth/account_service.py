"""Reusable account creation and RSA profile-field preparation."""

import hashlib
import json
import sqlite3

from crypto.hashing import generate_salt, hash_password
from crypto.key_manager import get_active_key
from crypto.rsa import rsa_decrypt_bytes, rsa_encrypt_bytes
from database import db


def normalize_email(email: str) -> str:
    """Normalize an email using the project's trim-and-lowercase rule."""
    if not isinstance(email, str):
        raise TypeError("email must be a string")
    normalized = email.strip().lower()
    if not normalized:
        raise ValueError("email is required")
    return normalized


def email_lookup_hash(normalized_email: str) -> bytes:
    """Return deterministic SHA-256 lookup bytes for a normalized email."""
    if not isinstance(normalized_email, str) or not normalized_email:
        raise ValueError("normalized email is required")
    return hashlib.sha256(normalized_email.encode("utf-8")).digest()


def find_user_by_email(normalized_email: str):
    """Find an account by its deterministic lookup hash without decrypting rows."""
    return db.query_one(
        "SELECT * FROM users WHERE email_lookup_hash = ?",
        (email_lookup_hash(normalized_email),),
    )


def serialize_rsa_ciphertext(blocks: list[int]) -> bytes:
    """Serialize RSA ciphertext blocks as compact JSON for SQLite BLOB storage."""
    if not isinstance(blocks, list) or not all(isinstance(block, int) and block >= 0 for block in blocks):
        raise ValueError("RSA ciphertext must be a list of non-negative integers")
    return json.dumps(blocks, separators=(",", ":")).encode("utf-8")


def encrypt_profile_field(value: str, public_key) -> bytes:
    """Encrypt one profile value with RSA_PROFILE and return reusable JSON bytes."""
    if not isinstance(value, str):
        raise TypeError("profile value must be a string")
    return serialize_rsa_ciphertext(rsa_encrypt_bytes(value.encode("utf-8"), public_key))


def deserialize_rsa_ciphertext(serialized: bytes) -> list[int]:
    """Decode the shared compact JSON RSA ciphertext representation."""
    if not isinstance(serialized, bytes):
        raise TypeError("serialized RSA ciphertext must be bytes")
    try:
        blocks = json.loads(serialized.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed RSA ciphertext") from exc
    if not isinstance(blocks, list) or not blocks or not all(isinstance(block, int) and block >= 0 for block in blocks):
        raise ValueError("malformed RSA ciphertext")
    return blocks


def decrypt_profile_field(serialized: bytes, private_key) -> str:
    """Decrypt one profile field using the same serialization as registration."""
    plaintext = rsa_decrypt_bytes(deserialize_rsa_ciphertext(serialized), private_key)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("profile field is not valid UTF-8") from exc


def create_user(name: str, email: str, contact: str, password: str, role: str = "student") -> int:
    """Create an account with encrypted profile fields and a salted password hash."""
    if role not in {"student", "admin"}:
        raise ValueError("invalid account role")
    for value, field in ((name, "name"), (contact, "contact"), (password, "password")):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} is required")
    normalized_email = normalize_email(email)
    profile_key = get_active_key("RSA_PROFILE")
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    values = (
        encrypt_profile_field(name.strip(), profile_key["public_key"]),
        encrypt_profile_field(normalized_email, profile_key["public_key"]),
        encrypt_profile_field(contact.strip(), profile_key["public_key"]),
        email_lookup_hash(normalized_email),
        password_hash,
        salt,
        role,
        profile_key["version"],
    )
    try:
        return db.execute(
            """INSERT INTO users
               (encrypted_name, encrypted_email, encrypted_contact, email_lookup_hash,
                password_hash, password_salt, role, profile_key_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        ).lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError("email address is already registered") from exc
