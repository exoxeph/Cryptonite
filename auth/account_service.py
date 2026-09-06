"""Reusable account creation and RSA profile-field preparation."""

import hashlib
import json
import sqlite3
import re

from crypto.hashing import generate_salt, hash_password
from crypto.key_manager import get_active_key, get_key_by_version
from database.db import get_db
from crypto.rsa import rsa_decrypt_bytes, rsa_encrypt_bytes
from database import db
from utils.crypto_trace import mask_email, mask_phone, trace_decrypt, trace_encrypt


def normalize_email(email: str) -> str:
    """Normalize an email using the project's trim-and-lowercase rule."""
    if not isinstance(email, str):
        raise TypeError("email must be a string")
    normalized = email.strip().lower()
    if not normalized:
        raise ValueError("email is required")
    return normalized


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip() or any(character.isdigit() for character in name):
        raise ValueError("name must contain no numbers")
    return name.strip()


def validate_password(password: str) -> str:
    if (
        not isinstance(password, str)
        or len(password) < 8
        or not re.search(r"[A-Z]", password)
        or not re.search(r"[a-z]", password)
        or not re.search(r"\d", password)
    ):
        raise ValueError("password must be at least 8 characters with upper, lower, and numeric characters")
    return password


def validate_bracu_id(bracu_id: str) -> str:
    if not isinstance(bracu_id, str) or not re.fullmatch(r"\d{8}", bracu_id.strip()):
        raise ValueError("BRACU ID must contain exactly 8 digits")
    return bracu_id.strip()


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


def get_user_by_id(user_id: int):
    """Load the authoritative user row used after successful OTP verification."""
    return db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def serialize_rsa_ciphertext(container: dict) -> bytes:
    """Serialize a textbook-RSA byte container as compact JSON."""
    if not isinstance(container, dict) or container.get("format") != "TBR1":
        raise ValueError("invalid RSA ciphertext container")
    return json.dumps(container, separators=(",", ":")).encode("utf-8")


def encrypt_profile_field(value: str, public_key) -> bytes:
    """Encrypt one profile value with RSA_PROFILE and return reusable JSON bytes."""
    if not isinstance(value, str):
        raise TypeError("profile value must be a string")
    result = serialize_rsa_ciphertext(rsa_encrypt_bytes(value.encode("utf-8"), public_key))
    trace_encrypt("RSA_PROFILE", field="profile value", plaintext=mask_email(value) if "@" in value else mask_phone(value), storage="users encrypted column", result="BEFORE DATABASE INSERT")
    return result


def deserialize_rsa_ciphertext(serialized: bytes) -> dict:
    """Decode the shared compact JSON RSA ciphertext representation."""
    if not isinstance(serialized, bytes):
        raise TypeError("serialized RSA ciphertext must be bytes")
    try:
        container = json.loads(serialized.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed RSA ciphertext") from exc
    if not isinstance(container, dict) or container.get("format") != "TBR1":
        raise ValueError("malformed RSA ciphertext")
    return container


def decrypt_profile_field(serialized: bytes, private_key) -> str:
    """Decrypt one profile field using the same serialization as registration."""
    plaintext = rsa_decrypt_bytes(deserialize_rsa_ciphertext(serialized), private_key)
    try:
        result = plaintext.decode("utf-8")
        trace_decrypt("RSA_PROFILE", plaintext="[AUTHORIZED VALUE]", result="AUTHORIZED DISPLAY")
        return result
    except UnicodeDecodeError as exc:
        raise ValueError("profile field is not valid UTF-8") from exc


def get_profile(user_id: int) -> dict:
    """Decrypt one user's profile using the key version recorded on that row."""
    row = get_user_by_id(user_id)
    if row is None:
        raise ValueError("user does not exist")
    profile_key = get_key_by_version("RSA_PROFILE", row["profile_key_version"])
    return {
        "role": row["role"],
        "name": decrypt_profile_field(row["encrypted_name"], profile_key["private_key"]),
        "email": decrypt_profile_field(row["encrypted_email"], profile_key["private_key"]),
        "contact": decrypt_profile_field(row["encrypted_contact"], profile_key["private_key"]),
        "bracu_id": (
            decrypt_profile_field(row["encrypted_bracu_id"], profile_key["private_key"])
            if row["encrypted_bracu_id"] is not None else ""
        ),
    }


def update_profile(user_id: int, name: str, email: str, contact: str, bracu_id: str | None = None) -> None:
    """Encrypt and atomically replace all profile fields under one active key."""
    row = get_user_by_id(user_id)
    if row is None:
        raise ValueError("user does not exist")
    for value, field in ((name, "name"), (contact, "contact")):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} is required")
    if row["role"] == "student" and bracu_id:
        bracu_id = validate_bracu_id(bracu_id)
    elif row["role"] != "student":
        bracu_id = None
    normalized_email = normalize_email(email)
    profile_key = get_active_key("RSA_PROFILE")
    encrypted_values = (
        encrypt_profile_field(name.strip(), profile_key["public_key"]),
        encrypt_profile_field(normalized_email, profile_key["public_key"]),
        encrypt_profile_field(contact.strip(), profile_key["public_key"]),
        encrypt_profile_field(bracu_id, profile_key["public_key"]) if bracu_id else row["encrypted_bracu_id"],
        email_lookup_hash(normalized_email),
        profile_key["version"],
        user_id,
    )
    try:
        connection = get_db()
        with connection:
            cursor = connection.execute(
                """UPDATE users
                   SET encrypted_name = ?, encrypted_email = ?, encrypted_contact = ?,
                       encrypted_bracu_id = ?, email_lookup_hash = ?, profile_key_version = ?
                   WHERE id = ?""",
                (encrypted_values[0], encrypted_values[1], encrypted_values[2], encrypted_values[3], encrypted_values[4], encrypted_values[5], encrypted_values[6]),
            )
            if cursor.rowcount != 1:
                raise ValueError("user does not exist")
    except sqlite3.IntegrityError as exc:
        raise ValueError("email address is already registered") from exc


def create_user(name: str, email: str, contact: str, password: str, role: str = "student", bracu_id: str | None = None) -> int:
    """Create an account with encrypted profile fields and a salted password hash."""
    if role not in {"student", "admin"}:
        raise ValueError("invalid account role")
    for value, field in ((name, "name"), (contact, "contact"), (password, "password")):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} is required")
    normalized_email = normalize_email(email)
    if role == "student" and bracu_id:
        bracu_id = validate_bracu_id(bracu_id)
    profile_key = get_active_key("RSA_PROFILE")
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    values = (
        encrypt_profile_field(name.strip(), profile_key["public_key"]),
        encrypt_profile_field(normalized_email, profile_key["public_key"]),
        encrypt_profile_field(contact.strip(), profile_key["public_key"]),
        encrypt_profile_field(bracu_id, profile_key["public_key"]) if bracu_id else None,
        email_lookup_hash(normalized_email),
        password_hash,
        salt,
        role,
        profile_key["version"],
    )
    try:
        return db.execute(
            """INSERT INTO users
               (encrypted_name, encrypted_email, encrypted_contact, encrypted_bracu_id, email_lookup_hash,
                password_hash, password_salt, role, profile_key_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        ).lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError("email address is already registered") from exc
