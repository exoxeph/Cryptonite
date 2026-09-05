"""Application-owned email OTP generation, storage, expiry, and verification."""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from flask import current_app

from crypto.hashing import generate_salt
from database import db
from services import email_service
from utils.crypto_trace import trace_hash


def generate_otp() -> str:
    """Generate exactly six unpredictable decimal digits, preserving leading zeroes."""
    return "".join(secrets.choice("0123456789") for _ in range(6))


def store_otp(user_id: int, otp_code: str) -> int:
    """Store only a salted SHA-256 OTP hash and return its database ID."""
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("user_id must be a positive integer")
    _validate_otp_format(otp_code)
    salt = generate_salt()
    otp_hash = hashlib.sha256(salt + otp_code.encode("ascii")).digest()
    expires_at = _utc_now() + timedelta(seconds=current_app.config["OTP_EXPIRY_SECONDS"])
    connection = db.get_db()
    with connection:
        # Only the newest unused issuance may be accepted for this login flow.
        connection.execute("UPDATE otp_codes SET used = 1 WHERE user_id = ? AND used = 0", (user_id,))
        cursor = connection.execute(
            """INSERT INTO otp_codes (user_id, otp_hash, otp_salt, expires_at, used)
               VALUES (?, ?, ?, ?, 0)""",
            (user_id, otp_hash, salt, expires_at.isoformat(),),
        )
    trace_hash("OTP", method="SHA-256", salt_bytes=len(salt), otp="[NEVER LOGGED]", result="STORED SALTED HASH")
    return cursor.lastrowid


def verify_otp(user_id: int, submitted_code: str) -> bool:
    """Verify the latest unused, unexpired OTP and atomically consume it."""
    if not isinstance(user_id, int) or user_id <= 0 or not isinstance(submitted_code, str):
        return False
    if len(submitted_code) != 6 or not submitted_code.isdigit():
        return False
    row = db.query_one(
        "SELECT id, otp_hash, otp_salt, expires_at FROM otp_codes "
        "WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1",
        (user_id,),
    )
    if row is None or _parse_utc(row["expires_at"]) <= _utc_now():
        return False
    submitted_hash = hashlib.sha256(row["otp_salt"] + submitted_code.encode("ascii")).digest()
    if not secrets.compare_digest(submitted_hash, row["otp_hash"]):
        trace_hash("OTP_VERIFY", result="NO MATCH", otp="[NEVER LOGGED]")
        return False
    connection = db.get_db()
    with connection:
        cursor = connection.execute("UPDATE otp_codes SET used = 1 WHERE id = ? AND used = 0", (row["id"],))
    result = cursor.rowcount == 1
    trace_hash("OTP_VERIFY", result="MATCH" if result else "ALREADY USED", otp="[NEVER LOGGED]")
    return result


def invalidate_latest_otp(user_id: int) -> None:
    """Invalidate the latest OTP issuance so failed delivery cannot be used."""
    row = db.query_one(
        "SELECT id FROM otp_codes WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)
    )
    if row is not None:
        invalidate_otp(row["id"])


def invalidate_otp(otp_id: int) -> None:
    """Invalidate one exact OTP issuance, used when delivery of that issuance fails."""
    if not isinstance(otp_id, int) or otp_id <= 0:
        raise ValueError("otp_id must be a positive integer")
    connection = db.get_db()
    with connection:
        connection.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_id,))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("OTP timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _validate_otp_format(otp_code: str) -> None:
    if not isinstance(otp_code, str) or len(otp_code) != 6 or not otp_code.isdigit():
        raise ValueError("OTP must be exactly six decimal digits")
