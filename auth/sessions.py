"""Server-revocable, CMAC-protected authenticated sessions for Phase 8."""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from flask import current_app, request

from crypto.cmac_auth import compute_cmac, verify_cmac
from crypto.key_manager import get_active_key
from database import db
from utils.crypto_trace import trace_event


def create_session(user) -> str:
    """Create a random session ID, persist only its hash, and sign its cookie."""
    user_id = user["id"]
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("session user must have a positive integer ID")
    session_id = secrets.token_urlsafe(32)
    expires_at = _format_expiry(_utc_now() + timedelta(seconds=current_app.config["SESSION_LIFETIME_SECONDS"]))
    session_id_hash = hashlib.sha256(session_id.encode("ascii")).digest()
    signature = compute_cmac(_session_cmac_key(), _payload(session_id, user_id, expires_at)).hex()
    db.execute(
        "INSERT INTO sessions (session_id_hash, user_id, expires_at, active) VALUES (?, ?, ?, 1)",
        (session_id_hash, user_id, expires_at),
    )
    trace_event("SESSION", "CREATE", user_id=user_id, expiry=expires_at, session_id="[HIDDEN]", cookie="[HIDDEN]")
    return f"{session_id}.{expires_at}.{signature}"


def validate_session(cookie_value: str | None):
    """Return the authoritative user row for a valid cookie, else ``None``."""
    validated = _validated_session(cookie_value)
    return validated[0] if validated is not None else None


def get_current_user():
    """Read the configured auth cookie and return its validated database user."""
    return validate_session(request.cookies.get(current_app.config["AUTH_SESSION_COOKIE_NAME"]))


def invalidate_session(cookie_value: str | None) -> None:
    """Mark a currently valid server-side session inactive for logout revocation."""
    validated = _validated_session(cookie_value)
    if validated is None:
        return
    _, session_row = validated
    db.execute("UPDATE sessions SET active = 0 WHERE id = ?", (session_row["id"],))


def set_session_cookie(response, cookie_value: str):
    """Attach the authenticated cookie with configured browser security flags."""
    _, expires_at, _ = _parse_cookie(cookie_value)
    response.set_cookie(
        current_app.config["AUTH_SESSION_COOKIE_NAME"],
        cookie_value,
        expires=_parse_expiry(expires_at),
        httponly=current_app.config["SESSION_COOKIE_HTTPONLY"],
        samesite=current_app.config["SESSION_COOKIE_SAMESITE"],
        secure=current_app.config["SESSION_COOKIE_SECURE"],
    )
    return response


def clear_session_cookie(response):
    """Expire the browser cookie; server-side invalidation is handled separately."""
    response.delete_cookie(
        current_app.config["AUTH_SESSION_COOKIE_NAME"],
        httponly=current_app.config["SESSION_COOKIE_HTTPONLY"],
        samesite=current_app.config["SESSION_COOKIE_SAMESITE"],
        secure=current_app.config["SESSION_COOKIE_SECURE"],
    )
    return response


def _validated_session(cookie_value: str | None):
    try:
        session_id, cookie_expiry, signature = _parse_cookie(cookie_value)
        session_row = db.query_one(
            "SELECT * FROM sessions WHERE session_id_hash = ?",
            (hashlib.sha256(session_id.encode("ascii")).digest(),),
        )
        if session_row is None or session_row["active"] != 1:
            return None
        if cookie_expiry != session_row["expires_at"] or _parse_expiry(cookie_expiry) <= _utc_now():
            return None
        user = db.query_one("SELECT * FROM users WHERE id = ?", (session_row["user_id"],))
        if user is None:
            return None
        if not verify_cmac(_session_cmac_key(), _payload(session_id, user["id"], cookie_expiry), signature):
            trace_event("SESSION", "VALIDATE", result="INVALID CMAC", session_id="[HIDDEN]")
            return None
        trace_event("SESSION", "VALIDATE", user_id=user["id"], result="AUTHENTICATED", session_id="[HIDDEN]")
        return user, session_row
    except (TypeError, ValueError, UnicodeEncodeError):
        return None


def _parse_cookie(cookie_value: str | None) -> tuple[str, str, bytes]:
    if not isinstance(cookie_value, str):
        raise ValueError("invalid session cookie")
    parts = cookie_value.split(".")
    if len(parts) != 3:
        raise ValueError("invalid session cookie")
    session_id, expires_at, signature_hex = parts
    if not session_id or not expires_at or len(signature_hex) != 16:
        raise ValueError("invalid session cookie")
    if any(character not in "0123456789abcdef" for character in signature_hex):
        raise ValueError("invalid session cookie")
    _parse_expiry(expires_at)
    return session_id, expires_at, bytes.fromhex(signature_hex)


def _payload(session_id: str, user_id: int, expires_at: str) -> bytes:
    """Build canonical, delimiter-safe CMAC input for the session cookie."""
    return f"{session_id}|{user_id}|{expires_at}".encode("ascii")


def _session_cmac_key() -> bytes:
    key = get_active_key("CMAC_SESSION")["private_key"]
    if not isinstance(key, bytes) or len(key) != 24:
        raise ValueError("active CMAC_SESSION key is invalid")
    return key


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_expiry(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_expiry(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
