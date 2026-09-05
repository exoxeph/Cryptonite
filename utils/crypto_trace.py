"""Opt-in, redacted cryptography lifecycle tracing for faculty demonstrations."""

import os
from contextlib import contextmanager

from flask import current_app, has_app_context


def enabled() -> bool:
    if has_app_context():
        return bool(current_app.config.get("FACULTY_CRYPTO_TRACE", False))
    return os.getenv("FACULTY_CRYPTO_TRACE", "false").strip().lower() in {"1", "true", "yes", "on"}


def trace_event(category: str, event: str, **fields) -> None:
    if not enabled():
        return
    print(f"[TRACE][{category}][{event}] " + " | ".join(f"{key}={_safe(key, value)}" for key, value in fields.items()))


def trace_encrypt(purpose: str, **fields) -> None:
    trace_event("CRYPTO", "ENCRYPT", purpose=purpose, **fields)


def trace_decrypt(purpose: str, **fields) -> None:
    trace_event("CRYPTO", "DECRYPT", purpose=purpose, **fields)


def trace_hash(purpose: str, **fields) -> None:
    trace_event("AUTH", "HASH", purpose=purpose, **fields)


def trace_mac(purpose: str, **fields) -> None:
    trace_event("CRYPTO", "MAC", purpose=purpose, **fields)


def trace_key_event(event: str, **fields) -> None:
    trace_event("KEY", event, **fields)


def trace_db(event: str, **fields) -> None:
    trace_event("DB", event, **fields)


def mask_email(value: str) -> str:
    if not isinstance(value, str) or "@" not in value:
        return "[REDACTED]"
    local, domain = value.split("@", 1)
    return f"{local[:1]}***@{domain}"


def mask_phone(value: str) -> str:
    if not isinstance(value, str):
        return "[REDACTED]"
    return f"{value[:2]}*******{value[-2:]}" if len(value) > 4 else "[REDACTED]"


@contextmanager
def demo_action(action: str, **fields):
    trace_event("DEMO", "START", action=action, **fields)
    try:
        yield
    finally:
        trace_event("DEMO", "END", action=action)


def _safe(key, value):
    if any(token in key.lower() for token in ("password", "otp", "secret", "private", "session_id", "cookie", "cmac_key", "root")):
        return "[REDACTED]"
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, (list, tuple)) and len(value) > 8:
        return f"<items:{len(value)}>"
    return value
