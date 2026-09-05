"""Course-aligned CMAC authentication using TripleDES.

TripleDES is used here because it matches the CSE447 demonstration. It is an
educational choice, not a recommendation for modern production systems.
CMAC authenticates data; it does not encrypt it.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import cmac
from utils.crypto_trace import trace_mac


CMAC_KEY_LENGTH = 24
CMAC_TAG_LENGTH = 8


def compute_cmac(key: bytes, message: bytes) -> bytes:
    """Compute an 8-byte CMAC tag for ``message`` using a 24-byte key."""
    _require_bytes(key, "key")
    _require_bytes(message, "message")
    _require_key_length(key)
    authenticator = cmac.CMAC(TripleDES(key))
    authenticator.update(message)
    result = authenticator.finalize()
    trace_mac("CMAC", message_bytes=len(message), tag_bytes=len(result), key="[PROTECTED]")
    return result


def verify_cmac(key: bytes, message: bytes, expected_tag: bytes) -> bool:
    """Return whether ``expected_tag`` authenticates ``message``."""
    _require_bytes(key, "key")
    _require_bytes(message, "message")
    _require_bytes(expected_tag, "expected_tag")
    _require_key_length(key)
    if len(expected_tag) != CMAC_TAG_LENGTH:
        trace_mac("CMAC_VERIFY", result="INVALID", key="[PROTECTED]")
        return False
    authenticator = cmac.CMAC(TripleDES(key))
    authenticator.update(message)
    try:
        authenticator.verify(expected_tag)
    except InvalidSignature:
        trace_mac("CMAC_VERIFY", result="INVALID", key="[PROTECTED]")
        return False
    trace_mac("CMAC_VERIFY", result="VALID", key="[PROTECTED]")
    return True


def _require_bytes(value: object, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _require_key_length(key: bytes) -> None:
    if len(key) != CMAC_KEY_LENGTH:
        raise ValueError("CMAC key must be 24 bytes")
