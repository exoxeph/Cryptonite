"""Versioned operational-key storage protected by the configured root RSA key.

This is the only module that bridges the crypto modules and SQLite. Operational
private material is serialized explicitly, wrapped with the root RSA public key,
and stored as ciphertext. The root private key remains outside SQLite in the
decimal ``ROOT_RSA_N/E/D`` configuration values; production systems would use a
secret manager, KMS, or HSM instead of this educational local arrangement.

Unlike the otherwise pure ``crypto/*`` modules, this infrastructure module is
the intentional configuration/database exception described by the plan: it
uses Flask's application configuration and the generic database connection to
coordinate key storage, but contains no route or UI logic.
"""

import base64
import json
import secrets

from flask import current_app

from crypto.ecc import ecc_generate_keypair
from crypto.ecc_curve import is_on_curve
from crypto.rsa import rsa_decrypt_bytes, rsa_encrypt_bytes, rsa_generate_keypair
from database.db import get_db


PURPOSE_ALGORITHMS = {
    "RSA_PROFILE": "RSA",
    "RSA_EVIDENCE": "RSA",
    "ECC_POSTS": "ECC",
    "ECC_CHAT": "ECC",
    "HMAC_CHAT": "HMAC",
    "HMAC_SESSION": "HMAC",
}
VALID_STATUSES = {"ACTIVE", "RETIRED", "REVOKED"}


def generate_key(purpose: str, algorithm: str | None = None) -> dict:
    """Generate, wrap, and atomically activate the next key version for purpose."""
    expected_algorithm = _validate_purpose_and_algorithm(purpose, algorithm)
    public_key, private_material = _generate_material(expected_algorithm)
    wrapped_private = _wrap_private_key(_serialize_private(expected_algorithm, private_material))

    connection = get_db()
    with connection:
        row = connection.execute(
            "SELECT COALESCE(MAX(version), 0) AS max_version FROM keys WHERE purpose = ?",
            (purpose,),
        ).fetchone()
        version = row["max_version"] + 1
        connection.execute(
            "UPDATE keys SET status = 'RETIRED', retired_at = CURRENT_TIMESTAMP "
            "WHERE purpose = ? AND status = 'ACTIVE'",
            (purpose,),
        )
        connection.execute(
            """INSERT INTO keys
               (algorithm, purpose, version, public_key, encrypted_private_key, status)
               VALUES (?, ?, ?, ?, ?, 'ACTIVE')""",
            (
                expected_algorithm,
                purpose,
                version,
                _serialize_public(expected_algorithm, public_key),
                wrapped_private,
            ),
        )
    return _key_record(version, expected_algorithm, public_key, private_material)


def get_active_key(purpose: str) -> dict:
    """Return the active key with actual Python public/private key types."""
    _validate_purpose_and_algorithm(purpose)
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM keys WHERE purpose = ? AND status = 'ACTIVE'", (purpose,)
    ).fetchone()
    if row is None:
        raise KeyError(f"no active key exists for purpose {purpose}")
    return _decode_row(row)


def get_key_by_version(purpose: str, version: int) -> dict:
    """Return an ACTIVE or RETIRED historical key; REVOKED keys are unavailable."""
    _validate_purpose_and_algorithm(purpose)
    if not isinstance(version, int) or version <= 0:
        raise ValueError("key version must be a positive integer")
    row = get_db().execute(
        "SELECT * FROM keys WHERE purpose = ? AND version = ?", (purpose, version)
    ).fetchone()
    if row is None:
        raise KeyError(f"key version {version} does not exist for purpose {purpose}")
    if row["status"] == "REVOKED":
        raise ValueError(f"key version {version} is revoked")
    return _decode_row(row)


def rotate_key(purpose: str) -> dict:
    """Generate the next purpose version; old ciphertext is left untouched."""
    return generate_key(purpose)


def retire_key(purpose: str, version: int) -> None:
    """Retire a key while retaining it for historical decryption."""
    _change_lifecycle(purpose, version, "RETIRED", require_replacement=True)


def revoke_key(purpose: str, version: int) -> None:
    """Revoke a non-active key so it can no longer be returned for decryption."""
    _change_lifecycle(purpose, version, "REVOKED", require_replacement=True)


def bootstrap_keys() -> None:
    """Ensure exactly one active version exists for each of the six purposes."""
    for purpose in PURPOSE_ALGORITHMS:
        try:
            get_active_key(purpose)
        except KeyError:
            generate_key(purpose)


def _wrap_private_key(private_key_material: bytes) -> bytes:
    """Wrap serialized private material with the configured root RSA public key."""
    if not isinstance(private_key_material, bytes):
        raise TypeError("private key material must be bytes")
    ciphertext = rsa_encrypt_bytes(private_key_material, _root_public_key())
    return json.dumps(ciphertext, separators=(",", ":")).encode("utf-8")


def _unwrap_private_key(wrapped: bytes) -> bytes:
    """Deserialize and decrypt wrapped private material, rejecting malformed data."""
    if not isinstance(wrapped, bytes):
        raise TypeError("wrapped private key must be bytes")
    try:
        blocks = json.loads(wrapped.decode("utf-8"))
        if not isinstance(blocks, list) or not blocks or not all(
            isinstance(block, int) and block >= 0 for block in blocks
        ):
            raise ValueError("wrapped private key must contain ciphertext integers")
        return rsa_decrypt_bytes(blocks, _root_private_key())
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("malformed wrapped private key") from exc


def _root_public_key() -> tuple[int, int]:
    """Load and validate the root public key without logging or persisting it."""
    n = _root_integer("ROOT_RSA_N")
    e = _root_integer("ROOT_RSA_E")
    _validate_root_modulus(n)
    if e <= 1:
        raise ValueError("ROOT_RSA_E must be greater than 1")
    return e, n


def _root_private_key() -> tuple[int, int]:
    """Load the root private exponent from configuration only."""
    n = _root_integer("ROOT_RSA_N")
    d = _root_integer("ROOT_RSA_D")
    _validate_root_modulus(n)
    if d <= 0:
        raise ValueError("ROOT_RSA_D must be positive")
    return d, n


def _root_integer(name: str) -> int:
    value = current_app.config.get(name, "")
    try:
        if not isinstance(value, (str, int)) or str(value).strip() == "":
            raise ValueError
        return int(str(value), 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a decimal integer configured in the environment") from exc


def _validate_root_modulus(modulus: int) -> None:
    if modulus <= 0:
        raise ValueError("ROOT_RSA_N must be positive")
    if (modulus.bit_length() + 7) // 8 <= 2 * 32 + 2:
        raise ValueError("ROOT_RSA_N is too small for SHA-256 OAEP-style wrapping")


def _validate_purpose_and_algorithm(purpose: str, algorithm: str | None = None) -> str:
    if purpose not in PURPOSE_ALGORITHMS:
        raise ValueError(f"unknown key purpose: {purpose}")
    expected = PURPOSE_ALGORITHMS[purpose]
    if algorithm is not None and algorithm != expected:
        raise ValueError(f"purpose {purpose} requires algorithm {expected}")
    return expected


def _generate_material(algorithm: str):
    if algorithm == "RSA":
        pair = rsa_generate_keypair(current_app.config["RSA_KEY_BITS"])
        return pair["public"], pair["private"]
    if algorithm == "ECC":
        pair = ecc_generate_keypair()
        return pair["public"], pair["private"]
    if algorithm == "HMAC":
        return None, secrets.token_bytes(32)
    raise ValueError(f"unsupported algorithm: {algorithm}")


def _serialize_public(algorithm: str, public_key) -> str | None:
    if algorithm == "HMAC":
        return None
    if algorithm == "RSA":
        e, n = _require_rsa_public(public_key)
        return json.dumps({"e": str(e), "n": str(n)}, sort_keys=True, separators=(",", ":"))
    if algorithm == "ECC":
        if not is_on_curve(public_key) or public_key is None:
            raise ValueError("invalid ECC public key")
        return json.dumps({"x": public_key[0], "y": public_key[1]}, sort_keys=True, separators=(",", ":"))
    raise ValueError("unsupported algorithm")


def _serialize_private(algorithm: str, private_key) -> bytes:
    if algorithm == "RSA":
        d, n = private_key
        if not isinstance(d, int) or not isinstance(n, int) or d <= 0 or n <= 0:
            raise ValueError("invalid RSA private key")
        value = {"d": str(d), "n": str(n)}
    elif algorithm == "ECC":
        if not isinstance(private_key, int) or private_key <= 0:
            raise ValueError("invalid ECC private key")
        value = {"d": str(private_key)}
    elif algorithm == "HMAC":
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("HMAC private key must be 32 bytes")
        value = {"key": base64.b64encode(private_key).decode("ascii")}
    else:
        raise ValueError("unsupported algorithm")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_row(row) -> dict:
    algorithm = row["algorithm"]
    expected = _validate_purpose_and_algorithm(row["purpose"])
    if algorithm != expected or algorithm not in {"RSA", "ECC", "HMAC"}:
        raise ValueError("stored key purpose/algorithm mismatch")
    try:
        public_key = _deserialize_public(algorithm, row["public_key"])
        private_key = _deserialize_private(algorithm, _unwrap_private_key(row["encrypted_private_key"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("malformed stored key record") from exc
    if algorithm == "RSA" and public_key[1] != private_key[1]:
        raise ValueError("stored RSA public/private moduli do not match")
    return _key_record(row["version"], algorithm, public_key, private_key)


def _deserialize_public(algorithm: str, serialized: str | None):
    if algorithm == "HMAC":
        if serialized is not None:
            raise ValueError("HMAC public key must be NULL")
        return None
    if not isinstance(serialized, str):
        raise ValueError("public key serialization must be text")
    value = json.loads(serialized)
    if algorithm == "RSA":
        return _require_rsa_public((int(value["e"]), int(value["n"])))
    point = (int(value["x"]), int(value["y"]))
    if point is None or not is_on_curve(point):
        raise ValueError("invalid ECC public key")
    return point


def _deserialize_private(algorithm: str, serialized: bytes):
    value = json.loads(serialized.decode("utf-8"))
    if algorithm == "RSA":
        d, n = int(value["d"]), int(value["n"])
        if d <= 0 or n <= 0:
            raise ValueError("invalid RSA private key")
        return d, n
    if algorithm == "ECC":
        d = int(value["d"])
        if d <= 0:
            raise ValueError("invalid ECC private key")
        return d
    decoded = base64.b64decode(value["key"], validate=True)
    if len(decoded) != 32:
        raise ValueError("invalid HMAC private key length")
    return decoded


def _require_rsa_public(public_key):
    if (
        not isinstance(public_key, tuple)
        or len(public_key) != 2
        or not all(isinstance(value, int) for value in public_key)
        or public_key[0] <= 1
        or public_key[1] <= 0
    ):
        raise ValueError("invalid RSA public key")
    return public_key


def _key_record(version: int, algorithm: str, public_key, private_key) -> dict:
    return {"version": version, "public_key": public_key, "private_key": private_key}


def _change_lifecycle(purpose: str, version: int, target_status: str, require_replacement: bool) -> None:
    _validate_purpose_and_algorithm(purpose)
    if target_status not in VALID_STATUSES:
        raise ValueError("invalid key lifecycle status")
    if not isinstance(version, int) or version <= 0:
        raise ValueError("key version must be a positive integer")
    connection = get_db()
    with connection:
        row = connection.execute(
            "SELECT status FROM keys WHERE purpose = ? AND version = ?", (purpose, version)
        ).fetchone()
        if row is None:
            raise KeyError(f"key version {version} does not exist for purpose {purpose}")
        if row["status"] == "REVOKED":
            raise ValueError("key is already revoked")
        if row["status"] == "ACTIVE" and require_replacement:
            raise ValueError("cannot retire or revoke the active key without a replacement")
        connection.execute(
            "UPDATE keys SET status = ?, retired_at = CURRENT_TIMESTAMP WHERE purpose = ? AND version = ?",
            (target_status, purpose, version),
        )
