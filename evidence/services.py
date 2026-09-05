"""RSA-encrypted evidence storage and retrieval for Phase 12."""

import json
from pathlib import Path
from collections import OrderedDict

from flask import current_app

from auth.rbac import can_view_evidence, is_owner
from crypto.key_manager import get_active_key, get_key_by_version
from crypto.rsa import rsa_decrypt_bytes, rsa_encrypt_bytes
from database import db
from database.db import get_db


ALLOWED_MIME_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}
_EVIDENCE_CACHE_LIMIT = 32
_EVIDENCE_CACHE = OrderedDict()


class EvidenceNotFoundError(ValueError):
    """Raised when an evidence record does not exist."""


class EvidenceValidationError(ValueError):
    """Raised when an upload does not meet the evidence policy."""


def store_evidence(post_id: int, owner_id: int, filename: str, file_bytes: bytes, mimetype: str) -> int:
    post = db.query_one("SELECT id, owner_id FROM posts WHERE id = ?", (post_id,))
    if post is None:
        raise EvidenceNotFoundError("post does not exist")
    if not is_owner({"id": owner_id}, post["owner_id"]):
        raise PermissionError("post owner required")
    _validate_upload(filename, mimetype, file_bytes)

    active_key = get_active_key("RSA_EVIDENCE")
    encrypted_bytes = _serialize_ciphertext(rsa_encrypt_bytes(file_bytes, active_key["public_key"]))
    encrypted_filename = _serialize_ciphertext(
        rsa_encrypt_bytes(filename.encode("utf-8"), active_key["public_key"])
    )

    evidence_path = None
    connection = get_db()
    try:
        with connection:
            cursor = connection.execute(
                """INSERT INTO evidence
                   (post_id, owner_id, encrypted_filename, file_path, rsa_key_version)
                   VALUES (?, ?, ?, '', ?)""",
                (post_id, owner_id, encrypted_filename, active_key["version"]),
            )
            evidence_id = cursor.lastrowid
            evidence_path = _evidence_path(evidence_id)
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_bytes(encrypted_bytes)
            connection.execute(
                "UPDATE evidence SET file_path = ? WHERE id = ?",
                (f"encrypted_uploads/evidence_{evidence_id}.enc", evidence_id),
            )
        _cache_evidence(evidence_id, active_key["version"], filename, file_bytes, mimetype)
        return evidence_id
    except Exception:
        if evidence_path is not None:
            evidence_path.unlink(missing_ok=True)
        raise


def validate_evidence_upload(filename: str, mimetype: str, file_bytes: bytes) -> None:
    """Validate an upload before a related complaint is created."""
    _validate_upload(filename, mimetype, file_bytes)


def read_evidence(evidence_id: int, requester) -> tuple[str, bytes, str]:
    row = db.query_one(
        """SELECT e.*, p.owner_id AS post_owner_id
           FROM evidence AS e JOIN posts AS p ON p.id = e.post_id
           WHERE e.id = ?""",
        (evidence_id,),
    )
    if row is None:
        raise EvidenceNotFoundError("evidence does not exist")
    if not can_view_evidence(requester, {"owner_id": row["post_owner_id"]}):
        raise PermissionError("evidence access denied")

    key = get_key_by_version("RSA_EVIDENCE", row["rsa_key_version"])
    cached = _get_cached_evidence(row["id"], row["rsa_key_version"])
    if cached is not None:
        return cached
    try:
        ciphertext = _deserialize_ciphertext(_evidence_path(row["id"]).read_bytes())
        file_bytes = rsa_decrypt_bytes(ciphertext, key["private_key"])
        filename_ciphertext = _deserialize_ciphertext(row["encrypted_filename"])
        filename = rsa_decrypt_bytes(filename_ciphertext, key["private_key"]).decode("utf-8")
    except (OSError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence could not be read") from exc
    mimetype = _mimetype_for_filename(filename)
    _cache_evidence(row["id"], row["rsa_key_version"], filename, file_bytes, mimetype)
    return filename, file_bytes, mimetype


def _evidence_cache_key(evidence_id: int, key_version: int) -> tuple[str, int, int]:
    return (str(current_app.config["DATABASE_PATH"]), evidence_id, key_version)


def _cache_evidence(evidence_id: int, key_version: int, filename: str, file_bytes: bytes, mimetype: str) -> None:
    cache_key = _evidence_cache_key(evidence_id, key_version)
    _EVIDENCE_CACHE[cache_key] = (filename, file_bytes, mimetype)
    _EVIDENCE_CACHE.move_to_end(cache_key)
    while len(_EVIDENCE_CACHE) > _EVIDENCE_CACHE_LIMIT:
        _EVIDENCE_CACHE.popitem(last=False)


def _get_cached_evidence(evidence_id: int, key_version: int):
    cache_key = _evidence_cache_key(evidence_id, key_version)
    cached = _EVIDENCE_CACHE.get(cache_key)
    if cached is not None:
        _EVIDENCE_CACHE.move_to_end(cache_key)
    return cached


def list_evidence(post_id: int, requester) -> list[dict]:
    post = db.query_one("SELECT owner_id FROM posts WHERE id = ?", (post_id,))
    if post is None or not can_view_evidence(requester, post):
        return []
    rows = db.query_all(
        "SELECT id, encrypted_filename, rsa_key_version FROM evidence WHERE post_id = ? ORDER BY id",
        (post_id,),
    )
    items = []
    for row in rows:
        filename = rsa_decrypt_bytes(
            _deserialize_ciphertext(row["encrypted_filename"]),
            get_key_by_version("RSA_EVIDENCE", row["rsa_key_version"])["private_key"],
        ).decode("utf-8")
        mimetype = _mimetype_for_filename(filename)
        items.append({
            "id": row["id"],
            "filename": filename,
            "mimetype": mimetype,
            "is_image": mimetype.startswith("image/"),
        })
    return items


def _validate_upload(filename: str, mimetype: str, file_bytes: bytes) -> None:
    if not isinstance(filename, str) or not filename:
        raise EvidenceValidationError("filename is required")
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_MIME_TYPES or mimetype != ALLOWED_MIME_TYPES[suffix]:
        raise EvidenceValidationError("unsupported evidence type")
    if not isinstance(file_bytes, bytes):
        raise EvidenceValidationError("evidence must be bytes")
    if len(file_bytes) > current_app.config["MAX_EVIDENCE_SIZE_BYTES"]:
        raise EvidenceValidationError("evidence is too large")


def _evidence_path(evidence_id: int) -> Path:
    upload_dir = Path(current_app.config.get("EVIDENCE_UPLOAD_DIR", Path(current_app.root_path) / "encrypted_uploads"))
    return upload_dir / f"evidence_{evidence_id}.enc"


def safe_download_name(filename: str) -> str:
    cleaned = "".join(
        "_" if character in {"/", "\\"} else character
        for character in filename
        if 32 <= ord(character) != 127
    )
    return cleaned or "evidence"


def _serialize_ciphertext(container: dict) -> bytes:
    if not isinstance(container, dict) or container.get("format") != "TBR1":
        raise ValueError("invalid RSA ciphertext")
    return json.dumps(container, separators=(",", ":")).encode("utf-8")


def _deserialize_ciphertext(value: bytes) -> dict:
    try:
        container = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise ValueError("malformed RSA ciphertext") from exc
    if not isinstance(container, dict) or container.get("format") != "TBR1":
        raise ValueError("malformed RSA ciphertext")
    return container


def _mimetype_for_filename(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return ALLOWED_MIME_TYPES.get(suffix, "application/octet-stream")
