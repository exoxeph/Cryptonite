"""RSA-encrypted evidence storage and retrieval for Phase 12."""

import json
from pathlib import Path

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
                (evidence_path.relative_to(Path(current_app.root_path)).as_posix(), evidence_id),
            )
        return evidence_id
    except Exception:
        if evidence_path is not None:
            evidence_path.unlink(missing_ok=True)
        raise


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
    try:
        ciphertext = _deserialize_ciphertext(Path(current_app.root_path, row["file_path"]).read_bytes())
        file_bytes = rsa_decrypt_bytes(ciphertext, key["private_key"])
        filename_ciphertext = _deserialize_ciphertext(row["encrypted_filename"])
        filename = rsa_decrypt_bytes(filename_ciphertext, key["private_key"]).decode("utf-8")
    except (OSError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence could not be read") from exc
    return filename, file_bytes, _mimetype_for_filename(filename)


def list_evidence(post_id: int, requester) -> list[dict]:
    rows = db.query_all("SELECT id FROM evidence WHERE post_id = ? ORDER BY id", (post_id,))
    if not rows:
        return []
    post = db.query_one("SELECT owner_id FROM posts WHERE id = ?", (post_id,))
    if post is None or not can_view_evidence(requester, post):
        return []
    return [{"id": row["id"]} for row in rows]


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
    return Path(current_app.root_path) / "encrypted_uploads" / f"evidence_{evidence_id}.enc"


def _serialize_ciphertext(blocks: list[int]) -> bytes:
    if not isinstance(blocks, list) or not all(type(block) is int and block >= 0 for block in blocks):
        raise ValueError("invalid RSA ciphertext")
    return json.dumps(blocks, separators=(",", ":")).encode("utf-8")


def _deserialize_ciphertext(value: bytes) -> list[int]:
    try:
        blocks = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise ValueError("malformed RSA ciphertext") from exc
    if not isinstance(blocks, list) or not blocks or not all(type(block) is int and block >= 0 for block in blocks):
        raise ValueError("malformed RSA ciphertext")
    return blocks


def _mimetype_for_filename(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return ALLOWED_MIME_TYPES.get(suffix, "application/octet-stream")
