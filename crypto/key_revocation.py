"""Migrate records away from a retired key before revoking it."""

import os
import uuid

from auth.account_service import decrypt_profile_field, encrypt_profile_field
from chat.services import build_chat_mac_input
from crypto import key_manager
from crypto.cmac_auth import compute_cmac, verify_cmac
from crypto.ecc_encoding import (
    deserialize_ecc_ciphertext,
    ecc_decrypt_bytes,
    ecc_encrypt_bytes,
    serialize_ecc_ciphertext,
)
from crypto.rsa import rsa_decrypt_bytes, rsa_encrypt_bytes
from database import db
from database.db import get_db
from evidence.services import _deserialize_ciphertext, _evidence_path, _serialize_ciphertext
from utils.crypto_trace import trace_key_event


def reencrypt_and_revoke(purpose: str, version: int) -> None:
    """Migrate all dependent records to the active key, then revoke the old key."""
    old_row = db.query_one(
        "SELECT status FROM keys WHERE purpose = ? AND version = ?", (purpose, version)
    )
    if old_row is None:
        raise KeyError("key version does not exist")
    if old_row["status"] == "ACTIVE":
        raise ValueError("cannot revoke the active key without a replacement")
    if old_row["status"] != "RETIRED":
        raise ValueError("only retired keys can be revoked")

    # The target is always the current ACTIVE key for the same purpose. This
    # also rejects a retired key with no active replacement.
    active = key_manager.get_active_key(purpose)
    if active["version"] == version:
        raise ValueError("cannot revoke the active key")
    old = key_manager.get_key_by_version(purpose, version)
    dependent_count = _dependency_count(purpose, version)
    trace_key_event(
        "REVOCATION_START",
        purpose=purpose,
        retired_version=f"v{version}",
        migration_target=f"v{active['version']} ACTIVE",
        dependent_records=dependent_count,
    )

    replacements = []
    connection = get_db()
    try:
        with connection:
            if purpose == "RSA_PROFILE":
                _migrate_profiles(connection, old, active, version)
            elif purpose == "RSA_EVIDENCE":
                replacements = _migrate_evidence(connection, old, active, version)
            elif purpose == "ECC_POSTS":
                _migrate_posts(connection, old, active, version)
            elif purpose == "ECC_CHAT":
                _migrate_chat_ciphertext(connection, old, active, version)
            elif purpose == "CMAC_CHAT":
                _migrate_chat_macs(connection, active, version)
            elif purpose == "CMAC_SESSION":
                # Session signatures are intentionally not migrated. The
                # rotation already makes old signatures invalid.
                pass

            _stage_evidence_replacements(replacements)
            _apply_evidence_replacements(replacements)
            remaining = _dependency_count(purpose, version, connection)
            if remaining != 0:
                raise ValueError("key still has dependent records")
            key_manager._change_lifecycle(purpose, version, "REVOKED", require_replacement=True)
        _cleanup_evidence_replacements(replacements)
        trace_key_event(
            "REVOCATION_COMPLETE",
            purpose=purpose,
            retired_version=f"v{version}",
            remaining_references=0,
        )
    except Exception as exc:
        _restore_evidence_replacements(replacements)
        trace_key_event(
            "REVOCATION_ABORTED",
            purpose=purpose,
            retired_version=f"v{version}",
            reason=type(exc).__name__,
            old_key_remains="RETIRED",
        )
        raise


def _dependency_count(purpose: str, version: int, connection=None) -> int:
    connection = connection or get_db()
    queries = {
        "RSA_PROFILE": "SELECT COUNT(*) AS count FROM users WHERE profile_key_version = ?",
        "RSA_EVIDENCE": "SELECT COUNT(*) AS count FROM evidence WHERE rsa_key_version = ?",
        "ECC_POSTS": "SELECT COUNT(*) AS count FROM posts WHERE ecc_key_version = ?",
        "ECC_CHAT": "SELECT COUNT(*) AS count FROM chat_messages WHERE ecc_key_version = ?",
        "CMAC_CHAT": "SELECT COUNT(*) AS count FROM chat_messages WHERE cmac_key_version = ?",
        "CMAC_SESSION": "SELECT 0 AS count",
    }
    if purpose not in queries:
        raise ValueError(f"unknown key purpose: {purpose}")
    if purpose == "CMAC_SESSION":
        return 0
    return connection.execute(queries[purpose], (version,)).fetchone()["count"]


def _migrate_profiles(connection, old, active, version):
    rows = connection.execute(
        "SELECT id, encrypted_name, encrypted_email, encrypted_contact, encrypted_bracu_id "
        "FROM users WHERE profile_key_version = ?", (version,)
    ).fetchall()
    for row in rows:
        fields = [
            encrypt_profile_field(decrypt_profile_field(value, old["private_key"]), active["public_key"])
            for value in (row["encrypted_name"], row["encrypted_email"], row["encrypted_contact"])
        ]
        bracu = None
        if row["encrypted_bracu_id"] is not None:
            bracu = encrypt_profile_field(
                decrypt_profile_field(row["encrypted_bracu_id"], old["private_key"]), active["public_key"]
            )
        connection.execute(
            "UPDATE users SET encrypted_name = ?, encrypted_email = ?, encrypted_contact = ?, "
            "encrypted_bracu_id = ?, profile_key_version = ? WHERE id = ?",
            (*fields, bracu, active["version"], row["id"]),
        )


def _migrate_evidence(connection, old, active, version):
    replacements = []
    rows = connection.execute(
        "SELECT id, encrypted_filename FROM evidence WHERE rsa_key_version = ?", (version,)
    ).fetchall()
    for row in rows:
        path = _evidence_path(row["id"])
        original = path.read_bytes()
        plaintext = rsa_decrypt_bytes(_deserialize_ciphertext(original), old["private_key"])
        filename = rsa_decrypt_bytes(
            _deserialize_ciphertext(row["encrypted_filename"]), old["private_key"]
        )
        encrypted_file = _serialize_ciphertext(rsa_encrypt_bytes(plaintext, active["public_key"]))
        encrypted_filename = _serialize_ciphertext(rsa_encrypt_bytes(filename, active["public_key"]))
        replacements.append({"path": path, "original": original, "encrypted": encrypted_file})
        connection.execute(
            "UPDATE evidence SET encrypted_filename = ?, rsa_key_version = ? WHERE id = ?",
            (encrypted_filename, active["version"], row["id"]),
        )
    return replacements


def _stage_evidence_replacements(replacements):
    for replacement in replacements:
        path = replacement["path"]
        temporary = path.with_name(f".{path.name}.revoke-{uuid.uuid4().hex}.tmp")
        with temporary.open("wb") as stream:
            stream.write(replacement["encrypted"])
            stream.flush()
            os.fsync(stream.fileno())
        replacement["temporary"] = temporary


def _apply_evidence_replacements(replacements):
    for replacement in replacements:
        path = replacement["path"]
        backup = path.with_name(f".{path.name}.revoke-{uuid.uuid4().hex}.bak")
        os.replace(path, backup)
        replacement["backup"] = backup
        os.replace(replacement["temporary"], path)


def _cleanup_evidence_replacements(replacements):
    for replacement in replacements:
        for name in ("backup", "temporary"):
            candidate = replacement.get(name)
            if candidate is not None:
                try:
                    candidate.unlink(missing_ok=True)
                except OSError:
                    # Cleanup failure leaves only encrypted staging/backup
                    # artifacts; it must not undo a committed DB migration.
                    pass


def _restore_evidence_replacements(replacements):
    for replacement in reversed(replacements):
        path = replacement["path"]
        temporary = replacement.get("temporary")
        backup = replacement.get("backup")
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if backup is not None and backup.exists():
            path.unlink(missing_ok=True)
            os.replace(backup, path)


def _migrate_posts(connection, old, active, version):
    rows = connection.execute(
        "SELECT id, encrypted_title, encrypted_description FROM posts WHERE ecc_key_version = ?", (version,)
    ).fetchall()
    for row in rows:
        title = ecc_decrypt_bytes(deserialize_ecc_ciphertext(row["encrypted_title"]), old["private_key"])
        description = ecc_decrypt_bytes(deserialize_ecc_ciphertext(row["encrypted_description"]), old["private_key"])
        connection.execute(
            "UPDATE posts SET encrypted_title = ?, encrypted_description = ?, ecc_key_version = ? WHERE id = ?",
            (
                serialize_ecc_ciphertext(ecc_encrypt_bytes(title, active["public_key"])),
                serialize_ecc_ciphertext(ecc_encrypt_bytes(description, active["public_key"])),
                active["version"], row["id"],
            ),
        )


def _migrate_chat_ciphertext(connection, old, active, version):
    rows = connection.execute(
        "SELECT id, post_id, sender_id, ciphertext, mac, cmac_key_version, created_at "
        "FROM chat_messages WHERE ecc_key_version = ?", (version,)
    ).fetchall()
    if not rows:
        return
    active_cmac = key_manager.get_active_key("CMAC_CHAT")
    for row in rows:
        old_cmac = key_manager.get_key_by_version("CMAC_CHAT", row["cmac_key_version"])
        mac_input = build_chat_mac_input(row["post_id"], row["sender_id"], row["created_at"], row["ciphertext"])
        if not verify_cmac(old_cmac["private_key"], mac_input, row["mac"]):
            raise ValueError("chat message integrity verification failed")
        plaintext = ecc_decrypt_bytes(deserialize_ecc_ciphertext(row["ciphertext"]), old["private_key"])
        ciphertext = serialize_ecc_ciphertext(ecc_encrypt_bytes(plaintext, active["public_key"]))
        mac = compute_cmac(
            active_cmac["private_key"],
            build_chat_mac_input(row["post_id"], row["sender_id"], row["created_at"], ciphertext),
        )
        connection.execute(
            "UPDATE chat_messages SET ciphertext = ?, mac = ?, ecc_key_version = ?, cmac_key_version = ? WHERE id = ?",
            (ciphertext, mac, active["version"], active_cmac["version"], row["id"]),
        )


def _migrate_chat_macs(connection, active, version):
    old = key_manager.get_key_by_version("CMAC_CHAT", version)
    rows = connection.execute(
        "SELECT id, post_id, sender_id, ciphertext, mac, created_at FROM chat_messages WHERE cmac_key_version = ?",
        (version,),
    ).fetchall()
    for row in rows:
        mac_input = build_chat_mac_input(row["post_id"], row["sender_id"], row["created_at"], row["ciphertext"])
        if not verify_cmac(old["private_key"], mac_input, row["mac"]):
            raise ValueError("chat message integrity verification failed")
        mac = compute_cmac(
            active["private_key"],
            mac_input,
        )
        connection.execute(
            "UPDATE chat_messages SET mac = ?, cmac_key_version = ? WHERE id = ?",
            (mac, active["version"], row["id"]),
        )
