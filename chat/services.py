"""ECC-confidential, CMAC-authenticated private complaint conversations."""

from datetime import datetime, timezone

from auth.rbac import can_access_chat, can_start_chat
from crypto.ecc_encoding import deserialize_ecc_ciphertext, ecc_decrypt_bytes, ecc_encrypt_bytes, serialize_ecc_ciphertext
from crypto.cmac_auth import compute_cmac, verify_cmac
from crypto.key_manager import get_active_key, get_key_by_version
from database import db
from utils.crypto_trace import trace_decrypt, trace_encrypt, trace_mac


MAX_CHAT_MESSAGE_LENGTH = 300
INTEGRITY_WARNING = "Message integrity verification failed. Possible unauthorized modification detected."


class ChatPostNotFoundError(ValueError):
    """Raised when a conversation's complaint does not exist."""


def initialize_chat(post_id: int, actor) -> None:
    """Explicitly open the one private conversation attached to a complaint."""
    post = _get_post(post_id)
    if post is None:
        raise ChatPostNotFoundError("post does not exist")
    if not can_start_chat(actor, post):
        if actor is not None and actor["role"] == "admin" and post["chat_started_at"] is not None:
            return
        raise PermissionError("chat initialization denied")
    db.execute(
        "UPDATE posts SET chat_started_at = CURRENT_TIMESTAMP WHERE id = ? AND chat_started_at IS NULL",
        (post_id,),
    )


def send_message(post_id: int, sender_id: int, plaintext: str) -> int:
    post = _get_post(post_id)
    if post is None:
        raise ChatPostNotFoundError("post does not exist")
    sender = db.query_one("SELECT id, role FROM users WHERE id = ?", (sender_id,))
    if sender is None or not can_access_chat(sender, post):
        raise PermissionError("chat access denied")
    if post["status"] == "Resolved":
        raise PermissionError("resolved chat is read-only")
    if not isinstance(plaintext, str) or not plaintext.strip() or len(plaintext) > MAX_CHAT_MESSAGE_LENGTH:
        raise ValueError("invalid chat message")
    plaintext = plaintext.strip()

    ecc_key = get_active_key("ECC_CHAT")
    cmac_key = get_active_key("CMAC_CHAT")
    ciphertext = serialize_ecc_ciphertext(ecc_encrypt_bytes(plaintext.encode("utf-8"), ecc_key["public_key"]))
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    mac = compute_cmac(
        cmac_key["private_key"],
        build_chat_mac_input(post_id, sender_id, created_at, ciphertext),
    )
    trace_encrypt("ECC_CHAT", algorithm="EC-ElGamal", key_version=ecc_key["version"], bytes=len(plaintext.encode("utf-8")))
    trace_mac("CMAC_CHAT", key_version=cmac_key["version"], result="GENERATED", tag="[REDACTED]")
    return db.execute(
        """INSERT INTO chat_messages
           (post_id, sender_id, ciphertext, mac, ecc_key_version, cmac_key_version, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (post_id, sender_id, ciphertext, mac, ecc_key["version"], cmac_key["version"], created_at),
    ).lastrowid


def get_conversation(post_id: int, requester) -> list[dict]:
    post = _get_post(post_id)
    if post is None:
        raise ChatPostNotFoundError("post does not exist")
    if not can_access_chat(requester, post):
        raise PermissionError("chat access denied")

    messages = []
    rows = db.query_all(
        "SELECT * FROM chat_messages WHERE post_id = ? ORDER BY created_at ASC, id ASC",
        (post_id,),
    )
    for row in rows:
        sender = db.query_one("SELECT id, role FROM users WHERE id = ?", (row["sender_id"],))
        display = "Admin" if sender is not None and sender["role"] == "admin" else "Owner"
        cmac_key = get_key_by_version("CMAC_CHAT", row["cmac_key_version"])
        valid = verify_cmac(
            cmac_key["private_key"],
            build_chat_mac_input(row["post_id"], row["sender_id"], row["created_at"], row["ciphertext"]),
            row["mac"],
        )
        trace_mac("CMAC_CHAT", key_version=row["cmac_key_version"], result="VALID" if valid else "INVALID")
        item = {"id": row["id"], "sender": display, "created_at": row["created_at"], "integrity_ok": valid}
        if not valid:
            item["warning"] = INTEGRITY_WARNING
        else:
            ecc_key = get_key_by_version("ECC_CHAT", row["ecc_key_version"])
            try:
                item["plaintext"] = ecc_decrypt_bytes(
                    deserialize_ecc_ciphertext(row["ciphertext"]), ecc_key["private_key"]
                ).decode("utf-8")
                trace_decrypt("ECC_CHAT", key_version=row["ecc_key_version"], result="DECRYPTED AFTER MAC")
            except (TypeError, ValueError, UnicodeDecodeError) as exc:
                raise ValueError("chat message could not be read") from exc
        messages.append(item)
    return messages


def build_chat_mac_input(post_id: int, sender_id: int, timestamp: str, ciphertext: str) -> bytes:
    """Build an unambiguous length-prefixed MAC payload in frozen field order."""
    fields = (str(post_id), str(sender_id), timestamp, ciphertext)
    return b"".join(len(value.encode("utf-8")).to_bytes(8, "big") + value.encode("utf-8") for value in fields)


def _get_post(post_id: int):
    return db.query_one("SELECT id, owner_id, status, chat_started_at FROM posts WHERE id = ?", (post_id,))
