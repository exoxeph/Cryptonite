"""Encrypted complaint storage and display services for Phase 10."""

import sqlite3
from math import ceil

from auth.account_service import decrypt_profile_field
from auth.rbac import can_access_chat, can_edit_post
from crypto.ecc_encoding import (
    deserialize_ecc_ciphertext,
    ecc_decrypt_bytes,
    ecc_encrypt_bytes,
    serialize_ecc_ciphertext,
)
from crypto.key_manager import get_active_key, get_key_by_version
from database import db
from database.db import get_db


MAX_TITLE_LENGTH = 120
MAX_DESCRIPTION_LENGTH = 500
DEFAULT_PAGE_SIZE = 10
STUDENT_DASHBOARD_LIMIT = 5
ADMIN_DASHBOARD_LIMIT = 6
VALID_STATUSES = {"Pending", "Acknowledged", "Resolved"}
ADMIN_SORTS = {
    "newest": "p.created_at DESC, p.id DESC",
    "oldest": "p.created_at ASC, p.id ASC",
    "most_upvoted": "upvote_count DESC, p.id DESC",
    "least_upvoted": "upvote_count ASC, p.id ASC",
}
STATUS_TRANSITIONS = {
    "Pending": "Acknowledged",
    "Acknowledged": "Resolved",
}


class PostNotFoundError(ValueError):
    """Raised when a requested post does not exist."""


class UpvoteAlreadyExistsError(ValueError):
    """Raised when the database uniqueness rule rejects a duplicate upvote."""


def create_post(owner_id: int, title: str, description: str, anonymous: bool) -> int:
    title, description = _validate_content(title, description)
    active_key = get_active_key("ECC_POSTS")
    values = (
        owner_id,
        serialize_ecc_ciphertext(ecc_encrypt_bytes(title.encode("utf-8"), active_key["public_key"])),
        serialize_ecc_ciphertext(ecc_encrypt_bytes(description.encode("utf-8"), active_key["public_key"])),
        1 if bool(anonymous) else 0,
        active_key["version"],
    )
    return db.execute(
        """INSERT INTO posts
           (owner_id, encrypted_title, encrypted_description, anonymous, status, ecc_key_version)
           VALUES (?, ?, ?, ?, 'Pending', ?)""",
        values,
    ).lastrowid


def get_post_for_display(post_id: int, viewer) -> dict | None:
    _require_viewer(viewer)
    row = _get_post(post_id)
    if row is None:
        return None
    return _display_post(row, viewer)


def list_public_posts(
    viewer, page: int = 1, per_page: int = DEFAULT_PAGE_SIZE, status: str = "all", sort: str = "newest"
) -> list[dict]:
    _require_viewer(viewer)
    page = _validate_page(page)
    per_page = _validate_page_size(per_page)
    status = _validate_admin_status(status)
    sort = _validate_admin_sort(sort)
    rows = _query_post_summaries(page, per_page, viewer["id"], status=status, order_by=ADMIN_SORTS[sort])
    key_cache = {}
    return [_display_post_summary(row, viewer, key_cache) for row in rows]


def count_public_posts(status: str = "all") -> int:
    status = _validate_admin_status(status)
    if status == "all":
        return db.query_one("SELECT COUNT(*) AS count FROM posts")["count"]
    return db.query_one("SELECT COUNT(*) AS count FROM posts WHERE status = ?", (status,))["count"]


def get_student_dashboard(user_id: int) -> dict:
    counts = _status_counts("WHERE owner_id = ?", (user_id,))
    counts["total"] = sum(counts.values())
    rows = db.query_all(
        """SELECT id, owner_id, encrypted_title, anonymous, status, created_at,
                  ecc_key_version,
                  (SELECT COUNT(*) FROM upvotes u WHERE u.post_id = p.id) AS upvote_count,
                  1 AS has_upvoted,
                  0 AS evidence_count
           FROM posts p WHERE owner_id = ? ORDER BY id DESC LIMIT ?""",
        (user_id, STUDENT_DASHBOARD_LIMIT),
    )
    key_cache = {}
    return {
        "counts": counts,
        "posts": [_display_post_summary(row, {"id": user_id, "role": "student"}, key_cache) for row in rows],
    }


def get_editable_post(post_id: int, editor) -> dict | None:
    row = _get_post(post_id)
    if row is None:
        return None
    if not can_edit_post(editor, row):
        raise PermissionError("post owner required")
    return _decrypt_post_fields(row)


def update_post(post_id: int, editor_id: int, title: str, description: str, anonymous: bool | None = None) -> None:
    title, description = _validate_content(title, description)
    row = _get_post(post_id)
    if row is None:
        raise ValueError("post does not exist")
    if row["owner_id"] != editor_id:
        raise PermissionError("post owner required")
    active_key = get_active_key("ECC_POSTS")
    encrypted_title = serialize_ecc_ciphertext(ecc_encrypt_bytes(title.encode("utf-8"), active_key["public_key"]))
    encrypted_description = serialize_ecc_ciphertext(
        ecc_encrypt_bytes(description.encode("utf-8"), active_key["public_key"])
    )
    anonymous_value = row["anonymous"] if anonymous is None else (1 if bool(anonymous) else 0)
    try:
        connection = get_db()
        with connection:
            cursor = connection.execute(
                """UPDATE posts
                   SET encrypted_title = ?, encrypted_description = ?, anonymous = ?,
                       ecc_key_version = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE id = ? AND owner_id = ?""",
                (encrypted_title, encrypted_description, anonymous_value, active_key["version"], post_id, editor_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("post owner required")
    except sqlite3.IntegrityError as exc:
        raise ValueError("post update failed") from exc


def upvote_post(user_id: int, post_id: int) -> None:
    """Insert one student upvote; the database uniqueness constraint is authoritative."""
    post = _get_post(post_id)
    if post is None:
        raise PostNotFoundError("post does not exist")
    user = db.query_one("SELECT id, role FROM users WHERE id = ?", (user_id,))
    if user is None or user["role"] != "student":
        raise PermissionError("student upvote required")
    if post["owner_id"] == user_id:
        raise PermissionError("post owner cannot upvote")
    try:
        db.execute("INSERT INTO upvotes (user_id, post_id) VALUES (?, ?)", (user_id, post_id))
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed: upvotes.user_id, upvotes.post_id" not in str(exc):
            raise
        raise UpvoteAlreadyExistsError("upvote already exists") from exc


def toggle_upvote(user_id: int, post_id: int) -> bool:
    """Toggle one student's upvote and return whether it is now present."""
    post = _get_post(post_id)
    if post is None:
        raise PostNotFoundError("post does not exist")
    user = db.query_one("SELECT id, role FROM users WHERE id = ?", (user_id,))
    if user is None or user["role"] != "student":
        raise PermissionError("student upvote required")
    if post["owner_id"] == user_id:
        raise PermissionError("post owner cannot upvote")
    if has_user_upvoted(user_id, post_id):
        db.execute("DELETE FROM upvotes WHERE user_id = ? AND post_id = ?", (user_id, post_id))
        return False
    upvote_post(user_id, post_id)
    return True


def get_upvote_count(post_id: int) -> int:
    """Return the authoritative number of upvote rows for a post."""
    row = db.query_one("SELECT COUNT(*) AS count FROM upvotes WHERE post_id = ?", (post_id,))
    return row["count"]


def has_user_upvoted(user_id: int, post_id: int) -> bool:
    """Check existence of one user's upvote without trusting browser state."""
    return db.query_one(
        "SELECT 1 AS present FROM upvotes WHERE user_id = ? AND post_id = ?",
        (user_id, post_id),
    ) is not None


def change_status(post_id: int, new_status: str, actor) -> None:
    row = _get_post(post_id)
    if row is None:
        raise PostNotFoundError("post does not exist")
    if actor is None or actor["role"] != "admin":
        raise PermissionError("Admin role required")
    if new_status not in VALID_STATUSES:
        raise ValueError("invalid status")
    if STATUS_TRANSITIONS.get(row["status"]) != new_status:
        raise ValueError("invalid status transition")
    connection = get_db()
    with connection:
        connection.execute(
            "UPDATE posts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (new_status, post_id),
        )


def acknowledge_post(post_id: int, actor) -> None:
    change_status(post_id, "Acknowledged", actor)


def list_admin_posts(
    viewer, page: int = 1, per_page: int = DEFAULT_PAGE_SIZE, status: str = "all", sort: str = "newest"
) -> list[dict]:
    _require_admin(viewer)
    page = _validate_page(page)
    per_page = _validate_page_size(per_page)
    status = _validate_admin_status(status)
    sort = _validate_admin_sort(sort)
    rows = _query_post_summaries(page, per_page, viewer["id"], status=status, order_by=ADMIN_SORTS[sort])
    key_cache = {}
    return [_display_post_summary(row, viewer, key_cache) for row in rows]


def count_admin_posts(status: str = "all") -> int:
    status = _validate_admin_status(status)
    if status == "all":
        return count_public_posts()
    return db.query_one("SELECT COUNT(*) AS count FROM posts WHERE status = ?", (status,))["count"]


def get_admin_dashboard(viewer) -> dict:
    _require_admin(viewer)
    rows = db.query_all(
        """SELECT id, owner_id, encrypted_title, anonymous, status, created_at,
                  ecc_key_version,
                  (SELECT COUNT(*) FROM upvotes u WHERE u.post_id = p.id) AS upvote_count,
                  0 AS has_upvoted,
                  0 AS evidence_count
           FROM posts p WHERE status != 'Resolved' ORDER BY id DESC LIMIT ?""",
        (ADMIN_DASHBOARD_LIMIT,),
    )
    key_cache = {}
    return {
        "counts": _status_counts(),
        "posts": [_display_post_summary(row, viewer, key_cache) for row in rows],
        "total": count_admin_posts(),
    }


def get_admin_post_for_display(post_id: int, viewer) -> dict | None:
    _require_admin(viewer)
    row = _get_post(post_id)
    if row is None:
        return None
    return _display_post(row, viewer, reveal_anonymous=True)


def get_page_count(total: int, per_page: int = DEFAULT_PAGE_SIZE) -> int:
    return max(1, ceil(total / _validate_page_size(per_page)))


def _query_post_summaries(page: int, per_page: int, viewer_id: int, status: str = "all", order_by: str = "p.id DESC"):
    offset = (page - 1) * per_page
    status_clause = "" if status == "all" else "WHERE p.status = ?"
    params = [viewer_id]
    if status != "all":
        params.append(status)
    params.extend((per_page, offset))
    return db.query_all(
        f"""SELECT p.id, p.owner_id, p.encrypted_title, p.anonymous, p.status, p.created_at,
                  ecc_key_version,
                  (SELECT COUNT(*) FROM upvotes u WHERE u.post_id = p.id) AS upvote_count,
                  (SELECT COUNT(*) FROM evidence e WHERE e.post_id = p.id) AS evidence_count,
                  EXISTS(SELECT 1 FROM upvotes v WHERE v.post_id = p.id AND v.user_id = ?) AS has_upvoted
           FROM posts p {status_clause} ORDER BY {order_by} LIMIT ? OFFSET ?""",
        params,
    )


def _display_post_summary(row, viewer, key_cache: dict) -> dict:
    title_key = ("ECC_POSTS", row["ecc_key_version"])
    if title_key not in key_cache:
        key_cache[title_key] = get_key_by_version(*title_key)
    title = ecc_decrypt_bytes(
        deserialize_ecc_ciphertext(row["encrypted_title"]),
        key_cache[title_key]["private_key"],
    ).decode("utf-8")
    has_upvoted = bool(row["has_upvoted"])
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "title": title,
        "display_owner": "Anonymous Student" if row["anonymous"] else "Student",
        "anonymous": bool(row["anonymous"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["created_at"],
        "upvote_count": row["upvote_count"],
        "evidence_count": row["evidence_count"],
        "has_upvoted": has_upvoted,
        "can_upvote": viewer["role"] == "student" and row["owner_id"] != viewer["id"],
        "can_access_chat": can_access_chat(viewer, row),
    }


def _status_counts(where: str = "", params: tuple = ()) -> dict[str, int]:
    rows = db.query_all(
        f"SELECT status, COUNT(*) AS count FROM posts {where} GROUP BY status",
        params,
    )
    counts = {status: 0 for status in VALID_STATUSES}
    counts.update({row["status"]: row["count"] for row in rows})
    return counts


def _validate_page(page: int) -> int:
    if isinstance(page, bool) or not isinstance(page, int) or page < 1:
        raise ValueError("invalid page")
    return page


def _validate_page_size(per_page: int) -> int:
    if isinstance(per_page, bool) or not isinstance(per_page, int) or per_page < 1:
        raise ValueError("invalid page size")
    return per_page


def _validate_admin_status(status: str) -> str:
    if status != "all" and status not in VALID_STATUSES:
        raise ValueError("invalid status filter")
    return status


def _validate_admin_sort(sort: str) -> str:
    if sort not in ADMIN_SORTS:
        raise ValueError("invalid admin sort")
    return sort


def _display_post(row, viewer, reveal_anonymous: bool = False) -> dict:
    key_cache = {}
    values = _decrypt_post_fields(row, key_cache)
    if row["anonymous"] and not reveal_anonymous:
        display_owner = "Anonymous Student"
    else:
        owner = db.query_one("SELECT * FROM users WHERE id = ?", (row["owner_id"],))
        if owner is None:
            raise ValueError("post owner does not exist")
        owner_cache_key = ("RSA_PROFILE", owner["profile_key_version"])
        if owner_cache_key not in key_cache:
            key_cache[owner_cache_key] = get_key_by_version(*owner_cache_key)
        owner_key = key_cache[owner_cache_key]
        display_owner = decrypt_profile_field(owner["encrypted_name"], owner_key["private_key"])
    has_upvoted = has_user_upvoted(viewer["id"], row["id"])
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "title": values["title"],
        "description": values["description"],
        "display_owner": display_owner,
        "anonymous": bool(row["anonymous"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "upvote_count": get_upvote_count(row["id"]),
        "has_upvoted": has_upvoted,
        "can_upvote": viewer["role"] == "student" and row["owner_id"] != viewer["id"],
        "can_access_chat": can_access_chat(viewer, row),
    }


def _decrypt_post_fields(row, key_cache: dict | None = None) -> dict:
    key_cache = {} if key_cache is None else key_cache
    cache_key = ("ECC_POSTS", row["ecc_key_version"])
    if cache_key not in key_cache:
        key_cache[cache_key] = get_key_by_version(*cache_key)
    post_key = key_cache[cache_key]
    return {
        "title": ecc_decrypt_bytes(
            deserialize_ecc_ciphertext(row["encrypted_title"]), post_key["private_key"]
        ).decode("utf-8"),
        "description": ecc_decrypt_bytes(
            deserialize_ecc_ciphertext(row["encrypted_description"]), post_key["private_key"]
        ).decode("utf-8"),
    }


def _validate_content(title: str, description: str) -> tuple[str, str]:
    if not isinstance(title, str) or not title.strip() or len(title.strip()) > MAX_TITLE_LENGTH:
        raise ValueError("invalid title")
    if not isinstance(description, str) or not description.strip() or len(description.strip()) > MAX_DESCRIPTION_LENGTH:
        raise ValueError("invalid description")
    return title.strip(), description.strip()


def _get_post(post_id: int):
    return db.query_one("SELECT * FROM posts WHERE id = ?", (post_id,))


def _require_viewer(viewer) -> None:
    if viewer is None or viewer["role"] not in {"student", "admin"}:
        raise PermissionError("authenticated viewer required")


def _require_admin(viewer) -> None:
    if viewer is None or viewer["role"] != "admin":
        raise PermissionError("Admin role required")
