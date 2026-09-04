"""Minimal Phase 10 authorization predicates."""


def is_admin(user) -> bool:
    return user is not None and user["role"] == "admin"


def is_owner(user, owner_id: int) -> bool:
    return user is not None and user["id"] == owner_id


def can_create_post(user) -> bool:
    return user is not None and user["role"] == "student"


def can_edit_post(user, post) -> bool:
    return user is not None and is_owner(user, post["owner_id"])
