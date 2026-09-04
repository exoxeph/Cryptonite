import sqlite3

import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from crypto import key_manager
from database import db
from posts.services import get_upvote_count, has_user_upvoted, upvote_post


class UpvoteConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-upvote-flow-123456"
    DATABASE_PATH = ""
    RSA_KEY_BITS = 1024
    ROOT_RSA_N = ROOT_RSA_E = ROOT_RSA_D = ""
    OTP_EXPIRY_SECONDS = 300
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_SECONDS = 3600


@pytest.fixture
def upvote_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    UpvoteConfig.DATABASE_PATH = str(tmp_path / "upvotes.db")
    UpvoteConfig.ROOT_RSA_E, UpvoteConfig.ROOT_RSA_N = map(str, root["public"])
    UpvoteConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(UpvoteConfig)
    with app.app_context():
        db.init_db()
        key_manager.bootstrap_keys()
    return app


def _user(app, email, role="student", name="Student"):
    with app.app_context():
        return create_user(name, email, "555", "password", role=role)


def _authenticate(client, app, user_id):
    with app.app_context():
        otp.store_otp(user_id, "004271")
    with client.session_transaction() as state:
        state["pending_auth_user_id"] = user_id
    assert client.post("/verify-otp", data={"otp": "004271"}).status_code == 302


def _make_post(client):
    response = client.post("/posts/new", data={"title": "Complaint", "description": "Details"})
    assert response.status_code == 302
    return int(response.location.rsplit("/", 1)[-1])


def _post_owner(app, post_id):
    with app.app_context():
        return db.query_one("SELECT owner_id FROM posts WHERE id = ?", (post_id,))["owner_id"]


def _count(app, post_id):
    with app.app_context():
        return get_upvote_count(post_id)


def _has_upvoted(app, user_id, post_id):
    with app.app_context():
        return has_user_upvoted(user_id, post_id)


def test_upvote_requires_login(upvote_app):
    with upvote_app.test_client() as client:
        assert client.post("/posts/1/upvote").status_code == 302


def test_upvote_increments_count(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as owner_client:
        _authenticate(owner_client, upvote_app, owner)
        post_id = _make_post(owner_client)
    with upvote_app.test_client() as voter_client:
        _authenticate(voter_client, upvote_app, voter)
        assert voter_client.post(f"/posts/{post_id}/upvote").status_code == 302
        detail = voter_client.get(f"/posts/{post_id}")
    assert b"Upvotes: 1" in detail.data
    assert _count(upvote_app, post_id) == 1


def test_duplicate_upvote_rejected(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, voter)
        assert client.post(f"/posts/{post_id}/upvote").status_code == 302
        duplicate = client.post(f"/posts/{post_id}/upvote")
    assert duplicate.status_code == 409
    assert b"UNIQUE constraint" not in duplicate.data
    assert _count(upvote_app, post_id) == 1


def test_owner_cannot_upvote_own_post(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
        response = client.post(f"/posts/{post_id}/upvote")
    assert response.status_code == 403
    assert _count(upvote_app, post_id) == 0


def test_owner_cannot_upvote_own_anonymous_post(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        response = client.post("/posts/new", data={"title": "Anonymous", "description": "Details", "anonymous": "on"})
        post_id = int(response.location.rsplit("/", 1)[-1])
        denied = client.post(f"/posts/{post_id}/upvote")
    assert denied.status_code == 403
    assert _count(upvote_app, post_id) == 0


def test_admin_cannot_upvote(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    admin = _user(upvote_app, "admin@example.com", role="admin", name="Admin")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, admin)
        response = client.post(f"/posts/{post_id}/upvote")
    assert response.status_code == 403
    assert _count(upvote_app, post_id) == 0


def test_missing_post_upvote_returns_clean_404(upvote_app):
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, voter)
        response = client.post("/posts/999/upvote")
    assert response.status_code == 404
    assert b"no such table" not in response.data.lower()


def test_second_student_can_upvote_same_post(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    first = _user(upvote_app, "first@example.com")
    second = _user(upvote_app, "second@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    for user_id in (first, second):
        with upvote_app.test_client() as client:
            _authenticate(client, upvote_app, user_id)
            assert client.post(f"/posts/{post_id}/upvote").status_code == 302
    assert _count(upvote_app, post_id) == 2


def test_upvote_count_matches_database_rows(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, voter)
        client.post(f"/posts/{post_id}/upvote")
    with upvote_app.app_context():
        rows = db.query_one("SELECT COUNT(*) AS count FROM upvotes WHERE post_id = ?", (post_id,))["count"]
    assert _count(upvote_app, post_id) == rows == 1


def test_has_user_upvoted_true_after_insert(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    assert _has_upvoted(upvote_app, voter, post_id) is False
    with upvote_app.app_context():
        upvote_post(voter, post_id)
    assert _has_upvoted(upvote_app, voter, post_id) is True


def test_has_user_upvoted_false_before_insert(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    assert _has_upvoted(upvote_app, voter, post_id) is False


def test_crafted_user_id_is_ignored(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, voter)
        response = client.post(f"/posts/{post_id}/upvote", data={"user_id": owner})
    assert response.status_code == 302
    with upvote_app.app_context():
        assert db.query_one("SELECT user_id FROM upvotes WHERE post_id = ?", (post_id,))["user_id"] == voter


def test_owner_self_upvote_creates_no_row(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
        client.post(f"/posts/{post_id}/upvote")
    with upvote_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM upvotes WHERE post_id = ?", (post_id,))["count"] == 0


def test_duplicate_upvote_creates_only_one_row(upvote_app):
    owner = _user(upvote_app, "owner@example.com")
    voter = _user(upvote_app, "voter@example.com")
    with upvote_app.test_client() as client:
        _authenticate(client, upvote_app, owner)
        post_id = _make_post(client)
    with upvote_app.app_context():
        upvote_post(voter, post_id)
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO upvotes (user_id, post_id) VALUES (?, ?)", (voter, post_id))
        assert db.query_one("SELECT COUNT(*) AS count FROM upvotes WHERE post_id = ?", (post_id,))["count"] == 1
