import json

import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from crypto import key_manager
from database import db


class PostsConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-posts-flow-123456"
    DATABASE_PATH = ""
    RSA_KEY_BITS = 1024
    ROOT_RSA_N = ""
    ROOT_RSA_E = ""
    ROOT_RSA_D = ""
    OTP_EXPIRY_SECONDS = 300
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_SECONDS = 3600


@pytest.fixture
def posts_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    PostsConfig.DATABASE_PATH = str(tmp_path / "posts.db")
    PostsConfig.ROOT_RSA_E, PostsConfig.ROOT_RSA_N = map(str, root["public"])
    PostsConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(PostsConfig)
    with app.app_context():
        db.init_db()
        key_manager.bootstrap_keys()
    return app


def _user(app, email, role="student", name="Student", contact="555"):
    with app.app_context():
        return create_user(name, email, contact, "password", role=role)


def _authenticate(client, app, user_id):
    with app.app_context():
        otp.store_otp(user_id, "004271")
    with client.session_transaction() as flask_session:
        flask_session["pending_auth_user_id"] = user_id
    response = client.post("/verify-otp", data={"otp": "004271"})
    assert response.status_code == 302


def _post_row(app, post_id):
    with app.app_context():
        return db.query_one("SELECT * FROM posts WHERE id = ?", (post_id,))


def _create_post(client, title="Complaint", description="Details", anonymous=False, **extra):
    data = {"title": title, "description": description}
    if anonymous:
        data["anonymous"] = "on"
    data.update(extra)
    return client.post("/posts/new", data=data)


def test_public_post_listing_requires_login(posts_app):
    with posts_app.test_client() as client:
        assert client.get("/posts").status_code == 302


def test_post_detail_requires_login(posts_app):
    with posts_app.test_client() as client:
        assert client.get("/posts/1").status_code == 302


def test_create_post_stores_ciphertext(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        response = _create_post(client, "Broken gate", "The gate does not lock")
    assert response.status_code == 302
    post_id = int(response.location.rsplit("/", 1)[-1])
    row = _post_row(posts_app, post_id)
    assert row["owner_id"] == user_id
    assert row["status"] == "Pending"
    assert row["anonymous"] == 0
    assert row["ecc_key_version"] == 1
    assert json.loads(row["encrypted_title"])
    assert json.loads(row["encrypted_description"])
    assert row["encrypted_title"] != "Broken gate"
    assert row["encrypted_description"] != "The gate does not lock"


def test_public_post_listing_decrypts_title_only(posts_app):
    user_id = _user(posts_app, "alice@example.com", name="Alice")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        _create_post(client, "Broken gate", "The gate does not lock")
        response = client.get("/posts")
    assert response.status_code == 200
    assert b"Broken gate" in response.data
    assert b"The gate does not lock" not in response.data
    assert b"Alice" not in response.data
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        detail = client.get("/posts/1")
    assert b"The gate does not lock" in detail.data
    assert b"Alice" in detail.data


def test_public_post_feed_paginates_before_decryption(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        for number in range(1, 12):
            _create_post(client, f"Complaint {number:02d}", f"Private description {number}")
        page_one = client.get("/posts?page=1")
        page_two = client.get("/posts?page=2")
    assert b"Page 1 of 2" in page_one.data
    assert b"Complaint 11" in page_one.data
    assert b"Complaint 01" not in page_one.data
    assert b"Private description" not in page_one.data
    assert b"Page 2 of 2" in page_two.data
    assert b"Complaint 01" in page_two.data


def test_student_dashboard_loads_only_recent_complaints(posts_app):
    user_id = _user(posts_app, "dashboard@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        for number in range(1, 7):
            _create_post(client, f"Dashboard complaint {number}", "Dashboard details")
        response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Dashboard complaint 6" in response.data
    assert b"Dashboard complaint 1" not in response.data
    assert b"6" in response.data


def test_non_anonymous_post_shows_owner_name(posts_app):
    user_id = _user(posts_app, "alice@example.com", name="Alice")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        post_response = _create_post(client, "Visible", "Visible details")
        response = client.get(post_response.location)
    assert b"Alice" in response.data


def test_anonymous_post_hides_owner_name_but_keeps_owner_id(posts_app):
    user_id = _user(posts_app, "alice@example.com", name="Alice")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        post_response = _create_post(client, "Private identity", "Sensitive details", anonymous=True)
        response = client.get(post_response.location)
    post_id = int(post_response.location.rsplit("/", 1)[-1])
    assert b"Anonymous Student" in response.data
    assert b"Alice" not in response.data
    assert _post_row(posts_app, post_id)["owner_id"] == user_id


def test_anonymous_post_does_not_expose_owner_name_in_response(posts_app):
    alice_id = _user(posts_app, "alice@example.com", name="Alice")
    bob_id = _user(posts_app, "bob@example.com", name="Bob")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, alice_id)
        post_response = _create_post(client, "Anonymous", "Details", anonymous=True)
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, bob_id)
        response = client.get(post_response.location)
    assert b"Anonymous Student" in response.data
    assert b"Alice" not in response.data


def test_owner_can_edit_own_post(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        created = _create_post(client)
        response = client.post(
            created.location.replace("/posts/", "/posts/") + "/edit",
            data={"title": "Updated", "description": "Updated details", "anonymous": "on"},
        )
    assert response.status_code == 302
    post_id = int(created.location.rsplit("/", 1)[-1])
    row = _post_row(posts_app, post_id)
    assert row["anonymous"] == 1
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        assert b"Updated" in client.get(f"/posts/{post_id}").data


def test_non_owner_cannot_edit_post(posts_app):
    owner_id = _user(posts_app, "owner@example.com")
    other_id = _user(posts_app, "other@example.com")
    with posts_app.test_client() as owner_client:
        _authenticate(owner_client, posts_app, owner_id)
        created = _create_post(owner_client)
    with posts_app.test_client() as other_client:
        _authenticate(other_client, posts_app, other_id)
        response = other_client.get(created.location + "/edit")
    assert response.status_code == 403


def test_crafted_owner_id_cannot_create_for_another_user(posts_app):
    alice_id = _user(posts_app, "alice@example.com")
    bob_id = _user(posts_app, "bob@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, alice_id)
        response = _create_post(client, owner_id=bob_id)
    post_id = int(response.location.rsplit("/", 1)[-1])
    assert _post_row(posts_app, post_id)["owner_id"] == alice_id


def test_crafted_owner_id_cannot_edit_another_users_post(posts_app):
    owner_id = _user(posts_app, "owner@example.com")
    other_id = _user(posts_app, "other@example.com")
    with posts_app.test_client() as owner_client:
        _authenticate(owner_client, posts_app, owner_id)
        created = _create_post(owner_client)
    post_id = int(created.location.rsplit("/", 1)[-1])
    with posts_app.test_client() as other_client:
        _authenticate(other_client, posts_app, other_id)
        response = other_client.post(
            f"/posts/{post_id}/edit",
            data={"owner_id": owner_id, "title": "Hijacked", "description": "No", "status": "Resolved"},
        )
    assert response.status_code == 403
    assert _post_row(posts_app, post_id)["status"] == "Pending"


def test_student_cannot_submit_status_change_during_edit(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        created = _create_post(client)
        post_id = int(created.location.rsplit("/", 1)[-1])
        assert client.post(
            f"/posts/{post_id}/edit",
            data={"title": "Still pending", "description": "Details", "status": "Resolved"},
        ).status_code == 302
    assert _post_row(posts_app, post_id)["status"] == "Pending"


def test_admin_can_view_public_post_list(posts_app):
    student_id = _user(posts_app, "student@example.com")
    admin_id = _user(posts_app, "admin@example.com", role="admin", name="Admin")
    with posts_app.test_client() as student_client:
        _authenticate(student_client, posts_app, student_id)
        _create_post(student_client, "Student complaint", "Details")
    with posts_app.test_client() as admin_client:
        _authenticate(admin_client, posts_app, admin_id)
        response = admin_client.get("/posts")
        create_response = admin_client.get("/posts/new")
    assert b"Student complaint" in response.data
    assert create_response.status_code == 403


@pytest.mark.parametrize(
    ("field", "valid_length", "invalid_length"),
    [("title", 120, 121), ("description", 500, 501)],
)
def test_post_title_and_description_length_limits(posts_app, field, valid_length, invalid_length):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        valid = {"title": "Title", "description": "Description"}
        valid[field] = "x" * valid_length
        invalid = dict(valid)
        invalid[field] = "x" * invalid_length
        assert _create_post(client, **valid).status_code == 302
        rejected = _create_post(client, **invalid)
    assert rejected.status_code == 200
    assert b"Complaint could not be created" in rejected.data


def test_empty_title_rejected(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        response = _create_post(client, title="", description="Details")
    assert response.status_code == 200


def test_empty_description_rejected(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        response = _create_post(client, title="Title", description="")
    assert response.status_code == 200


def test_historical_post_decrypts_after_ecc_rotation(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.app_context():
        from posts.services import create_post
        post_id = create_post(user_id, "Old title", "Old description", False)
        old_version = _post_row(posts_app, post_id)["ecc_key_version"]
        key_manager.rotate_key("ECC_POSTS")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        response = client.get(f"/posts/{post_id}")
    assert response.status_code == 200
    assert b"Old title" in response.data
    assert _post_row(posts_app, post_id)["ecc_key_version"] == old_version


def test_edit_reencrypts_both_fields_with_active_ecc_key(posts_app):
    user_id = _user(posts_app, "alice@example.com")
    with posts_app.app_context():
        from posts.services import create_post
        post_id = create_post(user_id, "Old title", "Old description", False)
        before = _post_row(posts_app, post_id)
        active = key_manager.rotate_key("ECC_POSTS")
    with posts_app.test_client() as client:
        _authenticate(client, posts_app, user_id)
        assert client.post(
            f"/posts/{post_id}/edit",
            data={"title": "New title", "description": "New description"},
        ).status_code == 302
    after = _post_row(posts_app, post_id)
    assert after["ecc_key_version"] == active["version"]
    assert after["encrypted_title"] != before["encrypted_title"]
    assert after["encrypted_description"] != before["encrypted_description"]
