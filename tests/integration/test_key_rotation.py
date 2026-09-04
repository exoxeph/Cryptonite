import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from crypto import key_manager
from database import db


class KeyRotationConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-key-rotation-123456"
    DATABASE_PATH = ""
    RSA_KEY_BITS = 1024
    ROOT_RSA_N = ROOT_RSA_E = ROOT_RSA_D = ""
    OTP_EXPIRY_SECONDS = 300
    MAX_EVIDENCE_SIZE_BYTES = 200 * 1024
    EVIDENCE_UPLOAD_DIR = ""
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_SECONDS = 3600


@pytest.fixture
def key_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    KeyRotationConfig.DATABASE_PATH = str(tmp_path / "key-rotation.db")
    KeyRotationConfig.EVIDENCE_UPLOAD_DIR = str(tmp_path / "encrypted_uploads")
    KeyRotationConfig.ROOT_RSA_E, KeyRotationConfig.ROOT_RSA_N = map(str, root["public"])
    KeyRotationConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(KeyRotationConfig)
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


def _create_post(client, title):
    response = client.post(
        "/posts/new",
        data={"title": title, "description": "Rotation demonstration", "anonymous": ""},
    )
    assert response.status_code == 302
    return int(response.location.rsplit("/", 1)[-1])


def _key_rows(app, purpose):
    with app.app_context():
        return db.query_all(
            "SELECT version, status FROM keys WHERE purpose = ? ORDER BY version", (purpose,)
        )


def _post_row(app, post_id):
    with app.app_context():
        return db.query_one(
            "SELECT encrypted_title, encrypted_description, ecc_key_version FROM posts WHERE id = ?",
            (post_id,),
        )


def test_admin_can_view_key_status(key_app):
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        response = client.get("/admin/keys")
    assert response.status_code == 200
    assert b"ECC_POSTS" in response.data
    assert b"ACTIVE" in response.data
    assert b"RETIRED" not in response.data


def test_key_status_listing_never_unwraps_private_material(key_app, monkeypatch):
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        monkeypatch.setattr("auth.decorators.get_current_user", lambda: {"id": admin, "role": "admin"})
        monkeypatch.setattr(key_manager, "_unwrap_private_key", lambda value: pytest.fail("private key was unwrapped"))
        assert client.get("/admin/keys").status_code == 200


def test_admin_can_rotate_ecc_posts(key_app):
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    before = _key_rows(key_app, "ECC_POSTS")
    old_version = before[-1]["version"]
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        response = client.post("/admin/keys/ECC_POSTS/rotate")
    assert response.status_code == 302
    rows = _key_rows(key_app, "ECC_POSTS")
    assert [(row["version"], row["status"]) for row in rows] == [
        (old_version, "RETIRED"),
        (old_version + 1, "ACTIVE"),
    ]


def test_old_data_decrypts_after_rotation(key_app):
    owner = _user(key_app, "owner@example.com")
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    with key_app.test_client() as client:
        _authenticate(client, key_app, owner)
        post_id = _create_post(client, "Post A")
    before = _post_row(key_app, post_id)

    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        assert client.post("/admin/keys/ECC_POSTS/rotate").status_code == 302

    after = _post_row(key_app, post_id)
    assert tuple(after) == tuple(before)
    with key_app.test_client() as client:
        _authenticate(client, key_app, owner)
        response = client.get(f"/posts/{post_id}")
    assert response.status_code == 200
    assert b"Post A" in response.data


def test_new_data_uses_new_version_after_rotation(key_app):
    owner = _user(key_app, "owner@example.com")
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    with key_app.test_client() as client:
        _authenticate(client, key_app, owner)
        post_a = _create_post(client, "Post A")
    old_version = _post_row(key_app, post_a)["ecc_key_version"]
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        assert client.post("/admin/keys/ECC_POSTS/rotate").status_code == 302
    with key_app.test_client() as client:
        _authenticate(client, key_app, owner)
        post_b = _create_post(client, "Post B")
    assert _post_row(key_app, post_a)["ecc_key_version"] == old_version
    assert _post_row(key_app, post_b)["ecc_key_version"] == old_version + 1
    with key_app.test_client() as client:
        _authenticate(client, key_app, owner)
        assert client.get(f"/posts/{post_a}").status_code == 200
        assert client.get(f"/posts/{post_b}").status_code == 200


def test_only_one_active_key_per_purpose_at_any_time(key_app):
    purposes = tuple(key_manager.PURPOSE_ALGORITHMS)
    with key_app.app_context():
        for purpose in purposes:
            assert db.query_one(
                "SELECT COUNT(*) AS count FROM keys WHERE purpose = ? AND status = 'ACTIVE'",
                (purpose,),
            )["count"] == 1
        key_manager.rotate_key("ECC_POSTS")
        key_manager.rotate_key("HMAC_CHAT")
        for purpose in purposes:
            assert db.query_one(
                "SELECT COUNT(*) AS count FROM keys WHERE purpose = ? AND status = 'ACTIVE'",
                (purpose,),
            )["count"] == 1


def test_student_cannot_view_or_rotate_keys(key_app):
    student = _user(key_app, "student@example.com")
    with key_app.test_client() as client:
        _authenticate(client, key_app, student)
        assert client.get("/admin/keys").status_code == 403
        assert client.post("/admin/keys/ECC_POSTS/rotate").status_code == 403


def test_unauthenticated_cannot_view_or_rotate_keys(key_app):
    with key_app.test_client() as client:
        assert client.get("/admin/keys").status_code == 302
        assert client.post("/admin/keys/ECC_POSTS/rotate").status_code == 302


def test_invalid_key_purpose_rejected(key_app):
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        response = client.post("/admin/keys/FOO/rotate", data={"algorithm": "RSA", "version": "99"})
    assert response.status_code == 400
    assert not _key_rows(key_app, "ECC_POSTS")[0]["status"] == "REVOKED"


def test_rotation_route_is_post_only(key_app):
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    before = _key_rows(key_app, "ECC_POSTS")
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        assert client.get("/admin/keys/ECC_POSTS/rotate").status_code == 405
    assert _key_rows(key_app, "ECC_POSTS") == before


def test_crafted_admin_role_does_not_bypass_key_rbac(key_app):
    student = _user(key_app, "student@example.com")
    before = _key_rows(key_app, "ECC_POSTS")
    with key_app.test_client() as client:
        _authenticate(client, key_app, student)
        response = client.post(
            "/admin/keys/ECC_POSTS/rotate",
            data={"role": "admin", "admin": "true", "user_id": "999", "actor_id": "999"},
        )
    assert response.status_code == 403
    assert _key_rows(key_app, "ECC_POSTS") == before


def test_key_page_exposes_metadata_not_secrets(key_app):
    admin = _user(key_app, "admin@example.com", role="admin", name="Admin")
    with key_app.app_context():
        hmac = key_manager.get_active_key("HMAC_CHAT")
        root_private = str(key_app.config["ROOT_RSA_D"])
        hmac_secret = hmac["private_key"].hex()
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        response = client.get("/admin/keys")
    body = response.data.decode("utf-8")
    assert "ECC_POSTS" in body and "ACTIVE" in body
    assert root_private not in body
    assert hmac_secret not in body
    assert "encrypted_private_key" not in body
