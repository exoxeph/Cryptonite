import hashlib

import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user, find_user_by_email, get_profile
from crypto import key_manager
from database import db
from services import email_service


class ProfileConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-profile-flow-123456"
    DATABASE_PATH = ""
    RSA_PRIME_BITS = 128
    RSA_PUBLIC_EXPONENT = 11
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
def profile_app(tmp_path):
    root = key_manager.rsa_generate_keypair(128)
    ProfileConfig.DATABASE_PATH = str(tmp_path / "profile.db")
    ProfileConfig.ROOT_RSA_E, ProfileConfig.ROOT_RSA_N = map(str, root["public"])
    ProfileConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(ProfileConfig)
    with app.app_context():
        db.init_db()
        key_manager.bootstrap_keys()
    return app


def _create_user(app, email, name="Alice", contact="111"):
    with app.app_context():
        return create_user(name, email, contact, "password")


def _authenticate(client, app, user_id):
    with app.app_context():
        otp.store_otp(user_id, "004271")
    with client.session_transaction() as flask_session:
        flask_session["pending_auth_user_id"] = user_id
    response = client.post("/verify-otp", data={"otp": "004271"})
    assert response.status_code == 302


def _row(app, user_id):
    with app.app_context():
        return db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def test_unauthenticated_profile_requests_are_rejected(profile_app):
    with profile_app.test_client() as client:
        assert client.get("/profile").status_code == 302
        assert client.post("/profile", data={}).status_code == 302


def test_profile_view_shows_decrypted_data_to_owner(profile_app):
    user_id = _create_user(profile_app, "alice@example.com")
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        response = client.get("/profile")
    assert response.status_code == 200
    assert b"Alice" in response.data
    assert b"alice@example.com" in response.data
    assert b"111" in response.data
    assert b"profile_key_version" not in response.data


def test_profile_view_denies_other_user(profile_app):
    alice_id = _create_user(profile_app, "alice@example.com", "Alice")
    bob_id = _create_user(profile_app, "bob@example.com", "Bob", "222")
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, alice_id)
        response = client.get(f"/profile?user_id={bob_id}")
    assert response.status_code == 200
    assert b"Alice" in response.data
    assert b"Bob" not in response.data
    assert b"222" not in response.data


def test_profile_update_reencrypts_with_active_key(profile_app):
    user_id = _create_user(profile_app, "alice@example.com")
    before = _row(profile_app, user_id)
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        response = client.post(
            "/profile",
            data={"name": "Alice Updated", "email": " NEW@Example.COM ", "contact": "999"},
        )
        assert response.status_code == 302
        page = client.get("/profile")
    after = _row(profile_app, user_id)
    assert b"Alice Updated" in page.data
    assert b"new@example.com" in page.data
    assert b"999" in page.data
    with profile_app.app_context():
        active_version = key_manager.get_active_key("RSA_PROFILE")["version"]
    assert after["profile_key_version"] == active_version
    assert after["email_lookup_hash"] == hashlib.sha256(b"new@example.com").digest()
    assert all(after[field] != before[field] for field in ("encrypted_name", "encrypted_email", "encrypted_contact"))
    assert all(after[field] != value for field, value in (
        ("encrypted_name", b"Alice Updated"),
        ("encrypted_email", b"new@example.com"),
        ("encrypted_contact", b"999"),
    ))


def test_profile_view_reads_historical_key_after_rotation(profile_app):
    user_id = _create_user(profile_app, "alice@example.com")
    with profile_app.app_context():
        version_one = _row(profile_app, user_id)["profile_key_version"]
        key_manager.rotate_key("RSA_PROFILE")
        assert key_manager.get_active_key("RSA_PROFILE")["version"] != version_one
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        response = client.get("/profile")
    assert response.status_code == 200
    assert b"Alice" in response.data
    assert _row(profile_app, user_id)["profile_key_version"] == version_one


def test_profile_update_reencrypts_all_fields_after_rotation(profile_app):
    user_id = _create_user(profile_app, "alice@example.com")
    before = _row(profile_app, user_id)
    with profile_app.app_context():
        active = key_manager.rotate_key("RSA_PROFILE")
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        response = client.post("/profile", data={"name": "Alice 2", "email": "alice@example.com", "contact": "111"})
        assert response.status_code == 302
        assert client.get("/profile").status_code == 200
    after = _row(profile_app, user_id)
    assert after["profile_key_version"] == active["version"]
    assert after["encrypted_name"] != before["encrypted_name"]
    with profile_app.app_context():
        assert get_profile(user_id) == {"name": "Alice 2", "email": "alice@example.com", "contact": "111"}


def test_profile_rewrite_of_unchanged_values_uses_textbook_determinism(profile_app):
    user_id = _create_user(profile_app, "alice@example.com")
    before = _row(profile_app, user_id)
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        assert client.post("/profile", data={"name": "Alice", "email": "alice@example.com", "contact": "111"}).status_code == 302
    after = _row(profile_app, user_id)
    assert all(after[field] == before[field] for field in ("encrypted_name", "encrypted_email", "encrypted_contact"))


def test_profile_update_ignores_crafted_target_user_id(profile_app):
    alice_id = _create_user(profile_app, "alice@example.com", "Alice")
    bob_id = _create_user(profile_app, "bob@example.com", "Bob", "222")
    bob_before = _row(profile_app, bob_id)
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, alice_id)
        assert client.post(
            "/profile?user_id=" + str(bob_id),
            data={"user_id": bob_id, "name": "Alice Changed", "email": "alice@example.com", "contact": "333"},
        ).status_code == 302
    bob_after = _row(profile_app, bob_id)
    assert bob_after["encrypted_name"] == bob_before["encrypted_name"]
    assert bob_after["encrypted_contact"] == bob_before["encrypted_contact"]


def test_duplicate_email_update_is_rejected_without_changes(profile_app):
    alice_id = _create_user(profile_app, "alice@example.com")
    _create_user(profile_app, "bob@example.com", "Bob", "222")
    before = _row(profile_app, alice_id)
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, alice_id)
        response = client.post("/profile", data={"name": "Changed", "email": "bob@example.com", "contact": "333"})
    after = _row(profile_app, alice_id)
    assert response.status_code == 200
    assert b"Profile could not be updated" in response.data
    assert tuple(after[field] for field in ("encrypted_name", "encrypted_email", "encrypted_contact", "email_lookup_hash", "profile_key_version")) == tuple(
        before[field] for field in ("encrypted_name", "encrypted_email", "encrypted_contact", "email_lookup_hash", "profile_key_version")
    )


def test_email_lookup_changes_with_profile_email(profile_app):
    user_id = _create_user(profile_app, "alice@example.com")
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        assert client.post("/profile", data={"name": "Alice", "email": " NEW@Example.COM ", "contact": "111"}).status_code == 302
    with profile_app.app_context():
        assert find_user_by_email("new@example.com")["id"] == user_id
        assert find_user_by_email("alice@example.com") is None


def test_profile_email_update_supports_end_to_end_login(profile_app, monkeypatch):
    user_id = _create_user(profile_app, "old@example.com")
    sent = []
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, user_id)
        assert client.post(
            "/profile",
            data={"name": "Alice", "email": "new@example.com", "contact": "111"},
        ).status_code == 302
        with profile_app.app_context():
            row = _row(profile_app, user_id)
            assert row["email_lookup_hash"] == hashlib.sha256(b"new@example.com").digest()
            assert row["encrypted_email"] != b"new@example.com"
            assert row["profile_key_version"] == key_manager.get_active_key("RSA_PROFILE")["version"]

        with profile_app.app_context():
            otp_count_before_old_login = db.query_one("SELECT COUNT(*) AS count FROM otp_codes")["count"]
        old_login = client.post("/login", data={"email": "old@example.com", "password": "password"})
        assert old_login.status_code == 200
        assert b"Invalid email or password." in old_login.data
        with profile_app.app_context():
            assert db.query_one("SELECT COUNT(*) AS count FROM otp_codes")["count"] == otp_count_before_old_login

        monkeypatch.setattr(email_service, "send_otp_email", lambda address, code: sent.append((address, code)))
        new_login = client.post("/login", data={"email": " NEW@EXAMPLE.COM ", "password": "password"})
        assert new_login.status_code == 302
        assert new_login.location.endswith("/verify-otp")
        assert sent and sent[-1][0] == "new@example.com"
        assert client.post("/verify-otp", data={"otp": sent[-1][1]}).status_code == 302


def test_duplicate_email_update_preserves_original_login(profile_app, monkeypatch):
    alice_id = _create_user(profile_app, "alice@example.com")
    _create_user(profile_app, "bob@example.com", "Bob", "222")
    before = _row(profile_app, alice_id)
    sent = []
    with profile_app.test_client() as client:
        _authenticate(client, profile_app, alice_id)
        response = client.post("/profile", data={"name": "Changed", "email": "bob@example.com", "contact": "333"})
        assert response.status_code == 200
        after = _row(profile_app, alice_id)
        assert tuple(after[field] for field in ("encrypted_name", "encrypted_email", "encrypted_contact", "email_lookup_hash", "profile_key_version")) == tuple(
            before[field] for field in ("encrypted_name", "encrypted_email", "encrypted_contact", "email_lookup_hash", "profile_key_version")
        )
        monkeypatch.setattr(email_service, "send_otp_email", lambda address, code: sent.append((address, code)))
        original_login = client.post("/login", data={"email": " ALICE@EXAMPLE.COM ", "password": "password"})
        assert original_login.status_code == 302
        assert sent and sent[-1][0] == "alice@example.com"
