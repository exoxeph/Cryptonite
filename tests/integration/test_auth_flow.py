from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app import create_app
from crypto import key_manager
from database import db
from auth import otp
from auth.account_service import create_user
from services import email_service


class AuthConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-auth-flow-123456789"
    DATABASE_PATH = ""
    RSA_PRIME_BITS = 128
    RSA_PUBLIC_EXPONENT = 11
    ROOT_RSA_N = ""
    ROOT_RSA_E = ""
    ROOT_RSA_D = ""
    OTP_EXPIRY_SECONDS = 300
    EMAIL_API_PROVIDER = "resend"
    EMAIL_API_KEY = "test-key"
    EMAIL_FROM_ADDRESS = "test@example.com"
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_SECONDS = 3600


@pytest.fixture
def auth_app(tmp_path):
    root = key_manager.rsa_generate_keypair(128)
    AuthConfig.DATABASE_PATH = str(tmp_path / "auth.db")
    AuthConfig.ROOT_RSA_E, AuthConfig.ROOT_RSA_N = map(str, root["public"])
    AuthConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(AuthConfig)
    with app.app_context():
        db.init_db()
        key_manager.bootstrap_keys()
    return app


def test_register_creates_encrypted_student(auth_app):
    with auth_app.test_client() as client:
        response = client.post("/register", data={"name": "Alice", "bracu_id": "22101234", "email": " User@Example.com ", "contact": "1700000000", "password": "Secret123"})
    assert response.status_code == 302
    with auth_app.app_context():
        row = db.query_one("SELECT * FROM users")
        assert row["role"] == "student"
        assert row["email_lookup_hash"] == __import__("hashlib").sha256(b"user@example.com").digest()
        assert row["profile_key_version"] == key_manager.get_active_key("RSA_PROFILE")["version"]
        assert row["encrypted_name"] != b"Alice"
        assert row["encrypted_email"] != b"user@example.com"
        assert row["encrypted_contact"] != b"555"
        assert row["password_hash"] != b"secret"
        assert json.loads(row["encrypted_name"])


def test_registration_has_no_role_selector_and_crafted_admin_stays_student(auth_app):
    with auth_app.test_client() as client:
        page = client.get("/register")
        assert b'name="role"' not in page.data
        client.post("/register", data={"name": "Bob", "bracu_id": "22101235", "email": "bob@example.com", "contact": "1700000000", "password": "Secret123", "role": "admin"})
    with auth_app.app_context():
        assert db.query_one("SELECT role FROM users WHERE email_lookup_hash = ?", (__import__("hashlib").sha256(b"bob@example.com").digest(),))["role"] == "student"


def test_registration_rejects_invalid_student_identity_and_password(auth_app):
    with auth_app.test_client() as client:
        response = client.post(
            "/register",
            data={"name": "Student 7", "bracu_id": "123", "email": "bad@example.com", "contact": "123", "password": "weak"},
        )
    assert response.status_code == 200
    assert b"Name cannot contain numbers" in response.data or b"BRACU ID" in response.data
    with auth_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM users") ["count"] == 0


def test_duplicate_normalized_email_is_rejected(auth_app):
    with auth_app.test_client() as client:
        client.post("/register", data={"name": "A", "bracu_id": "22101236", "email": "a@example.com", "contact": "1700000000", "password": "Secret123"})
        response = client.post("/register", data={"name": "B", "bracu_id": "22101237", "email": " A@EXAMPLE.COM ", "contact": "1700000001", "password": "Secret123"})
    assert response.status_code == 200
    with auth_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM users")["count"] == 1


def test_controlled_seed_creates_encrypted_admin(auth_app):
    from database.seed import create_demo_admin

    with auth_app.app_context():
        create_demo_admin("Admin", "admin@example.com", "999", "admin-password")
        row = db.query_one("SELECT * FROM users WHERE role = 'admin'")
        assert row is not None
        assert len(row["password_hash"]) == 32
        assert len(row["password_salt"]) == 16
        assert row["encrypted_name"] != b"Admin"
        assert row["password_hash"] != b"admin-password"


def _register(client, email="user@example.com"):
    return client.post(
        "/register",
        data={"name": "User", "bracu_id": "22101234", "email": email, "contact": "1700000000", "password": "Secret123"},
    )


def test_login_normalizes_email_and_sends_otp_without_session(auth_app, monkeypatch):
    sent = []
    with auth_app.test_client() as client:
        _register(client, "user@example.com")
        monkeypatch.setattr(email_service, "send_otp_email", lambda address, code: sent.append((address, code)))
        response = client.post("/login", data={"email": " USER@EXAMPLE.COM ", "password": "Secret123"})
        assert response.status_code == 302
        assert response.location.endswith("/verify-otp")
        with client.session_transaction() as flask_session:
            assert isinstance(flask_session["pending_auth_user_id"], int)
    assert len(sent) == 1
    with auth_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM sessions")["count"] == 0
        otp_row = db.query_one("SELECT * FROM otp_codes")
        assert len(otp_row["otp_hash"]) == 32
        assert len(otp_row["otp_salt"]) == 16
        assert sent[0][1].encode() not in otp_row["otp_hash"]


def test_invalid_login_is_generic_and_creates_no_otp(auth_app, monkeypatch):
    with auth_app.test_client() as client:
        _register(client)
        monkeypatch.setattr(email_service, "send_otp_email", lambda *_: pytest.fail("email must not be sent"))
        wrong = client.post("/login", data={"email": "user@example.com", "password": "wrong"})
        unknown = client.post("/login", data={"email": "missing@example.com", "password": "wrong"})
    assert wrong.status_code == unknown.status_code == 200
    assert b"Invalid email or password." in wrong.data
    assert b"Invalid email or password." in unknown.data
    with auth_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM otp_codes")["count"] == 0


def test_otp_generation_and_verification_lifecycle(auth_app):
    with auth_app.app_context():
        user_id = create_user("User", "otp@example.com", "555", "secret")
        code = otp.generate_otp()
        assert len(code) == 6 and code.isdigit()
        otp.store_otp(user_id, code)
        assert otp.verify_otp(user_id, code)
        assert not otp.verify_otp(user_id, code)
        assert db.query_one("SELECT used FROM otp_codes") ["used"] == 1


def test_otp_wrong_malformed_and_expired_codes_fail(auth_app):
    with auth_app.app_context():
        user_id = create_user("User", "expired@example.com", "555", "secret")
        code = "004271"
        otp.store_otp(user_id, code)
        assert not otp.verify_otp(user_id, "004272")
        assert not otp.verify_otp(user_id, "bad")
        expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        db.execute("UPDATE otp_codes SET expires_at = ?", (expired,))
        assert not otp.verify_otp(user_id, code)


def test_email_failure_invalidates_otp_and_pending_state(auth_app, monkeypatch):
    with auth_app.test_client() as client:
        _register(client)
        monkeypatch.setattr(email_service, "send_otp_email", lambda *_: (_ for _ in ()).throw(email_service.EmailDeliveryError()))
        response = client.post("/login", data={"email": "user@example.com", "password": "Secret123"})
        assert response.status_code == 200
        assert b"Verification code could not be sent. Please try again." in response.data
        with client.session_transaction() as flask_session:
            assert "pending_auth_user_id" not in flask_session
    with auth_app.app_context():
        row = db.query_one("SELECT * FROM otp_codes")
        assert row["used"] == 1
        assert not otp.verify_otp(1, "000000")


def test_failed_older_delivery_does_not_invalidate_newer_otp(auth_app, monkeypatch):
    sent = []
    attempts = 0

    def deliver(_address, code):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise email_service.EmailDeliveryError()
        sent.append(code)

    with auth_app.test_client() as client:
        _register(client)
        monkeypatch.setattr(email_service, "send_otp_email", deliver)
        first = client.post("/login", data={"email": "user@example.com", "password": "Secret123"})
        second = client.post("/login", data={"email": "user@example.com", "password": "Secret123"})
        assert first.status_code == 200
        assert second.status_code == 302
        assert sent and client.post("/verify-otp", data={"otp": sent[0]}).status_code == 302


def test_verify_route_requires_pending_auth_and_creates_session_after_otp(auth_app, monkeypatch):
    with auth_app.test_client() as client:
        assert client.get("/verify-otp").status_code == 302
        _register(client)
        sent = []
        monkeypatch.setattr(email_service, "send_otp_email", lambda _address, code: sent.append(code))
        client.post("/login", data={"email": "user@example.com", "password": "Secret123"})
        response = client.post("/verify-otp", data={"otp": sent[0]})
        assert response.status_code == 302
        assert response.location.endswith("/dashboard")
        with client.session_transaction() as flask_session:
            assert "pending_auth_user_id" not in flask_session
    with auth_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM sessions")["count"] == 1


def test_dev_otp_print_mode_preserves_login_flow_without_email(auth_app, capsys):
    auth_app.config["OTP_EMAIL_ENABLED"] = False
    auth_app.config["OTP_DEV_PRINT_CODE"] = True
    with auth_app.test_client() as client:
        _register(client, "dev@example.com")
        response = client.post("/login", data={"email": "dev@example.com", "password": "Secret123"})
        assert response.status_code == 302
        output = capsys.readouterr().out
        code = output.rsplit(": ", 1)[-1].strip()
        assert len(code) == 6 and code.isdigit()
        assert client.post("/verify-otp", data={"otp": code}).status_code == 302
