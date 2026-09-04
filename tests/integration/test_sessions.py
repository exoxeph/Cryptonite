import hashlib

import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from auth import sessions as auth_sessions
from crypto.hmac_custom import generate_mac
from crypto import key_manager
from database import db


class SessionConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-session-flow-123456"
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
def session_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    SessionConfig.DATABASE_PATH = str(tmp_path / "sessions.db")
    SessionConfig.ROOT_RSA_E, SessionConfig.ROOT_RSA_N = map(str, root["public"])
    SessionConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(SessionConfig)
    with app.app_context():
        db.init_db()
        key_manager.bootstrap_keys()
    return app


def _authenticate(client, app):
    with app.app_context():
        user_id = create_user("User", "session@example.com", "555", "secret")
        code = "004271"
        otp.store_otp(user_id, code)
    with client.session_transaction() as flask_session:
        flask_session["pending_auth_user_id"] = user_id
    response = client.post("/verify-otp", data={"otp": code})
    cookie = client.get_cookie(app.config["AUTH_SESSION_COOKIE_NAME"])
    return user_id, response, cookie.value


def test_otp_creates_hashed_server_session_and_cookie_flags(session_app):
    with session_app.test_client() as client:
        user_id, response, cookie_value = _authenticate(client, session_app)
        assert response.status_code == 302
        assert response.location.endswith("/dashboard")
        assert "HttpOnly" in response.headers["Set-Cookie"]
        assert "SameSite=Lax" in response.headers["Set-Cookie"]
        assert "Secure" not in response.headers["Set-Cookie"]
        assert client.get("/dashboard").status_code == 200
        with client.session_transaction() as flask_session:
            assert "pending_auth_user_id" not in flask_session
    session_id = cookie_value.split(".")[0]
    with session_app.app_context():
        row = db.query_one("SELECT * FROM sessions")
        assert row["user_id"] == user_id and row["active"] == 1
        assert row["session_id_hash"] == hashlib.sha256(session_id.encode("ascii")).digest()
        assert row["session_id_hash"] != session_id.encode("ascii")


def test_flask_secret_key_is_separate_from_hmac_session_key(session_app):
    with session_app.app_context():
        hmac_session_key = key_manager.get_active_key("HMAC_SESSION")["private_key"]
    assert session_app.config["SECRET_KEY"].encode("utf-8") != hmac_session_key


@pytest.mark.parametrize("part", [0, 1, 2])
def test_tampered_cookie_parts_are_rejected(session_app, part):
    with session_app.test_client() as client:
        _, _, cookie_value = _authenticate(client, session_app)
        parts = cookie_value.split(".")
        parts[part] = (
            ("x" if part != 2 else ("0" if parts[part][0] != "0" else "1"))
            + parts[part][1:]
        )
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], ".".join(parts))
        assert client.get("/dashboard").status_code == 302


def test_missing_malformed_unknown_expired_and_mismatched_sessions_are_rejected(session_app):
    with session_app.test_client() as client:
        assert client.get("/dashboard").status_code == 302
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], "malformed")
        assert client.get("/dashboard").status_code == 302
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], "unknown.2099-01-01T00:00:00Z." + "0" * 64)
        assert client.get("/dashboard").status_code == 302
        user_id, _, cookie_value = _authenticate(client, session_app)
        session_id = cookie_value.split(".")[0]
        expired_at = "2000-01-01T00:00:00Z"
        with session_app.app_context():
            db.execute("UPDATE sessions SET expires_at = ?", (expired_at,))
            key = key_manager.get_active_key("HMAC_SESSION")["private_key"]
            expired_signature = generate_mac(key, auth_sessions._payload(session_id, user_id, expired_at)).hex()
        expired_cookie = f"{session_id}.{expired_at}.{expired_signature}"
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], expired_cookie)
        assert client.get("/dashboard").status_code == 302
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], cookie_value)
        assert client.get("/dashboard").status_code == 302


def test_cookie_and_database_expiry_must_match(session_app):
    with session_app.test_client() as client:
        _, _, cookie_value = _authenticate(client, session_app)
        with session_app.app_context():
            db.execute("UPDATE sessions SET expires_at = '2099-01-01T00:00:00Z'")
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], cookie_value)
        assert client.get("/dashboard").status_code == 302


def _assert_malformed_token_rejected(app, token):
    with app.test_client() as client:
        client.set_cookie(app.config["AUTH_SESSION_COOKIE_NAME"], token)
        response = client.get("/dashboard")
        assert response.status_code == 302


def test_empty_session_token_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "")


def test_single_component_token_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "abc")


def test_two_component_token_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "abc.def")


def test_extra_component_token_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "a.b.c.d")


def test_invalid_timestamp_token_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "session.not-a-time." + "0" * 64)


def test_empty_signature_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "session.2099-01-01T00:00:00Z.")


def test_non_hex_signature_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "session.2099-01-01T00:00:00Z." + "z" * 64)


def test_wrong_length_signature_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "session.2099-01-01T00:00:00Z." + "0" * 63)


def test_extremely_long_malformed_token_rejected(session_app):
    _assert_malformed_token_rejected(session_app, "x" * 2048)


def test_logout_revokes_database_row_and_old_cookie_replay_fails(session_app):
    with session_app.test_client() as client:
        _, _, cookie_value = _authenticate(client, session_app)
        logout = client.post("/logout")
        assert logout.status_code == 302
        assert "Max-Age=0" in logout.headers["Set-Cookie"]
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], cookie_value)
        assert client.get("/dashboard").status_code == 302
    with session_app.app_context():
        assert db.query_one("SELECT active FROM sessions")["active"] == 0


def test_hmac_session_rotation_invalidates_old_cookie(session_app):
    with session_app.test_client() as client:
        user_id, _, old_cookie = _authenticate(client, session_app)
        with session_app.app_context():
            key_manager.rotate_key("HMAC_SESSION")
        client.set_cookie(session_app.config["AUTH_SESSION_COOKIE_NAME"], old_cookie)
        assert client.get("/dashboard").status_code == 302
        with session_app.app_context():
            otp.store_otp(user_id, "117733")
        with client.session_transaction() as flask_session:
            flask_session["pending_auth_user_id"] = user_id
        assert client.post("/verify-otp", data={"otp": "117733"}).status_code == 302
        assert client.get("/dashboard").status_code == 200
