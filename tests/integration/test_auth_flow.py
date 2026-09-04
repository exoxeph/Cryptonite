import json

import pytest

from app import create_app
from crypto import key_manager
from database import db


class AuthConfig:
    TESTING = True
    SECRET_KEY = "test"
    DATABASE_PATH = ""
    RSA_KEY_BITS = 1024
    ROOT_RSA_N = ""
    ROOT_RSA_E = ""
    ROOT_RSA_D = ""


@pytest.fixture
def auth_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
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
        response = client.post("/register", data={"name": "Alice", "email": " User@Example.com ", "contact": "555", "password": "secret"})
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
        client.post("/register", data={"name": "Bob", "email": "bob@example.com", "contact": "555", "password": "secret", "role": "admin"})
    with auth_app.app_context():
        assert db.query_one("SELECT role FROM users WHERE email_lookup_hash = ?", (__import__("hashlib").sha256(b"bob@example.com").digest(),))["role"] == "student"


def test_duplicate_normalized_email_is_rejected(auth_app):
    with auth_app.test_client() as client:
        client.post("/register", data={"name": "A", "email": "a@example.com", "contact": "1", "password": "secret"})
        response = client.post("/register", data={"name": "B", "email": " A@EXAMPLE.COM ", "contact": "2", "password": "secret"})
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
