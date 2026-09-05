import sqlite3

import pytest

from app import create_app
from database import db


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-db-schema-123456789"
    DATABASE_PATH = ""
    ROOT_RSA_N = ""
    ROOT_RSA_E = ""
    ROOT_RSA_D = ""
    RSA_PRIME_BITS = 128
    RSA_PUBLIC_EXPONENT = 11
    EMAIL_API_PROVIDER = ""
    EMAIL_API_KEY = ""
    EMAIL_FROM_ADDRESS = ""
    OTP_EXPIRY_SECONDS = 300
    MAX_EVIDENCE_SIZE_BYTES = 200 * 1024
    SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_SECONDS = 3600


@pytest.fixture
def app_with_temp_db(tmp_path):
    TestConfig.DATABASE_PATH = str(tmp_path / "test_authority_bridged.db")
    app = create_app(TestConfig)
    with app.app_context():
        db.init_db()
    return app


def table_names(app):
    with app.app_context():
        rows = db.query_all(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    return {row["name"] for row in rows}


def columns(app, table):
    with app.app_context():
        rows = db.query_all(f"PRAGMA table_info({table})")
    return {row["name"] for row in rows}


def indexes(app, table):
    with app.app_context():
        rows = db.query_all(f"PRAGMA index_list({table})")
    return rows


def insert_minimal_user():
    return db.execute(
        """
        INSERT INTO users (
            encrypted_name,
            encrypted_email,
            encrypted_contact,
            email_lookup_hash,
            password_hash,
            password_salt,
            role,
            profile_key_version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            b"name-ciphertext",
            b"email-ciphertext",
            b"contact-ciphertext",
            b"lookup-hash",
            b"password-hash",
            b"password-salt",
            "student",
            1,
        ),
    ).lastrowid


def test_all_required_tables_exist(app_with_temp_db):
    assert table_names(app_with_temp_db) == {
        "keys",
        "users",
        "sessions",
        "otp_codes",
        "posts",
        "upvotes",
        "evidence",
        "chat_messages",
    }


def test_foreign_keys_enabled(app_with_temp_db):
    with app_with_temp_db.app_context():
        row = db.query_one("PRAGMA foreign_keys")

    assert row[0] == 1


def test_init_db_is_idempotent(app_with_temp_db):
    with app_with_temp_db.app_context():
        before = table_names(app_with_temp_db)
        db.init_db()
        after = table_names(app_with_temp_db)

    assert after == before


def test_users_email_lookup_hash_exists_and_is_unique(app_with_temp_db):
    assert "email_lookup_hash" in columns(app_with_temp_db, "users")
    assert any(index["unique"] for index in indexes(app_with_temp_db, "users"))

    with app_with_temp_db.app_context():
        insert_minimal_user()
        with pytest.raises(sqlite3.IntegrityError):
            insert_minimal_user()


def test_otp_salt_exists(app_with_temp_db):
    assert "otp_salt" in columns(app_with_temp_db, "otp_codes")


def test_evidence_file_path_schema(app_with_temp_db):
    evidence_columns = columns(app_with_temp_db, "evidence")

    assert "file_path" in evidence_columns
    assert "encrypted_file_path" not in evidence_columns


def test_chat_messages_schema_has_cmac_version_and_no_receiver(app_with_temp_db):
    chat_columns = columns(app_with_temp_db, "chat_messages")

    assert "cmac_key_version" in chat_columns
    assert "receiver_id" not in chat_columns


def test_upvotes_unique_user_post_constraint_works(app_with_temp_db):
    with app_with_temp_db.app_context():
        user_id = insert_minimal_user()
        post_id = db.execute(
            """
            INSERT INTO posts (
                owner_id,
                encrypted_title,
                encrypted_description,
                anonymous,
                status,
                ecc_key_version
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, "title-ciphertext", "description-ciphertext", 0, "Pending", 1),
        ).lastrowid
        db.execute(
            "INSERT INTO upvotes (user_id, post_id) VALUES (?, ?)",
            (user_id, post_id),
        )

        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO upvotes (user_id, post_id) VALUES (?, ?)",
                (user_id, post_id),
            )


def test_keys_unique_purpose_version_constraint_works(app_with_temp_db):
    with app_with_temp_db.app_context():
        db.execute(
            """
            INSERT INTO keys (
                algorithm,
                purpose,
                version,
                public_key,
                encrypted_private_key,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("RSA", "RSA_PROFILE", 1, "public", b"private-ciphertext", "ACTIVE"),
        )

        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                """
                INSERT INTO keys (
                    algorithm,
                    purpose,
                    version,
                    public_key,
                    encrypted_private_key,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("RSA", "RSA_PROFILE", 1, "public", b"other-private", "RETIRED"),
            )


def test_phase_1_does_not_seed_admin_account(app_with_temp_db):
    with app_with_temp_db.app_context():
        row = db.query_one("SELECT COUNT(*) AS count FROM users WHERE role = ?", ("admin",))

    assert row["count"] == 0
