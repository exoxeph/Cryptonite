import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user, get_profile
from auth.sessions import create_session
from chat.services import get_conversation, send_message
from crypto import key_manager
from database import db
from evidence.services import read_evidence, store_evidence


class KeyRotationConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-key-rotation-123456"
    DATABASE_PATH = ""
    RSA_PRIME_BITS = 128
    RSA_PUBLIC_EXPONENT = 11
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
    root = key_manager.rsa_generate_keypair(128)
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
        key_manager.rotate_key("CMAC_CHAT")
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
        assert client.post("/admin/keys/ECC_POSTS/1/revoke").status_code == 302


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
        cmac = key_manager.get_active_key("CMAC_CHAT")
        root_private = str(key_app.config["ROOT_RSA_D"])
        cmac_secret = cmac["private_key"].hex()
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        response = client.get("/admin/keys")
    body = response.data.decode("utf-8")
    assert "ECC_POSTS" in body and "ACTIVE" in body
    assert root_private not in body
    assert cmac_secret not in body
    assert "encrypted_private_key" not in body


def test_revoke_is_admin_only_and_visible_only_for_retired_keys(key_app):
    admin = _user(key_app, "revoke-admin@example.com", role="admin", name="Admin")
    student = _user(key_app, "revoke-student@example.com")
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        assert client.post("/admin/keys/ECC_POSTS/rotate").status_code == 302
        page = client.get("/admin/keys")
        assert page.status_code == 200
        assert b"Revoke" in page.data
        assert client.post("/admin/keys/ECC_POSTS/1/revoke", data={"role": "student"}).status_code == 302
        assert client.post("/admin/keys/ECC_POSTS/2/revoke").status_code == 400
        assert client.post("/admin/keys/ECC_POSTS/1/revoke").status_code == 400
        assert client.post("/admin/keys/UNKNOWN/1/revoke").status_code == 400
        assert client.post("/admin/keys/ECC_POSTS/999/revoke").status_code == 404
    with key_app.test_client() as client:
        _authenticate(client, key_app, student)
        assert client.post("/admin/keys/ECC_POSTS/2/revoke").status_code == 403
    assert _key_rows(key_app, "ECC_POSTS")[0]["status"] == "REVOKED"


def test_revoke_migrates_posts_before_revoking(key_app):
    owner = _user(key_app, "post-revoke-owner@example.com")
    admin = _user(key_app, "post-revoke-admin@example.com", role="admin", name="Admin")
    with key_app.test_client() as client:
        _authenticate(client, key_app, owner)
        post_id = _create_post(client, "Before revoke")
    before = _post_row(key_app, post_id)
    with key_app.test_client() as client:
        _authenticate(client, key_app, admin)
        assert client.post("/admin/keys/ECC_POSTS/rotate").status_code == 302
        assert client.post("/admin/keys/ECC_POSTS/1/revoke").status_code == 302
        assert client.get(f"/posts/{post_id}").status_code == 200
    after = _post_row(key_app, post_id)
    assert after["ecc_key_version"] == 2
    assert after["encrypted_title"] != before["encrypted_title"]
    assert _key_rows(key_app, "ECC_POSTS")[0]["status"] == "REVOKED"
    with key_app.app_context():
        with pytest.raises(ValueError, match="revoked"):
            key_manager.get_key_by_version("ECC_POSTS", 1)


def test_revoke_migrates_profile_and_evidence_records(key_app):
    owner = _user(key_app, "profile-revoke@example.com", name="Profile Owner")
    with key_app.app_context():
        post_id = db.execute(
            "INSERT INTO posts (owner_id, encrypted_title, encrypted_description, ecc_key_version) VALUES (?, ?, ?, ?)",
            (owner, "[]", "[]", 1),
        ).lastrowid
        evidence_id = store_evidence(post_id, owner, "proof.pdf", b"%PDF old evidence", "application/pdf")
        old_profile = db.query_one("SELECT profile_key_version, encrypted_email FROM users WHERE id = ?", (owner,))
        key_manager.rotate_key("RSA_PROFILE")
        key_manager.rotate_key("RSA_EVIDENCE")
        key_manager.revoke_key("RSA_PROFILE", 1)
        key_manager.revoke_key("RSA_EVIDENCE", 1)
        profile = get_profile(owner)
        evidence = read_evidence(evidence_id, {"id": owner, "role": "student"})
        profile_row = db.query_one("SELECT profile_key_version, encrypted_email FROM users WHERE id = ?", (owner,))
        evidence_row = db.query_one("SELECT rsa_key_version FROM evidence WHERE id = ?", (evidence_id,))
    assert profile["email"] == "profile-revoke@example.com"
    assert profile_row["profile_key_version"] == 2
    assert profile_row["encrypted_email"] != old_profile["encrypted_email"]
    assert evidence[1] == b"%PDF old evidence"
    assert evidence_row["rsa_key_version"] == 2
    assert _key_rows(key_app, "RSA_PROFILE")[0]["status"] == "REVOKED"
    assert _key_rows(key_app, "RSA_EVIDENCE")[0]["status"] == "REVOKED"


def test_revoke_migrates_chat_ciphertext_and_mac_records(key_app):
    owner = _user(key_app, "chat-revoke-owner@example.com")
    with key_app.app_context():
        # Build the post through the service so the encrypted fields use ECC_POSTS.
        from posts.services import create_post
        post_id = create_post(owner, "Chat revoke", "Details", False)
        db.execute("UPDATE posts SET status = 'Acknowledged', chat_started_at = CURRENT_TIMESTAMP WHERE id = ?", (post_id,))
        message_id = send_message(post_id, owner, "Message before key revocation")
        key_manager.rotate_key("ECC_CHAT")
        key_manager.rotate_key("CMAC_CHAT")
        key_manager.revoke_key("ECC_CHAT", 1)
        key_manager.revoke_key("CMAC_CHAT", 1)
        row = db.query_one("SELECT ecc_key_version, cmac_key_version FROM chat_messages WHERE id = ?", (message_id,))
        conversation = get_conversation(post_id, {"id": owner, "role": "student"})
    assert row["ecc_key_version"] == 2
    assert row["cmac_key_version"] == 2
    assert conversation[0]["integrity_ok"] is True
    assert conversation[0]["plaintext"] == "Message before key revocation"


def test_failed_revoke_keeps_key_retired_and_records_unchanged(key_app, monkeypatch):
    owner = _user(key_app, "failed-revoke@example.com")
    with key_app.app_context():
        from posts.services import create_post
        post_id = create_post(owner, "Protected post", "Protected details", False)
        before = _post_row(key_app, post_id)
        key_manager.rotate_key("ECC_POSTS")
        monkeypatch.setattr("crypto.key_revocation.ecc_decrypt_bytes", lambda *_args: (_ for _ in ()).throw(ValueError("bad ciphertext")))
        with pytest.raises(ValueError, match="bad ciphertext"):
            key_manager.revoke_key("ECC_POSTS", 1)
        after = _post_row(key_app, post_id)
        assert tuple(after) == tuple(before)
        assert _key_rows(key_app, "ECC_POSTS")[0]["status"] == "RETIRED"


def test_cmac_session_revocation_does_not_modify_session_rows(key_app):
    user = _user(key_app, "session-revoke@example.com")
    with key_app.app_context():
        create_session(db.query_one("SELECT * FROM users WHERE id = ?", (user,)))
        before = [tuple(row) for row in db.query_all("SELECT * FROM sessions ORDER BY id")]
        key_manager.rotate_key("CMAC_SESSION")
        key_manager.revoke_key("CMAC_SESSION", 1)
        after = [tuple(row) for row in db.query_all("SELECT * FROM sessions ORDER BY id")]
    assert after == before
    assert _key_rows(key_app, "CMAC_SESSION")[0]["status"] == "REVOKED"


def test_revoke_requires_an_active_replacement(key_app):
    with key_app.app_context():
        key_manager.generate_key("ECC_POSTS")
        db.execute("UPDATE keys SET status = 'RETIRED' WHERE purpose = 'ECC_POSTS'")
        with pytest.raises(KeyError, match="active key"):
            key_manager.revoke_key("ECC_POSTS", 1)
        assert _key_rows(key_app, "ECC_POSTS")[0]["status"] == "RETIRED"


def test_evidence_revoke_restores_files_when_later_replacement_fails(key_app, monkeypatch):
    owner = _user(key_app, "evidence-rollback@example.com")
    with key_app.app_context():
        from posts.services import create_post
        post_id = create_post(owner, "Evidence rollback", "Details", False)
        first_id = store_evidence(post_id, owner, "one.pdf", b"%PDF one", "application/pdf")
        second_id = store_evidence(post_id, owner, "two.pdf", b"%PDF two", "application/pdf")
        paths = [_evidence_path_for_test(key_app, first_id), _evidence_path_for_test(key_app, second_id)]
        originals = [path.read_bytes() for path in paths]
        key_manager.rotate_key("RSA_EVIDENCE")
        original_replace = __import__("crypto.key_revocation", fromlist=["os"]).os.replace
        calls = 0

        def fail_on_second_file(source, destination):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected replacement failure")
            return original_replace(source, destination)

        monkeypatch.setattr("crypto.key_revocation.os.replace", fail_on_second_file)
        with pytest.raises(OSError, match="injected"):
            key_manager.revoke_key("RSA_EVIDENCE", 1)
        assert [path.read_bytes() for path in paths] == originals
        assert db.query_all("SELECT rsa_key_version FROM evidence ORDER BY id")[-2]["rsa_key_version"] == 1
        assert _key_rows(key_app, "RSA_EVIDENCE")[0]["status"] == "RETIRED"
        assert read_evidence(first_id, {"id": owner, "role": "student"})[1] == b"%PDF one"


def test_revoke_refuses_to_revoke_when_dependencies_remain(key_app, monkeypatch):
    owner = _user(key_app, "dependency-check@example.com")
    with key_app.app_context():
        from posts.services import create_post
        post_id = create_post(owner, "Dependency check", "Details", False)
        key_manager.rotate_key("ECC_POSTS")
        monkeypatch.setattr("crypto.key_revocation._migrate_posts", lambda *_args: None)
        with pytest.raises(ValueError, match="dependent"):
            key_manager.revoke_key("ECC_POSTS", 1)
        assert db.query_one("SELECT ecc_key_version FROM posts WHERE id = ?", (post_id,))["ecc_key_version"] == 1
        assert _key_rows(key_app, "ECC_POSTS")[0]["status"] == "RETIRED"


def test_revoke_emits_redacted_faculty_trace(key_app, capsys):
    key_app.config["FACULTY_CRYPTO_TRACE"] = True
    with key_app.app_context():
        key_manager.generate_key("ECC_POSTS")
        key_manager.rotate_key("ECC_POSTS")
        key_manager.revoke_key("ECC_POSTS", 1)
    output = capsys.readouterr().out
    assert "REVOCATION_START" in output
    assert "REVOCATION_COMPLETE" in output
    assert "retired_version=v1" in output and "migration_target=v3 ACTIVE" in output
    assert "private_key" not in output


def _evidence_path_for_test(app, evidence_id):
    from pathlib import Path
    return Path(app.config["EVIDENCE_UPLOAD_DIR"]) / f"evidence_{evidence_id}.enc"
