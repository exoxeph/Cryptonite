import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from chat.services import INTEGRITY_WARNING, get_conversation, send_message
from crypto import key_manager
from database import db


class ChatConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-chat-flow-123456"
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
def chat_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    ChatConfig.DATABASE_PATH = str(tmp_path / "chat.db")
    ChatConfig.EVIDENCE_UPLOAD_DIR = str(tmp_path / "encrypted_uploads")
    ChatConfig.ROOT_RSA_E, ChatConfig.ROOT_RSA_N = map(str, root["public"])
    ChatConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(ChatConfig)
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


def _post(client, anonymous=False):
    response = client.post(
        "/posts/new",
        data={"title": "Complaint", "description": "Details", "anonymous": "on" if anonymous else ""},
    )
    assert response.status_code == 302
    return int(response.location.rsplit("/", 1)[-1])


def _message_row(app, message_id=1):
    with app.app_context():
        return db.query_one("SELECT * FROM chat_messages WHERE id = ?", (message_id,))


def test_owner_and_admin_can_exchange_messages(chat_app):
    owner = _user(chat_app, "owner@example.com", name="Owner")
    admin = _user(chat_app, "admin@example.com", role="admin", name="Admin")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        assert client.post(f"/posts/{post_id}/chat", data={"message": "Please review this issue"}).status_code == 302
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, admin)
        assert client.get(f"/posts/{post_id}/chat").status_code == 200
        assert client.post(f"/posts/{post_id}/chat", data={"message": "I will review it"}).status_code == 302
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        response = client.get(f"/posts/{post_id}/chat")
    assert b"Please review this issue" in response.data
    assert b"I will review it" in response.data
    assert b"Owner" in response.data
    assert b"Admin" in response.data


def test_chat_requires_login(chat_app):
    with chat_app.test_client() as client:
        assert client.get("/posts/1/chat").status_code == 302
        assert client.post("/posts/1/chat", data={"message": "message"}).status_code == 302


def test_other_student_denied_chat_access(chat_app):
    owner = _user(chat_app, "owner@example.com")
    other = _user(chat_app, "other@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, other)
        assert client.get(f"/posts/{post_id}/chat").status_code == 403
        assert client.post(f"/posts/{post_id}/chat", data={"message": "no"}).status_code == 403


def test_anonymous_post_owner_can_access_chat(chat_app):
    owner = _user(chat_app, "owner@example.com")
    other = _user(chat_app, "other@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client, anonymous=True)
        assert client.get(f"/posts/{post_id}/chat").status_code == 200
        client.post(f"/posts/{post_id}/chat", data={"message": "private"})
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, other)
        assert client.get(f"/posts/{post_id}/chat").status_code == 403


def test_crafted_sender_id_and_role_are_ignored(chat_app):
    owner = _user(chat_app, "owner@example.com")
    other = _user(chat_app, "other@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, other)
        response = client.post(
            f"/posts/{post_id}/chat",
            data={"message": "forged", "sender_id": owner, "user_id": owner, "role": "admin", "admin": "true"},
        )
    assert response.status_code == 403
    with chat_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS count FROM chat_messages", ()) ["count"] == 0


def test_private_chat_message_length_limit(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        assert client.post(f"/posts/{post_id}/chat", data={"message": "x" * 300}).status_code == 302
        assert client.post(f"/posts/{post_id}/chat", data={"message": "x" * 301}).status_code == 400
        assert client.post(f"/posts/{post_id}/chat", data={"message": "   "}).status_code == 400
    assert _message_row(chat_app)["id"] == 1


def test_message_is_encrypted_and_mac_protected_at_rest(chat_app):
    owner = _user(chat_app, "owner@example.com")
    plaintext = "Please review my complaint"
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        client.post(f"/posts/{post_id}/chat", data={"message": plaintext})
    row = _message_row(chat_app)
    assert plaintext not in row["ciphertext"]
    assert plaintext.encode() not in row["mac"]
    assert row["ecc_key_version"] == 1
    assert row["hmac_key_version"] == 1


def test_untampered_message_not_flagged(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        client.post(f"/posts/{post_id}/chat", data={"message": "valid"})
    with chat_app.app_context():
        messages = get_conversation(post_id, {"id": owner, "role": "student"})
    assert messages == [{"id": 1, "sender": "Owner", "created_at": messages[0]["created_at"], "integrity_ok": True, "plaintext": "valid"}]


def test_tampered_ciphertext_detected(chat_app, monkeypatch):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        client.post(f"/posts/{post_id}/chat", data={"message": "secret"})
    with chat_app.app_context():
        db.execute("UPDATE chat_messages SET ciphertext = ? WHERE id = 1", ("not-json",))
        monkeypatch.setattr(
            "chat.services.deserialize_ecc_ciphertext",
            lambda *args: pytest.fail("deserialization must be skipped"),
        )
        monkeypatch.setattr("chat.services.ecc_decrypt_bytes", lambda *args: pytest.fail("decryption must be skipped"))
        messages = get_conversation(post_id, {"id": owner, "role": "student"})
    assert messages[0]["integrity_ok"] is False
    assert messages[0]["warning"] == INTEGRITY_WARNING
    assert "plaintext" not in messages[0]


def test_full_tamper_detection_demo_flow(chat_app):
    owner = _user(chat_app, "owner@example.com", name="Owner")
    admin = _user(chat_app, "admin@example.com", role="admin", name="Admin")
    plaintext = "Please review this complaint."

    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        assert client.post(f"/posts/{post_id}/chat", data={"message": plaintext}).status_code == 302

    with chat_app.app_context():
        normal = get_conversation(post_id, {"id": admin, "role": "admin"})
        assert normal[0]["integrity_ok"] is True
        assert normal[0]["plaintext"] == plaintext
        assert "warning" not in normal[0]

        row = db.query_one("SELECT id, ciphertext FROM chat_messages WHERE post_id = ?", (post_id,))
        tampered_ciphertext = "tampered"
        assert tampered_ciphertext != row["ciphertext"]
        db.execute("UPDATE chat_messages SET ciphertext = ? WHERE id = ?", (tampered_ciphertext, row["id"]))

        tampered = get_conversation(post_id, {"id": admin, "role": "admin"})

    assert tampered[0]["integrity_ok"] is False
    assert tampered[0]["warning"] == INTEGRITY_WARNING
    assert "plaintext" not in tampered[0]


def test_tampered_mac_detected(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        client.post(f"/posts/{post_id}/chat", data={"message": "secret"})
    with chat_app.app_context():
        db.execute("UPDATE chat_messages SET mac = ? WHERE id = 1", (b"bad",))
        messages = get_conversation(post_id, {"id": owner, "role": "student"})
    assert messages[0]["integrity_ok"] is False
    assert messages[0]["warning"] == INTEGRITY_WARNING
    assert "plaintext" not in messages[0]


def test_message_moved_to_different_post_context_fails_mac(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_a = _post(client)
        post_b = _post(client)
    with chat_app.app_context():
        send_message(post_a, owner, "secret")
        row = _message_row(chat_app)
        db.execute(
            "INSERT INTO chat_messages (post_id, sender_id, ciphertext, mac, ecc_key_version, hmac_key_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (post_b, row["sender_id"], row["ciphertext"], row["mac"], row["ecc_key_version"], row["hmac_key_version"], row["created_at"]),
        )
        messages = get_conversation(post_b, {"id": owner, "role": "student"})
    assert messages[0]["integrity_ok"] is False


@pytest.mark.parametrize("column", ["sender_id", "created_at"])
def test_sender_or_timestamp_context_tamper_fails_mac(chat_app, column):
    owner = _user(chat_app, "owner@example.com")
    other = _user(chat_app, "other@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        client.post(f"/posts/{post_id}/chat", data={"message": "secret"})
    with chat_app.app_context():
        value = other if column == "sender_id" else "2099-01-01 00:00:00"
        db.execute(f"UPDATE chat_messages SET {column} = ? WHERE id = 1", (value,))
        messages = get_conversation(post_id, {"id": owner, "role": "student"})
    assert messages[0]["integrity_ok"] is False


def test_hmac_chat_rotation_preserves_old_message_verification(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
    with chat_app.app_context():
        send_message(post_id, owner, "old")
        key_manager.rotate_key("HMAC_CHAT")
        send_message(post_id, owner, "new")
        rows = db.query_all("SELECT hmac_key_version, ecc_key_version FROM chat_messages ORDER BY id")
        messages = get_conversation(post_id, {"id": owner, "role": "student"})
    assert [row["hmac_key_version"] for row in rows] == [1, 2]
    assert [message["plaintext"] for message in messages] == ["old", "new"]


def test_ecc_chat_rotation_preserves_old_message_decryption(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
    with chat_app.app_context():
        send_message(post_id, owner, "old")
        key_manager.rotate_key("ECC_CHAT")
        send_message(post_id, owner, "new")
        rows = db.query_all("SELECT ecc_key_version, hmac_key_version FROM chat_messages ORDER BY id")
        messages = get_conversation(post_id, {"id": owner, "role": "student"})
    assert [row["ecc_key_version"] for row in rows] == [1, 2]
    assert [row["hmac_key_version"] for row in rows] == [1, 1]
    assert [message["plaintext"] for message in messages] == ["old", "new"]


def test_missing_post_returns_404(chat_app):
    owner = _user(chat_app, "owner@example.com")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        assert client.get("/posts/999/chat").status_code == 404
        assert client.post("/posts/999/chat", data={"message": "missing"}).status_code == 404


def test_chat_links_are_restricted_to_participants(chat_app):
    owner = _user(chat_app, "owner@example.com")
    other = _user(chat_app, "other@example.com")
    admin = _user(chat_app, "admin@example.com", role="admin", name="Admin")
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, owner)
        post_id = _post(client)
        assert b"Private chat" in client.get(f"/posts/{post_id}").data
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, other)
        assert b"Private chat" not in client.get(f"/posts/{post_id}").data
    with chat_app.test_client() as client:
        _authenticate(client, chat_app, admin)
        assert b"Private chat" in client.get(f"/posts/{post_id}").data
