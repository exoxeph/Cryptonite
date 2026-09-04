import io
import json
from pathlib import Path

import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from crypto import key_manager
from database import db


class EvidenceConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-evidence-flow-123456"
    DATABASE_PATH = ""
    RSA_KEY_BITS = 1024
    ROOT_RSA_N = ROOT_RSA_E = ROOT_RSA_D = ""
    OTP_EXPIRY_SECONDS = 300
    MAX_EVIDENCE_SIZE_BYTES = 200 * 1024
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_SECONDS = 3600


@pytest.fixture
def evidence_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    EvidenceConfig.DATABASE_PATH = str(tmp_path / "evidence.db")
    EvidenceConfig.ROOT_RSA_E, EvidenceConfig.ROOT_RSA_N = map(str, root["public"])
    EvidenceConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(EvidenceConfig)
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
        data={
            "title": "Complaint",
            "description": "Details",
            "anonymous": "on" if anonymous else "",
        },
    )
    assert response.status_code == 302
    return int(response.location.rsplit("/", 1)[-1])


def _upload(client, post_id, filename="report.pdf", content=b"%PDF-1.7 evidence", mimetype="application/pdf", **extra):
    data = {"file": (io.BytesIO(content), filename, mimetype)}
    data.update(extra)
    return client.post(f"/posts/{post_id}/evidence", data=data, content_type="multipart/form-data")


def _evidence_row(app, evidence_id):
    with app.app_context():
        return db.query_one("SELECT * FROM evidence WHERE id = ?", (evidence_id,))


def test_owner_can_upload_and_view_evidence(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    original = b"%PDF-1.7\nowner evidence"
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        upload = _upload(client, post_id, content=original)
        assert upload.status_code == 302
        evidence_id = _evidence_row(evidence_app, 1)["id"]
        response = client.get(f"/evidence/{evidence_id}")
    assert response.status_code == 200
    assert response.data == original
    assert response.mimetype == "application/pdf"
    assert "report.pdf" in response.headers["Content-Disposition"]


def test_admin_can_view_evidence(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    admin = _user(evidence_app, "admin@example.com", role="admin", name="Admin")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        _upload(client, post_id)
        evidence_id = _evidence_row(evidence_app, 1)["id"]
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, admin)
        response = client.get(f"/evidence/{evidence_id}")
    assert response.status_code == 200


def test_other_student_denied_evidence(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    other = _user(evidence_app, "other@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        _upload(client, post_id)
        evidence_id = _evidence_row(evidence_app, 1)["id"]
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, other)
        response = client.get(f"/evidence/{evidence_id}")
    assert response.status_code == 403


def test_upload_requires_login(evidence_app):
    with evidence_app.test_client() as client:
        response = client.post("/posts/1/evidence")
    assert response.status_code == 302


def test_non_owner_cannot_upload_evidence(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    other = _user(evidence_app, "other@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, other)
        response = _upload(client, post_id)
    assert response.status_code == 403


def test_admin_cannot_upload_as_post_owner(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    admin = _user(evidence_app, "admin@example.com", role="admin", name="Admin")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, admin)
        response = _upload(client, post_id, owner_id=owner)
    assert response.status_code == 403


def test_oversized_file_rejected(evidence_app, monkeypatch):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        called = False

        def fail_if_called(*args, **kwargs):
            nonlocal called
            called = True
            raise AssertionError("RSA encryption must not run for oversized evidence")

        monkeypatch.setattr("evidence.services.rsa_encrypt_bytes", fail_if_called)
        response = _upload(client, post_id, content=b"x" * (200 * 1024 + 1))
    assert response.status_code == 413
    assert called is False


@pytest.mark.parametrize(
    ("filename", "mimetype", "content"),
    [
        ("image.PNG", "image/png", b"\x89PNG\r\n\x1a\n"),
        ("photo.jpg", "image/jpeg", b"\xff\xd8\xff\xe0"),
        ("photo.jpeg", "image/jpeg", b"\xff\xd8\xff\xe0"),
    ],
)
def test_valid_image_types_are_accepted(evidence_app, filename, mimetype, content):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        response = _upload(client, post_id, filename, content, mimetype)
    assert response.status_code == 302


def test_wrong_file_type_rejected(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        response = _upload(client, post_id, filename="report.exe", mimetype="application/octet-stream")
    assert response.status_code == 400


def test_filename_encrypted_but_file_path_plain_id_derived(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        _upload(client, post_id, filename="medical_report.pdf")
    row = _evidence_row(evidence_app, 1)
    assert b"medical_report.pdf" not in row["encrypted_filename"]
    assert row["file_path"] == "encrypted_uploads/evidence_1.enc"
    assert row["rsa_key_version"] == 1


def test_stored_file_is_not_plaintext(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    original = b"%PDF-1.7\nsecret evidence"
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        _upload(client, post_id, content=original)
    stored = Path(evidence_app.root_path, "encrypted_uploads", "evidence_1.enc").read_bytes()
    assert stored != original
    assert not stored.startswith(b"%PDF")
    assert json.loads(stored.decode("utf-8")) != list(original)


def test_view_does_not_leave_plaintext_on_disk(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        _upload(client, post_id)
        client.get("/evidence/1")
    files = list((Path(evidence_app.root_path) / "encrypted_uploads").iterdir())
    assert files and all(path.suffix == ".enc" for path in files)


def test_missing_evidence_returns_404(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        response = client.get("/evidence/999")
    assert response.status_code == 404


def test_crafted_owner_id_is_ignored(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    other = _user(evidence_app, "other@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, other)
        response = _upload(client, post_id, owner_id=owner, user_id=owner, post_owner=owner)
    assert response.status_code == 403


def test_anonymous_post_uses_real_owner_for_evidence_access(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    other = _user(evidence_app, "other@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client, anonymous=True)
        assert b"Anonymous Student" in client.get(f"/posts/{post_id}").data
        _upload(client, post_id)
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, other)
        assert client.get("/evidence/1").status_code == 403
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        assert client.get("/evidence/1").status_code == 200


def test_path_traversal_filename_not_used_for_storage(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        response = _upload(client, post_id, filename="../../secret.pdf")
    assert response.status_code == 302
    assert not (Path(evidence_app.root_path).parent / "secret.pdf").exists()
    assert list((Path(evidence_app.root_path) / "encrypted_uploads").glob("*.enc"))


def test_historical_evidence_decrypts_after_rsa_evidence_rotation(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    original = b"%PDF-1.7\nold key evidence"
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
        _upload(client, post_id, content=original)
    with evidence_app.app_context():
        key_manager.rotate_key("RSA_EVIDENCE")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        response = client.get("/evidence/1")
    assert response.status_code == 200
    assert response.data == original


def test_post_detail_upload_controls_are_owner_only(evidence_app):
    owner = _user(evidence_app, "owner@example.com")
    admin = _user(evidence_app, "admin@example.com", role="admin", name="Admin")
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, owner)
        post_id = _post(client)
    with evidence_app.test_client() as client:
        _authenticate(client, evidence_app, admin)
        response = client.get(f"/posts/{post_id}")
    assert b"Upload evidence" not in response.data
