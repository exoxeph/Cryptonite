import time

import pytest

from app import create_app
from auth import otp
from auth.account_service import create_user
from crypto import key_manager
from database import db
from evidence.services import store_evidence
from posts.services import acknowledge_post, change_status


class AdminConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-admin-status-123456"
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
def admin_app(tmp_path):
    root = key_manager.rsa_generate_keypair(1024)
    AdminConfig.DATABASE_PATH = str(tmp_path / "admin.db")
    AdminConfig.EVIDENCE_UPLOAD_DIR = str(tmp_path / "encrypted_uploads")
    AdminConfig.ROOT_RSA_E, AdminConfig.ROOT_RSA_N = map(str, root["public"])
    AdminConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(AdminConfig)
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


def _status(app, post_id):
    with app.app_context():
        return db.query_one("SELECT status, updated_at, owner_id FROM posts WHERE id = ?", (post_id,))


def test_admin_can_change_status(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        response = client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Acknowledged"})
    assert response.status_code == 302
    assert _status(admin_app, post_id)["status"] == "Acknowledged"


def test_student_cannot_change_status(admin_app):
    student = _user(admin_app, "student@example.com")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, student)
        post_id = _post(client)
        response = client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Acknowledged"})
    assert response.status_code == 403
    assert _status(admin_app, post_id)["status"] == "Pending"


def test_admin_sees_true_owner_on_anonymous_post(admin_app):
    owner = _user(admin_app, "owner@example.com", name="Alice Owner")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client, anonymous=True)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        response = client.get(f"/admin/posts/{post_id}")
    assert b"Alice Owner" in response.data
    assert b"Anonymous Student" not in response.data


def test_status_change_reflected_in_public_view(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.post(f"/admin/posts/{post_id}/acknowledge")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        response = client.get(f"/posts/{post_id}")
    assert b"Acknowledged" in response.data


def test_admin_can_acknowledge_pending_post(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        assert client.post(f"/admin/posts/{post_id}/acknowledge").status_code == 302
    assert _status(admin_app, post_id)["status"] == "Acknowledged"


def test_admin_can_resolve_acknowledged_post(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.post(f"/admin/posts/{post_id}/acknowledge")
        assert client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Resolved"}).status_code == 302
    assert _status(admin_app, post_id)["status"] == "Resolved"


@pytest.mark.parametrize("new_status", ["Resolved", "Pending", "Closed", "Rejected", "Open", "Done"])
def test_invalid_or_disallowed_status_rejected(admin_app, new_status):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    before = _status(admin_app, post_id)["updated_at"]
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        response = client.post(f"/admin/posts/{post_id}/status", data={"new_status": new_status})
    assert response.status_code == 400
    after = _status(admin_app, post_id)
    assert after["status"] == "Pending"
    assert after["updated_at"] == before


def test_admin_cannot_skip_pending_to_resolved(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        assert client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Resolved"}).status_code == 400
    assert _status(admin_app, post_id)["status"] == "Pending"


@pytest.mark.parametrize("new_status", ["Pending", "Acknowledged"])
def test_admin_cannot_move_status_backward_or_resolved(admin_app, new_status):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.post(f"/admin/posts/{post_id}/acknowledge")
        client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Resolved"})
        assert client.post(f"/admin/posts/{post_id}/status", data={"new_status": new_status}).status_code == 400
    assert _status(admin_app, post_id)["status"] == "Resolved"


def test_same_status_transition_rejected(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        assert client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Pending"}).status_code == 400


def test_acknowledged_to_pending_transition_rejected(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.post(f"/admin/posts/{post_id}/acknowledge")
        response = client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Pending"})
    assert response.status_code == 400
    assert _status(admin_app, post_id)["status"] == "Acknowledged"


@pytest.mark.parametrize("new_status", ["Acknowledged", "Resolved"])
def test_same_status_transition_rejected_for_each_non_pending_state(admin_app, new_status):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.post(f"/admin/posts/{post_id}/acknowledge")
        if new_status == "Resolved":
            client.post(f"/admin/posts/{post_id}/status", data={"new_status": "Resolved"})
        response = client.post(f"/admin/posts/{post_id}/status", data={"new_status": new_status})
    assert response.status_code == 400


def test_status_change_updates_updated_at(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    before = _status(admin_app, post_id)["updated_at"]
    time.sleep(1.1)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.post(f"/admin/posts/{post_id}/acknowledge")
    assert _status(admin_app, post_id)["updated_at"] != before


def test_direct_service_rejects_student(admin_app):
    owner = _user(admin_app, "owner@example.com")
    student = _user(admin_app, "student@example.com")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with pytest.raises(PermissionError):
        with admin_app.app_context():
            change_status(post_id, "Acknowledged", {"id": student, "role": "student"})
    assert _status(admin_app, post_id)["status"] == "Pending"


def test_student_cannot_access_admin_routes(admin_app):
    student = _user(admin_app, "student@example.com")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, student)
        assert client.get("/admin/posts").status_code == 403
        assert client.get("/admin/posts/999").status_code == 403
        assert client.post("/admin/posts/999/status", data={"new_status": "Acknowledged"}).status_code == 403
        assert client.post("/admin/posts/999/acknowledge").status_code == 403


def test_unauthenticated_admin_routes_rejected(admin_app):
    with admin_app.test_client() as client:
        assert client.get("/admin/posts").status_code == 302
        assert client.get("/admin/posts/1").status_code == 302
        assert client.post("/admin/posts/1/status").status_code == 302
        assert client.post("/admin/posts/1/acknowledge").status_code == 302


def test_missing_admin_post_returns_404(admin_app):
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        assert client.get("/admin/posts/999999").status_code == 404
        assert client.post("/admin/posts/999999/status", data={"new_status": "Acknowledged"}).status_code == 404
        assert client.post("/admin/posts/999999/acknowledge").status_code == 404


def test_crafted_role_does_not_authorize_student(admin_app):
    student = _user(admin_app, "student@example.com")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, student)
        response = client.post(
            "/admin/posts/1/status",
            data={"new_status": "Acknowledged", "role": "admin", "actor_role": "admin", "admin": "true", "user_id": "1"},
        )
    assert response.status_code == 403


def test_admin_anonymous_view_does_not_change_owner_id(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client, anonymous=True)
    before = _status(admin_app, post_id)["owner_id"]
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.get(f"/admin/posts/{post_id}")
    assert _status(admin_app, post_id)["owner_id"] == before


def test_public_anonymous_view_still_hides_owner_after_admin_view(admin_app):
    owner = _user(admin_app, "owner@example.com", name="Private Owner")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client, anonymous=True)
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        client.get(f"/admin/posts/{post_id}")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        response = client.get(f"/posts/{post_id}")
    assert b"Anonymous Student" in response.data
    assert b"Private Owner" not in response.data


def test_admin_detail_includes_authorized_evidence_link(admin_app):
    owner = _user(admin_app, "owner@example.com")
    admin = _user(admin_app, "admin@example.com", role="admin", name="Admin")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, owner)
        post_id = _post(client)
    with admin_app.app_context():
        store_evidence(post_id, owner, "report.pdf", b"%PDF", "application/pdf")
    with admin_app.test_client() as client:
        _authenticate(client, admin_app, admin)
        response = client.get(f"/admin/posts/{post_id}")
    assert b"/evidence/1" in response.data
