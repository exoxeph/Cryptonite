"""Evidence upload and retrieval routes for Phase 12."""

from io import BytesIO

from flask import Blueprint, current_app, g, redirect, request, send_file, url_for

from auth.decorators import login_required
from auth.rbac import can_upload_evidence
from evidence.services import (
    EvidenceNotFoundError,
    EvidenceValidationError,
    read_evidence,
    safe_download_name,
    store_evidence,
)
from database import db


evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.post("/posts/<int:post_id>/evidence")
@login_required
def upload_evidence(post_id):
    post = db.query_one("SELECT id, owner_id FROM posts WHERE id = ?", (post_id,))
    if post is None:
        return "Post not found.", 404
    if not can_upload_evidence(g.current_user, post):
        return "You are not allowed to upload evidence.", 403
    uploaded_files = [item for item in request.files.getlist("file") if item.filename]
    if not uploaded_files:
        return "Evidence upload is invalid.", 400
    try:
        for uploaded in uploaded_files:
            if uploaded.content_length and uploaded.content_length > current_app.config["MAX_EVIDENCE_SIZE_BYTES"]:
                return "Evidence file is too large.", 413
            file_bytes = uploaded.read()
            store_evidence(post_id, g.current_user["id"], uploaded.filename, file_bytes, uploaded.mimetype)
    except EvidenceValidationError as exc:
        if "too large" in str(exc):
            return "Evidence file is too large.", 413
        return "Evidence upload is invalid.", 400
    except (OSError, TypeError, ValueError):
        return "Evidence upload could not be completed.", 400
    return redirect(url_for("posts.post_detail", post_id=post_id))


@evidence_bp.get("/evidence/<int:evidence_id>")
@login_required
def get_evidence(evidence_id):
    try:
        filename, file_bytes, mimetype = read_evidence(evidence_id, g.current_user)
    except EvidenceNotFoundError:
        return "Evidence not found.", 404
    except PermissionError:
        return "You are not allowed to view this evidence.", 403
    except (OSError, TypeError, ValueError):
        return "Evidence could not be read.", 400
    return send_file(
        BytesIO(file_bytes),
        mimetype=mimetype,
        as_attachment=request.args.get("inline") != "1",
        download_name=safe_download_name(filename),
    )
