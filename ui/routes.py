"""Public pages and safe in-memory UI previews.

Preview routes deliberately do not read or write application records and do
not grant authentication. They exist only to inspect the presentation layer.
"""

from functools import wraps

from flask import Blueprint, abort, current_app, render_template


ui_bp = Blueprint("ui", __name__)


@ui_bp.get("/")
def home():
    return render_template("public/home.html")


@ui_bp.get("/about")
@ui_bp.get("/how-it-works")
def about():
    return render_template("public/about.html")


@ui_bp.get("/help")
def help_page():
    return render_template("public/help.html")


def preview_only(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_app.config.get("UI_PREVIEW_ENABLED", False):
            abort(404)
        return view(*args, **kwargs)

    return wrapped


PREVIEW_POST = {
    "id": 42,
    "title": "Library Noise After Midnight",
    "description": "A recurring noise issue near the library is affecting late study sessions and residence access.",
    "display_owner": "Anonymous Student",
    "status": "Acknowledged",
    "created_at": "2026-09-03 21:14",
    "updated_at": "2026-09-04 09:10",
    "upvote_count": 38,
    "anonymous": True,
    "can_upvote": True,
    "can_access_chat": True,
    "has_upvoted": False,
}


def _preview_context():
    posts = [
        PREVIEW_POST,
        {**PREVIEW_POST, "id": 41, "title": "Broken AC in CSE Lab", "status": "Pending", "display_owner": "Nadia Rahman", "upvote_count": 14, "anonymous": False},
        {**PREVIEW_POST, "id": 40, "title": "Accessible entrance signage", "status": "Resolved", "display_owner": "Imran Chowdhury", "upvote_count": 27, "anonymous": False},
    ]
    return {"posts": posts, "post": PREVIEW_POST, "user": {"name": "Nadia", "role": "student"}}


@ui_bp.get("/ui-preview")
@preview_only
def preview_index():
    return render_template("preview/index.html")


@ui_bp.get("/ui-preview/<page>")
@preview_only
def preview_page(page):
    context = _preview_context()
    templates = {
        "student-dashboard": ("preview/student_dashboard.html", "Student dashboard"),
        "complaints": ("preview/complaints.html", "Complaints"),
        "complaint-detail": ("preview/complaint_detail.html", "Complaint detail"),
        "admin-dashboard": ("preview/admin_dashboard.html", "Admin dashboard"),
        "admin-complaint": ("preview/admin_complaint.html", "Admin complaint"),
        "admin-keys": ("preview/admin_keys.html", "Key management"),
        "chat": ("preview/chat.html", "Private conversation"),
        "profile": ("preview/profile.html", "Profile"),
    }
    template = templates.get(page)
    if template is None:
        abort(404)
    context["preview_title"] = template[1]
    return render_template(template[0], **context)
