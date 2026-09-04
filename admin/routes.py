"""Admin complaint management routes for Phase 13."""

from flask import Blueprint, g, redirect, render_template, request, url_for

from auth.decorators import role_required
from evidence.services import list_evidence
from posts.services import (
    PostNotFoundError,
    acknowledge_post,
    change_status,
    get_admin_post_for_display,
    list_admin_posts,
)


admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/admin/posts")
@role_required("admin")
def posts():
    try:
        values = list_admin_posts(g.current_user)
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Admin posts could not be loaded.", 500
    return render_template("admin/posts.html", posts=values)


@admin_bp.get("/admin/posts/<int:post_id>")
@role_required("admin")
def post_detail(post_id):
    try:
        post = get_admin_post_for_display(post_id, g.current_user)
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Admin post could not be loaded.", 500
    if post is None:
        return "Post not found.", 404
    return render_template(
        "admin/post_detail.html",
        post=post,
        evidence=list_evidence(post_id, g.current_user),
    )


@admin_bp.post("/admin/posts/<int:post_id>/status")
@role_required("admin")
def update_status(post_id):
    try:
        change_status(post_id, request.form.get("new_status", ""), g.current_user)
    except PostNotFoundError:
        return "Post not found.", 404
    except (TypeError, ValueError, PermissionError):
        return "Invalid status transition.", 400
    return redirect(url_for("admin.post_detail", post_id=post_id))


@admin_bp.post("/admin/posts/<int:post_id>/acknowledge")
@role_required("admin")
def acknowledge(post_id):
    try:
        acknowledge_post(post_id, g.current_user)
    except PostNotFoundError:
        return "Post not found.", 404
    except (TypeError, ValueError, PermissionError):
        return "Invalid status transition.", 400
    return redirect(url_for("admin.post_detail", post_id=post_id))
