"""Admin complaint management routes for Phase 13."""

from flask import Blueprint, g, redirect, render_template, request, url_for

from auth.decorators import role_required
from crypto import key_manager
from evidence.services import list_evidence
from posts.services import (
    count_admin_posts,
    PostNotFoundError,
    acknowledge_post,
    change_status,
    get_admin_post_for_display,
    list_admin_posts,
    get_page_count,
)


admin_bp = Blueprint("admin", __name__)
VALID_KEY_PURPOSES = frozenset(key_manager.PURPOSE_ALGORITHMS)


@admin_bp.get("/admin/keys")
@role_required("admin")
def keys():
    metadata = key_manager.list_key_metadata()
    grouped = {purpose: [] for purpose in key_manager.PURPOSE_ALGORITHMS}
    for row in metadata:
        grouped[row["purpose"]].append(row)
    return render_template("admin/keys.html", keys_by_purpose=grouped)


@admin_bp.post("/admin/keys/<purpose>/rotate")
@role_required("admin")
def rotate_key(purpose):
    if purpose not in VALID_KEY_PURPOSES:
        return "Unknown key purpose.", 400
    try:
        key_manager.rotate_key(purpose)
    except (KeyError, TypeError, ValueError):
        return "Key rotation could not be completed.", 400
    return redirect(url_for("admin.keys"))


@admin_bp.get("/admin/posts")
@role_required("admin")
def posts():
    try:
        page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        page = 1
    status = request.args.get("status", "all")
    sort = request.args.get("sort", "newest")
    try:
        total = count_admin_posts(status)
        total_pages = get_page_count(total)
        page = min(page, total_pages)
        values = list_admin_posts(g.current_user, page=page, status=status, sort=sort)
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Admin posts could not be loaded.", 500
    return render_template(
        "admin/posts.html", posts=values, page=page, total_pages=total_pages, selected_status=status, selected_sort=sort
    )


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
