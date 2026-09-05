"""Authenticated complaint routes for Phase 10."""

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, url_for

from auth.decorators import login_required
from auth.rbac import can_create_post
from evidence.services import EvidenceValidationError, list_evidence, store_evidence
from posts.services import (
    count_public_posts,
    create_post,
    get_page_count,
    get_editable_post,
    get_post_for_display,
    list_public_posts,
    count_admin_posts,
    list_admin_posts,
    PostNotFoundError,
    toggle_upvote,
    update_post,
)


posts_bp = Blueprint("posts", __name__)


@posts_bp.get("/posts")
@login_required
def post_list():
    try:
        page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        page = 1
    selected_status = request.args.get("status", "all")
    selected_sort = request.args.get("sort", "newest")
    try:
        is_admin = g.current_user["role"] == "admin"
        total = count_admin_posts(selected_status) if is_admin else count_public_posts(selected_status)
        total_pages = get_page_count(total)
        page = min(page, total_pages)
        posts = (
            list_admin_posts(g.current_user, page=page, status=selected_status, sort=selected_sort)
            if is_admin
            else list_public_posts(g.current_user, page=page, status=selected_status, sort=selected_sort)
        )
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Posts could not be loaded.", 500
    return render_template(
        "posts.html", posts=posts, page=page, total_pages=total_pages,
        selected_status=selected_status, selected_sort=selected_sort,
    )


@posts_bp.get("/posts/<int:post_id>")
@login_required
def post_detail(post_id):
    try:
        post = get_post_for_display(post_id, g.current_user)
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Post could not be loaded.", 500
    if post is None:
        return "Post not found.", 404
    return render_template(
        "post_detail.html",
        post=post,
        evidence=list_evidence(post_id, g.current_user),
        can_upload_evidence=g.current_user["id"] == post.get("owner_id", g.current_user["id"]),
    )


@posts_bp.post("/posts/<int:post_id>/upvote")
@login_required
def upvote(post_id):
    try:
        has_upvoted = toggle_upvote(g.current_user["id"], post_id)
    except PostNotFoundError:
        return "Post not found.", 404
    except PermissionError:
        if request.accept_mimetypes.best == "application/json":
            return jsonify(error="You are not allowed to upvote this complaint."), 403
        return "You are not allowed to upvote this complaint.", 403
    if request.accept_mimetypes.best == "application/json":
        from posts.services import get_upvote_count

        return jsonify(
            upvote_count=get_upvote_count(post_id),
            has_upvoted=has_upvoted,
        ), 200
    return redirect(url_for("posts.post_list"))


@posts_bp.route("/posts/new", methods=("GET", "POST"))
@login_required
def new_post():
    if not can_create_post(g.current_user):
        return "You are not allowed to create complaints.", 403
    error = None
    values = {field: "" for field in ("title", "description")}
    if request.method == "POST":
        values["title"] = request.form.get("title", "")
        values["description"] = request.form.get("description", "")
        anonymous = request.form.get("anonymous") in {"on", "true", "1"}
        try:
            post_id = create_post(g.current_user["id"], values["title"], values["description"], anonymous)
        except (TypeError, ValueError):
            error = "Complaint could not be created. Please check your information."
        else:
            uploads = [item for item in request.files.getlist("evidence") if item.filename]
            try:
                for uploaded in uploads:
                    store_evidence(
                        post_id, g.current_user["id"], uploaded.filename,
                        uploaded.read(), uploaded.mimetype,
                    )
            except (EvidenceValidationError, OSError, TypeError, ValueError):
                flash("Complaint created, but one or more evidence files could not be uploaded.", "warning")
            return redirect(url_for("posts.post_detail", post_id=post_id))
    return render_template("create_post.html", error=error, values=values)


@posts_bp.route("/posts/<int:post_id>/edit", methods=("GET", "POST"))
@login_required
def edit_post(post_id):
    try:
        editable = get_editable_post(post_id, g.current_user)
    except PermissionError:
        return "You are not allowed to edit this complaint.", 403
    except (KeyError, TypeError, ValueError):
        return "Post could not be loaded.", 500
    if editable is None:
        return "Post not found.", 404
    error = None
    values = dict(editable)
    if request.method == "POST":
        values["title"] = request.form.get("title", "")
        values["description"] = request.form.get("description", "")
        values["anonymous"] = request.form.get("anonymous") in {"on", "true", "1"}
        try:
            update_post(post_id, g.current_user["id"], values["title"], values["description"], values["anonymous"])
        except PermissionError:
            return "You are not allowed to edit this complaint.", 403
        except (TypeError, ValueError):
            error = "Complaint could not be updated. Please check your information."
        else:
            return redirect(url_for("posts.post_detail", post_id=post_id))
    return render_template("create_post.html", error=error, values=values, edit=True, post_id=post_id)
