"""Authenticated complaint routes for Phase 10."""

from flask import Blueprint, g, redirect, render_template, request, url_for

from auth.decorators import login_required
from auth.rbac import can_create_post
from posts.services import (
    create_post,
    get_editable_post,
    get_post_for_display,
    list_public_posts,
    update_post,
)


posts_bp = Blueprint("posts", __name__)


@posts_bp.get("/posts")
@login_required
def post_list():
    try:
        posts = list_public_posts(g.current_user)
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Posts could not be loaded.", 500
    return render_template("posts.html", posts=posts)


@posts_bp.get("/posts/<int:post_id>")
@login_required
def post_detail(post_id):
    try:
        post = get_post_for_display(post_id, g.current_user)
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Post could not be loaded.", 500
    if post is None:
        return "Post not found.", 404
    return render_template("post_detail.html", post=post)


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
