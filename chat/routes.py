"""Private complaint chat routes for Phase 14."""

from flask import Blueprint, g, redirect, render_template, request, url_for

from auth.decorators import login_required
from chat.services import ChatPostNotFoundError, get_conversation, send_message


chat_bp = Blueprint("chat", __name__)


@chat_bp.get("/posts/<int:post_id>/chat")
@login_required
def conversation(post_id):
    try:
        messages = get_conversation(post_id, g.current_user)
    except ChatPostNotFoundError:
        return "Post not found.", 404
    except PermissionError:
        return "You are not allowed to access this chat.", 403
    except (KeyError, TypeError, ValueError):
        return "Chat could not be loaded.", 400
    return render_template("chat.html", post_id=post_id, messages=messages)


@chat_bp.post("/posts/<int:post_id>/chat")
@login_required
def send(post_id):
    try:
        send_message(post_id, g.current_user["id"], request.form.get("message", ""))
    except ChatPostNotFoundError:
        return "Post not found.", 404
    except PermissionError:
        return "You are not allowed to access this chat.", 403
    except (KeyError, TypeError, ValueError):
        return "Chat message could not be sent.", 400
    return redirect(url_for("chat.conversation", post_id=post_id))
