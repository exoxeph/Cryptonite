"""Authentication decorators that delegate cookie validation to auth.sessions."""

from functools import wraps

from flask import g, redirect, url_for

from auth.sessions import get_current_user


def login_required(view_func):
    """Redirect unauthenticated requests; attach authoritative user data to g."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for("auth.login"))
        g.current_user = user
        return view_func(*args, **kwargs)

    return wrapped


def role_required(required_role):
    """Require authentication and one authoritative database role."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user is None:
                return redirect(url_for("auth.login"))
            if user["role"] != required_role:
                return "You are not allowed to access this page.", 403
            g.current_user = user
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
