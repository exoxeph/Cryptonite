"""Public account registration routes for Phase 6."""

from flask import Blueprint, redirect, render_template, request, url_for

from auth.account_service import create_user


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=("GET", "POST"))
def register():
    """Create a student account; role values from the client are ignored."""
    error = None
    if request.method == "POST":
        fields = {name: request.form.get(name, "") for name in ("name", "email", "contact", "password")}
        if not all(isinstance(value, str) and value.strip() for value in fields.values()):
            error = "All fields are required."
        else:
            try:
                create_user(**fields, role="student")
            except (ValueError, TypeError):
                error = "Registration could not be completed. Please check your information."
            else:
                return redirect(url_for("auth.register_success"))
    return render_template("register.html", error=error)


@auth_bp.get("/register/success")
def register_success():
    """Provide a simple post-registration confirmation without implementing login."""
    return "Registration successful."
