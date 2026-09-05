"""Public account registration routes for Phase 6."""

from flask import Blueprint, current_app, g, redirect, render_template, request, session, url_for

from auth.account_service import create_user
from auth.account_service import (
    decrypt_profile_field,
    find_user_by_email,
    get_profile,
    get_user_by_id,
    normalize_email,
    update_profile,
)
from auth.decorators import login_required
from auth import otp
from auth import sessions as auth_sessions
from crypto.hashing import verify_password
from crypto.key_manager import get_key_by_version
from services import email_service


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
            except ValueError as exc:
                if str(exc) == "email address is already registered":
                    error = "An account with this email already exists. Try signing in instead."
                elif str(exc) in {"name is required", "email is required", "contact is required", "password is required"}:
                    error = "Please complete all fields before creating your account."
                else:
                    error = "Account setup is currently unavailable. Please try again later."
            except TypeError:
                error = "Please enter valid information in each field."
            else:
                return redirect(url_for("auth.register_success"))
    return render_template("register.html", error=error)


@auth_bp.get("/register/success")
def register_success():
    """Provide a simple post-registration confirmation without implementing login."""
    return render_template("register_success.html")


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    """Verify password, issue OTP, and set only a temporary pending-auth marker."""
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        try:
            normalized_email = normalize_email(email)
            row = find_user_by_email(normalized_email)
            valid_password = row is not None and verify_password(
                password, row["password_salt"], row["password_hash"]
            )
        except (TypeError, ValueError):
            row = None
            valid_password = False
        if not valid_password:
            error = "Invalid email or password."
        elif not current_app.config.get("OTP_EMAIL_ENABLED", True):
            if not current_app.config.get("OTP_DEV_PRINT_CODE", False):
                error = "Email verification is temporarily paused. Please try again later."
            else:
                code = otp.generate_otp()
                otp.store_otp(row["id"], code)
                print(f"[DEV ONLY] Cryptonite OTP for {normalized_email}: {code}", flush=True)
                session["pending_auth_user_id"] = row["id"]
                return redirect(url_for("auth.verify_otp"))
        else:
            code = otp.generate_otp()
            otp_id = otp.store_otp(row["id"], code)
            try:
                profile_key = get_key_by_version("RSA_PROFILE", row["profile_key_version"])
                recipient = decrypt_profile_field(row["encrypted_email"], profile_key["private_key"])
                email_service.send_otp_email(recipient, code)
            except (ValueError, KeyError, email_service.EmailDeliveryError):
                otp.invalidate_otp(otp_id)
                session.pop("pending_auth_user_id", None)
                error = "Verification code could not be sent. Please try again."
            else:
                session["pending_auth_user_id"] = row["id"]
                return redirect(url_for("auth.verify_otp"))
    return render_template("login.html", error=error)


@auth_bp.route("/verify-otp", methods=("GET", "POST"))
def verify_otp():
    """Consume pending-auth OTP, then establish the authenticated session."""
    user_id = session.get("pending_auth_user_id")
    if not isinstance(user_id, int):
        return redirect(url_for("auth.login"))
    error = None
    if request.method == "POST":
        if otp.verify_otp(user_id, request.form.get("otp", "")):
            user = get_user_by_id(user_id)
            if user is None:
                session.pop("pending_auth_user_id", None)
                return redirect(url_for("auth.login"))
            cookie_value = auth_sessions.create_session(user)
            session.pop("pending_auth_user_id", None)
            response = redirect(url_for("auth.dashboard"))
            return auth_sessions.set_session_cookie(response, cookie_value)
        error = "Verification code is invalid or expired."
    return render_template("verify_otp.html", error=error)


@auth_bp.get("/dashboard")
@login_required
def dashboard():
    """Render the role-specific authenticated landing page."""
    if g.current_user["role"] == "admin":
        from posts.services import get_admin_dashboard

        try:
            dashboard_data = get_admin_dashboard(g.current_user)
        except (KeyError, TypeError, ValueError, PermissionError):
            return "Admin dashboard could not be loaded.", 500
        return render_template(
            "admin/dashboard.html",
            posts=dashboard_data["posts"],
            counts=dashboard_data["counts"],
            total=dashboard_data["total"],
        )
    from posts.services import get_student_dashboard

    try:
        dashboard_data = get_student_dashboard(g.current_user["id"])
    except (KeyError, TypeError, ValueError, PermissionError):
        return "Dashboard could not be loaded.", 500
    return render_template("dashboard.html", user=g.current_user, **dashboard_data)


@auth_bp.post("/logout")
def logout():
    """Revoke the current server-side session and clear its browser cookie."""
    auth_sessions.invalidate_session(request.cookies.get(current_app.config["AUTH_SESSION_COOKIE_NAME"]))
    response = redirect(url_for("auth.login"))
    return auth_sessions.clear_session_cookie(response)


@auth_bp.route("/profile", methods=("GET", "POST"))
@login_required
def profile():
    """View or update only the profile belonging to the authenticated user."""
    error = None
    if request.method == "POST":
        try:
            update_profile(
                g.current_user["id"],
                request.form.get("name", ""),
                request.form.get("email", ""),
                request.form.get("contact", ""),
            )
        except (TypeError, ValueError):
            error = "Profile could not be updated. Please check your information."
        else:
            return redirect(url_for("auth.profile"))
    try:
        values = get_profile(g.current_user["id"])
    except (KeyError, TypeError, ValueError):
        return render_template("profile.html", profile=None, error="Profile could not be loaded."), 500
    return render_template("profile.html", profile=values, error=error)
