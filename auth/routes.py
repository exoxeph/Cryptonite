"""Public account registration routes for Phase 6."""

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from auth.account_service import create_user
from auth.account_service import decrypt_profile_field, find_user_by_email, get_user_by_id, normalize_email
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
            except (ValueError, TypeError):
                error = "Registration could not be completed. Please check your information."
            else:
                return redirect(url_for("auth.register_success"))
    return render_template("register.html", error=error)


@auth_bp.get("/register/success")
def register_success():
    """Provide a simple post-registration confirmation without implementing login."""
    return "Registration successful."


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
    """Minimal authenticated landing page until the profile module exists."""
    return "Authenticated session active."


@auth_bp.post("/logout")
def logout():
    """Revoke the current server-side session and clear its browser cookie."""
    auth_sessions.invalidate_session(request.cookies.get(current_app.config["AUTH_SESSION_COOKIE_NAME"]))
    response = redirect(url_for("auth.login"))
    return auth_sessions.clear_session_cookie(response)
