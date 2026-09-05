import click
import sqlite3
from flask import Flask, g, jsonify, render_template, request

from config import Config
from database import db


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    secret_key = app.config.get("SECRET_KEY")
    known_placeholders = {
        "replace-with-a-strong-random-secret-at-least-32-characters",
        "replace-with-dev-secret",
    }
    if (
        not isinstance(secret_key, str)
        or len(secret_key) < 32
        or secret_key.strip() in known_placeholders
    ):
        raise RuntimeError("SECRET_KEY must be a generated random value of at least 32 characters")
    db.init_app(app)

    @app.before_request
    def load_current_user():
        """Expose a valid session to public templates without authorizing routes."""
        if request.path not in {"/", "/about", "/how-it-works", "/help"} and not request.path.startswith("/ui-preview"):
            return
        from auth.sessions import get_current_user

        try:
            g.current_user = get_current_user()
        except sqlite3.Error:
            # The health endpoint and first-run public pages can exist before init-db.
            g.current_user = None

    from auth.routes import auth_bp
    from admin.routes import admin_bp
    from chat.routes import chat_bp
    from evidence.routes import evidence_bp
    from posts.routes import posts_bp
    from ui.routes import ui_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(posts_bp)
    app.register_blueprint(ui_bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok"), 200

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("errors/500.html"), 500

    @app.cli.command("bootstrap-keys")
    def bootstrap_keys_command():
        """Initialize the database and create any missing operational keys."""
        from crypto.key_manager import bootstrap_keys

        db.init_db()
        bootstrap_keys()
        click.echo("Operational keys bootstrapped.")

    @app.cli.command("seed-admin")
    @click.option("--name", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--contact", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def seed_admin_command(name, email, contact, password):
        """Create one controlled local Admin account with supplied credentials."""
        from auth.account_service import create_user
        from crypto.key_manager import bootstrap_keys

        db.init_db()
        bootstrap_keys()
        create_user(name, email, contact, password, role="admin")
        click.echo("Admin account created.")

    return app


if __name__ == "__main__":
    create_app().run()
