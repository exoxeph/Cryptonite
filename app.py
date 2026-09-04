import click
from flask import Flask, jsonify

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

    from auth.routes import auth_bp

    app.register_blueprint(auth_bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok"), 200

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
