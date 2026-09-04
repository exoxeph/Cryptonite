import click
from flask import Flask, jsonify

from config import Config
from database import db


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    db.init_app(app)

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

    return app


if __name__ == "__main__":
    create_app().run()
