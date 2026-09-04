from flask import Flask, jsonify

from config import Config


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    @app.get("/health")
    def health():
        return jsonify(status="ok"), 200

    return app


if __name__ == "__main__":
    create_app().run()
