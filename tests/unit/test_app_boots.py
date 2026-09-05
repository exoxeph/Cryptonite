import pytest

from app import create_app


class BootConfig:
    SECRET_KEY = "test-only-secret-for-app-boot-123456789"
    DATABASE_PATH = ":memory:"
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = "authority_bridged_session"
    SESSION_COOKIE_SECURE = False
    MAX_EVIDENCE_SIZE_BYTES = 200 * 1024
    RSA_PRIME_BITS = 128
    RSA_PUBLIC_EXPONENT = 11


def test_app_requires_secret_key():
    class MissingSecretConfig:
        SECRET_KEY = None

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(MissingSecretConfig)


def test_app_rejects_example_secret_placeholder():
    class PlaceholderSecretConfig:
        SECRET_KEY = "replace-with-a-strong-random-secret-at-least-32-characters"

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(PlaceholderSecretConfig)


def test_app_factory_returns_app():
    app = create_app(BootConfig)

    assert app is not None
    assert app.config["RSA_PRIME_BITS"] == 128
    assert app.config["RSA_PUBLIC_EXPONENT"] == 11
    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert app.config["MAX_EVIDENCE_SIZE_BYTES"] == 200 * 1024
    assert "bootstrap-keys" in app.cli.commands


def test_health_endpoint_returns_ok():
    app = create_app(BootConfig)

    with app.test_client() as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
