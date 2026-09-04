from app import create_app


def test_app_factory_returns_app():
    app = create_app()

    assert app is not None
    assert app.config["RSA_KEY_BITS"] == 2048
    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert app.config["MAX_EVIDENCE_SIZE_BYTES"] == 200 * 1024


def test_health_endpoint_returns_ok():
    app = create_app()

    with app.test_client() as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
