import json

import pytest

from app import create_app
from crypto import key_manager
from crypto.ecc_curve import is_on_curve
from database import db


class KeyManagerConfig:
    TESTING = True
    SECRET_KEY = "test-only-secret-for-key-manager-123456"
    DATABASE_PATH = ""
    RSA_PRIME_BITS = 128
    RSA_PUBLIC_EXPONENT = 11
    ROOT_RSA_N = ""
    ROOT_RSA_E = ""
    ROOT_RSA_D = ""


@pytest.fixture
def app_with_keys(tmp_path):
    root = key_manager.rsa_generate_keypair(128)
    KeyManagerConfig.DATABASE_PATH = str(tmp_path / "keys.db")
    KeyManagerConfig.ROOT_RSA_E, KeyManagerConfig.ROOT_RSA_N = map(str, root["public"])
    KeyManagerConfig.ROOT_RSA_D = str(root["private"][0])
    app = create_app(KeyManagerConfig)
    with app.app_context():
        db.init_db()
    return app


def test_wrap_unwrap_and_malformed_data(app_with_keys):
    with app_with_keys.app_context():
        plaintext = b"private material"
        wrapped = key_manager._wrap_private_key(plaintext)
        assert key_manager._unwrap_private_key(wrapped) == plaintext
        assert plaintext not in wrapped
        with pytest.raises(ValueError, match="malformed"):
            key_manager._unwrap_private_key(b"not-json")


def test_rsa_operational_key_round_trip_and_storage_safety(app_with_keys):
    with app_with_keys.app_context():
        generated = key_manager.generate_key("RSA_PROFILE")
        row = db.query_one("SELECT * FROM keys WHERE purpose = ?", ("RSA_PROFILE",))
        retrieved = key_manager.get_active_key("RSA_PROFILE")
        assert generated["version"] == retrieved["version"] == 1
        assert retrieved["public_key"] == generated["public_key"]
        assert isinstance(retrieved["private_key"], tuple)
        assert json.dumps(retrieved["private_key"]) .encode() not in row["encrypted_private_key"]
        assert row["public_key"] is not None


def test_ecc_and_cmac_operational_keys(app_with_keys):
    with app_with_keys.app_context():
        ecc = key_manager.generate_key("ECC_POSTS")
        cmac_key = key_manager.generate_key("CMAC_CHAT")
        assert is_on_curve(ecc["public_key"])
        assert key_manager.get_key_by_version("ECC_POSTS", 1)["private_key"] == ecc["private_key"]
        assert cmac_key["public_key"] is None
        assert len(cmac_key["private_key"]) == 24
        assert key_manager.get_active_key("CMAC_CHAT")["private_key"] == cmac_key["private_key"]
        row = db.query_one("SELECT public_key FROM keys WHERE purpose = 'CMAC_CHAT'")
        assert row["public_key"] is None


def test_rotation_historical_retrieval_and_revocation(app_with_keys):
    with app_with_keys.app_context():
        first = key_manager.generate_key("ECC_CHAT")
        second = key_manager.rotate_key("ECC_CHAT")
        assert second["version"] == 2
        assert key_manager.get_active_key("ECC_CHAT")["version"] == 2
        assert key_manager.get_key_by_version("ECC_CHAT", 1)["private_key"] == first["private_key"]
        assert db.query_all("SELECT status FROM keys WHERE purpose = 'ECC_CHAT'")[0]["status"] == "RETIRED"
        key_manager.revoke_key("ECC_CHAT", 1)
        with pytest.raises(ValueError, match="revoked"):
            key_manager.get_key_by_version("ECC_CHAT", 1)
        with pytest.raises(ValueError, match="active"):
            key_manager.revoke_key("ECC_CHAT", 2)


def test_bootstrap_is_idempotent_and_all_purposes_are_active(app_with_keys):
    with app_with_keys.app_context():
        key_manager.bootstrap_keys()
        key_manager.bootstrap_keys()
        rows = db.query_all("SELECT purpose, version, status FROM keys")
        assert {row["purpose"] for row in rows} == set(key_manager.PURPOSE_ALGORITHMS)
        assert all(row["version"] == 1 and row["status"] == "ACTIVE" for row in rows)


def test_purpose_and_stored_key_validation(app_with_keys):
    with app_with_keys.app_context():
        with pytest.raises(ValueError, match="unknown"):
            key_manager.generate_key("UNKNOWN")
        with pytest.raises(ValueError, match="requires"):
            key_manager.generate_key("RSA_PROFILE", "ECC")
        key_manager.generate_key("CMAC_SESSION")
        db.execute("UPDATE keys SET public_key = '{}' WHERE purpose = 'CMAC_SESSION'")
        with pytest.raises(ValueError, match="malformed"):
            key_manager.get_active_key("CMAC_SESSION")
