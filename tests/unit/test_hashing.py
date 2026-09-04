import pytest

from crypto.hashing import generate_salt, hash_password, verify_password


def test_salts_are_random_and_correct_length():
    assert len(generate_salt()) == 16
    assert generate_salt() != generate_salt()


def test_password_hash_round_trip_and_wrong_password():
    salt = generate_salt()
    digest = hash_password("correct horse", salt)
    assert verify_password("correct horse", salt, digest)
    assert not verify_password("wrong horse", salt, digest)


def test_same_password_with_different_salts_differs():
    assert hash_password("password", generate_salt()) != hash_password("password", generate_salt())


def test_invalid_password_inputs_rejected():
    with pytest.raises(TypeError):
        hash_password(b"password", generate_salt())
    with pytest.raises(ValueError):
        hash_password("password", b"")
