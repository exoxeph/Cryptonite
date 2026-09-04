import hashlib

import pytest

from crypto.hmac_custom import MAC_LENGTH, _normalize_key, generate_mac, verify_mac


def test_rfc4231_case_1():
    assert generate_mac(bytes.fromhex("0b" * 20), b"Hi There").hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )


def test_rfc4231_case_2():
    assert generate_mac(b"Jefe", b"what do ya want for nothing?").hex() == (
        "5bdcc146bf60754e6a042426089575c75"
        "a003f089d2739839dec58b964ec3843"
    )


def test_mac_verifies_and_detects_tampering():
    key, message = b"secret", b"message"
    mac = generate_mac(key, message)
    assert verify_mac(key, message, mac)
    assert not verify_mac(key, b"messagf", mac)
    assert not verify_mac(b"secreu", message, mac)
    assert not verify_mac(key, message, bytes([mac[0] ^ 1]) + mac[1:])


def test_empty_inputs_and_determinism():
    mac = generate_mac(b"", b"")
    assert len(mac) == MAC_LENGTH
    assert verify_mac(b"", b"", mac)
    assert generate_mac(b"same", b"data") == generate_mac(b"same", b"data")
    assert generate_mac(b"same", b"data") != generate_mac(b"same", b"other")


def test_key_normalization_rules():
    assert _normalize_key(b"short") == b"short" + b"\0" * 59
    exact = bytes(range(64))
    assert _normalize_key(exact) == exact
    long_key = bytes(range(65))
    expected = hashlib.sha256(long_key).digest() + b"\0" * 32
    assert _normalize_key(long_key) == expected


def test_mac_is_not_naive_sha256_concat():
    key, message = b"key", b"message"
    assert generate_mac(key, message) != hashlib.sha256(key + message).digest()


@pytest.mark.parametrize("bad", ["key", bytearray(b"key"), None])
def test_invalid_key_type_rejected(bad):
    with pytest.raises(TypeError, match="key"):
        generate_mac(bad, b"message")


def test_invalid_message_and_received_mac_types_rejected():
    with pytest.raises(TypeError, match="message"):
        generate_mac(b"key", "message")
    with pytest.raises(TypeError, match="received_mac"):
        verify_mac(b"key", b"message", "mac")
    assert not verify_mac(b"key", b"message", b"short")
