import pytest

from crypto.cmac_auth import CMAC_KEY_LENGTH, CMAC_TAG_LENGTH, compute_cmac, verify_cmac


def test_cmac_verifies_and_detects_tampering():
    key, message = bytes(range(CMAC_KEY_LENGTH)), b"Secret message"
    tag = compute_cmac(key, message)
    assert len(tag) == CMAC_TAG_LENGTH
    assert verify_cmac(key, message, tag)
    assert not verify_cmac(key, b"Secret messagf", tag)
    assert not verify_cmac(key, message, bytes([tag[0] ^ 1]) + tag[1:])


def test_multiple_messages_require_matching_tags():
    key = b"course-aligned-key-24bytes!"[:CMAC_KEY_LENGTH]
    messages = [b"message one", b"message two", b"message three"]
    tags = [compute_cmac(key, message) for message in messages]
    assert all(verify_cmac(key, message, tag) for message, tag in zip(messages, tags))
    assert not verify_cmac(key, messages[0], tags[1])


def test_cmac_is_deterministic_for_same_inputs():
    key, message = b"0123456789abcdefghijklmn", b"same input"
    assert compute_cmac(key, message) == compute_cmac(key, message)


@pytest.mark.parametrize("key", [b"short", b"0" * 23, b"0" * 25])
def test_invalid_key_length_rejected(key):
    with pytest.raises(ValueError, match="24 bytes"):
        compute_cmac(key, b"message")


@pytest.mark.parametrize("bad", ["key", bytearray(b"key"), None])
def test_invalid_key_type_rejected(bad):
    with pytest.raises(TypeError, match="key"):
        compute_cmac(bad, b"message")


def test_invalid_message_and_tag_types_rejected():
    key = b"0123456789abcdefghijklmn"
    with pytest.raises(TypeError, match="message"):
        compute_cmac(key, "message")
    with pytest.raises(TypeError, match="expected_tag"):
        verify_cmac(key, b"message", "tag")
    assert not verify_cmac(key, b"message", b"short")
