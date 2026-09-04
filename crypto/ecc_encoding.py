"""Byte/text encoding helpers layered on the point-level EC-ElGamal module."""

import json

from crypto.ecc import ecc_decrypt_point, ecc_encrypt_point
from crypto.ecc_curve import G, P, Point, is_on_curve, scalar_multiply


_BYTE_TO_POINT = {value: scalar_multiply(value + 1, G) for value in range(256)}
_POINT_TO_BYTE = {point: value for value, point in _BYTE_TO_POINT.items()}
if len(_POINT_TO_BYTE) != 256 or any(point is None for point in _BYTE_TO_POINT.values()):
    raise RuntimeError("configured ECC generator cannot represent all byte values")


def byte_to_point(byte_value: int) -> Point:
    """Map byte ``b`` to ``(b + 1)G`` without using the infinity point."""
    if type(byte_value) is not int or not 0 <= byte_value <= 255:
        raise ValueError("byte value must be in [0, 255]")
    return _BYTE_TO_POINT[byte_value]


def point_to_byte(point: Point) -> int:
    """Reverse the fixed byte mapping, rejecting points outside its table."""
    if point not in _POINT_TO_BYTE:
        raise ValueError("point is not part of the configured byte mapping")
    return _POINT_TO_BYTE[point]


def ecc_encrypt_bytes(data: bytes, public_key: Point) -> list[tuple[Point, Point]]:
    """Encrypt each byte independently, retrying an unrepresentable infinity C2."""
    if not isinstance(data, bytes):
        raise TypeError("ECC byte encryption requires bytes")
    ciphertext = []
    for value in data:
        while True:
            c1, c2 = ecc_encrypt_point(byte_to_point(value), public_key)
            if c1 is not None and c2 is not None:
                ciphertext.append((c1, c2))
                break
    return ciphertext


def ecc_decrypt_bytes(ciphertext: list[tuple[Point, Point]], private_key: int) -> bytes:
    """Decrypt serialized point pairs and reverse the fixed byte mapping."""
    if not isinstance(ciphertext, list):
        raise TypeError("ECC ciphertext must be a list")
    output = bytearray()
    for entry in ciphertext:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError("ECC ciphertext entry must contain two points")
        point = ecc_decrypt_point(entry[0], entry[1], private_key)
        output.append(point_to_byte(point))
    return bytes(output)


def serialize_ecc_ciphertext(ciphertext: list[tuple[Point, Point]]) -> str:
    """Serialize ciphertext as compact JSON ``[c1x,c1y,c2x,c2y]`` entries."""
    if not isinstance(ciphertext, list):
        raise TypeError("ECC ciphertext must be a list")
    serialized = []
    for entry in ciphertext:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError("ECC ciphertext entry must contain two points")
        c1, c2 = entry
        if c1 is None or c2 is None or not is_on_curve(c1) or not is_on_curve(c2):
            raise ValueError("ECC ciphertext points must be finite curve points")
        serialized.append([c1[0], c1[1], c2[0], c2[1]])
    return json.dumps(serialized, separators=(",", ":"))


def deserialize_ecc_ciphertext(serialized: str) -> list[tuple[Point, Point]]:
    """Parse and validate the centralized four-coordinate JSON format."""
    if not isinstance(serialized, str):
        raise TypeError("serialized ECC ciphertext must be text")
    try:
        entries = json.loads(serialized)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("malformed ECC ciphertext") from exc
    if not isinstance(entries, list):
        raise ValueError("malformed ECC ciphertext")
    ciphertext = []
    for entry in entries:
        if not isinstance(entry, list) or len(entry) != 4 or any(type(value) is not int for value in entry):
            raise ValueError("malformed ECC ciphertext entry")
        c1, c2 = (entry[0], entry[1]), (entry[2], entry[3])
        if not (0 <= c1[0] < P and 0 <= c1[1] < P and 0 <= c2[0] < P and 0 <= c2[1] < P):
            raise ValueError("ECC ciphertext coordinate is out of range")
        if not is_on_curve(c1) or not is_on_curve(c2):
            raise ValueError("ECC ciphertext point is off curve")
        ciphertext.append((c1, c2))
    return ciphertext
