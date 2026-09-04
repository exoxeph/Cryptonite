"""Point-based EC-ElGamal encryption built on :mod:`crypto.ecc_curve`."""

import secrets

from crypto.ecc_curve import G, N, Point, is_on_curve, point_add, point_neg, scalar_multiply


def ecc_generate_keypair() -> dict:
    """Generate ``d`` in [1, N-1] and its public point ``Q = dG``."""
    private_key = secrets.randbelow(N - 1) + 1
    public_key = scalar_multiply(private_key, G)
    if not is_on_curve(public_key):
        raise ValueError("generated ECC public key is invalid")
    return {"public": public_key, "private": private_key}


def ecc_encrypt_point(m_point: Point, public_key: Point) -> tuple[Point, Point]:
    """Encrypt a curve point as ``(C1, C2) = (kG, M + kQ)`` with fresh k."""
    _require_point(m_point, "plaintext")
    _require_point(public_key, "public key")
    ephemeral = secrets.randbelow(N - 1) + 1
    c1 = scalar_multiply(ephemeral, G)
    c2 = point_add(m_point, scalar_multiply(ephemeral, public_key))
    return c1, c2


def ecc_decrypt_point(c1: Point, c2: Point, private_key: int) -> Point:
    """Recover ``M`` as ``C2 - dC1`` using the EC-ElGamal identity dC1=kQ."""
    _require_point(c1, "ciphertext C1")
    _require_point(c2, "ciphertext C2")
    if not isinstance(private_key, int) or not 1 <= private_key < N:
        raise ValueError("ECC private scalar must be in [1, N-1]")
    shared_secret = scalar_multiply(private_key, c1)
    return point_add(c2, point_neg(shared_secret))


def _require_point(point: Point, name: str) -> None:
    if not is_on_curve(point):
        raise ValueError(f"{name} is not on the configured elliptic curve")
