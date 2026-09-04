import pytest

from crypto.bigint_utils import is_probable_prime
from crypto.ecc import ecc_decrypt_point, ecc_encrypt_point, ecc_generate_keypair
from crypto.ecc_curve import A, B, G, N, P, is_on_curve, point_add, point_double, point_neg, scalar_multiply


def test_curve_parameters_and_generator_order():
    assert is_probable_prime(P)
    assert (4 * A**3 + 27 * B**2) % P != 0
    assert is_on_curve(G)
    assert N > 256
    assert scalar_multiply(N, G) is None
    assert all(scalar_multiply(order, G) is not None for order in (1, 2, 3, 6, 67, 134, 201))


def test_infinity_and_inverse_identities():
    assert point_add(G, None) == G
    assert point_add(None, G) == G
    assert point_add(G, point_neg(G)) is None


def test_manually_reproducible_doubling_and_addition():
    # For G=(1,113): lambda=3/(226)=? mod 751, giving 2G=(93,351).
    assert point_double(G) == (93, 351)
    assert point_add(G, (93, 351)) == (444, 194)


def test_scalar_multiplication_identities():
    assert scalar_multiply(0, G) is None
    assert scalar_multiply(1, G) == G
    assert scalar_multiply(2, G) == point_double(G)
    assert scalar_multiply(3, G) == point_add(G, scalar_multiply(2, G))


def test_generated_keypair_is_valid():
    pair = ecc_generate_keypair()
    assert 1 <= pair["private"] < N
    assert is_on_curve(pair["public"])
    assert pair["public"] == scalar_multiply(pair["private"], G)


def test_encrypt_decrypt_round_trip_for_several_points():
    pair = ecc_generate_keypair()
    for multiplier in (1, 2, 3, 17, 100):
        message = scalar_multiply(multiplier, G)
        ciphertext = ecc_encrypt_point(message, pair["public"])
        assert ecc_decrypt_point(*ciphertext, pair["private"]) == message


def test_same_plaintext_gets_different_ciphertexts():
    pair = ecc_generate_keypair()
    first = ecc_encrypt_point(G, pair["public"])
    second = ecc_encrypt_point(G, pair["public"])
    assert first != second


def test_wrong_private_key_does_not_recover_message():
    pair = ecc_generate_keypair()
    other = ecc_generate_keypair()
    ciphertext = ecc_encrypt_point(G, pair["public"])
    assert ecc_decrypt_point(*ciphertext, other["private"]) != G


@pytest.mark.parametrize("point", [(0, 0), (1, 1), (-1, 113), (P, 1)])
def test_invalid_points_rejected(point):
    with pytest.raises(ValueError, match="curve"):
        point_add(point, G)
    with pytest.raises(ValueError, match="curve"):
        ecc_encrypt_point(point, G)


def test_invalid_ciphertext_and_private_scalar_rejected():
    pair = ecc_generate_keypair()
    with pytest.raises(ValueError, match="curve"):
        ecc_decrypt_point((0, 0), G, pair["private"])
    ciphertext = ecc_encrypt_point(G, pair["public"])
    for invalid in (0, N, -1, "1"):
        with pytest.raises(ValueError, match="private"):
            ecc_decrypt_point(*ciphertext, invalid)


def test_infinity_public_key_rejected():
    with pytest.raises(ValueError, match="public key"):
        ecc_encrypt_point(G, None)


def test_infinity_c1_rejected():
    pair = ecc_generate_keypair()
    with pytest.raises(ValueError, match="C1"):
        ecc_decrypt_point(None, G, pair["private"])


def test_point_double_at_vertical_tangent():
    assert is_on_curve((P - 1, 0))
    assert point_double((P - 1, 0)) is None
    assert point_double(None) is None
