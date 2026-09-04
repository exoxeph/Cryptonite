"""Raw elliptic-curve arithmetic for the project's educational curve.

The fixed curve is over F_P and has equation y^2 = x^3 + A*x + B (mod P):
P = 751, A = 0, B = 1, G = (1, 113), and N = 402.  N is the order
of G and is greater than 256, which is required by the later byte mapping.
This small curve is for teaching and demonstration, not production security.
``None`` represents the point at infinity, the additive identity.
"""

from crypto.bigint_utils import mod_inverse

Point = tuple[int, int] | None

P = 751
A = 0
B = 1
G: Point = (1, 113)
N = 402


def is_on_curve(point: Point) -> bool:
    """Return whether a point satisfies the curve equation; infinity is valid."""
    if point is None:
        return True
    if not isinstance(point, tuple) or len(point) != 2:
        return False
    x, y = point
    if not isinstance(x, int) or not isinstance(y, int) or not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_neg(point: Point) -> Point:
    """Return the additive inverse ``(x, -y mod P)`` of a curve point."""
    _require_point(point)
    return None if point is None else (point[0], (-point[1]) % P)


def point_add(p1: Point, p2: Point) -> Point:
    """Add two points using the chord slope and modular inverse division."""
    _require_point(p1)
    _require_point(p2)
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        return point_double(p1)

    # Lambda = (y2-y1) * (x2-x1)^(-1) mod P: this is modular division.
    denominator_inverse = mod_inverse((x2 - x1) % P, P)
    slope = ((y2 - y1) * denominator_inverse) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_double(point: Point) -> Point:
    """Double a point using the tangent slope and modular inverse division."""
    _require_point(point)
    if point is None:
        return None
    x1, y1 = point
    if y1 == 0:
        return None

    # Lambda = (3*x1^2+A) * (2*y1)^(-1) mod P: modular, not ordinary, division.
    denominator_inverse = mod_inverse((2 * y1) % P, P)
    slope = ((3 * x1 * x1 + A) * denominator_inverse) % P
    x3 = (slope * slope - 2 * x1) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_multiply(k: int, point: Point) -> Point:
    """Multiply a point by ``k`` using manual double-and-add."""
    _require_point(point)
    if not isinstance(k, int) or k < 0:
        raise ValueError("scalar must be a non-negative integer")
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result


def _require_point(point: Point) -> None:
    if not is_on_curve(point):
        raise ValueError("point is not on the configured elliptic curve")
