"""Raw elliptic-curve arithmetic for the project's educational curve.

The fixed curve is over F_P and has equation y^2 = x^3 + A*x + B (mod P):
P = 751, A = 0, B = 1, G = (1, 113), and N = 402.  N is the order
of G and is greater than 256, which is required by the later byte mapping.
This small curve is for teaching and demonstration, not production security.
``None`` represents the point at infinity, the additive identity.
"""

Point = tuple[int, int] | None

P = 751
A = 0
B = 1
G: Point = (1, 113)
N = 402


def is_on_curve(point: Point, a: int = A, p: int = P, b: int = B) -> bool:
    """Return whether a point satisfies the curve equation; infinity is valid."""
    if point is None:
        return True
    if not isinstance(point, tuple) or len(point) != 2:
        return False
    x, y = point
    if type(x) is not int or type(y) is not int or not (0 <= x < p and 0 <= y < p):
        return False
    return (y * y - (x * x * x + a * x + b)) % p == 0


def point_neg(point: Point, p: int = P, a: int = A, b: int = B) -> Point:
    """Return the additive inverse ``(x, -y mod P)`` of a curve point."""
    _require_point(point, a=a, p=p, b=b)
    return None if point is None else (point[0], (-point[1]) % p)


def point_add(p1: Point, p2: Point, a: int = A, p: int = P, b: int = B) -> Point:
    """Add two points using the chord slope and modular inverse division."""
    _require_point(p1, a=a, p=p, b=b)
    _require_point(p2, a=a, p=p, b=b)
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 == p2:
        return point_double(p1, a=a, p=p, b=b)

    # Lambda = (y2-y1) * (x2-x1)^(-1) mod p: modular division.
    denominator_inverse = pow((x2 - x1) % p, -1, p)
    slope = ((y2 - y1) * denominator_inverse) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return x3, y3


def point_double(point: Point, a: int = A, p: int = P, b: int = B) -> Point:
    """Double a point using the tangent slope and modular inverse division."""
    _require_point(point, a=a, p=p, b=b)
    if point is None:
        return None
    x1, y1 = point
    if (2 * y1) % p == 0:
        return None

    # Lambda = (3*x1^2+a) * (2*y1)^(-1) mod p: modular division.
    denominator_inverse = pow((2 * y1) % p, -1, p)
    slope = ((3 * x1 * x1 + a) * denominator_inverse) % p
    x3 = (slope * slope - 2 * x1) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return x3, y3


def scalar_multiply(k: int, point: Point, a: int = A, p: int = P, b: int = B) -> Point:
    """Multiply a point by ``k`` using manual double-and-add."""
    _require_point(point, a=a, p=p, b=b)
    if type(k) is not int or k < 0:
        raise ValueError("scalar must be a non-negative integer")
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend, a=a, p=p, b=b)
        addend = point_double(addend, a=a, p=p, b=b)
        k >>= 1
    return result


def _require_point(point: Point, a: int = A, p: int = P, b: int = B) -> None:
    if not is_on_curve(point, a=a, p=p, b=b):
        raise ValueError("point is not on the configured elliptic curve")
