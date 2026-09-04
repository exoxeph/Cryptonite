"""Small, reusable number-theory helpers for the educational crypto modules."""

import secrets


def gcd(a: int, b: int) -> int:
    """Return the non-negative greatest common divisor using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return ``(gcd, x, y)`` where ``a*x + b*y == gcd``."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Return the inverse of ``a`` modulo ``m`` or raise when none exists."""
    if m <= 0:
        raise ValueError("modulus must be positive")
    divisor, coefficient, _ = extended_gcd(a % m, m)
    if divisor != 1:
        raise ValueError("modular inverse does not exist")
    return coefficient % m


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Compute ``base**exp mod mod`` by manual square-and-multiply."""
    if mod <= 0:
        raise ValueError("modulus must be positive")
    if exp < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % mod
    base %= mod
    while exp:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Use Miller-Rabin witnesses to reject composites with high confidence."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    if n % 2 == 0:
        return False
    for prime in small_primes:
        if n % prime == 0:
            return False

    exponent = n - 1
    shifts = 0
    while exponent % 2 == 0:
        shifts += 1
        exponent //= 2

    for _ in range(rounds):
        witness = secrets.randbelow(n - 3) + 2
        value = mod_pow(witness, exponent, n)
        if value in (1, n - 1):
            continue
        for _ in range(shifts - 1):
            value = (value * value) % n
            if value == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bit_length: int) -> int:
    """Generate an odd probable prime of exactly ``bit_length`` bits with secrets."""
    if bit_length < 2:
        raise ValueError("prime bit length must be at least 2")

    while True:
        candidate = secrets.randbits(bit_length)
        candidate |= (1 << (bit_length - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
