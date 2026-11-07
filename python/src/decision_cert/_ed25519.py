"""The parts of Ed25519 point handling that `cryptography` does not expose, in pure Python.

The Rust crate verifies with ed25519-dalek's `verify_strict`, which on top of the RFC 8032 equation
rejects a small-order public key `A` or a small-order `R`, and a non-canonical `S`. OpenSSL (behind
`cryptography`) checks `S` but not small order, so these checks run here first. Decoding follows
curve25519-dalek's `CompressedEdwardsY::decompress`, which is what the Rust crate uses: `y` is read
modulo p and `x = 0` with the sign bit set is accepted. Nothing here is secret, so nothing here needs
to run in constant time.
"""

from __future__ import annotations

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z


def decode(b: bytes) -> Point | None:
    """The point a 32-byte encoding names, or None when it names no curve point."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = (n & ((1 << 255) - 1)) % P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    # x = sqrt(u / v), per RFC 8032 §5.1.3 step 3.
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if (v * x * x - u) % P != 0:
        x = x * _SQRT_M1 % P
        if (v * x * x - u) % P != 0:
            return None
    if (x & 1) != sign:
        x = (P - x) % P
    return (x, y, 1, x * y % P)


def add(p: Point, q: Point) -> Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


IDENTITY: Point = (0, 1, 1, 0)


def mul(k: int, p: Point) -> Point:
    out = IDENTITY
    while k:
        if k & 1:
            out = add(out, p)
        p = add(p, p)
        k >>= 1
    return out


def is_identity(p: Point) -> bool:
    x, y, z, _ = p
    return x % P == 0 and (y - z) % P == 0


def is_small_order(p: Point) -> bool:
    """True when 8·p is the identity: p lies in the torsion subgroup."""
    for _ in range(3):
        p = add(p, p)
    return is_identity(p)


def encode(p: Point) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE_Y = 4 * pow(5, P - 2, P) % P
BASE: Point = decode(_BASE_Y.to_bytes(32, "little"))  # type: ignore[assignment]
