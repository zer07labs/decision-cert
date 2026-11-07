"""The small-order check that `verify_strict` adds, and that OpenSSL does not do."""

from __future__ import annotations

import hashlib

import pytest

from decision_cert import _ed25519 as ed

# The eight points of the torsion subgroup, canonically encoded (libsodium's blocklist lists the
# order-8 ones as 26e8958f... and c7176a70...). rust/src/lib.rs tests the same list against dalek.
CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # identity
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
]
# Non-canonical encodings of the same points: the sign bit on x = 0, and y read modulo p.
NON_CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]


def test_the_table_is_the_whole_torsion_subgroup() -> None:
    found: set[str] = set()
    i = 0
    while len(found) < 8:
        i += 1
        y = int.from_bytes(hashlib.sha256(bytes([i])).digest(), "little") % ed.P
        p = ed.decode(y.to_bytes(32, "little"))
        if p is not None:
            found.add(ed.encode(ed.mul(ed.L, p)).hex())
    assert found == set(CANONICAL)


@pytest.mark.parametrize("h", CANONICAL + NON_CANONICAL)
def test_small_order_encodings_decode_and_are_small_order(h: str) -> None:
    p = ed.decode(bytes.fromhex(h))
    assert p is not None
    assert ed.is_small_order(p)


def test_the_base_point_and_a_real_key_are_not_small_order() -> None:
    assert not ed.is_small_order(ed.BASE)
    assert ed.is_identity(ed.mul(ed.L, ed.BASE))
    pub = bytes.fromhex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")  # seed [7]*32
    p = ed.decode(pub)
    assert p is not None and not ed.is_small_order(p)
    assert ed.encode(p) == pub


def test_a_non_point_does_not_decode() -> None:
    # y = 2 gives u/v with no square root mod p.
    assert ed.decode((2).to_bytes(32, "little")) is None
    assert ed.decode(b"\x00" * 31) is None
