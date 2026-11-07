"""The rules the port must match beyond the shared fixtures (each mirrors the Rust crate)."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from support import KEYS, base, resign, set_path

import decision_cert as dc

UTC = dt.UTC


def ok(cert: dict[str, Any]) -> dc.Verified:
    return dc.verify(resign(cert), KEYS)


def rejects(cert: dict[str, Any], want: str, *, sign: bool = True) -> None:
    with pytest.raises(dc.Invalid) as e:
        dc.verify(resign(cert) if sign else cert, KEYS)
    assert want in str(e.value)


def test_the_reference_certificate_resigned_verifies() -> None:
    v = ok(base())
    assert v.id.startswith("sha256:") and len(v.id) == 71


@pytest.mark.parametrize(
    "path",
    ["alpha", "coverage", "realized_band.level", "audit.rate", "calibration_map.params.temperature", "ucb", "delta"],
)
def test_a_boolean_is_never_a_number(path: str) -> None:
    rejects(set_path(base(), path, True), "invalid type: boolean")


@pytest.mark.parametrize("path", ["n_cal", "n_temperature", "n", "audit.n"])
def test_integer_fields_reject_integral_floats(path: str) -> None:
    rejects(set_path(base(), path, 1.0), "invalid type: floating point `1.0`, expected u64")


def test_nullable_integers_reject_floats_too() -> None:
    rejects(set_path(base(), "split.seed", 7.0), "expected i64")
    rejects(set_path(base(), "calibration_map.label_budget", 3.0), "expected u64")


def test_integer_ranges_are_serdes() -> None:
    rejects(set_path(base(), "n", -1), "expected u64")
    rejects(set_path(base(), "split.seed", 2**63), "expected i64")
    assert ok(set_path(base(), "split.seed", -(2**63)))


def test_unknown_fields_are_rejected_at_every_level() -> None:
    for path in ["extra", "split.extra", "calibration_map.extra", "rule.extra", "realized_band.extra", "audit.extra"]:
        rejects(set_path(base(), path, 1), "unknown field `extra`")
    seg = base("valid_segments_unicode")
    seg["segments"][0]["extra"] = 1
    rejects(seg, "unknown field `extra`")


def test_missing_nullable_fields_are_rejected() -> None:
    c = base()
    del c["manifest_hash"]
    rejects(c, "missing field `manifest_hash`")


def test_loads_rejects_what_serde_json_rejects() -> None:
    for text in ['{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', '{"a": 1e400}', '"\\ud800"']:
        with pytest.raises(dc.Invalid):
            dc.loads(text)
    assert dc.loads('{"a": 1, "a": 2}') == {"a": 2}


def test_minus_zero_text_is_a_float() -> None:
    v = dc.loads('{"n": -0, "x": -0.0}')
    assert isinstance(v["n"], float) and isinstance(v["x"], float)
    c = base()
    c["n"] = v["n"]
    rejects(c, "expected u64")


@pytest.mark.parametrize(
    "ts",
    [
        "2027-01-23T12:00:00+00:00",
        "2027-01-23 12:00:00Z",
        "2027-01-23t12:00:00Z",
        "2027-01-23T12:00:00.5Z",
        "2023-02-29T00:00:00Z",
        "2027-01-23T24:00:00Z",
        "2027-13-01T00:00:00Z",
        "2027-01-23T12:60:00Z",
        "2027-01-23T12:00:61Z",
        "\uff12\uff10\uff12\uff17-01-23T12:00:00Z",
    ],
)
def test_timestamps_must_be_the_strict_form(ts: str) -> None:
    rejects(set_path(base(), "expires_at", ts), "is not YYYY-MM-DDTHH:MM:SSZ")


def test_leap_seconds_and_year_zero_are_accepted_like_chrono() -> None:
    v = ok(set_path(base(), "expires_at", "2026-12-31T23:59:60Z"))
    assert not v.is_expired(dt.datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC))
    assert v.is_expired(dt.datetime(2027, 1, 1, tzinfo=UTC))
    assert ok(set_path(base(), "fitted_at", "2024-02-29T00:00:00Z"))
    v0 = ok(set_path(base(), "expires_at", "0000-01-01T00:00:00Z"))
    assert v0.is_expired(dt.datetime(1, 1, 1, tzinfo=UTC))


def test_is_expired_from_expires_at_on() -> None:
    v = ok(base())
    assert v.expires_at == dt.datetime(2027, 1, 23, 12, tzinfo=UTC)
    assert v.is_expired(v.expires_at) and dc.is_expired(v, v.expires_at)
    assert not v.is_expired(v.expires_at - dt.timedelta(seconds=1))
    assert v.is_expired(dt.datetime(2027, 1, 23, 13, 0, tzinfo=dt.timezone(dt.timedelta(hours=1))))
    with pytest.raises(ValueError):
        v.is_expired(dt.datetime(2030, 1, 1))


def test_certified_segments_set_the_threshold_and_inherited_ones_do_not() -> None:
    v = dc.verify(*_fixture_pair("valid_segments_unicode"))
    top = v.cert["abstain_below"]
    assert v.threshold_for("east") == 0.9 == dc.threshold_for(v, "east")
    assert v.threshold_for("zürich ☃") == top
    assert v.threshold_for(None) == top
    assert v.threshold_for("nowhere") == top
    assert v.temperature() == v.cert["calibration_map"]["params"]["temperature"]


def test_temperature_is_none_for_other_map_kinds() -> None:
    assert ok(set_path(base(), "calibration_map.kind", "isotonic")).temperature() is None


def test_keys_must_be_strict_base64url() -> None:
    c = resign(base())
    ((kid, raw),) = KEYS.items()
    for bad in [raw + "=", raw[:-1] + "+", raw[:-1], raw[:-1] + ("B" if raw[-1] != "B" else "C")]:
        with pytest.raises(dc.BadKey):
            dc.verify(c, {kid: bad})


def test_a_signature_with_nonzero_trailing_bits_does_not_verify() -> None:
    c = resign(base())
    last = c["signature"][-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    c["signature"] = c["signature"][:-1] + alphabet[alphabet.index(last) | 1]
    if c["signature"][-1] == last:
        c["signature"] = c["signature"][:-1] + alphabet[alphabet.index(last) | 2]
    with pytest.raises(dc.BadSignature):
        dc.verify(c, KEYS)


def test_integers_beyond_2_53_canonicalise_as_serde_jcs_does() -> None:
    assert dc.canonical({"n": 2**53 + 1}) == b'{"n":9007199254740992}'
    assert dc.canonical({"n": 2**64 - 1}) == b'{"n":18446744073709552000}'
    assert dc.canonical({"n": 2**53 - 1}) == b'{"n":9007199254740991}'
    assert dc.canonical({"x": -0.0, "b": True}) == b'{"b":true,"x":0}'


def test_not_an_object() -> None:
    with pytest.raises(dc.Invalid, match="not a JSON object"):
        dc.verify([], KEYS)


def _fixture_pair(name: str) -> tuple[Any, Any]:
    from support import fixture

    f = fixture(name)
    return f["certificate"], f["keys"]
