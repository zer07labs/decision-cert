"""Evidence packs (docs/evidence-pack.md): every fixture pack in tests/packs/ gets its expected verdict,
and the verifier's rules hold on packs edited in a temporary directory. The fixtures come from
tools/gen_pack_fixtures.py; never edit them by hand."""

from __future__ import annotations

import contextlib
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest

import decision_cert._pack as pk
from decision_cert import PACK_FORMAT, Invalid, Limits, PackError, measured_cases_hash, verify_pack
from decision_cert.__main__ import main
from decision_cert.issue.recompute import differences

PACKS = Path(__file__).resolve().parent / "packs"
EXPECTED: dict[str, Any] = json.loads((PACKS / "expected.json").read_text(encoding="utf-8"))
NOW = dt.datetime(2026, 11, 16, tzinfo=dt.UTC)
OTHER_KEYS = {"ed25519:0000000000000000": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}


def cli(args: list[str]) -> tuple[int, str]:
    code, out, _ = cli_err(args)
    return code, out


def cli_err(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as e:  # argparse usage errors
            code = int(e.code or 0)
    return code, out.getvalue(), err.getvalue()


def copy_pack(tmp: Path, name: str = "valid") -> Path:
    dst = tmp / name
    shutil.copytree(PACKS / name, dst)
    return dst


def rewrite_manifest(pack: Path, edit: Any) -> None:
    m = json.loads((pack / "pack.json").read_text(encoding="utf-8"))
    edit(m)
    (pack / "pack.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


def test_the_fixture_manifest_lists_every_file_and_every_hash_matches() -> None:
    listed = {}
    for line in (PACKS / "PACKS.sha256").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    present = {p.relative_to(PACKS).as_posix() for p in PACKS.rglob("*") if p.is_file()} - {"PACKS.sha256"}
    assert set(listed) == present
    for name, digest in listed.items():
        assert hashlib.sha256((PACKS / name).read_bytes()).hexdigest() == digest, name


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_every_fixture_pack_gets_its_expected_verdict(name: str) -> None:
    want = EXPECTED[name]
    report = verify_pack(PACKS / name, now=NOW)
    assert report.ok == (want["verdict"] == "verified"), [c for c in report.checks if c.status == "fail"]
    failure = report.first_failure()
    assert (failure.name if failure else None) == want["first_failure"]
    if want["recomputed"] is not None:
        assert sum(c.status == "ok" and c.name.startswith("recompute") for c in report.checks) == want["recomputed"]


def test_the_tar_and_the_directory_give_the_same_checks() -> None:
    assert verify_pack(PACKS / "valid", now=NOW).checks == verify_pack(PACKS / "valid.tar", now=NOW).checks


def test_the_valid_pack_runs_every_check_in_order() -> None:
    report = verify_pack(PACKS / "valid", now=NOW)
    names = [c.name for c in report.checks]
    assert names[:4] == ["layout", "manifest", "files", "trusted-keys"]
    for p in ("certificates/approved.json", "certificates/route.json"):
        i = names.index(f"certificate {p}")
        assert names[i : i + 3] == [f"certificate {p}", f"cases {p}", f"recompute {p}"]
    assert [c.name for c in report.checks if c.status != "ok"] == ["trusted-keys"]
    assert len(report.certificate_ids) == 2


def test_a_location_only_pack_names_where_the_cases_are_and_skips_the_recompute() -> None:
    report = verify_pack(PACKS / "valid_location_only", now=NOW)
    assert report.ok
    cases = next(c for c in report.checks if c.name.startswith("cases"))
    assert cases.status == "skipped" and "example://tenant-synthetic/" in cases.detail
    assert [c.status for c in report.skipped("recompute")] == ["skipped"]


def test_keys_from_the_caller_replace_the_packs_own() -> None:
    signer = json.loads((PACKS / "valid" / "trusted-keys.json").read_text(encoding="utf-8"))
    assert verify_pack(PACKS / "valid", signer, now=NOW).ok
    report = verify_pack(PACKS / "valid", OTHER_KEYS, now=NOW)
    assert not report.ok
    first = report.first_failure()
    assert first is not None and first.name.startswith("certificate ")


def test_without_the_issuer_the_recompute_is_skipped_not_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pk, "_load_recompute", lambda: None)
    report = verify_pack(PACKS / "valid", now=NOW)
    assert report.ok
    assert len(report.skipped("recompute")) == 2
    assert all("decision-cert[issue]" in c.detail for c in report.skipped("recompute"))


def test_recompute_false_skips_it() -> None:
    report = verify_pack(PACKS / "invalid_recompute", now=NOW, recompute=False)
    assert report.ok
    assert [c.detail for c in report.skipped("recompute")] == ["not asked for"]


def test_an_expired_certificate_is_reported_not_failed() -> None:
    report = verify_pack(PACKS / "valid", now=dt.datetime(2030, 1, 1, tzinfo=dt.UTC))
    assert report.ok
    assert all("expired at the check time" in c.detail for c in report.checks if c.name.startswith("certificate "))
    assert not any("unexpired" in c.detail for c in report.checks if c.name.startswith("certificate "))


def test_an_unknown_manifest_field_is_reported_and_not_checked(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    rewrite_manifest(pack, lambda m: m.update(note="added by a later v1 assembler"))
    report = verify_pack(pack, now=NOW)
    assert report.ok
    assert "not checked: note" in report.checks[1].detail


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (lambda m: m["certificates"][0]["measurement"].update(location=None, cases=None), "both null"),
        (lambda m: m["certificates"][0]["measurement"].update(cases="cases/../x.jsonl"), "member path"),
        (lambda m: m.pop("tenant"), "lacks tenant"),
        (lambda m: m.update(tenant=""), "tenant"),
        (lambda m: m.update(created_at="2026-11-16"), "timestamp"),
        (lambda m: m["files"].update({"pack.json": "sha256:" + "0" * 64}), "may list"),
        (lambda m: m["certificates"].append(dict(m["certificates"][0])), "listed twice"),
        (lambda m: m["certificates"][0]["measurement"]["procedure"].update(ttl_days=0), "ttl_days"),
    ],
)
def test_a_manifest_the_verifier_cannot_read_is_rejected(tmp_path: Path, edit: Any, reason: str) -> None:
    pack = copy_pack(tmp_path)
    rewrite_manifest(pack, edit)
    report = verify_pack(pack, now=NOW)
    first = report.first_failure()
    assert first is not None and first.name == "manifest" and reason in first.detail, report.checks


def test_a_link_in_a_directory_pack_is_rejected(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    (pack / "extra.json").symlink_to(pack / "trusted-keys.json")
    first = verify_pack(pack, now=NOW).first_failure()
    assert first is not None and first.name == "layout" and "link" in first.detail


def test_a_hidden_file_is_not_a_member_path(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    (pack / ".DS_Store").write_bytes(b"\0")
    first = verify_pack(pack, now=NOW).first_failure()
    assert first is not None and first.name == "layout"


def test_a_pack_without_a_manifest_is_rejected(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    (pack / "pack.json").unlink()
    first = verify_pack(pack, now=NOW).first_failure()
    assert first is not None and first.name == "layout" and "pack.json" in first.detail


def test_a_missing_path_is_a_pack_error(tmp_path: Path) -> None:
    with pytest.raises(PackError):
        verify_pack(tmp_path / "nothing-here", now=NOW)


def test_measured_cases_hash_binds_cannot_tell_from_v1_3_only() -> None:
    row = {
        "case_id": "a",
        "set": "calibration",
        "label_index": 0,
        "raw_scores": [1.0, 0.0],
        "decided_at": None,
        "segment": None,
        "propensity": None,
        "cannot_tell": 0.4,
    }
    other = {**row, "cannot_tell": 0.9}
    assert measured_cases_hash([row], "decision-certificate.v1.2") == measured_cases_hash(
        [other], "decision-certificate.v1.2"
    )
    assert measured_cases_hash([row], "decision-certificate.v1.3") != measured_cases_hash(
        [other], "decision-certificate.v1.3"
    )


def test_measured_cases_hash_sorts_by_case_id_bytes() -> None:
    rows = [
        {f: None for f in pk.CASE_FIELDS} | {"case_id": cid, "set": "calibration", "label_index": 0}
        for cid in ("b", "a", "é")
    ]
    assert measured_cases_hash(rows, "decision-certificate.v1.3") == measured_cases_hash(
        list(reversed(rows)), "decision-certificate.v1.3"
    )


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ('{"case_id": "a"}', "exactly the fields"),
        (
            '{"case_id":"a","set":"holdout","label_index":0,"raw_scores":null,"decided_at":null,'
            '"segment":null,"propensity":null,"cannot_tell":null}',
            "set must be",
        ),
        (
            '{"case_id":"a","set":"calibration","label_index":2,"raw_scores":null,"decided_at":null,'
            '"segment":null,"propensity":null,"cannot_tell":null}',
            "label_index",
        ),
        (
            '{"case_id":"a","set":"calibration","label_index":0,"raw_scores":[1],"decided_at":null,'
            '"segment":null,"propensity":null,"cannot_tell":null}',
            "raw_scores",
        ),
        (
            '{"case_id":"a","set":"calibration","label_index":0,"raw_scores":null,"decided_at":"2026-11-01",'
            '"segment":null,"propensity":null,"cannot_tell":null}',
            "timestamp",
        ),
        (
            '{"case_id":"a","set":"calibration","label_index":0,"raw_scores":null,"decided_at":null,'
            '"segment":null,"propensity":true,"cannot_tell":null}',
            "propensity",
        ),
    ],
)
def test_read_cases_refuses_a_line_that_is_not_a_measured_case(line: str, reason: str) -> None:
    with pytest.raises(Invalid, match=reason):
        pk.read_cases((line + "\n").encode(), 2)


def test_read_cases_refuses_a_repeated_case_id() -> None:
    line = (
        '{"case_id":"a","set":"calibration","label_index":0,"raw_scores":null,"decided_at":null,'
        '"segment":null,"propensity":null,"cannot_tell":null}\n'
    )
    with pytest.raises(Invalid, match="twice"):
        pk.read_cases((line * 2).encode(), 2)


def test_differences_compares_numbers_up_to_the_tolerance_and_the_rest_exactly() -> None:
    assert differences({"a": 0.1, "b": [1, 2]}, {"a": 0.1 + 1e-15, "b": [1.0, 2.0]}) == []
    assert differences({"a": 0.1}, {"a": 0.2}) == ["a"]
    assert differences({"s": [{"x": True}]}, {"s": [{"x": 1}]}) == ["s.0.x"]
    assert differences({"a": 1}, {"b": 1}) == ["a", "b"]
    assert differences({"l": [1]}, {"l": [1, 2]}) == ["l"]


def test_tar_bytes_is_deterministic() -> None:
    members = {"pack.json": b"{}", "b/c.json": b"[]"}
    assert pk.tar_bytes(members) == pk.tar_bytes(dict(reversed(members.items())))


def test_cli_exit_codes() -> None:
    now = ["--now", "2026-11-16T00:00:00Z"]
    code, out = cli(["verify-pack", str(PACKS / "valid"), *now])
    unpinned = "pack verified: 2 certificate(s); consistent with its own keys only; pin keys with --keys\n"
    assert code == 0 and out.endswith(unpinned)
    code, out = cli(["verify-pack", str(PACKS / "invalid_recompute"), *now])
    assert code == 1 and out.endswith("pack rejected\n")
    assert cli(["verify-pack", str(PACKS / "valid_location_only"), *now])[0] == 0
    assert cli(["verify-pack", str(PACKS / "valid_location_only"), "--require-recompute", *now])[0] == 1
    assert cli(["verify-pack", str(PACKS / "valid"), "--require-recompute", *now])[0] == 0
    assert cli(["verify-pack", str(PACKS / "invalid_recompute"), "--no-recompute", *now])[0] == 0
    assert cli(["verify-pack", str(PACKS / "no-such-pack"), *now])[0] == 2
    assert cli(["verify-pack", str(PACKS / "valid"), "--now", "yesterday"])[0] == 2
    assert cli(["verify-pack", str(PACKS / "valid"), "--no-recompute", "--require-recompute"])[0] == 2


def test_cli_keys_from_a_file(tmp_path: Path) -> None:
    other = tmp_path / "keys.json"
    other.write_text(json.dumps(OTHER_KEYS), encoding="utf-8")
    now = ["--now", "2026-11-16T00:00:00Z"]
    assert cli(["verify-pack", str(PACKS / "valid"), "--keys", str(other), *now])[0] == 1
    signer = PACKS / "valid" / "trusted-keys.json"
    code, out = cli(["verify-pack", str(PACKS / "valid"), "--keys", str(signer), *now])
    assert code == 0 and out.endswith("pack verified: 2 certificate(s)\n")
    bad = tmp_path / "bad.json"
    bad.write_text("[1]", encoding="utf-8")
    assert cli(["verify-pack", str(PACKS / "valid"), "--keys", str(bad), *now])[0] == 2


def test_the_format_name() -> None:
    assert PACK_FORMAT == "decision-evidence-pack.v1"


# ---------- pinned keys ----------


def test_without_keys_the_trusted_keys_check_warns_and_the_verdict_says_so() -> None:
    report = verify_pack(PACKS / "valid", now=NOW)
    assert report.ok and not report.keys_pinned
    tk = next(c for c in report.checks if c.name == "trusted-keys")
    assert tk.status == "warn" and pk.UNPINNED in tk.detail
    assert pk.render(report).endswith(f"pack verified: 2 certificate(s); {pk.UNPINNED}\n")
    signer = json.loads((PACKS / "valid" / "trusted-keys.json").read_text(encoding="utf-8"))
    pinned = verify_pack(PACKS / "valid", signer, now=NOW)
    assert pinned.keys_pinned and all(c.status == "ok" for c in pinned.checks)
    assert pk.render(pinned).endswith("pack verified: 2 certificate(s)\n")


# ---------- read limits ----------


def valid_members() -> dict[str, bytes]:
    root = PACKS / "valid"
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_a_directory_pack_over_a_read_limit_is_refused(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    largest = max(len(b) for b in valid_members().values())
    total = sum(len(b) for b in valid_members().values())
    assert verify_pack(pack, now=NOW, limits=Limits(total, largest, 6)).ok
    with pytest.raises(PackError, match="member limit"):
        verify_pack(pack, now=NOW, limits=Limits(member_bytes=largest - 1))
    with pytest.raises(PackError, match="bytes in all"):
        verify_pack(pack, now=NOW, limits=Limits(total_bytes=total - 1))
    with pytest.raises(PackError, match="more than 5 members"):
        verify_pack(pack, now=NOW, limits=Limits(members=5))


def test_a_directory_pack_reads_no_file_past_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = copy_pack(tmp_path)
    (pack / "zz-big.bin").write_bytes(b"\0" * (1 << 20))
    opened: list[str] = []
    real_open = Path.open

    def spy(self: Path, *a: Any, **k: Any) -> Any:
        opened.append(self.name)
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", spy)
    largest = max(len(b) for b in valid_members().values())
    with pytest.raises(PackError, match=re.escape("zz-big.bin")):
        verify_pack(pack, now=NOW, limits=Limits(member_bytes=largest))
    assert "zz-big.bin" not in opened


def big_gzip_tar(big: int) -> bytes:
    """The valid pack as a gzip tar with an extra member of `big` zero bytes, which compresses to little."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in [*valid_members().items(), ("zz-big.bin", b"\0" * big)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_a_tar_pack_over_a_read_limit_is_refused_before_the_member_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "big.tar.gz"
    path.write_bytes(big_gzip_tar(8 << 20))
    assert path.stat().st_size < 1 << 20
    extracted: list[str] = []
    real = tarfile.TarFile.extractfile

    def spy(self: tarfile.TarFile, member: Any) -> Any:
        extracted.append(member.name)
        return real(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", spy)
    with pytest.raises(PackError, match=re.escape("'zz-big.bin' is 8388608 bytes")):
        verify_pack(path, now=NOW, limits=Limits(member_bytes=1 << 20))
    assert "zz-big.bin" not in extracted
    with pytest.raises(PackError, match="bytes in all"):
        verify_pack(path, now=NOW, limits=Limits(total_bytes=4 << 20))
    with pytest.raises(PackError, match="more than 3 members"):
        verify_pack(PACKS / "valid.tar", now=NOW, limits=Limits(members=3))


def test_the_cli_reports_a_read_limit_as_a_usage_error() -> None:
    now = ["--now", "2026-11-16T00:00:00Z"]
    for pack in ("valid", "valid.tar"):
        code, out, err = cli_err(["verify-pack", str(PACKS / pack), "--max-member-bytes", "100", *now])
        assert code == 2 and out == "" and "--max-member-bytes" in err and "Traceback" not in err
    code, _, err = cli_err(["verify-pack", str(PACKS / "valid"), "--max-members", "2", *now])
    assert code == 2 and "--max-members" in err
    code, _, err = cli_err(["verify-pack", str(PACKS / "valid"), "--max-total-bytes", "100", *now])
    assert code == 2 and "--max-total-bytes" in err
    assert cli_err(["verify-pack", str(PACKS / "valid"), "--max-members", "0", *now])[0] == 2
    assert cli_err(["verify-pack", str(PACKS / "valid"), "--max-total-bytes", str(1 << 30), *now])[0] == 0


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError):
        Limits(members=0)


# ---------- unreadable packs ----------


def test_a_truncated_gzip_pack_is_a_pack_error_not_a_traceback(tmp_path: Path) -> None:
    whole = gzip.compress((PACKS / "valid.tar").read_bytes(), mtime=0)
    path = tmp_path / "truncated.tar.gz"
    path.write_bytes(whole[: len(whole) // 2])
    with pytest.raises(PackError, match=re.escape("truncated.tar.gz")):
        verify_pack(path, now=NOW)
    code, out, err = cli_err(["verify-pack", str(path), "--now", "2026-11-16T00:00:00Z"])
    assert code == 2 and out == "" and err.startswith("decision-cert: ") and "Traceback" not in err


def test_a_corrupt_gzip_pack_is_a_pack_error(tmp_path: Path) -> None:
    whole = bytearray(gzip.compress((PACKS / "valid.tar").read_bytes(), mtime=0))
    whole[20:60] = b"\xff" * 40  # inside the deflate stream
    path = tmp_path / "corrupt.tar.gz"
    path.write_bytes(bytes(whole))
    with pytest.raises(PackError):
        verify_pack(path, now=NOW)


def test_a_truncated_plain_tar_is_a_pack_error(tmp_path: Path) -> None:
    whole = (PACKS / "valid.tar").read_bytes()
    path = tmp_path / "truncated.tar"
    path.write_bytes(whole[:1000])
    with pytest.raises(PackError):
        verify_pack(path, now=NOW)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_file_in_a_directory_pack_is_a_pack_error(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    locked = pack / "trusted-keys.json"
    locked.chmod(0)
    try:
        with pytest.raises(PackError, match="PermissionError"):
            verify_pack(pack, now=NOW)
        code, _, err = cli_err(["verify-pack", str(pack), "--now", "2026-11-16T00:00:00Z"])
        assert code == 2 and "Traceback" not in err
    finally:
        locked.chmod(0o644)


# ---------- duplicate keys ----------


def test_a_manifest_with_a_repeated_key_is_rejected(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    text = (pack / "pack.json").read_text(encoding="utf-8")
    top = text.replace('"tenant": ', '"tenant": "someone-else",\n  "tenant": ', 1)
    (pack / "pack.json").write_text(top, encoding="utf-8")
    report = verify_pack(pack, now=NOW)
    failure = report.first_failure()
    assert failure is not None and failure.name == "manifest" and "'tenant' appears twice" in failure.detail

    nested = text.replace('"data_hash": ', '"data_hash": "sha256:' + "0" * 64 + '", "data_hash": ', 1)
    (pack / "pack.json").write_text(nested, encoding="utf-8")
    failure = verify_pack(pack, now=NOW).first_failure()
    assert failure is not None and failure.name == "manifest" and "'data_hash' appears twice" in failure.detail
