"""`python -m decision_cert verify` and the Rust `decision-cert verify` agree on exit code and output
for every fixture and for the usage errors. The Rust half is skipped when cargo is not on PATH."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from support import FIXTURES

from decision_cert.__main__ import main

RUST = Path(__file__).resolve().parents[2] / "rust"
NOW = "2026-11-07T00:00:00Z"


def python_cli(args: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = main(args)
        except SystemExit as e:  # argparse usage errors
            code = int(e.code or 0)
    return code, out.getvalue()


@pytest.fixture(scope="module")
def rust_bin() -> Path | None:
    if shutil.which("cargo") is None:
        return None
    subprocess.run(["cargo", "build", "--quiet", "--locked", "--features", "cli"], cwd=RUST, check=True)
    return RUST / "target" / "debug" / "decision-cert"


def split_fixture(tmp: Path, name: str) -> tuple[Path, Path]:
    f = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    cert, keys = tmp / f"{name}.cert.json", tmp / f"{name}.keys.json"
    cert.write_text(json.dumps(f["certificate"], ensure_ascii=False), encoding="utf-8")
    keys.write_text(json.dumps(f["keys"]), encoding="utf-8")
    return cert, keys


def cases(tmp: Path) -> list[tuple[str, list[str], int]]:
    out = []
    for p in sorted(FIXTURES.glob("*.json")):
        f = json.loads(p.read_text(encoding="utf-8"))
        cert, keys = split_fixture(tmp, p.stem)
        out.append((p.stem, ["verify", str(cert), "--keys", str(keys), "--now", NOW], 0 if f["valid"] else 1))
    cert, keys = split_fixture(tmp, "valid_basic")
    garbage = tmp / "garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    nan = tmp / "nan.json"
    nan.write_text('{"spec": NaN}', encoding="utf-8")
    out += [
        ("expired", ["verify", str(cert), "--keys", str(keys), "--now", "2027-01-23T12:00:00Z"], 1),
        ("not-yet-expired", ["verify", str(cert), "--keys", str(keys), "--now", "2027-01-23T11:59:59Z"], 0),
        ("cert-not-json", ["verify", str(garbage), "--keys", str(keys), "--now", NOW], 1),
        ("cert-nan", ["verify", str(nan), "--keys", str(keys), "--now", NOW], 1),
        ("bad-now", ["verify", str(cert), "--keys", str(keys), "--now", "2026-11-07"], 2),
        ("keys-missing", ["verify", str(cert), "--keys", str(tmp / "nope.json"), "--now", NOW], 2),
        ("keys-not-json", ["verify", str(cert), "--keys", str(garbage), "--now", NOW], 2),
        ("keys-not-strings", ["verify", str(cert), "--keys", str(nan), "--now", NOW], 2),
        ("cert-missing", ["verify", str(tmp / "nope.json"), "--keys", str(keys), "--now", NOW], 2),
        ("no-keys-flag", ["verify", str(cert)], 2),
        ("no-command", [], 2),
    ]
    return out


def test_python_cli_exit_codes(tmp_path: Path) -> None:
    for name, args, want in cases(tmp_path):
        code, out = python_cli(args)
        assert code == want, f"{name}: exit {code}, want {want}"
        assert (out.strip().startswith("sha256:")) == (want == 0), name


def test_rust_and_python_cli_agree(tmp_path: Path, rust_bin: Path | None) -> None:
    if rust_bin is None:
        pytest.skip("cargo not on PATH")
    for name, args, _ in cases(tmp_path):
        r = subprocess.run([str(rust_bin), *args], capture_output=True, text=True)
        assert python_cli(args) == (r.returncode, r.stdout), f"{name}: rust {r.returncode} {r.stdout!r} {r.stderr!r}"
