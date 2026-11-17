"""The Python inclusion verifier (`decision_cert._inclusion`, decision-cert-inclusion.v1) on every case
of `fixtures/inclusion-v1/manifest.json`, written by `tools/gen_inclusion_fixtures.py`; then the Python and
Rust command-line verifiers on every bundle and consistency document there and on random trees, line for
line. The Rust halves are skipped when cargo is not on PATH (CI always has it)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import random
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from support import FIXTURES

import decision_cert as dc
from decision_cert import _inclusion as inc
from decision_cert.__main__ import main

SET = FIXTURES / "inclusion-v1"
RUST = Path(__file__).resolve().parents[2] / "rust"
MANIFEST: dict[str, Any] = json.loads((SET / "manifest.json").read_text(encoding="utf-8"))
CASES: list[dict[str, Any]] = MANIFEST["cases"]


def text(rel: str) -> str:
    return (SET / rel).read_text(encoding="utf-8")


def read_trust(rel: str) -> dc.LogTrust:
    return dc.LogTrust.from_json(dc.parse_ijson(text(rel)))


def line_of(check: str, doc_rel: str, trust_rel: str) -> dict[str, Any]:
    """The verdict line `verify-bundle` / `verify-consistency` prints, without `detail`."""
    trust = read_trust(trust_rel)
    form = dc.ErrorName.BUNDLE_FORM if check == "bundle" else dc.ErrorName.CONSISTENCY_FORM
    try:
        try:
            v = dc.parse_ijson(text(doc_rel))
        except ValueError as e:
            raise dc.InclusionError(form, f"not I-JSON: {e}") from None
        out = dc.verify_bundle(v, trust).to_json() if check == "bundle" else dc.verify_consistency(v, trust).to_json()
    except dc.InclusionError as e:
        return {"verdict": "refused", "error": str(e.name)}
    return {**out, "verdict": "accepted"}


def outcome(case: dict[str, Any]) -> Any:
    """What the Python verifier says on one manifest case, in the manifest's `expect` shape."""
    check = case["check"]
    if check in ("bundle", "consistency"):
        return line_of(check, case["doc"], case["trust"])
    if check == "trust":
        try:
            t = read_trust(case["trust"])
        except ValueError:
            return {"verdict": "refused", "error": "trust_form"}
        except dc.InclusionError as e:
            return {"verdict": "refused", "error": str(e.name)}
        return {"verdict": "accepted", "tenant": t.tenant, "m": t.m, "policy": str(t.policy)}
    if check == "tenants":
        try:
            dc.check_tenants([read_trust(t) for t in case["trusts"]])
        except dc.InclusionError as e:
            return {"verdict": "refused", "error": str(e.name)}
        return {"verdict": "accepted"}
    if check == "policy":
        trust = read_trust(case["trust"])
        result: dc.InclusionVerdict | dc.InclusionError | None = None
        if case["doc"] is not None:
            try:
                result = dc.verify_bundle(dc.parse_ijson(text(case["doc"])), trust)
            except dc.InclusionError as e:
                result = e
        o = dc.apply_policy(result, trust.policy)
        out: dict[str, Any] = {"outcome": o.action}
        if o.verdict is not None:
            out["verdict"] = o.verdict.to_json()
        if o.error is not None:
            out["error"] = str(o.error.name)
        return out
    if check == "leaf_hash":
        leaf = dc.Leaf.from_json(dc.parse_ijson(text(case["leaf"])))
        return {"leaf_hash": base64.b64encode(dc.leaf_hash(leaf)).decode()}
    if check == "rfc9162_inclusion":
        h = inc.hash_leaf_bytes(bytes.fromhex(case["leaf_input"]))
        p = [bytes.fromhex(x) for x in case["path"]]
        return inc.verify_inclusion_path(case["leaf_index"], case["tree_size"], h, p, bytes.fromhex(case["root"]))
    if check == "rfc9162_consistency":
        p = [bytes.fromhex(x) for x in case["path"]]
        r1, r2 = bytes.fromhex(case["older_root"]), bytes.fromhex(case["newer_root"])
        return inc.verify_consistency_path(case["older"], case["newer"], r1, r2, p)
    raise AssertionError(f"unknown check {check}")


def test_the_set_is_whole() -> None:
    listed = {line.split("  ")[1] for line in (SET / "INCLUSION.sha256").read_text().splitlines()}
    on_disk = {p.relative_to(SET).as_posix() for p in SET.rglob("*.json")}
    assert listed == on_disk
    names = [c["name"] for c in CASES]
    assert len(names) == len(set(names))
    errors = {c["expect"].get("error") for c in CASES if isinstance(c["expect"], dict)}
    assert {str(e) for e in dc.ErrorName} <= errors, "every §14 error name has a case"
    checks = Counter(c["check"] for c in CASES)
    assert checks["bundle"] >= 140 and checks["consistency"] >= 40 and checks["policy"] == 9, checks


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_python_agrees_with_every_inclusion_v1_case(case: dict[str, Any]) -> None:
    assert outcome(case) == case["expect"]


# ---------- unit checks beside the fixtures ----------


def test_parse_ijson_refuses_a_repeated_member() -> None:
    with pytest.raises(ValueError, match="appears twice"):
        dc.parse_ijson('{"a": 1, "b": {"c": 1, "c": 2}}')
    with pytest.raises(ValueError):
        dc.parse_ijson('{"a": NaN}')
    with pytest.raises(ValueError):
        dc.parse_ijson('["\\ud800"]')
    assert dc.parse_ijson('{"a": [1, 2.5, "x"]}') == {"a": [1, 2.5, "x"]}


def test_tree_helpers_agree_on_every_small_tree() -> None:
    leaves = [inc.hash_leaf_bytes(bytes([i])) for i in range(17)]
    for n in range(1, 18):
        d = leaves[:n]
        root = inc.root_hash(d)
        assert root is not None
        for i in range(n):
            p = inc.audit_path(d, i)
            assert p is not None and inc.verify_inclusion_path(i, n, d[i], p, root)
            assert not any(inc.verify_inclusion_path(j, n, d[i], p, root) for j in range(n) if j != i)
        for m in range(1, n + 1):
            r1 = inc.root_hash(d[:m])
            c = inc.consistency_path(d, m)
            assert r1 is not None and c is not None and inc.verify_consistency_path(m, n, r1, root, c)
    assert inc.root_hash([]) is None and inc.audit_path(leaves, 17) is None and inc.consistency_path(leaves, 0) is None


def test_apply_policy() -> None:
    err = dc.InclusionError(dc.ErrorName.BAD_PROOF, "x")
    assert dc.apply_policy(None, "off") == dc.PolicyOutcome("load")
    assert dc.apply_policy(err, dc.Policy.OFF) == dc.PolicyOutcome("load")
    assert dc.apply_policy(err, "warn") == dc.PolicyOutcome("refuse", error=err)
    o = dc.apply_policy(None, "warn")
    assert o.action == "load_with_warning" and o.error is not None and o.error.name == "inclusion_missing"
    assert dc.apply_policy(None, "refuse").action == "refuse"


def test_parse_checkpoint_reads_the_note() -> None:
    case = next(c for c in CASES if c["name"] == "bundle_valid_size_8_index_4_keyset")
    b = json.loads(text(case["doc"]))
    cp = dc.parse_checkpoint(b["checkpoint"])
    assert cp.tree_size == 8 and cp.origin == b["log_id"] and len(cp.signatures) == 2
    assert cp.note_text == "".join(line + "\n" for line in b["checkpoint"].split("\n")[:3])
    with pytest.raises(dc.InclusionError) as e:
        dc.parse_checkpoint(b["checkpoint"][:-1])
    assert e.value.name == dc.ErrorName.CHECKPOINT_FORM and str(e.value).startswith("checkpoint_form: ")


# ---------- the command-line verifiers, Python and Rust, line for line ----------


def python_cli(args: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = main(args)
        except SystemExit as e:
            code = int(e.code or 0)
    return code, out.getvalue()


@pytest.fixture(scope="module")
def rust_bin() -> Path:
    if shutil.which("cargo") is None:
        pytest.skip("cargo not on PATH")
    subprocess.run(["cargo", "build", "--quiet", "--locked", "--features", "cli"], cwd=RUST, check=True)
    return RUST / "target" / "debug" / "decision-cert"


def rust_cli(binary: Path, args: list[str]) -> tuple[int, str]:
    r = subprocess.run([str(binary), *args], capture_output=True, text=True, check=False)
    return r.returncode, r.stdout


def same_output(rust: tuple[int, str], python: tuple[int, str], where: str) -> None:
    """The same exit code and the same stdout, byte for byte; for a document that is not I-JSON, the
    same line apart from the parser's wording in `detail`."""
    assert rust[0] == python[0], where
    if rust[1] != python[1]:
        r, p = json.loads(rust[1]), json.loads(python[1])
        assert r["detail"].startswith("not I-JSON: ") and p["detail"].startswith("not I-JSON: "), where
        r.pop("detail")
        p.pop("detail")
        assert r == p, where


def cli_cases() -> list[tuple[str, list[str], int]]:
    out = []
    for c in CASES:
        if c["check"] in ("bundle", "consistency"):
            cmd = "verify-bundle" if c["check"] == "bundle" else "verify-consistency"
            code = 0 if c["expect"]["verdict"] == "accepted" else 1
            out.append((c["name"], [cmd, str(SET / c["doc"]), "--trust", str(SET / c["trust"])], code))
        elif c["check"] == "trust" and c["expect"]["verdict"] == "refused":
            some = next(x for x in CASES if x["check"] == "bundle")
            out.append((c["name"], ["verify-bundle", str(SET / some["doc"]), "--trust", str(SET / c["trust"])], 2))
    bundle = str(SET / "bundles" / "valid_size_8_index_4_keyset.json")
    trust = str(SET / "trust" / "acme-bank.json")
    out += [
        ("missing_bundle", ["verify-bundle", "/nonexistent/bundle.json", "--trust", trust], 2),
        ("missing_trust", ["verify-bundle", bundle, "--trust", "/nonexistent/trust.json"], 2),
        ("no_trust_flag", ["verify-bundle", bundle], 2),
        ("missing_document", ["verify-consistency", "/nonexistent/doc.json", "--trust", trust], 2),
    ]
    return out


CLI_CASES = cli_cases()


@pytest.mark.parametrize(("name", "args", "code"), CLI_CASES, ids=[c[0] for c in CLI_CASES])
def test_python_cli_exit_codes(name: str, args: list[str], code: int) -> None:
    got, out = python_cli(args)
    assert got == code, name
    if code in (0, 1):
        line = json.loads(out)
        assert line["verdict"] == ("accepted" if code == 0 else "refused") and out.count("\n") == 1
    else:
        assert out == ""


def test_rust_and_python_cli_agree_on_every_document(rust_bin: Path) -> None:
    for name, args, _ in CLI_CASES:
        same_output(rust_cli(rust_bin, args), python_cli(args), name)


def test_rust_and_python_cli_agree_on_a_file_that_is_not_utf8(rust_bin: Path, tmp_path: Path) -> None:
    p = tmp_path / "latin1.json"
    p.write_bytes(b'{"spec": "\xe9"}')
    args = ["verify-bundle", str(p), "--trust", str(SET / "trust" / "acme-bank.json")]
    same_output(rust_cli(rust_bin, args), python_cli(args), "not utf-8")
    assert python_cli(args)[0] == 1


# ---------- the differential test: random trees, indices and edits ----------


def _random_documents(tmp: Path, rng: random.Random) -> list[tuple[str, list[str]]]:
    """Bundles and consistency documents over random trees of the fixtures' log, at random indices and
    sizes, with random edits; each with its trust configuration. Built here with the generator's helpers
    (tools/gen_inclusion_fixtures.py), not the verifier."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import gen_inclusion_fixtures as gen

    trusts = {name: str(SET / "trust" / f"{name}.json") for name in ("acme-bank", "acme-bank-m2", "acme-bank-m3")}
    witnesses = list(gen.W)

    def b64_edit(s: str) -> str:
        b = bytearray(base64.b64decode(s))
        b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        return base64.b64encode(bytes(b)).decode()

    out: list[tuple[str, list[str]]] = []
    for k in range(120):
        size = rng.choice([1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 64, 100, 129, 255, 256, 299, 300])
        index = rng.randrange(size)
        cos = [(w, gen.T0 + rng.randrange(0, 4)) for w in rng.sample(witnesses, rng.randint(0, 3))]
        b = gen.bundle(index, size, gen.a_checkpoint(size, cos))
        edit = rng.randrange(10)
        if edit == 1 and b["proof"]:
            b["proof"][rng.randrange(len(b["proof"]))] = b64_edit(b["proof"][0])
        elif edit == 2:
            b["leaf_index"] = rng.randrange(size + 2)
        elif edit == 3 and b["proof"]:
            b["proof"].pop(rng.randrange(len(b["proof"])))
        elif edit == 4:
            other = rng.randrange(1, 301)
            b["checkpoint"] = gen.a_checkpoint(other, cos)
        elif edit == 5:
            lines = b["checkpoint"].split("\n")
            i = rng.randrange(len(lines))
            lines[i] = lines[i][: rng.randrange(len(lines[i]) + 1)]
            b["checkpoint"] = "\n".join(lines)
        elif edit == 6:
            lines = b["checkpoint"].split("\n")
            sig = [i for i, x in enumerate(lines) if x.startswith(gen.EM)]
            i = rng.choice(sig)
            name, value = lines[i][2:].split(" ", 1)
            lines[i] = f"{gen.EM} {name} {b64_edit(value)}"
            b["checkpoint"] = "\n".join(lines)
        f = tmp / f"bundle_{k}.json"
        f.write_text(json.dumps(b), encoding="utf-8")
        out.append(
            (
                f"bundle {k} size {size} index {index} edit {edit}",
                ["verify-bundle", str(f), "--trust", rng.choice(list(trusts.values()))],
            )
        )
    for k in range(60):
        newer = rng.randrange(1, 301)
        older = rng.randrange(1, newer + 1)
        d = gen.consistency(older, newer)
        edit = rng.randrange(6)
        if edit == 1 and d["proof"]:
            d["proof"][rng.randrange(len(d["proof"]))] = b64_edit(d["proof"][0])
        elif edit == 2:
            d["older"], d["newer"] = d["newer"], d["older"]
        elif edit == 3:
            d["newer"] = gen.a_checkpoint(rng.randrange(1, 301))
        f = tmp / f"consistency_{k}.json"
        f.write_text(json.dumps(d), encoding="utf-8")
        out.append(
            (
                f"consistency {k} {older}->{newer} edit {edit}",
                ["verify-consistency", str(f), "--trust", trusts["acme-bank"]],
            )
        )
    return out


def test_rust_and_python_agree_on_random_trees(rust_bin: Path, tmp_path: Path) -> None:
    docs = _random_documents(tmp_path, random.Random(20261117))
    verdicts: Counter[str] = Counter()
    for name, args in docs:
        r, p = rust_cli(rust_bin, args), python_cli(args)
        assert r == p, name
        line = json.loads(p[1])
        verdicts[line.get("error", line["verdict"])] += 1
    assert verdicts["accepted"] >= 30 and len(verdicts) >= 6, verdicts
