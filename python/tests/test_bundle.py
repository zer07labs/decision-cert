"""The issuer's side of the inclusion spec (decision_cert._bundle, plan Phase 4): the certificate leaf and
its record, `certify --leaf-out`, `log backfill`, and `bundle`; then end to end: issue -> leaf -> a
test-local tree -> proof and a checkpoint signed with the fixtures' test keys -> bundle -> both
command-line verifiers accept it. The tree, checkpoints and cosignatures are built with the generator's
helpers (tools/gen_inclusion_fixtures.py), not the verifier's. The Rust halves are skipped when cargo is
not on PATH (CI always has it)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from support import FIXTURES
from test_issue import cases, domain

import decision_cert as dc
from decision_cert.__main__ import main
from decision_cert.issue import certify as ct

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_inclusion_fixtures as gen

SET = FIXTURES / "inclusion-v1"
RUST = Path(__file__).resolve().parents[2] / "rust"
TRUST = SET / "trust" / "acme-bank.json"  # acme-bank's log (gen.LOG_A) and witness w1
TRUST_GLOBEX = SET / "trust" / "globex.json"
TENANT = gen.TENANT
OLDER = {  # certificates issued before acme-bank's log existed: one per spec
    "v1": "valid_basic",
    "v1.1": "v1.1/valid_basic",
    "v1.2": "v1.2/valid_basic",
    "v1.3": "v1.3/valid_basic",
    "v1.4": "v1.4/valid_basic",
    "v1.5_operator": "v1.5/valid_operator",
    "v1.5_hosted": "v1.5/valid_hosted",
}


def fixture_cert(name: str) -> dict[str, Any]:
    c: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["certificate"]
    return c


def cli(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as e:
            code = int(e.code or 0)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(scope="module")
def rust_bin() -> Path:
    if shutil.which("cargo") is None:
        pytest.skip("cargo not on PATH")
    subprocess.run(["cargo", "build", "--quiet", "--locked", "--features", "cli"], cwd=RUST, check=True)
    return RUST / "target" / "debug" / "decision-cert"


def rust_cli(binary: Path, args: list[str]) -> tuple[int, str]:
    r = subprocess.run([str(binary), *args], capture_output=True, text=True, check=False)
    return r.returncode, r.stdout


# ---------- the leaf ----------


@pytest.mark.parametrize(
    ("name", "leaf_file"),
    [("v1.2/valid_basic", "certificate_v1_2"), ("v1.5/valid_operator", "certificate_v1_5")],
)
def test_the_certificate_leaf_is_the_fixtures_leaf(name: str, leaf_file: str) -> None:
    cert = fixture_cert(name)
    want = json.loads((SET / "leaves" / f"{leaf_file}.json").read_text(encoding="utf-8"))
    rec = dc.leaf_record(cert)
    assert rec["leaf"] == want and rec["certificate_id"] == dc.certificate_id(cert) == ct.certificate_id(cert)
    manifest = json.loads((SET / "manifest.json").read_text(encoding="utf-8"))
    case = next(c for c in manifest["cases"] if c["name"] == f"leaf_hash_{leaf_file}")
    assert rec["leaf_hash"] == case["expect"]["leaf_hash"]
    assert set(rec) == {"certificate_id", "leaf", "leaf_hash"}


def test_tenant_is_in_a_v1_5_leaf_only() -> None:
    for name in OLDER.values():
        cert = fixture_cert(name)
        leaf = dc.certificate_leaf(cert).to_json()
        assert ("tenant" in leaf) == (cert["spec"] == dc.SPEC_V1_5)
        assert leaf["spec"] == cert["spec"] and leaf["fitted_at"] == cert["fitted_at"]


@pytest.mark.parametrize(
    "edit",
    [
        lambda c: c.pop("tenant"),
        lambda c: c.update(fitted_at="2026-10-25 12:00:00"),
        lambda c: c.update(spec="decision-certificate.v2"),
        lambda c: c.pop("signer_key_id"),
    ],
)
def test_a_value_that_is_not_a_certificate_has_no_leaf(edit: Any) -> None:
    cert = fixture_cert("v1.5/valid_operator")
    edit(cert)
    with pytest.raises(dc.InclusionError) as e:
        dc.certificate_leaf(cert)
    assert e.value.name is dc.ErrorName.LEAF_FORM
    with pytest.raises(dc.InclusionError):
        dc.certificate_leaf([cert])


def test_leaf_records_are_one_jcs_line_each() -> None:
    recs = [dc.leaf_record(fixture_cert(n)) for n in ("v1.2/valid_basic", "v1.5/valid_hosted")]
    text = dc.leaf_records_text(recs)
    lines = text.splitlines()
    assert text.endswith("\n") and len(lines) == 2
    assert [json.loads(x) for x in lines] == recs
    assert [x.encode() for x in lines] == [dc.canonical(r) for r in recs]


# ---------- the issuer writes the leaf ----------


def issue_with_leaf_out(tmp: Path, *extra: str) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """`certify --spec v1.5 --tenant acme-bank --leaf-out`: (the certificate, its leaf record, the key)."""
    preds, rows = cases(2000)
    (tmp / "preds.jsonl").write_text("".join(json.dumps(p) + "\n" for p in preds))
    (tmp / "rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    if not (tmp / "op.pem").exists():
        ct.keygen(tmp / "op.pem")
    out, leaves = tmp / "cal.json", tmp / "leaves.jsonl"
    ct.main(["certify", "--predictions", str(tmp / "preds.jsonl"), "--data", str(tmp / "rows.jsonl"),
             "--domain-dir", str(domain(tmp)), "--backend", "toy", "--key", str(tmp / "op.pem"),
             "--audit", "full-label", "--spec", dc.SPEC_V1_5, "--tenant", TENANT, "--out", str(out),
             "--leaf-out", str(leaves), *extra])  # fmt: skip
    cert = json.loads(out.read_text())["approved"]["certificate"]
    (rec,) = [json.loads(x) for x in leaves.read_text().splitlines()]
    return cert, rec, ct.load_private_key(tmp / "op.pem")


def test_certify_leaf_out_writes_the_certificate_s_leaf(tmp_path: Path) -> None:
    cert, rec, _ = issue_with_leaf_out(tmp_path)
    assert rec == dc.leaf_record(cert)
    assert rec["leaf"] == {
        "kind": "certificate",
        "certificate_id": ct.certificate_id(cert),
        "signer_key_id": cert["signer_key_id"],
        "spec": dc.SPEC_V1_5,
        "fitted_at": cert["fitted_at"],
        "tenant": TENANT,
    }
    leaf = dc.Leaf.from_json(rec["leaf"])
    assert base64.b64decode(rec["leaf_hash"]) == dc.leaf_hash(leaf)
    report = json.loads((tmp_path / "cal.certify.json").read_text())
    assert report["decisions"]["approved"]["certificate_id"] == rec["certificate_id"]


# ---------- backfill ----------


def write(tmp: Path, name: str, v: Any) -> Path:
    p = tmp / name
    p.write_text(json.dumps(v), encoding="utf-8")
    return p


def test_backfill_orders_by_fitted_at_then_certificate_id_and_writes_each_once() -> None:
    certs = [fixture_cert(n) for n in OLDER.values()]
    later = fixture_cert("v1.2/valid_dr_map")
    assert later["fitted_at"] == certs[0]["fitted_at"]
    recs = dc.backfill_records([*certs, certs[2], later], TENANT)
    ids = [r["certificate_id"] for r in recs]
    assert len(ids) == len(set(ids)) == len(certs) + 1
    assert [(r["leaf"]["fitted_at"], r["certificate_id"]) for r in recs] == sorted(
        (c["fitted_at"], dc.certificate_id(c)) for c in [*certs, later]
    )
    # a later fitted_at comes after every earlier one, whatever its id
    early = dict(later, fitted_at="2026-01-01T00:00:00Z")
    assert dc.backfill_records([*certs, early], TENANT)[0]["leaf"]["fitted_at"] == "2026-01-01T00:00:00Z"
    # each record is marked backfilled beside its leaf; the leaf and its hash are the ones any certificate gets
    plain = [dc.leaf_record(c) for c in dc.backfill_order([*certs, later])]
    assert recs == [{**r, "backfilled": True} for r in plain]
    assert all("backfilled" not in r for r in plain)
    assert [(r["leaf"], r["leaf_hash"]) for r in recs] == [(r["leaf"], r["leaf_hash"]) for r in plain]


def test_backfill_refuses_another_tenant_s_certificate() -> None:
    with pytest.raises(dc.InclusionError) as e:
        dc.backfill_records([fixture_cert("v1.2/valid_basic"), fixture_cert("v1.5/valid_operator")], "globex")
    assert e.value.name is dc.ErrorName.TENANT_MISMATCH
    # a v1 to v1.4 certificate names no tenant
    assert len(dc.backfill_records([fixture_cert("v1.4/valid_basic")], "globex")) == 1
    with pytest.raises(ValueError, match="tenant"):
        dc.backfill_records([], "acme bank")


def test_log_backfill_command(tmp_path: Path) -> None:
    files = [write(tmp_path, f"{tag}.json", fixture_cert(n)) for tag, n in OLDER.items()]
    calibration = write(tmp_path, "cal.json", {"approved": {"certificate": fixture_cert("v1.3/valid_dr_map")}})
    out = tmp_path / "backfill.jsonl"
    code, stdout, _ = cli(["log", "backfill", "--tenant", TENANT, "--leaf-out", str(out), *map(str, files),
                           str(calibration), str(files[0])])  # fmt: skip
    assert code == 0 and "no early time evidence" in stdout
    want = dc.backfill_records([*(fixture_cert(n) for n in OLDER.values()), fixture_cert("v1.3/valid_dr_map")], TENANT)
    assert out.read_text() == dc.leaf_records_text(want)
    # refusals: another tenant's v1.5 certificate, a file that is not a certificate, usage
    out.unlink()
    assert cli(["log", "backfill", "--tenant", "globex", "--leaf-out", str(out), *map(str, files)])[0] == 1
    assert cli(["log", "backfill", "--tenant", TENANT, "--leaf-out", str(out), str(TRUST)])[0] == 1
    assert not out.exists()
    assert cli(["log", "backfill", "--tenant", "acme bank", "--leaf-out", str(out), str(files[0])])[0] == 2
    assert cli(["log", "backfill", "--tenant", TENANT, "--leaf-out", str(out), "/nonexistent.json"])[0] == 2
    assert cli(["log", "backfill", "--tenant", TENANT, str(files[0])])[0] == 2
    assert cli(["log"])[0] == 2


# ---------- a test-local log: the generator's tree and signing helpers ----------


class MemoryLog:
    """acme-bank's log in memory: leaves appended in order, checkpoints signed with the fixtures' log key
    and cosigned by witness w1 (test keys from fixed seeds)."""

    def __init__(self) -> None:
        self.leaves: list[dict[str, Any]] = []

    def append(self, leaf: dict[str, Any]) -> int:
        self.leaves.append(leaf)
        return len(self.leaves) - 1

    def hashes(self, size: int) -> list[bytes]:
        return [gen.jcs_leaf_hash(x) for x in self.leaves[:size]]

    def checkpoint(self, size: int, cosigned_at: int) -> str:
        text = gen.note_text(gen.LOG_A, size, gen.mth(self.hashes(size)))
        return gen.checkpoint(text, [gen.log_line(text), gen.cosig_line(text, gen.W1, cosigned_at)])

    def proof(self, index: int, size: int) -> list[str]:
        return [gen.b64(x) for x in gen.path(self.hashes(size), index)]


def bundle_args(tmp: Path, cert: Path, index: int, proof: list[str], checkpoint: str, **kw: Path) -> list[str]:
    (tmp / "proof.json").write_text(json.dumps(proof))
    (tmp / "checkpoint.txt").write_text(checkpoint)
    return ["bundle", "--certificate", str(cert), "--leaf-index", str(index), "--proof", str(tmp / "proof.json"),
            "--checkpoint", str(tmp / "checkpoint.txt"), "--trust", str(kw.get("trust", TRUST)),
            "--out", str(kw.get("out", tmp / "bundle.json"))]  # fmt: skip


def test_end_to_end_issue_backfill_append_checkpoint_bundle_verify(tmp_path: Path, rust_bin: Path) -> None:
    # the log starts: the older certificates are backfilled first
    log = MemoryLog()
    older = {tag: write(tmp_path, f"{tag}.json", fixture_cert(n)) for tag, n in OLDER.items()}
    leaves = tmp_path / "backfill.jsonl"
    assert cli(["log", "backfill", "--tenant", TENANT, "--leaf-out", str(leaves), *map(str, older.values())])[0] == 0
    backfilled: dict[str, int] = {}
    records: dict[str, Path] = {}
    for line in leaves.read_text().splitlines():
        rec = json.loads(line)
        assert rec["backfilled"] is True
        backfilled[rec["certificate_id"]] = log.append(rec["leaf"])
        records[rec["certificate_id"]] = write(tmp_path, f"record-{len(records)}.json", rec)
    # the issuer issues a certificate and writes its leaf; the log appends it, then other leaves
    cert, rec, key = issue_with_leaf_out(tmp_path)
    cert_file = write(tmp_path, "issued.json", cert)
    index = log.append(rec["leaf"])
    for i in range(5):
        log.append(gen.keyset_leaf(i))

    # while waiting: a checkpoint from before the append does not include the leaf yet (exit 3)
    early = log.checkpoint(index, gen.T0)
    code, stdout, _ = cli(bundle_args(tmp_path, cert_file, index, log.proof(0, index), early))
    assert code == 3 and json.loads(stdout)["error"] == "bad_proof"
    assert not (tmp_path / "bundle.json").exists()

    # the next cosigned checkpoint includes it: bundle, then both verifiers accept the bundle
    size, t = len(log.leaves), gen.T0 + 3600
    code, stdout, _ = cli(bundle_args(tmp_path, cert_file, index, log.proof(index, size), log.checkpoint(size, t)))
    assert code == 0, stdout
    out = tmp_path / "bundle.json"
    data = out.read_bytes()
    assert data == dc.canonical(json.loads(data))  # written as its JCS bytes
    args = ["verify-bundle", str(out), "--trust", str(TRUST)]
    py = cli(args)
    assert (py[0], py[1]) == (0, stdout)
    assert rust_cli(rust_bin, args) == (0, stdout)
    verdict = json.loads(stdout)
    assert verdict["verdict"] == "accepted" and verdict["certificate_id"] == rec["certificate_id"]
    assert (verdict["backfilled"], verdict["backfilled_by"]) == (False, [])  # a newly issued certificate
    assert "backfilled" not in json.loads(data)
    assert (verdict["leaf_index"], verdict["tree_size"], verdict["t_proven"]) == (index, size, gen.time_of(t))
    # the certificate itself verifies on its own, for the tenant
    keys = write(tmp_path, "keys.json", {ct.key_id(key.public_key()): ct.b64url(ct.raw_public(key.public_key()))})
    assert cli(["verify", str(cert_file), "--keys", str(keys), "--tenant", TENANT])[0] == 0

    # a proof against the older checkpoint stays valid as the log grows: the bundle is not refreshed
    for i in range(5, 40):
        log.append(gen.keyset_leaf(i))
    assert cli(args)[0] == 0 and rust_cli(rust_bin, args)[0] == 0

    # a backfilled certificate: no early time evidence; t_proven is the first cosigned checkpoint after
    # the log started, not its fitted_at
    first = older["v1.5_hosted"]
    cid = dc.certificate_id(fixture_cert(OLDER["v1.5_hosted"]))
    i, size, t = backfilled[cid], len(log.leaves), gen.T0 + 7200
    out = tmp_path / "backfilled.json"
    marked = [*bundle_args(tmp_path, first, i, log.proof(i, size), log.checkpoint(size, t), out=out),
              "--leaf-record", str(records[cid])]  # fmt: skip
    code, stdout, _ = cli(marked)
    assert code == 0, stdout
    assert json.loads(out.read_bytes())["backfilled"] is True  # carried from its leaf record (§8)
    args = ["verify-bundle", str(out), "--trust", str(TRUST)]
    assert rust_cli(rust_bin, args) == (0, stdout) and cli(args)[:2] == (0, stdout)
    verdict = json.loads(stdout)
    assert (verdict["backfilled"], verdict["backfilled_by"]) == (True, ["bundle"])
    assert verdict["t_proven"] == gen.time_of(t) > fixture_cert(OLDER["v1.5_hosted"])["fitted_at"]
    # stripped of the bundle's member, it is still marked under a configuration that gives the log's started_at
    stripped = json.loads(out.read_bytes())
    del stripped["backfilled"]
    stripped_file = write(tmp_path, "stripped.json", stripped)
    started = json.loads(TRUST.read_text())
    started["logs"][0]["started_at"] = gen.time_of(gen.T0)
    started_file = write(tmp_path, "started.json", started)
    for trust_file, want in ((TRUST, (False, [])), (started_file, (True, ["started_at"]))):
        args = ["verify-bundle", str(stripped_file), "--trust", str(trust_file)]
        code, line, _ = cli(args)
        assert code == 0 and rust_cli(rust_bin, args) == (0, line)
        assert (json.loads(line)["backfilled"], json.loads(line)["backfilled_by"]) == want
    assert verdict["leaf_index"] < len(backfilled) <= index  # backfilled before any new leaf
    # a v1 certificate, backfilled, bundles the same way (here with --backfilled)
    v1 = dc.certificate_id(fixture_cert(OLDER["v1"]))
    i = backfilled[v1]
    code, stdout, _ = cli([*bundle_args(tmp_path, older["v1"], i, log.proof(i, size), log.checkpoint(size, t),
                                        out=out), "--backfilled"])  # fmt: skip
    args = ["verify-bundle", str(out), "--trust", str(TRUST)]
    assert code == 0 and rust_cli(rust_bin, args) == (0, stdout)
    assert json.loads(stdout)["backfilled_by"] == ["bundle"]
    # a leaf record for another certificate is a usage error; nothing written
    out.unlink()
    wrong = [*bundle_args(tmp_path, older["v1"], i, log.proof(i, size), log.checkpoint(size, t), out=out),
             "--leaf-record", str(records[cid])]  # fmt: skip
    assert cli(wrong)[0] == 2 and not out.exists()


def test_bundle_refusals(tmp_path: Path) -> None:
    log = MemoryLog()
    certs = {tag: fixture_cert(n) for tag, n in OLDER.items()}
    files = {tag: write(tmp_path, f"{tag}.json", c) for tag, c in certs.items()}
    at = {tag: log.append(dc.certificate_leaf(c).to_json()) for tag, c in certs.items()}
    size = len(log.leaves)
    cp = log.checkpoint(size, gen.T0)
    out = tmp_path / "bundle.json"

    def run(tag: str, index: int, proof_of: int, **kw: Path) -> tuple[int, dict[str, Any]]:
        code, stdout, _ = cli(bundle_args(tmp_path, files[tag], index, log.proof(proof_of, size), cp, **kw))
        return code, json.loads(stdout) if stdout else {}

    assert run("v1.2", at["v1.2"], at["v1.2"])[0] == 0
    out.unlink()
    # a bundle for a different certificate: another certificate's index and proof
    code, line = run("v1.2", at["v1.3"], at["v1.3"])
    assert (code, line["verdict"], line["error"]) == (1, "refused", "bad_proof")
    code, line = run("v1.2", at["v1.2"], at["v1.3"])
    assert (code, line["error"]) == (1, "bad_proof")
    # the wrong tenant: acme-bank's v1.5 certificate under globex's configuration, and acme-bank's log under it
    code, line = run("v1.5_operator", at["v1.5_operator"], at["v1.5_operator"], trust=TRUST_GLOBEX)
    assert (code, line["error"]) == (1, "tenant_mismatch")
    code, line = run("v1.2", at["v1.2"], at["v1.2"], trust=TRUST_GLOBEX)
    assert (code, line["error"]) == (1, "unknown_log")
    # an index out of range: not in this checkpoint yet (exit 3), or past the proof
    code, line = run("v1.2", size, at["v1.2"])
    assert (code, line["error"]) == (3, "bad_proof")
    assert not out.exists()
    # library: the same refusals by name
    trust = dc.LogTrust.from_json(dc.parse_ijson(TRUST.read_text()))
    with pytest.raises(dc.NotYetInCheckpoint) as e:
        dc.bundle_certificate(certs["v1.2"], size + 4, log.proof(0, size), cp, trust)
    assert (e.value.name, e.value.leaf_index, e.value.tree_size) == (dc.ErrorName.BAD_PROOF, size + 4, size)
    with pytest.raises(dc.InclusionError) as e2:
        dc.bundle_certificate(certs["v1.2"], at["v1.2"], log.proof(at["v1.2"], size), cp, trust, log_id=gen.LOG_G)
    assert e2.value.name is dc.ErrorName.UNKNOWN_LOG
    b, verdict = dc.bundle_certificate(certs["v1.4"], at["v1.4"], log.proof(at["v1.4"], size), cp, trust)
    assert dc.verify_bundle(dc.parse_ijson(dc.bundle_bytes(b).decode()), trust) == verdict
    assert "backfilled" not in b and verdict.backfilled is False and verdict.backfilled_by == ()
    b, verdict = dc.bundle_certificate(
        certs["v1.4"], at["v1.4"], log.proof(at["v1.4"], size), cp, trust, backfilled=True
    )
    assert b["backfilled"] is True and verdict.backfilled is True and verdict.backfilled_by == ("bundle",)
    # usage and unreadable files: exit 2, nothing written
    good = bundle_args(tmp_path, files["v1.2"], at["v1.2"], log.proof(at["v1.2"], size), cp)
    for i, bad in ((good.index("--trust") + 1, str(SET / "trust" / "invalid_m_zero.json")),
                   (good.index("--certificate") + 1, "/nonexistent.json"),
                   (good.index("--leaf-index") + 1, "-1"),
                   (good.index("--leaf-index") + 1, "1.0")):  # fmt: skip
        args = list(good)
        args[i] = bad
        assert cli(args)[0] == 2, bad
    assert not out.exists()
