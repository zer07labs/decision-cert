"""The reference log and witness (decision_cert._log, plan Phase 5): the tlog-tiles layout, the tree read
from the tiles against the verifier's tree code, append's refusals, the checkpoint cadence, the witness's
refusals; then end to end through the command lines: init -> append (issued and backfilled records) ->
checkpoint -> witness cosign -> prove -> bundle -> verify-bundle in the Python and the Rust CLI -> append
more -> checkpoint -> consistency -> verify-consistency in both -> the witness refuses a forked log.

The end-to-end test needs the Rust CLI. It is skipped without cargo, except when DECISION_CERT_REQUIRE_RUST
is set, as CI sets it, where a missing cargo fails it."""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_bundle import OLDER, cli, fixture_cert, issue_with_leaf_out, write

import decision_cert as dc
from decision_cert import _inclusion as inc
from decision_cert._log import seconds_of, tile_path, time_of

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_inclusion_fixtures as gen

RUST = Path(__file__).resolve().parents[2] / "rust"
TENANT = gen.TENANT


def seeded(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"test_log: {name}".encode()).digest())


LOG_KEY, W1_KEY, W2_KEY = seeded("log"), seeded("witness 1"), seeded("witness 2")


def raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pem(tmp: Path, name: str, k: Ed25519PrivateKey) -> Path:
    p = tmp / f"{name}.pem"
    p.write_bytes(
        k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return p


@pytest.fixture(scope="module")
def rust_bin() -> Path:
    if shutil.which("cargo") is None:
        if os.environ.get("DECISION_CERT_REQUIRE_RUST"):
            pytest.fail("DECISION_CERT_REQUIRE_RUST is set and cargo is not on PATH")
        pytest.skip("cargo not on PATH")
    subprocess.run(["cargo", "build", "--quiet", "--locked", "--features", "cli"], cwd=RUST, check=True)
    return RUST / "target" / "debug" / "decision-cert"


def rust_cli(binary: Path, args: list[str]) -> tuple[int, str]:
    r = subprocess.run([str(binary), *args], capture_output=True, text=True, check=False)
    return r.returncode, r.stdout


def ok(args: list[str]) -> dict[str, Any]:
    """Run a Python command that must succeed; its JSON line."""
    code, out, err = cli(args)
    assert code == 0, (args, out, err)
    v: dict[str, Any] = json.loads(out)
    return v


def refused(args: list[str], error: str, code: int = 1) -> None:
    got, out, err = cli(args)
    assert got == code, (args, out, err)
    if code == 1:
        assert json.loads(out)["error"] == error, out
    else:
        assert error in err, err


def leaves(n: int, offset: int = 0) -> list[dict[str, Any]]:
    return [gen.keyset_leaf(offset + i) for i in range(n)]


def new_log(tmp: Path, name: str = "log", **kw: Any) -> dc.FileLog:
    return dc.FileLog.init(tmp / name, TENANT, raw(LOG_KEY), **kw)


# ---------- the layout and the tree ----------


def test_tile_paths_are_tlog_tiles() -> None:
    assert tile_path(0, 0) == "tile/0/000"
    assert tile_path(0, 5, 44) == "tile/0/005.p/44"
    assert tile_path(2, 1000) == "tile/2/x001/000"
    assert tile_path(1, 1234067) == "tile/1/x001/x234/067"
    assert tile_path("entries", 12, 7) == "tile/entries/012.p/7"


def test_the_tree_on_the_tiles_is_rfc9162(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    rng = random.Random(7)
    all_leaves: list[dict[str, Any]] = []
    # appends of several sizes, crossing tile boundaries at 256 and 512, and a level-1 hash
    for batch in (1, 2, 250, 3, 1, 300, 10):
        new = leaves(batch, len(all_leaves))
        log.append([{"leaf": x} for x in new], seconds_of("2027-01-01T00:00:00Z"))
        all_leaves += new
    n = log.size
    assert n == len(all_leaves) == 567
    d = log.path
    assert (d / "tile/0/000").stat().st_size == (d / "tile/0/001").stat().st_size == 256 * 32
    assert (d / "tile/0/002.p/55").stat().st_size == 55 * 32
    assert (d / "tile/1/000.p/2").stat().st_size == 2 * 32
    assert not (d / "tile/0/000.p").exists()  # partials go when the full tile is written
    assert (d / "tile/entries/000").exists() and (d / "tile/entries/002.p/55").exists()
    assert [log.leaf(i) for i in range(n)] == all_leaves
    hashes = [inc.leaf_hash(dc.Leaf.from_json(x)) for x in all_leaves]
    for size in [1, 2, 3, 255, 256, 257, 511, 512, 513, n, *rng.sample(range(1, n + 1), 20)]:
        assert log.root(size) == inc.root_hash(hashes[:size]), size
        for i in {0, size - 1, rng.randrange(size)}:
            p = log.inclusion_proof(i, size)
            assert p == inc.audit_path(hashes[:size], i)
            assert inc.verify_inclusion_path(i, size, hashes[i], p, log.root(size))
        older = rng.randrange(1, size + 1)
        c = log.consistency_proof(older, size)
        assert c == (inc.consistency_path(hashes[:size], older) if older < size else [])
        assert inc.verify_consistency_path(older, size, log.root(older), log.root(size), c)
    # a reopened log reads the same tree
    again = dc.FileLog(d)
    assert again.size == n and again.root(n) == log.root(n)


def test_append_refusals_append_nothing(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    now = seconds_of("2026-11-01T00:00:00Z")
    v15 = fixture_cert("v1.5/valid_operator")  # acme-bank's
    globex_head = gen.audit_head_leaf(3, tenant="globex")

    def refuse(records: list[Any], name: str) -> None:
        with pytest.raises(dc.LogError) as e:
            log.append(records, now)
        assert e.value.name == name, e.value
        assert dc.FileLog(log.path).size == log.size

    good = {"leaf": gen.keyset_leaf(1)}
    refuse([good, {"leaf": globex_head}], "tenant_mismatch")
    refuse([good, {"leaf": {**dc.leaf_record(v15)["leaf"], "tenant": "globex"}}], "tenant_mismatch")
    refuse([good, {"leaf": {"kind": "receipt"}}], "leaf_form")
    refuse([good, "not a record"], "record_form")
    refuse([good, {"leaf": gen.keyset_leaf(2), "note": 1}], "record_form")
    refuse(
        [{**dc.leaf_record(v15), "leaf_hash": dc.leaf_record(fixture_cert("v1.2/valid_basic"))["leaf_hash"]}],
        "record_form",
    )
    refuse([{**dc.leaf_record(v15), "backfilled": False}], "record_form")
    refuse([{"leaf": gen.keyset_leaf(2), "backfilled": True}], "record_form")
    refuse([good, good], "duplicate_leaf")
    assert log.size == 0 and log.config.started_at is None
    # backfilled leaves first, then new ones; never a backfilled one after a new one
    bf = dc.backfill_records([fixture_cert(n) for n in OLDER.values()], TENANT)
    out = log.append(bf[:2], now)
    assert [o["leaf_index"] for o in out] == [0, 1] and all(o["backfilled"] for o in out)
    assert log.config.started_at == "2026-11-01T00:00:00Z" == dc.FileLog(log.path).config.started_at
    log.append([good], now + 60)
    assert log.config.started_at == "2026-11-01T00:00:00Z"  # the first entry's time, kept
    refuse(bf[2:3], "backfill_order")
    refuse([good], "duplicate_leaf")
    # the mark is the log's own record, never in a leaf or a tile
    assert [log.leaf_record(i).get("backfilled") for i in range(3)] == [True, True, None]
    assert log.leaf(0) == bf[0]["leaf"] and log.entry(0) == dc.Leaf.from_json(bf[0]["leaf"]).canonical()
    assert b"backfilled" not in b"".join(p.read_bytes() for p in (log.path / "tile").rglob("*") if p.is_file())


def test_checkpoint_cadence_and_keys(tmp_path: Path) -> None:
    log = new_log(tmp_path, cadence_seconds=3600)
    t = seconds_of("2027-01-01T00:00:00Z")
    with pytest.raises(dc.LogError, match="empty_log"):
        log.checkpoint(LOG_KEY, t)
    log.append([{"leaf": x} for x in leaves(5)], t)
    with pytest.raises(dc.LogError, match="key"):
        log.checkpoint(W1_KEY, t)
    note = log.checkpoint(LOG_KEY, t)
    assert note is not None and (log.path / "checkpoint").read_text() == note
    cp = inc.parse_checkpoint(note)
    assert (cp.origin, cp.tree_size, cp.root_hash) == (log.config.log_id, 5, log.root(5))
    log.append([{"leaf": x} for x in leaves(2, 5)], t + 10)
    assert log.checkpoint(LOG_KEY, t + 3599) is None and log.due(t + 3599) == t + 3600
    assert inc.parse_checkpoint((log.path / "checkpoint").read_text()).tree_size == 5
    assert log.checkpoint(LOG_KEY, t + 3599, force=True) is not None
    assert log.checkpoint(LOG_KEY, t + 3599 + 3600) is not None
    assert log.checkpointed() == {"tree_size": 7, "at": time_of(t + 7199)}


def test_witness_refusals(tmp_path: Path) -> None:
    log = new_log(tmp_path)
    t = seconds_of("2027-01-01T00:00:00Z")
    log.append([{"leaf": x} for x in leaves(4)], t)
    cp4 = log.checkpoint(LOG_KEY, t)
    assert cp4 is not None
    w = dc.FileWitness.init(tmp_path / "w.json", "witness.example/w1", raw(W1_KEY), log.config.trust_entry())
    out, _ = w.cosign(cp4, None, W1_KEY, t + 1)
    assert out.startswith(cp4) and out.count("\n— ") == 2
    log.append([{"leaf": x} for x in leaves(3, 4)], t)
    cp7 = log.checkpoint(LOG_KEY, t, force=True)
    assert cp7 is not None

    def refuse(note: str, doc: Any, name: str, key: Ed25519PrivateKey = W1_KEY) -> None:
        before = (tmp_path / "w.json").read_text()
        with pytest.raises(dc.LogError) as e:
            dc.FileWitness(tmp_path / "w.json").cosign(note, doc, key, t + 2)
        assert e.value.name == name, e.value
        assert (tmp_path / "w.json").read_text() == before

    refuse(cp7, None, "bad_consistency_proof")  # no proof from 4
    doc = log.consistency(cp4, cp7)
    refuse(cp7, {**doc, "proof": doc["proof"][:-1]}, "bad_consistency_proof")
    refuse(cp7, doc, "key", W2_KEY)
    # a checkpoint signed by another key, or of another log
    other = new_log(tmp_path, "other")
    other.append([{"leaf": x} for x in leaves(7)], t)
    cp_other = other.checkpoint(LOG_KEY, t)
    assert cp_other is not None
    refuse(cp_other, doc, "origin_mismatch")
    text = cp7.split("\n\n")[0] + "\n"
    refuse(text + "\n" + dc.log_signature_line(text, log.config.key_name, W2_KEY), doc, "log_signature_missing")
    # a fork with the same log_id and key: another root at a size it cosigned is a split view
    fork = new_log(tmp_path, "fork", log_id=log.config.log_id)
    fork.append([{"leaf": x} for x in leaves(3)] + [{"leaf": gen.keyset_leaf(99)}], t)
    fork4 = fork.checkpoint(LOG_KEY, t)
    assert fork4 is not None
    refuse(fork4, None, "split_view")
    # it extends what it cosigned: cosign 7, then refuse 4 again (a regression)
    out, cp = dc.FileWitness(tmp_path / "w.json").cosign(cp7, doc, W1_KEY, t + 2)
    assert cp.tree_size == 7
    refuse(cp4, None, "size_regression")
    # the same checkpoint again: its earlier line replaced, never two lines from one key
    again, _ = dc.FileWitness(tmp_path / "w.json").cosign(out, None, W1_KEY, t + 3)
    assert inc.parse_checkpoint(again).signatures[-1].value[:8] == (t + 3).to_bytes(8, "big")
    assert again.count("— witness.example/w1 ") == 1


# ---------- end to end, through both command lines ----------


def trust_config(tmp: Path, log_dir: Path, witness: dict[str, Any]) -> Path:
    entry = ok(["log", "info", "--dir", str(log_dir)])["trust_entry"]
    return write(tmp, "log-trust.json", dc.trust_config(TENANT, [entry], [witness]))


def both(rust_bin: Path, args: list[str]) -> dict[str, Any]:
    """The Python and the Rust CLI on one command: the same exit code 0 and the same line."""
    code, out, err = cli(args)
    assert code == 0, (args, out, err)
    assert rust_cli(rust_bin, args) == (0, out), args
    v: dict[str, Any] = json.loads(out)
    return v


def test_end_to_end_issue_log_cosign_prove_bundle_verify(tmp_path: Path, rust_bin: Path) -> None:
    log_key, w_key, w2_key = pem(tmp_path, "log", LOG_KEY), pem(tmp_path, "w1", W1_KEY), pem(tmp_path, "w2", W2_KEY)
    d = tmp_path / "log"
    # the log starts; older certificates are backfilled first, then the issuer's new one is appended
    init = ok(["log", "init", "--dir", str(d), "--tenant", TENANT, "--key", str(log_key)])
    log_id = init["log_id"]
    assert log_id.startswith("log:") and len(log_id) == 36 and "started_at" not in init["trust_entry"]
    older = {tag: write(tmp_path, f"{tag}.json", fixture_cert(n)) for tag, n in OLDER.items()}
    backfill = tmp_path / "backfill.jsonl"
    assert cli(["log", "backfill", "--tenant", TENANT, "--leaf-out", str(backfill), *map(str, older.values())])[0] == 0
    latest_fitted = max(seconds_of(fixture_cert(n)["fitted_at"]) for n in OLDER.values())
    started = time_of(latest_fitted + 3600)
    appended = [
        json.loads(x) for x in cli(["log", "append", "--dir", str(d), str(backfill), "--now", started])[1].splitlines()
    ]
    assert len(appended) == len(OLDER) and all(a["backfilled"] for a in appended)
    cert, rec, _ = issue_with_leaf_out(tmp_path)
    assert cert["fitted_at"] > started
    issued = write(tmp_path, "issued.json", cert)
    (tmp_path / "issued.jsonl").write_text(json.dumps(rec) + "\n")
    (new,) = [
        json.loads(x) for x in cli(["log", "append", "--dir", str(d), str(tmp_path / "issued.jsonl")])[1].splitlines()
    ]
    assert new == {"leaf_index": len(OLDER), "leaf_hash": rec["leaf_hash"], "certificate_id": rec["certificate_id"]}
    info = ok(["log", "info", "--dir", str(d)])
    assert (info["tree_size"], info["started_at"], info["trust_entry"]["started_at"]) == (
        len(OLDER) + 1,
        started,
        started,
    )
    assert info["cadence_seconds"] == 3600

    # checkpoint (hourly: a second one within the hour is not due), then the witness cosigns
    t1 = seconds_of(cert["fitted_at"]) + 600
    cp1 = ok(["log", "checkpoint", "--dir", str(d), "--key", str(log_key), "--now", time_of(t1)])
    assert cp1["tree_size"] == len(OLDER) + 1
    assert ok(["log", "checkpoint", "--dir", str(d), "--key", str(log_key), "--now", time_of(t1 + 60)]) == {
        "checkpoint": None,
        "next_due": time_of(t1 + 3600),
    }
    refused(["log", "checkpoint", "--dir", str(d), "--key", str(w_key)], "is not log", 2)
    (tmp_path / "info.json").write_text(json.dumps(info))
    w = ok(["witness", "init", "--state", str(tmp_path / "w1.json"), "--name", "witness.example/w1",
            "--key", str(w_key), "--log-entry", str(tmp_path / "info.json")])  # fmt: skip
    cosigned1 = tmp_path / "cosigned-1"
    v = ok(["witness", "cosign", "--state", str(tmp_path / "w1.json"), "--key", str(w_key),
            "--checkpoint", str(d / "checkpoint"), "--out", str(cosigned1), "--now", time_of(t1 + 5)])  # fmt: skip
    assert v == {"verdict": "cosigned", "log_id": log_id, "tree_size": len(OLDER) + 1, "time": time_of(t1 + 5)}
    trust = trust_config(tmp_path, d, w["witness"])

    # prove and bundle the issued certificate; both verifiers accept it, not marked backfilled
    proof, record = tmp_path / "proof.json", tmp_path / "record.json"
    p = ok(["log", "prove", "--dir", str(d), "--checkpoint", str(cosigned1), "--certificate-id", rec["certificate_id"],
            "--out", str(proof), "--record-out", str(record)])  # fmt: skip
    assert p == {"leaf_index": len(OLDER), "tree_size": len(OLDER) + 1, "certificate_id": rec["certificate_id"],
                 "backfilled": False}  # fmt: skip
    out = tmp_path / "bundle.json"
    bundle_args = ["bundle", "--certificate", str(issued), "--leaf-index", str(len(OLDER)), "--proof", str(proof),
                   "--checkpoint", str(cosigned1), "--trust", str(trust), "--out", str(out),
                   "--leaf-record", str(record)]  # fmt: skip
    ok(bundle_args)
    verdict = both(rust_bin, ["verify-bundle", str(out), "--trust", str(trust)])
    assert verdict["verdict"] == "accepted" and verdict["certificate_id"] == rec["certificate_id"]
    assert (verdict["backfilled"], verdict["backfilled_by"], verdict["t_proven"]) == (False, [], time_of(t1 + 5))
    assert [x["name"] for x in verdict["witnesses"]] == ["witness.example/w1"]

    # a backfilled certificate: prove hands its mark to bundle; started_at marks it as well
    hosted = dc.certificate_id(fixture_cert(OLDER["v1.5_hosted"]))
    p = ok(["log", "prove", "--dir", str(d), "--checkpoint", str(cosigned1), "--certificate-id", hosted,
            "--out", str(proof), "--record-out", str(record)])  # fmt: skip
    assert p["backfilled"] is True and json.loads(record.read_text())["backfilled"] is True
    bf_out = tmp_path / "backfilled.json"
    ok(["bundle", "--certificate", str(older["v1.5_hosted"]), "--leaf-index", str(p["leaf_index"]), "--proof",
        str(proof), "--checkpoint", str(cosigned1), "--trust", str(trust), "--out", str(bf_out),
        "--leaf-record", str(record)])  # fmt: skip
    verdict = both(rust_bin, ["verify-bundle", str(bf_out), "--trust", str(trust)])
    assert (verdict["backfilled"], verdict["backfilled_by"]) == (True, ["bundle", "started_at"])

    # the log grows: a leaf not in the cosigned checkpoint yet waits (exit 3) for the next one
    more = tmp_path / "more.jsonl"
    more.write_text("".join(json.dumps({"leaf": x}) + "\n" for x in leaves(20, 1000)))
    ok(["log", "append", "--dir", str(d), str(more), "--now", time_of(t1 + 1800)])
    refused(["log", "prove", "--dir", str(d), "--checkpoint", str(cosigned1), "--index", str(len(OLDER) + 3),
             "--out", str(proof)], "bad_proof", 3)  # fmt: skip
    t2 = t1 + 3600
    assert ok(["log", "checkpoint", "--dir", str(d), "--key", str(log_key), "--now", time_of(t2)])["tree_size"] == 28
    doc = tmp_path / "consistency.json"
    assert ok(["log", "consistency", "--dir", str(d), "--older", str(cosigned1), "--newer", str(d / "checkpoint"),
               "--out", str(doc)])["log_id"] == log_id  # fmt: skip
    v = both(rust_bin, ["verify-consistency", str(doc), "--trust", str(trust)])
    assert (v["verdict"], v["older_size"], v["newer_size"]) == ("accepted", 8, 28)
    cosigned2 = tmp_path / "cosigned-2"
    cosign = ["witness", "cosign", "--state", str(tmp_path / "w1.json"), "--key", str(w_key)]
    refused([*cosign, "--checkpoint", str(d / "checkpoint"), "--out", str(cosigned2)], "bad_consistency_proof")
    ok([*cosign, "--checkpoint", str(d / "checkpoint"), "--consistency", str(doc), "--out", str(cosigned2),
        "--now", time_of(t2 + 5)])  # fmt: skip
    # the earlier bundle still verifies; a leaf of the grown log bundles against the new checkpoint
    both(rust_bin, ["verify-bundle", str(out), "--trust", str(trust)])
    ok(["log", "prove", "--dir", str(d), "--checkpoint", str(cosigned2), "--index", "20", "--out", str(proof)])
    leaf_bundle = {"spec": inc.SPEC_BUNDLE, "log_id": log_id, "leaf_index": 20, "leaf": leaves(20, 1000)[12],
                   "proof": json.loads(proof.read_text()), "checkpoint": cosigned2.read_text()}  # fmt: skip
    v = both(rust_bin, ["verify-bundle", str(write(tmp_path, "keyset.json", leaf_bundle)), "--trust", str(trust)])
    assert (v["kind"], v["tree_size"], v["t_proven"]) == ("keyset", 28, time_of(t2 + 5))
    v = both(rust_bin, ["verify-consistency", str(doc), "--trust", str(trust)])

    # a forked log: the same log_id and key, another history. The witness refuses it.
    fork = dc.FileLog.init(tmp_path / "fork", TENANT, raw(LOG_KEY), log_id=log_id)
    honest = dc.FileLog(d)
    fork.append([honest.leaf_record(i) for i in range(27)] + [{"leaf": gen.keyset_leaf(5000)}], t2)
    fork_cp = tmp_path / "fork-28"
    fork.checkpoint(LOG_KEY, t2 + 10)
    fork_cp.write_text((fork.path / "checkpoint").read_text())
    refused([*cosign, "--checkpoint", str(fork_cp), "--out", str(tmp_path / "x")], "split_view")
    fork.append([{"leaf": gen.keyset_leaf(5001)}], t2 + 20)
    fork.checkpoint(LOG_KEY, t2 + 30, force=True)
    fork_cp.write_text((fork.path / "checkpoint").read_text())
    # the honest log's proof from 28 does not lead to the fork's tree, and the fork cannot prove its own
    refused(["log", "consistency", "--dir", str(fork.path), "--older", str(cosigned2), "--newer", str(fork_cp),
             "--out", str(tmp_path / "x.json")], "not_this_log")  # fmt: skip
    ok(["log", "append", "--dir", str(d), str(write(tmp_path, "one.jsonl", {"leaf": gen.keyset_leaf(5002)}))])
    ok(["log", "checkpoint", "--dir", str(d), "--key", str(log_key), "--force", "--now", time_of(t2 + 40)])
    ok(["log", "consistency", "--dir", str(d), "--older", str(cosigned2), "--newer", str(d / "checkpoint"),
        "--out", str(doc)])  # fmt: skip
    refused([*cosign, "--checkpoint", str(fork_cp), "--consistency", str(doc), "--out", str(tmp_path / "x")],
            "bad_consistency_proof")  # fmt: skip
    refused([*cosign, "--checkpoint", str(cosigned1), "--out", str(tmp_path / "x")], "size_regression")
    assert not (tmp_path / "x").exists()
    # a second witness's key is not this witness's
    refused([*cosign[:-1], str(w2_key), "--checkpoint", str(d / "checkpoint"), "--consistency", str(doc),
             "--out", str(tmp_path / "x")], "not witness", 2)  # fmt: skip
    # the honest log's next checkpoint is cosigned
    ok([*cosign, "--checkpoint", str(d / "checkpoint"), "--consistency", str(doc), "--out", str(tmp_path / "c3"),
        "--now", time_of(t2 + 50)])  # fmt: skip


def test_log_cli_usage(tmp_path: Path) -> None:
    key = pem(tmp_path, "log", LOG_KEY)
    d = tmp_path / "log"
    ok(["log", "init", "--dir", str(d), "--tenant", TENANT, "--key", str(key)])
    refused(["log", "init", "--dir", str(d), "--tenant", TENANT, "--key", str(key)], "not empty", 2)
    refused(["log", "init", "--dir", str(tmp_path / "b"), "--tenant", "acme bank", "--key", str(key)], "tenant", 2)
    refused(["log", "info", "--dir", str(tmp_path / "none")], "not a reference log", 2)
    (tmp_path / "bad.pem").write_text("not a key")
    refused(["log", "init", "--dir", str(tmp_path / "c"), "--tenant", TENANT, "--key", str(tmp_path / "bad.pem")],
            "PEM", 2)  # fmt: skip
    refused(["log", "append", "--dir", str(d), str(write(tmp_path, "r.jsonl", {"leaf": {}})), "--now", "today"],
            "--now", 2)  # fmt: skip
    (tmp_path / "bad.jsonl").write_text('{"leaf": 1, "leaf": 2}\n')
    refused(["log", "append", "--dir", str(d), str(tmp_path / "bad.jsonl")], "record_form")
    assert ok(["log", "info", "--dir", str(d)])["tree_size"] == 0
