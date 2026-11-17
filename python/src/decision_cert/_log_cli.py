"""The command line of the reference log and witness (`python -m decision_cert log ...` and
`python -m decision_cert witness ...`); see `_log` for what they do and `__main__` for the summary.

Every command prints one JSON line on stdout. Exit 0: done. Exit 1: refused, with
`{"verdict": "refused", "error": <name>, "detail": ...}` (the reason also on stderr), nothing written.
Exit 2: usage error, an unreadable file, a key that is not the log's or the witness's, or a directory or
state file that is not one. Exit 3 (`log prove`): the checkpoint does not include the leaf yet.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from ._inclusion import parse_ijson
from ._log import (
    DEFAULT_CADENCE_SECONDS,
    FileLog,
    FileWitness,
    LogError,
    NotIncludedYet,
    load_private_key,
    raw_public,
    seconds_of,
    time_of,
)

#: Refusals that are usage errors (exit 2): the operator's files or arguments, not the log's content.
_USAGE = {"key", "state", "tenant", "cadence", "index", "time"}


def add_log_commands(lsub: Any) -> None:
    """`log init`, `info`, `append`, `checkpoint`, `prove`, `consistency` (beside `log backfill`)."""
    p = lsub.add_parser("init", help="Create a tenant's reference log in an empty directory.")
    p.add_argument("--dir", type=Path, required=True, help="The log's directory (empty or absent).")
    p.add_argument("--tenant", required=True, help="The tenant whose log this is: one log, one tenant.")
    p.add_argument("--key", type=Path, required=True, help="The log key (Ed25519 PEM); only its public part is kept.")
    p.add_argument("--key-name", help="The log key's C2SP key name (default: the log_id).")
    p.add_argument(
        "--cadence-seconds",
        type=int,
        default=DEFAULT_CADENCE_SECONDS,
        help="How often `log checkpoint` signs a checkpoint (default 3600, hourly).",
    )
    p = lsub.add_parser("info", help="Print the log's tenant, size, started_at and its log trust configuration entry.")
    p.add_argument("--dir", type=Path, required=True)
    p = lsub.add_parser("append", help="Append leaf records (certify --leaf-out, log backfill) to the log.")
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("records", type=Path, nargs="+", help="Leaf record files, JSON Lines.")
    p.add_argument("--now", help="The append time, YYYY-MM-DDTHH:MM:SSZ (default: now).")
    p = lsub.add_parser("checkpoint", help="Sign a checkpoint of the log when the cadence says it is due.")
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True, help="The log key (Ed25519 PEM).")
    p.add_argument("--now", help="The checkpoint time, YYYY-MM-DDTHH:MM:SSZ (default: now).")
    p.add_argument("--force", action="store_true", help="Sign now even if the cadence says it is not due.")
    p = lsub.add_parser("prove", help="Write a leaf's inclusion proof against a checkpoint, for `bundle`.")
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("--checkpoint", type=Path, required=True, help="A checkpoint of this log, cosigned or not.")
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument("--index", type=int, help="The leaf index.")
    which.add_argument("--certificate-id", help="The certificate whose leaf to prove.")
    p.add_argument("--out", type=Path, required=True, help="Where to write the proof (a JSON array).")
    p.add_argument("--record-out", type=Path, help="Also write the leaf's record, its backfilled mark included.")
    p = lsub.add_parser("consistency", help="Write the consistency proof document between two checkpoints.")
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("--older", type=Path, required=True)
    p.add_argument("--newer", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)


def add_witness_commands(sub: Any) -> None:
    """`witness init` and `witness cosign`."""
    w = sub.add_parser("witness", help="The reference witness.")
    wsub = w.add_subparsers(dest="witness_command", required=True)
    p = wsub.add_parser("init", help="Create a witness's state file for one log.")
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--name", required=True, help="The witness's C2SP cosigner name.")
    p.add_argument("--key", type=Path, required=True, help="The witness key (Ed25519 PEM); only its id is kept.")
    p.add_argument("--log-entry", type=Path, required=True, help="The log's trust entry, as `log info` prints it.")
    p = wsub.add_parser("cosign", help="Cosign a checkpoint that extends the last one this witness cosigned.")
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True, help="The witness key (Ed25519 PEM).")
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--consistency", type=Path, help="The consistency proof document from the last cosigned one.")
    p.add_argument("--out", type=Path, required=True, help="Where to write the cosigned checkpoint.")
    p.add_argument("--now", help="The cosignature time, YYYY-MM-DDTHH:MM:SSZ (default: now).")


def _line(v: Any) -> None:
    print(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _refused(e: LogError, code: int = 1) -> int:
    if e.name in _USAGE:
        print(f"decision-cert: {e}", file=sys.stderr)
        return 2
    _line({"verdict": "refused", "error": e.name, "detail": e.detail})
    print(f"decision-cert: {e}", file=sys.stderr)
    return code


def _now(text: str | None) -> int:
    if text is None:
        return int(dt.datetime.now(dt.UTC).timestamp())
    try:
        return seconds_of(text)
    except ValueError as e:
        raise LogError("time", f"--now: {e}") from None


def _read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise LogError("state", f"{path}: {e}") from None


def _read_json(path: Path) -> Any:
    try:
        return parse_ijson(_read_text(path))
    except ValueError as e:
        raise LogError("state", f"{path}: not I-JSON: {e}") from None


def _write(path: Path, data: str) -> None:
    try:
        path.write_text(data, encoding="utf-8")
    except OSError as e:
        raise LogError("state", f"{path}: {e}") from None


def run_log(args: argparse.Namespace) -> int:
    try:
        return _run_log(args)
    except NotIncludedYet as e:
        return _refused(e, 3)
    except LogError as e:
        return _refused(e)


def _run_log(args: argparse.Namespace) -> int:
    cmd = args.log_command
    if cmd == "init":
        key = load_private_key(args.key)
        log = FileLog.init(
            args.dir, args.tenant, raw_public(key), key_name=args.key_name, cadence_seconds=args.cadence_seconds
        )
        _line({"tenant": log.config.tenant, "log_id": log.config.log_id, "trust_entry": log.config.trust_entry()})
        print(
            "the log's started_at is set by its first append; `log info` then prints its trust entry with it",
            file=sys.stderr,
        )
        return 0
    log = FileLog(args.dir)
    if cmd == "info":
        cfg = log.config
        _line(
            {
                "tenant": cfg.tenant,
                "log_id": cfg.log_id,
                "tree_size": log.size,
                "started_at": cfg.started_at,
                "cadence_seconds": cfg.cadence_seconds,
                "checkpointed": log.checkpointed(),
                "trust_entry": cfg.trust_entry(),
            }
        )
        return 0
    if cmd == "append":
        records: list[Any] = []
        for f in args.records:
            for i, line in enumerate(_read_text(f).splitlines()):
                if line.strip():
                    try:
                        records.append(parse_ijson(line))
                    except ValueError as e:
                        raise LogError("record_form", f"{f}, line {i + 1}: not I-JSON: {e}") from None
        for appended in log.append(records, _now(args.now)):
            _line(appended)
        return 0
    if cmd == "checkpoint":
        now = _now(args.now)
        note = log.checkpoint(load_private_key(args.key), now, force=args.force)
        if note is None:
            due = log.due(now)
            assert due is not None
            _line({"checkpoint": None, "next_due": time_of(due)})
            print(f"decision-cert: not due until {time_of(due)} (--force signs now)", file=sys.stderr)
            return 0
        _line({"checkpoint": str(args.dir / "checkpoint"), "tree_size": log.size, "at": time_of(now)})
        return 0
    if cmd == "prove":
        index = args.index if args.certificate_id is None else log.find(args.certificate_id)
        proof = log.prove(_read_text(args.checkpoint), index)
        _write(args.out, json.dumps(proof) + "\n")
        rec = log.leaf_record(index)
        if args.record_out is not None:
            _write(args.record_out, json.dumps(rec, sort_keys=True) + "\n")
        out: dict[str, Any] = {
            "leaf_index": index,
            "tree_size": log.check_checkpoint(_read_text(args.checkpoint)).tree_size,
        }
        if "certificate_id" in rec:
            out["certificate_id"] = rec["certificate_id"]
            out["backfilled"] = rec.get("backfilled") is True
        _line(out)
        return 0
    if cmd == "consistency":
        doc = log.consistency(_read_text(args.older), _read_text(args.newer))
        _write(args.out, json.dumps(doc, indent=2) + "\n")
        _line({"log_id": doc["log_id"], "proof": len(doc["proof"])})
        return 0
    raise AssertionError(cmd)


def run_witness(args: argparse.Namespace) -> int:
    try:
        if args.witness_command == "init":
            entry = _read_json(args.log_entry)
            if isinstance(entry, dict) and isinstance(entry.get("trust_entry"), dict):
                entry = entry["trust_entry"]  # `log info`'s whole line
            if not isinstance(entry, dict):
                raise LogError("state", f"{args.log_entry}: not a log trust entry")
            key = load_private_key(args.key)
            w = FileWitness.init(args.state, args.name, raw_public(key), entry)
            _line({"witness": w.trust_entry(), "log_id": w.log.log_id})
            return 0
        w = FileWitness(args.state)
        doc = _read_json(args.consistency) if args.consistency is not None else None
        note, cp = w.cosign(_read_text(args.checkpoint), doc, load_private_key(args.key), _now(args.now))
        _write(args.out, note)
        _line(
            {
                "verdict": "cosigned",
                "log_id": cp.origin,
                "tree_size": cp.tree_size,
                "time": time_of(w.state["cosigned_at"]),
            }
        )
        return 0
    except LogError as e:
        return _refused(e)
