"""`python -m decision_cert verify <cert.json> --keys <keys.json> [--tenant <tenant>] [--now <ts>]`

Exit 0: the certificate verifies against the trusted keys and has not expired at `--now` (default:
the current time); its id is printed on stdout.
Exit 1: it does not verify, or it has expired; the reason is printed on stderr.
Exit 2: usage error, an unreadable file, or a keys file that is not a JSON object of strings (with
`--tenant`: of key entries, spec v1.5 §4).
With `--tenant`, the certificate is verified for that expected tenant (any spec; a v1.5 certificate
needs it). The Rust `decision-cert verify` behaves the same.

`python -m decision_cert verify-pack <pack> [--keys <keys.json>] [--now <ts>] [--no-recompute | --require-recompute]
[--max-total-bytes N] [--max-member-bytes N] [--max-members N]`

Verifies an evidence pack, a directory or a tar (docs/evidence-pack.md), and prints one line per
check and the verdict on stdout. Exit 0: no check failed (with `--require-recompute`, also no
recompute skipped); without `--keys` the verdict says the pack is consistent with its own keys only.
Exit 1: a check failed. Exit 2: usage error, the pack or keys file can't be read (missing, truncated,
corrupt), or the pack reaches a read limit. An expired certificate is reported, not failed: a pack is
often checked after the fact.

`python -m decision_cert verify-bundle <bundle.json> --trust <log-trust.json>` and
`python -m decision_cert verify-consistency <consistency.json> --trust <log-trust.json>` check an
inclusion bundle or a consistency proof document (draft `decision-cert-inclusion.v1`) against one
tenant's log trust configuration, and print one JSON verdict line on stdout: `{"verdict": "accepted",
...}` with exit 0, or `{"verdict": "refused", "error": <error name>, "detail": ...}` with exit 1 (the
reason also on stderr). Exit 2: usage error, an unreadable file, or a log trust configuration that is
not I-JSON or not well formed (`trust_form`, on stderr). `verify-bundle` does not verify the bundle's
certificate itself; `verify` does. The Rust `decision-cert verify-bundle` and `verify-consistency`
behave the same.

`python -m decision_cert bundle --certificate <cert.json> --leaf-index <n> --proof <proof.json>
--checkpoint <checkpoint> --trust <log-trust.json> --out <bundle.json> [--log-id <log id>]` is the
issuer's step once a cosigned checkpoint includes the certificate's leaf: it builds the leaf from the
certificate, checks the bundle as `verify-bundle` does (the proof file is a JSON array of base64 node
hashes, the checkpoint file the signed note, cosignatures included; the log is the checkpoint's origin
unless `--log-id` is given), and writes it as its JCS bytes. It prints `verify-bundle`'s verdict line.
Exit 0: written. Exit 1: refused, nothing written. Exit 2: usage error, an unreadable file, or a
configuration that is not well formed. Exit 3: the checkpoint does not include the leaf yet (its tree
size is not above the index): nothing written; bundle against a later cosigned checkpoint.

`python -m decision_cert log backfill --tenant <tenant> --leaf-out <leaves.jsonl> <file>...` writes the
leaf records of certificates issued before the tenant's log existed, for the log to append first, before
any new leaf, in the draft's §12 order (by `fitted_at`, then `certificate_id`; each certificate once).
Each file holds a certificate or an issuer's calibration file. Exit 1: a file holds something that is not
a certificate, or a v1.5 certificate for another tenant; nothing written. Exit 2: usage error or an
unreadable file. A backfilled leaf carries no mark (§12): it gets no early time evidence because its
`t_proven` is the first cosigned checkpoint that includes it, after the log started.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from . import CertError, Invalid, loads, tenant_keys_from_json, timestamp, verify, verify_for_tenant
from ._bundle import NotYetInCheckpoint, backfill_records, bundle_bytes, bundle_certificate, leaf_records_text
from ._inclusion import ErrorName, InclusionError, LogTrust, parse_ijson, verify_bundle, verify_consistency
from ._pack import DEFAULT_LIMITS, Limits, PackError, render, verify_pack


def _positive(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        n = 0
    if n < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive integer")
    return n


def _index(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        n = -1
    if not 0 <= n <= 2**53 - 1 or not text.isdigit():
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer from 0 to 2^53 - 1")
    return n


def _usage(msg: str) -> int:
    print(f"decision-cert: {msg}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decision-cert", description="Verify decision-certificate.v1 certificates")
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="Verify a certificate against trusted keys and check its expiry.")
    v.add_argument("cert", type=Path, help="The certificate, a JSON object.")
    v.add_argument(
        "--keys",
        type=Path,
        required=True,
        help="Trusted keys: key id -> base64url public key (with --tenant, an entry may also be "
        '{"key", "mode", "host"}).',
    )
    v.add_argument("--tenant", help="The tenant the certificate must be for (spec v1.5); its keys are --keys.")
    v.add_argument("--now", help="The time to check expiry at, YYYY-MM-DDTHH:MM:SSZ (default: now).")
    vp = sub.add_parser("verify-pack", help="Verify an evidence pack (a directory or a tar).")
    vp.add_argument("pack", type=Path, help="The pack: a directory holding pack.json, or a tar of one.")
    vp.add_argument(
        "--keys",
        type=Path,
        help="Trusted keys obtained out of band (default: the pack's own, which shows consistency only).",
    )
    vp.add_argument("--now", help="The time to report expiry at, YYYY-MM-DDTHH:MM:SSZ (default: now).")
    rc = vp.add_mutually_exclusive_group()
    rc.add_argument("--no-recompute", action="store_true", help="Skip re-running the procedure on included cases.")
    rc.add_argument(
        "--require-recompute", action="store_true", help="Fail unless every certificate's figures are recomputed."
    )
    d = DEFAULT_LIMITS
    vp.add_argument(
        "--max-total-bytes",
        type=_positive,
        default=d.total_bytes,
        help=f"Refuse a pack whose files hold more than this, uncompressed (default {d.total_bytes}, 1 GiB).",
    )
    vp.add_argument(
        "--max-member-bytes",
        type=_positive,
        default=d.member_bytes,
        help=f"Refuse a pack with a file larger than this, uncompressed (default {d.member_bytes}).",
    )
    vp.add_argument(
        "--max-members",
        type=_positive,
        default=d.members,
        help=f"Refuse a pack with more entries than this (default {d.members}).",
    )
    vb = sub.add_parser(
        "verify-bundle", help="Verify an inclusion bundle against a tenant's log trust configuration (draft)."
    )
    vb.add_argument("bundle", type=Path, help="The bundle, a `decision-cert-inclusion.v1` JSON object.")
    vb.add_argument(
        "--trust",
        type=Path,
        required=True,
        help="The tenant's log trust configuration, a `decision-cert-log-trust.v1` JSON object.",
    )
    vc = sub.add_parser(
        "verify-consistency",
        help="Verify a consistency proof document against a tenant's log trust configuration (draft).",
    )
    vc.add_argument("doc", type=Path, help="The document, a `decision-cert-consistency.v1` JSON object.")
    vc.add_argument(
        "--trust",
        type=Path,
        required=True,
        help="The tenant's log trust configuration, a `decision-cert-log-trust.v1` JSON object.",
    )
    bd = sub.add_parser(
        "bundle",
        help="Bundle a certificate with its inclusion proof and a cosigned checkpoint (draft), checked first.",
    )
    bd.add_argument("--certificate", type=Path, required=True, help="The certificate as issued, a JSON object.")
    bd.add_argument(
        "--leaf-index", type=_index, required=True, help="The leaf's position in the log, which the log gave it."
    )
    bd.add_argument(
        "--proof", type=Path, required=True, help="The inclusion proof: a JSON array of base64 node hashes."
    )
    bd.add_argument(
        "--checkpoint", type=Path, required=True, help="The checkpoint's signed note, with its cosignatures."
    )
    bd.add_argument(
        "--trust",
        type=Path,
        required=True,
        help="The tenant's log trust configuration, a `decision-cert-log-trust.v1` JSON object.",
    )
    bd.add_argument("--out", type=Path, required=True, help="Where to write the bundle (its JCS bytes).")
    bd.add_argument("--log-id", help="The log's id (default: the checkpoint's origin).")
    lg = sub.add_parser("log", help="The issuer's log tooling (draft).")
    lsub = lg.add_subparsers(dest="log_command", required=True)
    bf = lsub.add_parser(
        "backfill",
        help="Write the leaf records of certificates issued before the tenant's log existed, in backfill order.",
    )
    bf.add_argument("files", type=Path, nargs="+", help="Certificates, or issuer calibration files.")
    bf.add_argument("--tenant", required=True, help="The tenant whose log the leaves are for.")
    bf.add_argument("--leaf-out", type=Path, required=True, help="Where to write the leaf records (JSON Lines).")
    args = ap.parse_args(argv)  # exits 2 on a usage error
    if args.command == "verify-pack":
        return _verify_pack(args)
    if args.command == "bundle":
        return _bundle(args)
    if args.command == "log":
        return _backfill(args)
    if args.command == "verify-bundle":
        return _inclusion(args.bundle, args.trust, lambda v, t: verify_bundle(v, t).to_json(), ErrorName.BUNDLE_FORM)
    if args.command == "verify-consistency":
        return _inclusion(
            args.doc, args.trust, lambda v, t: verify_consistency(v, t).to_json(), ErrorName.CONSISTENCY_FORM
        )

    try:
        keys_text = args.keys.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _usage(f"{args.keys}: {e}")
    tenant_keys = None
    if args.tenant is not None:
        try:
            tenant_keys = tenant_keys_from_json(loads(keys_text))
        except CertError as e:
            return _usage(f"{args.keys}: not a JSON object of key id -> key entry: {e}")
        keys = {}
    else:
        try:
            keys = loads(keys_text)
        except Invalid as e:
            return _usage(f"{args.keys}: not a JSON object of key id -> public key: {e}")
        if not isinstance(keys, dict) or not all(isinstance(k, str) and isinstance(x, str) for k, x in keys.items()):
            return _usage(f"{args.keys}: not a JSON object of key id -> public key")
    if args.now is None:
        now = dt.datetime.now(dt.UTC)
    else:
        try:
            now = timestamp(args.now)
        except Invalid:
            return _usage(f"--now {args.now!r} is not YYYY-MM-DDTHH:MM:SSZ")
    try:
        text = args.cert.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _usage(f"{args.cert}: {e}")

    try:
        if tenant_keys is not None:
            cert = verify_for_tenant(loads(text), args.tenant, tenant_keys)
        else:
            cert = verify(loads(text), keys)
    except CertError as e:
        print(f"{args.cert}: {e}", file=sys.stderr)
        return 1
    if cert.is_expired(now):
        print(
            f"{args.cert}: certificate {cert.id} has expired (its expires_at is not after the check time)",
            file=sys.stderr,
        )
        return 1
    print(cert.id)
    return 0


def _json_line(v: Any) -> str:
    """One JSON line as the crate prints it: members sorted, no spaces, non-ASCII as is."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _inclusion(doc: Path, trust_path: Path, check: Callable[[Any, LogTrust], dict[str, Any]], form: ErrorName) -> int:
    """`verify-bundle` and `verify-consistency`: one JSON verdict line on stdout, exit 0 or 1; exit 2 for an
    unreadable file or a configuration that is not well formed."""
    trust = _read_trust(trust_path)
    if isinstance(trust, str):
        return _usage(trust)
    try:
        doc_bytes = doc.read_bytes()
    except OSError as e:
        return _usage(f"{doc}: {e}")
    try:
        try:
            value = parse_ijson(doc_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise InclusionError(form, f"not I-JSON: {e}") from None
        verdict = check(value, trust)
    except InclusionError as e:
        print(_json_line({"verdict": "refused", "error": str(e.name), "detail": e.detail}))
        print(f"{doc}: {e}", file=sys.stderr)
        return 1
    print(_json_line({**verdict, "verdict": "accepted"}))
    return 0


def _read_trust(path: Path) -> LogTrust | str:
    """The log trust configuration, or the usage message for a file that is unreadable or not well formed."""
    try:
        data = path.read_bytes()
    except OSError as e:
        return f"{path}: {e}"
    try:
        try:
            value = parse_ijson(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise InclusionError(ErrorName.TRUST_FORM, str(e)) from None
        return LogTrust.from_json(value)
    except InclusionError as e:
        return f"{path}: {e}"


def _read_json(path: Path) -> tuple[Any, None] | tuple[None, str]:
    """A JSON file read as I-JSON, or the usage message for one that is unreadable or not I-JSON."""
    try:
        return parse_ijson(path.read_bytes().decode("utf-8")), None
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return None, f"{path}: {e}"


def _bundle(args: argparse.Namespace) -> int:
    trust = _read_trust(args.trust)
    if isinstance(trust, str):
        return _usage(trust)
    cert, err = _read_json(args.certificate)
    if err is not None:
        return _usage(err)
    proof, err = _read_json(args.proof)
    if err is not None:
        return _usage(err)
    try:
        checkpoint = args.checkpoint.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _usage(f"{args.checkpoint}: {e}")
    try:
        bundle, verdict = bundle_certificate(cert, args.leaf_index, proof, checkpoint, trust, args.log_id)
    except NotYetInCheckpoint as e:
        print(_json_line({"verdict": "refused", "error": str(e.name), "detail": e.detail}))
        print(f"{args.certificate}: {e}", file=sys.stderr)
        return 3
    except InclusionError as e:
        print(_json_line({"verdict": "refused", "error": str(e.name), "detail": e.detail}))
        print(f"{args.certificate}: {e}", file=sys.stderr)
        return 1
    try:
        args.out.write_bytes(bundle_bytes(bundle))
    except OSError as e:
        return _usage(f"{args.out}: {e}")
    print(_json_line({**verdict.to_json(), "verdict": "accepted"}))
    return 0


def _certificates_in(value: Any) -> list[Any] | None:
    """The certificates a file holds: a certificate (an object with a string `spec`), or an issuer's
    calibration file (an object of decision id -> an entry with a `certificate`). None for anything else."""
    if isinstance(value, dict) and isinstance(value.get("spec"), str):
        return [value]
    if isinstance(value, dict) and value and all(isinstance(e, dict) and "certificate" in e for e in value.values()):
        return [e["certificate"] for e in value.values()]
    return None


def _backfill(args: argparse.Namespace) -> int:
    certs: list[Any] = []
    for f in args.files:
        value, err = _read_json(f)
        if err is not None:
            return _usage(err)
        found = _certificates_in(value)
        if found is None:
            print(f"{f}: neither a certificate nor an issuer's calibration file", file=sys.stderr)
            return 1
        certs += found
    try:
        records = backfill_records(certs, args.tenant)
    except ValueError as e:
        return _usage(f"--tenant: {e}")
    except InclusionError as e:
        print(f"decision-cert log backfill: {e}", file=sys.stderr)
        return 1
    try:
        args.leaf_out.write_text(leaf_records_text(records), encoding="utf-8")
    except OSError as e:
        return _usage(f"{args.leaf_out}: {e}")
    if dropped := len(certs) - len(records):
        print(f"decision-cert log backfill: {dropped} repeated certificate(s) written once", file=sys.stderr)
    print(
        f"wrote {len(records)} leaf record(s) for {args.tenant}'s log to {args.leaf_out}: append them in this "
        "order when the log starts, before any new leaf. They get no early time evidence: each one's t_proven "
        "is the first cosigned checkpoint that includes it."
    )
    return 0


def _read_keys(path: Path) -> dict[str, str] | str:
    """The keys file as a dict, or the usage message for a file that is not one."""
    try:
        keys = loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        return f"{path}: {e}"
    except Invalid as e:
        return f"{path}: not a JSON object of key id -> public key: {e}"
    if not isinstance(keys, dict) or not all(isinstance(k, str) and isinstance(x, str) for k, x in keys.items()):
        return f"{path}: not a JSON object of key id -> public key"
    return keys


def _verify_pack(args: argparse.Namespace) -> int:
    keys = None
    if args.keys is not None:
        read = _read_keys(args.keys)
        if isinstance(read, str):
            return _usage(read)
        keys = read
    now = None
    if args.now is not None:
        try:
            now = timestamp(args.now)
        except Invalid:
            return _usage(f"--now {args.now!r} is not YYYY-MM-DDTHH:MM:SSZ")
    try:
        limits = Limits(args.max_total_bytes, args.max_member_bytes, args.max_members)
        report = verify_pack(args.pack, keys, now=now, recompute=not args.no_recompute, limits=limits)
    except PackError as e:
        return _usage(str(e))
    sys.stdout.write(render(report))
    if not report.ok:
        return 1
    if args.require_recompute and (skipped := report.skipped("recompute")):
        print(f"decision-cert: --require-recompute: {len(skipped)} recompute(s) skipped", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
