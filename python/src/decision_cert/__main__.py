"""`python -m decision_cert verify <cert.json> --keys <keys.json> [--now <ts>]`

Exit 0: the certificate verifies against the trusted keys and has not expired at `--now` (default:
the current time); its id is printed on stdout.
Exit 1: it does not verify, or it has expired; the reason is printed on stderr.
Exit 2: usage error, an unreadable file, or a keys file that is not a JSON object of strings.
The Rust `decision-cert verify` behaves the same.

`python -m decision_cert verify-pack <pack> [--keys <keys.json>] [--now <ts>] [--no-recompute | --require-recompute]`

Verifies an evidence pack, a directory or a tar (docs/evidence-pack.md), and prints one line per
check and the verdict on stdout. Exit 0: no check failed (with `--require-recompute`, also no
recompute skipped). Exit 1: a check failed. Exit 2: usage error, or the pack or keys file can't be
read. An expired certificate is reported, not failed: a pack is often checked after the fact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections.abc import Sequence
from pathlib import Path

from . import CertError, Invalid, loads, timestamp, verify
from ._pack import PackError, render, verify_pack


def _usage(msg: str) -> int:
    print(f"decision-cert: {msg}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decision-cert", description="Verify decision-certificate.v1 certificates")
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="Verify a certificate against trusted keys and check its expiry.")
    v.add_argument("cert", type=Path, help="The certificate, a JSON object.")
    v.add_argument("--keys", type=Path, required=True, help="Trusted keys: key id -> base64url public key.")
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
    args = ap.parse_args(argv)  # exits 2 on a usage error
    if args.command == "verify-pack":
        return _verify_pack(args)

    try:
        keys_text = args.keys.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _usage(f"{args.keys}: {e}")
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
        report = verify_pack(args.pack, keys, now=now, recompute=not args.no_recompute)
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
