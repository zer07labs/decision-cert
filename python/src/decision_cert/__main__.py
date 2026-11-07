"""`python -m decision_cert verify <cert.json> --keys <keys.json> [--now <ts>]`

Exit 0: the certificate verifies against the trusted keys and has not expired at `--now` (default:
the current time); its id is printed on stdout.
Exit 1: it does not verify, or it has expired; the reason is printed on stderr.
Exit 2: usage error, an unreadable file, or a keys file that is not a JSON object of strings.
The Rust `decision-cert verify` behaves the same.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections.abc import Sequence
from pathlib import Path

from . import CertError, Invalid, loads, timestamp, verify


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
    args = ap.parse_args(argv)  # exits 2 on a usage error

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
        print(f"{args.cert}: certificate {cert.id} expired at {cert.cert['expires_at']}", file=sys.stderr)
        return 1
    print(cert.id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
