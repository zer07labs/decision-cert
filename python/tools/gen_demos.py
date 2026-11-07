"""Write the demo files that are derived from signed material, and `demo/DEMOS.sha256`.

    cd python && uv run python tools/gen_demos.py          # write
    cd python && uv run python tools/gen_demos.py --check  # fail if anything would change

`demo/example/` is `fixtures/valid_basic.json` split into the two files the command-line verifier
takes: the certificate exactly as signed, and its trusted keys. It is the conformance fixture,
signed with the public test key, not a demo-key certificate. Signed demo certificates are copied
into `demo/<name>/` unchanged; this script only hashes them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo"


def dump(o: Any) -> str:
    return json.dumps(o, indent=2, ensure_ascii=False) + "\n"


def derived() -> dict[Path, str]:
    f = json.loads((ROOT / "fixtures" / "valid_basic.json").read_text(encoding="utf-8"))
    return {
        DEMO / "example" / "certificate.json": dump(f["certificate"]),
        DEMO / "example" / "trusted-keys.json": dump(f["keys"]),
    }


def manifest() -> str:
    files = sorted(p for p in DEMO.rglob("*.json"))
    return "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(DEMO).as_posix()}\n" for p in files)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if a demo file or the manifest would change")
    args = ap.parse_args()
    stale: list[str] = []
    for path, text in derived().items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(path.relative_to(DEMO).as_posix())
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
    sha = DEMO / "DEMOS.sha256"
    want = manifest()
    if not sha.exists() or sha.read_text(encoding="utf-8") != want:
        stale.append(sha.name)
        if not args.check:
            sha.write_text(want, encoding="utf-8")
    if stale and args.check:
        print(f"stale: {', '.join(stale)}; run tools/gen_demos.py", file=sys.stderr)
        return 1
    print(f"{'checked' if args.check else 'wrote'} demo files and DEMOS.sha256")
    return 0


if __name__ == "__main__":
    sys.exit(main())
