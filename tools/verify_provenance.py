#!/usr/bin/env python3
"""Verify a signed SLSA-style provenance envelope against an archive.

    python tools/verify_provenance.py \
        --envelope release/provenance.dsse.json \
        --archive release/SIS-v3.3.2-....zip \
        --public-key <64-hex-ed25519-public-key>

Exit status is non-zero when the signature, statement shape, subject
name or subject SHA-256 does not match the archive.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--public-key", required=True,
                        help="64-hex Ed25519 public key")
    args = parser.parse_args(argv)
    try:
        statement = provenance.verify_file(
            args.envelope, args.public_key, archive_path=args.archive)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"provenance verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "ok": True,
        "subject": statement["subject"][0],
        "predicateType": statement["predicateType"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
