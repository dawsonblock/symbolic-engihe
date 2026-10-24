"""Build a deterministic, final-artifact-verified release ZIP.

Historical SOURCE_SHA256.json is excluded intentionally. Distributed source
is inventoried by the single RELEASE_SHA256.json included in the archive.
"""
from __future__ import annotations
import argparse
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_release import verify
from build_release import write_manifest


def build(root: Path, target: Path):
    write_manifest(root)
    manifest = json.loads((root / "RELEASE_SHA256.json").read_text())
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in sorted([*manifest["files"], "RELEASE_SHA256.json"]):
            p = root / rel
            if p.is_symlink() or not p.is_file():
                raise ValueError("missing_or_symlink_member:" + rel)
            info = zipfile.ZipInfo(root.name + "/" + rel, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 << 16)
            z.writestr(info, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return verify(target)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("path", type=Path, help="output ZIP path")
    p.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    args = p.parse_args()
    print(json.dumps(build(args.source.resolve(), args.path.resolve()), indent=2))

if __name__ == "__main__":
    main()
