"""Generate or drift-check RELEASE_SHA256.json.

The release manifest inventories every distributed file (including v3 code,
docs, tests, examples and tools) by SHA-256 so a fresh extracted archive can
verify itself with ``tools/verify_release.py`` — no Git history required.
The historical SOURCE_SHA256.json is untouched; it records the audited v2
baseline and intentionally omits later development.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_source_manifest import _included  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "RELEASE_SHA256.json"


def inventory(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if not _included(relative):
            continue
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def manifest_document(root: Path) -> dict:
    return {"schema": 1, "files": inventory(root)}


def write_manifest(root: Path) -> Path:
    document = manifest_document(root)
    target = root / MANIFEST_NAME
    fd, tmp = tempfile.mkstemp(dir=root, prefix=".release-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if RELEASE_SHA256.json is missing or stale")
    parser.add_argument("--zip", metavar="PATH",
                        help="also build the canonical deterministic release ZIP at PATH")
    parser.add_argument("--attest", metavar="PATH",
                        help="with --zip: write the release attestation JSON to PATH")
    args = parser.parse_args(argv)
    current = manifest_document(ROOT)
    if args.check:
        try:
            existing = json.loads((ROOT / MANIFEST_NAME).read_text(encoding="utf-8"))
        except OSError:
            print("release manifest missing; run tools/build_release.py", file=sys.stderr)
            return 1
        if existing != current:
            print("release manifest is stale; run tools/build_release.py", file=sys.stderr)
            return 1
        print(f"release manifest covers {len(current['files'])} files and is current")
        if not args.zip:
            return 0
    else:
        target = write_manifest(ROOT)
        print(f"wrote {MANIFEST_NAME} covering {len(current['files'])} files")
    if args.zip:
        import verify_release
        zip_path = verify_release.build_zip(ROOT, Path(args.zip))
        report = verify_release.verify(zip_path)
        print(f"canonical ZIP verified: {zip_path} sha256={report['zip_sha256']} "
              f"files={report['source_files']}")
        if args.attest:
            attest = verify_release.release_attestation(zip_path, ROOT)
            attest_path = Path(args.attest)
            attest_path.parent.mkdir(parents=True, exist_ok=True)
            attest_path.write_text(
                json.dumps(attest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"release attestation written: {attest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
