#!/usr/bin/env python3
"""Build the release ZIP plus its out-of-band provenance bundle.

One command produces every artifact under ``release/`` from the current
source tree:

    SIS-v3.3.1-AUTHORITY-CLOSURE.zip   archive (single project dir)
    RELEASE_SHA256.json                archive-internal manifest (repo root)
    release/release_manifest.json      release identity + source commit
    release/source_inventory.json      per-file hash + size
    release/verification.json          zip + fresh-extraction verification
    release/SHA256SUMS                 checksums of the out-of-band files

The archive never contains ``release/``: it is provenance about the
archive, not payload. The build refuses a dirty source tree, re-hashes
every member against the tree it came from, and records the exact Git
commit, so a stale ZIP cannot be published under a current manifest.
"""
from __future__ import annotations

import argparse
import compileall
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_canonical_zip import build, source_binding  # noqa: E402
from verify_release import verify_tree  # noqa: E402

SMOKE_TEST = "tests/v3/test_candidates.py"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    ).decode().strip()


def _docs(root: Path) -> list[str]:
    paths = sorted((root / "docs" / "v3").glob("*.md"))
    paths += sorted((root / "docs" / "audits").glob("*.md"))
    return [p.relative_to(root).as_posix() for p in paths]


def _evidence(root: Path) -> list[str]:
    base = root / "evidence"
    return [f"evidence/{p.name}/" for p in sorted(base.iterdir()) if p.is_dir()]


def fresh_extraction_checks(tree: Path) -> dict:
    """Gate the extracted archive: it must compile and its smoke test pass.

    Recording a result is not verification. A non-compiling or
    test-failing extraction fails the build, so a broken archive can
    never ship under a green manifest.
    """
    if not compileall.compile_dir(str(tree / "src"), quiet=1, force=True):
        raise ValueError("fresh-extraction compile check failed")
    smoke = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", SMOKE_TEST],
        cwd=tree, capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    lines = (smoke.stdout or smoke.stderr).strip().splitlines()
    tail = lines[-1] if lines else ""
    if smoke.returncode != 0:
        raise ValueError(
            f"fresh-extraction smoke test failed"
            f" (rc={smoke.returncode}): {tail}")
    return {
        "compileall_src": True,
        "extracted_test_smoke": {
            "command": f"pytest -q {SMOKE_TEST}",
            "returncode": smoke.returncode,
            "tail": tail,
        },
    }


def package(root: Path, release: str, *, status: str, passed: int,
            skipped: int, failed: int, allow_dirty: bool = False) -> dict:
    root = Path(root).resolve()
    out = root / "release"
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"{release}.zip"

    binding = source_binding(root)
    build_record = {
        "schema_version": 1,
        "kind": "release_build_record",
        "release": release,
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "base_commit": binding["commit"],
        "builder": "tools/package_release.py -> tools/build_canonical_zip.py",
        "commit_binding": (
            "every archive member is re-hashed against the working tree at "
            "build time (verify_against_tree); the source commit and dirty "
            "state are recorded in release/verification.json"
        ),
        "manifest_scope": (
            "all _included() source/evidence files; release/ and "
            "evidence/release/build_record.json are out-of-band and never "
            "inventoried into the archive"
        ),
        "post_build_verification": (
            "release/verification.json — outside the archive by construction"
        ),
        "generated_at": _utcnow(),
    }
    (root / "evidence" / "release").mkdir(parents=True, exist_ok=True)
    (root / "evidence" / "release" / "build_record.json").write_text(
        json.dumps(build_record, indent=2, sort_keys=True) + "\n")

    report = build(root, archive, require_clean=not allow_dirty)
    manifest = json.loads((root / "RELEASE_SHA256.json").read_text())
    inventory = {
        "schema_version": 1,
        "release": release,
        "source_commit": report["source"]["commit"],
        "files": {
            relative: {
                "sha256": digest,
                "bytes": (root / relative).stat().st_size,
            }
            for relative, digest in sorted(manifest["files"].items())
        },
    }

    with tempfile.TemporaryDirectory(prefix="sis-release-") as temp:
        with zipfile.ZipFile(archive) as z:
            z.extractall(temp)
        tree = Path(temp) / root.name
        tree_report = verify_tree(tree)
        fresh = fresh_extraction_checks(tree)
        verification = {
            "schema_version": 1,
            "kind": "release_verification",
            "archive": archive.name,
            "zip_verify": {
                "valid": report["valid"],
                "source_files": report["source_files"],
                "project": report["project"],
                "manifest": report["manifest"],
                "zip_sha256": report["zip_sha256"],
            },
            "source_binding": report["source_binding"],
            "source": report["source"],
            "fresh_extraction": {"verify_tree": tree_report, **fresh},
        }

    release_manifest = {
        "schema_version": 1,
        "release": release,
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "source_commit": report["source"]["commit"],
        "source_commit_note": (
            "archive members are byte-identical to this commit for every "
            "manifest-covered file; the release commit itself touches only "
            "out-of-band release/ provenance"
        ),
        "status": status,
        "test_result": {
            "command": "PYTHONPATH=src python3 -m pytest tests/ -q",
            "passed": passed,
            "skipped": skipped,
            "failed": failed,
        },
        "archive": {
            "path": f"release/{archive.name}",
            "sha256": report["zip_sha256"],
            "source_files": report["source_files"],
            "inner_project_dir": root.name,
        },
        "docs": _docs(root),
        "evidence": _evidence(root),
        "notes": (
            "release/ artifacts are out-of-band provenance and are "
            "intentionally absent from the archive manifest"
        ),
    }

    (out / "release_manifest.json").write_text(
        json.dumps(release_manifest, indent=2, sort_keys=True) + "\n")
    (out / "source_inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    (out / "verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n")
    sums = []
    for name in (archive.name, "release_manifest.json",
                 "source_inventory.json", "verification.json"):
        sums.append(f"{_sha256(out / name)}  {name}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    return {"release_manifest": release_manifest, "verification": verification}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--release", default="SIS-v3.3.1-AUTHORITY-CLOSURE")
    parser.add_argument("--status", required=True)
    parser.add_argument("--passed", type=int, required=True)
    parser.add_argument("--skipped", type=int, default=0)
    parser.add_argument("--failed", type=int, default=0)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    result = package(
        args.root, args.release, status=args.status,
        passed=args.passed, skipped=args.skipped, failed=args.failed,
        allow_dirty=args.allow_dirty,
    )
    print(json.dumps({
        "release": result["release_manifest"]["release"],
        "status": result["release_manifest"]["status"],
        "source_commit": result["release_manifest"]["source_commit"],
        "archive_sha256": result["release_manifest"]["archive"]["sha256"],
        "source_files": result["release_manifest"]["archive"]["source_files"],
        "fresh_extraction": result["verification"]["fresh_extraction"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
