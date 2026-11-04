"""Build the validation-evidence bundle for a release.

The source archive describes the code. This bundle records what was
*executed* on the host that qualified the release — the qualification run,
its logs, the release metadata and the notes that describe them — with a
SHA-256 manifest of its own, so the bundle verifies without the source
archive.

The bundle carries no key material and is not publisher-signed;
``release/release_manifest.json`` records the provenance state.

Usage::

    python tools/build_evidence_bundle.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from sis import __version__  # noqa: E402

EVIDENCE_MANIFEST = "EVIDENCE_SHA256.json"

#: The qualification run and the logs it wrote.
QUALIFICATION_MEMBERS = (
    "qualification/qualification.json",
    "qualification/focused_tests.log",
    "qualification/container_isolation.log",
    "qualification/postgres.log",
    "qualification/full_suite.log",
    "evidence/v351/PHASE0_BASELINE.md",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _release_manifest(root: Path) -> dict:
    return json.loads((root / "release" / "release_manifest.json").read_text())


def members(root: Path) -> list[str]:
    """The repository-relative files the bundle carries."""
    manifest = _release_manifest(root)
    docs = sorted(path.name for path in root.glob(f"SIS_v{__version__}_*.md"))
    return [*QUALIFICATION_MEMBERS, *docs,
            "RELEASE_SHA256.json",
            "release/release_manifest.json",
            "release/source_inventory.json",
            "release/verification.json",
            manifest["provenance"]["path"]]


def _write(z, name: str, payload: bytes, stamp) -> None:
    info = zipfile.ZipInfo(name, stamp)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    z.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED,
               compresslevel=9)


def build(root: Path = ROOT) -> tuple[Path, Path]:
    root = Path(root).resolve()
    out = root / "release"
    names = members(root)
    for name in names:
        if not (root / name).is_file():
            raise SystemExit(f"missing evidence member: {name}")
    release = f"SIS_v{__version__}_VALIDATION_EVIDENCE"
    document = {
        "schema_version": 1,
        "release": release,
        "files": {name: _sha256(root / name) for name in names},
        "note": ("Locally generated evidence bundle recording what was "
                 "executed on this host. Not publisher-signed."),
    }
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    bundle = out / f"{release}.zip"
    stamp = tuple(datetime.now(timezone.utc).timetuple()[:3]) + (0, 0, 0)
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as z:
        for name in names:
            _write(z, name, (root / name).read_bytes(), stamp)
        _write(z, EVIDENCE_MANIFEST, payload, stamp)
    source = root / _release_manifest(root)["archive"]["path"]
    sums = out / f"SIS-v{__version__}-SHA256SUMS"
    sums.write_text("\n".join(
        f"{_sha256(path)}  {path.name}" for path in (source, bundle)) + "\n")
    return bundle, sums


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    bundle, sums = build(args.root)
    print(json.dumps({
        "bundle": str(bundle.relative_to(Path(args.root).resolve())),
        "bundle_sha256": _sha256(bundle),
        "sums": str(sums.relative_to(Path(args.root).resolve())),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
