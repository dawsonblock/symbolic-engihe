# Release provenance — v4.0.0

Built on this machine from working tree at `21e789b` (manifest commit);
last code commit `9a146b8`.

## Artifacts (in `dist/`, gitignored)

| Artifact | Value |
|---|---|
| `sis-v3-release.zip` SHA-256 | **see `dist/attestation.json` `zip_sha256`** — generated at build time; this file ships inside the archive so it cannot name its own digest |
| `SOURCE_SHA256.json` | regenerated to cover the full tree |
| `attestation.json` | authoritative per-build record: git_sha, python, platform, manifest + zip digests, timestamp |
| Determinism | independent rebuilds are byte-identical — rebuild and compare `zip_sha256` against attestation to reproduce |

## Verification

    python tools/build_release.py --zip dist/sis-v3-release.zip --attest dist/attestation.json
    python tools/verify_release.py dist/sis-v3-release.zip
    python tools/check_source_manifest.py          # 229 files verified

`verify_release.py` validates the manifest, the archive's self-coverage,
entry safety (no symlinks/non-regulars/duplicates/traversal), and file
hashes by streaming the ZIP — no extraction.

## Relationship to the original upload

Original ZIP SHA-256 `3871bbe6…` (v2.4.0 baseline) is the audited input,
not this artifact. This ZIP is the repaired v3.1–v4.0 line; it is
bit-for-bit reproducible from the committed tree via `build_zip`.
