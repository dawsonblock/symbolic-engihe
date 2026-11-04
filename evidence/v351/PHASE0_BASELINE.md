# SIS v3.5.1 — Phase 0 Baseline Report

Captured: 2026-11-04
Repository: `/Users/dawsonblock/Downloads/Symbolic-Engine/sis-v2-authority-transfer`
Branch: `sis/v3.4.0-engineering-upgrade`
HEAD: `949104736c5951bfaeb92ca93e89f84a3564c639`
Working tree: clean (`git status --porcelain` empty)

## Inputs

| Prompt-named input | Present on host |
|---|---|
| `symbolic-engihe-sis-v3.4.0-engineering-upgrade 4.zip` | **No.** The live repository is a git worktree of `symbolic-induction-engine-v2.4.0-codex-sis-v3-m0`; no archive extraction was required or performed. |
| `SIS_v3_5_0_Upgrade4_Independent_Deep_Audit.md` | **No** |
| `SIS_v3_5_0_Upgrade4_Independent_Audit_Evidence.zip` | **No** |
| Prior engineering-upgrade archives | Yes: `release/SIS-v3.3.{0,1,2}-*.zip` |

Because the audit documents were not supplied, the audit's findings are
taken from the prompt text only. Every one that is testable in this tree
was reproduced independently; results are in
`SIS_v3.5.1_DEFECT_MATRIX.md`.

## Version declarations

| Location | Value |
|---|---|
| `pyproject.toml` `[project].version` | `3.5.0` |
| `src/sis/__init__.py` `__version__` | `3.5.0` |
| `src/sis/v3/__init__.py` `SCHEMA_VERSION` | `1` (record schema, not package version) |

The package identifies itself as **3.5.0**, confirming the prompt's
observation that the ZIP name (v3.4.0) disagrees with the internal
version. Target `3.5.1` is a valid patch increment on this scheme.

## Environment

```
Python 3.12.0 (main, Apr 26 2026) [Clang 21.0.0]  aarch64-darwin
/Users/dawsonblock/.pyenv/versions/3.12.0/bin/python
```

| Pin (`requirements-lock.txt`) | Installed | Match |
|---|---|---|
| `pytest==8.4.2` | 8.4.2 | yes |
| `cryptography==48.0.1` | 48.0.1 | yes |
| `setuptools==82.0.1` | 82.0.1 | yes |
| `psycopg[binary]==3.3.4` | 3.3.4 | yes |
| (not pinned) `hypothesis` | 6.151.4 | available for Phase 4 |

Runtime backends available: Docker 29.9.2 (Desktop), `postgres` 14.20
(Homebrew), `initdb`/`pg_ctl`. No podman/lima container runtime is
required.

## Baseline test execution

```
PYTHONPATH=src:. python -m pytest tests -q
→ 1362 passed, 12 skipped, 0 failed in 86.49s
```

The audit's `1,315 passed / 45 failed / 14 skipped` **does not
reproduce** in this environment. The pinned dependency set is installed
and matches the lockfile exactly. Without the audit's environment
inventory the 45 failures cannot be attributed to a specific cause;
they are recorded as *not reproduced* rather than *fixed*.

Skipped tests (12) are opt-in profiles, not passes:
`test_control_plane_postgres.py` (PostgreSQL, gated on
`SIS_POSTGRES_DSN`), and platform-gated POSIX/ACL cases.

## Release manifest drift

`python tools/build_release.py --check` → `release manifest is stale`.

Reproduced independently by recomputing `inventory()` and diffing against
`RELEASE_SHA256.json`:

```
manifest entries: 407   current files: 408
CHANGED 6
  src/sis/v3/five_arm.py
  src/sis/v3/serving.py
  src/sis/v3/statistical_power.py
  tests/v3/test_v340_five_arm.py
  tests/v3/test_v350_campaign_integrity.py
  tests/v3/test_v350_production_profile.py
MISSING 0
UNLISTED 1
  tests/v3/five_arm_testkit.py
```

This **exactly matches** the audit's "six stale entries plus one newly
added fixture absent from the manifest". Cause: commit `9491047`
(working changes from the prior review) was committed without
regenerating the inventory. Not tampering — a release-process gap.

## Defect-to-source traceability (initial)

| ID | Invariant | Source | Reproduced |
|---|---|---|---|
| D-01 | Evidence must be bound to the arm that produced it | `five_arm.py` `_validate_outcome`, `contracts.py` `EvaluatorReceiptV2` | yes |
| D-02 | Resource measurements must be authenticated | `five_arm.py` `build_report`, `_recompute_metrics` | yes |
| D-03 | Callable receipt authority must fail closed | `five_arm.py` `_verify_receipt:411` | yes |
| D-04 | Production readiness must not be bypassable by clearing the cached profile | `serving.py:468,691` | yes |
| D-05 | Receipt expiry/revocation must be enforced | `evidence_binding.py` `EvidenceBindingAuthority.receipt` | yes |
| D-06 | Report validation must be total over untrusted input | `five_arm.py` `_is_finite_number`, `assess` | yes |
| D-07 | Release manifest must match the tree | `RELEASE_SHA256.json` | yes |
| D-08 | Evaluator isolation must be an enforced OS boundary | `evaluator_isolation.py` (declared only) | yes (declared vs enforced) |
| D-09 | Cross-replica guarantees must be qualified on PostgreSQL | `test_control_plane_postgres.py` (skipped) | blocked → now runnable |

## Notes on prior observations

- "69 focused changed-module tests passed" — reproduced: the three
  touched modules collect exactly 69 tests and all pass.
- "Runtime dependency mismatches" — not reproduced; the installed set
  matches the lockfile.
- "Unresolved evaluator-receipt attribution and measurement defects" —
  reproduced and characterized; see D-01/D-02.
