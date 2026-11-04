# SIS v3.5.0 implementation record

This is the engineering-remediation branch. It implements the parts of
the v3.5.0 plan that can be built and verified in this repository without
new infrastructure; the rest is listed, with reasons, under **Not
implemented here**. Baseline and measured runs: `V350_BASELINE.md`.

## Status

| PR | Scope | State |
|---|---|---|
| PR-00 | Freeze and reproduce baseline | done |
| PR-01 | Mandatory production authority profile | done |
| PR-02 | Real evaluator execution isolation | **not implemented** |
| PR-03 | Five-arm evaluation and evidence integrity | **not implemented** |
| PR-04 | Key custody, crypto backend, utility semantics | done |
| PR-05 | Memory/skill/procedure learning quality | **not implemented** |
| PR-06 | Powered real-agent efficacy evaluation | **not implemented** |
| PR-07 | Cross-replica, operations and release | partial (existing tests only) |

## PR-00 — baseline

`V350_BASELINE.md` records the pinned runtime, both measured profiles,
the manifest and the reproductions. It also explains why the deep
audit's 1,249 / 45 / 14 result is a non-pinned environment and is not
used as an acceptance number.

## PR-01 — production authority profile

`serving.ProductionRequirements` is the single statement of what a
production gateway may not be missing: control plane (bound), binding
authority, ledger, monitor, signing custody, evidence policy and
provider, rollout state, a vetted crypto backend and one key per role
(evaluator, harness, authorization, ledger).

- The **constructor** raises `production_requirements_missing:<reasons>`
  when any of those is absent, invalid or bound to a different plane.
- **`health()`** reports `checks["production_profile"]` and is not ready
  when the profile is incomplete.
- **`serve()`** re-evaluates the profile before issuing guidance and
  abstains with `production_profile_incomplete`, so a caller that
  invokes the gateway directly cannot bypass `/readyz`.
- Production has exactly **one commit path**: the authority ledger. The
  direct `commit_bound_authorization` branch is guarded by a defensive
  `production_requires_ledger` error.
- Key separation is checked, not assumed: the evaluator, harness,
  authorization and ledger key sets must be non-empty and disjoint.
- The audit record carries `production_problems` and `rollout_stage`.

`tests/v3/test_v350_production_profile.py` covers each missing
component, plane mismatch, shared keys, custody drift, a non-vetted
backend, an invalid rollout state, the constructor refusals, a complete
production gateway that serves, and a runtime degradation that makes
`serve()` abstain.

## PR-04 — custody, crypto backend, utility semantics

- `custody_report()` now re-checks every seed on disk (regular file, not
  a symlink, owner-only, owned by this principal, 32 bytes) and requires
  every signing role. A `chmod 0600 -> 0644` after enrollment makes
  `ready` false and names the role in `missing_roles`; it never reports
  seed material.
- `signatures.require_vetted_backend(production=True)` raises
  `CryptoBackendError("crypto_backend_not_vetted")` unless the active
  backend is `cryptography`. `cryptography==48.0.1` is now a lock pin and
  a `crypto` extra.
- `CalibrationPolicy.utility_mode` makes the meaning of utility explicit:
  `ranking` (default, historical) or `abstention`, which rejects below
  `min_net_utility_milli` with `net_utility_below_threshold`. The policy
  digest is recorded with every decision (`evidence_policy_digest`).

`tests/v3/test_v350_custody_and_utility.py` covers chmod drift, a deleted
seed, a symlinked seed, no seed material in the report, the backend
refusal, ranking vs abstention, and digest stability.

## Not implemented here

These are deliberately not claimed:

- **PR-02.** The evaluator still runs under `LocalSubprocessExecutor`.
  A production sandbox backend (OCI container or microVM, non-root UID,
  no network, read-only root, syscall and PID limits, verified image and
  task digests, attestation) and a separate trusted signer are a
  deployment-integration project; building a *checked* sandbox requires
  a target runtime this repository does not ship. The current profile
  refuses an unisolated run as a *production evaluation*
  (`verify_profile`), but that is a declaration, not enforcement.
- **PR-03.** The five-arm design still accepts any singleton B/C/D, and
  `assess()` does not validate report rows against the plan, recompute
  metrics from authenticated rows, bind a signed analysis manifest or
  enforce an evidence ceiling. The audit's "supported + confirmatory for
  undeclared exploratory rows" reproducer is therefore still open.
- **PR-05.** Candidate lifecycle, provenance, revocation/requalification
  and conflict/degradation checks are not extended here.
- **PR-06.** A powered, preregistered, blind, lineage-separated live
  study needs model credentials, quota and a task corpus. No efficacy
  claim is made.
- **PR-07.** The existing cross-replica, kill-switch, migration and
  recovery tests still pass on SQLite and PostgreSQL, but structured
  metrics, reason-coded audit events, signed CI provenance and staged
  rollout approvals are not added here.

## Verification

| Run | Result |
|---|---|
| SQLite, pinned runtime | 1325 passed, 12 skipped |
| PostgreSQL 14.20 | 1334 passed, 3 skipped |
| `tools/check_runtime.py` | pins match |
| `tools/reproduce_v340_defects.py` | 0 open |
| `tools/verify_release.py .` | manifest verifies |
