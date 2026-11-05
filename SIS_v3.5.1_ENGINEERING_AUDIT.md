# SIS v3.5.1 — Engineering Audit

**Release decision: CONDITIONAL_GO.**
See §8 for the exact scope this permits and §7 for what it does not.

---

## 1. Scope and inputs

| Prompt-named input | Present |
|---|---|
| `symbolic-engihe-sis-v3.4.0-engineering-upgrade 4.zip` | **No.** The live repository is a git worktree; no archive was extracted. |
| `SIS_v3_5_0_Upgrade4_Independent_Deep_Audit.md` | **No** |
| `SIS_v3_5_0_Upgrade4_Independent_Audit_Evidence.zip` | **No** |
| Prior upgrade archives | Yes (`release/SIS-v3.3.*.zip`) |

The audit's findings were therefore taken from the prompt text and
**reproduced independently** rather than read from the report. Every
reproduction in `SIS_v3.5.1_DEFECT_MATRIX.md` is an observation on the
baseline commit, not a restatement.

The repository identifies itself as **3.5.0** (`pyproject.toml`,
`src/sis/__init__.py`) despite the archive name, confirming the prompt's
observation. It is now **3.5.1**.

## 2. Baseline

`9491047`, clean tree, Python 3.12.0, pinned dependencies matching
`requirements-lock.txt` exactly.

```
PYTHONPATH=src:. python -m pytest tests -q
→ 1362 passed, 12 skipped, 0 failed
```

`tools/build_release.py --check` → stale. Independent recomputation:
6 changed files, 1 unlisted file — **exactly** the audit's finding.

The audit's `1,315 passed / 45 failed / 14 skipped` **did not
reproduce**. Recorded as *not reproduced*, not as *fixed*.

## 3. Implementation

### 3.1 New modules

| File | Lines | Purpose |
|---|---|---|
| `src/sis/v3/trial_evidence.py` | 478 | `ExperimentAuthorizationV2`, `TrialMeasurementV1`, domain-separated signing, canonical serialization |
| `src/sis/v3/container_isolation.py` | 392 | Enforced container boundary; parent-side signing bound to a completed run |

### 3.2 Modified modules

| File | Change |
|---|---|
| `src/sis/v3/five_arm.py` | Measurement/receipt/authorization verification; verified view; total validation; Holm correction; infrastructure-failure accounting; `authorize_experiment()`; authorization-commitment and independence checks |
| `src/sis/v3/evidence_binding.py` | `trusted_experiment_keys`, `key_validity`, `authenticated_receipt`, `experiment_authorization`, `measurement`, `validity`; `allow_expired` applies to receipts |
| `src/sis/v3/trial_evidence.py` | Timestamp policy aligned with `evidence_binding` |
| `src/sis/v3/serving.py` | Readiness gated on `self._production`; experiment key added to the separation check |
| `tools/check_source_manifest.py` | `qualification/` is out-of-band (a run record is not source) |
| `tools/v351_qualify.py` | Computed decision with blocking limitations; summary-line counts; isolation skips are blocked; destructive PostgreSQL opt-in |
| `tools/provenance.py`, `tools/package_release.py`, `tools/build_canonical_zip.py` | Dirty-tree state recorded in the statement; full dirty-path list with an explicit "and N more" |
| `.github/workflows/ci.yml` | PostgreSQL job sets `SIS_POSTGRES_ALLOW_DESTRUCTIVE=1` |
| `tests/v3/five_arm_testkit.py` | Produces the full signed chain |
| `tests/v3/test_v340_five_arm.py`, `test_v350_campaign_integrity.py`, `test_v350_production_profile.py` | Fixtures upgraded to the signed chain; **no assertion was weakened** |
| `pyproject.toml`, `src/sis/__init__.py`, `requirements-lock.txt` | Version 3.5.1; `hypothesis==6.151.4` pinned |
| `CHANGELOG.md` | v3.5.1 entry |

### 3.3 New tests

| File | Tests |
|---|---|
| `tests/v3/test_v351_evidence_chain.py` | 52 |
| `tests/v3/test_v351_report_totality.py` | 16 (incl. Hypothesis properties + full-chain leaf mutation) |
| `tests/v3/test_v351_container_isolation.py` | 19 (real container where available) |
| `tests/v3/test_v351_postgres_qualification.py` | 5 (real PostgreSQL, cross-process) |
| `tests/v3/test_v351_learning_preservation.py` | 6 (the learning path still works) |
| `tests/v3/test_v351_qualification_harness.py` | 10 (decision, counts, gate semantics) |
| `tools/v351_qualify.py` | gate harness |

No test was deleted. Three existing fixtures were updated to carry the
new signed records — the assertions themselves are unchanged.

## 4. Security invariants established

| Invariant | Evidence |
|---|---|
| A signature must be valid for the exact trial, arm, task, model and measurement | `test_v351_evidence_chain.py::AttributionTests` (13) |
| The authorization's environment, criterion and test-suite commitments must match the receipt | `AuthorizationCommitmentTests` (3) |
| A dependent evaluation is not an independent trial | `AuthorizationCommitmentTests::test_a_dependent_receipt_is_not_an_independent_trial` |
| Resource measurements are authenticated, not declared | `AttributionTests` + `MeasurementTests` (10) |
| A limit violation is a non-solve, not an inconsistent report | `StatusTests::test_a_limit_violation_is_valid_evidence_but_not_a_solve` |
| Expiry, revocation, key windows and the historical-evidence policy are enforced with distinct semantics | `SignerAuthorityTests` (14) + `HistoricalEvidenceTests` (2) |
| The preregistration must be for the plan's protocol | `ChainConsistencyTests::test_a_preregistration_for_another_protocol_is_refused` |
| Report validation is total over untrusted input | `test_v351_report_totality.py` (16) |
| Production readiness cannot be restored by clearing a cache | `test_v350_production_profile.py::test_clearing_the_cached_profile_does_not_restore_readiness` |
| The workload has no network, no host filesystem and no signing key | `test_v351_container_isolation.py` (19) |
| A signed measurement belongs to one completed, production-ready run | `SigningTests` (3) |
| Cross-process exactly-one-commit | `test_v351_postgres_qualification.py` (5) |

### 4.1 The two headline attacks, before and after

**Arm swap.** Baseline: A=20/29, E=5/29 → `regressed`; after exchanging
the two arms' genuine outcomes → `supported`, `receipts_verified: True`,
`problems: []`. v3.5.1: `invalid_report` with
`measurement_arm_mismatch` and `measurement_arm_config_mismatch`.

**Cost forgery.** Baseline: A and E both 20/29 → `no_evidence`; after
pushing every solved `A` row over budget and recomputing the aggregate →
`supported`. v3.5.1: `invalid_report` with
`measurement_tokens_mismatch`, `measurement_budget_mismatch`,
`measurement_outcome_mismatch`.

Neither attack required a key.

## 5. Test results

Executed by `tools/v351_qualify.py`; raw logs in `qualification/`.

| Gate | Command | Result |
|---|---|---|
| evidence_and_report_integrity | `pytest tests/v3/test_v351_evidence_chain.py test_v351_report_totality.py test_v340_five_arm.py test_v350_campaign_integrity.py test_v350_production_profile.py` | **140 passed, 0 failed** |
| evaluator_isolation | `pytest tests/v3/test_v351_container_isolation.py` | **19 passed, 0 failed** (Docker 29.9.2, `python:3.12-slim`) |
| postgres_cross_process | `pytest test_control_plane_postgres.py test_v351_postgres_qualification.py` with `SIS_POSTGRES_DSN` and `SIS_POSTGRES_ALLOW_DESTRUCTIVE=1` | **10 passed, 0 failed** (PostgreSQL 14.20) |
| full_regression | `pytest tests` | **1482 passed, 3 skipped, 0 failed** |
| release_manifest | `python tools/build_release.py --check` | **pass** (after regeneration) |
| release_verification | `python tools/verify_release.py .` | **pass** |

Baseline was 1362 passed / 12 skipped. The delta is +120 tests
(1482 - 1362). The skip count falls from 12 to 3 because the PostgreSQL
profile is now qualified rather than skipped.

### 5.1 Property-based and mutation testing

`test_v351_report_totality.py` runs 200 Hypothesis examples per property
over recursive JSON (including `NaN`, `inf`, 400-digit integers, nested
nulls, lists-of-lists) and asserts `validate_report` and `assess` never
raise. A separate sweep mutates every sampled leaf of a *fully signed,
`supported`* report to six hostile values, runs the full chain
(authority, analysis, experiment authorization) and asserts the verdict
never becomes `supported` (only the three documented unsigned telemetry
fields are exempt). The unmutated baseline is asserted `supported`
first, so a regression in the sweep cannot pass vacuously.

**This found a real defect the audit did not report:** an unhashable
`task_id` (a list) raised `TypeError` in `validate_report`'s duplicate
check. Fixed. The review follow-up also found that the original sweep
was vacuous (it ran without an authority, so no mutation could ever be
`supported`); it now exercises the real verification path.

## 6. Database qualification

| Backend | Status | What is actually proven |
|---|---|---|
| SQLite | **Qualified** | single-process atomicity, unique nonce, unique outcome (full suite) |
| PostgreSQL 14.20 | **Qualified** | 4 OS processes → exactly 1 commit, 3 `session_nonce_replayed`; duplicate outcome refused; failed transaction leaves no row; second connection sees the same head |

The SQLite suite is not presented as PostgreSQL qualification. When
`SIS_POSTGRES_DSN` is unset, the gate reports **blocked**, and the
decision becomes `CONDITIONAL_GO` rather than `GO`.

## 7. Remaining defects and limitations

1. **Evaluator key compromise still forges that evaluator's numbers.**
   The arm mapping, task set, model and preregistration come from other
   keys, so a forged evaluator cannot re-attribute evidence across arms
   or change what was preregistered — but it can claim a pass and a cost
   that did not happen. Single-key trust assumption; documented.
2. **`abstained`, `negative_transfer`, `integrity_failures` are unsigned.**
   They feed reporting metrics, not the supported verdict.
3. **The measurement is what the evaluator reports.** If its metering is
   wrong, the signature certifies a wrong number.
   `termination_reason == "unmetered"` marks runs whose cost is not
   authoritative; those cannot support a claim.
4. **Container boundary is Docker-specific** on this host. `podman` is
   supported by name but unexercised here.
5. **Image pinning is a local image id**, re-checked before and after the
   run. It detects a moved tag; it is not a registry attestation chain.
6. **The release manifest is locally generated and unauthenticated by the
   publisher.** No publisher signing key was available. It proves
   integrity against accidental drift, not authorship.
7. **No performance or model-capability evaluation was run.** No model
   weights were modified, and no task-success benchmark was executed in
   this environment. Nothing in this document claims an improvement in
   reasoning capability.
8. **The audit's 45 baseline failures remain unexplained.** Without the
   audit's environment inventory they cannot be attributed to product or
   environment. They are not claimed as fixed.
9. **The archive was built from an uncommitted working tree.**
   `release/release_manifest.json` records `UNCOMMITTED SOURCE`, the
   first 20 differing paths and a count of the rest;
   `release/provenance.intoto.json` carries the full list and
   `source_dirty: true`. The archive is bound to its own
   `RELEASE_SHA256.json`, not to commit `9491047`. A committed rebuild
   would produce a commit-bound provenance statement.
10. **The experiment key is optional in serving.** The separation check
    refuses a shared evaluator/experiment key whenever an experiment key
    is pinned, but a deployment that omits one simply cannot produce a
    `supported` verdict; it is not a serving-time readiness failure.
11. **The receipt vocabulary is coarser than the measurement's.**
    `error` and `partial` are non-solves mapped to a `fail` receipt; the
    evaluator cannot issue a receipt that says "error". This keeps the
    existing contract stable, but it means the receipt alone cannot
    distinguish a failed attempt from an infrastructure failure.
12. **`limit_violations` is a report field checked against the signed
    measurement.** A third-party report producer must carry the same
    list; a report that omits it is `invalid_report` rather than being
    silently treated as within budget.

## 8. Release decision

**CONDITIONAL_GO.**

Permitted deployment scope:

* production serving with the v3.5.0 production profile **and** the
  v3.5.1 readiness gate;
* confirmatory five-arm evaluation **only** where the evaluator runs
  under `container_isolation` with a pinned image and the trusted parent
  holds the signing key;
* PostgreSQL for any multi-replica claim (qualified here on 14.20);
* evidence produced under this release, with all five key roles held
  separately.

Not permitted under this decision:

* unrestricted production claims — evaluator key compromise remains a
  single-key trust assumption (§7.1);
* any claim of measured model improvement — none was run (§7.7);
* presenting the locally generated manifest as publisher-signed (§7.6);
* multi-replica operation on SQLite.

A `GO` requires §7.1, §7.7 and §7.9 to be addressed; the qualification
harness treats those three as blocking limitations and computes
`CONDITIONAL_GO` while any remains. It computes `GO` only when every
gate passes and no blocking limitation is declared.

## 8.1 Independent audit follow-up

A second, independent audit of the v3.5.1 archive reproduced ten further
defects that this audit did not find. All ten are repaired; the rows are
D-27..D-36 in `SIS_v3.5.1_DEFECT_MATRIX.md`. The two that mattered most:

* **The campaign plan was not part of the signed experiment.** A
  genuine `no_evidence` run became `supported` when only the
  caller-supplied token budget changed, with every signed record
  untouched. `ExperimentAuthorizationV2` now carries `plan_digest`, and
  the assessment refuses `experiment_plan_mismatch`.
* **The production evaluator was a host subprocess.** `run_isolated`
  checked a declarative profile and then executed on the host with the
  signing seed reachable. It now refuses `production=True` with
  `production_boundary_not_enforced` until `container_isolation` is
  wired into that path.

This audit's own review pass (D-14..D-20) and the first code review
(D-21..D-26) were both incomplete in the same direction: they checked
that each component behaved as documented, not that the components
agreed with each other. The cross-component invariants — plan to
authorization, key label to key material, profile declaration to the
executor actually used — are where the remaining risk lives.

## 9. Artifacts

| Artifact | Location |
|---|---|
| Upgraded repository | `SIS_v3.5.1_FULL_UPGRADED.zip` |
| Validation evidence | `SIS_v3.5.1_VALIDATION_EVIDENCE.zip` |
| This audit | `SIS_v3.5.1_ENGINEERING_AUDIT.md` |
| Defect matrix | `SIS_v3.5.1_DEFECT_MATRIX.md` |
| Security architecture | `SIS_v3.5.1_SECURITY_ARCHITECTURE.md` |
| Reproduction | `SIS_v3.5.1_REPRODUCTION.md` |
| Manifest | `RELEASE_SHA256.json`, `release/SIS-v3.5.1-SHA256SUMS` |
