# SIS v3.4.0 implementation record

Twelve independently reviewable changes on
`sis/v3.4.0-engineering-upgrade`, branched from `d3dc19e` (v3.3.2).
Baseline and reproduction evidence: `docs/v3/V340_BASELINE.md`.
Operating instructions: `docs/v3/V340_RUNBOOK.md`.

## Checklist

| # | Change | State |
|---|---|---|
| PR-01 | Baseline reproduction, pinned runtime, legacy-evidence quarantine | done |
| PR-02 | `AuthorizationV2`, `ExecutionAttemptV2`, `EvaluatorReceiptV2`, `OutcomeV2` | done |
| PR-03 | SQLite/PostgreSQL schema 2 and 3, atomic attribution constraints | done |
| PR-04 | Authenticated outcome endpoint with exact evidence matching | done |
| PR-05 | Atomic attribution, replay controls, cross-process tests | done |
| PR-06 | Unified candidate/procedure authority ledger, `AuthoritySnapshotV2` | done |
| PR-07 | Expiry, revocation, kill switch, liveness vs readiness | done |
| PR-08 | Isolated evaluator and four-identity key custody | done |
| PR-09 | Statistical power, timestamped preregistration, lineage holdouts | done |
| PR-10 | Controlled five-arm campaign with after-cost verdict | done |
| PR-11 | Evidence-calibrated retrieval and negative-transfer controls | done |
| PR-12 | Monitoring, staged rollout, reversible migration, recovery drills | done |

Suite, SQLite profile: **1268 passed, 10 skipped**.
Suite, PostgreSQL profile (`SIS_POSTGRES_DSN` set): run per
`V340_RUNBOOK.md` §1; it was not re-run in the environment that applied
the review corrections, so its count is not restated here.

Baseline was 986 passed, 8 skipped.

The 7 tests that only run with a DSN are the multi-replica profile: 4
control-plane tests and the 3 PostgreSQL constraint tests in
`test_v340_concurrency.py`.

## PR-01 — evidence chain baseline

- `tools/reproduce_v340_defects.py` drives the real production stack and
  reports each P0 attack as OPEN or CLOSED. On v3.3.2 all three were OPEN;
  now all three are CLOSED with a stable rejection reason.
- `tools/check_runtime.py` verifies the interpreter and every pin in
  `requirements-lock.txt`.
- Legacy evidence is physically quarantined: schema-1 rows live in
  `guidance_outcome` and are reported as `legacy_unverified`; only
  `outcome_v2` rows are `verified`, and `independent_outcomes()` reads
  only the verified chain.

## PR-02 — binding contracts

New records in `contracts.py`: `AuthorizationV2`, `ExecutionAttemptV2`,
`EvaluatorReceiptV2`, `OutcomeV2`, `AuthoritySnapshotV2`.

`evidence_binding.py` provides domain-separated Ed25519 signing and
verification for each, derives the attempt id from the signed execution
identity (the harness cannot choose an id it could reuse), computes the
exposure commitment, and implements `match_chain` — the single place that
decides whether a receipt may be attributed to an authorization.

`exposure_state` separates *delivered* from *used*:
`not_delivered`, `delivered_unread`, `used_partial`, `used`. An attempt
that never reports uses the `unreported_exposure_digest`, so the gateway
never assumes the guidance was used.

## PR-03 — persistence

Schema 2 adds `authorization_v2` (`UNIQUE(attempt_id)`,
`UNIQUE(nonce)`), `attempt_exposure`, `evaluator_receipt_v2`
(`UNIQUE(authorization_id)`, `UNIQUE(nonce)`, `UNIQUE(receipt_digest)`)
and `outcome_v2` (`UNIQUE(authorization_id)`, partial unique index on
`receipt_digest` where `independence='independent'`).

Schema 3 adds the authority ledger: `authority_state`, `authority_subject`,
`authority_revocation`, `authority_snapshot_v2`, `authority_event`.

Both backends share the same methods on `_SqlControlPlane`, so SQLite and
PostgreSQL enforce identical constraints.

## PR-04 — authenticated outcome endpoint

`V3ServingService._outcome` now forwards the authenticated principal.
`GovernedServingGateway.record_outcome` has two modes:

- **bound** (any gateway with a signing control plane): the full V2 chain
  is required and every binding is compared exactly. Missing or
  mismatched evidence is rejected with a stable reason.
- **legacy** (development gateways with no control plane): the schema-1
  path still works and is tagged `legacy_unverified`. Production refuses
  it outright (`bound_outcome_required`).

`authorization_for_task()` is no longer reachable from outcome acceptance:
an implicit "latest authorization" is exactly how one receipt used to be
credited to two interventions.

Acceptance matrix (17 tests) covers: cross-principal submission,
cross-repository receipt, cross-tree receipt, cross-attempt receipt,
receipt reuse, modified guidance digest, modified result after signature,
untrusted signer, expired authorization, revoked authorization, missing
receipt, implicit authorization, and the legitimate submission.

## PR-05 — atomicity

The constraints that make attribution exact are database constraints.
`tests/v3/test_v340_concurrency.py` runs real child processes against a
real database file: six processes racing on one outcome produce exactly
one `accepted` and five `outcome_already_recorded`; six racing on one
nonce produce one commit; the constraint survives a process restart.
The PostgreSQL profile runs the same invariants when `SIS_POSTGRES_DSN`
is set.

### A defect only the PostgreSQL profile could find

Running the PostgreSQL tests for the first time failed immediately with
`the query has 0 placeholders but 1 parameters were passed`. Every
statement shared by both backends had been written with `?`, which SQLite
accepts and psycopg rejects. The fix is one choke point rather than 26
hand edits: `_ParamStyle` wraps the PostgreSQL connection and rewrites
`?` to `%s`, so shared SQL is written once and works on both drivers.

A second failure followed: duplicate outcomes surfaced as
`control_plane_unavailable` instead of `outcome_already_recorded`, because
`_is_integrity_error` had been implemented on the SQLite backend only.
Both are now covered by the PostgreSQL run, and both were invisible to a
green SQLite suite.

## PR-06 — unified authority ledger

`authority_ledger.py` implements

    Authorize = I ∧ S ∧ E ∧ A ∧ ¬R ∧ ¬K

as a guard evaluated *inside* the transaction that commits the
authorization. The epoch row is read there — with `SELECT … FOR UPDATE`
on PostgreSQL, and under SQLite's `BEGIN IMMEDIATE` write lock — so a
revocation or disable that commits first cannot be overtaken, and a
decision that observed a stale epoch is refused (`authority_epoch_changed`).

`AuthoritySnapshotV2` is signed and monotonic; `publish()` is idempotent
per epoch and reads the epoch, every head and the signed record in one
transaction (`publish_authority_snapshot`). `readiness()` verifies the
stored snapshot against the ledger's own public key, so a tampered row is
not "stale", it is not a snapshot. The ledger refuses to sign snapshots
with the same key the control plane uses to sign authorizations.
`LedgerMirror` keeps candidate/procedure/grant projections in step with
their systems of record.

## PR-07 — expiry, kill switch, readiness

- The kill switch is read from the shared store on every request and
  re-read inside the committing transaction.
- An identity that expired before the commit is refused
  (`identity_expired`); an authorization may not outlive its identity.
- `gateway.recheck()` re-verifies expiry, revocation, disable and epoch
  before a delayed delivery. Both timestamps are parsed, not compared as
  ISO text: `14:00+05:00` is `09:00Z`, and string ordering accepts it as
  unexpired. An authorization whose ledger epoch has moved is refused
  (`authority_epoch_changed`).
- `/livez` answers while the process is alive; `/readyz` answers 503 when
  the deployment cannot record trustworthy evidence. Both answer before
  the API-key check: a liveness probe that receives 401 is a restart
  loop. A production replica that can serve but cannot bind an outcome is
  alive and not ready.

## PR-08 — evaluator isolation and custody

`key_custody.py` enrolls one owner-only seed per role and refuses shared
identities, group-readable seeds and unknown roles. It never returns a
seed; `sign()` loads one for the duration of one signature.

`evaluator_isolation.py` declares the isolation a run had (network,
memory, CPU, wall clock, open files, read-only root, clean env, pinned
image), refuses to call an unisolated run a production evaluation, and
treats a crash or timeout as `error` with **no receipt**.

The child also **performs the measurement**: `run_isolated` sends only
the binding (authorization, attempt, submission, task, isolation), never
a result. The worker runs the registered acceptance command, derives the
outcome, artifact digest, suite commitment and environment digest from
that run, and only then loads the evaluator seed and signs. A binding
without a measurement is refused (`measurement_missing`), so the
evaluator key is not a signature oracle for a caller-chosen result.

## PR-09 — statistical defensibility

`statistical_power.py` implements the paired McNemar and two-proportion
sample-size formulas with milli-scale integer inputs, so a serialized
policy is exact.

- `PowerRequirement` fixes the sample size before the run.
- `PreregistrationRecord` is signed by a timestamping authority; the
  validator requires it to predate the evaluation.
- `LineageRegistry` groups repositories by lineage, not snapshot digest;
  an unknown or shared lineage is a leak.
- `classify()` returns confirmatory only when every requirement holds,
  and `QualificationValidator` rejects a confirmatory certificate that
  violates its preregistered sample size, its registration order, or its
  lineage separation.

`analyze_report` now uses the declared `power_requirement` and marks an
undersized run exploratory with
`release_gate = IMPLEMENTED_NOT_EFFICACY_QUALIFIED`. A requirement that
cannot be evaluated is reported (`power_requirement_error`) and also
forces exploratory; it is never replaced by a convenient default.

## PR-10 — five-arm benchmark

`five_arm.py` declares the arms and their components and refuses a design
that is not a subset chain (`A` bare, `B`/`C`/`D` one component each, `E`
all three). `CampaignPlan` binds a preregistration, a power requirement,
a seed and budgets; arm order is seeded, not incidental.

`assess()` reports the E-vs-A contrast, every component contrast, the
token ratio and a verdict: `supported`, `no_evidence`, `regressed`,
`underpowered`, `no_advantage_after_cost`, or `invalid_holdout`. More
than twice the tokens for the same solve rate is not an advantage, and a
run that exceeded its declared token or wall budget is recorded as a
failure rather than a solve (`budget_exceeded`).

## PR-11 — evidence-calibrated retrieval

`evidence_policy.py` turns serving into an explicit trade-off:

    utility = expected_gain
              - token_cost - latency - uncertainty - regression_risk

and refuses to serve when the lower bound of the gain interval is not
positive. Abstention conditions are decisive, not outweighed. The token
budget is a hard stop, because a half-served procedure is not the
procedure that was evaluated.

`negative_transfer_guard` blocks a rule whose known failures share a task
signature prefix with the current task; it runs inside `_calibrate`, so a
blocked rule never reaches composition. `select()` materializes its input
once, so an `Iterable` (including a generator) is accepted.

Independence is **signed by the evaluator**, not asserted by the
requester: `EvaluatorReceiptV2` carries `independence` and
`dependency_receipt_digest`, `match_chain` reads them from the receipt,
and a dependent outcome must name a receipt that exists for the same
task. A request that restates independence differently is refused
(`independence_mismatch`).

## PR-12 — operations

- `operations.py` scans for authority inconsistencies with explicit
  severities; `critical` means serving must stop. A gateway given a
  monitor consults it in `health()`, so a critical finding removes the
  replica from service.
- `rollout.py` enforces shadow → advisory → full, stepwise, with eight
  release gates. A missing gate is a failed gate; rollback is always
  available and keeps the gate status it was given. A gateway given a
  `RolloutState` enforces it: shadow abstains (`rollout_shadow`), advisory
  grants no procedures.
- `tools/migrate_control_plane.py` upgrades additively and downgrades
  only with `--yes` after a verified, owner-only SQLite backup. An
  intermediate target (`--to 2`) lands at that schema rather than at the
  newest one.
- Five recovery drills are encoded in `tests/v3/test_v340_operations.py`.

## Review corrections

`tests/v3/test_v340_review_fixes.py` pins the defects found by reviewing
the branch rather than by running it: `recheck()` string timestamp
comparison, the missing PostgreSQL epoch lock, the evaluator signing a
caller-supplied result, non-atomic snapshot publication, dual
`authority_epoch` semantics, caller-asserted independence, the
double-iterating `select()`, the unwired monitor and rollout, the
unapplied negative-transfer guard, `--to 2` landing at 3, `?` rewriting
inside SQL literals, and the smaller corrections listed in `CHANGELOG.md`.

## What is still not claimed

- No efficacy claim is made. PR-10 provides the controlled harness and
  the verdict function; running it against a live agent on a powered
  holdout is a separate, expensive step, and the verdict defaults to
  `underpowered` until that happens.
- Network isolation and immutable images are *declared* by the profile
  and verified by `verify_profile`, but this module cannot create a
  network namespace. A deployment that claims production isolation must
  supply it at the platform layer.
- PostgreSQL is qualified locally (14.20) but the 7 profile tests still
  skip without `SIS_POSTGRES_DSN`; a deployment must run them against its
  own server before claiming cross-replica guarantees. The `FOR UPDATE`
  lock and the additive-column migration added by the review corrections
  are only exercised by that run, and were not re-run when they landed.
- Three skips remain and none is a failure:
  `test_v240_review.py` needs Windows ACLs, `test_skill_ingest_hardening.py`
  needs the `skills/vskill-main 2` corpus at the repo root, and
  `test_source_manifest.py` needs the pinned baseline commit
  `daf0ccce…`, which is **not present in this repository and not on the
  remote** (`git fetch` returns `not our ref`). Baseline source-manifest
  verification therefore cannot be reproduced from this checkout at all;
  that is a provenance gap in the distribution, not something this branch
  introduced.
