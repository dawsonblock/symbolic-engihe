# SIS v3.5.1 — Security Architecture and Threat Model

## 1. The claim this release defends

> SIS must never classify an AI improvement as independently supported
> unless the complete execution, assignment, outcome, measurement and
> authorization evidence has been authenticated and the statistical
> acceptance conditions are satisfied.

A valid signature is necessary and not sufficient. A signature over an
incomplete record proves only that some key holder said something.

## 2. Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│ UNTRUSTED                                                           │
│                                                                     │
│   report JSON (produced by whoever ran the campaign)                │
│   workload code inside the container                                │
│   any field the evaluator did not sign                              │
└───────────────┬─────────────────────────────────┬───────────────────┘
                │                                 │
┌───────────────▼─────────────────┐   ┌───────────▼───────────────────┐
│ EVIDENCE PRODUCERS (pinned)     │   │ ENFORCED BOUNDARY             │
│                                 │   │                               │
│  experiment authority key       │   │  --network none               │
│    signs ExperimentAuthorization│   │  --read-only + tmpfs          │
│  evaluator key                  │   │  --cap-drop ALL               │
│    signs EvaluatorReceiptV2     │   │  no-new-privileges            │
│    signs TrialMeasurementV1     │   │  memory / cpu / pids limits   │
│  timestamp authority key        │   │  non-root uid                 │
│    signs PreregistrationRecord  │   │  two explicit mounts          │
│  analysis key                   │   │  NO signing key               │
│    signs AnalysisManifest       │   │                               │
└───────────────┬─────────────────┘   └───────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────────────┐
│ TRUSTED VERIFIER  (assess)                                          │
│   EvidenceBindingAuthority: trust roots, revocation, key windows    │
│   validate_report: structure + chain                                │
│   verified view: rebuilt from measurements, never from the report   │
│   statistics: McNemar + Newcombe + Holm                             │
└─────────────────────────────────────────────────────────────────────┘
```

Five key roles, deliberately disjoint. `serving._signer_separation_problems`
checks evaluator, harness, authorization, experiment and ledger roles
for overlap whenever they are pinned, and it compares **public key
material**, not key ids: the same key enrolled under four different
labels is one signer. The timestamp and analysis keys are separate trust
roots passed to `assess`.

| Role | Signs | Compromise consequence |
|---|---|---|
| experiment authority | `ExperimentAuthorizationV2` | can authorize a different arm mapping, model or task set |
| evaluator | `EvaluatorReceiptV2`, `TrialMeasurementV1` | can claim a pass and a cost that did not happen |
| timestamp authority | `PreregistrationRecord` | can back-date a preregistration |
| analysis | `AnalysisManifest` | can bind the analysis to a different holdout/timing |
| authorization / harness / ledger | `AuthorizationV2`, `ExecutionAttemptV2`, ledger entries | replay and guidance-exposure attacks |

No single key can produce a `supported` verdict.

## 3. Evidence lineage

```
PreregistrationRecord  ──signed by timestamp authority──┐
        │ digest                                        │
        ▼                                               │
ExperimentAuthorizationV2 ──signed by experiment key────┤
  experiment_id, protocol_digest, preregistration_digest │
  plan_digest  (budgets, seed, arm order, tasks, power)  │
  arms[A..E] = (label, components, config_digest)        │
  model_identity, model_digest                          │
  task_digests{task_id → sha256}                        │
  environment_digest, criterion_version,                │
  test_suite_commitment, validity window                │
  alpha_milli, multiplicity, token_ratio_milli          │
        │ digest                                        │
        ▼                                               │
TrialMeasurementV1 ──signed by evaluator────────────────┤
  experiment_id, authorization_digest                   │
  trial_id (unique), arm, arm_config_digest             │
  task_id, task_digest, model_digest                    │
  evaluator_identity, evaluator_build_digest            │
  receipt_digest, receipt_id, authorization_id,         │
  attempt_id                                            │
  tokens_in + tokens_out = tokens_total                 │
  wall_seconds_milli, tool_calls, tool_errors           │
  limit_violations, status, termination_reason          │
  started_at ≤ completed_at ≤ issued_at                 │
        │ receipt_digest                                │
        ▼                                               │
EvaluatorReceiptV2 ──signed by evaluator────────────────┤
  task_id, result, environment_digest,                  │
  criterion_version, test_suite_commitment,             │
  independence, issued_at, expires_at                   │
        │                                               │
        ▼                                               │
AnalysisManifest ──signed by analysis key───────────────┘
  protocol_digest, preregistration digest,
  first_evaluation_at, holdout_repositories, full lineage map
```

`assess` re-derives every one of these links. The report contributes
structure only. In particular, the authorization's
`environment_digest`, `criterion_version` and `test_suite_commitment`
must equal the receipt's, the preregistration's `protocol_digest` must
equal the plan's, and a receipt whose `independence` is `dependent` is
not an independent trial.

## 4. What each verification step rejects

| # | Requirement | Rejection code |
|---|---|---|
| 1 | receipt belongs to the declared experiment | `measurement_experiment_mismatch` |
| 2 | trial was authorized for the declared arm | `measurement_arm_mismatch`, `measurement_arm_config_mismatch`, `experiment_arm_config_mismatch` |
| 3 | task digest matches the preregistered task | `measurement_task_digest_mismatch`, `measurement_task_unauthorized`, `experiment_task_set_mismatch` |
| 4 | model and arm configuration match authorization | `measurement_model_mismatch`, `experiment_arm_components_mismatch` |
| 5 | attempt belongs to the authorized trial | `measurement_attempt_mismatch`, `measurement_authorization_id_mismatch` |
| 6 | evaluator signer authorized for that execution | `measurement_untrusted_signer`, `receipt_untrusted:…` |
| 7 | receipt references the correct attempt | `measurement_receipt_mismatch`, `measurement_receipt_id_mismatch` |
| 8 | measured outcome matches the authenticated receipt | `measurement_status_mismatch`, `measurement_outcome_mismatch` |
| 9 | receipt cannot be assigned to another arm | `measurement_arm_mismatch` (arm is inside the signed body) |
| 10 | duplicate/replayed evidence cannot count twice | `measurement_duplicated`, `receipt_replayed`, `receipt_duplicated` |
| 11 | environment, criterion and test suite match the authorization | `measurement_environment_mismatch`, `measurement_criterion_mismatch`, `measurement_test_suite_mismatch` |
| 12 | a dependent evaluation is not an independent trial | `receipt_not_independent` |
| 13 | the preregistration is for the plan's protocol | `preregistration_protocol_mismatch` |
| 14 | a limit violation is a non-solve, not an inconsistent report | `measurement_limit_violations_mismatch`, `measurement_budget_mismatch` |

## 5. Signer authority, expiry and revocation

`EvidenceBindingAuthority.validity()` returns stable, distinct reasons:

| Reason | Meaning | Policy |
|---|---|---|
| `signer_revoked` | key id in the revocation set | always rejected |
| `evidence_revoked` | record digest revoked | always rejected |
| `evidence_not_yet_valid` | `issued_at > now` | always rejected |
| `evidence_expired` | `now >= expires_at` | rejected unless `allow_expired` **and** the signed `issued_at` precedes expiry |
| `signing_key_not_yet_valid` | `issued_at < key.not_before` | always rejected |
| `signing_key_expired` | `issued_at >= key.not_after` | always rejected |

The historical-evidence policy is explicit and per-call: a key that
expired *after* a securely signed issuance instant does not retroactively
invalidate that record, but the caller must say so (`allow_expired=True`)
and the record's own signed timestamp is the proof. There is no implicit
grace period. The policy is applied to receipts, measurements and
experiment authorizations alike; a malformed `now` is a reported
`validity_error`, not an exception out of the validator.

An unsigned timestamp supplied by the report is never used: `issued_at`
is inside the signed body of both `TrialMeasurementV1` and
`EvaluatorReceiptV2`.

## 6. Evaluator isolation

`evaluator_isolation` (v3.5.0) gives a process group, clean environment,
POSIX rlimits and a wall-clock bound. Those are **controls**, not a
boundary. `container_isolation` (v3.5.1) provides the boundary:

| Control | Flag | Verified by |
|---|---|---|
| network denied | `--network none` | `test_network_is_denied` |
| host filesystem not visible | two bind mounts only | `test_the_host_filesystem_is_not_visible` |
| immutable root | `--read-only` + tmpfs | `test_the_root_filesystem_is_read_only` |
| no capabilities | `--cap-drop ALL` (a partial drop is not a control) | `test_a_partial_capability_drop_is_not_a_boundary` |
| no privilege escalation | `--security-opt no-new-privileges` | argv assertion |
| memory bound | `--memory` + `--memory-swap` | `test_memory_is_bounded` |
| cpu bound | `--cpus` | argv assertion |
| process bound | `--pids-limit` | `test_the_process_count_is_bounded` |
| non-root | `--user 65534:65534`, uid compared as an integer | `test_a_root_user_is_not_a_verified_control`, `test_a_leading_zero_uid_is_root` |
| pinned image | `image_digest` re-checked before and after | `test_a_moved_image_is_refused` |
| wall-clock bound | parent removes the named container on timeout | `test_a_hung_workload_is_actually_stopped` |
| **no signing key** | key dir is not a mount | `test_the_signing_key_is_not_present` |
| **no symlink escape** | `O_NOFOLLOW` + regular-file check + 64 KiB cap | `test_a_symlinked_measurement_is_not_this_runs_evidence` |
| **bounded ingestion** | stdout/stderr read from capped temporary files | `test_a_symlinked_measurement_is_not_this_runs_evidence` |
| no stale measurement | sink measurement removed before the run; read only on exit 0 | `test_a_stale_measurement_is_not_this_runs_evidence` |

The **no signing key** and **no stale measurement** rows are the
architectural point: the workload produces a measurement, and the
**trusted parent** signs it after the container has exited
(`container_isolation.sign_measurement`). `sign_measurement`
takes the completed `ContainerResult` and refuses a run that did not
succeed or whose profile is not `production_ready`; a compromised
workload has nothing to steal and nothing to forge with, and a stale or
failed run cannot be signed as if it were evidence.

**This boundary is not yet the one the evaluator uses.**
`evaluator_isolation.run_isolated` still spawns a host subprocess, so it
refuses `production=True` with `production_boundary_not_enforced` rather
than accept a profile it cannot enforce. The container module is the
enforced boundary and the integration is the next engineering step; until
it lands, a production evaluation does not start.

## 7. Storage guarantees

| Backend | Guarantee | Qualified by |
|---|---|---|
| SQLite | single-process atomicity, unique nonce, unique outcome | full suite (default) |
| PostgreSQL 14.20 | cross-process exactly-one-commit, duplicate refusal, rollback, shared head | `test_control_plane_postgres.py` + `test_v351_postgres_qualification.py`, run against a live server |

SQLite results are not presented as PostgreSQL qualification. The
PostgreSQL gate is `blocked` (not passed) when `SIS_POSTGRES_DSN` is
unset, and `tools/v351_qualify.py` reports it that way.

## 8. Promotion controls

A confirmatory verdict requires **all** of:

1. `validate_report.ok` — structure, plan binding, chain integrity;
2. `validation.verified` — every one of the 145 (task × arm) cells
   carries an authenticated measurement;
3. `receipts_verified` and `measurements_verified`, with every receipt
   `independent` and its environment, criterion and test suite equal to
   the authorization's;
4. a verified `ExperimentAuthorizationV2` whose arm mapping, task set,
   protocol **and plan digest** match the plan — a budget, seed or
   ordering change is a different experiment, not a reinterpretation;
5. a verified `AnalysisManifest` and `PreregistrationRecord`, with the
   preregistration bound to the plan's protocol;
6. `classify(...).ok` — sample size, timing, lineage-disjoint holdout;
7. `decisive["significant"]` **and** Holm-adjusted p ≤ the authorized
   `alpha_milli`, which must equal the preregistered alpha;
8. no infrastructure failures (`status == "error"`), which return
   `no_evidence` before the contrast is read;
9. token ratio ≤ the authorized `token_ratio_milli` (latency is
   reported but is not part of the cost rule);
10. input `evidence_class` not exploratory/demonstration.

Failure of any one yields a non-supporting verdict, never a weaker
`supported`.

## 9. Threat model — what an attacker with each capability can do

| Capability | Outcome after v3.5.1 |
|---|---|
| edit the report JSON | every number is checked against a signed measurement; any edit is `invalid_report` |
| swap two arms' genuine receipts + measurements | `measurement_arm_mismatch` (arm is signed) |
| present a receipt from another environment, criterion or test suite | `measurement_environment_mismatch`, `measurement_criterion_mismatch`, `measurement_test_suite_mismatch` |
| count a dependent evaluation as an independent trial | `receipt_not_independent` |
| bind the analysis to a preregistration for another protocol | `preregistration_protocol_mismatch` |
| replay a receipt/trial into another cell | `receipt_replayed`, `measurement_duplicated` |
| re-sign a measurement with a compromised evaluator key | can forge one arm's results, but not the arm mapping (experiment key), not the preregistration (timestamp key), not the analysis (analysis key). Requires evaluator key compromise, which is the documented single-key trust assumption. |
| compromise the workload inside the container | no signing key present; can only emit a measurement, and the parent signs only a completed, production-ready run (a stale or failed measurement is refused) |
| clear the production-profile cache | no effect; readiness derives from wiring |
| replay an authorization across replicas | PostgreSQL unique nonce, cross-process qualified |
| present expired/revoked evidence | distinct rejection reasons; `allow_expired` is explicit and applies to receipts too |

## 10. Residual risk

1. **Evaluator key compromise** forges that evaluator's measurements.
   Mitigated, not eliminated: the arm mapping, task set, model and
   preregistration come from other keys, so a forged evaluator cannot
   re-attribute evidence across arms or change what was preregistered.
2. **`abstained`, `negative_transfer`, `integrity_failures` are unsigned.**
   They feed reporting metrics but not the supported verdict. Documented
   in `_verified_view`.
3. **`tokens`/`wall` are what the evaluator reports.** If the evaluator's
   own metering is wrong, the signature certifies a wrong number. The
   `termination_reason == "unmetered"` escape hatch marks runs whose cost
   is not authoritative, and those cannot support a claim.
4. **Container runtime trust.** The boundary is Docker's; a compromised
   Docker daemon is outside this model.
5. **Image digest is a local id.** `resolve_image_digest` reads the local
   image id and re-checks it before and after the run. That detects a
   moved tag on this host; it is not a registry-attestation chain.
6. **The experiment key is optional in serving.** If it is pinned, it
   may not be the evaluator key; if it is absent, the assessment cannot
   produce `supported`.
7. **The receipt vocabulary is coarser than the measurement's.** A
   `status` of `error` or `partial` is a non-solve carried by a `fail`
   receipt; the receipt alone cannot distinguish an infrastructure
   failure from a failed attempt.
8. **`limit_violations` is a report field checked against the signed
   measurement.** A third-party report producer must carry it; omitting
   it is `invalid_report`, not "within budget".
