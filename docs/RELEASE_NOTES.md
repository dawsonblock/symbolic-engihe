# SIS v3.3.1 — Authority Closure and Governed Skill Learning

## Release classification

**`IMPLEMENTED_NOT_EFFICACY_QUALIFIED`**

- P0 authority, evaluation-certificate, execution-identity and evidence
  custody gates are implemented and covered by adversarial tests.
- The evaluator sandbox is implemented as defense-in-depth (seatbelt,
  resource limits, protected-path denial, network denial). It is **not**
  a validated OS boundary; production hostile-code evaluation requires a
  rootless worker or microVM.
- The powered real-agent five-arm efficacy run was **not executed** in
  this release. The working interface and gate are present; the real
  gate is marked blocked. No learning-efficacy claim is made.

## What changed

### Authority closure (P0)

- `AuthorityCheckpointV1`, `FileAuthorityCheckpointStore`,
  `AuthorityJournal`, `AuthorityStateVerifier`.
- Monotonic sequence, previous-digest chain, authority epoch, journal
  head/sequence and candidate-revision digest.
- Compare-and-append with OS file locking and atomic replacement.
- Crash-recoverable publication; local-ahead serving denial;
  rollback/divergence detection.
- Production serving requires a checkpoint-verified registry; a
  local-only database is not rollback resistant.

### Evaluation evidence closure (P0)

- `EvaluationCertificateV1`, `QualificationPolicy`,
  `QualificationValidator`, `ProtocolRegistry`.
- Evidence classes: exploratory, demonstration, confirmatory, invalid.
- Candidate-delivery attestations; actual delivered artifact is bound per
  task.
- Sample size, preregistration, protocol conformance, holdout partition,
  statistical acceptance, negative transfer, revocation and scope are
  re-derived. A 2-task run cannot satisfy a 29-task protocol.
- Production qualification requires a certificate; demonstration
  registries cannot serve production.

### Execution identity and custody (P0)

- `ExecutionIdentityV1` and `ExecutionIdentityAuthority`.
- Tree/commit/family/workspace/task/nonce binding, expiry and replay
  checks; contradictory claims abstain with no actionable instructions.
- `EvidenceCustodyStore`: immutable objects, dependency links, signed
  revocation/supersession logs, explicit offline policy.
- Deleted, altered, revoked, superseded or unavailable evidence fails
  closed.

### Skill ingestion (P1)

- Scope-aware candidate ids; identical content for two scopes produces
  two candidates; metadata conflict is explicit.
- Structured Markdown parser; code fences, quotes and example commands
  never become active instructions; line references preserved.
- High-severity prompt-injection/shell-step findings block automatic
  qualification and are preserved for review.
- Discovery raises rather than silently truncating at 500; pagination and
  explicit completeness flags.
- Bounded large documents (96 KiB accepted, full body SHA-256, explicit
  inline truncation), frontmatter variants, duplicate/symlink/size
  safeguards, never executes installation scripts.

### Evaluator reliability and sandbox (P1)

- Pinned runtime profile (Python 3.12, pytest 8.4.2), plugin autoload
  disabled, explicit plugin policy.
- Bootstrap probe separates evaluator initialization from task execution.
- 2 GiB default address-space envelope; all three scripted holdouts run
  without manual memory-limit changes.
- Outcome taxonomy: TASK_PASS, TASK_FAIL, EVALUATOR_BOOTSTRAP_ERROR,
  RESOURCE_LIMIT, TIMEOUT, SANDBOX_FAILURE, EVIDENCE_FAILURE,
  INFRASTRUCTURE_ERROR.
- Seatbelt denies protected paths (keys, evaluator registry, authority
  stores) and network; receipts record isolation facts.

### Learning qualification (P1)

- Five-arm campaign (`A` baseline, `B` memory, `C` skills, `D` symbolic,
  `E` integrated), preregistered protocol, hidden/disjoint holdout,
  frozen candidate digests.
- Exact McNemar, Wilson intervals, Newcombe difference interval, power
  analysis, negative transfer, resource overhead, failure categories,
  integration-vs-components.
- Scripted demo is labelled demonstration and cannot claim efficacy.
  Real-agent gate is implemented; powered run blocked in this release.

## Test evidence

- Baseline v3.3 branch: **804 passed, 2 skipped**.
- v3.3.1: **926 passed, 3 skipped, 0 failed**
  (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONPATH=src
  python3 -m pytest -q`).
- New suites: authority checkpoints 23, evaluation certificates 22,
  execution identity/custody 22, skill ingestion hardening 19 + 1 skip,
  evaluator runtime 19, learning qualification 15.
- Skill compatibility: 65/66 vskill `SKILL.md` files parse; the one
  rejection is an e2e fixture with no description and only an HTML
  comment body. Five large documents were explicitly truncated with
  preserved body digests.
- Scripted holdouts: `write-skills`, `php2shell-check`, `write-tests` all
  qualified under the pinned 2 GiB profile; A 0/1, E 1/1 each.

## Known limitations

- Local sandbox is not a validated hostile-code boundary.
- Checkpoint/custody separation is a deployment requirement; a principal
  that can write both the candidate DB and the checkpoint store defeats
  rollback resistance.
- A compromised authority or evaluator key defeats its corresponding
  gate.
- Pattern-based injection scanning is advisory, not proof of safety.
- No powered real-agent efficacy result; no claim of improvement.

## Artifacts

- `release/SIS-v3.3.1-AUTHORITY-CLOSURE.zip`
- `release/RELEASE_SHA256.json` (in-archive inventory)
- `release/release_manifest.json`, `release/source_inventory.json`,
  `release/verification.json`, `release/SHA256SUMS` (out-of-band
  provenance)
- `evidence/` — baseline, authority, adversarial, ingestion, sandbox,
  evaluation and release evidence.
- `evidence/release/release_verification.json` is out-of-band: it
  contains the archive hash and therefore cannot be a member of the
  archive it describes.
