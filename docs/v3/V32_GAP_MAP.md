# SIS v3.2 Gap Map — plan PRs vs current v3.1-alpha state

Baseline: branch codex/sis-authority-transfer-qualification @ fc00086
(661 tests, live Codex study executed, all v3.1 gates except efficacy).

## Phase 1 — security (PR-01..03)

| Spec item | Status | Remaining |
|---|---|---|
| persistent signer revocations | DONE (PR-04: signed RevocationV1, committed, per-request enforced, tamper fails closed) | — |
| authoritative evidence dependencies | DONE (evidence-bound induction, receipt_resolver, cascade suspension) | — |
| authenticated cross-repo grants | DONE (PR-03 ScopeGrantV1 + registry lineage + transfer evidence) | — |
| trusted task identities | PARTIAL: registry resolves repos; task_statement_digest is unbound in live flow | bind task statement to evaluator registration |

## Phase 2 — execution pipeline (PR-04..05)

| Spec item | Status | Remaining |
|---|---|---|
| verified learning inputs | DONE (SourceChangeV1 + digest-bound induction) | — |
| authenticated v3 service | DONE (adapter auth probe PR-05) | — |
| real Codex->procedure | PARTIAL: e2e loop + live serving proven; no agent->capture->learn ingest path from live codex exec events yet | codex-cli event->SourceChange ingestor |

## Phase 3 — execution custody (PR-06)

| Spec item | Status | Remaining |
|---|---|---|
| isolated execution | PARTIAL: unverified_local only; codex arm ran inside copied workspace + CLI sandbox | document/stronger sandbox |
| independent evaluator credentials | DONE (EvaluatorKeyStore, private test material) | — |
| verified resource accounting | PARTIAL: codex exec prints token usage on stdout; not metered into UsageMeter | parse exec events into meter |
| enforceable termination | GAP: watchdog abandons daemon thread; codex subprocess keeps running past wall | kill process group on timeout |

## Phase 4 — proof (PR-07..08)

| Spec item | Status | Remaining |
|---|---|---|
| benchmark harness repair | DONE: steps-serving fix found+fixed by live study | — |
| repo-disjoint comparison | PARTIAL: executed, +2 signal, underpowered | bigger corpus + rerun |
| reproducible release evidence | DONE (manifest/verify, 263 files) | — |

## Conclusion

v3.2 = v3.1 + ~4 real deltas: (a) subprocess termination, (b) exec-event
usage metering, (c) task-statement binding, (d) codex-event source-change
ingest. Plus the still-open efficacy gate (needs harder corpus, n>=10).
The spec doc itself was a UI attachment, not on disk; this map derives
from the PR titles in the request.
