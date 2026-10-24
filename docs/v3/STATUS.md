# SIS v3 implementation status

Current classification: **M0 contracts/policy plus SIS3-003 executor,
SIS3-005 episode store, SIS3-006 signed receipts, SIS3-004 CLI adapter (real
backend contact, quota-limited), SIS3-007–012 (procedure store + miner,
source-preserving patcher, hard-gated retrieval, recommend/abstain guidance,
signed promotion controller + rollback, external anchor chain, four-arm
benchmark harness) are implemented and locally tested.** A *passing* live
Codex episode is blocked by account quota (reset ~8:36 PM on run date);
OS-validated isolation, evaluator process separation, and any efficacy claim
remain unestablished. No v3.0.0-alpha label is claimed.

## SIS3-001 and SIS3-002 report

```yaml
phase_id: SIS3-001+SIS3-002
status: blocked
base_revision: daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08
source_files_changed:
  - .github/workflows/ci.yml
  - pyproject.toml
  - src/sis/server.py
  - tools/check_source_manifest.py
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/MIGRATION.md
  - docs/v3/STATUS.md
  - docs/v3/TEST_MATRIX.md
  - docs/v3/THREAT_MODEL.md
  - docs/v3/TRUST_BOUNDARIES.md
  - examples/v3/contracts_v1.json
  - examples/v3/negative_transfer/remaining_balance.json
  - src/sis/v3/__init__.py
  - src/sis/v3/contracts.py
  - src/sis/v3/guidance.py
  - src/sis/v3/policy.py
  - tests/v3/__init__.py
  - tests/v3/test_contracts.py
  - tests/v3/test_guidance.py
  - tests/v3/test_http_permissions.py
  - tests/v3/test_policy.py
  - tests/v3/test_source_manifest.py
tests_added: 25
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 tools/check_source_manifest.py --baseline-ref daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08"
  - "python3 -m compileall -q src/sis tests/v3"
  - "Isolated temporary venv: pip install -e .; import sis, sis.v3"
  - "Extracted Git baseline: unittest, smoke integration, and source manifest checks"
observed_outcomes:
  - "Baseline at base_revision: 338 tests, 1 skipped; smoke passed; 138 manifest files verified"
  - "Development tree: 363 tests, 1 skipped; smoke passed; compileall passed"
  - "Pinned baseline integrity: 138 files verified; development delta reported separately"
  - "Editable install passed; imported SIS 2.4.0 and v3 schema version 1"
  - "The plan's exact ZIP SHA-256 was not verified because that ZIP is absent"
environment_and_dependency_versions:
  - "macOS 26.2"
  - "Python 3.12.0"
  - "setuptools 82.0.1 (pinned build backend)"
security_tests:
  - "All 12 operator POST routes denied a keyed reader token and forged JSON role"
  - "Unknown route aliases returned 404; query alias remained subject to operator authentication"
  - "Unkeyed loopback code-study compatibility passed in a disposable temporary database"
  - "Contract unknown fields, duplicate keys, non-finite numbers, oversized JSON, invalid paths, and executable preconditions rejected"
  - "Legacy Sub-to-Add preview reproduced the remaining_balance false transfer; v3 guidance abstained with unverified_task_intent and no procedure IDs"
remaining_unknowns:
  - "Exact planned archive symbolic-induction-engine-v2.4.0-codex-sis-v3-m0.zip and SHA-256 5ef4a01f63f3d9b95619f89f06769c955e9d1816ea97b0c90d12ecffca00244c remain unverified"
  - "GitHub CI was configured but not observed running; Windows and Python 3.10/3.13 were not tested locally"
  - "No real Codex SDK integration/run, isolated hostile-code execution, evaluator custody, signed receipt verification, external anchor, or efficacy experiment"
  - "The existing v2 sis_code_preview remains experimental and can still propose the known false transfer"
next_gate: "Verify the exact source archive identity and review M0 evidence before starting M1"
```

## Gate interpretation

The implementation and local tests are complete for the first two tickets, but
the overall M0 gate remains blocked on the planned archive identity. The pinned
Git source manifest and extracted Git baseline were independently checked in
this workspace; this does not substitute for verifying the absent ZIP hash.
No claim is made about live Codex capture, hostile-code containment, qualified
procedures, or improved coding-agent outcomes.

## SIS3-004 Codex adapter implementation slice

```yaml
phase_id: SIS3-004-adapter-slice
status: tested
base_revision: f001ade3110f6e5954488b72af228469569087c6
source_files_changed:
  - pyproject.toml
  - src/sis/v3/contracts.py
  - src/sis/v3/adapters/__init__.py
  - src/sis/v3/adapters/base.py
  - src/sis/v3/adapters/codex.py
  - tests/v3/test_codex_adapter.py
  - docs/v3/CODEX_ADAPTER.md
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/STATUS.md
tests_added: 8
commands_run:
  - "PYTHONPATH=src python3 -m unittest tests.v3.test_codex_adapter -v"
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 tools/check_source_manifest.py --baseline-ref daf0ccc"
  - "python3 -m compileall -q src/sis/v3/adapters tests/v3/test_codex_adapter.py"
  - "python3 -m pip install --dry-run '.[codex]'"
  - "python3 -m pip wheel --no-deps --no-build-isolation -w /tmp/sis-codex-adapter-wheel ."
  - "python3 -c 'import glob, zipfile; wheels=glob.glob(\"/tmp/sis-codex-adapter-wheel/*.whl\"); assert len(wheels)==1; names=set(zipfile.ZipFile(wheels[0]).namelist()); expected={\"sis/v3/adapters/__init__.py\", \"sis/v3/adapters/base.py\", \"sis/v3/adapters/codex.py\"}; assert expected <= names'"
  - >-
    PYTHONPATH=/Users/dawsonblock/Downloads/codex-main/sdk/python/src:src python3 -c 'import inspect, openai_codex; from sis.v3.adapters import AgentTurn, CodexAdapter; from openai_codex import Codex, ExternalMessage, Sandbox; assert "thread_start" in dir(Codex) and "thread_resume" in dir(Codex); assert "turn" in dir(openai_codex.Thread); assert "stream" in dir(openai_codex.TurnHandle) and "interrupt" in dir(openai_codex.TurnHandle); assert Sandbox.__members__["workspace_write"]; assert ExternalMessage.__init__; print("source_sdk_version=" + openai_codex.__version__); print(inspect.signature(openai_codex.Thread.turn)); print("public API surface check passed")'
observed_outcomes:
  - "Adapter tests passed: 8 tests; the full SIS suite passed: 371 tests, 1 skipped"
  - "CLI/HTTP smoke passed; this is local integration evidence only"
  - "Pinned pristine baseline: 138 source files verified; development delta reported separately"
  - "Optional dependency resolved to openai-codex 0.163.0 and openai-codex-cli-bin 0.163.0"
  - "Built wheel contains all three sis.v3.adapters package files"
  - "Built wheel SHA-256: 602b05952f70f7ed694c80510433f59d453728cd8035e0cff387d4ad5416a191"
  - "Provided SDK source imports as 0.0.0-dev and exposes typed thread, turn, interrupt, sandbox, and ExternalMessage APIs"
environment_and_dependency_versions:
  - "macOS 26.2"
  - "Python 3.12.0"
  - "Provided SDK checkout: openai-codex 0.0.0-dev; CLI binary requirement 0.153.4"
  - "Build extra: published openai-codex==0.163.0; dependency resolution dry-run only"
security_tests:
  - "SDK event summaries omit prompt/assistant text, command/output content, terminal input, diffs, and paths"
  - "Default Codex sandbox is read-only; adapter rejects full_access"
  - "External SIS content is passed through SDK ExternalMessage with tool-level provenance"
  - "The adapter has no direct command runner, evaluator-state writer, or signing API; Codex handles tool execution under its configured permissions"
remaining_unknowns:
  - "No authenticated live Codex task was run; wheel install and SDK runtime behavior remain unverified"
  - "The supplied Codex source directory has no Git revision; adapter targets its public API and pins the published SDK separately"
  - "Workspace-write is a Codex permission preset, not a validated OS isolation boundary"
  - "Commands are observed by event type and exit state; the adapter does not classify whether command text invoked tests"
  - "No durable event store, replay/recovery, source snapshot collector, independent verifier, or signed outcome receipt exists yet"
  - "M0's exact source archive and SHA-256 remain unavailable and unverified"
next_gate: "Run one controlled authenticated task in a disposable workspace, then implement durable event capture and exact workspace snapshot collection before claiming M1 complete"
```

## SIS3-003 / SIS3-005 / SIS3-006 report

```yaml
phase_id: SIS3-003+SIS3-005+SIS3-006
status: tested
base_revision: extracted archive tree (no .git; see manifest test skip note)
source_files_changed:
  - src/sis/v3/runner.py
  - src/sis/v3/episode_store.py
  - src/sis/v3/signatures.py
  - src/sis/v3/verifier.py
  - tests/v3/test_runner_isolation.py
  - tests/v3/test_episode_replay.py
  - tests/v3/test_receipt_signatures.py
  - tests/v3/test_verified_episode.py
  - tests/v3/test_source_manifest.py
  - docs/v3/STATUS.md
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/THREAT_MODEL.md
  - docs/v3/TRUST_BOUNDARIES.md
  - docs/v3/TEST_MATRIX.md
  - docs/v3/MIGRATION.md
tests_added: 48
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests/v3 -t . -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 -m compileall -q src/sis/v3 tests/v3"
observed_outcomes:
  - "Full suite: 419 tests, 0 failures, 2 skips (pre-existing skip + pinned-baseline probe absent .git)"
  - "v3 slice: 81 tests, 0 failures, 1 skip; no ResourceWarnings under -W error"
  - "CLI/HTTP smoke passed; local integration evidence only"
  - "RFC 8032 known-answer tests pass; vendored Ed25519 cross-verifies with cryptography 48.0.1 when installed"
  - "Executor: infinite loop wall-clock killed; 4 MiB stdout capped at 1 MiB with flag; 64 MiB write stopped at RLIMIT_FSIZE; aggregate disk budget audited; fork attempt bounded; host env not leaked; symlink escape flagged; terminate_all leaves no live workers"
  - "sandbox-exec seatbelt verified on this host: network connect denied (EPERM), writes outside workspace denied; executor reports network:seatbelt_denied vs network:not_enforced honestly"
  - "Episode store: chained replay, idempotent retry, conflict rejection, missing-artifact rejection, partial-tail crash recovery, mid-file tamper detection, head anchoring"
  - "Verifier: signed pass/fail receipts verify online and offline with public key only; tampered body, wrong key, unknown signer rejected; replayed nonce and duplicate evaluation rejected across restart; corrupt journal fails closed; agent/runner/learner/operator/forged roles denied evaluate"
  - "End-to-end vertical passed with a deterministic scripted agent on a real disposable workspace; NOT a live Codex run"
environment_and_dependency_versions:
  - "macOS 26.x (Darwin 25.2.0)"
  - "Python 3.12.0"
  - "cryptography 48.0.1 present in dev env (interop check only; not required at runtime)"
  - "sandbox-exec present at /usr/bin/sandbox-exec (deprecated Apple API; treated as experimental)"
security_tests:
  - "CommandSpec rejects argv traversal, oversize args/stdin/env, invalid cwd and env names"
  - "Receipts always carry isolation:unverified_local; network enforcement status is reported, not implied"
  - "OutcomeReceiptV1 signature is Ed25519 over canonical payload with domain sis-v3:outcome_receipt:1"
  - "Evaluation rejected for: unregistered_task, source_mismatch (incl. missing base_commit), replayed_nonce, duplicate_evaluation, missing submission, task_registration_conflict"
  - "Evaluator seed stored 0600 in a 0700 directory; public verification path needs only the exported public key"
remaining_unknowns:
  - "No live Codex/agent episode; M1 gate item 'actual coding task end-to-end' is demonstrated only with a scripted fixture agent"
  - "local-subprocess executor is not a validated sandbox even with seatbelt; no Linux rootless or microVM backend exists"
  - "RLIMIT_NPROC counts the real UID's processes on POSIX; low values can make forking commands fail early"
  - "ru_maxrss is a cumulative high-water mark, not a per-exec delta"
  - "Vendored pure-Python Ed25519 is not constant-time; production should substitute a vetted provider behind the same API"
  - "Append-only store is code discipline over a writable filesystem, not WORM; anchor_head exports heads but no external attestation service exists"
  - "Verifier shares the caller's OS process in tests; separate evaluator service/process custody is specified but not deployed"
  - "No promotion controller, qualified catalog, or benchmark harness; no efficacy claim"
next_gate: "Run one authenticated Codex task in a disposable workspace through this pipeline, then gate M1 on real adapter capture + independent receipt"
```

## SIS3-004 (CLI) + SIS3-007–012 report

```yaml
phase_id: SIS3-004-cli+007-012
status: tested (live contact achieved; passing live episode blocked by quota)
source_files_changed:
  - src/sis/v3/adapters/codex_cli.py
  - src/sis/v3/procedures.py
  - src/sis/v3/patcher.py
  - src/sis/v3/retrieval.py
  - src/sis/v3/guidance.py
  - src/sis/v3/promotion.py
  - src/sis/v3/rollback.py
  - src/sis/v3/audit.py
  - src/sis/v3/benchmark.py
  - src/sis/v3/verifier.py  # persists full receipts; load_receipt accessor
  - src/sis/v3/schemas/*.json  # 9 golden canonical examples
  - scripts/v3/run_codex_episode.py
  - examples/v3/fixtures/buggy_calc/*
  - docs/v3/episodes/live-001/*
  - tests/v3/test_codex_cli_adapter.py
  - tests/v3/test_procedures.py
  - tests/v3/test_patcher.py
  - tests/v3/test_retrieval.py
  - tests/v3/test_promotion.py
  - tests/v3/test_audit.py
  - tests/v3/test_benchmark.py
  - tests/v3/test_schemas.py
tests_added: 60
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 scripts/v3/run_codex_episode.py --work-root /tmp/sis-live-ws --evidence-root /tmp/sis-live-evidence"
  - "codex exec --json --ephemeral -s workspace-write -C /tmp/codex-dbg (direct capability probe)"
observed_outcomes:
  - "Full suite: 479 tests, 0 failures, 2 skips; no ResourceWarnings under -W error"
  - "LIVE CODEX CONTACT: codex-cli 0.156.1 (ChatGPT auth) reached the backend inside a disposable fixture workspace; turn failed with account usage-limit error; episode.jsonl (5 chained events), anchor, journal, and public key preserved in docs/v3/episodes/live-001/"
  - "Evaluator correctly signed outcome=fail on the still-buggy tree; offline public-key signature verification passed at run time"
  - "A passing live episode remains blocked: ChatGPT Codex quota exhausted, resets ~8:36 PM; codex-mini-latest not supported on this account"
  - "ProcedureStore: digest-keyed append-only catalog, revision conflicts, chain/tamper detection, persistence across reopen"
  - "Miner: deterministic candidates from verified episodes only; learner role required; pass→candidate, fail→counterexample-bearing candidate"
  - "Patcher: unique-span byte replacement preserves CRLF/Unicode/comments; nonunique/missing/identity/path-escape rejected; proposals are artifacts, not writes"
  - "Retrieval: every precondition kind gated; contraindication→prior_negative_transfer; only qualified records surface; deterministic ranking"
  - "Guidance: recommend path returns procedures+evidence+matched gates; abstains on unverified intent, empty catalog, or all-gates-failed incl. the remaining_balance fixture (prior_negative_transfer)"
  - "Promotion: full lifecycle draft→…→qualified; illegal edges, wrong token, agent role, missing receipts, missing/invalid evaluator signature all rejected; decision log hash-chained, restart-safe, tamper-detecting; checkpoint/restore suspends post-checkpoint qualifications"
  - "Audit: AnchorChain records verified heads; reports grew_after_anchor vs corrupt vs missing"
  - "Benchmark: paired A/B/C/D arms in fresh workspaces, identical-tree receipt reuse, independent scoring, paired wins/losses/ties report"
environment_and_dependency_versions:
  - "macOS 26.x; Python 3.12.0; codex-cli 0.156.1; ChatGPT plan (no API key)"
security_tests:
  - "CLI adapter emits bounded summaries only (no command/output text); scrubbed env; wall-clock process-group kill; cancel; danger-full-access not offered"
  - "Promotion decisions require operator role+token AND evaluator Ed25519 signature for evidence-bearing transitions"
  - "Replayed operator token alone cannot qualify: evaluator signature is independently verified"
remaining_unknowns:
  - "No PASSING live Codex episode — quota-limited; the M1 gate item 'one actual coding task completes end-to-end' is demonstrated for failure capture, not task success"
  - "Promotion operator token is a shared-secret digest gate (research build), not per-principal auth"
  - "Benchmark token/tool budgets are declared caps enforced by the agent runtime; the harness enforces wall-clock only"
  - "Miner is deterministic and records observed evidence; no LLM candidate generation yet"
next_gate: "When quota resets, run scripts/v3/run_codex_episode.py for a passing live episode; then pilot qualification + the four-arm benchmark on scripted tasks before any efficacy language"
```

## Repair pass (post-012)

```yaml
phase_id: repairs-1
status: tested
source_files_changed:
  - src/sis/v3/signatures.py  # cryptography preferred, vendored fallback
  - src/sis/v3/promotion.py   # per-principal operator Ed25519 auth
  - src/sis/v3/evaluator_worker.py  # evaluator signing in a child process
  - src/sis/v3/benchmark.py   # wall-clock budget violation flags
  - tests/v3/test_receipt_signatures.py
  - tests/v3/test_promotion.py
  - tests/v3/test_benchmark.py
  - tests/v3/test_evaluator_worker.py
tests_added: 9
observed_outcomes:
  - "Full suite: 488 tests, 0 failures, 2 skips"
  - "signatures.backend() == 'cryptography' here (constant-time); vendored path byte-identical and still tested"
  - "Promotion accepts operator Ed25519 signatures; wrong key / missing credentials rejected; shared token remains as fallback"
  - "evaluate_via_subprocess: seed loads only inside the child process; signed receipt verifies offline; unregistered task rejected with exit 2"
  - "Benchmark arms now flag wall_seconds > budget.wall_seconds as budget_exceeded and count them in the report"
remaining_unknowns:
  - "Subprocess custody shares one OS principal — a true split needs a separate service account/host"
  - "Passing live Codex episode still pending quota reset"
```

## Live episode 002 — passing Codex task (M1 gate item met)

```yaml
phase_id: live-episode-002
status: verified
observed_outcomes:
  - "codex exec --json (codex-cli 0.156.1) ran the buggy_calc fixture after the 8:36 PM quota reset: 16 chained events including a failed command (exit 128), one file_change edit (percentage fix), a verification command (exit 0), turn.completed with real token usage"
  - "Independent evaluator injected hidden acceptance tests into a fresh workspace and signed outcome=pass; offline public-key verification passed"
  - "Evidence preserved under docs/v3/episodes/live-002/ including the full signed OutcomeReceiptV1"
remaining_unknowns:
  - "One solved task is pipeline proof, not lift; no cross-task retrieval or efficacy evidence exists"
next_gate: "Mine a candidate from this episode, qualify it via promotion on disjoint fixtures, then a scripted four-arm pilot"
```

## v3.1 roadmap slice — release integrity, projection, envelopes, semantic gates, catalog scopes, guidance phases, benchmark stats

```yaml
phase_id: v31-roadmap-slice-1
tickets: [SIS3-101, SIS3-102, SIS3-122, SIS3-131, SIS3-141, SIS3-150(partial), SIS3-161, SIS3-170/171(partial)]
status: implemented_and_tested
changed_files:
  - tools/build_release.py           # NEW: RELEASE_SHA256.json generation + drift check
  - tools/verify_release.py          # ZIP-native verify() restored + RELEASE manifest + verify_tree + build_zip + compile
  - tools/check_source_manifest.py   # both manifest names excluded from source inventory
  - src/sis/registry.py              # close() + context manager
  - src/sis/family_eval.py           # close() + context manager
  - src/sis/skill_holdout.py         # close() + context manager
  - src/sis/v3/episode_projection.py # NEW: deterministic projection + agent_view redaction
  - src/sis/v3/outcome_v2.py         # NEW: OutcomeEnvelopeV2 issue/verify, key registry, revocation, nonce replay, expiry
  - src/sis/v3/semantic_checks.py    # NEW: AST operator-class diff + metamorphic violation flags
  - src/sis/v3/counterexamples.py    # NEW: cross-catalog negative-evidence index
  - src/sis/v3/catalog.py            # NEW: namespace scopes + cascade_suspend
  - src/sis/v3/guidance_gateway.py   # NEW: shadow/diagnostic/conditional phases + kill switch + acceptance log
  - src/sis/v3/retrieval.py          # AblationFlags (benchmark-only gate removal)
  - src/sis/v3/benchmark.py          # wilson_ci + mcnemar_p + per-arm solve-rate CIs in report
  - src/sis/v3/contracts.py          # OutcomeEnvelopeV2 record (V1 serialization untouched)
  - tests/v3/test_release_artifact.py
  - tests/v3/test_roadmap_modules.py
tests_added: 40
observed_outcomes:
  - "Full suite: 526 tests, 0 failures, 2 skips, run under -W error with zero warnings"
  - "RELEASE_SHA256.json covers 220 files; build_zip + ZIP-native verify() round-trips; verify_tree on fresh extraction + --compile passes"
  - "ZIP verifier rejects: missing manifest, extra/missing/tampered member, duplicate paths, symlinks, unsafe paths, oversized members — streaming, never extracts"
  - "OutcomeEnvelopeV2 verifies offline; forgery, tampered payload, unknown/revoked/wrong-purpose keys, nonce replay, expiry, and validity windows all fail closed"
  - "semantic_checks flags Sub->Add noncommutative->commutative swaps (remaining_balance class); commutative->commutative passes"
  - "GuidanceGateway: shadow abstains but logs would_recommend; diagnostic reports reasons without procedure IDs; conditional serves; kill switch via file and SIS3_DISABLE env"
  - "Cascade suspension converts a revoked evidence digest into governed suspension decisions on dependent qualified records"
remaining_unknowns:
  - "Cross-repository scope promotion has no repository-disjoint evidence requirement enforced in code yet — scope is metadata, gate is procedural"
  - "OutcomeEnvelopeV2 is defined and tested but not yet wired into the benchmark/evaluator issuance path"
  - "mcnemar/wilson are correct statistics but zero real held-out tasks have been run; M5 efficacy gate untouched"
  - "SQLite close() exists everywhere; WAL databases still leave -wal/-shm files by design until final checkpoint"
next_gate: "Wire envelope issuance into verifier path; enforce cross-repo evidence count in promotion; pre-register held-out suite"
```

## SIS-311/312/313 — receipt authority, transactional ledger, fail-closed retrieval

```yaml
phase_id: v31-integrity-closure-1
tickets: [SIS-311, SIS-312, SIS-313]
status: implemented_and_tested
changed_files:
  - src/sis/v3/verifier.py      # verify_and_resolve_receipt + ExpectedProtocol protocol binding
  - src/sis/v3/promotion.py     # PromotionDecisionV2 (post-state inside signed body), stale-head
                              # optimistic concurrency, crash-tail recovery, full V2 replay verify,
                              # projected_statuses, qualified_projection_drift
  - src/sis/v3/procedures.py    # add() rejects status=qualified without allow_qualified
  - src/sis/v3/contracts.py     # PromotionDecisionV2 record; expired/revoked/stale_evidence/
                              # unsupported_context reason codes
  - src/sis/v3/retrieval.py     # expires_at enforcement (malformed -> expired), revoked digest
                              # denylist, now injection
  - src/sis/v3/guidance.py      # revoked/now pass-through, policy reasons updated
  - tests/v3/test_promotion.py  # +8 receipt-authority + 6 ledger/projection tests
  - tests/v3/test_retrieval.py  # +5 expiry/revocation tests
tests_added: 14
observed_outcomes:
  - "Full suite: 546 tests, 0 failures, 2 skips under -W error"
  - "signed-FAIL->tampered-PASS -> receipt_digest_mismatch, head unchanged; substituted receipt, forged signature, untrusted/revoked signer, protocol mismatch, malformed/unresolvable receipts all rejected with stable reason codes"
  - "suspended->qualified requalification requires fresh verified receipts + evaluator signature"
  - "direct store.add(status=qualified) rejected; only allow_qualified fixtures/controller mint qualified state"
  - "V2 decisions sign the complete post-state (new_record_digest + new_qualified_head) BEFORE either signature; verify() replays chain + evaluator/operator signatures + transition legality + head continuity; torn trailing writes truncated on restart"
  - "expected_old_head optimistic-concurrency guard rejects stale views"
  - "expired/malformed-expiry/revoked-digest procedures abstain with stable reason codes; malformed expires_at rejected at contract parse"
remaining_unknowns:
  - "V1 decisions verify for chain/digest only (pre-state not inside their signed body) — flagged legacy_v1 in verify()"
  - "Qualified-catalog materialized projection exists (projected_statuses) but retrieval still reads record.status directly — full projection-only retrieval is the next hardening step"
  - "min_pass_receipts/min_distinct_repos are policy knobs; recommended pilot defaults (>=3 tasks, >=2 repos) are documented, not yet enforced as defaults"
next_gate: "SIS-314 release attestation; then v3.2 governed artifact channel + typed AST repair procedures"
```

## Codex master execution plan — v3.1.0 through v4.0.0 (this branch)

| Milestone | Commit | Verdict |
|---|---|---|
| Phase 0 baseline audit | (docs in 5cffa35) | defects B–I reproduced against b0fb6c4; A already closed |
| v3.1.0 release integrity | 5cffa35 | GO — deterministic ZIP, strict manifest/attestation verify, adversarial ZIP tests |
| v3.1.1 authoritative qualification + atomic promotion | e0b49e8 | GO — governed status only via signed decisions; intent journal; EligibilitySnapshot sole serving authority |
| v3.1.2 benchmark truthfulness | e4f0808 | GO — valid-solve = independent pass; hard budgets; seeded arm order; paired stats |
| v3.2.0 unified policy-gated eligibility | 4ee6fd2 | GO — snapshot-only serving; signed ScopeGrantV1; wrong-repo abstention; kill switch intact |
| v3.2.1 transactional verify_and_consume + semantic-check closure | 61f05c4 | GO — one-time envelope consumption, restart-surviving replay guard; operator-class heuristics no longer waive semantic checks |
| v3.3.0 live Codex adapter qualification | 38efcf5 | PASSED — real SDK 0.163.0, 4/4 live tests (start/stream/lineage/resume/interrupt/ExternalMessage) |
| v3.4.0 typed symbolic repair induction | 99ffda3 | GO — RepairHypothesisV1 AST templates + typed metavariables; A→B→C disjoint-repo transfer; counterexample contract failure → abstain |
| v4.0.0 held-out efficacy qualification | 9a146b8 | NO-GO on statistical power (honest): live Codex experiment, D vs A = 1 win / 0 losses / 2 ties on n=3 held-out tasks; no in-scope harm; negative-transfer risk confirmed on control (agent corrupts correct code under fix-pressure in both arms — contract+abstention gates are the mitigation) |

Release artifact: `dist/sis-v3-release.zip` — 229 files, deterministic
(byte-identical rebuilds), verified by `tools/verify_release.py`,
attested in `dist/attestation.json`
(zip_sha256 `7cfbfcae3c24c49039fb6c4c7dfd8fe0e9a0197fc182d3303ed59508c7e9ce15`,
git `9a146b8`). Suite: 600 passed, 6 skipped.
