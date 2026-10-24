## v2.4.0 — Bounded coding-agent repair recipes (2026-10-21)

- Added pure Python AST operator-swap capture, with no arbitrary Python source execution.
- Replays every labeled input through a restricted bounded expression interpreter before promotion.
- Generalizes successful repair operators across independently supplied Python function names.
- Adds separated source-program holdouts, duplicate/overlap checks, independent promotion recomputation.
- Adds SQLite code recipe catalog, local hash-linked audit, retirement and conflict protection.
- Exposes read-only code previews through model ToolBridge; operator-only study and retirement through CLI/HTTP.
- Ships functional demo, adversarial tests, detailed security/limitations guide; v1.0–v2.3 retained.
- Does not implement sandboxed Python unit-test execution, generalized code synthesis, or real LLM qualification.

## v2.3.0 — Controlled tabular workflow learning (2026-10-21)

- Added observed-tool `WorkflowSession` with deterministic filter/aggregation operations over bounded typed records.
- Added replay and SHA-256-linked execution events. Full capture control remains an untrusted authority boundary.
- Added exact semantic canonicalization for reordered and duplicate independent filters. Does not claim unrestricted equivalence of algorithms.
- Added independent SQLite `WorkflowCatalog`, operator-gated promotions, local audit verification, retirement, and fail-closed inference.
- Added read-only LLM tool definition, CLI commands, and local HTTP routes with separated operator authorization.
- Added adversarial tests and demonstration. Existing symbolic skill, LoRA, and holdout workflows remain included unchanged.
- No independent external-task evaluation, unrestricted agent execution, or real-model training claim.

## 2.2.0 — Instrumented Experience Abstraction

- Capture actual allowlisted deterministic tool executions through `InstrumentedSession`, preserving explicit input, previous-result, and literal provenance; reject ambiguous value-only binding.
- Replay captures through the unchanged bounded SIS interpreter; verify each resolved operand, step result, strict JSON type, local event hash link, and final answer.
- Cluster verified successful training captures by their generalized data-flow AST, reject incompatible programs and duplicate/overlapping train-validation inputs; convert erroneous executions into corrected training examples only with independent correction labels.
- Submit reconstructed candidates to the existing v2.1 governed `trace_study` and `SkillCatalog` promotion sequence; model tool bridge remains read-only.
- Add CLI `experience-capture` and `experience-induce`, documented Python instrumentation API, complete runnable synthetic example fixtures, and 32 focused tests.
- Explicit non-goals: no arbitrary tool execution, raw-chat understanding, privileged external attestation, automatic LoRA execution, or independent intelligence improvements.

## v2.1.0 — Typed execution-trace induction (2026-10-21)

- Added `sis.trace_learning`: bounded declarative step programs, typed intermediate replay, and train-only proposal extraction.
- Added operator-side `Service.trace_study` and `sis trace-study` CLI, preserving the existing verification and promotion gate.
- Rejected forged intermediate values, future-variable references, invalid ASTs, type confusion, validation-derived traces and injected proposals.
- Added integration tests, sample multi-step traces, documentation, and clean source manifest packaging.
- Real task-family generalization, independent evaluator custody, and GPU finetuning are **not** established.

## v2.0.0 — Evaluator-controlled task-family comparison

- Added `sis.family_eval`: signed evaluation precommitments, explicit family
  and input collision checks, a one-use SQLite experiment vault, 3/4-arm
  paired live comparison, Holm-corrected item and family-level sign-test p-values, within-family accuracy,
  and frozen qualification-policy scoring. No mutating tool exposure.
- Added `sis family-eval-seal` and `sis family-eval-run` with opt-in networking,
  protected evaluator secret, pinned claimed model IDs and non-overwriting
  results; added `sis family-eval-verify` for signed report authenticity.
- Added synthetic, offline four-arm demonstration, adversarial tests, and
  detailed data-custody / inference limitations.
- Retained all v1.9 neural training, procedural skill, induction, and audit
  subsystems. **No real LLM fine-tuning or benchmark lift measured in this release.**

## v1.9.0 — Opt-in LoRA training and three/four-arm evaluation

- Implemented training export authenticity checks and a dependency-optional, actual PEFT/Transformers LoRA training runner with completion-only LM labels.
- Added strict config/data checks, opt-in execution, offline loading default, never-overwrite adapters and source-bound training receipt.
- Added frozen-bundle neural comparison: base LLM, base LLM with skill result, adapted LLM, optional placebo prompt, paired aggregate metrics.
- Added v1.9 fixtures, new security and experimental-design guide, and regression tests.
- Does not claim trained neural weights or independent real-LLM results; this source release tests validation, masking and orchestration using mocks.

# v1.8.0 — Frozen procedural evaluation and controlled pseudo-labels

- Hash-bound `skill-freeze` artifacts include independently checked active skill dependency closure and audit head.
- Precommitted two-split procedural-skill holdouts under evaluator-owned SQLite vault/HMAC, one-use scoring, signed aggregate receipts, strict replay and crash-safe receipt recovery.
- Sample-size, coverage, accuracy and 95% Wilson lower-bound qualification policy per split, declared exclusion records and duplicate prevention.
- Qualified skill-to-LLM JSONL *pseudo-label* export with custodian-side private-overlap rejection and signed output hash manifest; **no neural weight training**.
- Regression tests for forgery, modification, reuse, concurrent claims, distribution shift, archive/CLI integration, and failure paths.
- Honest evidence boundaries: local software verification only; independent holdout ownership is required for credible generalization claims.

# v1.7.0 — Governed bounded procedural skills

- Added strict interpreted JSON program AST: conditionals, lexical bindings, bounded list reductions and skill composition with active dependency checks.
- Added deterministic skill discovery and operator proposals, requiring disjoint caller-provided validation, ambiguity checks, and independent recomputation before promotion.
- Added separate hash-linked skill catalog with semantic transition replay, fail-closed prediction, negative-feedback suspension, and retirement.
- Added conservative episode-to-study adapter that requires external corrected outputs for failed episodes; trace strings are metadata only.
- Added skill CLI, HTTP endpoints, read-only LLM tool bridge and basic caller-controlled benchmarking.
- Preserved v1.6 rule engine, evaluator, paired LLM tests, and existing database schema; skill chain has no external anchor and is not independently qualified.

# v1.6.0 — Paired LLM evaluation (2026-10-20)

- Same-model, read-only baseline vs SIS-augmented benchmark with counterbalanced arm order.
- No reference labels included in LLM request content; fail-closed registry audit and drift checks.
- Strict typed JSON answer/abstention decoding; provider failures invalidate runs.
- Exact McNemar comparison, paired contingency table, Wilson descriptive intervals, coverage, latency, and optional provider-reported token usage.
- Two-step network opt-in CLI; refuses overwriting benchmark result artifacts.
- Added local tests, synthetic fixtures, and explicit limitations of local experiment evidence.
- No changes to prior SQLite storage schema, evidence claims, or promotion authority.

# Changelog

## 1.5.0 — October 20, 2026

- Add explicit, one-to-one schema-map transfer of active source rules with strict type/list constraints; no automatic assertion of cross-domain validity.
- Extend read-only Service, CLI, HTTP, and agent tool-bridge entrypoints for one-record and bounded batch transfer.
- Precommit a typed evaluation qualification policy into the authenticated public study at sealing time.
- Add post-score evaluator-signed qualification and replay verification, separate from source rule promotion.
- Require meaningful holdout sample counts, overall accuracy/coverage, shifted-test performance, descriptive baseline margin, and 95% Wilson lower-bound screening.
- Preserve v1.4 sealed evaluation compatibility but refuse retroactive qualification of uncommitted legacy test policies.
- Add dedicated local integration and adversarial tests; explicitly deny that synthetic datasets or signed local policy passes establish independent effectiveness.


## 1.4.0 — October 20, 2026

- Introduce a separate evaluator-side, HMAC-authenticated one-use holdout vault, isolated from model-facing public train/validation data.
- Bind submissions to a signed public task and evaluate only locally admissible AST candidates.
- Provide test and shifted-regime aggregate metrics without revealing holdout examples or labels to the candidate process.
- Reject repeated or overlapping samples across all tasks in a single vault, including concurrent duplicate scoring attempts.
- Add signed scoring receipts and evaluator-side replay verification against private test data.
- Add 27 unit/integration checks, CLI subcommands, documentation and a synthetic example generator.
- Clarify that single-vault anti-reuse and HMAC receipts do not establish independent test custody or prevent whole-vault rollback.

## 1.3.0 — October 20, 2026

- Harden event replay with semantic transition validation, immutable field checks,
  typed/counter validation, and rule-ID integrity checks.
- Add an admission firewall rejecting bounded witnesses of disagreement against
  existing active rules in the same namespace and schema.
- Add separate HTTP operator secret for mutating/trusted routes. Prediction-only
  keys cannot promote rules, send feedback, or invoke operator LLM chat.
- Fail closed when listing rules with invalid audit; reject output-type mismatches
  before feedback can suspend a rule.
- Enforce strict type equivalence for candidate fitting and benchmark scoring
  (Python `True == 1` must never count as a valid typed match).
- Add adversarial regression tests and authenticated operator integration tests.

## 1.2.0 — October 20, 2026

- Require a full independent registry re-induction from supplied examples and search options before promotion (fixes the forged-result Python boundary).
- Add opt-in, operator-held audit checkpoints with SHA-256 or HMAC-SHA256 integrity for validating a DB audit prefix across appends.
- Add bounded batch prediction to CLI, Python service, and HTTP API.
- Refuse LLM HTTP redirects to reduce bearer-token and training-data exfiltration risk.
- Add new regression suite and release documentation.

## v1.1.0 — 2026-10-20

- Implemented deterministic, bounded active query selection from multiple training-consistent rules. Questions are explicitly **unlabeled** and never automatically promoted.
- Added disjoint train/validation/test benchmark with coverage, selective accuracy, overall accuracy, and a train-majority baseline. Caller's test set is not transmitted to induction.
- Added complete rule projections to the SQLite hash-linked events. The verifier now compares replayed latest projections against each stored rule and predictions fail closed if inconsistent.
- Added rule retirement with an append-only event and explicit no-reactivation policy.
- Added portable LLM tool definitions and a narrowly allowlisted Python `ToolBridge` that exposes only prediction and query proposal.
- Extended local HTTP API, CLI, example fixtures, verification instructions and tests.
- Maintained the no-exec, bounded-AST, opt-in external-LLM baseline.
- Legacy v1.0 database events are detected as unverifiable rather than silently upgraded; see `docs/UPGRADE_V1_1.md`.

## v1.0.0 — 2026-10-20

- Initial installable Python symbolic-induction research prototype.
- Implemented bounded AST synthesis and hypothesis counterexample probing.
- Implemented optional Z3 disagreement search, opt-in LLM proposals, SQLite registry and local HTTP/CLI APIs.
- Provided local synthetic tests and a deterministic ZIP source manifest.
