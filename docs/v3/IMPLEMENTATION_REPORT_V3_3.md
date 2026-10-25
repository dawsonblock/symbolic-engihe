# SIS v3.3 Implementation Report

Ledger of the governed-learning build, milestone by milestone, on branch
`codex/sis-v3.2-authority-integrity` (baseline commit `07a9174`).

## M0 — Baseline integrity: PASS

- The four manifest discrepancies (verifier.py, live_study.py,
  test_receipt_signatures.py, unlisted V32_GAP_MAP.md) all map to pushed
  review-fix commit `07a9174` — legitimate recorded changes, not
  unauthorized edits. Baseline = `07a9174` + this work.
- Artifacts: `docs/audits/BASELINE_INTEGRITY.md`,
  `evidence/baseline/{source_inventory,integrity_findings,baseline_tests}.json`.

## M1 — Authority/evidence hardening: PASS (verified, mostly pre-existing)

- WAL + BEGIN IMMEDIATE + append-only audit already present in
  `AuthorityDB`; `CandidateRegistry`/`MemoryStore` built to the same
  pattern.
- Evidence handles: qualification requires bound receipt digests;
  `verified` flags never cross a trust boundary.
- Trust domains: policy roles agent/runner/learner/evaluator/operator
  gate every mutation; learners and optimizers hold no signing material.

## M2 — Experience memory: PASS

- `contracts.py`: `ExperienceRecordV1` (digest-referenced trace/receipt,
  facts vs hypotheses separated).
- `memory.py`: `MemoryStore` (dedup/replay rejection, tamper-proof
  reads), `induce_candidate`, `retrieve_memories` (applicability +
  counterexample gates, budget, abstention). JSON-only ingest.

## M3 — Candidate registry: PASS

- `contracts.py`: `CandidateV1` for six types (symbolic_procedure,
  diagnostic_strategy, experience_memory, skill_instruction,
  skill_bundle, prompt_variant); domain-separated `content_digest` binds
  payload.
- `candidates.py`: role-gated transactional state machine
  PROPOSED→VALIDATED→EVALUATING→{REJECTED,INCONCLUSIVE,QUALIFIED}→REVOKED;
  operator-only qualification with mandatory receipts; append-only audit.

## M4 — Skill evolution: PASS

- `evolution.py`: pure-payload mutators (no command construction),
  injected `EvaluationClient`, hard `EvolutionBudget`, digest-deduped
  `Frontier`. Optimizer output is PROPOSED intake only.

## M5 — Composition + track unification: PASS

- `composition.py`: precedence by type, dedup, polarity-conflict
  detection, `precedence`/`abstain` policies, token/step budgets.
  Procedures, skills, memories, prompt variants merge through one choke
  point — never concatenated into a system prompt.

## M6 — Governed evaluation plane: PASS (machinery)

- `governed_eval.py`: `EvaluationPartition` + sealed-holdout check,
  `preregister` (float-safe protocol digest), `required_sample_size`,
  `compute_metrics` (abstention + negative transfer measured via
  `served_map`), `run_governed_evaluation` with 5 arms.
- `benchmark.py`: opt-in arm `E`; `report_digest` normalizes floats
  deterministically.

## M7 — Governed serving: PASS

- `serving.py`: `GovernedServingGateway` — signed-registry repo
  resolution, per-candidate rejection audit (`out_of_scope`,
  `inapplicable`, `counterexample`, `revoked`), advisory-only delivery.
  Candidate-only advice serves under an honest abstain decision.

## M8 — vskill packaging: PASS

- `skill_package.py`: manifest + payload + SHA256SUMS;
  `verify_install` fails closed on any mismatch; `import_bundle`
  registers at PROPOSED — the manifest's qualification claim is ignored.

## M9 — Deterministic campaign: PASS

- `tools/governed_campaign.py`: fixtures → verified baseline episodes →
  memory induction → skill evolution → dev selection → sealed-holdout
  paired eval (arms A–E) → operator qualification bound to real receipts
  → governed serving → revocation demo → skill bundle export +
  `campaign_evidence.json`.
- Deterministic result: A=0, B=2, C=2, D=0, E=2 on two unseen-repo
  holdouts — memory and skills transfer convention knowledge; the
  signature-bound procedure correctly abstains (negative control).
  Machinery evidence only — NOT live efficacy.
- Failure-injection coverage in tests: forged roles, tampered rows,
  replayed episodes, illegal transitions, missing receipts, bundle
  tamper, prompt-injection-as-data, revocation mid-serving, partition
  overlap, out-of-scope/unknown-repo serving.

## M10 — Release qualification: IMPLEMENTED_NOT_EFFICACY_QUALIFIED

- Suite: **709 passed, 2 skipped** (`PYTHONPATH=src pytest tests/`).
- Docs: ARCHITECTURE_V3_3, SECURITY_BOUNDARIES_V3_3, MEMORY_DESIGN,
  EVOLUTION_DESIGN, EVALUATION_PROTOCOL_V3_3, V33_LIMITATIONS, this
  report.
- Release artifacts under `release/` with manifest + source inventory.
- Efficacy requires a live-model campaign on a powered sample; the
  deterministic run proves machinery, not effect size.

## Defects found and fixed during the build

| defect | fix |
|---|---|
| `preregister` crashed on float alpha/min_effect (canonical_json rejects floats) | digest a normalized copy; raw values retained in doc |
| `report_digest` crashed on float metrics | same normalization |
| campaign: strict partition rule blocked dev reuse | disjointness relaxed to seal holdout/monitoring while allowing induction↔development overlap (documented) |
| campaign: double `verifier.evaluate` on identical trees → `duplicate_evaluation` | reuse harness-issued receipts via `load_receipt` |
| campaign: raw step concat starved real steps behind an 8-item cap | merge via `compose_guidance` |
| campaign: buggy `clamp` fixture passed its own test; `dedup`/`clamp` holdouts untransferable by design | holdouts redesigned as unseen-repo variants `money2`/`slug2` of the dev conventions |
| campaign: `scripted_agent` wrote `<task>.py` not the fixture's module | write the declared module name |
