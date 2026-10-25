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

- Suite: **737 passed, 2 skipped** (`PYTHONPATH=src pytest tests/`).
- Docs: ARCHITECTURE_V3_3, SECURITY_BOUNDARIES_V3_3, MEMORY_DESIGN,
  EVOLUTION_DESIGN, EVALUATION_PROTOCOL_V3_3, V33_LIMITATIONS, this
  report.
- Release artifacts under `release/` with manifest + source inventory.
- Efficacy requires a live-model campaign on a powered sample; the
  deterministic run proves machinery, not effect size.

### Post-build release verification (repair pass)

- The first shipped archive failed `tools/verify_release.py` twice:
  flat layout (no single project directory) and an embedded manifest
  that did not match the archive contents. Rebuilt with
  `verify_release.build_zip`: single project dir, 297 covered files,
  `verify()` + fresh-extraction `verify_tree` + `compileall` +
  extracted-test smoke all pass (`release/verification.json`).
- `RELEASE_SHA256.json` regenerated for the v3.3 tree; the prior file
  was a stale v2-era manifest. `release/` provenance is intentionally
  out-of-band: an archive cannot contain its own checksum.
- All six `evidence/` directories populated: baseline, integration
  (campaign + exported skill bundle), security (13/13 failure-injection
  scenarios green), benchmark, qualification, release.
- Archive content verified identical to commit `62588bb` for every
  manifest-covered file.

### Completion pass 2 (metrics closure + live study)

- `benchmark.py`: added the missing `B_vs_A` paired contrast — every
  arm now has a vs-baseline paired outcome (previously B was the only
  arm without one).
- `governed_eval.compute_metrics`: added literal spec metric keys
  `paired_win_rate`, `paired_loss_rate` (vs arm A, same valid-solve
  rule) and `mean_cost_per_verified_solve` (`None` — cost is unmetered,
  never fabricated). Suite: 710 passed, 2 skipped.

### Completion pass 3 (release binding + qualification authority)

- **Release archive was stale and could self-embed.** `dee2c4b`
  inventoried `release/` into `RELEASE_SHA256.json` without rebuilding
  the ZIP, so the shipped archive still contained pre-hardening code.
  Worse, the next build would embed the previous ZIP (and its stale
  checksum) inside itself, and `verify()` would still pass because the
  archive matched its own embedded manifest. `release/` is now
  out-of-band: excluded from the inventory, rejected as an archive
  member, and `build_canonical_zip` re-hashes every member against the
  source tree (`verify_against_tree`), records the Git commit, and
  refuses a dirty tree. New tests cover embedding, stale archives,
  dirty builds, and source binding.
- **Qualification accepted unauthenticated digests.**
  `CandidateRegistry.qualify` checked only that `receipt_refs` were
  64-hex strings. It now requires a deployment-supplied
  `receipt_authority`; every digest must resolve to a
  signature-authenticated receipt with outcome `pass`. Wiring this in
  exposed a latent campaign bug: qualification drew from a dict seeded
  with synthetic authority-demo receipts, so a random digest sort could
  cite a receipt the verifier never issued (flaky ~80%). Holdout
  evidence is now separate, and no verified pass receipt means no
  qualification.
- **Regression metric was mislabeled.** `verified_regression_rate` was
  the absolute failure rate, so baseline A reported 0.5 regressions
  against itself. It is now the fraction of baseline-verified solves an
  arm loses; `failure_rate` keeps the absolute number.
- **Memory and serving evidence binding.** `MemoryStore.ingest` takes an
  `evidence_check` hook wired to `verify_experience_evidence`
  (journal resolution + signature + outcome match); serving audit rows
  carry `task_id`, and `record_outcome` binds a receipt digest/outcome
  to the exact served guidance digest.
- Suite: **737 passed, 2 skipped**. Deterministic campaign unchanged
  (A=0/B=2/C=2/D=0/E=2); live governed campaign re-run at this tree:
  all arms 2/2 (ceiling), authentic lifecycle.
- `tools/smoke_integration.py` run locally on macOS: CLI + authed
  loopback HTTP smoke passes (401/403/200 status boundaries).
- `tools/live_study.py` executed against authenticated `codex exec`
  (ChatGPT login): 6 held-out tasks × arms A–D. Real result:
  A=4, B=3, C=3, **D=5** — served procedures were the best arm and
  D-vs-A is 1W/0L, but p=1.0: positive direction, underpowered,
  gate not met (`evidence/benchmark/live_study_v33.json`).
- `tools/governed_live_campaign.py` (new) ran the complete v3.3
  lifecycle with real `codex exec`: baseline dev episodes (A=2/2),
  induction, evolution, 5-arm sealed holdout. Result: **all arms
  2/2** — codex hit the fixture ceiling unaided, null efficacy
  contrast, but the full governed loop (episodes → receipts →
  qualification → serving → revocation) executed authentically with
  a real agent (`evidence/benchmark/live-campaign/`).

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
