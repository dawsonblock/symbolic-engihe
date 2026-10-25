# SIS v3.3.0 — Governed Learning — Release Notes

Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**

Security/correctness gates pass; learning efficacy on real models is
deliberately not claimed. See `V33_LIMITATIONS.md`.

## What is new

- **Typed candidate plane** — `CandidateV1` (six artifact types) plus
  `CandidateRegistry`: WAL sqlite, role-gated transitions,
  operator-only qualification with mandatory bound receipts,
  append-only transition audit, digest-verified reads.
- **Experience memory** — `ExperienceRecordV1`, `MemoryStore`
  (episode-replay rejection, tamper-proof), `induce_candidate`,
  gated `retrieve_memories` with abstention.
- **Skill evolution** — `SkillOptimizer` with pure-payload mutators,
  injected dev evaluator, hard budgets, ranked frontier; intake-only
  output.
- **Composition policy** — `compose_guidance`: typed precedence,
  dedup, conflict handling (`precedence`|`abstain`), token budget.
- **Governed evaluation plane** — five paired arms (A–E), sealed
  holdout partitions, preregistered protocol digests, powered sample
  sizing, abstention/negative-transfer metrics.
- **Governed serving** — `GovernedServingGateway`: registry-resolved
  repo identity, scope/revocation/applicability/counterexample gates
  with per-candidate rejection audit; advisory-only output.
- **vskill-style packaging** — export/verify/import of skill bundles;
  imports land at PROPOSED regardless of claimed status.
- **Deterministic campaign CLI** — `tools/governed_campaign.py`
  produces `campaign_evidence.json`: A=0, B=2, C=2, D=0, E=2 on
  unseen-repo holdouts (machinery evidence).

## What did not change

- v3.2 authority model, receipt signing, statement binding, source-change
  capture, strict procedure gateway, four-arm benchmark default.
- `report_digest`/`preregister` now tolerate floats via deterministic
  normalization — digest *values* differ from a hypothetical
  un-normalized computation, but semantics are unchanged and stable.

## Verification

- `PYTHONPATH=src python3 -m pytest tests/ -q`
- **709 passed, 2 skipped** (47 new v3.3 tests: registry, memory,
  evolution, composition, serving, packaging, governed eval, campaign).
- Every module compiles (`python3 -m py_compile`).

## Upgrade notes

- No schema migrations needed for v3.2 state; new stores are new files.
- Callers opting into arm `E` must pass `arms=("A","B","C","D","E")`.
- `CandidateRegistry.qualify` requires `receipt_refs` — wire real
  evaluator receipt digests, never placeholders.
