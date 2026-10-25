# SIS v3.3 Limitations

## Efficacy

- **Learning efficacy is not established.** The deterministic campaign
  proves the machinery end-to-end (verified episodes → candidates →
  sealed-holdout paired eval → governed qualification → serving →
  revocation) with a scripted agent. It does not show a real model
  solves more unseen tasks. That requires a live-model campaign on a
  powered sample; until then the release is
  `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
- Holdout size in the deterministic fixture (2 tasks) is a smoke test,
  not a statistical result; `mcnemar_exact_p` is reported honestly and
  is not significant.

## Isolation

- Execution isolation remains `isolation:unverified_local`; the
  runner reports what it can enforce, no more. Network denial via
  seatbelt is best-effort on macOS only.
- Usage accounting remains `reported`-grade for agent-supplied counters;
  only `UsageMeter`-instrumented paths are `verified`.

## Composition and memory

- Conflict detection is a lexical polarity heuristic — it catches
  "always X" vs "never X", not semantic contradictions. Deployments that
  cannot tolerate heuristic misses should serve with
  `conflict_policy="abstain"`.
- Memory retrieval scoring is deterministic gate-counting, not neural
  similarity. Semantic ranking across distant phrasings is out of scope
  for this release.
- Hypotheses inside memory payloads are carried for evaluation only;
  nothing upgrades them to causal truth automatically.

## Evolution

- Mutators are a fixed, hand-declared set over step lists. There is no
  free-form code mutation, and no candidate code ever executes inside
  the optimizer.
- Dev-set fitness selection can overfit the development partition by
  construction; that is exactly why the sealed holdout is separate.
  Reports must never present dev fitness as generalization.

## Serving and packaging

- `global` candidate scope is refused unless `allow_global_scope=True`
  is set deliberately — it is a deployment decision, not a default.
- `security_scan` is a string heuristic for advisory triage only; a
  clean scan never implies qualification and a flagged bundle is not
  proof of malice.
- Bundle format is vskill-*style* (manifest + payload + SHA256SUMS);
  wire compatibility with an external vskill registry is not claimed.

## Not in scope (per charter)

No neural fine-tuning, no LoRA/weight adaptation, no live-registry
promotion channels, no cloud deployment. Learning is bounded to
symbolic procedures, experience memory, and text-level skill variants.
