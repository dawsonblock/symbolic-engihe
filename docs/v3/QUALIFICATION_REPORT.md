# SIS3-013 qualification report — gate status

Date: 2026-10-23/24. Suite: 526 tests, 0 failures, 2 skips (run under `-W error`).

Repair pass landed: `cryptography` Ed25519 backend preferred (vendored
fallback kept wire-identical), per-principal operator signatures for
promotion (token fallback retained), evaluator signing moved into a child
process (`evaluator_worker`), benchmark wall-clock violations flagged.

v3.1 roadmap slice landed: ZIP-native release verification
(`tools/verify_release.py` `verify()` streams the archive and never
extracts; `RELEASE_SHA256.json` covers 220 files), extracted-tree
`verify_tree` + `build_zip`, SQLite `close()`/context-manager on all four
connection owners, `episode_projection` with an agent-facing redacted view,
`OutcomeEnvelopeV2` with pinned-key registry/revocation/nonce replay/expiry,
`semantic_checks` metamorphic operator-class gating, `counterexamples`
negative-evidence index, scoped `catalog` with evidence-revocation cascade
suspension, `guidance_gateway` shadow/diagnostic/conditional phases with kill
switch, retrieval `AblationFlags`, and benchmark Wilson/McNemar statistics.

## Milestone gate ledger

| Gate | Required evidence | Status |
|---|---|---|
| M0 | Old tests green; no unauthorized mutation; negative-transfer rejection; schema round-trip; fresh-release verification | **Met**: 526 green; `verify()` on a built ZIP + `verify_tree` on fresh extraction + compile check all pass; tamper/extra/missing/duplicate/symlink rejected |
| M1 | ≥1 actual coding task end-to-end through adapter→store→verifier | **Met**: live-002 — real Codex fixed the fixture bug, evaluator independently signed `pass`, 16 chained events, full receipt preserved (`docs/v3/episodes/live-002/`). Live-001 documents the earlier quota-limited fail |
| M2 | Forgeries/digest mismatches denied; signed receipts survive replay/restart | **Met locally**; evaluator shares the caller's process — separate OS-principal custody not deployed |
| M3 | False transfer rejected; compatible task gets useful candidate; source preservation; traceable evidence | **Mechanics met**: hard gates + contraindications + abstain paths tested; `semantic_checks` now flags noncommutative→commutative operator swaps structurally; no *live* cross-repository transfer demonstrated |
| M4 | Mutation denied to agent identities; unsigned/unauthorized promotion rejected; corruption safe; rollback tested | **Met locally** (operator token is a shared-secret gate, not per-principal auth) |
| M5 | Pre-registered held-out tasks; four arms; equal budgets; independent scoring; positive D−A lower bound | **Not met**: harness exists and is tested with scripted agents; zero real held-out tasks have been run |
| M6 | Learned ranker beats deterministic retrieval at matched budgets | **Not attempted** (correctly deferred) |

## Release-label decision

- `v3.0.0-alpha` criterion: "a real adapter and verifier operate end-to-end".
  **Met by live-002** — the alpha bar is cleared on pipeline grounds.
  Caveat: a single solved fixture task is not efficacy evidence; alpha is
  the honest ceiling until M5 data exists.
- `v3.0.0-beta` / stable: far out of scope; requires the M5 efficacy gate.

## What is proven vs. unproven

Proven: bounded contracts, default-deny policy, bounded execution,
tamper-evident storage, evaluator-signed outcomes, digest-locked proposals,
hard-gated retrieval, signed promotion decisions, paired benchmark mechanics,
and a real (failed) Codex episode captured end-to-end.

Unproven: any procedure ever serving a real second task, any improvement in
solved-task rate, OS-validated isolation, evaluator custody beyond
subprocess memory separation, WORM/external anchoring.

## Next concrete steps

1. ~~Passing live episode~~ — done (live-002).
2. Mine a candidate from live-002; qualify it through the promotion
   controller on a second disjoint fixture; serve it via guidance on a third.
3. Run the four-arm harness on ≥3 scripted fixtures; only then consider
   pre-registering a real held-out suite.
