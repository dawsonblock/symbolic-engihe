# SIS3-013 qualification report — gate status

Date: 2026-10-23/24. Suite: 488 tests, 0 failures, 2 skips.

Repair pass landed: `cryptography` Ed25519 backend preferred (vendored
fallback kept wire-identical), per-principal operator signatures for
promotion (token fallback retained), evaluator signing moved into a child
process (`evaluator_worker`), benchmark wall-clock violations flagged.

## Milestone gate ledger

| Gate | Required evidence | Status |
|---|---|---|
| M0 | Old tests green; no unauthorized mutation; negative-transfer rejection; schema round-trip | **Met** (archive-hash caveat recorded) |
| M1 | ≥1 actual coding task end-to-end through adapter→store→verifier | **Partially met**: real Codex CLI backend contact captured as chained episode with signed evaluator receipt (`docs/v3/episodes/live-001`), but the turn failed on account quota. A *passing* live episode is still required |
| M2 | Forgeries/digest mismatches denied; signed receipts survive replay/restart | **Met locally**; evaluator shares the caller's process — separate OS-principal custody not deployed |
| M3 | False transfer rejected; compatible task gets useful candidate; source preservation; traceable evidence | **Mechanics met**: hard gates + contraindications + abstain paths tested; no *live* cross-repository transfer demonstrated |
| M4 | Mutation denied to agent identities; unsigned/unauthorized promotion rejected; corruption safe; rollback tested | **Met locally** (operator token is a shared-secret gate, not per-principal auth) |
| M5 | Pre-registered held-out tasks; four arms; equal budgets; independent scoring; positive D−A lower bound | **Not met**: harness exists and is tested with scripted agents; zero real held-out tasks have been run |
| M6 | Learned ranker beats deterministic retrieval at matched budgets | **Not attempted** (correctly deferred) |

## Release-label decision

- `v3.0.0-alpha` criterion: "a real adapter and verifier operate end-to-end".
  We have real adapter contact and real signed evaluation on a real (failed)
  episode — the plumbing is proven, but no task was ever solved end-to-end.
  Conservative call: **pre-alpha**. Do not publish an alpha label until one
  passing live episode exists.
- `v3.0.0-beta` / stable: far out of scope; requires the M5 efficacy gate.

## What is proven vs. unproven

Proven: bounded contracts, default-deny policy, bounded execution,
tamper-evident storage, evaluator-signed outcomes, digest-locked proposals,
hard-gated retrieval, signed promotion decisions, paired benchmark mechanics,
and a real (failed) Codex episode captured end-to-end.

Unproven: any live task success, any procedure ever serving a real second
task, any improvement in solved-task rate, OS-validated isolation, evaluator
custody separation, WORM/external anchoring, constant-time signatures.

## Next concrete steps

1. After quota reset (~8:36 PM): `PYTHONPATH=src python3
   scripts/v3/run_codex_episode.py --work-root /tmp/sis-live-ws
   --evidence-root /tmp/sis-live-evidence` for a passing live episode.
2. Mine a candidate from that episode; qualify it through the promotion
   controller on a second disjoint fixture; serve it via guidance on a third.
3. Run the four-arm harness on ≥3 scripted fixtures; only then consider
   pre-registering a real held-out suite.
