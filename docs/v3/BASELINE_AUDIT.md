# SIS v3 baseline audit — executed reproduction

Phase 0 of the master repair program. Every finding below was **executed**
against the checked-out source — nothing is inferred from the supplied
external audit (`SIS_v3_deep_source_audit_2026-10-24.md`, not present in the
repository).

## Environment

| Item | Value |
|---|---|
| checkout | `b0fb6c4cfb2ffed236e83b25583bd4dcb4a34e36` on `main` (working tree clean) |
| interpreter | Python 3.12.0 (`/Users/dawsonblock/.pyenv/versions/3.12.0/bin/python3`) |
| platform | macOS Darwin 25.2.0 |
| pytest | 8.4.2 |
| cryptography | 48.0.1 (Ed25519 backend = `cryptography`) |
| codex-cli | 0.156.1 at `/Users/dawsonblock/.nvm/versions/node/v24.16.0/bin/codex` |
| openai-codex PyPI SDK | **not installed** in this environment |

Source-ZIP SHA-256 from the plan (`3871bbe6…47816b`) could not be verified:
the ZIP itself is not in the workspace — only the extracted Git checkout.

## Baseline test counts (executed)

| Command | Result |
|---|---|
| `python3 -m compileall -q src tests` | OK |
| `PYTHONPATH=src python3 -m pytest -q tests/v3` | **212 passed, 1 skipped** in 9.66s |
| `PYTHONPATH=src python3 -m pytest -q tests/` | **549 passed, 2 skipped** in 14.32s |

STATUS.md claims "546 tests, 0 failures, 2 skips under -W error" at the
previous slice; observed 549 (+3, consistent with the `b0fb6c4` debug-pass
commit which added regression tests).

## Defect reproduction (tool: `tools/reproduce_defects.py`)

Executed output, verbatim:

```
A_two_manifest_zip: PASS (rejected: missing exactly-one manifest)
B_qualified_bypass: OPEN: allow_qualified=True minted status=qualified without any decision
C_scope_no_evidence: OPEN: scope=cross_repository set by bare role string, zero repo-disjoint evidence
D_overbudget_solve: OPEN: over-budget pass counted (solved_A=1, violations=0, D_vs_A wins=0)
E_nonce_no_consume: OPEN: verify1=True, seen_nonces size after verify=0, verify2=True — no consume API
F_crash_window: OPEN: uncommitted qualified visible (status=qualified); verify() flags: ['qualified_projection_drift']
G_operator_class: OPEN: Add->Mult changes=[('commutative', 'commutative')], violations=[]
H_tree_symlink: OPEN: tree with unexpected symlink verified (files=1)
I_wall_truncation: OBSERVED: slept 1.05s, int-truncated wall=1, exceeded(1s)=False
```

### Divergences from the supplied audit

- **(A) duplicate-manifest ZIP rejection — ALREADY CLOSED.** `verify()`
  requires exactly one recognized manifest at the project prefix and rejects
  `len(manifests) != 1`. A ZIP carrying both `RELEASE_SHA256.json` and
  `SOURCE_SHA256.json` is refused. The audit's premise no longer holds.
- **(F) crash window — PARTIALLY CLOSED.** V2 decisions do sign the full
  post-state before signatures, and `verify()` reports
  `qualified_projection_drift`. But `transition()` still persists the record
  *before* the decision line, so a crash leaves a servable
  `status=qualified` record — the drift is only detectable on explicit
  verify, and retrieval reads `record.status` directly. Still open.
- **(G) — confirmed open.** `Add→Mult` is commutative→commutative, so
  `metamorphic_violations` returns `[]`. Same for `Div→FloorDiv`,
  `Sub→Div`, operand reordering, float/NaN, and `and/or` short-circuit
  swaps — the algebraic-class heuristic cannot see any of them.

### Additional defects observed during reproduction

- **build_zip non-deterministic.** Two builds of an identical tree produce
  different archive bytes (member mtimes and the manifest's 0o600 mode are
  embedded). No release-attestation document is emitted.
- **verify_tree skips non-regular files.** Symlinks, FIFOs, sockets and
  devices under the tree are silently ignored, not rejected (H).
- **Receipt cache** in `BenchmarkHarness` is keyed only by
  `(task_id, submission_digest)` — it ignores evaluator identity, criterion
  version and protocol, and reuse hides per-arm independence.
- **No deadline kill / arm-order randomization.** Arms run in fixed A,B,C,D
  order in the harness process; `wall` is truncated to `int`, so real
  1.05 s over a 1 s cap is recorded as compliant.
- **Serving path never sees revocation/scope.** `GuidanceGateway.recommend`
  calls `sis_recommend` without `revoked`, no `Catalog` scope check exists
  in the serving path, and `CounterexampleIndex.blocked` is a global block
  signal rather than per-procedure.

## P0 gate assessment

Baseline failures are *expected* per the plan; each reproduced OPEN item
has an isolated regression target before repair. Proceed to Phase 1.
