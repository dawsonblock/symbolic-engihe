# Security closure ledger — audit defects A–I

Reproduction evidence: `docs/v3/BASELINE_AUDIT.md` (defects B–I confirmed
OPEN at `b0fb6c4`; A already closed by the prior v3.1 integrity slice).

| ID | Defect | Closure commit | Evidence |
|----|--------|---------------|----------|
| A | ZIP/streaming verify gaps | pre-existing (`9ec4166`/`a8d5590`) + `5cffa35` | `verify()` rejects traversal/symlink/dupes/non-regulars; `verify_tree` fails on symlinks; deterministic `build_zip` |
| B | `allow_qualified=True` code-level status bypass | `e0b49e8` | `store.add()` accepts draft/candidate only; governed status requires `_commit_record(backing_decision=…)`; `verify()` flags `unbacked_status_at_*` |
| C | Agent-reported pass counted as solve; truncated wall clock; no deadline; fixed arm order; cross-arm receipt reuse | `e4f0808` | `benchmark.py`: valid-solve = independent verifier pass only; float wall strings; deadline + cooperative cancel; seeded order; scoped evaluation markers |
| D | Cross-repo scope via caller-supplied role string, no signed backing | `4ee6fd2` | `ScopeGrantV1` signed decisions; `set_scope` removed; scope projection inside `EligibilitySnapshot`; wrong-repo abstention tests |
| E | `verify_envelope` pure — nonce replay possible | `61f05c4` | `verify_and_consume`: flock-guarded durable signer+nonce ledger; spent envelope cannot back a second transition; survives restart |
| F | Crash window: record appended before decision | `e0b49e8` | Intent journal before either append; recovery completes idempotently or fails closed on diverged intents; phantom-backing detected |
| G | `a + b → a * b` unflagged (same algebraic class) | `61f05c4` | `semantic_checks.py`: every operator substitution, operand reorder, and structural change flagged; class heuristics are filters, never proof |
| H | Serving surfaces read raw `record.status` | `4ee6fd2` | retrieval/guidance/gateway consume `EligibilitySnapshot` rebuilt at request time; any inconsistency → `conflicting_evidence` abstain; kill switch → `catalog_unavailable` |
| I | Codex adapter on undocumented APIs / sandbox claims | `38efcf5` | public `openai-codex==0.163.0` SDK; bounded `ObservationEventV1` normalization, no raw content; sandbox documented as convenience, not a boundary |

## Residual exposures (explicit, not waived)

- Evaluator custody is same-process in the default deployment
  (M2 met locally; separate-OS-principal custody requires deployment
  work, not more code here).
- macOS seatbelt backend is best-effort; `unverified_local` profile is
  the honest label and must be retained until an audited backend exists.
- Codex sandbox is an agent convenience; hostile-code containment is
  NOT established and must not be claimed.
- `min_pass_receipts`/`min_distinct_repos` remain policy knobs —
  recommended pilot floor: ≥3 tasks, ≥2 repos.
