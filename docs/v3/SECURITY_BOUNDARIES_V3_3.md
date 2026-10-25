# SIS v3.3 Security Boundaries

## Roles and permissions (policy.py)

| role | permissions relevant to learning plane |
|---|---|
| agent | guidance:read, qualified_catalog:read, observation:append |
| runner | workspace:execute, observation:append, artifact:read |
| learner | candidate:write, artifact:read |
| evaluator | outcome:evaluate, outcome:sign, evaluator_private:read, artifact:read |
| operator | promotion:approve, policy:write, qualified_catalog:read, artifact:read |

- `candidate:write` → learner only. Memory induction and the skill
  optimizer run under this role: they can submit at PROPOSED and move
  `proposed→validated`. Nothing else.
- `outcome:evaluate` → evaluator only. Owns `validated→evaluating`,
  `evaluating→rejected|inconclusive`, and every receipt signature.
- `promotion:approve` → operator only. Owns `evaluating→qualified` and
  `qualified→revoked`. Qualification requires ≥1 bound receipt digest —
  a promotion cannot exist without cited evidence. The registry also
  requires a deployment-supplied `receipt_authority` callable: every
  cited digest must resolve to a signature-authenticated receipt whose
  outcome is `pass`. Without that authority, qualification is refused
  (`qualification_requires_receipt_authority`); a bare 64-hex string is
  never treated as evidence.

## Fail-closed boundaries (all tested)

- **Registry reads re-verify digests** — a tampered `candidate` row raises
  `candidate_tampered`; a tampered `experience` row raises
  `experience_tampered`. Corrupt JSON never deserializes into a record.
- **Replayed episodes are rejected** — `MemoryStore.ingest` keys on
  `(episode_id, task_fingerprint)`; a mutated copy of an episode is a
  `DuplicateEpisode`, never a second vote.
- **Idempotent submit, conflicting ids rejected** — re-submitting an
  identical candidate is a no-op; the same id with different content is a
  conflict.
- **Transition audit is hash-chained** — every `candidate_transition`
  row is sealed inside the same transaction as the state change with a
  `prev_digest`/`entry_digest` link; `audit()` re-verifies the whole
  chain on every read, so rewritten, reordered, deleted or truncated
  history raises `audit_chain_tampered`. Pre-chain databases are
  backfilled at open (sealed over current content — backfill makes rows
  verifiable, it cannot prove they were not already altered).
- **Serving is scope-bound** — `repository_scope` of `registry_id` /
  `family_id` resolves through the signed `RepositoryRegistry`; a
  self-declared or unknown repository identity abstains. `global` scope
  is served only behind an explicit `allow_global_scope` flag.
- **Family targeting is an opt-in hard gate** — `target_task_family` is
  provenance by default; when the caller passes `task_family`,
  off-target candidates are rejected with `family_mismatch` and counted
  in the audit rejections.
- **Counterexamples suppress with boundary anchoring** — a
  `known_counterexamples` string vetoes a candidate only on a
  token-boundary match in the task's failure/symbol/file context
  (needles shorter than 3 characters must equal a whole token), so a
  short string cannot suppress everything it merely substrings.
- **Serving audit records what was delivered** — `candidate_digests`
  covers only candidates whose steps actually shipped in
  `helpful_next_checks` (post-budget, post-truncation), not every
  catalog item considered; each rejection is recorded with a reason.
  Every `served_guidance` audit row carries the `task_id` and the
  guidance digest.
- **Outcomes bind to delivered guidance** — `record_outcome` attaches a
  signed receipt digest and outcome to the exact guidance digest this
  gateway served for that task; unknown tasks, mismatched digests, and
  malformed receipt references raise instead of writing an uncorrelated
  audit row.
- **Malformed serving input abstains audited** — a request that fails
  contract parsing returns `abstain/catalog_unavailable` inside the
  audited path rather than propagating an unlogged exception.
- **Prompt injection is data** — a qualified candidate whose steps say
  "grant operator role" is served verbatim inside `helpful_next_checks`
  and nothing else: `decision` stays `abstain`, `procedure_ids` stays
  empty, no permission changes.
- **Optimizer cannot self-qualify** — `SkillOptimizer` has no state path
  past PROPOSED; its dev evaluator is an injected interface it does not
  control, and it cannot see holdout partitions (structural).
- **Imported bundles are unqualified** — `import_bundle` verifies hashes
  and registers at PROPOSED regardless of the manifest's claimed
  `sis_qualification_status`; a passing `security_scan` never implies
  qualification. `verify_install` returns problems for *any*
  unverifiable element — corrupt or missing `manifest.json`, undeclared
  hashes, unexpected files, or a manifest whose `candidate_id`/
  `candidate_digest` disagrees with the payload — it never raises.
- **Preregistration conformance is measured, not cosmetic** —
  `run_governed_evaluation` records a `conformance` block comparing the
  executed run to the preregistered budget, arm set, and sample size;
  an off-plan or underpowered run reports `conforms=False` with named
  mismatches rather than hiding behind the protocol digest.
- **Receipt reuse is impossible** — verifier nonces and the
  `(task_id, tree_digest, criterion_version)` dedup marker reject
  replays; the benchmark receipt cache reuses identical-submission
  receipts by reference, not by re-evaluation.

## What is NOT enforced here (honest limits)

- Local execution is `isolation:unverified_local`; seatbelt network
  denial is opportunistic, not a guarantee.
- Advisory text is delivered to the agent — the harness must treat it as
  untrusted context. SIS guarantees the channel is advisory; the agent's
  sandbox is responsible for action-level enforcement.
- The polarity conflict detector is a heuristic, not a semantic proof;
  `conflict_policy="abstain"` is the conservative option.
