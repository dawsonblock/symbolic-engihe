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
  a promotion cannot exist without cited evidence.

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
- **Serving is scope-bound** — `repository_scope` of `registry_id` /
  `family_id` resolves through the signed `RepositoryRegistry`; a
  self-declared or unknown repository identity abstains. `global` scope
  is served only behind an explicit `allow_global_scope` flag.
- **Counterexamples suppress** — any `known_counterexamples` string found
  in the task's failure/symbol/file context vetoes that candidate.
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
  qualification.
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
