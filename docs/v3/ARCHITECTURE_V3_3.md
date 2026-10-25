# SIS v3.3 Architecture — Governed Learning

v3.3 adds a governed learning plane to the v3.2 authority-integrity
baseline. Three learning tracks feed one typed candidate registry; one
governed promotion boundary decides what may serve; one composition
policy merges what serves.

## Trust plane map

```
untrusted/agent side                 trusted side
--------------------                 --------------------------
coding agent (Codex/scripted)   -->  OutcomeVerifier  (signed receipts,
runner / executor               -->   statement-bound registration)
                                      |
ExperienceRecordV1  --[learner]-->    MemoryStore     (dedup, tamper-proof)
SkillOptimizer      --[learner]-->    CandidateRegistry (PROPOSED only)
                                      |
                                  EVALUATING --[evaluator]--> dev/holdout
                                  receipts --[operator]------> QUALIFIED
                                      |
                           GovernedServingGateway
                           (scope + revocation + applicability +
                            counterexample + composition budget)
                                      |
                           GuidanceV1 advisory channel --> agent
```

## Components

| module | role |
|---|---|
| `candidates.py` | `CandidateRegistry`: WAL sqlite, role-gated state machine, append-only transition audit, digest-verified reads |
| `contracts.py` | `CandidateV1`, `ExperienceRecordV1` records (canonical digests, bounded validation) |
| `memory.py` | `MemoryStore` (episode dedup, outcome index), `induce_candidate`, `retrieve_memories` (gates + abstention) |
| `evolution.py` | `SkillOptimizer`, pure-payload mutators, `Frontier`, `EvolutionBudget`; dev-eval via injected `EvaluationClient` |
| `composition.py` | `compose_guidance`: precedence by type, dedup, polarity conflicts, token budget, abstain |
| `governed_eval.py` | `EvaluationPartition` + sealed-holdout disjointness, `preregister`, `required_sample_size`, `compute_metrics`, `run_governed_evaluation` (5 arms) |
| `serving.py` | `GovernedServingGateway`: registry-authenticated repo identity, per-candidate rejection audit, advisory-only serving |
| `skill_package.py` | vskill-style bundles: manifest + payload + SHA256SUMS, `export_bundle`/`verify_install`/`import_bundle`/`security_scan` |
| `tools/governed_campaign.py` | deterministic end-to-end campaign CLI (M9) |

## Learning tracks

- **A — symbolic induction** (existing `learning/`): verified source changes
  to bounded procedures; unchanged.
- **B — experience memory**: verified episodes to `ExperienceRecordV1` to
  `experience_memory` candidates. Facts and hypotheses stay separated;
  hypotheses never become causal truth without evaluation.
- **C — skill evolution**: pure-function payload mutations evaluated by an
  injected dev-set client under a hard evaluation budget; output is
  PROPOSED candidates only.

## Invariants

1. Candidate generation never confers promotion authority —
   `proposed→validated` is `candidate:write` (learner); `evaluating→qualified`
   is `promotion:approve` (operator) and requires ≥1 bound receipt digest.
   The registry also requires a deployment-supplied `receipt_authority`:
   each cited digest must resolve to a signature-authenticated receipt
   with outcome `pass`, so a digest string alone is never evidence.
2. Receipts are the only evidence handle. Booleans carry no authority.
3. Learner/optimizer hold no signing keys and no authority-DB access.
4. Served text is data: delivered through `helpful_next_checks`, it can
   describe an action but cannot grant one.
5. Promotion supports audit, revocation, rollback (`qualified→revoked` is
   terminal-audited; audit rows are append-only in the same transaction).
6. The qualification holdout is sealed: no shared `repo_snapshot_digest`
   with induction/development; enforced, not assumed.
