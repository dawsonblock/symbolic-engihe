# SIS v3.3 Evaluation Protocol

## Arms

| arm | configuration |
|---|---|
| A | base agent |
| B | base + qualified experience memory |
| C | base + evolved skill candidates |
| D | base + SIS symbolic procedures (strict gateway) |
| E | base + full governed integration (all qualified artifacts, composed) |

Same agent, same `BudgetCaps`, paired per task. Arm is opt-in via
`arms=`; the historical default remains `("A","B","C","D")`.

## Validity conditions (structural, not assumed)

1. **Sealed holdout** — `assert_partition_disjoint` rejects any shared
   `repo_snapshot_digest` between holdout/monitoring and
   induction/development before the run. Induction and development may
   overlap by design; dev evidence is never reported as generalization.
2. **Preregistration** — `preregister` freezes primary metric, method,
   alpha, min effect, sample size, budget, and arms into a
   domain-separated `protocol_digest` committed before the holdout run
   and embedded in the report.
3. **Sample size** — `required_sample_size(p1, p2)` is a conservative
   normal-approx McNemar calculation; declare the effect size worth
   detecting and power before running.
4. **Hidden labels** — arms receive only their injected guidance context;
   outcomes come only from signed `OutcomeReceiptV1`s issued by the
   evaluator against its own registered criteria.
5. **Repository disjointness** — `assert_repository_disjoint` additionally
   verifies the holdout repos never appeared in learned material.

## Metrics (per arm, from `compute_metrics`)

`solved_task_rate`, `verified_regression_rate`, `abstention_rate`,
`negative_transfer_rate` (served×failed on misleading tasks),
`mean_tokens_per_task`, `mean_tool_calls_per_task`,
`mean_wall_seconds_per_task`, `evaluation_integrity_failures`.
Missing usage stays `None`/`unverified` — never fabricated.

`served_map[(task_id, arm)]` records whether guidance was actually
served, so abstention and negative transfer are *measured*, not
inferred.

## Statistics

- Primary contrast: paired `E` vs `A` wins/losses/ties with exact
  McNemar p (`mcnemar_p`) and Wilson intervals (`wilson_ci`) where
  reported.
- Exploratory vs confirmatory is declared in the report
  (`analysis_mode`); anything not preregistered is exploratory.
- Inconclusive is a legitimate verdict: report
  `EFFICACY_NOT_QUALIFIED` rather than a massaged pass.

## Negative-transfer suite

Include deliberately misleading memories and tasks where a previously
successful strategy is wrong. Measure: did the system abstain
(`abstention_rate`, counterexample suppression) or apply-and-fail
(`negative_transfer_rate`)? Both are reported per arm.

## Honest outcome vocabulary

- `solved` = receipt `pass` AND not `budget_exceeded` AND no arm error.
- `verified` usage = harness-metered `UsageMeter` counters only;
  stdout-parsed usage is `reported`; absent usage is `unverified`.
- A positive result on six tasks, or more unit tests, is not efficacy.
