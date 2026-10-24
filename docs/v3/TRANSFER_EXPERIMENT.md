# v4.0.0 — held-out transfer efficacy experiment (SIS3-501)

**Status: real experiment executed against the live Codex backend;
verdict NO-GO for claiming statistically significant improvement,
GO for "no in-scope harm observed + directional signal".**

## Protocol

- Agent: real OpenAI Codex via `openai-codex==0.163.0` SDK,
  `workspace_write` sandbox, fresh disposable workspace per arm.
- Scoring: `OutcomeVerifier` runs each repo's registered acceptance
  command in a subprocess and signs the receipt. Agent declarations were
  never consulted.
- Procedure: `RepairHypothesisV1` mined from a verified episode in seed
  repo-a (`a - b` → `a * b`), typed `operator_substitution`, bound to an
  executable semantic contract.
- Held-out set (disjoint repos, never used for mining/qualification):

| Task | Bug | Arm A (no guidance) | Arm D (guidance) |
|------|-----|---------------------|------------------|
| ho1 | `volume(l,w,h) = l-w-h` | pass | pass |
| ho2 | `interest(p,r) = p-r` | pass | pass |
| ho3 | `energy(m,c) = m-c` | **fail** | **pass** |
| control | `balance(a,b)=a-b` (correct) | fail | fail |

Paired D vs A on held-out tasks: **1 win, 0 losses, 2 ties** (n=3).

## Findings

1. Directional positive signal: on ho3 the guided arm repaired what the
   unguided arm failed to repair. No arm-D loss was observed in-scope.
2. n=3 cannot support a significance claim; the Wilson lower bound on
   the paired delta includes zero. The honest gate M5 remains **not met**
   at statistical power — a larger held-out suite is required.
3. Negative-transfer evidence (control): the agent broke a *correct*
   function under fix-pressure in **both** arms (A and D alike). The
   failure is attributable to the agent+task framing, not to the served
   procedure — but it confirms the necessity of the executable
   semantic-contract gate and gateway abstention before serving.
4. Arm D served procedure intent/steps text in-prompt (the conditional-
   phase surface), not internal hypothesis internals.

## Reproduction

    PYTHONPATH=src:. SIS3_LIVE_CODEX=1 \
        python -m pytest tests/v3/test_efficacy_live.py -x -s

Requires local Codex credentials; ~2 min wall clock for 8 live turns.
Artifact: `efficacy_report.json` written into the test's temp root and
printed to stdout (evaluator verdicts only).
