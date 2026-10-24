# v4.0.x — held-out transfer efficacy experiments (SIS3-501)

**Status: three real runs executed against the live Codex backend.
v4.0.2 (4 arms × 12 held-out tasks + control): D solved 12/12; A/B/C
10/12 each; placebo/raw-context zero effect (0/0/12). Guidance rescues
exactly the tasks the baseline misses — but baseline misses only 2/12
on this bug class, so discordant pairs = 2 (exact McNemar p = 0.25).
M5 stays OPEN: power requires a harder task distribution where the
baseline genuinely fails, not more tasks of this class.**

## v4.0.2 — four-arm run (52 live turns, independent scoring)

| Metric | A | B (placebo) | C (raw ctx) | D (guidance) |
|--------|---|-------------|-------------|--------------|
| Held-out solves | 10/12 | 10/12 | 10/12 | **12/12** |
| Paired vs D | 2W/0L/10T | 2W/0L/10T | 2W/0L/10T | — |
| B vs A, C vs A | 0/0/12 | — | 0/0/12 | — |

Wins concentrated on ho3 `energy` and ho6 `speed` — identical structure
to other tasks; the agent's per-run variance decided which failed.
Harder variants (nested chains `rows-cols-depth`, `n-n-n`, multi-function
files, distractors) were all solved by every arm — task difficulty, not
quantity, is the power bottleneck.

## v4.0.1 — four-arm run, 6 tasks (28 live turns)

## v4.0.1 — four-arm run (28 live turns, independent scoring)

| Task | A baseline | B placebo | C raw-context | D guidance |
|------|-----------|-----------|---------------|------------|
| ho1 `volume` | pass | pass | pass | pass |
| ho2 `interest` | pass | pass | pass | pass |
| ho3 `energy` | fail | fail | fail | **pass** |
| ho4 `dose` | pass | pass | pass | pass |
| ho5 `total` | pass | pass | pass | pass |
| ho6 `speed` | fail | fail | fail | **pass** |
| control `balance` | fail | fail | fail | fail |

Paired (held-out): D-vs-A **2 wins / 0 losses / 4 ties**; identical vs
B and C. B-vs-A and C-vs-A: **0/0/6** — placebo and raw context had no
effect, so the D advantage is attributable to the procedure itself.

- D-arm solve rate: 6/6; A/B/C: 4/6 each.
- Control (correct function under fix-pressure): every arm broke it —
  agent+task framing risk confirmed again; contract+abstention gates
  remain the mitigation.
- Verdict: placebo-controlled directional evidence; M5 significance
  still requires more discordant pairs (~16+ tasks or harder tasks
  where the baseline genuinely fails).

## v4.0.0 — two-arm run (8 live turns)

## Protocol (applies to both runs)

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
