"""Four-arm paired benchmark harness (SIS3-012 / v3.1.2).

Arms: ``A`` baseline agent, ``B`` placebo context, ``C`` raw episode-context
retrieval, ``D`` qualified procedure guidance. For every task, each arm runs
in a fresh disposable workspace with an identical budget envelope
(``BudgetCaps``); the arm callable receives an ``ArmContext`` whose only
difference is the injected context payload. Submissions are scored by the
independent ``OutcomeVerifier`` — the harness never trusts arm-reported
results — and the report counts paired wins/losses/ties over *valid solves*
only.

Truthfulness rules (v3.1.2):

* ``valid_solve`` = independently verified ``pass`` AND no timeout AND no
  wall/token/tool budget violation AND no agent/evaluator error. An
  over-budget or errored ``pass`` never counts as a solve or a paired win.
* Wall time is ``time.monotonic()`` float seconds; the agent is stopped at
  the hard deadline (daemon thread + cooperative ``ctx.cancelled`` event).
  The harness records whether termination was actually observed —
  ``termination_verified=False`` means the agent kept running and the
  submission is excluded, never admitted.
* Arm order is shuffled per task under a recorded ``arm_seed``.
* Every arm attempt is independently evaluated — no receipt cache.
* Token/tool usage is measured at the adapter boundary via
  ``ctx.usage``; an arm that does not meter them is reported as
  ``declared_only`` and the run is not equal-budget certified.
"""
from __future__ import annotations

import math
import random
import secrets
import shutil
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import ContractError, GuidanceV1, TaskEnvelopeV1, canonical_digest
from .episode_store import EpisodeStore
from .runner import tree_digest
from .verifier import OutcomeVerifier

ARMS = ("A", "B", "C", "D")

CATEGORIES = (
    "pass", "fail", "timeout", "budget_exceeded", "agent_error",
    "evaluator_error", "infrastructure_error", "abstained",
)


class BenchmarkError(RuntimeError):
    """The benchmark cannot produce an auditable result."""


@dataclass(frozen=True)
class BudgetCaps:
    wall_seconds: int
    token_budget: int
    tool_budget: int

    def __post_init__(self) -> None:
        for name in ("wall_seconds", "token_budget", "tool_budget"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ContractError(f"{name} must be a positive integer")


@dataclass
class ArmUsage:
    """Adapter-metered resource consumption; ``None`` means unmeasured."""

    tokens_used: int | None = None
    tools_used: int | None = None


@dataclass
class ArmContext:
    """The only input that varies between arms of the same task.

    ``cancelled`` is set by the harness at the wall deadline — cooperative
    agents poll it and stop. ``deadline_monotonic`` is the absolute
    ``time.monotonic()`` deadline. ``usage`` is filled in by adapters that
    meter tokens/tool calls.
    """

    task: TaskEnvelopeV1
    arm: str
    workspace: Path
    budget: BudgetCaps
    guidance: GuidanceV1 | None = None
    context_digest: str | None = None
    deadline_monotonic: float = 0.0
    cancelled: threading.Event = field(default_factory=threading.Event)
    usage: ArmUsage = field(default_factory=ArmUsage)


@dataclass(frozen=True)
class ArmResult:
    task_id: str
    arm: str
    outcome: str            # raw verifier outcome or "error"/"abstained"
    category: str           # one of CATEGORIES
    receipt_digest: str | None
    submission_digest: str | None
    wall_seconds: float
    budget_exceeded: bool
    valid_solve: bool
    exclusion_reason: str | None = None
    tokens_used: int | None = None
    tools_used: int | None = None
    termination_verified: bool = True
    error: str | None = None


@dataclass
class TaskResult:
    task_id: str
    arm_order: tuple[str, ...] = ()
    arms: dict[str, ArmResult] = field(default_factory=dict)


AgentFn = Callable[[ArmContext], None]
ContextFn = Callable[[TaskEnvelopeV1, str], GuidanceV1 | None]


def _categorize(res: ArmResult) -> bool:
    """valid_solve: verified pass, in-budget, error-free, termination known."""
    return (
        res.outcome == "pass"
        and res.category == "pass"
        and not res.budget_exceeded
        and res.termination_verified
    )


class BenchmarkHarness:
    """Runs paired arms and reports independently verified outcomes."""

    def __init__(
        self,
        *,
        verifier: OutcomeVerifier,
        store: EpisodeStore | None = None,
        work_root: str | Path | None = None,
    ) -> None:
        self.verifier = verifier
        self.store = store
        self._own_root = work_root is None
        self.work_root = Path(work_root) if work_root else Path(
            tempfile.mkdtemp(prefix="sis-v3-bench-")
        )
        self.work_root.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        tasks: list[tuple[TaskEnvelopeV1, Path]],
        agent: AgentFn,
        *,
        budget: BudgetCaps,
        context_provider: ContextFn | None = None,
        arms: tuple[str, ...] = ARMS,
        seed: str | None = None,
    ) -> dict:
        """Execute every arm per task; return an auditable paired report."""
        unknown = [a for a in arms if a not in ARMS]
        if unknown:
            raise ContractError(f"unknown arms: {unknown}")
        seed = seed or secrets.token_hex(16)
        results: list[TaskResult] = []
        for task, base_dir in tasks:
            rng = random.Random(f"{seed}:{task.task_id}")
            order = list(arms)
            rng.shuffle(order)
            task_result = TaskResult(task_id=task.task_id,
                                     arm_order=tuple(order))
            for arm in order:
                task_result.arms[arm] = self._run_arm(
                    task, Path(base_dir), agent, arm, budget, context_provider
                )
            results.append(task_result)
        return self._report(results, arms, budget, seed)

    def _run_arm(
        self,
        task: TaskEnvelopeV1,
        base_dir: Path,
        agent: AgentFn,
        arm: str,
        budget: BudgetCaps,
        context_provider: ContextFn | None,
    ) -> ArmResult:
        workspace = Path(tempfile.mkdtemp(prefix=f"arm-{arm}-", dir=self.work_root))
        retained = False
        try:
            try:
                shutil.copytree(base_dir, workspace, dirs_exist_ok=True)
            except OSError as exc:
                return ArmResult(
                    task.task_id, arm, "error", "infrastructure_error", None,
                    None, 0.0, False, False, "workspace_setup_failed",
                    error=f"{type(exc).__name__}:{str(exc)[:200]}")
            guidance = context_provider(task, arm) if context_provider else None
            context_digest = None
            if arm in {"B", "C"}:
                context_digest = canonical_digest("arm_context", 1, {
                    "arm": arm, "task_id": task.task_id,
                    "nonce": secrets.token_hex(8),
                })
            ctx = ArmContext(
                task=task, arm=arm, workspace=workspace,
                budget=budget, guidance=guidance, context_digest=context_digest,
            )
            start = time.monotonic()
            ctx.deadline_monotonic = start + budget.wall_seconds
            error = None
            timed_out = False

            def _invoke() -> None:
                try:
                    agent(ctx)
                except Exception as exc:  # arm failures are observations
                    nonlocal error
                    error = f"{type(exc).__name__}:{str(exc)[:200]}"

            worker = threading.Thread(target=_invoke, daemon=True,
                                      name=f"sis-bench-{task.task_id}-{arm}")
            worker.start()
            worker.join(timeout=budget.wall_seconds)
            wall = time.monotonic() - start
            terminated = not worker.is_alive()
            if not terminated:
                timed_out = True
                ctx.cancelled.set()
                # Grace: give a cooperative agent a bounded chance to stop,
                # but never wait long enough to admit a late result.
                worker.join(timeout=min(2.0, budget.wall_seconds))
                terminated = not worker.is_alive()
                retained = not terminated  # keep the tree as evidence
            exceeded = timed_out or wall > budget.wall_seconds
            token_exceeded = (ctx.usage.tokens_used is not None
                              and ctx.usage.tokens_used > budget.token_budget)
            tool_exceeded = (ctx.usage.tools_used is not None
                             and ctx.usage.tools_used > budget.tool_budget)
            submission_digest = tree_digest(workspace)

            def _mk(outcome, category, reason, **kw):
                res = ArmResult(
                    task.task_id, arm, outcome, category, None,
                    submission_digest, wall, exceeded or token_exceeded
                    or tool_exceeded, False, reason,
                    ctx.usage.tokens_used, ctx.usage.tools_used,
                    terminated, error)
                for k, v in kw.items():
                    object.__setattr__(res, k, v)
                return res

            if timed_out:
                return _mk("error", "timeout", "wall_deadline_exceeded")
            if error is not None:
                return _mk("error", "agent_error", "agent_exception")
            if token_exceeded or tool_exceeded:
                return _mk("error", "budget_exceeded",
                           "token_budget_exceeded" if token_exceeded
                           else "tool_budget_exceeded")
            try:
                receipt = self.verifier.evaluate(
                    actor_role="evaluator",
                    task=task,
                    submission_dir=workspace,
                    evaluation_nonce=f"bench-{task.task_id}-{arm}-" + secrets.token_hex(6),
                    evaluation_scope=f"benchmark-arm:{task.task_id}:{arm}",
                )
            except Exception as exc:
                return ArmResult(
                    task.task_id, arm, "error", "evaluator_error", None,
                    submission_digest, wall, exceeded, False,
                    "evaluation_failed", ctx.usage.tokens_used,
                    ctx.usage.tools_used, terminated,
                    f"evaluation:{str(exc)[:200]}")
            category = "pass" if receipt.outcome == "pass" else (
                "abstained" if receipt.outcome == "abstain" else "fail")
            res = ArmResult(
                task.task_id, arm, receipt.outcome, category, receipt.digest,
                submission_digest, wall, exceeded, False, None,
                ctx.usage.tokens_used, ctx.usage.tools_used, terminated)
            object.__setattr__(res, "valid_solve", _categorize(res))
            return res
        finally:
            if not retained:
                shutil.rmtree(workspace, ignore_errors=True)

    def _report(self, results: list[TaskResult], arms: tuple[str, ...],
                budget: BudgetCaps, seed: str) -> dict:
        per_task = []
        metered_all = {"token": True, "tool": True}
        for task_result in results:
            entry = {"task_id": task_result.task_id,
                     "arm_order": list(task_result.arm_order), "arms": {}}
            for arm, res in task_result.arms.items():
                entry["arms"][arm] = {
                    "outcome": res.outcome,
                    "category": res.category,
                    "valid_solve": res.valid_solve,
                    "receipt_digest": res.receipt_digest,
                    "wall_seconds": f"{res.wall_seconds:.6f}",
                    "budget_exceeded": res.budget_exceeded,
                    "tokens_used": res.tokens_used,
                    "tools_used": res.tools_used,
                    "termination_verified": res.termination_verified,
                    **({"exclusion_reason": res.exclusion_reason}
                       if res.exclusion_reason else {}),
                    **({"error": res.error} if res.error else {}),
                }
                if res.tokens_used is None:
                    metered_all["token"] = False
                if res.tools_used is None:
                    metered_all["tool"] = False
            per_task.append(entry)

        valid = {arm: [t for t in results if t.arms[arm].valid_solve]
                 for arm in arms}
        solved = {arm: len(valid[arm]) for arm in arms}
        raw_pass = {arm: sum(1 for t in results
                             if t.arms[arm].outcome == "pass") for arm in arms}
        excluded = {
            arm: sum(1 for t in results if not t.arms[arm].valid_solve
                     and t.arms[arm].category not in {"pass", "fail"})
            for arm in arms
        }
        walls = {
            arm: sorted(t.arms[arm].wall_seconds for t in results)
            for arm in arms
        }

        def _median(xs):
            if not xs:
                return None
            mid = len(xs) // 2
            v = xs[mid] if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2
            return f"{v:.6f}"

        solve_rates = {
            arm: {"solved": solved[arm], "n": len(results),
                  "excluded": excluded[arm],
                  "wilson_ci95": (
                      [f"{x:.10f}" for x in wilson_ci(solved[arm], len(results))]
                      if results else None),
                  "median_wall_seconds": _median(walls[arm]),
                  "wall_seconds_per_valid_solve": (
                      f"{sum(walls[arm]) / solved[arm]:.6f}"
                      if solved[arm] else None)}
            for arm in arms
        }
        pairs = {}
        for left, right in (("D", "A"), ("D", "B"), ("D", "C"), ("C", "A")):
            if left not in arms or right not in arms:
                continue
            wins = losses = ties = skipped = 0
            for t in results:
                la, ra = t.arms[left], t.arms[right]
                # Pair counts only when BOTH arms produced a valid observation
                # (pass or fail). Excluded arms never win or lose.
                if (la.category not in {"pass", "fail"}
                        or la.budget_exceeded or not la.termination_verified
                        or ra.category not in {"pass", "fail"}
                        or ra.budget_exceeded or not ra.termination_verified):
                    skipped += 1
                    continue
                a, b = la.valid_solve, ra.valid_solve
                wins += a and not b
                losses += b and not a
                ties += a == b
            n = len(results) - skipped
            pairs[f"{left}_vs_{right}"] = {
                "wins": wins, "losses": losses, "ties": ties,
                "pairs_n": n, "excluded_tasks": skipped,
                "solved_delta": wins - losses,
                "mcnemar_exact_p": f"{mcnemar_p(wins, losses):.10f}",
            }
        certified = all(metered_all.values())
        return {
            "schema_version": 2,
            "tasks": len(results),
            "arm_seed": seed,
            "budget": {"wall_seconds": budget.wall_seconds,
                       "token_budget": budget.token_budget,
                       "tool_budget": budget.tool_budget},
            "solved_counts": solved,
            "raw_pass_counts": raw_pass,
            "solve_rates": solve_rates,
            "budget_violations": sum(
                1 for t in results for r in t.arms.values() if r.budget_exceeded
            ),
            "paired": pairs,
            "per_task": per_task,
            "budget_certification": {
                "wall": "enforced",
                "token": "enforced" if metered_all["token"] else "declared_only",
                "tool": "enforced" if metered_all["tool"] else "declared_only",
                "equal_budget_certified": certified,
            },
            "harness_digest": None,
        }


def report_digest(report: Mapping) -> str:
    """Content-address a report for anchoring alongside episode evidence."""
    return canonical_digest("benchmark_report", 2, report)


def wilson_ci(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a binomial rate (honest even at small n)."""
    if type(k) is not int or type(n) is not int or not (0 <= k <= n) or n == 0:
        raise ContractError("wilson_ci requires integers with 0 <= k <= n, n > 0")
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    lo, hi = max(0.0, center - half), min(1.0, center + half)
    if k == 0:
        lo = 0.0
    if k == n:
        hi = 1.0
    return (lo, hi)


def mcnemar_p(b: int, c: int) -> float:
    """Exact two-sided McNemar (binomial sign) p-value on discordant pairs."""
    if type(b) is not int or type(c) is not int or b < 0 or c < 0:
        raise ContractError("mcnemar_p requires nonnegative integer counts")
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # P(X <= k) under Binomial(n, 0.5), doubled and capped at 1.
    cumulative = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2.0 * cumulative)
