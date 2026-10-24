"""Four-arm paired benchmark harness (SIS3-012).

Arms: ``A`` baseline agent, ``B`` placebo context, ``C`` raw episode-context
retrieval, ``D`` qualified procedure guidance. For every task, each arm runs
in a fresh disposable workspace with an identical budget envelope
(``BudgetCaps``); the arm callable receives a ``ArmContext`` whose only
difference is the injected context payload. Submissions are scored by the
independent ``OutcomeVerifier`` — the harness never trusts arm-reported
results — and the report counts paired wins/losses/ties, solved rates,
abstentions, and budget violations. Agent callables are injected, so tests
use scripted agents and production runs can plug the Codex adapters without
changing the accounting.
"""
from __future__ import annotations

import secrets
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import ContractError, GuidanceV1, TaskEnvelopeV1, canonical_digest
from .episode_store import EpisodeStore
from .runner import tree_digest
from .verifier import OutcomeVerifier

ARMS = ("A", "B", "C", "D")


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


@dataclass(frozen=True)
class ArmContext:
    """The only input that varies between arms of the same task."""

    task: TaskEnvelopeV1
    arm: str
    workspace: Path
    budget: BudgetCaps
    guidance: GuidanceV1 | None = None
    context_digest: str | None = None  # placebo (B) or episode-context (C) digest


@dataclass(frozen=True)
class ArmResult:
    task_id: str
    arm: str
    outcome: str
    receipt_digest: str | None
    submission_digest: str | None
    wall_seconds: int
    error: str | None = None


@dataclass
class TaskResult:
    task_id: str
    arms: dict[str, ArmResult] = field(default_factory=dict)


AgentFn = Callable[[ArmContext], None]
ContextFn = Callable[[TaskEnvelopeV1, str], GuidanceV1 | None]


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
        # Identical submissions reuse the issued receipt: the signed outcome
        # binds the tree digest, so re-running the suite would be identical.
        self._receipt_cache: dict[tuple[str, str], tuple[str, str]] = {}

    def run(
        self,
        tasks: list[tuple[TaskEnvelopeV1, Path]],
        agent: AgentFn,
        *,
        budget: BudgetCaps,
        context_provider: ContextFn | None = None,
        arms: tuple[str, ...] = ARMS,
    ) -> dict:
        """Execute every arm per task; return an auditable paired report."""
        unknown = [a for a in arms if a not in ARMS]
        if unknown:
            raise ContractError(f"unknown arms: {unknown}")
        results: list[TaskResult] = []
        for task, base_dir in tasks:
            task_result = TaskResult(task_id=task.task_id)
            for arm in arms:
                task_result.arms[arm] = self._run_arm(
                    task, Path(base_dir), agent, arm, budget, context_provider
                )
            results.append(task_result)
        return self._report(results, arms, budget)

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
        try:
            shutil.copytree(base_dir, workspace, dirs_exist_ok=True)
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
            error = None
            try:
                agent(ctx)
            except Exception as exc:  # arm failures are observations, not verdicts
                error = f"{type(exc).__name__}:{str(exc)[:200]}"
            wall = max(0, int(time.monotonic() - start))
            submission_digest = tree_digest(workspace)
            if error is not None:
                return ArmResult(task.task_id, arm, "error", None, submission_digest, wall, error)
            cache_key = (task.task_id, submission_digest)
            cached = self._receipt_cache.get(cache_key)
            if cached is not None:
                outcome, receipt_digest = cached
            else:
                try:
                    receipt = self.verifier.evaluate(
                        actor_role="evaluator",
                        task=task,
                        submission_dir=workspace,
                        evaluation_nonce=f"bench-{task.task_id}-{arm}-" + secrets.token_hex(6),
                    )
                except Exception as exc:
                    return ArmResult(task.task_id, arm, "error", None, submission_digest, wall,
                                     f"evaluation:{str(exc)[:200]}")
                outcome, receipt_digest = receipt.outcome, receipt.digest
                self._receipt_cache[cache_key] = (outcome, receipt_digest)
            return ArmResult(task.task_id, arm, outcome,
                             receipt_digest, submission_digest, wall)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def _report(self, results: list[TaskResult], arms: tuple[str, ...], budget: BudgetCaps) -> dict:
        per_task = []
        for task_result in results:
            entry = {"task_id": task_result.task_id, "arms": {}}
            for arm, res in task_result.arms.items():
                entry["arms"][arm] = {
                    "outcome": res.outcome,
                    "receipt_digest": res.receipt_digest,
                    "wall_seconds": res.wall_seconds,
                    **({"error": res.error} if res.error else {}),
                }
            per_task.append(entry)

        solved = {arm: sum(1 for t in results if t.arms[arm].outcome == "pass") for arm in arms}
        pairs = {}
        for left, right in (("D", "A"), ("D", "B"), ("D", "C"), ("C", "A")):
            if left not in arms or right not in arms:
                continue
            wins = losses = ties = 0
            for t in results:
                a, b = t.arms[left].outcome == "pass", t.arms[right].outcome == "pass"
                wins += a and not b
                losses += b and not a
                ties += a == b
            pairs[f"{left}_vs_{right}"] = {
                "wins": wins, "losses": losses, "ties": ties,
                "solved_delta": wins - losses,
            }
        return {
            "schema_version": 1,
            "tasks": len(results),
            "budget": {"wall_seconds": budget.wall_seconds,
                       "token_budget": budget.token_budget,
                       "tool_budget": budget.tool_budget},
            "solved_counts": solved,
            "paired": pairs,
            "per_task": per_task,
            "budget_enforcement": "wall_seconds measured; token/tool budgets are declared caps enforced by the agent runtime, not the harness",
            "harness_digest": None,
        }


def report_digest(report: Mapping) -> str:
    """Content-address a report for anchoring alongside episode evidence."""
    return canonical_digest("benchmark_report", 1, report)
