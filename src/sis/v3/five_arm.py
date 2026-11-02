"""Controlled five-arm benchmark (PR-10).

The five arms must differ only in the component under test:

    A  Codex alone
    B  Codex + memory
    C  Codex + qualified skills
    D  Codex + symbolic procedures
    E  Codex + complete SIS

Without a manifest saying exactly which components each arm enabled, a
"five-arm" run is five different experiments and the E-vs-A contrast
measures packaging rather than capability. ``ComponentManifest`` makes the
configuration explicit and ``validate_design`` refuses a run whose arms
are not a subset chain.

``assess`` then answers the question the benchmark exists for: did E solve
more independently graded tasks than A, and did it still do so after the
extra tokens and latency are counted? A higher solve rate at a much higher
token cost, with overlapping intervals, is reported as no demonstrated
advantage.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .governed_eval import GOVERNED_ARMS
from .learning_qualification import (
    CONFIRMATORY,
    EXPLORATORY,
    paired_contrast,
    resource_overhead,
)
from .statistical_power import PowerRequirement

ARMS = tuple(GOVERNED_ARMS)

COMPONENTS = ("memory", "skills", "procedures")


class CampaignError(RuntimeError):
    """The campaign design is not a controlled five-arm comparison."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class ArmConfiguration:
    """One arm's declared component set."""

    arm: str
    label: str
    memory: bool = False
    skills: bool = False
    procedures: bool = False

    def __post_init__(self) -> None:
        if self.arm not in ARMS:
            raise CampaignError("arm_unknown", self.arm)
        if not self.label:
            raise CampaignError("arm_label_required", self.arm)

    @property
    def components(self) -> tuple[str, ...]:
        return tuple(name for name in COMPONENTS if getattr(self, name))

    @property
    def integrated(self) -> bool:
        return len(self.components) == len(COMPONENTS)

    def to_dict(self) -> dict:
        return {
            "arm": self.arm,
            "label": self.label,
            "components": list(self.components),
            "integrated": self.integrated,
        }


FIVE_ARM_DESIGN: tuple[ArmConfiguration, ...] = (
    ArmConfiguration(arm="A", label="codex_alone"),
    ArmConfiguration(arm="B", label="codex_memory", memory=True),
    ArmConfiguration(arm="C", label="codex_skills", skills=True),
    ArmConfiguration(arm="D", label="codex_procedures", procedures=True),
    ArmConfiguration(arm="E", label="codex_complete_sis", memory=True,
                     skills=True, procedures=True),
)


def validate_design(design: Sequence[ArmConfiguration] = FIVE_ARM_DESIGN
                    ) -> None:
    """Every arm must be a subset of E and differ from A by its component."""
    arms = tuple(config.arm for config in design)
    if arms != ARMS:
        raise CampaignError("design_must_be_A_B_C_D_E", ",".join(arms))
    by_arm = {config.arm: config for config in design}
    if by_arm["A"].components:
        raise CampaignError("baseline_arm_must_be_bare")
    integrated = set(by_arm["E"].components)
    if integrated != set(COMPONENTS):
        raise CampaignError("integrated_arm_must_enable_everything")
    for arm in ("B", "C", "D"):
        components = set(by_arm[arm].components)
        if len(components) != 1:
            raise CampaignError("component_arm_must_isolate_one_component",
                                arm)
        if not components <= integrated:
            raise CampaignError("component_arm_not_subset_of_E", arm)
    for arm in ARMS:
        config = by_arm[arm]
        if arm != "A" and not config.components:
            raise CampaignError("component_arm_is_empty", arm)


@dataclass(frozen=True)
class CampaignPlan:
    """A preregistered, seeded, budgeted five-arm run."""

    protocol: Mapping
    power_requirement: PowerRequirement
    task_ids: tuple[str, ...]
    seed: int
    design: tuple[ArmConfiguration, ...] = FIVE_ARM_DESIGN
    max_tokens_per_task: int = 100_000
    max_wall_seconds_per_task: int = 600

    def __post_init__(self) -> None:
        validate_design(self.design)
        if not self.task_ids:
            raise CampaignError("campaign_requires_tasks")
        if len(set(self.task_ids)) != len(self.task_ids):
            raise CampaignError("task_ids_must_be_unique")
        if type(self.seed) is not int:
            raise CampaignError("seed_must_be_an_integer")
        if list(self.protocol.get("arms", [])) != list(ARMS):
            raise CampaignError("protocol_arms_do_not_match_the_design")

    @property
    def required_sample_size(self) -> int:
        return self.power_requirement.required_sample_size()

    @property
    def powered(self) -> bool:
        return len(self.task_ids) >= self.required_sample_size

    def arm_order(self) -> tuple[str, ...]:
        """Deterministic, seed-dependent arm order per task.

        The order is fixed by the seed rather than by wall-clock or
        dictionary order, so a rerun of the same plan runs the same arms
        in the same sequence and a differing result is a real difference.
        """
        return tuple(sorted(
            ARMS, key=lambda arm: ((self.seed * 2654435761) ^ ord(arm))
            % 1_000_003))

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "protocol_digest": self.protocol.get("protocol_digest"),
            "power_requirement": self.power_requirement.to_dict(),
            "required_sample_size": self.required_sample_size,
            "task_count": len(self.task_ids),
            "powered": self.powered,
            "seed": self.seed,
            "arms": [config.to_dict() for config in self.design],
            "arm_order": list(self.arm_order()),
            "budgets": {
                "max_tokens_per_task": self.max_tokens_per_task,
                "max_wall_seconds_per_task": self.max_wall_seconds_per_task,
            },
        }


@dataclass(frozen=True)
class ArmOutcome:
    arm: str
    valid_solve: bool
    tokens: int
    wall_seconds: float
    tool_calls: int = 0


def build_report(plan: CampaignPlan,
                 outcomes: Iterable[tuple[str, Mapping[str, ArmOutcome]]],
                 *, evidence_class: str = EXPLORATORY,
                 holdout_disjoint: bool = True) -> dict:
    """Assemble the report shape ``analyze_report`` consumes."""
    per_task: list[dict] = []
    totals: dict[str, dict[str, float]] = {
        arm: {"solved": 0, "tokens": 0, "wall": 0.0, "tools": 0, "n": 0}
        for arm in ARMS
    }
    for task_id, arms in outcomes:
        row = {"task_id": task_id, "arms": {}}
        for arm in ARMS:
            outcome = arms.get(arm)
            if outcome is None:
                raise CampaignError("missing_arm_outcome", f"{task_id}/{arm}")
            exceeded = (outcome.tokens > plan.max_tokens_per_task
                        or outcome.wall_seconds >
                        plan.max_wall_seconds_per_task)
            # A run that blew its declared budget did not solve the task
            # inside the envelope the campaign was powered for; counting
            # it as a solve is exactly the "more expensive answer" the
            # verdict is supposed to catch.
            solved = bool(outcome.valid_solve) and not exceeded
            row["arms"][arm] = {
                "outcome": "pass" if solved else "fail",
                "valid_solve": solved,
                "budget_exceeded": exceeded,
                "error": None,
                "tokens": outcome.tokens,
                "wall_seconds": outcome.wall_seconds,
                "tool_calls": outcome.tool_calls,
            }
            bucket = totals[arm]
            bucket["solved"] += int(solved)
            bucket["tokens"] += outcome.tokens
            bucket["wall"] += outcome.wall_seconds
            bucket["tools"] += outcome.tool_calls
            bucket["n"] += 1
        per_task.append(row)
    n = len(per_task)
    metrics = {}
    for arm, bucket in totals.items():
        metrics[arm] = {
            "solved_task_rate": bucket["solved"] / n if n else 0.0,
            "mean_tokens_per_task": bucket["tokens"] / n if n else None,
            "mean_wall_seconds_per_task": bucket["wall"] / n if n else None,
            "mean_tool_calls_per_task": bucket["tools"] / n if n else None,
            "abstention_rate": 0.0,
            "negative_transfer_rate": 0.0,
            "evaluation_integrity_failures": 0,
        }
    return {
        "schema_version": 1,
        "kind": "controlled_five_arm_campaign",
        "protocol_digest": plan.protocol.get("protocol_digest"),
        "plan": plan.to_dict(),
        "holdout_disjoint": holdout_disjoint,
        "per_task": per_task,
        "governed": {
            "metrics": metrics,
            "conformance": {
                "conforms": holdout_disjoint,
                "executed_task_count": n,
                "declared_sample_size": len(plan.task_ids),
                "mismatches": [] if holdout_disjoint else ["holdout_overlap"],
            },
        },
        "evidence_class": evidence_class,
        "budget_exceeded": sum(
            1 for row in per_task for arm in ARMS
            if row["arms"][arm]["budget_exceeded"]),
    }


def assess(report: Mapping, *, plan: CampaignPlan) -> dict:
    """The E-vs-A verdict, including the after-cost comparison."""
    decisive = paired_contrast(report, baseline="A", treatment="E")
    overhead = resource_overhead(report)
    a_solved = report["governed"]["metrics"]["A"]["solved_task_rate"]
    e_solved = report["governed"]["metrics"]["E"]["solved_task_rate"]
    a_tokens = overhead["A"]["mean_tokens_per_task"]
    e_tokens = overhead["E"]["mean_tokens_per_task"]
    token_ratio = (e_tokens / a_tokens
                   if a_tokens and e_tokens is not None else None)
    # A component arm beating E would mean the integrated system adds
    # complexity without adding capability.
    component_arms = {}
    for arm in ("B", "C", "D"):
        component_arms[arm] = paired_contrast(
            report, baseline=arm, treatment="E")
    underpowered = len(report["per_task"]) < plan.required_sample_size
    if not report.get("holdout_disjoint", True):
        verdict = "invalid_holdout"
    elif decisive["delta"] < 0:
        verdict = "regressed"
    elif decisive["delta"] == 0 or not decisive["significant"]:
        verdict = "no_evidence"
    elif underpowered:
        verdict = "underpowered"
    elif token_ratio is not None and token_ratio > 2.0:
        # Same-or-better solve rate at more than twice the tokens is not
        # a demonstrated advantage; it is a more expensive way to reach
        # the same answer.
        verdict = "no_advantage_after_cost"
    else:
        verdict = "supported"
    return {
        "schema_version": 1,
        "verdict": verdict,
        "decisive_contrast": decisive,
        "component_contrasts": component_arms,
        "solve_rate": {"A": a_solved, "E": e_solved},
        "mean_tokens": {"A": a_tokens, "E": e_tokens},
        "token_ratio": token_ratio,
        "required_sample_size": plan.required_sample_size,
        "observed_sample_size": len(report["per_task"]),
        "underpowered": underpowered,
        "budget_exceeded": report.get("budget_exceeded", 0),
        "evidence_class": (CONFIRMATORY if not underpowered
                           and report.get("holdout_disjoint", True)
                           else EXPLORATORY),
        "overhead": overhead,
    }


__all__ = [
    "ARMS",
    "ArmConfiguration",
    "ArmOutcome",
    "COMPONENTS",
    "CampaignError",
    "CampaignPlan",
    "FIVE_ARM_DESIGN",
    "assess",
    "build_report",
    "validate_design",
]
