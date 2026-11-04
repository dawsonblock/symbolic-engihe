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

import hashlib
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .contracts import canonical_digest
from .governed_eval import GOVERNED_ARMS
from .learning_qualification import (
    CONFIRMATORY,
    EXPLORATORY,
    paired_contrast,
    resource_overhead,
)
from .statistical_power import (
    LineageRegistry,
    PowerRequirement,
    PreregistrationRecord,
    classify,
)

ARMS = tuple(GOVERNED_ARMS)

COMPONENTS = ("memory", "skills", "procedures")

#: The only controlled mapping. B/C/D must isolate *their* component, not
#: merely some singleton subset of E.
_EXPECTED_COMPONENTS = {
    "A": frozenset(),
    "B": frozenset({"memory"}),
    "C": frozenset({"skills"}),
    "D": frozenset({"procedures"}),
    "E": frozenset(COMPONENTS),
}


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
    """Every arm must enable exactly its declared component.

    A subset chain is not enough: B=skills, C=memory, D=procedures is a
    subset chain and a different experiment. The mapping is fixed.
    """
    arms = tuple(config.arm for config in design)
    if arms != ARMS:
        raise CampaignError("design_must_be_A_B_C_D_E", ",".join(arms))
    by_arm = {config.arm: config for config in design}
    for arm in ARMS:
        components = frozenset(by_arm[arm].components)
        if components != _EXPECTED_COMPONENTS[arm]:
            raise CampaignError(
                "arm_component_mapping_invalid",
                f"{arm}={sorted(components)} expected="
                f"{sorted(_EXPECTED_COMPONENTS[arm])}")


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
        if not isinstance(self.protocol, Mapping):
            raise CampaignError("protocol_must_be_an_object")
        if not self.task_ids:
            raise CampaignError("campaign_requires_tasks")
        if len(set(self.task_ids)) != len(self.task_ids):
            raise CampaignError("task_ids_must_be_unique")
        if type(self.seed) is not int:
            raise CampaignError("seed_must_be_an_integer")
        for name in ("max_tokens_per_task", "max_wall_seconds_per_task"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise CampaignError(f"{name}_invalid", str(value))
        if list(self.protocol.get("arms", [])) != list(ARMS):
            raise CampaignError("protocol_arms_do_not_match_the_design")

    @property
    def required_sample_size(self) -> int:
        return self.power_requirement.required_sample_size()

    @property
    def powered(self) -> bool:
        return len(self.task_ids) >= self.required_sample_size

    def arm_order(self, task_id: str | None = None) -> tuple[str, ...]:
        """Deterministic, seed-dependent arm order for one task.

        The order is fixed by the seed and the task, not by wall-clock or
        dictionary order, so a rerun of the same plan runs the same arms
        in the same sequence and a differing result is a real difference.
        The order is recorded per task in the report so an auditor can
        check that the campaign followed the plan.
        """
        # blake2b keys are capped at 64 bytes and a task id may be 256,
        # so the seed/task material is hashed to a fixed-size key first.
        key = hashlib.sha256(f"{self.seed}:{task_id or ''}".encode(
            "utf-8")).digest()
        return tuple(sorted(ARMS, key=lambda arm: hashlib.blake2b(
            arm.encode("utf-8"), digest_size=8, key=key).digest()))

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
            "task_arm_orders": {task_id: list(self.arm_order(task_id))
                                for task_id in self.task_ids},
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
    abstained: bool = False
    negative_transfer: bool = False
    integrity_failures: int = 0
    receipt_id: str | None = None


def build_report(plan: CampaignPlan,
                 outcomes: Iterable[tuple[str, Mapping[str, ArmOutcome]]],
                 *, evidence_class: str = EXPLORATORY,
                 holdout_disjoint: bool = True) -> dict:
    """Assemble the report shape ``analyze_report`` consumes."""
    per_task: list[dict] = []
    totals: dict[str, dict[str, float]] = {
        arm: {"solved": 0, "tokens": 0, "wall": 0.0, "tools": 0, "n": 0,
              "abstained": 0, "negative": 0, "integrity": 0}
        for arm in ARMS
    }
    for task_id, arms in outcomes:
        row = {"task_id": task_id, "arms": {},
               "arm_order": list(plan.arm_order(task_id))}
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
                "receipt_id": outcome.receipt_id,
                "arm_config_digest": canonical_digest(
                    "arm_configuration", 1,
                    next(config for config in plan.design
                         if config.arm == arm).to_dict()),
                "tokens": outcome.tokens,
                "wall_seconds": outcome.wall_seconds,
                "tool_calls": outcome.tool_calls,
            }
            bucket = totals[arm]
            bucket["solved"] += int(solved)
            bucket["tokens"] += outcome.tokens
            bucket["wall"] += outcome.wall_seconds
            bucket["tools"] += outcome.tool_calls
            bucket["abstained"] += int(outcome.abstained)
            bucket["negative"] += int(outcome.negative_transfer)
            bucket["integrity"] += outcome.integrity_failures
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
            "abstention_rate": bucket["abstained"] / n if n else 0.0,
            "negative_transfer_rate": bucket["negative"] / n if n else 0.0,
            "evaluation_integrity_failures": bucket["integrity"],
        }
    return {
        "schema_version": 1,
        "kind": "controlled_five_arm_campaign",
        "protocol_digest": plan.protocol.get("protocol_digest"),
        "plan": plan.to_dict(),
        "plan_digest": canonical_digest("campaign_plan", 1, plan.to_dict()),
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


@dataclass(frozen=True)
class ReportValidation:
    """Whether a report is a complete, internally consistent run."""

    ok: bool
    problems: tuple[str, ...]
    metrics: Mapping


def _recompute_metrics(per_task: Sequence[Mapping]) -> dict:
    """Recompute every metric from row-level outcomes.

    The report's aggregate block is never trusted: a caller that can
    write ``solved_task_rate`` can also write a favourable one.
    """
    totals = {arm: {"solved": 0, "tokens": 0, "wall": 0.0, "tools": 0,
                    "n": 0, "abstained": 0, "negative": 0, "integrity": 0}
              for arm in ARMS}
    for row in per_task:
        for arm in ARMS:
            outcome = row["arms"][arm]
            exceeded = bool(outcome.get("budget_exceeded"))
            solved = bool(outcome.get("valid_solve")) and not exceeded
            bucket = totals[arm]
            bucket["solved"] += int(solved)
            bucket["tokens"] += outcome.get("tokens") or 0
            bucket["wall"] += outcome.get("wall_seconds") or 0.0
            bucket["tools"] += outcome.get("tool_calls") or 0
            bucket["abstained"] += int(bool(outcome.get("abstained")))
            bucket["negative"] += int(bool(outcome.get("negative_transfer")))
            bucket["integrity"] += int(outcome.get("integrity_failures") or 0)
            bucket["n"] += 1
    n = len(per_task)
    return {
        arm: {
            "solved_task_rate": bucket["solved"] / n if n else 0.0,
            "mean_tokens_per_task": bucket["tokens"] / n if n else None,
            "mean_wall_seconds_per_task": bucket["wall"] / n if n else None,
            "mean_tool_calls_per_task": bucket["tools"] / n if n else None,
            "abstention_rate": bucket["abstained"] / n if n else 0.0,
            "negative_transfer_rate": bucket["negative"] / n if n else 0.0,
            "evaluation_integrity_failures": bucket["integrity"],
        }
        for arm, bucket in totals.items()
    }


def validate_report(report: Mapping, plan: CampaignPlan) -> ReportValidation:
    """Check a report against the plan it claims to implement.

    Undeclared, duplicated or missing tasks; missing arms; a reordered
    run; a different arm configuration; a duplicated receipt; mismatched
    budgets or a forged aggregate are all failures. An incomplete run is
    incomplete, not confirmatory.
    """
    problems: list[str] = []
    per_task = report.get("per_task")
    if not isinstance(per_task, list):
        return ReportValidation(False, ("per_task_invalid",), {})
    task_ids = [row.get("task_id") for row in per_task]
    if any(not isinstance(task, str) or not task for task in task_ids):
        problems.append("task_id_invalid")
    if len(set(task_ids)) != len(task_ids):
        problems.append("task_id_duplicated")
    if set(task_ids) != set(plan.task_ids):
        problems.append("task_set_mismatch")
    if len(task_ids) != len(plan.task_ids):
        problems.append("task_count_mismatch")
    receipts: list[str] = []
    for row in per_task:
        task = row.get("task_id")
        arms = row.get("arms")
        if not isinstance(arms, Mapping) or set(arms) != set(ARMS):
            problems.append(f"arm_set_mismatch:{task}")
            continue
        if list(row.get("arm_order") or ()) != list(plan.arm_order(task)):
            problems.append(f"arm_order_mismatch:{task}")
        for arm in ARMS:
            outcome = arms[arm]
            if not isinstance(outcome, Mapping):
                problems.append(f"arm_outcome_invalid:{task}/{arm}")
                continue
            expected = canonical_digest(
                "arm_configuration", 1,
                next(config for config in plan.design
                     if config.arm == arm).to_dict())
            if outcome.get("arm_config_digest") != expected:
                problems.append(f"arm_config_mismatch:{task}/{arm}")
            if outcome.get("budget_exceeded") not in (True, False):
                problems.append(f"budget_flag_invalid:{task}/{arm}")
            receipt = outcome.get("receipt_id")
            if receipt is not None:
                receipts.append(receipt)
    if len(set(receipts)) != len(receipts):
        problems.append("receipt_duplicated")
    declared = report.get("plan") or {}
    if declared.get("seed") != plan.seed:
        problems.append("plan_seed_mismatch")
    if declared.get("protocol_digest") != plan.protocol.get("protocol_digest"):
        problems.append("plan_protocol_mismatch")
    if declared.get("budgets") != plan.to_dict()["budgets"]:
        problems.append("plan_budget_mismatch")
    if report.get("plan_digest") != canonical_digest(
            "campaign_plan", 1, plan.to_dict()):
        problems.append("plan_digest_mismatch")
    if report.get("protocol_digest") != plan.protocol.get("protocol_digest"):
        problems.append("protocol_digest_mismatch")
    metrics = _recompute_metrics(per_task) if not problems else {}
    if metrics and report.get("governed", {}).get("metrics") != metrics:
        problems.append("metrics_mismatch")
    return ReportValidation(not problems, tuple(problems), metrics)


@dataclass(frozen=True)
class AnalysisManifest:
    """The signed analysis inputs a confirmatory claim must be bound to."""

    protocol_digest: str
    preregistration: PreregistrationRecord | None
    lineages: LineageRegistry | None
    first_evaluation_at: str | None
    holdout_repositories: tuple[str, ...] = ()


def assess(report: Mapping, *, plan: CampaignPlan,
           analysis: AnalysisManifest | None = None) -> dict:
    """The E-vs-A verdict, including the after-cost comparison.

    A report that does not validate against its plan is ``invalid_report``.
    ``supported`` additionally requires a signed analysis manifest whose
    preregistration, sample size, timing and lineage separation hold, and
    an input evidence class that is not already exploratory.
    """
    validation = validate_report(report, plan)
    problems = list(validation.problems)
    decisive = paired_contrast(report, baseline="A", treatment="E")
    overhead = resource_overhead(report)
    metrics = validation.metrics or report.get("governed", {}).get(
        "metrics", {})
    a_solved = metrics.get("A", {}).get("solved_task_rate", 0.0)
    e_solved = metrics.get("E", {}).get("solved_task_rate", 0.0)
    a_tokens = overhead.get("A", {}).get("mean_tokens_per_task")
    e_tokens = overhead.get("E", {}).get("mean_tokens_per_task")
    token_ratio = (e_tokens / a_tokens
                   if a_tokens and e_tokens is not None else None)
    # A component arm beating E would mean the integrated system adds
    # complexity without adding capability.
    component_arms = {}
    for arm in ("B", "C", "D"):
        component_arms[arm] = paired_contrast(
            report, baseline=arm, treatment="E")
    observed = len(report.get("per_task", []))
    underpowered = observed < plan.required_sample_size
    evidence_class = EXPLORATORY
    classification = None
    if analysis is None:
        problems.append("analysis_manifest_missing")
    else:
        if analysis.protocol_digest != plan.protocol.get("protocol_digest"):
            problems.append("analysis_protocol_mismatch")
        verdict_obj = classify(
            preregistration=analysis.preregistration,
            observed_sample_size=observed,
            first_evaluation_at=analysis.first_evaluation_at,
            holdout_repositories=analysis.holdout_repositories,
            lineages=analysis.lineages)
        classification = verdict_obj.as_dict()
        problems.extend(verdict_obj.reasons)
        if verdict_obj.ok:
            evidence_class = CONFIRMATORY
    if report.get("evidence_class") in (EXPLORATORY, "demonstration"):
        # An exploratory or demonstration input can never be promoted by
        # a helper downstream.
        evidence_class = EXPLORATORY
        problems.append("input_evidence_not_confirmatory")
    if not validation.ok:
        verdict = "invalid_report"
        evidence_class = "invalid"
    elif not report.get("holdout_disjoint", True):
        verdict = "invalid_holdout"
        evidence_class = "invalid"
    elif decisive["delta"] < 0:
        verdict = "regressed"
    elif decisive["delta"] == 0 or not decisive["significant"]:
        verdict = "no_evidence"
    elif underpowered:
        verdict = "underpowered"
    elif token_ratio is not None and token_ratio > 2.0:
        verdict = "no_advantage_after_cost"
    elif evidence_class != CONFIRMATORY:
        # A significant contrast in an exploratory run is not a claim.
        verdict = "no_evidence"
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
        "observed_sample_size": observed,
        "underpowered": underpowered,
        "budget_exceeded": report.get("budget_exceeded", 0),
        "evidence_class": evidence_class,
        "problems": problems,
        "validation": {"ok": validation.ok,
                       "problems": list(validation.problems)},
        "classification": classification,
        "overhead": overhead,
    }


__all__ = [
    "ARMS",
    "ArmConfiguration",
    "ArmOutcome",
    "COMPONENTS",
    "CampaignError",
    "AnalysisManifest",
    "CampaignPlan",
    "FIVE_ARM_DESIGN",
    "ReportValidation",
    "assess",
    "build_report",
    "validate_design",
    "validate_report",
]
