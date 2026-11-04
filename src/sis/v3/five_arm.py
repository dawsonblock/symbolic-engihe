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
import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from . import signatures
from .contracts import ContractError, EvaluatorReceiptV2, canonical_digest, canonical_json
from .evidence_binding import verify_receipt
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
    verify_preregistration,
)

ARMS = tuple(GOVERNED_ARMS)

COMPONENTS = ("memory", "skills", "procedures")

ANALYSIS_DOMAIN = b"sis-v3:analysis-manifest:1\0"

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
    #: The evaluator's signed measurement. A bare id is not evidence; the
    #: report carries the receipt so ``assess`` can verify it.
    receipt: Mapping | None = None


def _receipt_id(outcome: ArmOutcome) -> str | None:
    if outcome.receipt_id is not None:
        return outcome.receipt_id
    if isinstance(outcome.receipt, Mapping):
        value = outcome.receipt.get("receipt_id")
        return value if isinstance(value, str) else None
    return None


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
    seen_tasks: set[str] = set()
    for task_id, arms in outcomes:
        if task_id not in plan.task_ids:
            raise CampaignError("undeclared_task", task_id)
        if task_id in seen_tasks:
            raise CampaignError("duplicate_task", task_id)
        seen_tasks.add(task_id)
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
                "receipt_id": _receipt_id(outcome),
                "receipt": (dict(outcome.receipt)
                            if isinstance(outcome.receipt, Mapping)
                            else None),
                "arm_config_digest": canonical_digest(
                    "arm_configuration", 1,
                    next(config for config in plan.design
                         if config.arm == arm).to_dict()),
                "tokens": outcome.tokens,
                "wall_seconds": outcome.wall_seconds,
                "tool_calls": outcome.tool_calls,
                "abstained": bool(outcome.abstained),
                "negative_transfer": bool(outcome.negative_transfer),
                "integrity_failures": outcome.integrity_failures,
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
    declared = len(plan.task_ids)
    conforms = bool(holdout_disjoint) and n == declared
    mismatches: list[str] = []
    if not holdout_disjoint:
        mismatches.append("holdout_overlap")
    if n != declared:
        mismatches.append("sample_size_mismatch")
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
                "conforms": conforms,
                "executed_task_count": n,
                "declared_sample_size": declared,
                "mismatches": mismatches,
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
    write ``solved_task_rate`` can also write a favourable one. Resource
    eligibility is recomputed from the numeric values, not from the
    report's ``budget_exceeded`` flag.
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


def _is_int(value) -> bool:
    return type(value) is int


def _is_finite_number(value) -> bool:
    return (type(value) in (int, float)
            and math.isfinite(float(value)))


def _verify_receipt(receipt: Mapping, *, receipt_authority) -> str | None:
    """Return a stable reason when a receipt cannot be authenticated."""
    try:
        record = EvaluatorReceiptV2.from_dict(
            {"schema_version": 1, **dict(receipt)})
    except (ContractError, TypeError, ValueError):
        return "receipt_malformed"
    if receipt_authority is None:
        return None
    try:
        verifier = getattr(receipt_authority, "receipt", None)
        if callable(verifier):
            verifier(record)
        elif callable(receipt_authority):
            if receipt_authority(record) is False:
                return "receipt_rejected"
        else:
            return "receipt_authority_invalid"
    except Exception as exc:  # noqa: BLE001 - fail closed
        return str(getattr(exc, "reason", type(exc).__name__))
    return None


def _validate_outcome(outcome: Mapping, *, plan: CampaignPlan, task: str,
                      arm: str, receipt_authority) -> tuple[list[str], bool]:
    """Check one arm outcome; return (problems, numeric_fields_valid)."""
    problems: list[str] = []
    numeric_ok = True
    valid = outcome.get("valid_solve")
    if type(valid) is not bool:
        problems.append(f"valid_solve_invalid:{task}/{arm}")
        numeric_ok = False
    flag = outcome.get("outcome")
    if flag not in ("pass", "fail"):
        problems.append(f"outcome_invalid:{task}/{arm}")
    tokens = outcome.get("tokens")
    if not _is_int(tokens) or tokens < 0:
        problems.append(f"tokens_invalid:{task}/{arm}")
        numeric_ok = False
    wall = outcome.get("wall_seconds")
    if not _is_finite_number(wall) or wall < 0:
        problems.append(f"wall_seconds_invalid:{task}/{arm}")
        numeric_ok = False
    tools = outcome.get("tool_calls")
    if not _is_int(tools) or tools < 0:
        problems.append(f"tool_calls_invalid:{task}/{arm}")
        numeric_ok = False
    for name in ("abstained", "negative_transfer"):
        if type(outcome.get(name)) is not bool:
            problems.append(f"{name}_invalid:{task}/{arm}")
            numeric_ok = False
    integrity = outcome.get("integrity_failures")
    if not _is_int(integrity) or integrity < 0:
        problems.append(f"integrity_failures_invalid:{task}/{arm}")
        numeric_ok = False

    exceeded = None
    if numeric_ok:
        exceeded = (tokens > plan.max_tokens_per_task
                    or wall > plan.max_wall_seconds_per_task)
    budget_flag = outcome.get("budget_exceeded")
    if type(budget_flag) is not bool:
        problems.append(f"budget_flag_invalid:{task}/{arm}")
        numeric_ok = False
    elif exceeded is not None and budget_flag != exceeded:
        # A report may not edit the flag to turn an over-budget run into
        # a solve; the numeric values decide eligibility.
        problems.append(f"budget_flag_mismatch:{task}/{arm}")
        numeric_ok = False

    if type(valid) is bool and flag in ("pass", "fail") and exceeded is not None:
        expected = "pass" if (valid and not exceeded) else "fail"
        if flag != expected:
            problems.append(f"outcome_conflict:{task}/{arm}")
            numeric_ok = False

    receipt_id = outcome.get("receipt_id")
    receipt = outcome.get("receipt")
    if not (isinstance(receipt_id, str) and receipt_id):
        problems.append(f"receipt_missing:{task}/{arm}")
    if not isinstance(receipt, Mapping):
        problems.append(f"receipt_missing:{task}/{arm}")
        return problems, numeric_ok
    if receipt.get("receipt_id") != receipt_id:
        problems.append(f"receipt_id_mismatch:{task}/{arm}")
    if receipt.get("task_id") != task:
        problems.append(f"receipt_task_mismatch:{task}/{arm}")
    if receipt.get("result") not in ("pass", "fail"):
        problems.append(f"receipt_result_invalid:{task}/{arm}")
    if type(valid) is bool and receipt.get("result") in ("pass", "fail"):
        if valid and receipt.get("result") != "pass":
            problems.append(f"receipt_result_conflict:{task}/{arm}")
        if (not valid and receipt.get("result") == "pass"
                and exceeded is False):
            problems.append(f"receipt_result_conflict:{task}/{arm}")
    reason = _verify_receipt(receipt, receipt_authority=receipt_authority)
    if reason is not None:
        problems.append(f"receipt_untrusted:{task}/{arm}:{reason}")
    return problems, numeric_ok


def validate_report(report: Mapping, plan: CampaignPlan, *,
                    receipt_authority=None) -> ReportValidation:
    """Check a report against the plan it claims to implement.

    Undeclared, duplicated or missing tasks; missing arms; a reordered
    run; a different arm configuration; a duplicated or absent receipt;
    modified budget flags; malformed or non-finite numbers; conflicting
    outcomes; mismatched budgets and a forged aggregate are all failures.
    An incomplete run is incomplete, not confirmatory.
    """
    if not isinstance(report, Mapping):
        return ReportValidation(False, ("report_invalid",), {})
    problems: list[str] = []
    if report.get("schema_version") != 1:
        problems.append("schema_version_invalid")
    if report.get("kind") != "controlled_five_arm_campaign":
        problems.append("report_kind_invalid")
    if report.get("evidence_class") not in (
            EXPLORATORY, "demonstration", CONFIRMATORY):
        problems.append("evidence_class_invalid")
    per_task = report.get("per_task")
    if not isinstance(per_task, list):
        return ReportValidation(False, ("per_task_invalid",), {})
    task_ids = [row.get("task_id") if isinstance(row, Mapping) else None
                for row in per_task]
    if any(not isinstance(task, str) or not task for task in task_ids):
        problems.append("task_id_invalid")
    if len(set(task_ids)) != len(task_ids):
        problems.append("task_id_duplicated")
    if set(task_ids) != set(plan.task_ids):
        problems.append("task_set_mismatch")
    if len(task_ids) != len(plan.task_ids):
        problems.append("task_count_mismatch")
    receipts: list[str] = []
    numeric_ok = True
    for row in per_task:
        if not isinstance(row, Mapping):
            problems.append("task_row_invalid")
            numeric_ok = False
            continue
        task = row.get("task_id")
        arms = row.get("arms")
        if not isinstance(arms, Mapping) or set(arms) != set(ARMS):
            problems.append(f"arm_set_mismatch:{task}")
            numeric_ok = False
            continue
        if not isinstance(task, str):
            numeric_ok = False
            continue
        if list(row.get("arm_order") or ()) != list(plan.arm_order(task)):
            problems.append(f"arm_order_mismatch:{task}")
        for arm in ARMS:
            outcome = arms[arm]
            if not isinstance(outcome, Mapping):
                problems.append(f"arm_outcome_invalid:{task}/{arm}")
                numeric_ok = False
                continue
            expected = canonical_digest(
                "arm_configuration", 1,
                next(config for config in plan.design
                     if config.arm == arm).to_dict())
            if outcome.get("arm_config_digest") != expected:
                problems.append(f"arm_config_mismatch:{task}/{arm}")
            found, outcome_numeric_ok = _validate_outcome(
                outcome, plan=plan, task=task, arm=arm,
                receipt_authority=receipt_authority)
            problems.extend(found)
            numeric_ok = numeric_ok and outcome_numeric_ok
            receipt_id = outcome.get("receipt_id")
            if isinstance(receipt_id, str) and receipt_id:
                receipts.append(receipt_id)
    if len(set(receipts)) != len(receipts):
        problems.append("receipt_duplicated")
    declared = report.get("plan")
    if not isinstance(declared, Mapping):
        problems.append("plan_block_invalid")
    else:
        if declared.get("seed") != plan.seed:
            problems.append("plan_seed_mismatch")
        if declared.get("protocol_digest") != plan.protocol.get(
                "protocol_digest"):
            problems.append("plan_protocol_mismatch")
        if declared.get("budgets") != plan.to_dict()["budgets"]:
            problems.append("plan_budget_mismatch")
        if declared != plan.to_dict():
            problems.append("plan_block_mismatch")
    if report.get("plan_digest") != canonical_digest(
            "campaign_plan", 1, plan.to_dict()):
        problems.append("plan_digest_mismatch")
    if report.get("protocol_digest") != plan.protocol.get("protocol_digest"):
        problems.append("protocol_digest_mismatch")

    metrics = {}
    if numeric_ok and not any(
            problem.startswith(("task_id_", "task_set_", "task_count_",
                                "task_row_", "arm_set_", "arm_outcome_"))
            for problem in problems):
        metrics = _recompute_metrics(per_task)
        governed = report.get("governed")
        if not isinstance(governed, Mapping):
            problems.append("governed_block_invalid")
        else:
            if governed.get("metrics") != metrics:
                problems.append("metrics_mismatch")
            declared_count = len(plan.task_ids)
            executed = len(per_task)
            conforms = bool(report.get("holdout_disjoint")) and \
                executed == declared_count
            mismatches = []
            if not report.get("holdout_disjoint"):
                mismatches.append("holdout_overlap")
            if executed != declared_count:
                mismatches.append("sample_size_mismatch")
            expected_conformance = {
                "conforms": conforms,
                "executed_task_count": executed,
                "declared_sample_size": declared_count,
                "mismatches": mismatches,
            }
            if governed.get("conformance") != expected_conformance:
                problems.append("conformance_mismatch")
        expected_budget = sum(
            1 for row in per_task for arm in ARMS
            if row["arms"][arm].get("budget_exceeded") is True)
        if report.get("budget_exceeded") != expected_budget:
            problems.append("budget_exceeded_mismatch")
    return ReportValidation(not problems, tuple(problems), metrics)


@dataclass(frozen=True)
class AnalysisManifest:
    """The signed analysis inputs a confirmatory claim must be bound to.

    A bare dataclass is not an authority. ``signature`` covers the
    protocol, the preregistration digest, the first-evaluation instant,
    the holdout repositories and the full lineage map, so an attacker
    cannot keep a valid preregistration and rewrite the timing or the
    holdout set that the verdict depends on.
    """

    protocol_digest: str
    preregistration: PreregistrationRecord | None
    lineages: LineageRegistry | None
    first_evaluation_at: str | None
    holdout_repositories: tuple[str, ...] = ()
    signer_key_id: str | None = None
    signature: str | None = None

    def body(self) -> bytes:
        preregistration = self.preregistration
        lineages = (list(self.lineages.entries())
                    if self.lineages is not None else None)
        return ANALYSIS_DOMAIN + canonical_json({
            "schema_version": 1,
            "protocol_digest": self.protocol_digest,
            "preregistration": (preregistration.digest
                                if preregistration is not None else None),
            "first_evaluation_at": self.first_evaluation_at,
            "holdout_repositories": list(self.holdout_repositories),
            "lineages": lineages,
        })

    def sign(self, seed: bytes, key_id: str) -> "AnalysisManifest":
        from dataclasses import replace
        if len(seed) != 32:
            raise CampaignError("analysis_seed_malformed")
        if not isinstance(key_id, str) or not key_id:
            raise CampaignError("analysis_signer_key_id_invalid")
        return replace(self, signer_key_id=key_id,
                       signature=signatures.sign(seed, self.body()).hex())

    def verify(self, public_hex: str) -> bool:
        if not isinstance(self.signature, str):
            return False
        try:
            return signatures.verify(bytes.fromhex(self.signature),
                                     self.body(),
                                     bytes.fromhex(public_hex))
        except (ValueError, TypeError):
            return False


def sign_analysis_manifest(seed: bytes, *, key_id: str,
                           **fields) -> AnalysisManifest:
    """Sign the analysis inputs; the only path to a confirmatory verdict."""
    return AnalysisManifest(**fields).sign(seed, key_id)


def assess(report: Mapping, *, plan: CampaignPlan,
           analysis: AnalysisManifest | None = None,
           receipt_authority=None,
           trusted_analysis_keys: Mapping[str, str] | None = None,
           trusted_timestamp_keys: Mapping[str, str] | None = None) -> dict:
    """The E-vs-A verdict, including the after-cost comparison.

    A report that does not validate against its plan is ``invalid_report``.
    ``supported`` additionally requires every arm outcome to carry an
    evaluator receipt authenticated by ``receipt_authority``, and a
    signed analysis manifest whose signature and preregistration both
    verify against configured trust roots. A self-declared
    ``confirmatory`` label in the report is never sufficient.
    """
    validation = validate_report(report, plan,
                                 receipt_authority=receipt_authority)
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
    analysis_verified = False
    preregistration_verified = False
    if receipt_authority is None:
        problems.append("receipt_authority_missing")
    if analysis is None:
        problems.append("analysis_manifest_missing")
    else:
        if analysis.protocol_digest != plan.protocol.get("protocol_digest"):
            problems.append("analysis_protocol_mismatch")
        if analysis.signature is None:
            problems.append("analysis_manifest_unsigned")
        elif not trusted_analysis_keys:
            problems.append("analysis_trust_root_missing")
        else:
            public = trusted_analysis_keys.get(analysis.signer_key_id)
            if public is None:
                problems.append("analysis_signer_untrusted")
            elif not analysis.verify(public):
                problems.append("analysis_signature_invalid")
            else:
                analysis_verified = True
        preregistration = analysis.preregistration
        if preregistration is None:
            problems.append("preregistration_missing")
        elif not trusted_timestamp_keys:
            problems.append("timestamp_trust_root_missing")
        else:
            public = trusted_timestamp_keys.get(
                preregistration.signer_key_id)
            if public is None:
                problems.append("timestamp_authority_untrusted")
            elif not verify_preregistration(preregistration, public):
                problems.append("preregistration_signature_invalid")
            else:
                preregistration_verified = True
        verdict_obj = classify(
            preregistration=analysis.preregistration,
            observed_sample_size=observed,
            first_evaluation_at=analysis.first_evaluation_at,
            holdout_repositories=analysis.holdout_repositories,
            lineages=analysis.lineages)
        classification = verdict_obj.as_dict()
        for reason in verdict_obj.reasons:
            if reason not in problems:
                problems.append(reason)
        if (verdict_obj.ok and analysis_verified
                and preregistration_verified):
            evidence_class = CONFIRMATORY
    if report.get("evidence_class") in (EXPLORATORY, "demonstration"):
        # An exploratory or demonstration input can never be promoted by
        # a helper downstream.
        evidence_class = EXPLORATORY
        problems.append("input_evidence_not_confirmatory")
    receipts_verified = (receipt_authority is not None
                         and validation.ok
                         and not any(problem.startswith("receipt_")
                                     for problem in problems))
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
    elif evidence_class != CONFIRMATORY or not receipts_verified:
        # A significant contrast without verified receipts, a signed
        # analysis and a valid preregistration is not a claim.
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
        "receipts_verified": receipts_verified,
        "analysis_verified": analysis_verified,
        "preregistration_verified": preregistration_verified,
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
    "sign_analysis_manifest",
    "validate_design",
    "validate_report",
]
