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
from .trial_evidence import (
    ExperimentAuthorizationV2,
    TrialEvidenceError,
    TrialMeasurementV1,
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
    #: The evaluator's signed *trial* record: which arm, which model,
    #: which task digest, and what the run cost. Without it the report
    #: cannot say that a receipt belongs to this arm, and cannot defend
    #: the numbers the verdict is computed from.
    measurement: Mapping | None = None
    #: Limits the run is reported to have hit. They are signed in the
    #: measurement; this field lets the report carry the same claim so a
    #: genuine over-limit run is a non-solve, not an inconsistent report.
    limit_violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        violations = self.limit_violations
        if not isinstance(violations, (list, tuple)):
            raise CampaignError("limit_violations_invalid", self.arm)
        object.__setattr__(self, "limit_violations", tuple(violations))


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
                        plan.max_wall_seconds_per_task
                        or bool(outcome.limit_violations))
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
                "measurement": (dict(outcome.measurement)
                                if isinstance(outcome.measurement, Mapping)
                                else None),
                "limit_violations": list(outcome.limit_violations),
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
    """Whether a report is a complete, internally consistent run.

    ``verified`` is the authenticated view of the run, rebuilt from the
    evaluator-signed measurements rather than from the report's own
    numbers. It is ``None`` when no measurement could be authenticated,
    which is the only correct answer for a legacy report: such a report
    may be analysed exploratorily but never promoted.
    """

    ok: bool
    problems: tuple[str, ...]
    metrics: Mapping
    verified: Mapping | None = None
    #: Whether the report's chain was authenticated, not merely parsed.
    #: ``ok`` is structural; a caller that needs evidence must check this.
    authenticated: bool = False


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
    # ``float(10**400)`` raises OverflowError, so an arbitrarily large
    # integer in an untrusted report would crash the validator instead of
    # being rejected. Integers are finite by construction; only floats
    # need the check.
    if type(value) is int:
        return True
    return type(value) is float and math.isfinite(value)


def _reported_wall_milli(value) -> int | None:
    """The report's wall time in whole milliseconds, or ``None``.

    ``round()`` is banker's rounding, so a wall time of exactly
    ``x.xxx5`` seconds would round to the even millisecond and reject an
    honest report. Half-up matches how an evaluator writing
    ``int(seconds * 1000)`` reports the same run.
    """
    if type(value) is int:
        return value * 1000
    if type(value) is float and math.isfinite(value):
        scaled = value * 1000
        if math.isfinite(scaled):
            return math.floor(scaled + 0.5)
        # ``1e308`` is finite but its millisecond value is not; it cannot
        # name any measured duration, and ``math.floor(inf)`` would raise.
        return -1
    return None


def _verify_receipt(receipt: Mapping, *, receipt_authority,
                    now: str | None = None,
                    allow_expired: bool = False) -> str | None:
    """Return a stable reason when a receipt cannot be authenticated."""
    try:
        record = EvaluatorReceiptV2.from_dict(
            {"schema_version": 1, **dict(receipt)})
    except (ContractError, TypeError, ValueError):
        return "receipt_malformed"
    if receipt_authority is None:
        return None
    try:
        verifier = getattr(receipt_authority, "authenticated_receipt", None)
        if callable(verifier):
            verifier(record, now=now, allow_expired=allow_expired)
        else:
            verifier = getattr(receipt_authority, "receipt", None)
            if callable(verifier):
                verifier(record)
            elif callable(receipt_authority):
                # A predicate is only a rejection if it says so. Every
                # other falsy return (None, 0, "", []) is not evidence of
                # success, so it must fail closed too.
                if not receipt_authority(record):
                    return "receipt_rejected"
            else:
                return "receipt_authority_invalid"
    except Exception as exc:  # noqa: BLE001 - fail closed
        return str(getattr(exc, "reason", type(exc).__name__))
    return None


def _arm_configuration(plan: CampaignPlan, arm: str) -> ArmConfiguration:
    return next(config for config in plan.design if config.arm == arm)


def _arm_config_digest(plan: CampaignPlan, arm: str) -> str:
    return canonical_digest("arm_configuration", 1,
                            _arm_configuration(plan, arm).to_dict())


def _verify_experiment_authorization(
        authorization, *, authority, plan: CampaignPlan,
        now: str | None, allow_expired: bool,
) -> tuple[ExperimentAuthorizationV2 | None, list[str]]:
    """Authenticate the experiment and check it describes this plan.

    The authorization is the only place the assessment learns which arm
    configuration, model and task content were legitimate, so every one
    of those comparisons happens here rather than in the report.
    """
    if authorization is None:
        return None, []
    problems: list[str] = []
    if not isinstance(authorization, ExperimentAuthorizationV2):
        try:
            authorization = ExperimentAuthorizationV2.from_dict(authorization)
        except (TrialEvidenceError, ContractError, TypeError, ValueError):
            return None, ["experiment_authorization_malformed"]
    verifier = getattr(authority, "experiment_authorization", None)
    if authority is None or not callable(verifier):
        # No trust root means nothing here is authenticated. That is a
        # qualification failure, not a malformed report, so it is
        # reported by ``assess`` rather than as a validation problem.
        return None, []
    try:
        verified = verifier(authorization)
    except Exception as exc:  # noqa: BLE001 - fail closed
        return None, ["experiment_authorization_untrusted:"
                      + str(getattr(exc, "reason", type(exc).__name__))]
    validity = getattr(authority, "validity", None)
    if callable(validity):
        try:
            reasons = validity(
                signer_key_id=verified.signer_key_id,
                digest=verified.digest, issued_at=verified.issued_at,
                expires_at=verified.expires_at, now=now,
                allow_expired=allow_expired)
        except Exception as exc:  # noqa: BLE001 - fail closed
            reasons = ("validity_error:" + type(exc).__name__,)
        for reason in reasons:
            problems.append("experiment_authorization_invalid:" + reason)
    if verified.protocol_digest != plan.protocol.get("protocol_digest"):
        problems.append("experiment_protocol_mismatch")
    if verified.plan_digest != canonical_digest(
            "campaign_plan", 1, plan.to_dict()):
        # Budgets, seed, arm order, task mapping and the power
        # requirement live in the plan. An authorization for a different
        # plan is a different experiment, even when every signed
        # measurement still names this one.
        problems.append("experiment_plan_mismatch")
    for config in plan.design:
        entry = verified.arm(config.arm)
        if entry is None:
            problems.append(f"experiment_arm_missing:{config.arm}")
            continue
        if entry["config_digest"] != _arm_config_digest(plan, config.arm):
            problems.append(f"experiment_arm_config_mismatch:{config.arm}")
        if tuple(entry["components"]) != config.components:
            problems.append(
                f"experiment_arm_components_mismatch:{config.arm}")
    if set(verified.task_digests) != set(plan.task_ids):
        problems.append("experiment_task_set_mismatch")
    return verified, problems


def _verify_measurement(
        measurement, *, plan: CampaignPlan, task: str, arm: str,
        receipt: EvaluatorReceiptV2 | None,
        authorization: ExperimentAuthorizationV2 | None,
        authority, now: str | None, allow_expired: bool,
) -> tuple[TrialMeasurementV1 | None, list[str]]:
    """Authenticate one trial record and bind it to the arm it claims.

    Every branch is a rejection. A measurement that cannot be tied to
    this experiment, this arm configuration, this task digest, this
    model and this receipt is not evidence for this row.
    """
    try:
        record = (measurement if isinstance(measurement, TrialMeasurementV1)
                  else TrialMeasurementV1.from_dict(measurement))
    except (TrialEvidenceError, ContractError, TypeError, ValueError):
        return None, [f"measurement_malformed:{task}/{arm}"]
    verifier = getattr(authority, "measurement", None)
    if authority is None or not callable(verifier):
        return None, []
    try:
        record = verifier(record)
    except Exception as exc:  # noqa: BLE001 - fail closed
        return None, [f"measurement_untrusted:{task}/{arm}:"
                      + str(getattr(exc, "reason", type(exc).__name__))]
    problems: list[str] = []
    validity = getattr(authority, "validity", None)
    if callable(validity):
        try:
            reasons = validity(signer_key_id=record.signer_key_id,
                               digest=record.digest,
                               issued_at=record.issued_at,
                               expires_at=None, now=now,
                               allow_expired=allow_expired)
        except Exception as exc:  # noqa: BLE001 - fail closed
            # A malformed ``now`` or an authority that cannot evaluate its
            # own policy is a rejection, never an exception out of the
            # validator.
            reasons = ("validity_error:" + type(exc).__name__,)
        for reason in reasons:
            problems.append(f"measurement_invalid:{task}/{arm}:{reason}")

    if record.task_id != task:
        problems.append(f"measurement_task_mismatch:{task}/{arm}")
    if record.arm != arm:
        # The single check that makes an A/E swap visible.
        problems.append(f"measurement_arm_mismatch:{task}/{arm}")
    if record.arm_config_digest != _arm_config_digest(plan, arm):
        problems.append(f"measurement_arm_config_mismatch:{task}/{arm}")
    if receipt is not None:
        if record.receipt_digest != receipt.digest:
            problems.append(f"measurement_receipt_mismatch:{task}/{arm}")
        if record.receipt_id != receipt.receipt_id:
            problems.append(f"measurement_receipt_id_mismatch:{task}/{arm}")
        if record.authorization_id != receipt.authorization_id:
            problems.append(
                f"measurement_authorization_id_mismatch:{task}/{arm}")
        if record.attempt_id != receipt.attempt_id:
            problems.append(f"measurement_attempt_mismatch:{task}/{arm}")
        if not _status_matches(record.status, receipt.result):
            problems.append(f"measurement_status_mismatch:{task}/{arm}")
        if record.evaluator_identity != receipt.evaluator_identity:
            problems.append(f"measurement_evaluator_mismatch:{task}/{arm}")
    if authorization is not None:
        if record.experiment_id != authorization.experiment_id:
            problems.append(f"measurement_experiment_mismatch:{task}/{arm}")
        if record.authorization_digest != authorization.digest:
            problems.append(
                f"measurement_authorization_mismatch:{task}/{arm}")
        expected_task = authorization.task_digests.get(task)
        if expected_task is None:
            problems.append(f"measurement_task_unauthorized:{task}/{arm}")
        elif record.task_digest != expected_task:
            problems.append(
                f"measurement_task_digest_mismatch:{task}/{arm}")
        if record.model_digest != authorization.model_digest:
            problems.append(f"measurement_model_mismatch:{task}/{arm}")
        if receipt is not None:
            # The authorization is the only place the run's environment,
            # criterion and test suite are frozen. A receipt that attests
            # different commitments is evidence for a different experiment.
            if receipt.environment_digest != authorization.environment_digest:
                problems.append(
                    f"measurement_environment_mismatch:{task}/{arm}")
            if receipt.criterion_version != authorization.criterion_version:
                problems.append(
                    f"measurement_criterion_mismatch:{task}/{arm}")
            if (receipt.test_suite_commitment
                    != authorization.test_suite_commitment):
                problems.append(
                    f"measurement_test_suite_mismatch:{task}/{arm}")
    if not record.metered:
        # The evaluator declined to meter this run; its cost is unknown,
        # so it can never support a cost-adjusted claim.
        problems.append(f"measurement_unmetered:{task}/{arm}")
    return record, problems


def _status_matches(measured: str, receipt_result: str) -> bool:
    """Whether a measurement status is consistent with the receipt result.

    A receipt records the coarse outcome (``pass``/``fail``); the
    measurement records what actually happened. ``error`` and ``partial``
    are non-solves, not contradictions: an infrastructure failure must be
    expressible without pretending the task was attempted and failed.
    """
    if receipt_result == "pass":
        return measured == "pass"
    return measured in ("fail", "partial", "error")


def _validate_outcome(outcome: Mapping, *, plan: CampaignPlan, task: str,
                      arm: str, receipt_authority,
                      authorization: ExperimentAuthorizationV2 | None = None,
                      now: str | None = None,
                      allow_expired: bool = False,
                      ) -> tuple[list[str], bool, TrialMeasurementV1 | None]:
    """Check one arm outcome; return (problems, numeric_fields_valid, record).

    The measurement is the source of truth for every number. The report's
    copy of that number is a claim, and a claim that disagrees with the
    signed record is a failure, not a tie-break.
    """
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
    error = outcome.get("error")
    if error is not None and not isinstance(error, str):
        problems.append(f"error_invalid:{task}/{arm}")
        numeric_ok = False
    limit_violations = outcome.get("limit_violations", ())
    if not isinstance(limit_violations, (list, tuple)) or \
            len(limit_violations) > 32 or not all(
                isinstance(name, str) and name for name in limit_violations):
        problems.append(f"limit_violations_invalid:{task}/{arm}")
        numeric_ok = False
        limit_violations = ()

    exceeded = None
    if numeric_ok:
        exceeded = (tokens > plan.max_tokens_per_task
                    or wall > plan.max_wall_seconds_per_task
                    or bool(limit_violations))
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
    receipt_record: EvaluatorReceiptV2 | None = None
    if not (isinstance(receipt_id, str) and receipt_id):
        problems.append(f"receipt_missing:{task}/{arm}")
    if not isinstance(receipt, Mapping):
        problems.append(f"receipt_missing:{task}/{arm}")
        return problems, numeric_ok, None
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
    reason = _verify_receipt(receipt, receipt_authority=receipt_authority,
                             now=now, allow_expired=allow_expired)
    if reason is not None:
        problems.append(f"receipt_untrusted:{task}/{arm}:{reason}")
    try:
        receipt_record = EvaluatorReceiptV2.from_dict(
            {"schema_version": 1, **dict(receipt)})
    except (ContractError, TypeError, ValueError):
        receipt_record = None
    if receipt_record is not None and receipt_record.independence != "independent":
        # A dependent evaluation is not an independent observation of the
        # arm. It may exist in the record vocabulary, but it cannot count
        # toward a verdict of any class, exploratory included.
        problems.append(f"receipt_not_independent:{task}/{arm}")

    measurement = outcome.get("measurement")
    if measurement is None:
        # A legacy row: structurally fine, but nothing here is
        # authenticated, so the run cannot be promoted.
        return problems, numeric_ok, None
    if not isinstance(measurement, Mapping):
        problems.append(f"measurement_malformed:{task}/{arm}")
        return problems, numeric_ok, None
    record, found = _verify_measurement(
        measurement, plan=plan, task=task, arm=arm,
        receipt=receipt_record, authorization=authorization,
        authority=receipt_authority, now=now,
        allow_expired=allow_expired)
    problems.extend(found)
    if record is None:
        return problems, numeric_ok, None

    # The report's numbers are claims about the signed record.
    if _is_int(tokens) and tokens != record.tokens_total:
        problems.append(f"measurement_tokens_mismatch:{task}/{arm}")
        numeric_ok = False
    # Compare milliseconds, not floats: an evaluator that records wall
    # time to three decimals must not fail on a last-bit difference.
    reported_wall = _reported_wall_milli(wall)
    if reported_wall is not None and \
            reported_wall != record.wall_seconds_milli:
        problems.append(f"measurement_wall_mismatch:{task}/{arm}")
        numeric_ok = False
    if _is_int(tools) and tools != record.tool_calls:
        problems.append(f"measurement_tool_calls_mismatch:{task}/{arm}")
        numeric_ok = False
    if tuple(limit_violations) != record.limit_violations:
        problems.append(f"measurement_limit_violations_mismatch:{task}/{arm}")
        numeric_ok = False
    if error and record.status != "error":
        # A report may not invent an infrastructure failure the signed
        # record does not describe.
        problems.append(f"measurement_error_mismatch:{task}/{arm}")
        numeric_ok = False
    measured_exceeded = (
        record.tokens_total > plan.max_tokens_per_task
        or record.wall_seconds > plan.max_wall_seconds_per_task
        or bool(record.limit_violations))
    if type(budget_flag) is bool and budget_flag != measured_exceeded:
        problems.append(f"measurement_budget_mismatch:{task}/{arm}")
        numeric_ok = False
    measured_solved = record.status == "pass" and not measured_exceeded
    if type(valid) is bool and valid != measured_solved:
        problems.append(f"measurement_outcome_mismatch:{task}/{arm}")
        numeric_ok = False
    return problems, numeric_ok, record


def _verified_view(plan: CampaignPlan, records: Mapping,
                   per_task: Sequence[Mapping],
                   report: Mapping) -> dict:
    """Rebuild the run from signed measurements only.

    ``paired_contrast`` and ``resource_overhead`` consume this mapping,
    never the report, so the statistics cannot be steered by a field the
    evaluator did not sign. Abstention, negative transfer and integrity
    counters are telemetry: they are copied from the report because they
    do not influence the supported verdict, and they are documented as
    unauthenticated.
    """
    rows: list[dict] = []
    for row in per_task:
        task = row["task_id"]
        arms: dict[str, dict] = {}
        for arm in ARMS:
            record = records[(task, arm)]
            exceeded = (
                record.tokens_total > plan.max_tokens_per_task
                or record.wall_seconds > plan.max_wall_seconds_per_task
                or bool(record.limit_violations))
            solved = record.status == "pass" and not exceeded
            claimed = row["arms"][arm]
            arms[arm] = {
                "outcome": "pass" if solved else "fail",
                "valid_solve": solved,
                "budget_exceeded": exceeded,
                # An ``error`` status is an infrastructure failure, not a
                # task the model failed. It is recorded separately so the
                # verdict refuses a confirmatory claim instead of quietly
                # treating the run as an ordinary loss.
                "infrastructure_failure": record.status == "error",
                "error": None,
                "tokens": record.tokens_total,
                "wall_seconds": record.wall_seconds,
                "tool_calls": record.tool_calls,
                "abstained": bool(claimed.get("abstained")),
                "negative_transfer": bool(claimed.get("negative_transfer")),
                "integrity_failures": claimed.get("integrity_failures") or 0,
                "trial_id": record.trial_id,
            }
        rows.append({"task_id": task, "arms": arms,
                     "arm_order": row.get("arm_order")})
    return {
        "per_task": rows,
        "holdout_disjoint": report.get("holdout_disjoint"),
        "budget_exceeded": sum(
            1 for row in rows for arm in ARMS
            if row["arms"][arm]["budget_exceeded"]),
        "governed": {"metrics": _recompute_metrics(rows)},
    }


def validate_report(report: Mapping, plan: CampaignPlan, *,
                    receipt_authority=None,
                    experiment_authorization=None,
                    now: str | None = None,
                    allow_expired: bool = False) -> ReportValidation:
    """Check a report against the plan and the signed trial evidence.

    Undeclared, duplicated or missing tasks; missing arms; a reordered
    run; a different arm configuration; a duplicated or absent receipt;
    a measurement that names another arm, task, model or receipt;
    modified budget flags; malformed or non-finite numbers; conflicting
    outcomes; mismatched budgets and a forged aggregate are all failures.
    An incomplete run is incomplete, not confirmatory.

    Validation is total over the untrusted input domain: every shape a
    JSON document can take produces a ``ReportValidation``, never an
    exception.
    """
    if not isinstance(report, Mapping):
        return ReportValidation(False, ("report_invalid",), {})
    problems: list[str] = []
    if type(report.get("schema_version")) is not int or \
            report.get("schema_version") != 1:
        problems.append("schema_version_invalid")
    if report.get("kind") != "controlled_five_arm_campaign":
        problems.append("report_kind_invalid")
    if report.get("evidence_class") not in (
            EXPLORATORY, "demonstration", CONFIRMATORY):
        problems.append("evidence_class_invalid")
    if type(report.get("holdout_disjoint")) is not bool:
        # The flag is a verdict input (``invalid_holdout``); a truthy
        # non-boolean is not a declaration of holdout disjointness.
        problems.append("holdout_disjoint_invalid")
    per_task = report.get("per_task")
    if not isinstance(per_task, list):
        return ReportValidation(False, ("per_task_invalid",), {})

    authorization, authorization_problems = _verify_experiment_authorization(
        experiment_authorization, authority=receipt_authority, plan=plan,
        now=now, allow_expired=allow_expired)
    problems.extend(authorization_problems)

    task_ids = [row.get("task_id") if isinstance(row, Mapping) else None
                for row in per_task]
    if any(not isinstance(task, str) or not task for task in task_ids):
        problems.append("task_id_invalid")
    else:
        # ``set()`` raises on an unhashable value, so the duplicate and
        # set comparisons only run once every id is known to be a string.
        if len(set(task_ids)) != len(task_ids):
            problems.append("task_id_duplicated")
        if set(task_ids) != set(plan.task_ids):
            problems.append("task_set_mismatch")
    if len(task_ids) != len(plan.task_ids):
        problems.append("task_count_mismatch")
    receipts: list[str] = []
    trials: list[str] = []
    receipt_digests: list[str] = []
    records: dict[tuple[str, str], TrialMeasurementV1] = {}
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
        arm_order = row.get("arm_order")
        if not isinstance(arm_order, (list, tuple)) or any(
                not isinstance(entry, str) for entry in arm_order):
            # ``list()`` raises on a non-iterable and a string would be
            # read as its characters, so the type is checked first: the
            # validator must not raise on any JSON-shaped report.
            problems.append(f"arm_order_invalid:{task}")
            numeric_ok = False
        elif list(arm_order) != list(plan.arm_order(task)):
            problems.append(f"arm_order_mismatch:{task}")
        for arm in ARMS:
            outcome = arms[arm]
            if not isinstance(outcome, Mapping):
                problems.append(f"arm_outcome_invalid:{task}/{arm}")
                numeric_ok = False
                continue
            expected = _arm_config_digest(plan, arm)
            if outcome.get("arm_config_digest") != expected:
                problems.append(f"arm_config_mismatch:{task}/{arm}")
            found, outcome_numeric_ok, record = _validate_outcome(
                outcome, plan=plan, task=task, arm=arm,
                receipt_authority=receipt_authority,
                authorization=authorization, now=now,
                allow_expired=allow_expired)
            problems.extend(found)
            numeric_ok = numeric_ok and outcome_numeric_ok
            if record is not None:
                records[(task, arm)] = record
                trials.append(record.trial_id)
                receipt_digests.append(record.receipt_digest)
            receipt_id = outcome.get("receipt_id")
            if isinstance(receipt_id, str) and receipt_id:
                receipts.append(receipt_id)
    if len(set(receipts)) != len(receipts):
        problems.append("receipt_duplicated")
    if len(set(trials)) != len(trials):
        # A replayed trial is not a second observation.
        problems.append("measurement_duplicated")
    if len(set(receipt_digests)) != len(receipt_digests):
        problems.append("receipt_replayed")

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
    verified = None
    structural = any(
        problem.startswith(("task_id_", "task_set_", "task_count_",
                            "task_row_", "arm_set_", "arm_outcome_"))
        for problem in problems)
    if numeric_ok and not structural:
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
        complete = len(records) == len(plan.task_ids) * len(ARMS)
        if complete and authorization is not None and not problems:
            verified = _verified_view(plan, records, per_task, report)
    return ReportValidation(not problems, tuple(problems), metrics, verified,
                            authenticated=verified is not None)


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


def authorize_experiment(
        plan: CampaignPlan, *, experiment_id: str, model_identity: str,
        model_digest: str, task_digests: Mapping[str, str],
        environment_digest: str, criterion_version: str,
        test_suite_commitment: str, preregistration_digest: str,
        issued_at: str, expires_at: str, seed: bytes, key_id: str,
        alpha_milli: int | None = None,
        multiplicity: str = "holm",
        token_ratio_milli: int = 2000,
        latency_ratio_milli: int = 0) -> ExperimentAuthorizationV2:
    """Sign the frozen description of this campaign.

    The arm configuration digests are derived from ``plan.design``, so an
    authorization cannot describe an arm mapping the plan does not use.
    The plan digest covers the budgets, seed, arm order, task mapping and
    power requirement, so the same signed measurements cannot be
    reinterpreted under a different campaign budget. ``alpha_milli``
    defaults to the plan's own power requirement: the threshold the study
    was powered for is the threshold the verdict must apply.
    """
    arms = tuple({
        "arm": config.arm,
        "label": config.label,
        "components": config.components,
        "config_digest": _arm_config_digest(plan, config.arm),
    } for config in plan.design)
    return ExperimentAuthorizationV2(
        schema_version=2,
        experiment_id=experiment_id,
        protocol_digest=plan.protocol.get("protocol_digest"),
        preregistration_digest=preregistration_digest,
        plan_digest=canonical_digest("campaign_plan", 1, plan.to_dict()),
        model_identity=model_identity,
        model_digest=model_digest,
        task_digests=dict(task_digests),
        environment_digest=environment_digest,
        criterion_version=criterion_version,
        test_suite_commitment=test_suite_commitment,
        alpha_milli=(plan.power_requirement.alpha_milli
                     if alpha_milli is None else alpha_milli),
        multiplicity=multiplicity,
        token_ratio_milli=token_ratio_milli,
        latency_ratio_milli=latency_ratio_milli,
        issued_at=issued_at,
        expires_at=expires_at,
        signer_key_id=key_id,
        signature="0" * 128,
        arms=arms,
    ).sign(seed, key_id)


def _holm_adjusted(pvalues: Mapping[str, float]) -> dict[str, float]:
    """Holm step-down adjustment across the four reported contrasts.

    Four contrasts are tested (E-vs-A plus three component contrasts).
    Reporting the smallest unadjusted p and calling it supported is the
    multiple-comparison error the preregistration exists to prevent.
    """
    order = sorted(pvalues, key=lambda key: pvalues[key])
    count = len(order)
    adjusted: dict[str, float] = {}
    running = 0.0
    for rank, key in enumerate(order):
        value = min(1.0, (count - rank) * pvalues[key])
        running = max(running, value)
        adjusted[key] = running
    return adjusted


def _empty_contrast(baseline: str = "A", treatment: str = "E") -> dict:
    return {
        "baseline": baseline,
        "treatment": treatment,
        "tasks": 0,
        "baseline_solved": 0,
        "treatment_solved": 0,
        "delta": 0.0,
        "wins": 0,
        "losses": 0,
        "ties": 0,
        "mcnemar_exact_p": 1.0,
        "difference_interval_95": [0.0, 0.0],
        "significant": False,
    }


def assess(report: Mapping, *, plan: CampaignPlan,
           analysis: AnalysisManifest | None = None,
           receipt_authority=None,
           trusted_analysis_keys: Mapping[str, str] | None = None,
           trusted_timestamp_keys: Mapping[str, str] | None = None,
           experiment_authorization=None,
           now: str | None = None,
           allow_expired: bool = False) -> dict:
    """The E-vs-A verdict, including the after-cost comparison.

    ``supported`` requires the whole chain, not just a signature: every
    arm outcome must carry an evaluator receipt *and* a trial measurement
    authenticated by ``receipt_authority``; the measurement must name
    this experiment, this arm configuration, this task digest, this model
    and this receipt; the experiment must be authorized by a pinned
    experiment key; and the analysis manifest and preregistration must
    verify against their own trust roots.

    Statistics are computed from the authenticated measurements, never
    from the report's numbers. A report that fails validation returns
    ``invalid_report`` without touching its contents, so malformed input
    can never raise.
    """
    validation = validate_report(
        report, plan, receipt_authority=receipt_authority,
        experiment_authorization=experiment_authorization,
        now=now, allow_expired=allow_expired)
    problems = list(validation.problems)
    observed_claim = 0
    if isinstance(report, Mapping) and isinstance(
            report.get("per_task"), list):
        observed_claim = len(report["per_task"])
    if not validation.ok:
        return {
            "schema_version": 1,
            "verdict": "invalid_report",
            "decisive_contrast": _empty_contrast(),
            "component_contrasts": {arm: _empty_contrast(arm, "E")
                                    for arm in ("B", "C", "D")},
            "solve_rate": {"A": 0.0, "E": 0.0},
            "mean_tokens": {"A": None, "E": None},
            "mean_wall_seconds": {"A": None, "E": None},
            "latency_ratio": None,
            "token_ratio": None,
            "decision_policy": {},
            "required_sample_size": plan.required_sample_size,
            "observed_sample_size": observed_claim,
            "underpowered": True,
            "budget_exceeded": (report.get("budget_exceeded", 0)
                                if isinstance(report, Mapping) else 0),
            "evidence_class": "invalid",
            "receipts_verified": False,
            "measurements_verified": False,
            "analysis_verified": False,
            "preregistration_verified": False,
            "holm_adjusted_p": {},
            "infrastructure_failures": 0,
            "equivalence_established": False,
            "problems": problems,
            "validation": {"ok": False,
                           "problems": list(validation.problems)},
            "classification": None,
            "overhead": {},
        }

    verified = validation.verified
    measured = verified is not None
    if not measured:
        problems.append("measurement_unverified" if receipt_authority is None
                        else "measurement_missing")
    source = verified if measured else {"per_task": []}

    authorization = experiment_authorization
    if isinstance(authorization, Mapping):
        try:
            authorization = ExperimentAuthorizationV2.from_dict(authorization)
        except (TrialEvidenceError, ContractError, TypeError, ValueError):
            authorization = None
    authorized = isinstance(authorization, ExperimentAuthorizationV2)
    # The decision rule is the one the experiment was authorized for: a
    # signed preregistration protects nothing if the verdict applies its
    # own threshold.
    alpha = authorization.alpha_milli / 1000 if authorized else 0.05
    cost_ratio = (authorization.token_ratio_milli / 1000 if authorized
                  else 2.0)
    latency_limit = (authorization.latency_ratio_milli / 1000
                     if authorized else 0.0)

    decisive = paired_contrast(source, baseline="A", treatment="E",
                               alpha=alpha)
    component_arms = {arm: paired_contrast(source, baseline=arm,
                                           treatment="E", alpha=alpha)
                      for arm in ("B", "C", "D")}
    overhead = resource_overhead(source)
    metrics = (verified or {}).get("governed", {}).get("metrics", {}) \
        if measured else {}
    a_solved = metrics.get("A", {}).get("solved_task_rate", 0.0)
    e_solved = metrics.get("E", {}).get("solved_task_rate", 0.0)
    a_tokens = overhead.get("A", {}).get("mean_tokens_per_task")
    e_tokens = overhead.get("E", {}).get("mean_tokens_per_task")
    token_ratio = (e_tokens / a_tokens
                   if a_tokens and e_tokens is not None else None)
    a_wall = overhead.get("A", {}).get("mean_wall_seconds_per_task")
    e_wall = overhead.get("E", {}).get("mean_wall_seconds_per_task")
    latency_ratio = (e_wall / a_wall
                     if a_wall and e_wall is not None else None)
    observed = len(source["per_task"])
    underpowered = observed < plan.required_sample_size
    infrastructure_failures = sum(
        1 for row in source["per_task"] for arm in ARMS
        if row["arms"][arm].get("infrastructure_failure"))
    if infrastructure_failures:
        # An infrastructure failure is not an unsuccessful attempt. It
        # also cannot be silently dropped: the paired design and the
        # preregistered sample size were computed over all tasks.
        problems.append("infrastructure_failure_present")

    adjusted = _holm_adjusted({
        "E_vs_A": decisive["mcnemar_exact_p"],
        **{f"{arm}_vs_E": component_arms[arm]["mcnemar_exact_p"]
           for arm in ("B", "C", "D")},
    })
    decisive_holm = adjusted["E_vs_A"]

    evidence_class = EXPLORATORY
    classification = None
    analysis_verified = False
    preregistration_verified = False
    if receipt_authority is None:
        problems.append("receipt_authority_missing")
    if experiment_authorization is None:
        problems.append("experiment_authorization_missing")
    elif receipt_authority is None:
        problems.append("experiment_authorization_unverified")
    if analysis is None:
        problems.append("analysis_manifest_missing")
    else:
        if analysis.protocol_digest != plan.protocol.get("protocol_digest"):
            problems.append("analysis_protocol_mismatch")
        if (authorized and analysis.preregistration is not None
                and authorization.preregistration_digest
                != analysis.preregistration.digest):
            # The experiment must have been authorized for the very
            # preregistration the analysis is bound to.
            problems.append("analysis_preregistration_mismatch")
        if (authorized and analysis.preregistration is not None
                and authorization.alpha_milli
                != analysis.preregistration.power.alpha_milli):
            # Two signed records disagree about the threshold: the
            # preregistration the study was powered for and the
            # authorization the verdict is told to apply.
            problems.append("analysis_alpha_mismatch")
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
        elif preregistration.protocol_digest != plan.protocol.get(
                "protocol_digest"):
            # The preregistration is signed, but it must be a
            # preregistration for *this* protocol, not merely a signed
            # record whose digest the other keys agreed to name.
            problems.append("preregistration_protocol_mismatch")
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
                         and not any(problem.startswith("receipt_")
                                     for problem in problems))
    measurements_verified = (measured
                             and not any(problem.startswith("measurement_")
                                         for problem in problems))
    analysis_consistent = not any(problem.startswith("analysis_")
                                  for problem in problems)
    if not report.get("holdout_disjoint", True):
        verdict = "invalid_holdout"
        evidence_class = "invalid"
    elif infrastructure_failures:
        # An infrastructure failure is not a task outcome. The paired
        # design cannot be read as a win, a loss or a regression when a
        # cell failed for a reason the model does not control.
        verdict = "no_evidence"
    elif decisive["delta"] < 0:
        verdict = "regressed"
    elif decisive["delta"] == 0 or not decisive["significant"]:
        verdict = "no_evidence"
    elif underpowered:
        verdict = "underpowered"
    elif token_ratio is not None and token_ratio > cost_ratio:
        verdict = "no_advantage_after_cost"
    elif (latency_limit and latency_ratio is not None
            and latency_ratio > latency_limit):
        # Only when the operator froze a latency bound in the signed
        # policy. Zero means the cost rule is token-only, and the
        # assessment says so in ``decision_policy``.
        verdict = "no_advantage_after_cost"
    elif decisive_holm > alpha:
        # The decisive contrast does not survive the family-wise
        # correction at the authorized threshold.
        verdict = "no_evidence"
    elif (evidence_class != CONFIRMATORY or not receipts_verified
            or not measurements_verified or not analysis_consistent):
        # A significant contrast without the full authenticated chain is
        # not a claim. ``analysis_consistent`` covers a preregistration,
        # protocol or threshold the signed records disagree about.
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
        "mean_wall_seconds": {"A": a_wall, "E": e_wall},
        "latency_ratio": latency_ratio,
        "token_ratio": token_ratio,
        # The rule the verdict actually applied. Latency is reported but
        # is not part of the cost decision; a claim of superiority after
        # latency cost needs a policy that says so.
        "decision_policy": {
            "alpha": alpha,
            "multiplicity": (authorization.multiplicity if authorized
                             else "holm"),
            "token_ratio_threshold": cost_ratio,
            "latency_ratio_threshold": latency_limit,
            "latency": ("thresholded" if latency_limit
                        else "reported, not thresholded"),
        },
        "required_sample_size": plan.required_sample_size,
        "observed_sample_size": observed,
        "underpowered": underpowered,
        "budget_exceeded": (verified or {}).get("budget_exceeded", 0),
        "evidence_class": evidence_class,
        "receipts_verified": receipts_verified,
        "measurements_verified": measurements_verified,
        "analysis_verified": analysis_verified,
        "preregistration_verified": preregistration_verified,
        "holm_adjusted_p": adjusted,
        "infrastructure_failures": infrastructure_failures,
        # A non-significant result is not evidence of equivalence: the
        # interval may still contain a difference worth acting on.
        "equivalence_established": False,
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
    "ExperimentAuthorizationV2",
    "FIVE_ARM_DESIGN",
    "ReportValidation",
    "assess",
    "authorize_experiment",
    "build_report",
    "sign_analysis_manifest",
    "validate_design",
    "validate_report",
]


