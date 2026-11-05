"""Run the five arms and emit an authenticated evidence chain.

``five_arm.assess`` has always required signed measurements, and until now
nothing but the test fixtures produced them: the campaign tooling ran the
arms and wrote a report whose numbers nobody had signed. This module is
the producer.

It drives :class:`sis.v3.benchmark.BenchmarkHarness` — real arms, real
token/wall/tool counters — and then, for every (task, arm) cell:

* signs an ``EvaluatorReceiptV2`` stating what the evaluator measured;
* signs a ``TrialMeasurementV1`` binding that receipt to the experiment,
  the arm, the arm configuration, the immutable task digest, the model
  and the metered cost;
* builds the ``ArmOutcome`` the controlled report carries.

The experiment is frozen first: ``authorize_experiment`` signs the plan
digest, the arm mapping, the task digests, the model and the
environment/criterion/suite commitments, plus the decision policy. The
assessment then has an independent trust root for every field it reads.

Two keys are involved and they must be distinct: the experiment authority
authorizes, the evaluator measures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from .contracts import EvaluatorReceiptV2, canonical_digest, canonical_json
from .evidence_binding import sign_receipt
from .five_arm import (
    ARMS,
    AnalysisManifest,
    ArmOutcome,
    CampaignPlan,
    _arm_config_digest,
    assess,
    authorize_experiment,
    build_report,
)
from .trial_evidence import TrialMeasurementV1, task_digest

#: Recorded when the harness meters a single counter, so the input/output
#: split is unavailable. The total is exact; nothing is hidden.
SPLIT_UNAVAILABLE = "tokens_split_unavailable"


class CampaignError(ValueError):
    """The campaign cannot produce an authenticated chain."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class CampaignCommitments:
    """The identities and commitments the run is authorized under."""

    experiment_id: str
    model_identity: str
    model_digest: str
    environment_digest: str
    criterion_version: str
    test_suite_commitment: str
    repository_id: str
    requester_principal_id: str
    authorization_id: str
    evaluator_identity: str = "sis-v3-evaluator"
    evaluator_build_digest: str = "0" * 64
    issued_at: str = "2026-01-01T00:00:00Z"
    expires_at: str = "2099-01-01T00:00:00Z"
    receipt_expires_at: str = "2099-01-01T00:00:00Z"

    def __post_init__(self) -> None:
        for name in ("experiment_id", "model_identity", "criterion_version",
                     "repository_id", "requester_principal_id",
                     "authorization_id", "evaluator_identity"):
            value = getattr(self, name)
            if not (isinstance(value, str) and value):
                raise CampaignError(f"{name}_invalid")
        for name in ("model_digest", "environment_digest",
                     "test_suite_commitment", "evaluator_build_digest"):
            value = getattr(self, name)
            if not (isinstance(value, str) and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value)):
                raise CampaignError(f"{name}_invalid")


@dataclass(frozen=True)
class _Cell:
    """One measured (task, arm) cell, as the harness reported it."""

    task_id: str
    arm: str
    outcome: str
    submission_digest: str | None
    tree_digest: str
    wall_seconds: int
    budget_exceeded: bool
    error: str | None
    tokens_used: int | None
    tools_used: int | None
    guidance_served: bool


def _cells(measured: Mapping, tasks: Sequence[tuple],
           served: Mapping[tuple[str, str], bool]) -> dict:
    tree = {task.task_id: task.repo_snapshot_digest for task, _ in tasks}
    cells = {}
    for row in measured["per_task"]:
        task_id = row["task_id"]
        for arm, entry in row["arms"].items():
            cells[(task_id, arm)] = _Cell(
                task_id=task_id,
                arm=arm,
                outcome=entry["outcome"],
                submission_digest=entry.get("submission_digest"),
                tree_digest=tree.get(task_id, "0" * 64),
                wall_seconds=int(entry.get("wall_seconds") or 0),
                budget_exceeded=bool(entry.get("budget_exceeded")),
                error=entry.get("error"),
                tokens_used=entry.get("tokens_used"),
                tools_used=entry.get("tools_used"),
                guidance_served=bool(served.get((task_id, arm))),
            )
    return cells


def _exposure_digest(cell: _Cell) -> str:
    """What the evaluator attests about guidance exposure for this cell.

    The harness decides which arms receive guidance; the wrapper records
    whether a non-abstaining guidance record was actually served. The
    content digest is not reported to the caller, so the record says so.
    """
    return canonical_digest("guidance_exposure", 1, {
        "task_id": cell.task_id, "arm": cell.arm,
        "served": cell.guidance_served, "content_reported": False})


def _measurement_for(*, campaign: CampaignPlan, authorization,
                     receipt: EvaluatorReceiptV2, cell: _Cell,
                     task_digest_value: str,
                     commitments: CampaignCommitments,
                     seed: bytes, key_id: str) -> TrialMeasurementV1:
    total = int(cell.tokens_used or 0)
    violations = ("budget",) if cell.budget_exceeded else ()
    return TrialMeasurementV1(
        schema_version=1,
        experiment_id=authorization.experiment_id,
        authorization_digest=authorization.digest,
        trial_id=f"trial-{cell.task_id}-{cell.arm}",
        arm=cell.arm,
        arm_config_digest=_arm_config_digest(campaign, cell.arm),
        task_id=cell.task_id,
        task_digest=task_digest_value,
        model_digest=authorization.model_digest,
        evaluator_identity=commitments.evaluator_identity,
        evaluator_build_digest=commitments.evaluator_build_digest,
        receipt_digest=receipt.digest,
        receipt_id=receipt.receipt_id,
        authorization_id=receipt.authorization_id,
        attempt_id=receipt.attempt_id,
        # The harness meters one counter. The total is exact; attributing
        # it to input keeps ``in + out == total`` without inventing a
        # split, and ``termination_reason`` records that the split was
        # not reported.
        tokens_in=total,
        tokens_out=0,
        tokens_total=total,
        wall_seconds_milli=cell.wall_seconds * 1000,
        tool_calls=int(cell.tools_used or 0),
        tool_errors=0,
        limit_violations=violations,
        status=cell.outcome,
        termination_reason=SPLIT_UNAVAILABLE,
        started_at=commitments.issued_at,
        completed_at=commitments.issued_at,
        issued_at=commitments.issued_at,
        signer_key_id=key_id,
        signature="0" * 128,
    ).sign(seed, key_id)


def run_authenticated_campaign(
    *,
    plan: CampaignPlan,
    tasks: Sequence[tuple],
    harness,
    agent: Callable,
    budget,
    context_provider: Callable | None,
    commitments: CampaignCommitments,
    preregistration,
    analysis: AnalysisManifest,
    experiment_seed: bytes,
    experiment_key_id: str,
    evaluator_seed: bytes,
    evaluator_key_id: str,
    receipt_authority,
    trusted_analysis_keys: Mapping[str, str],
    trusted_timestamp_keys: Mapping[str, str],
    evidence_class: str = "confirmatory",
    alpha_milli: int | None = None,
    token_ratio_milli: int = 2000,
    latency_ratio_milli: int = 0,
) -> dict:
    """Run the arms and return ``{authorization, report, verdict}``."""
    if experiment_key_id == evaluator_key_id:
        # The party that authorizes must not be the party that measures.
        raise CampaignError("authority_roles_not_separated", experiment_key_id)
    digests = {
        task.task_id: task_digest(task.task_id, canonical_json(task.to_dict()))
        for task, _ in tasks
    }
    authorization = authorize_experiment(
        plan,
        experiment_id=commitments.experiment_id,
        model_identity=commitments.model_identity,
        model_digest=commitments.model_digest,
        task_digests=digests,
        environment_digest=commitments.environment_digest,
        criterion_version=commitments.criterion_version,
        test_suite_commitment=commitments.test_suite_commitment,
        preregistration_digest=preregistration.digest,
        issued_at=commitments.issued_at,
        expires_at=commitments.expires_at,
        seed=experiment_seed,
        key_id=experiment_key_id,
        alpha_milli=alpha_milli,
        token_ratio_milli=token_ratio_milli,
        latency_ratio_milli=latency_ratio_milli,
    )
    served: dict[tuple[str, str], bool] = {}

    def recording_provider(task, arm):
        guidance = context_provider(task, arm) if context_provider else None
        served[(task.task_id, arm)] = guidance is not None
        return guidance

    measured = harness.run(tasks, agent, budget=budget,
                           context_provider=recording_provider, arms=ARMS)
    cells = _cells(measured, tasks, served)
    rows = []
    for row in measured["per_task"]:
        task_id = row["task_id"]
        arms: dict[str, ArmOutcome] = {}
        for arm in ARMS:
            cell = cells[(task_id, arm)]
            receipt = sign_receipt(
                evaluator_seed,
                receipt_id=f"rcpt-{task_id}-{arm}",
                authorization_id=commitments.authorization_id,
                attempt_id=f"attempt-{task_id}-{arm}",
                task_id=task_id,
                requester_principal_id=commitments.requester_principal_id,
                repository_id=commitments.repository_id,
                repository_tree_digest=cell.tree_digest,
                base_commit_digest=None,
                submitted_artifact_digest=(cell.submission_digest
                                           or cell.tree_digest),
                guidance_exposure_digest=_exposure_digest(cell),
                test_suite_commitment=commitments.test_suite_commitment,
                environment_digest=commitments.environment_digest,
                criterion_version=commitments.criterion_version,
                result="pass" if cell.outcome == "pass" else "fail",
                independence="independent",
                dependency_receipt_digest=None,
                evaluator_identity=commitments.evaluator_identity,
                issued_at=commitments.issued_at,
                expires_at=commitments.receipt_expires_at,
                nonce=f"nonce-{task_id}-{arm}",
                signer_key_id=evaluator_key_id,
            )
            measurement = _measurement_for(
                campaign=plan, authorization=authorization, receipt=receipt,
                cell=cell, task_digest_value=digests[task_id],
                commitments=commitments, seed=evaluator_seed,
                key_id=evaluator_key_id)
            arms[arm] = ArmOutcome(
                arm=arm,
                valid_solve=(cell.outcome == "pass"
                             and not cell.budget_exceeded
                             and not cell.error),
                tokens=int(cell.tokens_used or 0),
                wall_seconds=float(cell.wall_seconds),
                tool_calls=int(cell.tools_used or 0),
                receipt=receipt.to_dict(),
                measurement=measurement.to_dict(),
                limit_violations=(("budget",) if cell.budget_exceeded
                                  else ()),
            )
        rows.append((task_id, arms))
    report = build_report(plan, rows, evidence_class=evidence_class)
    verdict = assess(
        report, plan=plan, analysis=analysis,
        receipt_authority=receipt_authority,
        trusted_analysis_keys=trusted_analysis_keys,
        trusted_timestamp_keys=trusted_timestamp_keys,
        experiment_authorization=authorization)
    return {"authorization": authorization, "report": report,
            "verdict": verdict}
