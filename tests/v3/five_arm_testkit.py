"""Signed evaluator receipts, trial measurements and experiment
authorizations for five-arm tests.

The point of these fixtures is that a report is only confirmatory when
the whole chain authenticates: the experiment was authorized by a pinned
experiment key, each trial was measured by a pinned evaluator key, and
each measurement names this experiment, this arm configuration, this
task digest, this model and this receipt. Tests that want a ``supported``
verdict use these keys; tests that forge evidence use different ones.
"""
from __future__ import annotations

from sis.v3.contracts import EvaluatorReceiptV2, canonical_digest
from sis.v3.evidence_binding import (
    EvidenceBindingAuthority,
    sign_receipt,
)
from sis.v3.five_arm import AnalysisManifest, authorize_experiment
from sis.v3.statistical_power import (
    LineageRegistry,
    PowerRequirement,
    RepositoryLineage,
    sign_preregistration,
)
from sis.v3.trial_evidence import TrialMeasurementV1
from sis.v3.trial_evidence import task_digest as _task_digest
from tests.v3.test_evaluation_certificates import PROTOCOL_DIGEST

EVALUATOR_SEED = b"\x51" * 32
EVALUATOR_KEY_ID = "eval-key-1"
ANALYSIS_SEED = b"\x52" * 32
ANALYSIS_KEY_ID = "analysis-key-1"
EXPERIMENT_SEED = b"\x53" * 32
EXPERIMENT_KEY_ID = "experiment-key-1"
TIMESTAMP_SEED = b"\x01" * 32
TIMESTAMP_KEY_ID = "tsa-key"

EXPERIMENT_ID = "exp-v351"
MODEL_IDENTITY = "codex-1"
MODEL_DIGEST = "7" * 64
ENVIRONMENT_DIGEST = "8" * 64
CRITERION_VERSION = "v1"
TEST_SUITE_COMMITMENT = "1" * 64
ISSUED_AT = "2026-01-01T00:00:00Z"
EXPIRES_AT = "2099-01-01T00:00:00Z"
STARTED_AT = "2026-02-01T00:00:00Z"
COMPLETED_AT = "2026-02-01T00:00:10Z"
MEASURED_AT = "2026-02-01T00:00:11Z"


def evaluator_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(EVALUATOR_SEED).hex()


def analysis_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(ANALYSIS_SEED).hex()


def timestamp_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(TIMESTAMP_SEED).hex()


def experiment_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(EXPERIMENT_SEED).hex()


def trusted_analysis_keys() -> dict[str, str]:
    return {ANALYSIS_KEY_ID: analysis_public_hex()}


def trusted_timestamp_keys() -> dict[str, str]:
    return {TIMESTAMP_KEY_ID: timestamp_public_hex()}


def receipt_authority(*, revocation_provider=None, clock=None,
                      key_validity=None) -> EvidenceBindingAuthority:
    return EvidenceBindingAuthority(
        trusted_evaluator_keys={
            EVALUATOR_KEY_ID: evaluator_public_hex()},
        trusted_harness_keys={},
        trusted_experiment_keys={
            EXPERIMENT_KEY_ID: experiment_public_hex()},
        revocation_provider=revocation_provider,
        key_validity=key_validity,
        clock=clock)


def receipt_for(task: str, arm: str, result: str = "pass", *,
                receipt_id: str | None = None,
                signer_key_id: str = EVALUATOR_KEY_ID,
                seed: bytes = EVALUATOR_SEED) -> dict:
    """A signed EvaluatorReceiptV2 bound to one task/arm."""
    return sign_receipt(
        seed,
        receipt_id=receipt_id or f"rcpt-{task}-{arm}",
        authorization_id=f"auth-{task}-{arm}",
        attempt_id=f"attempt-{task}-{arm}",
        task_id=task,
        requester_principal_id="agent-1",
        repository_id="repo-1",
        repository_tree_digest="c" * 64,
        base_commit_digest="abc1234",
        submitted_artifact_digest="f" * 64,
        guidance_exposure_digest="d" * 64,
        test_suite_commitment=TEST_SUITE_COMMITMENT,
        environment_digest=ENVIRONMENT_DIGEST,
        criterion_version=CRITERION_VERSION,
        result=result,
        independence="independent",
        dependency_receipt_digest=None,
        evaluator_identity="sis-v3-evaluator",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        nonce=f"nonce-{task}-{arm}",
        signer_key_id=signer_key_id,
    ).to_dict()


def power(effect: int = 400, discordant: int = 300) -> PowerRequirement:
    return PowerRequirement(design="paired_mcnemar", effect_milli=effect,
                            discordant_milli=discordant)


def preregistration(*, protocol_digest: str = PROTOCOL_DIGEST,
                    training=("lin-t",), holdout=("lin-h",),
                    registered_at: str = "2026-01-01T00:00:00Z"):
    return sign_preregistration(
        TIMESTAMP_SEED,
        preregistration_id="pre-1", protocol_digest=protocol_digest,
        primary_metric="paired solved_delta E vs A",
        power=power().to_dict(),
        holdout_lineages=holdout, training_lineages=training,
        registered_at=registered_at, timestamp_authority="tsa",
        signer_key_id=TIMESTAMP_KEY_ID)


def manifest(*, protocol_digest: str = PROTOCOL_DIGEST,
             training=("lin-t",), holdout=("lin-h",),
             registered_at: str = "2026-01-01T00:00:00Z",
             first_evaluation: str = "2026-02-01T00:00:00Z",
             signed: bool = True) -> AnalysisManifest:
    prereg = preregistration(protocol_digest=protocol_digest,
                             training=training, holdout=holdout,
                             registered_at=registered_at)
    lineages = LineageRegistry()
    lineages.add(RepositoryLineage(
        registry_id="repo-1", lineage_id=holdout[0], family_id="fam"))
    value = AnalysisManifest(
        protocol_digest=protocol_digest,
        preregistration=prereg, lineages=lineages,
        first_evaluation_at=first_evaluation,
        holdout_repositories=("repo-1",))
    return value.sign(ANALYSIS_SEED, ANALYSIS_KEY_ID) if signed else value


def default_task_digests(campaign) -> dict[str, str]:
    return {task: task_digest(task, f"task-content:{task}")
            for task in campaign.task_ids}


def experiment_authorization(campaign, *, task_digests=None,
                             protocol_digest: str = PROTOCOL_DIGEST,
                             model_digest: str = MODEL_DIGEST,
                             environment_digest: str = ENVIRONMENT_DIGEST,
                             criterion_version: str = CRITERION_VERSION,
                             test_suite_commitment: str = TEST_SUITE_COMMITMENT,
                             experiment_id: str = EXPERIMENT_ID,
                             issued_at: str = ISSUED_AT,
                             expires_at: str = EXPIRES_AT,
                             seed: bytes = EXPERIMENT_SEED,
                             key_id: str = EXPERIMENT_KEY_ID):
    prereg = preregistration(protocol_digest=protocol_digest)
    return authorize_experiment(
        campaign,
        experiment_id=experiment_id,
        model_identity=MODEL_IDENTITY,
        model_digest=model_digest,
        task_digests=(task_digests if task_digests is not None
                      else default_task_digests(campaign)),
        environment_digest=environment_digest,
        criterion_version=criterion_version,
        test_suite_commitment=test_suite_commitment,
        preregistration_digest=prereg.digest,
        issued_at=issued_at,
        expires_at=expires_at,
        seed=seed,
        key_id=key_id,
    )


def arm_config_digest(campaign, arm: str) -> str:
    config = next(item for item in campaign.design if item.arm == arm)
    return canonical_digest("arm_configuration", 1, config.to_dict())


def measurement_for(task: str, arm: str, result: str = "pass", *,
                    campaign, authorization, receipt,
                    tokens_in: int = 600, tokens_out: int = 400,
                    wall_seconds_milli: int = 10_000,
                    tool_calls: int = 5, tool_errors: int = 0,
                    limit_violations=(),
                    status: str | None = None,
                    termination_reason: str | None = None,
                    trial_id: str | None = None,
                    started_at: str = STARTED_AT,
                    completed_at: str = COMPLETED_AT,
                    issued_at: str = MEASURED_AT,
                    seed: bytes = EVALUATOR_SEED,
                    signer_key_id: str = EVALUATOR_KEY_ID) -> dict:
    """A signed TrialMeasurementV1 for one arm/task of an authorized run."""
    record = (receipt if isinstance(receipt, EvaluatorReceiptV2)
              else EvaluatorReceiptV2.from_dict(receipt))
    task_digests = dict(authorization.task_digests)
    return TrialMeasurementV1(
        schema_version=1,
        experiment_id=authorization.experiment_id,
        authorization_digest=authorization.digest,
        trial_id=trial_id or f"trial-{task}-{arm}",
        arm=arm,
        arm_config_digest=arm_config_digest(campaign, arm),
        task_id=task,
        task_digest=task_digests[task],
        model_digest=authorization.model_digest,
        evaluator_identity="sis-v3-evaluator",
        evaluator_build_digest="4" * 64,
        receipt_digest=record.digest,
        receipt_id=record.receipt_id,
        authorization_id=record.authorization_id,
        attempt_id=record.attempt_id,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        tokens_total=tokens_in + tokens_out,
        wall_seconds_milli=wall_seconds_milli,
        tool_calls=tool_calls,
        tool_errors=tool_errors,
        limit_violations=tuple(limit_violations),
        status=status or result,
        termination_reason=termination_reason,
        started_at=started_at,
        completed_at=completed_at,
        issued_at=issued_at,
        signer_key_id=signer_key_id,
        signature="0" * 128,
    ).sign(seed, signer_key_id).to_dict()


def evaluation_public_hex() -> str:
    """Public key of a *different* evaluator, for replaced-registry tests."""
    from sis.v3 import signatures
    return signatures.public_key(b"\x77" * 32).hex()


def task_digest(task_id: str, document: str) -> str:
    return _task_digest(task_id, document)
