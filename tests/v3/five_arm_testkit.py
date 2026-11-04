"""Signed evaluator receipts and analysis manifests for five-arm tests.

The point of these fixtures is that a report is only confirmatory when
the receipts and the analysis are authenticated by keys the verifier was
configured to trust. Tests that want a ``supported`` verdict must use
these keys; tests that forge evidence must use different ones.
"""
from __future__ import annotations

from sis.v3.evidence_binding import (
    EvidenceBindingAuthority,
    sign_receipt,
)
from sis.v3.five_arm import AnalysisManifest
from sis.v3.statistical_power import (
    LineageRegistry,
    PowerRequirement,
    RepositoryLineage,
    sign_preregistration,
)

EVALUATOR_SEED = b"\x51" * 32
EVALUATOR_KEY_ID = "eval-key-1"
ANALYSIS_SEED = b"\x52" * 32
ANALYSIS_KEY_ID = "analysis-key-1"
TIMESTAMP_SEED = b"\x01" * 32
TIMESTAMP_KEY_ID = "tsa-key"
PROTOCOL_DIGEST = "a" * 64


def evaluator_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(EVALUATOR_SEED).hex()


def analysis_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(ANALYSIS_SEED).hex()


def timestamp_public_hex() -> str:
    from sis.v3 import signatures
    return signatures.public_key(TIMESTAMP_SEED).hex()


def trusted_analysis_keys() -> dict[str, str]:
    return {ANALYSIS_KEY_ID: analysis_public_hex()}


def trusted_timestamp_keys() -> dict[str, str]:
    return {TIMESTAMP_KEY_ID: timestamp_public_hex()}


def receipt_authority() -> EvidenceBindingAuthority:
    return EvidenceBindingAuthority(
        trusted_evaluator_keys={
            EVALUATOR_KEY_ID: evaluator_public_hex()},
        trusted_harness_keys={})


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
        test_suite_commitment="1" * 64,
        environment_digest="2" * 64,
        criterion_version="v1",
        result=result,
        independence="independent",
        dependency_receipt_digest=None,
        evaluator_identity="sis-v3-evaluator",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
        nonce=f"nonce-{task}-{arm}",
        signer_key_id=signer_key_id,
    ).to_dict()


def power(effect: int = 400, discordant: int = 300) -> PowerRequirement:
    return PowerRequirement(design="paired_mcnemar", effect_milli=effect,
                            discordant_milli=discordant)


def manifest(*, protocol_digest: str = PROTOCOL_DIGEST,
             training=("lin-t",), holdout=("lin-h",),
             registered_at: str = "2026-01-01T00:00:00Z",
             first_evaluation: str = "2026-02-01T00:00:00Z",
             signed: bool = True) -> AnalysisManifest:
    preregistration = sign_preregistration(
        TIMESTAMP_SEED,
        preregistration_id="pre-1", protocol_digest=protocol_digest,
        primary_metric="paired solved_delta E vs A",
        power=power().to_dict(),
        holdout_lineages=holdout, training_lineages=training,
        registered_at=registered_at, timestamp_authority="tsa",
        signer_key_id=TIMESTAMP_KEY_ID)
    lineages = LineageRegistry()
    lineages.add(RepositoryLineage(
        registry_id="repo-1", lineage_id=holdout[0], family_id="fam"))
    value = AnalysisManifest(
        protocol_digest=protocol_digest,
        preregistration=preregistration, lineages=lineages,
        first_evaluation_at=first_evaluation,
        holdout_repositories=("repo-1",))
    return value.sign(ANALYSIS_SEED, ANALYSIS_KEY_ID) if signed else value
