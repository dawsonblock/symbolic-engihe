"""Fail-closed, read-only v3 guidance surface for the M0 contract gate.

No qualified v3 procedure catalog exists yet. This function therefore only
returns bounded abstentions; it does not inspect or trust v2 local recipes.
"""
from .contracts import GuidanceRequestV1, GuidanceV1, canonical_digest


_POLICY_DESCRIPTOR = {
    "schema_version": 1,
    "mode": "abstain_only",
    "reasons": ["unverified_task_intent", "no_qualified_procedure"],
}
_POLICY_DIGEST = canonical_digest("guidance_policy", 1, _POLICY_DESCRIPTOR)


def sis_recommend(request: GuidanceRequestV1 | dict) -> GuidanceV1:
    """Return a strict, bounded recommendation or abstention; never mutates state."""
    if not isinstance(request, GuidanceRequestV1):
        request = GuidanceRequestV1.from_dict(request)
    if request.semantic_contract_digest is None:
        reason = "unverified_task_intent"
        checks = (
            "Confirm the requested behavior from task acceptance criteria or an independently reviewed specification.",
            "Reproduce the target failure with task-owned tests before considering any procedure.",
        )
    else:
        reason = "no_qualified_procedure"
        checks = (
            "No v3 qualified procedure catalog is installed for this research build.",
            "Verify the task outcome independently and retain the evidence for later review.",
        )
    return GuidanceV1(
        schema_version=1,
        decision="abstain",
        procedure_ids=(),
        revision=None,
        matched_preconditions=(),
        contraindications=(),
        evidence_ids=(),
        policy_digest=_POLICY_DIGEST,
        helpful_next_checks=checks,
        reason_code=reason,
        approximate_tokens=min(2_000, sum(max(1, len(item) // 4) for item in checks)),
    )
