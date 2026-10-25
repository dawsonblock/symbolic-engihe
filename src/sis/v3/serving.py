"""Strict governed serving (SIS v3.3, milestone 7).

Connects the qualified candidate catalog to approved agent harnesses.
Flow: authenticate repository identity through the trusted registry ->
select qualified candidates whose declared scope covers the resolved
identity -> re-verify digests, revocation and applicability -> suppress
counterexamples -> compose inside a deterministic budget -> deliver the
merged advisory steps through the untrusted context channel
(``helpful_next_checks``).

Isolation invariants:

- Candidate/skill/memory text is *data*. It is delivered as advisory
  steps only — it can describe an action but can never grant itself
  permission, alter sandbox/policy, or touch authority.
- Serving requires a resolvable repository identity. A self-declared
  ``repository_id`` that the trusted registry cannot resolve abstains.
- Revoked, tampered, malformed, out-of-scope, family-mismatched (when
  ``task_family`` is declared) or inapplicable candidates are excluded
  individually (each rejection is counted and auditable); nothing
  silently degrades to permissive.
- ``decision`` remains honest: ``recommend`` only when the strict
  procedure path qualifies; candidate-only advice rides along as
  advisory checks under an abstention decision with a reason.
- ``target_task_family``/``target_agent`` are provenance fields; the
  optional ``task_family`` argument turns the family field into an
  enforced gate for deployments that want it.
"""
from __future__ import annotations

import re
from typing import Callable, Mapping

from .candidates import CandidateRegistry
from .composition import compose_guidance
from .contracts import CandidateV1, ContractError, GuidanceRequestV1, GuidanceV1, canonical_digest
from .guidance import _abstain
from .retrieval import (RetrievalContext, precondition_holds,
                        suppression_match)

_HEX = re.compile(r"^[0-9a-f]{64}$")
_OUTCOMES = frozenset({"pass", "fail", "partial", "error"})

_POLICY = {
    "schema_version": 1,
    "mode": "governed_serving",
    "reasons": ["insufficient_support", "revoked", "conflicting_evidence",
                "no_qualified_procedure", "catalog_unavailable"],
}
_POLICY_DIGEST = canonical_digest("guidance_policy", 1, _POLICY)


def _unique_digests(digests) -> list[str]:
    """Ordered de-dup: one audit entry per delivered candidate."""
    out: list[str] = []
    seen: set[str] = set()
    for d in digests:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


class GovernedServingGateway:
    """Scope-, digest-, revocation- and applicability-gated candidate serving."""

    def __init__(
        self,
        registry: CandidateRegistry,
        *,
        repository_registry,
        strict_gateway=None,
        allow_global_scope: bool = False,
        conflict_policy: str = "precedence",
        max_steps: int = 12,
        token_budget: int = 400,
        audit_sink: Callable[[Mapping], None] | None = None,
    ) -> None:
        self._candidates = registry
        self._registry = repository_registry
        self._strict = strict_gateway
        self._allow_global = allow_global_scope
        self._conflict_policy = conflict_policy
        self._max_steps = max_steps
        self._token_budget = token_budget
        self._audit = audit_sink
        # task_id -> digest of the guidance actually served, so an outcome
        # can only be attached to guidance this gateway delivered.
        self._served: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    def serve(
        self,
        request: GuidanceRequestV1 | dict,
        *,
        repository_id: str,
        revoked_digests: frozenset | set = frozenset(),
        context: RetrievalContext | None = None,
        files_present=(),
        symbols_extra=(),
        task_family: str | None = None,
        now=None,
    ) -> GuidanceV1:
        served_map = {"candidates": [], "rejections": [],
                      "repository_id": None, "task_id": None}
        try:
            if not isinstance(request, GuidanceRequestV1):
                request = GuidanceRequestV1.from_dict(request)
            served_map["task_id"] = request.task_id
            resolved = self._resolve_repository(repository_id)
            served_map["repository_id"] = resolved
            if resolved is None:
                out = _abstain("insufficient_support", (
                    "Repository identity is not in the trusted registry.",))
                self._emit(served_map, out)
                return out

            ctx = context or RetrievalContext.from_request(
                request, files_present=files_present,
                symbols_extra=symbols_extra)
            eligible = self._eligible(
                resolved, request, ctx, revoked_digests, served_map,
                task_family=task_family)
            composed = compose_guidance(
                eligible, conflict_policy=self._conflict_policy,
                max_steps=self._max_steps, token_budget=self._token_budget)
            served_map["resolutions"] = list(composed.resolutions)

            strict = self._strict.recommend(
                request, repository_id=resolved,
                files_present=files_present,
                symbols_extra=symbols_extra, now=now) \
                if self._strict is not None else None

            if strict is not None and strict.decision == "recommend":
                steps = list(strict.helpful_next_checks)
                added = 0
                for step in composed.steps:
                    if step not in steps:
                        steps.append(step)
                        added += max(1, len(step) // 4)
                merged = tuple(steps)[:8]
                merged_set = set(merged)
                delivered = _unique_digests(
                    d for s, d in composed.step_sources
                    if s in merged_set)
                served_map["candidates"] = delivered
                out = GuidanceV1(
                    schema_version=1, decision="recommend",
                    procedure_ids=strict.procedure_ids,
                    revision=strict.revision,
                    matched_preconditions=strict.matched_preconditions,
                    contraindications=strict.contraindications,
                    evidence_ids=tuple(
                        list(strict.evidence_ids)
                        + [d for d in delivered
                           if d not in strict.evidence_ids])[:32],
                    policy_digest=_POLICY_DIGEST,
                    helpful_next_checks=merged,
                    reason_code=None,
                    approximate_tokens=min(
                        2_000, strict.approximate_tokens + added))
                self._emit(served_map, out)
                return out

            if composed.abstained:
                reason = composed.reason or "insufficient_support"
                out = GuidanceV1(
                    schema_version=1, decision="abstain",
                    procedure_ids=(), revision=None,
                    matched_preconditions=(), contraindications=(),
                    evidence_ids=(), policy_digest=_POLICY_DIGEST,
                    helpful_next_checks=(
                        "No qualified guidance survived the serving gates.",),
                    reason_code=reason if reason in _POLICY["reasons"]
                    else "insufficient_support",
                    approximate_tokens=8)
                self._emit(served_map, out)
                return out

            # Candidate-only advice: advisory steps under an honest
            # abstention decision — memories/skills never claim procedure
            # authority, but the qualified advisory text is still served.
            delivered_steps = tuple(composed.steps)[:7]
            delivered = _unique_digests(
                d for s, d in composed.step_sources
                if s in set(delivered_steps))
            served_map["candidates"] = delivered
            checks = delivered_steps + (
                "Advisory from qualified learned candidates; verify "
                "against task tests before relying on it.",)
            out = GuidanceV1(
                schema_version=1, decision="abstain",
                procedure_ids=(), revision=None,
                matched_preconditions=(), contraindications=(),
                evidence_ids=(), policy_digest=_POLICY_DIGEST,
                helpful_next_checks=tuple(checks)[:8],
                reason_code="no_qualified_procedure",
                approximate_tokens=min(2_000, sum(
                    max(1, len(s) // 4) for s in checks)))
            self._emit(served_map, out)
            return out
        except (ContractError, ValueError, TypeError):
            out = _abstain("catalog_unavailable", (
                "Serving inputs could not be validated.",))
            self._emit(served_map, out)
            return out

    # ------------------------------------------------------------------ #
    def _resolve_repository(self, repository_id: str) -> str | None:
        if not repository_id or self._registry is None:
            return None
        identity = self._registry.resolve(repository_id)
        return identity.registry_id if identity is not None else None

    def _eligible(
        self, requester_id: str, request, ctx,
        revoked: frozenset | set, served_map: dict,
        task_family: str | None = None,
    ) -> list[CandidateV1]:
        out: list[CandidateV1] = []
        requester = self._registry.resolve(requester_id)
        family = getattr(requester, "family_id", None)
        for cand in self._candidates.qualified():
            digest = cand.digest
            reject = None
            if digest in revoked:
                reject = "revoked"
            elif not self._scope_covers(cand, requester_id, family):
                reject = "out_of_scope"
            elif task_family is not None and \
                    cand.target_task_family != task_family:
                # Opt-in hard gate: when the caller declares the task's
                # family, candidates trained for another family are
                # rejected instead of serving off-target advisory text.
                reject = "family_mismatch"
            elif any(not precondition_holds(c, ctx)
                     for c in cand.applicability_predicate):
                reject = "inapplicable"
            elif self._counterexample_hit(cand, ctx):
                reject = "counterexample"
            if reject:
                served_map["rejections"].append(
                    {"candidate_id": cand.candidate_id, "reason": reject})
                continue
            out.append(cand)
        return out

    def _scope_covers(self, cand: CandidateV1, requester_id: str,
                      family_id) -> bool:
        scope = cand.repository_scope
        kind = scope.get("kind") if isinstance(scope, Mapping) else None
        if kind == "registry_id":
            return scope.get("value") == requester_id
        if kind == "family_id":
            return family_id is not None and scope.get("value") == family_id
        if kind == "global":
            return self._allow_global
        return False

    @staticmethod
    def _counterexample_hit(cand: CandidateV1, ctx) -> bool:
        haystack = " ".join(sorted(
            ctx.failure_signatures | ctx.symbols_present
            | ctx.files_present)).lower()
        return any(
            isinstance(cx, str) and suppression_match(haystack, cx)
            for cx in cand.known_counterexamples)

    def record_outcome(self, *, task_id: str, served_digest: str,
                       receipt_digest: str, outcome: str) -> None:
        """Bind the outcome that followed to the guidance that was served.

        The digest must be the guidance this gateway actually delivered
        for ``task_id``; an outcome cannot be attached to guidance that
        was never served, and the receipt reference must be a real
        SHA-256 handle. Durable correlation lives in the audit sink.
        """
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id must be a nonempty string")
        if not (isinstance(served_digest, str) and _HEX.fullmatch(served_digest)):
            raise ValueError("served_digest must be a lowercase SHA-256 digest")
        if not (isinstance(receipt_digest, str) and _HEX.fullmatch(receipt_digest)):
            raise ValueError("receipt_digest must be a lowercase SHA-256 digest")
        if outcome not in _OUTCOMES:
            raise ValueError("unknown outcome: " + repr(outcome))
        if self._served.get(task_id) != served_digest:
            raise ValueError("served_guidance_unknown")
        self._audit_record({
            "schema_version": 1,
            "kind": "serving_outcome",
            "task_id": task_id,
            "served_digest": served_digest,
            "receipt_digest": receipt_digest,
            "outcome": outcome,
        })

    def _emit(self, served_map: dict, guidance: GuidanceV1) -> None:
        task_id = served_map.get("task_id")
        if isinstance(task_id, str) and task_id:
            self._served[task_id] = guidance.digest
        self._audit_record({
            "schema_version": 1,
            "kind": "served_guidance",
            "task_id": task_id,
            "repository_id": served_map.get("repository_id"),
            "decision": guidance.decision,
            "candidate_digests": served_map.get("candidates", []),
            "rejections": served_map.get("rejections", []),
            "resolutions": served_map.get("resolutions", []),
            "served_digest": guidance.digest,
        })

    def _audit_record(self, record: dict) -> None:
        if self._audit is not None:
            self._audit(record)
