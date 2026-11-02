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
- Catalog integrity is re-derived on every serve. The registry folds
  the hash-chained transition log, requires the committed state column
  to match that projection, and re-authenticates the operator decision
  and evaluator evidence binding behind every qualified candidate. A
  direct state flip, a forged decision/evidence row, or a legacy
  unbacked qualification abstains with ``catalog_unavailable`` and an
  audited ``integrity_error`` — never a partial serve.
- Revoked, tampered, malformed, out-of-scope, family-mismatched (when
  ``task_family`` is declared), basis-revoked (a revocation naming the
  candidate's receipt, evidence binding or decision) or inapplicable
  candidates are excluded individually (each rejection is counted and
  auditable); nothing silently degrades to permissive.
- ``decision`` remains honest: ``recommend`` only when the strict
  procedure path qualifies; candidate-only advice is an explicit
  ``advisory`` decision (never a procedure grant), and a genuine
  abstention stays ``abstain`` with a reason.
- Serving outcomes bind a *signature-authenticated* receipt for the
  same task and outcome to the exact guidance digest this gateway
  delivered; a bare digest is not evidence.
- ``target_task_family``/``target_agent`` are provenance fields; the
  optional ``task_family`` argument turns the family field into an
  enforced gate for deployments that want it.
"""
from __future__ import annotations

import re
from typing import Callable, Mapping

from .candidates import CandidateError, CandidateRegistry
from .composition import compose_guidance
from .control_plane import ControlPlaneError
from .contracts import (
    CandidateV1,
    ContractError,
    EvaluatorReceiptV2,
    ExecutionAttemptV2,
    GuidanceRequestV1,
    GuidanceV1,
    OutcomeV2,
    _instant,
    canonical_digest,
)
from .authority_ledger import AuthorizationRequest, LedgerError
from .evidence_binding import (
    BindingError,
    attempt_id_for_identity,
    match_chain,
)
from .evidence_policy import negative_transfer_guard
from .evidence_policy import select as select_evidence
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
    """Decision/evidence-authenticated, scope- and revocation-gated serving."""

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
        receipt_authority: Callable[[str], object] | None = None,
        production: bool = False,
        execution_identity_authority=None,
        require_execution_identity: bool | None = None,
        used_session_nonces: set | None = None,
        control_plane=None,
        binding_authority=None,
        authority_ledger=None,
        evidence_policy=None,
        evidence_provider=None,
        rollout=None,
        monitor=None,
    ) -> None:
        self._candidates = registry
        self._identity_authority = execution_identity_authority
        if production and require_execution_identity is False:
            # An execution identity is the only authenticated statement of
            # which repository/commit/task this advice is for. Production
            # may not opt out of it.
            raise ValueError(
                "production_requires_execution_identity")
        self._require_identity = (
            bool(require_execution_identity)
            if require_execution_identity is not None else bool(production))
        if production and control_plane is None:
            # Replay protection that lives in one process is not replay
            # protection. Production must share the nonce constraint.
            raise ValueError("production_requires_control_plane")
        self._control_plane = control_plane
        if authority_ledger is not None and control_plane is None:
            # The ledger commits through the control plane; without one
            # it would never be consulted, so the wiring is a mistake.
            raise ValueError("authority_ledger_requires_control_plane")
        if (evidence_policy is None) != (evidence_provider is None):
            # A policy with no evidence or evidence with no policy is a
            # silently disabled control, not a default.
            raise ValueError(
                "evidence_policy_and_provider_must_be_configured_together")
        self._binding_authority = binding_authority
        self._ledger = authority_ledger
        self._evidence_policy = evidence_policy
        self._evidence_provider = evidence_provider
        # A rollout state is enforced when supplied: shadow delivers
        # nothing and advisory delivers no procedure grants. Supplying it
        # is the deployment's choice; a gateway without one serves at the
        # stage its operator configured elsewhere.
        self._rollout = rollout
        self._monitor = monitor
        # Bound outcomes require a control plane that can sign an
        # authorization and a key set that can authenticate the evaluator
        # and harness. Without both this gateway can still serve (guidance
        # is not the vulnerable surface) but it may not record an outcome
        # in production, and readiness reports the gap.
        self._bound = bool(
            control_plane is not None
            and getattr(control_plane, "supports_bound_authorization",
                        lambda: False)()
            and binding_authority is not None)
        self._used_nonces = used_session_nonces \
            if used_session_nonces is not None else set()
        # Production serving requires an independently checkpointed
        # registry. Development/tests may run uncheckpointed, but the
        # audit record says so explicitly; it is never presented as
        # production-qualified serving.
        self._production = bool(production)
        self._registry = repository_registry
        self._strict = strict_gateway
        self._allow_global = allow_global_scope
        self._conflict_policy = conflict_policy
        self._max_steps = max_steps
        self._token_budget = token_budget
        self._audit = audit_sink
        # Outcomes may only cite a receipt the trusted evaluator boundary
        # resolves and authenticates; a bare digest is not evidence.
        self._receipt_authority = receipt_authority
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
        execution_identity=None,
        requester_identity: str | None = None,
        now=None,
    ) -> GuidanceV1:
        served_map = {"candidates": [], "rejections": [],
                      "repository_id": None, "task_id": None}
        snapshot = None
        identity_result = None
        try:
            if not isinstance(request, GuidanceRequestV1):
                request = GuidanceRequestV1.from_dict(request)
            served_map["task_id"] = request.task_id
            if self._production:
                # Deny before any candidate text is composed: an
                # uncheckpointed or rolled-back catalog is not a
                # production authority, and a registry without a
                # certificate policy holds demonstration evidence only.
                if getattr(self._candidates, "qualification_mode",
                           "demonstration") != "production":
                    raise CandidateError(
                        "production_qualification_required")
                if not getattr(self._candidates, "has_evidence_custody",
                               False):
                    # Without custody there is no revocation or
                    # supersession history to witness.
                    raise CandidateError("evidence_custody_unconfigured")
                served_map["custody_freshness"] = \
                    self._candidates.check_offline_serving(offline=False)
                snapshot = self._authority_snapshot()
                if self._control_plane is not None:
                    try:
                        head = self._control_plane.authority_head()
                    except ControlPlaneError as exc:
                        raise CandidateError(
                            "control_plane_unavailable:"
                            f"{exc.reason}") from exc
                    if head is None:
                        # Upgrade/recovery: the signed checkpoint is the
                        # independent witness, so a fresh control plane
                        # can be anchored to it instead of refusing
                        # every serve.
                        seed = getattr(
                            self._candidates, "seed_authority_head", None)
                        if not callable(seed):
                            raise CandidateError(
                                "authority_head_uninitialized")
                        try:
                            seed(self._control_plane)
                        except ControlPlaneError as exc:
                            raise CandidateError(
                                "control_plane_unavailable:"
                                f"{exc.reason}") from exc
                served_map["authority"] = snapshot["authority"]
                served_map["authority_snapshot"] = snapshot["digest"]
            if self._control_plane is not None:
                # The kill switch is read from the shared store on every
                # request, so a disable committed by any replica is
                # effective here without a restart.
                try:
                    ledger_state = self._control_plane.authority_state()
                except ControlPlaneError as exc:
                    raise CandidateError(
                        "control_plane_unavailable:" + exc.reason) from exc
                if ledger_state.get("global_disable"):
                    served_map["global_disable"] = True
                    out = _abstain("catalog_unavailable", (
                        "Guidance serving is disabled by the operator.",))
                    self._emit(served_map, out)
                    return out
                # The epoch this decision observed. The commit refuses if
                # the ledger moved before it (authority_epoch_changed).
                served_map["observed_epoch"] = ledger_state.get("epoch")
            identity_result = None
            if self._require_identity or execution_identity is not None:
                if self._identity_authority is None:
                    raise CandidateError(
                        "execution_identity_authority_unconfigured")
                identity_result = self._identity_authority.verify(
                    execution_identity,
                    used_nonces=self._used_nonces,
                    expected_repository_id=repository_id or None,
                    expected_tree_digest=request.repo_snapshot_digest,
                    expected_commit=request.base_commit,
                    expected_task_id=request.task_id,
                    expected_task_family=task_family,
                    expected_requester=requester_identity,
                )
                if not identity_result.ok:
                    served_map["identity_error"] = identity_result.reason
                    out = _abstain("catalog_unavailable", (
                        "Execution identity could not be authenticated.",))
                    self._emit(served_map, out)
                    return out
                if self._control_plane is None:
                    self._used_nonces.add(
                        identity_result.identity.session_nonce)
                served_map["execution_identity"] = \
                    identity_result.identity.digest
            if self._rollout is not None and not self._rollout.may_serve():
                # Shadow observes and records, and never delivers. The
                # identity is verified first so the audit record says who
                # was asking, not just that something was withheld.
                served_map["rollout_stage"] = self._rollout.stage
                out = _abstain("rollout_shadow", (
                    "Guidance is in the shadow stage and is not delivered.",))
                self._emit(served_map, out)
                return out
            if identity_result is not None:
                resolved = identity_result.repository_identity.registry_id
            else:
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
            if self._evidence_policy is not None and \
                    self._evidence_provider is not None:
                eligible = self._calibrate(
                    eligible, ctx, served_map)
            served_map["candidate_ids"] = [c.candidate_id for c in eligible]
            served_map["basis_digests"] = [c.digest for c in eligible]
            composed = compose_guidance(
                eligible, conflict_policy=self._conflict_policy,
                max_steps=self._max_steps, token_budget=self._token_budget)
            served_map["resolutions"] = list(composed.resolutions)

            strict = self._strict.recommend(
                request, repository_id=resolved,
                files_present=files_present,
                symbols_extra=symbols_extra, now=now) \
                if self._strict is not None else None

            if strict is not None and strict.decision == "recommend" and (
                    self._rollout is None
                    or self._rollout.may_grant_procedures()):
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
                return self._finish(out, served_map, snapshot,
                                    identity_result, request.task_id)

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
                return self._finish(out, served_map, snapshot,
                                    identity_result, request.task_id)

            # Candidate-only advice: an explicit advisory decision —
            # memories/skills never claim procedure authority, but the
            # qualified advisory text is still served.
            delivered_steps = tuple(composed.steps)[:7]
            delivered = _unique_digests(
                d for s, d in composed.step_sources
                if s in set(delivered_steps))
            served_map["candidates"] = delivered
            checks = delivered_steps + (
                "Advisory from qualified learned candidates; verify "
                "against task tests before relying on it.",)
            out = GuidanceV1(
                schema_version=1, decision="advisory",
                procedure_ids=(), revision=None,
                matched_preconditions=(), contraindications=(),
                evidence_ids=(), policy_digest=_POLICY_DIGEST,
                helpful_next_checks=tuple(checks)[:8],
                reason_code="no_qualified_procedure",
                approximate_tokens=min(2_000, sum(
                    max(1, len(s) // 4) for s in checks)))
            return self._finish(out, served_map, snapshot,
                                identity_result, request.task_id)
        except CandidateError as exc:
            # The registry re-authenticates the audit chain, state
            # projection and signed serving basis on every read. A failure
            # here means the catalog cannot be trusted — abstain, never
            # serve a subset that merely happens to parse.
            served_map["integrity_error"] = str(exc)
            out = _abstain("catalog_unavailable", (
                "Candidate catalog integrity could not be verified.",))
            return self._finish(out, served_map, snapshot,
                                identity_result, served_map.get("task_id"))
        except (ContractError, ValueError, TypeError):
            out = _abstain("catalog_unavailable", (
                "Serving inputs could not be validated.",))
            return self._finish(out, served_map, snapshot,
                                identity_result, served_map.get("task_id"))

    @property
    def control_plane(self):
        return self._control_plane

    def health(self) -> dict:
        """Readiness of the authority inputs a decision depends on."""
        checks: dict[str, dict] = {}
        ok = True
        try:
            authority = self._candidates.authority_status()
            healthy = authority.get("mode") == "checkpoint_verified"
            checks["authority"] = {
                "ok": healthy,
                "mode": authority.get("mode"),
                "checkpoint_digest": authority.get("checkpoint_digest"),
            }
            ok = ok and healthy
        except Exception as exc:  # noqa: BLE001 - health reports, never raises
            checks["authority"] = {
                "ok": False, "error": type(exc).__name__}
            ok = False
        try:
            custody = self._candidates.evidence_custody_snapshot()
            checks["custody"] = {
                "ok": True,
                "revocation_head": custody["revocation_head"],
                "supersession_head": custody["supersession_head"],
                "custody_entry_count": custody["custody_entry_count"],
            }
        except Exception as exc:  # noqa: BLE001
            checks["custody"] = {
                "ok": False, "error": type(exc).__name__}
            ok = False
        if self._control_plane is not None:
            try:
                head = self._control_plane.authority_head()
                checks["control_plane"] = {
                    "ok": head is not None,
                    "sequence": head["sequence"] if head else None,
                }
                ok = ok and head is not None
            except Exception as exc:  # noqa: BLE001
                checks["control_plane"] = {
                    "ok": False, "error": type(exc).__name__}
                ok = False
        # Liveness is "the process answers"; readiness is "this deployment
        # can record trustworthy evidence". A production replica that can
        # serve but cannot bind an outcome is not ready, even though it is
        # alive.
        binding_ready = self._bound or not self._production
        checks["outcome_binding"] = {
            "ok": binding_ready,
            "mode": "bound" if self._bound else "legacy",
        }
        ok = ok and binding_ready
        if self._rollout is not None:
            # Gates govern promotion, not serving at the current stage;
            # the stage itself is what readiness reports.
            checks["rollout"] = {
                "ok": True,
                "stage": self._rollout.stage,
                "ready_to_promote": self._rollout.ready,
                "failed_gates": list(self._rollout.failed_gates),
                "may_serve": self._rollout.may_serve(),
            }
        if self._ledger is not None:
            # A configured ledger is the authority the decisions cite; if
            # its signed snapshot is missing, stale or unverifiable, this
            # replica cannot record trustworthy evidence.
            try:
                readiness = self._ledger.readiness()
                checks["ledger"] = readiness
                ok = ok and bool(readiness.get("ok"))
            except Exception as exc:  # noqa: BLE001 - fail closed
                checks["ledger"] = {
                    "ok": False, "error": type(exc).__name__}
                ok = False
        if self._monitor is not None:
            try:
                report = self._monitor.scan()
                allowed = bool(report.get("serving_allowed"))
                checks["authority_monitor"] = {
                    "ok": allowed,
                    "critical": report.get("critical", 0),
                    "warning": report.get("warning", 0),
                    "findings": [finding["code"]
                                 for finding in report.get("findings", [])],
                }
                ok = ok and allowed
            except Exception as exc:  # noqa: BLE001 - fail closed
                checks["authority_monitor"] = {
                    "ok": False, "error": type(exc).__name__}
                ok = False
        return {
            "ok": ok,
            "ready": ok,
            "alive": True,
            "serving_mode": "production" if self._production
            else "development",
            "outcome_binding": "bound" if self._bound else "legacy",
            "rollout_stage": (self._rollout.stage
                              if self._rollout is not None else None),
            "checks": checks,
        }

    # ------------------------------------------------------------------ #
    def _authority_snapshot(self) -> dict:
        """Verified authority + custody state a decision may rely on."""
        authority = self._candidates.authority_status()
        if authority.get("mode") != "checkpoint_verified":
            raise CandidateError("authority_checkpoint_unconfigured")
        custody = self._candidates.evidence_custody_snapshot()
        head = {
            "sequence": authority.get("checkpoint_sequence"),
            "checkpoint_digest": authority.get("checkpoint_digest"),
            "journal_head": authority.get("journal_head"),
            "revocation_head": custody["revocation_head"],
            "supersession_head": custody["supersession_head"],
            "custody_entry_count": custody["custody_entry_count"],
        }
        if head["sequence"] is None or head["checkpoint_digest"] is None:
            raise CandidateError("authority_checkpoint_incomplete")
        return {
            "authority": authority,
            "custody": custody,
            "head": head,
            "digest": canonical_digest("authority_snapshot", 1, head),
        }

    def _revalidate(self, snapshot: dict) -> None:
        """Fail if the authority changed while guidance was composed.

        A revocation committed before this decision returns must prevent
        the decision from delivering the revoked evidence. Comparing the
        full witnessed snapshot (candidate journal + custody heads)
        closes the read-then-compose window instead of assuming a short
        cache expiry is sufficient.
        """
        current = self._authority_snapshot()
        if current["digest"] != snapshot["digest"]:
            raise ControlPlaneError("authority_snapshot_changed")

    def _finish(self, out: GuidanceV1, served_map: dict, snapshot,
                identity_result, task_id) -> GuidanceV1:
        """Revalidate, commit the authorization receipt, then emit."""
        if identity_result is not None and identity_result.ok:
            try:
                if snapshot is not None:
                    self._revalidate(snapshot)
                snapshot_digest = (
                    snapshot["digest"] if snapshot is not None
                    else canonical_digest(
                        "authority_snapshot", 1, {"mode": "development"}))
                if self._ledger is not None and self._bound:
                    record = self._ledger.authorize(AuthorizationRequest(
                        attempt_id=attempt_id_for_identity(
                            identity_result.identity),
                        nonce=identity_result.identity.session_nonce,
                        session_digest=identity_result.identity.digest,
                        execution_identity_digest=(
                            identity_result.identity.digest),
                        requester_principal_id=(
                            identity_result.identity.requester_identity),
                        task_id=task_id,
                        repository_id=(
                            served_map.get("repository_id")
                            or identity_result.identity.repository_id),
                        repository_tree_digest=(
                            identity_result.identity.repository_tree_digest),
                        base_commit_digest=(
                            identity_result.identity.repository_commit),
                        guidance_digest=out.digest,
                        decision=out.decision,
                        expires_at=identity_result.identity.expires_at,
                        identity_expires_at=(
                            identity_result.identity.expires_at),
                        candidate_ids=tuple(
                            served_map.get("candidate_ids", ())),
                        procedure_ids=tuple(out.procedure_ids),
                        basis_digests=tuple(
                            served_map.get("basis_digests", ())),
                        expected_epoch=served_map.get("observed_epoch"),
                        expected_head=(
                            snapshot["head"] if snapshot is not None
                            else None),
                    ))
                    served_map["authorization_id"] = record.authorization_id
                    served_map["attempt_id"] = record.attempt_id
                    served_map["execution_identity_digest"] = \
                        record.execution_identity_digest
                    served_map["authority_epoch"] = record.authority_epoch
                elif self._control_plane is not None and self._bound:
                    record = self._control_plane.commit_bound_authorization(
                        attempt_id=attempt_id_for_identity(
                            identity_result.identity),
                        nonce=identity_result.identity.session_nonce,
                        session_digest=identity_result.identity.digest,
                        execution_identity_digest=(
                            identity_result.identity.digest),
                        requester_principal_id=(
                            identity_result.identity.requester_identity),
                        task_id=task_id,
                        repository_id=(
                            served_map.get("repository_id")
                            or identity_result.identity.repository_id),
                        repository_tree_digest=(
                            identity_result.identity.repository_tree_digest),
                        base_commit_digest=(
                            identity_result.identity.repository_commit),
                        guidance_digest=out.digest,
                        decision=out.decision,
                        expires_at=identity_result.identity.expires_at,
                        expected_head=(
                            snapshot["head"] if snapshot is not None
                            else None),
                    )
                    served_map["authorization_id"] = record.authorization_id
                    served_map["attempt_id"] = record.attempt_id
                    served_map["execution_identity_digest"] = \
                        record.execution_identity_digest
                    served_map["authority_epoch"] = record.authority_epoch
                elif self._control_plane is not None:
                    receipt = self._control_plane.commit_authorization(
                        nonce=identity_result.identity.session_nonce,
                        session_digest=identity_result.identity.digest,
                        expires_at=identity_result.identity.expires_at,
                        task_id=task_id,
                        repository_id=served_map.get("repository_id"),
                        guidance_digest=out.digest,
                        decision=out.decision,
                        snapshot_digest=snapshot_digest,
                        expected_head=(
                            snapshot["head"] if snapshot is not None
                            else None),
                    )
                    served_map["authorization_id"] = \
                        receipt["authorization_id"]
                self._served[task_id] = out.digest
            except (ControlPlaneError, CandidateError, ContractError,
                    LedgerError) as exc:
                reason = getattr(exc, "reason", str(exc))
                served_map["commit_error"] = reason
                if reason == "session_nonce_replayed":
                    detail = "Execution identity was already used."
                elif reason == "authority_snapshot_changed":
                    detail = ("Authority changed while guidance was being"
                              " prepared.")
                else:
                    detail = ("Authorization could not be committed against"
                              " the current authority snapshot.")
                out = _abstain("catalog_unavailable", (detail,))
        self._emit(served_map, out)
        return out

    def _calibrate(self, eligible, ctx, served_map: dict):
        """Apply the evidence-calibrated policy to the eligible set."""
        evidence = []
        for candidate in eligible:
            try:
                item = self._evidence_provider(candidate)
            except Exception as exc:  # noqa: BLE001 - fail closed per rule
                served_map["rejections"].append({
                    "candidate_id": candidate.candidate_id,
                    "reason": "evidence_unavailable",
                    "detail": type(exc).__name__})
                continue
            blocked = negative_transfer_guard(
                item, task_signature=ctx.task_signature,
                known_failures=item.known_failure_signatures)
            if blocked is not None:
                # A rule that already made a resembling task worse is not
                # a candidate, whatever its utility score says.
                served_map["rejections"].append({
                    "candidate_id": item.candidate_id,
                    "reason": blocked})
                continue
            evidence.append(item)
        if not evidence:
            return []
        decisions = select_evidence(
            evidence, ctx, self._evidence_policy,
            token_budget=self._token_budget, max_rules=self._max_steps)
        served_map["policy_decisions"] = [d.to_dict() for d in decisions]
        served_map["rejections"].extend(
            {"candidate_id": d.candidate_id, "reason": d.reason}
            for d in decisions if not d.serve)
        keep = {d.candidate_id for d in decisions if d.serve}
        return [c for c in eligible if c.candidate_id in keep]

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
        for cand, basis in self._candidates.qualified_bases():
            digest = cand.digest
            reject = None
            if digest in revoked:
                reject = "revoked"
            elif revoked and self._basis_revoked(basis, revoked):
                reject = "evidence_revoked"
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

    @staticmethod
    def _basis_revoked(basis: Mapping, revoked) -> bool:
        """True when a committed revocation names this candidate's basis.

        The decision is the authorization artifact; a revocation that
        names it must suppress serving exactly like one that names the
        receipts or the evidence binding.
        """
        handles = set(basis.get("receipt_refs", ())) \
            | set(basis.get("evidence_refs", ()))
        if basis.get("decision_digest"):
            handles.add(basis["decision_digest"])
        return bool(handles & set(revoked))

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

    def record_outcome(
        self, *, requester_principal_id: str | None = None,
        authorization_id: str | None = None,
        evaluator_receipt: EvaluatorReceiptV2 | Mapping | None = None,
        attempt: ExecutionAttemptV2 | Mapping | None = None,
        task_id: str | None = None,
        served_digest: str | None = None,
        receipt_digest: str | None = None,
        outcome: str | None = None,
        independence: str | None = None,
        dependency_receipt_digest: str | None = None,
    ) -> dict:
        """Record one verified outcome for one bound intervention.

        Bound mode (any gateway with a signing control plane) requires the
        full V2 chain. Every binding is compared exactly: requester,
        execution identity, task, attempt, repository, tree, commit,
        guidance and exposure. A missing or mismatched field is rejected;
        there is no fallback that records an unbound outcome.

        Legacy mode (development gateways with no control plane) keeps the
        schema-1 path so local experiments still work, and marks the
        result ``legacy_unverified``: it is never independent evidence.
        """
        if self._bound:
            return self._record_bound_outcome(
                requester_principal_id=requester_principal_id,
                authorization_id=authorization_id,
                evaluator_receipt=evaluator_receipt,
                attempt=attempt,
                task_id=task_id,
                served_digest=served_digest,
                receipt_digest=receipt_digest,
                outcome=outcome,
                independence=independence,
                dependency_receipt_digest=dependency_receipt_digest)
        return self._record_legacy_outcome(
            task_id=task_id, served_digest=served_digest,
            receipt_digest=receipt_digest, outcome=outcome,
            authorization_id=authorization_id)

    def _record_bound_outcome(
        self, *, requester_principal_id, authorization_id, evaluator_receipt,
        attempt, task_id, served_digest, receipt_digest, outcome,
        independence, dependency_receipt_digest,
    ) -> dict:
        if not (isinstance(requester_principal_id, str)
                and requester_principal_id):
            raise ValueError("requester_identity_required")
        if not (isinstance(authorization_id, str) and authorization_id):
            # An implicit "latest authorization for this task" is exactly
            # how one receipt used to be credited to two interventions.
            raise ValueError("authorization_id_required")
        if evaluator_receipt is None:
            raise ValueError("evaluator_receipt_required")
        try:
            authorization = self._control_plane.bound_authorization(
                authorization_id)
        except ControlPlaneError as exc:
            raise ValueError(exc.reason) from exc
        if authorization is None:
            raise ValueError("authorization_unknown")

        try:
            receipt = self._binding_authority.receipt(evaluator_receipt)
            attempt_record = (self._binding_authority.attempt(attempt)
                              if attempt is not None else None)
            revoked_signers, revoked_digests = \
                self._binding_authority.revocation_state()
            match = match_chain(
                authorization=authorization,
                attempt=attempt_record,
                receipt=receipt,
                requester_principal_id=requester_principal_id,
                now=self._binding_authority.now,
                revoked_signers=revoked_signers,
                revoked_digests=revoked_digests,
            )
        except BindingError as exc:
            raise ValueError(exc.reason) from exc

        # Caller-asserted values must agree with the binding; they are
        # never used as the source of truth.
        if task_id is not None and task_id != authorization.task_id:
            raise ValueError("outcome_task_mismatch")
        if served_digest is not None and \
                served_digest != authorization.guidance_digest:
            raise ValueError("served_guidance_unknown")
        if receipt_digest is not None and receipt_digest != receipt.digest:
            raise ValueError("receipt_digest_mismatch")
        if outcome is not None and outcome != receipt.result:
            raise ValueError("receipt_outcome_mismatch")
        if independence is not None and independence != receipt.independence:
            # Independence is the evaluator's signed statement, not the
            # requester's: a caller may restate it, not change it.
            raise ValueError("independence_mismatch")
        if dependency_receipt_digest is not None and \
                dependency_receipt_digest != receipt.dependency_receipt_digest:
            raise ValueError("dependency_receipt_mismatch")

        try:
            if attempt_record is not None:
                self._control_plane.record_attempt_exposure(attempt_record)
            self._control_plane.record_evaluator_receipt(receipt)
            record = OutcomeV2(
                schema_version=1,
                outcome_id="out-" + match.bindings_digest[:32],
                authorization_id=authorization.authorization_id,
                receipt_digest=receipt.digest,
                attempt_id=authorization.attempt_id,
                task_id=authorization.task_id,
                requester_principal_id=authorization.requester_principal_id,
                repository_id=authorization.repository_id,
                guidance_digest=authorization.guidance_digest,
                guidance_exposure_digest=receipt.guidance_exposure_digest,
                result=receipt.result,
                independence=match.independence,
                dependency_receipt_digest=match.dependency_receipt_digest,
                authority_snapshot_digest=(
                    authorization.authority_snapshot_digest),
                bindings_digest=match.bindings_digest,
                recorded_at=self._binding_authority.now,
            )
            stored = self._control_plane.record_bound_outcome(record)
        except ControlPlaneError as exc:
            raise ValueError(exc.reason) from exc
        except ContractError as exc:
            raise ValueError("outcome_malformed") from exc

        self._audit_record({
            "schema_version": 2,
            "kind": "serving_outcome",
            "evidence_class": "verified",
            "outcome_id": record.outcome_id,
            "authorization_id": record.authorization_id,
            "attempt_id": record.attempt_id,
            "execution_identity_digest":
                authorization.execution_identity_digest,
            "requester_principal_id": record.requester_principal_id,
            "repository_id": record.repository_id,
            "task_id": record.task_id,
            "served_digest": record.guidance_digest,
            "guidance_exposure_digest": record.guidance_exposure_digest,
            "receipt_digest": record.receipt_digest,
            "outcome": record.result,
            "independence": record.independence,
            "bindings_digest": record.bindings_digest,
        })
        return {"record": record, "stored": stored}

    def _record_legacy_outcome(self, *, task_id: str, served_digest: str,
                               receipt_digest: str, outcome: str,
                               authorization_id: str | None = None) -> dict:
        """Schema-1 path: dev-only, quarantined as legacy evidence.

        The digest must be the guidance this gateway actually delivered
        for ``task_id``; the receipt must resolve through the trusted
        evaluator boundary, authenticate, carry the same task and the
        same outcome. An unauthenticated digest is not an outcome.
        """
        if self._production:
            # Production evidence is only ever the verified chain.
            raise ValueError("bound_outcome_required")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id must be a nonempty string")
        if not (isinstance(served_digest, str) and _HEX.fullmatch(served_digest)):
            raise ValueError("served_digest must be a lowercase SHA-256 digest")
        if not (isinstance(receipt_digest, str) and _HEX.fullmatch(receipt_digest)):
            raise ValueError("receipt_digest must be a lowercase SHA-256 digest")
        if outcome not in _OUTCOMES:
            raise ValueError("unknown outcome: " + repr(outcome))
        authorization = None
        if self._control_plane is not None:
            if authorization_id is not None:
                authorization = self._control_plane.authorization(
                    authorization_id)
            else:
                authorization = self._control_plane.authorization_for_task(
                    task_id)
            if authorization is None or \
                    authorization["guidance_digest"] != served_digest or \
                    authorization["task_id"] != task_id:
                raise ValueError("served_guidance_unknown")
        elif self._served.get(task_id) != served_digest:
            raise ValueError("served_guidance_unknown")
        if self._receipt_authority is None:
            raise ValueError("receipt_authority_required")
        try:
            receipt = self._receipt_authority(receipt_digest)
        except Exception as exc:
            raise ValueError("receipt_unauthenticated") from exc
        if receipt is None:
            raise ValueError("receipt_unauthenticated")
        if getattr(receipt, "task_id", None) != task_id:
            raise ValueError("receipt_task_mismatch")
        if getattr(receipt, "outcome", None) != outcome:
            raise ValueError("receipt_outcome_mismatch")
        if self._control_plane is not None:
            try:
                self._control_plane.record_outcome(
                    authorization_id=authorization["authorization_id"],
                    task_id=task_id, served_digest=served_digest,
                    receipt_digest=receipt_digest, outcome=outcome)
            except ControlPlaneError as exc:
                raise ValueError(exc.reason) from exc
        self._audit_record({
            "schema_version": 1,
            "kind": "serving_outcome",
            "evidence_class": "legacy_unverified",
            "task_id": task_id,
            "served_digest": served_digest,
            "receipt_digest": receipt_digest,
            "outcome": outcome,
        })
        return {"record": None, "legacy": True}

    def recheck(self, authorization_id: str) -> dict:
        """Fresh authorization check before a delayed delivery.

        Guidance that was authorized earlier may be delivered later. The
        authorization is re-read from the shared store and every
        condition that can have changed since is re-evaluated: expiry,
        signer/digest revocation, the global kill switch and the ledger
        epoch. Anything that cannot be re-verified is a refusal.
        """
        if self._control_plane is None:
            raise ValueError("control_plane_required")
        try:
            authorization = self._control_plane.bound_authorization(
                authorization_id)
        except ControlPlaneError as exc:
            raise ValueError(exc.reason) from exc
        if authorization is None:
            raise ValueError("authorization_unknown")
        now = (self._binding_authority.now
               if self._binding_authority is not None else None)
        if now is not None and _instant(now) >= _instant(
                authorization.expires_at):
            # Both sides are parsed: comparing ISO strings accepts an
            # expired authorization whenever the recorded offset is not
            # "Z" (e.g. 14:00+05:00 is 09:00Z).
            raise ValueError("authorization_expired")
        if self._binding_authority is not None:
            signers, digests = self._binding_authority.revocation_state()
            if authorization.signer_key_id in signers:
                raise ValueError("authorization_signer_revoked")
            if authorization.digest in digests:
                raise ValueError("authorization_revoked")
        state = self._control_plane.authority_state()
        if state.get("global_disable"):
            raise ValueError("global_disable")
        epoch = state.get("epoch") or 0
        if authorization.authority_epoch != epoch:
            # The ledger moved after this decision; a delayed delivery is
            # a delivery under a state the decision never saw.
            raise ValueError("authority_epoch_changed")
        return {
            "authorization_id": authorization.authorization_id,
            "attempt_id": authorization.attempt_id,
            "authority_epoch": authorization.authority_epoch,
            "ledger_epoch": epoch,
            "expires_at": authorization.expires_at,
        }

    def _emit(self, served_map: dict, guidance: GuidanceV1) -> None:
        task_id = served_map.get("task_id")
        if isinstance(task_id, str) and task_id:
            self._served[task_id] = guidance.digest
        record = {
            "schema_version": 1,
            "kind": "served_guidance",
            "task_id": task_id,
            "repository_id": served_map.get("repository_id"),
            "decision": guidance.decision,
            "candidate_digests": served_map.get("candidates", []),
            "rejections": served_map.get("rejections", []),
            "resolutions": served_map.get("resolutions", []),
            "served_digest": guidance.digest,
            "serving_mode": "production" if self._production else "development",
        }
        if served_map.get("authority"):
            record["authority"] = served_map["authority"]
        if served_map.get("execution_identity"):
            record["execution_identity"] = served_map["execution_identity"]
        if served_map.get("identity_error"):
            record["identity_error"] = served_map["identity_error"]
        if served_map.get("integrity_error"):
            record["integrity_error"] = served_map["integrity_error"]
        if served_map.get("policy_decisions"):
            record["policy_decisions"] = served_map["policy_decisions"]
        if served_map.get("authority_epoch"):
            record["authority_epoch"] = served_map["authority_epoch"]
        if served_map.get("global_disable"):
            record["global_disable"] = True
        if served_map.get("rollout_stage"):
            record["rollout_stage"] = served_map["rollout_stage"]
        self._audit_record(record)

    def _audit_record(self, record: dict) -> None:
        if self._audit is not None:
            self._audit(record)
