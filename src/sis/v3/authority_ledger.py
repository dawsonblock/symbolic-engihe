"""Unified authority ledger (PR-06).

v3.3.2 kept candidate status in one SQLite database, procedure status in
another, scope grants in a third and signer revocations in a fourth. A
hash of those four heads is not an authority boundary: two of them can
change between the read and the commit, and the decision is then made
against a state that never existed.

This module gives every authority input one home — the control plane's
schema-3 tables — and one serialization point: the transaction that
commits an authorization also reads the epoch, evaluates the guard and
writes the record. The authorization predicate is

    Authorize = I ∧ S ∧ E ∧ A ∧ ¬R ∧ ¬K

where I is the verified execution identity, S the scope grant, E the
unexpired authorization, A the current authority (candidate and procedure
status at the pinned epoch), R an applicable revocation and K the global
disable flag. If any term cannot be evaluated, SIS abstains.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping

from . import signatures
from .contracts import (
    AuthoritySnapshotV2,
    ContractError,
    canonical_json,
)
from .control_plane import AuthorityView, ControlPlaneError

SNAPSHOT_DOMAIN = b"sis-v3:authority_snapshot_v2:1\0"

QUALIFIED = "qualified"
CANDIDATE_KIND = "candidate"
PROCEDURE_KIND = "procedure"
GRANT_KIND = "grant"
SIGNER_REVOCATION = "signer"
DIGEST_REVOCATION = "digest"


class LedgerError(RuntimeError):
    """An authority change or check failed closed."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def snapshot_body(snapshot: AuthoritySnapshotV2 | Mapping) -> bytes:
    body = snapshot.to_dict() if hasattr(snapshot, "to_dict") \
        else dict(snapshot)
    body.pop("signature", None)
    return SNAPSHOT_DOMAIN + canonical_json(body)


def sign_snapshot(seed: bytes, **fields) -> AuthoritySnapshotV2:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items() if k != "signature"}
    signature = signatures.sign(seed, snapshot_body(unsigned)).hex()
    return AuthoritySnapshotV2.from_dict({**unsigned, "signature": signature})


def verify_snapshot(snapshot: AuthoritySnapshotV2, public_hex: str) -> bool:
    try:
        return signatures.verify(
            bytes.fromhex(snapshot.signature), snapshot_body(snapshot),
            bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class AuthorizationRequest:
    """Everything the ledger needs to decide and commit one authorization."""

    attempt_id: str
    nonce: str
    session_digest: str
    execution_identity_digest: str
    requester_principal_id: str
    task_id: str
    repository_id: str
    repository_tree_digest: str
    base_commit_digest: str | None
    guidance_digest: str
    decision: str
    expires_at: str
    identity_expires_at: str
    candidate_ids: tuple[str, ...] = ()
    procedure_ids: tuple[str, ...] = ()
    grant_ids: tuple[str, ...] = ()
    basis_digests: tuple[str, ...] = ()
    signer_ids: tuple[str, ...] = ()
    expected_epoch: int | None = None
    expected_head: Mapping | None = None


class AuthorityLedger:
    """The single authority boundary every guidance decision commits to."""

    def __init__(self, control_plane, *, signing_key,
                 policy_version: str = "sis-v3.4.0-authority-policy",
                 clock: Callable[[], str] | None = None,
                 allow_shared_signer: bool = False) -> None:
        if not control_plane.supports_bound_authorization():
            raise LedgerError("control_plane_not_bound")
        authorization_signer = getattr(
            control_plane, "signing_key_id", lambda: None)()
        if signing_key.key_id == authorization_signer and \
                not allow_shared_signer:
            # The identity that issues authorizations must not also sign
            # the ledger snapshots: a shared key means the issuer can
            # rewrite the authority state its own decisions cite.
            raise LedgerError("ledger_signer_not_distinct",
                              signing_key.key_id)
        self._plane = control_plane
        self._key = signing_key
        self._public_hex = signatures.public_key(signing_key.seed).hex()
        self._policy_version = policy_version
        self._clock = clock or _utcnow

    @property
    def plane(self):
        return self._plane

    # -- authority changes --------------------------------------------- #
    def set_candidate_status(self, candidate_id: str, status: str, *,
                             detail: str | None = None) -> dict:
        return self._plane.set_authority_subject(
            subject_kind=CANDIDATE_KIND, subject_id=candidate_id,
            status=status, detail=detail, now=self._clock())

    def set_procedure_status(self, procedure_id: str, status: str, *,
                             detail: str | None = None) -> dict:
        return self._plane.set_authority_subject(
            subject_kind=PROCEDURE_KIND, subject_id=procedure_id,
            status=status, detail=detail, now=self._clock())

    def set_grant_status(self, grant_id: str, status: str, *,
                         detail: str | None = None) -> dict:
        return self._plane.set_authority_subject(
            subject_kind=GRANT_KIND, subject_id=grant_id,
            status=status, detail=detail, now=self._clock())

    def revoke_signer(self, key_id: str, *, reason: str | None = None) -> dict:
        return self._plane.set_authority_revocation(
            revocation_kind=SIGNER_REVOCATION, target=key_id, reason=reason,
            now=self._clock())

    def revoke_digest(self, digest: str, *, reason: str | None = None) -> dict:
        return self._plane.set_authority_revocation(
            revocation_kind=DIGEST_REVOCATION, target=digest, reason=reason,
            now=self._clock())

    def disable(self, *, reason: str | None = None) -> dict:
        return self._plane.set_global_disable(
            True, reason=reason, now=self._clock())

    def enable(self) -> dict:
        return self._plane.set_global_disable(
            False, reason=None, now=self._clock())

    # -- snapshot ------------------------------------------------------ #
    def state(self) -> dict:
        return self._plane.authority_state()

    @property
    def public_key(self) -> str:
        """Public key a reader verifies this ledger's snapshots with."""
        return self._public_hex

    def publish(self) -> AuthoritySnapshotV2:
        """Sign and persist a snapshot of the current epoch.

        The epoch, every head and the signed record are read and written
        in one control-plane transaction, so the snapshot cannot describe
        a state the ledger never held. Re-publishing an unchanged epoch
        is idempotent.
        """
        try:
            return self._plane.publish_authority_snapshot(self._build_snapshot)
        except ControlPlaneError as exc:
            if exc.reason == "authority_ledger_empty":
                raise LedgerError("authority_ledger_empty") from exc
            raise

    def _build_snapshot(self, epoch: int, state: Mapping,
                        heads: Mapping) -> AuthoritySnapshotV2:
        return sign_snapshot(
            self._key.seed,
            epoch=epoch,
            candidate_head=heads["candidate_head"],
            procedure_head=heads["procedure_head"],
            scope_grant_head=heads["scope_grant_head"],
            revocation_head=heads["revocation_head"],
            supersession_head=heads["supersession_head"],
            global_disable=state["global_disable"],
            subject_count=heads["subject_count"],
            policy_version=self._policy_version,
            issued_at=self._clock(),
            signer_key_id=self._key.key_id,
        )

    # -- authorization -------------------------------------------------- #
    def guard(self, request: AuthorizationRequest
              ) -> Callable[[AuthorityView], bool | str]:
        """Build the predicate evaluated inside the commit transaction."""

        def check(view: AuthorityView) -> bool | str:
            if view.global_disable:
                return "global_disable"
            for candidate_id in request.candidate_ids:
                status = view.subject(CANDIDATE_KIND, candidate_id)
                if status is None:
                    return "candidate_unknown"
                if status != QUALIFIED:
                    return "candidate_not_qualified"
            for procedure_id in request.procedure_ids:
                status = view.subject(PROCEDURE_KIND, procedure_id)
                if status is None:
                    return "procedure_unknown"
                if status != QUALIFIED:
                    return "procedure_not_qualified"
            for grant_id in request.grant_ids:
                if view.subject(GRANT_KIND, grant_id) != "active":
                    return "grant_not_active"
            for digest in request.basis_digests:
                if view.is_revoked(DIGEST_REVOCATION, digest):
                    return "evidence_revoked"
            for signer_id in request.signer_ids:
                if view.is_revoked(SIGNER_REVOCATION, signer_id):
                    return "signer_revoked"
            return True

        return check

    def authorize(self, request: AuthorizationRequest):
        """Commit one authorization against the pinned ledger epoch."""
        try:
            return self._plane.authorize_bound(
                attempt_id=request.attempt_id, nonce=request.nonce,
                session_digest=request.session_digest,
                execution_identity_digest=request.execution_identity_digest,
                requester_principal_id=request.requester_principal_id,
                task_id=request.task_id,
                repository_id=request.repository_id,
                repository_tree_digest=request.repository_tree_digest,
                base_commit_digest=request.base_commit_digest,
                guidance_digest=request.guidance_digest,
                decision=request.decision,
                expires_at=request.expires_at,
                identity_expires_at=request.identity_expires_at,
                guard=self.guard(request),
                expected_epoch=request.expected_epoch,
                expected_head=dict(request.expected_head)
                if request.expected_head is not None else None,
                committed_at=self._clock(),
            )
        except ContractError as exc:
            raise LedgerError("authorization_malformed", str(exc)) from exc

    def readiness(self) -> dict:
        """Readiness of the ledger itself (not process liveness).

        A snapshot that does not verify against this ledger's published
        key is not a snapshot: it is a row an attacker or a bug could
        have written, so readiness is false rather than "stale".
        """
        try:
            state = self._plane.authority_state()
        except Exception as exc:  # noqa: BLE001 - readiness reports
            return {"ok": False, "error": type(exc).__name__}
        snapshot = None
        try:
            snapshot = self._plane.authority_snapshot_v2()
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": type(exc).__name__}
        verified = (snapshot is not None
                    and verify_snapshot(snapshot, self._public_hex))
        current = (snapshot is not None and snapshot.epoch == state["epoch"])
        return {
            "ok": (state["epoch"] >= 1 and not state["global_disable"]
                   and current and verified),
            "epoch": state["epoch"],
            "global_disable": state["global_disable"],
            "snapshot_epoch": snapshot.epoch if snapshot is not None else None,
            "snapshot_current": current,
            "snapshot_verified": verified,
            "snapshot_signer": snapshot.signer_key_id
            if snapshot is not None else None,
        }


@dataclass
class LedgerMirror:
    """Mirror existing registries into the ledger on every transition.

    The candidate registry and the procedure store stay the systems of
    record for their own data; this keeps the ledger's projections in
    step so a decision has one place to consult. A mirror failure is
    surfaced, never swallowed: a stale projection is an authority
    inconsistency.
    """

    ledger: AuthorityLedger
    published: list[str] = field(default_factory=list)

    def candidate(self, candidate_id: str, status: str) -> dict:
        result = self.ledger.set_candidate_status(candidate_id, status)
        if result.get("changed"):
            self.published.append(candidate_id)
        return result

    def procedure(self, procedure_id: str, status: str) -> dict:
        return self.ledger.set_procedure_status(procedure_id, status)

    def grant(self, grant_id: str, status: str) -> dict:
        return self.ledger.set_grant_status(grant_id, status)

    def revoke(self, *, signer: str | None = None,
               digest: str | None = None, reason: str | None = None) -> None:
        if signer is not None:
            self.ledger.revoke_signer(signer, reason=reason)
        if digest is not None:
            self.ledger.revoke_digest(digest, reason=reason)

    def candidate_ids(self) -> Iterable[str]:
        return (row["subject_id"] for row in self.ledger.plane
                .authority_subjects(CANDIDATE_KIND))


__all__ = [
    "CANDIDATE_KIND",
    "DIGEST_REVOCATION",
    "GRANT_KIND",
    "LedgerError",
    "LedgerMirror",
    "PROCEDURE_KIND",
    "QUALIFIED",
    "SIGNER_REVOCATION",
    "SNAPSHOT_DOMAIN",
    "AuthorityLedger",
    "AuthorizationRequest",
    "sign_snapshot",
    "snapshot_body",
    "verify_snapshot",
]
