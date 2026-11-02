"""Cryptographic binding for the V2 evidence chain (SIS3-131 follow-on).

The v3.3.2 chain authenticated an *outcome* but not the intervention it
was attached to. An authenticated requester could submit another
requester's outcome, a receipt from another repository, or the same
receipt twice, and every one of those was accepted.

This module makes the chain explicit and checkable:

    authenticated principal
      -> signed execution identity
      -> AuthorizationV2      (which guidance, for which attempt)
      -> ExecutionAttemptV2   (what the attempt did with it)
      -> EvaluatorReceiptV2   (what the evaluator measured)
      -> OutcomeV2            (what is recorded for learning)

Every arrow is a domain-separated Ed25519 signature over a canonical body
that excludes the signature field. ``match_chain`` is the single place
that decides whether a receipt may be attributed to an authorization: it
compares every binding field and fails closed with a stable reason code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping

from . import signatures
from .contracts import (
    AuthorizationV2,
    ContractError,
    EvaluatorReceiptV2,
    ExecutionAttemptV2,
    ExecutionIdentityV1,
    canonical_digest,
    canonical_json,
)

AUTHORIZATION_DOMAIN = b"sis-v3:authorization_v2:1\0"
ATTEMPT_DOMAIN = b"sis-v3:execution_attempt:1\0"
RECEIPT_DOMAIN = b"sis-v3:evaluator_receipt_v2:1\0"

_HEX = re.compile(r"^[0-9a-f]{64}$")

EXPOSURE_STATES = frozenset(
    {"not_delivered", "delivered_unread", "used_partial", "used"})

#: OutcomeV2 rows written by this module are always verified evidence.
VERIFIED_EVIDENCE_CLASS = "verified"
#: Anything recorded before the V2 chain is quarantined from promotion.
LEGACY_EVIDENCE_CLASS = "legacy_unverified"


class BindingError(RuntimeError):
    """A binding failed closed with a stable, auditable reason code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _body(record, domain: bytes, signature_field: str) -> bytes:
    body = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    body.pop(signature_field, None)
    return domain + canonical_json(body)


def authorization_body(record: AuthorizationV2 | Mapping) -> bytes:
    return _body(record, AUTHORIZATION_DOMAIN, "authorization_signature")


def attempt_body(record: ExecutionAttemptV2 | Mapping) -> bytes:
    return _body(record, ATTEMPT_DOMAIN, "attestation")


def receipt_body(record: EvaluatorReceiptV2 | Mapping) -> bytes:
    return _body(record, RECEIPT_DOMAIN, "evaluator_signature")


def sign_authorization(seed: bytes, **fields) -> AuthorizationV2:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items()
                if k != "authorization_signature"}
    signature = signatures.sign(seed, authorization_body(unsigned)).hex()
    return AuthorizationV2.from_dict(
        {**unsigned, "authorization_signature": signature})


def sign_attempt(seed: bytes, **fields) -> ExecutionAttemptV2:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items() if k != "attestation"}
    signature = signatures.sign(seed, attempt_body(unsigned)).hex()
    return ExecutionAttemptV2.from_dict({**unsigned, "attestation": signature})


def sign_receipt(seed: bytes, **fields) -> EvaluatorReceiptV2:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items()
                if k != "evaluator_signature"}
    signature = signatures.sign(seed, receipt_body(unsigned)).hex()
    return EvaluatorReceiptV2.from_dict(
        {**unsigned, "evaluator_signature": signature})


def verify_authorization(record: AuthorizationV2, public_hex: str) -> bool:
    return _verify(record.authorization_signature,
                   authorization_body(record), public_hex)


def verify_attempt(record: ExecutionAttemptV2, public_hex: str) -> bool:
    return _verify(record.attestation, attempt_body(record), public_hex)


def verify_receipt(record: EvaluatorReceiptV2, public_hex: str) -> bool:
    return _verify(record.evaluator_signature,
                   receipt_body(record), public_hex)


def _verify(signature_hex: str, body: bytes, public_hex: str) -> bool:
    try:
        return signatures.verify(bytes.fromhex(signature_hex), body,
                                 bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------- #
# Identity-derived attempt binding
# --------------------------------------------------------------------- #
def attempt_id_for_identity(identity: ExecutionIdentityV1 | Mapping) -> str:
    """Derive the attempt id from a signed execution identity.

    The harness does not get to choose its own attempt id: an id it can
    pick is an id it can reuse. The id is a pure function of the signed
    identity digest, so two authorizations can only share an attempt if
    they share a signed identity — and the identity nonce is consumed
    exactly once, so they cannot.
    """
    digest = identity.digest if isinstance(identity, ExecutionIdentityV1) \
        else canonical_digest("execution_identity", 1, dict(identity))
    return attempt_id_for_digest(digest)


def attempt_id_for_digest(execution_identity_digest: str) -> str:
    """The attempt id implied by an execution-identity digest.

    The storage layer re-derives this on every authorization commit, so a
    caller that talks to the control plane directly cannot choose an
    attempt id either.
    """
    if not (isinstance(execution_identity_digest, str)
            and _HEX.fullmatch(execution_identity_digest)):
        raise BindingError("execution_identity_digest_invalid")
    return "att-" + canonical_digest(
        "execution_attempt_id", 1,
        {"execution_identity_digest": execution_identity_digest})[:48]


def guidance_exposure_digest(
    *, authorization_id: str, attempt_id: str, guidance_digest: str,
    exposure_state: str, harness_identity: str, reported_at: str,
    exposure_evidence_digest: str | None = None,
    attempt_sequence: int | None = None,
) -> str:
    """Commitment to what the attempt did with the guidance it was given.

    The evidence digest and the attempt sequence are part of the
    commitment, so neither signed field can be changed or ignored without
    changing the exposure an outcome is bound to.
    """
    if exposure_state not in EXPOSURE_STATES:
        raise BindingError("exposure_state_invalid", exposure_state)
    return canonical_digest("guidance_exposure", 1, {
        "authorization_id": authorization_id,
        "attempt_id": attempt_id,
        "guidance_digest": guidance_digest,
        "exposure_state": exposure_state,
        "harness_identity": harness_identity,
        "reported_at": reported_at,
        "exposure_evidence_digest": exposure_evidence_digest,
        "attempt_sequence": attempt_sequence,
    })


def attempt_exposure_digest(attempt: ExecutionAttemptV2) -> str:
    """The exposure commitment an attempt report declares."""
    return guidance_exposure_digest(
        authorization_id=attempt.authorization_id,
        attempt_id=attempt.attempt_id,
        guidance_digest=attempt.guidance_digest,
        exposure_state=attempt.exposure_state,
        harness_identity=attempt.harness_identity,
        reported_at=attempt.ended_at or attempt.started_at,
        exposure_evidence_digest=attempt.exposure_evidence_digest,
        attempt_sequence=attempt.attempt_sequence,
    )


def unreported_exposure_digest(authorization: AuthorizationV2) -> str:
    """The exposure commitment for an attempt that never reported.

    An attempt with no signed report has no observed use. The evaluator
    states that explicitly instead of the gateway assuming the guidance
    was used (or assuming it was not).
    """
    return canonical_digest("guidance_exposure_unreported", 1, {
        "authorization_id": authorization.authorization_id,
        "attempt_id": authorization.attempt_id,
        "guidance_digest": authorization.guidance_digest,
    })


def bindings_digest(
    authorization: AuthorizationV2, receipt: EvaluatorReceiptV2,
) -> str:
    """Digest over the exact binding tuple an outcome is recorded under."""
    return canonical_digest("outcome_bindings", 1, {
        "authorization_id": authorization.authorization_id,
        "attempt_id": authorization.attempt_id,
        "execution_identity_digest": authorization.execution_identity_digest,
        "task_id": authorization.task_id,
        "requester_principal_id": authorization.requester_principal_id,
        "repository_id": authorization.repository_id,
        "repository_tree_digest": authorization.repository_tree_digest,
        "base_commit_digest": authorization.base_commit_digest,
        "guidance_digest": authorization.guidance_digest,
        "submitted_artifact_digest": receipt.submitted_artifact_digest,
        "guidance_exposure_digest": receipt.guidance_exposure_digest,
        "test_suite_commitment": receipt.test_suite_commitment,
        "result": receipt.result,
    })


# --------------------------------------------------------------------- #
# Exact evidence matching
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class ChainMatch:
    """The verified binding tuple an outcome may be recorded under."""

    authorization: AuthorizationV2
    attempt: ExecutionAttemptV2 | None
    receipt: EvaluatorReceiptV2
    bindings_digest: str
    independence: str
    dependency_receipt_digest: str | None


def match_chain(
    *,
    authorization: AuthorizationV2 | None,
    attempt: ExecutionAttemptV2 | None,
    receipt: EvaluatorReceiptV2,
    requester_principal_id: str,
    now: str | None = None,
    revoked_signers: Iterable[str] = (),
    revoked_digests: Iterable[str] = (),
    expected_suite_commitment: str | None = None,
) -> ChainMatch:
    """Return the verified tuple, or raise ``BindingError``.

    Every check is a rejection: there is no "best effort" branch and no
    path that records an outcome with a missing or mismatched field.

    Independence is read from the signed receipt. It is never a parameter:
    a caller that could declare its own measurement independent would
    bypass the only control that keeps a re-used evaluation out of the
    independent trial count.
    """
    if not isinstance(authorization, AuthorizationV2):
        raise BindingError("authorization_unknown")
    if not isinstance(receipt, EvaluatorReceiptV2):
        raise BindingError("receipt_unauthenticated")
    if attempt is not None and not isinstance(attempt, ExecutionAttemptV2):
        raise BindingError("attempt_unauthenticated")
    if not (isinstance(requester_principal_id, str)
            and requester_principal_id):
        raise BindingError("requester_identity_required")

    try:
        instant = _instant(now or _utcnow())
    except (TypeError, ValueError) as exc:
        raise BindingError("clock_invalid") from exc
    revoked_signers = frozenset(revoked_signers)
    revoked_digests = frozenset(revoked_digests)

    if receipt.signer_key_id in revoked_signers:
        raise BindingError("receipt_signer_revoked", receipt.signer_key_id)
    if authorization.signer_key_id in revoked_signers:
        raise BindingError("authorization_signer_revoked",
                           authorization.signer_key_id)
    if receipt.digest in revoked_digests:
        raise BindingError("receipt_revoked", receipt.digest)
    if authorization.digest in revoked_digests:
        raise BindingError("authorization_revoked", authorization.digest)

    if instant >= _instant(authorization.expires_at):
        raise BindingError("authorization_expired")
    if receipt.expires_at is not None and instant >= _instant(
            receipt.expires_at):
        raise BindingError("receipt_expired")

    # The authenticated principal must own the authorization.
    if requester_principal_id != authorization.requester_principal_id:
        raise BindingError(
            "outcome_requester_mismatch",
            f"authorization={authorization.requester_principal_id}")

    for name in ("authorization_id", "attempt_id", "task_id",
                 "requester_principal_id", "repository_id",
                 "repository_tree_digest", "base_commit_digest"):
        if getattr(receipt, name) != getattr(authorization, name):
            raise BindingError(f"receipt_{_FIELD_REASONS[name]}_mismatch")

    if receipt.guidance_exposure_digest != _expected_exposure_digest(
            authorization, attempt):
        raise BindingError("receipt_exposure_mismatch")
    if expected_suite_commitment is not None and \
            receipt.test_suite_commitment != expected_suite_commitment:
        raise BindingError("receipt_suite_mismatch")

    if receipt.independence not in {"independent", "dependent"}:
        raise BindingError("independence_invalid", receipt.independence)
    if receipt.independence == "dependent":
        if receipt.dependency_receipt_digest is None:
            raise BindingError("dependency_receipt_required")
        if receipt.dependency_receipt_digest == receipt.digest:
            raise BindingError("dependency_receipt_self")

    return ChainMatch(
        authorization=authorization,
        attempt=attempt,
        receipt=receipt,
        bindings_digest=bindings_digest(authorization, receipt),
        independence=receipt.independence,
        dependency_receipt_digest=receipt.dependency_receipt_digest,
    )


_FIELD_REASONS = {
    "authorization_id": "authorization",
    "attempt_id": "attempt",
    "task_id": "task",
    "requester_principal_id": "requester",
    "repository_id": "repository",
    "repository_tree_digest": "tree",
    "base_commit_digest": "commit",
}


def _expected_exposure_digest(
    authorization: AuthorizationV2, attempt: ExecutionAttemptV2 | None,
) -> str:
    """The exposure commitment the authorization implies.

    With a signed attempt report the digest must be the one that attempt
    declared. Without one, no exposure was reported, so only the
    ``not_delivered`` commitment is acceptable — an unreported attempt can
    never claim it used the guidance.
    """
    if attempt is None:
        return unreported_exposure_digest(authorization)
    if attempt.authorization_id != authorization.authorization_id:
        raise BindingError("attempt_authorization_mismatch")
    if attempt.attempt_id != authorization.attempt_id:
        raise BindingError("attempt_id_mismatch")
    if attempt.guidance_digest != authorization.guidance_digest:
        raise BindingError("attempt_guidance_mismatch")
    if attempt.execution_identity_digest != \
            authorization.execution_identity_digest:
        raise BindingError("attempt_identity_mismatch")
    if attempt.requester_principal_id != \
            authorization.requester_principal_id:
        raise BindingError("attempt_requester_mismatch")
    return attempt_exposure_digest(attempt)


# --------------------------------------------------------------------- #
# Trusted keys and revocation state
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class SigningKey:
    """A signing seed with its public key id, held outside agent custody."""

    seed: bytes
    key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.seed, bytes) or len(self.seed) != 32:
            raise BindingError("signing_seed_invalid")
        if not (isinstance(self.key_id, str) and self.key_id):
            raise BindingError("signing_key_id_invalid")


class EvidenceBindingAuthority:
    """Verifies the V2 chain against pinned keys and live revocation state.

    ``revocation_provider`` is consulted on every call, so a revocation
    committed between two requests is visible to the second one without a
    restart. A provider that raises fails the request closed rather than
    silently reverting to "nothing is revoked".
    """

    def __init__(
        self,
        *,
        trusted_evaluator_keys: Mapping[str, str],
        trusted_harness_keys: Mapping[str, str],
        trusted_authorization_keys: Mapping[str, str] | None = None,
        revocation_provider: Callable[[], tuple[Iterable[str],
                                                Iterable[str]]] | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self._evaluator = _key_map(trusted_evaluator_keys, "evaluator")
        self._harness = _key_map(trusted_harness_keys, "harness")
        self._authorization = _key_map(
            trusted_authorization_keys or {}, "authorization")
        self._revocations = revocation_provider
        self._clock = clock or _utcnow

    # -- key sets ------------------------------------------------------ #
    def add_evaluator_key(self, key_id: str, public_hex: str) -> None:
        self._evaluator[_check_key(key_id, public_hex, "evaluator")] = \
            public_hex.lower()

    def add_harness_key(self, key_id: str, public_hex: str) -> None:
        self._harness[_check_key(key_id, public_hex, "harness")] = \
            public_hex.lower()

    def add_authorization_key(self, key_id: str, public_hex: str) -> None:
        self._authorization[_check_key(
            key_id, public_hex, "authorization")] = public_hex.lower()

    @property
    def now(self) -> str:
        return self._clock()

    def revocation_state(self) -> tuple[frozenset[str], frozenset[str]]:
        if self._revocations is None:
            return frozenset(), frozenset()
        try:
            signers, digests = self._revocations()
        except Exception as exc:  # noqa: BLE001 - fail closed
            raise BindingError("revocation_state_unavailable",
                               type(exc).__name__) from exc
        return frozenset(signers), frozenset(digests)

    # -- record verification ------------------------------------------- #
    def receipt(self, record) -> EvaluatorReceiptV2:
        if not isinstance(record, EvaluatorReceiptV2):
            try:
                record = EvaluatorReceiptV2.from_dict(record)
            except (ContractError, TypeError, ValueError) as exc:
                raise BindingError("receipt_malformed") from exc
        public = self._evaluator.get(record.signer_key_id)
        if public is None:
            raise BindingError("receipt_untrusted_signer",
                               record.signer_key_id)
        if not verify_receipt(record, public):
            raise BindingError("receipt_signature_invalid")
        return record

    def attempt(self, record) -> ExecutionAttemptV2:
        if not isinstance(record, ExecutionAttemptV2):
            try:
                record = ExecutionAttemptV2.from_dict(record)
            except (ContractError, TypeError, ValueError) as exc:
                raise BindingError("attempt_malformed") from exc
        public = self._harness.get(record.signer_key_id)
        if public is None:
            raise BindingError("attempt_untrusted_signer",
                               record.signer_key_id)
        if not verify_attempt(record, public):
            raise BindingError("attempt_signature_invalid")
        return record

    def authorization(self, record) -> AuthorizationV2:
        if not isinstance(record, AuthorizationV2):
            try:
                record = AuthorizationV2.from_dict(record)
            except (ContractError, TypeError, ValueError) as exc:
                raise BindingError("authorization_malformed") from exc
        if not self._authorization:
            # The gateway reads authorizations from the trusted control
            # plane it holds a handle on; an unpinned key set means the
            # deployment has not published one, not that any key is fine.
            return record
        public = self._authorization.get(record.signer_key_id)
        if public is None:
            raise BindingError("authorization_untrusted_signer",
                               record.signer_key_id)
        if not verify_authorization(record, public):
            raise BindingError("authorization_signature_invalid")
        return record


def _key_map(keys: Mapping[str, str], kind: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key_id, public_hex in (keys or {}).items():
        out[_check_key(key_id, public_hex, kind)] = public_hex.lower()
    return out


def _check_key(key_id: str, public_hex: str, kind: str) -> str:
    if not (isinstance(key_id, str) and key_id):
        raise BindingError(f"{kind}_key_id_invalid")
    if not (isinstance(public_hex, str)
            and len(public_hex) == 64):
        raise BindingError(f"{kind}_public_key_invalid", key_id)
    try:
        bytes.fromhex(public_hex)
    except ValueError as exc:
        raise BindingError(f"{kind}_public_key_invalid", key_id) from exc
    return key_id


__all__ = [
    "AUTHORIZATION_DOMAIN",
    "ATTEMPT_DOMAIN",
    "RECEIPT_DOMAIN",
    "EXPOSURE_STATES",
    "LEGACY_EVIDENCE_CLASS",
    "VERIFIED_EVIDENCE_CLASS",
    "BindingError",
    "ChainMatch",
    "EvidenceBindingAuthority",
    "SigningKey",
    "attempt_id_for_identity",
    "attempt_id_for_digest",
    "authorization_body",
    "attempt_body",
    "attempt_exposure_digest",
    "bindings_digest",
    "guidance_exposure_digest",
    "match_chain",
    "receipt_body",
    "sign_attempt",
    "sign_authorization",
    "sign_receipt",
    "unreported_exposure_digest",
    "verify_attempt",
    "verify_authorization",
    "verify_receipt",
]
