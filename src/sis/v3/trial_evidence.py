"""Authenticated trial evidence (SIS v3.5.1, PR-01 / PR-02).

A valid signature over an incomplete record is not evidence. The v3.5.0
``EvaluatorReceiptV2`` authenticates *that an evaluator measured
something*; it does not say which arm produced the measurement, which
model ran, which immutable task digest was executed, or how many tokens
were spent. Two holes followed from that:

* two arms' genuine receipts could be exchanged and the report still
  validated, because nothing bound a receipt to an arm; and
* token, wall-clock and tool counts were plain report fields, so a
  report writer could push the baseline over budget and turn
  ``no_evidence`` into ``supported`` without touching a signature.

This module closes both by adding two signed records that sit above the
receipt and below the report::

    Preregistration
      -> ExperimentAuthorizationV2   (experiment authority)
      -> TrialMeasurementV1          (evaluator)
      -> EvaluatorReceiptV2          (evaluator, referenced by digest)
      -> controlled five-arm report
      -> assessment

``ExperimentAuthorizationV2`` freezes the experiment: the protocol and
preregistration it implements, the five arm configurations, the model
identity and digest, the immutable digest of every authorized task, and
the environment/criterion/test-suite commitments the run must hold
constant. ``TrialMeasurementV1`` is the evaluator's signed statement
about one trial: which authorization it ran under, which arm and arm
configuration, which task and task digest, which model, which receipt,
and the metered resources.

Neither record trusts a field merely because it appears in a report. The
assessment reads numbers from the measurement and treats the report's
copies as claims to be checked.

Canonical serialization is ``contracts.canonical_json``: sorted keys,
no NaN/Infinity, int64 bounds, 64 KiB cap, domain-separated Ed25519
signatures over a body that excludes the signature field.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Mapping

from . import signatures
from .contracts import ContractError, canonical_digest, canonical_json

AUTHORIZATION_DOMAIN = b"sis-v3:experiment-authorization:2\0"
MEASUREMENT_DOMAIN = b"sis-v3:trial-measurement:1\0"

AUTHORIZATION_RECORD = "experiment_authorization"
MEASUREMENT_RECORD = "trial_measurement"

#: The evaluator's own result vocabulary, matching ``EvaluatorReceiptV2``.
STATUSES = frozenset({"pass", "fail", "partial", "error"})

#: Family-wise correction the verdict must apply across its contrasts.
MULTIPLICITY_POLICIES = frozenset({"holm"})

#: A single authorization carries at most this many task digests. The
#: limit is the canonical-JSON array/object bound in ``contracts``.
MAX_AUTHORIZED_TASKS = 128

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")


class TrialEvidenceError(ValueError):
    """A trial-evidence record is malformed or internally inconsistent."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _identifier(value, name: str) -> str:
    if not (isinstance(value, str) and _IDENTIFIER.fullmatch(value)):
        raise TrialEvidenceError(f"{name}_invalid")
    return value


def _digest(value, name: str) -> str:
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise TrialEvidenceError(f"{name}_invalid")
    return value


def _signature(value, name: str) -> str:
    if not (isinstance(value, str) and _SIGNATURE.fullmatch(value)):
        raise TrialEvidenceError(f"{name}_invalid")
    return value


def _count(value, name: str) -> int:
    # ``type(...) is int`` rejects bool and float alike: a counter that is
    # ``True`` or ``1.0`` is not a measurement.
    if type(value) is not int or value < 0:
        raise TrialEvidenceError(f"{name}_invalid")
    return value


def _instant(value, name: str) -> datetime:
    if not isinstance(value, str):
        raise TrialEvidenceError(f"{name}_invalid")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise TrialEvidenceError(f"{name}_invalid") from exc
    if parsed.tzinfo is None:
        # Same policy as ``evidence_binding``: a naive timestamp is read
        # as UTC rather than rejected, so both record families agree.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _body(domain: bytes, payload: Mapping) -> bytes:
    return domain + canonical_json(payload)


@dataclass(frozen=True)
class ExperimentAuthorizationV2:
    """The signed, frozen description of one authorized experiment.

    ``arms`` is the only place the assessment learns which arm
    configuration is legitimate; a measurement that names another
    configuration is refused. ``task_digests`` is the only place it
    learns which task content was authorized, so a task whose content
    changed after preregistration cannot be counted.

    ``plan_digest`` is the only place it learns the *policy* the run was
    powered and budgeted for: budgets, seed, arm order, task mapping and
    the power requirement are all inside the campaign plan. Without it a
    caller could keep every signed measurement and reinterpret them
    under a different budget. ``alpha_milli``, ``multiplicity`` and
    ``token_ratio_milli`` freeze the decision rule for the same reason:
    a signed preregistration has no protective value if the verdict
    applies a different threshold.
    """

    schema_version: int
    experiment_id: str
    protocol_digest: str
    preregistration_digest: str
    plan_digest: str
    model_identity: str
    model_digest: str
    task_digests: Mapping[str, str]
    environment_digest: str
    criterion_version: str
    test_suite_commitment: str
    alpha_milli: int
    multiplicity: str
    token_ratio_milli: int
    issued_at: str
    expires_at: str
    signer_key_id: str
    signature: str
    arms: tuple[Mapping, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 2:
            raise TrialEvidenceError("schema_version_invalid")
        _identifier(self.experiment_id, "experiment_id")
        _digest(self.protocol_digest, "protocol_digest")
        _digest(self.preregistration_digest, "preregistration_digest")
        _digest(self.plan_digest, "plan_digest")
        _identifier(self.model_identity, "model_identity")
        _digest(self.model_digest, "model_digest")
        _digest(self.environment_digest, "environment_digest")
        _identifier(self.criterion_version, "criterion_version")
        _digest(self.test_suite_commitment, "test_suite_commitment")
        if type(self.alpha_milli) is not int or not 1 <= self.alpha_milli <= 500:
            raise TrialEvidenceError("alpha_milli_invalid")
        if self.multiplicity not in MULTIPLICITY_POLICIES:
            raise TrialEvidenceError("multiplicity_invalid", str(self.multiplicity))
        if (type(self.token_ratio_milli) is not int
                or not 1 <= self.token_ratio_milli <= 1_000_000):
            raise TrialEvidenceError("token_ratio_milli_invalid")
        _instant(self.issued_at, "issued_at")
        _instant(self.expires_at, "expires_at")
        if _instant(self.expires_at, "expires_at") <= _instant(
                self.issued_at, "issued_at"):
            raise TrialEvidenceError("authorization_window_invalid")
        _identifier(self.signer_key_id, "signer_key_id")
        _signature(self.signature, "signature")

        arms = tuple(self.arms)
        if not arms or len(arms) > 16:
            raise TrialEvidenceError("arms_invalid")
        codes: list[str] = []
        for entry in arms:
            if not isinstance(entry, Mapping):
                raise TrialEvidenceError("arm_entry_invalid")
            if set(entry) != {"arm", "label", "components", "config_digest"}:
                raise TrialEvidenceError("arm_entry_invalid")
            codes.append(_identifier(entry["arm"], "arm"))
            _identifier(entry["label"], "arm_label")
            components = entry["components"]
            if not isinstance(components, (list, tuple)):
                raise TrialEvidenceError("arm_components_invalid")
            for name in components:
                _identifier(name, "arm_component")
            _digest(entry["config_digest"], "arm_config_digest")
        if len(set(codes)) != len(codes):
            raise TrialEvidenceError("arm_duplicated")
        object.__setattr__(self, "arms", tuple(
            {"arm": entry["arm"], "label": entry["label"],
             "components": tuple(entry["components"]),
             "config_digest": entry["config_digest"]} for entry in arms))

        tasks = self.task_digests
        if not isinstance(tasks, Mapping):
            raise TrialEvidenceError("task_digests_invalid")
        if not 1 <= len(tasks) <= MAX_AUTHORIZED_TASKS:
            raise TrialEvidenceError("task_digests_invalid")
        normalized: dict[str, str] = {}
        for task_id, digest in tasks.items():
            _identifier(task_id, "task_id")
            normalized[task_id] = _digest(digest, "task_digest")
        object.__setattr__(self, "task_digests", normalized)

    # -- serialization -------------------------------------------------- #
    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "protocol_digest": self.protocol_digest,
            "preregistration_digest": self.preregistration_digest,
            "plan_digest": self.plan_digest,
            "arms": [{"arm": entry["arm"], "label": entry["label"],
                      "components": list(entry["components"]),
                      "config_digest": entry["config_digest"]}
                     for entry in self.arms],
            "model_identity": self.model_identity,
            "model_digest": self.model_digest,
            "task_digests": dict(self.task_digests),
            "environment_digest": self.environment_digest,
            "criterion_version": self.criterion_version,
            "test_suite_commitment": self.test_suite_commitment,
            "alpha_milli": self.alpha_milli,
            "multiplicity": self.multiplicity,
            "token_ratio_milli": self.token_ratio_milli,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signer_key_id": self.signer_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: Mapping) -> "ExperimentAuthorizationV2":
        if not isinstance(value, Mapping):
            raise TrialEvidenceError("authorization_malformed")
        expected = {
            "schema_version", "experiment_id", "protocol_digest",
            "preregistration_digest", "plan_digest", "arms",
            "model_identity", "model_digest", "task_digests",
            "environment_digest", "criterion_version",
            "test_suite_commitment", "alpha_milli", "multiplicity",
            "token_ratio_milli", "issued_at", "expires_at",
            "signer_key_id", "signature",
        }
        if set(value) != expected:
            raise TrialEvidenceError("authorization_malformed")
        try:
            return cls(**dict(value))
        except ContractError as exc:
            raise TrialEvidenceError("authorization_malformed") from exc

    def body(self) -> bytes:
        payload = self.to_dict()
        payload.pop("signature")
        return _body(AUTHORIZATION_DOMAIN, payload)

    @property
    def digest(self) -> str:
        return canonical_digest(AUTHORIZATION_RECORD, 2, self.to_dict())

    def sign(self, seed: bytes, key_id: str) -> "ExperimentAuthorizationV2":
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise TrialEvidenceError("authorization_seed_invalid")
        _identifier(key_id, "signer_key_id")
        unsigned = replace(self, signer_key_id=key_id, signature="0" * 128)
        return replace(unsigned,
                       signature=signatures.sign(seed, unsigned.body()).hex())

    def verify(self, public_hex: str) -> bool:
        try:
            return signatures.verify(bytes.fromhex(self.signature),
                                     self.body(),
                                     bytes.fromhex(public_hex))
        except (ValueError, TypeError):
            return False

    def arm(self, code: str) -> Mapping | None:
        for entry in self.arms:
            if entry["arm"] == code:
                return entry
        return None


@dataclass(frozen=True)
class TrialMeasurementV1:
    """One evaluator-signed trial: what ran, for which arm, at what cost."""

    schema_version: int
    experiment_id: str
    authorization_digest: str
    trial_id: str
    arm: str
    arm_config_digest: str
    task_id: str
    task_digest: str
    model_digest: str
    evaluator_identity: str
    evaluator_build_digest: str
    receipt_digest: str
    receipt_id: str
    authorization_id: str
    attempt_id: str
    tokens_in: int
    tokens_out: int
    tokens_total: int
    wall_seconds_milli: int
    tool_calls: int
    tool_errors: int
    limit_violations: tuple[str, ...]
    status: str
    termination_reason: str | None
    started_at: str
    completed_at: str
    issued_at: str
    signer_key_id: str
    signature: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise TrialEvidenceError("schema_version_invalid")
        _identifier(self.experiment_id, "experiment_id")
        _digest(self.authorization_digest, "authorization_digest")
        _identifier(self.trial_id, "trial_id")
        _identifier(self.arm, "arm")
        _digest(self.arm_config_digest, "arm_config_digest")
        _identifier(self.task_id, "task_id")
        _digest(self.task_digest, "task_digest")
        _digest(self.model_digest, "model_digest")
        _identifier(self.evaluator_identity, "evaluator_identity")
        _digest(self.evaluator_build_digest, "evaluator_build_digest")
        _digest(self.receipt_digest, "receipt_digest")
        _identifier(self.receipt_id, "receipt_id")
        _identifier(self.authorization_id, "authorization_id")
        _identifier(self.attempt_id, "attempt_id")
        _count(self.tokens_in, "tokens_in")
        _count(self.tokens_out, "tokens_out")
        _count(self.tokens_total, "tokens_total")
        _count(self.wall_seconds_milli, "wall_seconds_milli")
        _count(self.tool_calls, "tool_calls")
        _count(self.tool_errors, "tool_errors")
        if self.tokens_total != self.tokens_in + self.tokens_out:
            # A total that does not equal its parts is the cheapest way to
            # hide spend; the record refuses to exist in that state.
            raise TrialEvidenceError("tokens_total_inconsistent")
        if self.tool_errors > self.tool_calls:
            raise TrialEvidenceError("tool_errors_inconsistent")
        if not isinstance(self.limit_violations, (list, tuple)):
            raise TrialEvidenceError("limit_violations_invalid")
        if len(self.limit_violations) > 32:
            raise TrialEvidenceError("limit_violations_invalid")
        for name in self.limit_violations:
            _identifier(name, "limit_violation")
        object.__setattr__(self, "limit_violations",
                           tuple(self.limit_violations))
        if self.status not in STATUSES:
            raise TrialEvidenceError("status_invalid")
        if self.termination_reason is not None:
            _identifier(self.termination_reason, "termination_reason")
        started = _instant(self.started_at, "started_at")
        completed = _instant(self.completed_at, "completed_at")
        issued = _instant(self.issued_at, "issued_at")
        if completed < started:
            raise TrialEvidenceError("completion_before_start")
        if issued < completed:
            raise TrialEvidenceError("issue_before_completion")
        _identifier(self.signer_key_id, "signer_key_id")
        _signature(self.signature, "signature")

    # -- derived -------------------------------------------------------- #
    @property
    def wall_seconds(self) -> float:
        return self.wall_seconds_milli / 1000

    @property
    def metered(self) -> bool:
        """Whether the evaluator claims authoritative metering.

        ``termination_reason == "unmetered"`` is the documented way to
        say "this run has no authoritative measurement"; such a trial may
        not be used for confirmatory qualification.
        """
        return self.termination_reason != "unmetered"

    # -- serialization -------------------------------------------------- #
    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "authorization_digest": self.authorization_digest,
            "trial_id": self.trial_id,
            "arm": self.arm,
            "arm_config_digest": self.arm_config_digest,
            "task_id": self.task_id,
            "task_digest": self.task_digest,
            "model_digest": self.model_digest,
            "evaluator_identity": self.evaluator_identity,
            "evaluator_build_digest": self.evaluator_build_digest,
            "receipt_digest": self.receipt_digest,
            "receipt_id": self.receipt_id,
            "authorization_id": self.authorization_id,
            "attempt_id": self.attempt_id,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "tokens_total": self.tokens_total,
            "wall_seconds_milli": self.wall_seconds_milli,
            "tool_calls": self.tool_calls,
            "tool_errors": self.tool_errors,
            "limit_violations": list(self.limit_violations),
            "status": self.status,
            "termination_reason": self.termination_reason,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "issued_at": self.issued_at,
            "signer_key_id": self.signer_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: Mapping) -> "TrialMeasurementV1":
        if not isinstance(value, Mapping):
            raise TrialEvidenceError("measurement_malformed")
        expected = {
            "schema_version", "experiment_id", "authorization_digest",
            "trial_id", "arm", "arm_config_digest", "task_id",
            "task_digest", "model_digest", "evaluator_identity",
            "evaluator_build_digest", "receipt_digest", "receipt_id",
            "authorization_id", "attempt_id", "tokens_in", "tokens_out",
            "tokens_total", "wall_seconds_milli", "tool_calls",
            "tool_errors", "limit_violations", "status",
            "termination_reason", "started_at", "completed_at",
            "issued_at", "signer_key_id", "signature",
        }
        if set(value) != expected:
            raise TrialEvidenceError("measurement_malformed")
        try:
            return cls(**dict(value))
        except ContractError as exc:
            raise TrialEvidenceError("measurement_malformed") from exc

    def body(self) -> bytes:
        payload = self.to_dict()
        payload.pop("signature")
        return _body(MEASUREMENT_DOMAIN, payload)

    @property
    def digest(self) -> str:
        return canonical_digest(MEASUREMENT_RECORD, 1, self.to_dict())

    def sign(self, seed: bytes, key_id: str) -> "TrialMeasurementV1":
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise TrialEvidenceError("measurement_seed_invalid")
        _identifier(key_id, "signer_key_id")
        unsigned = replace(self, signer_key_id=key_id, signature="0" * 128)
        return replace(unsigned,
                       signature=signatures.sign(seed, unsigned.body()).hex())

    def verify(self, public_hex: str) -> bool:
        try:
            return signatures.verify(bytes.fromhex(self.signature),
                                     self.body(),
                                     bytes.fromhex(public_hex))
        except (ValueError, TypeError):
            return False


def task_digest(task_id: str, task_document: str | bytes) -> str:
    """Immutable digest of the task content an arm is authorized to run."""
    raw = task_document.encode("utf-8") if isinstance(task_document, str) \
        else task_document
    return canonical_digest("task_document", 1,
                            {"task_id": task_id,
                             "content_sha256": hashlib.sha256(raw).hexdigest()})


__all__ = [
    "AUTHORIZATION_RECORD",
    "MEASUREMENT_RECORD",
    "MAX_AUTHORIZED_TASKS",
    "STATUSES",
    "ExperimentAuthorizationV2",
    "MULTIPLICITY_POLICIES",
    "TrialEvidenceError",
    "TrialMeasurementV1",
    "task_digest",
]
