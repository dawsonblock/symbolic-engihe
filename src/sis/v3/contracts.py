"""Strict, bounded v1 contracts for the SIS v3 research sidecar.

These records identify observations and evidence. A valid record is not proof
that its claims are true or that its producer had independent custody.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from typing import Any, ClassVar


MAX_RECORD_BYTES = 65_536
MAX_TEXT_CHARS = 4_096
MAX_SHORT_TEXT_CHARS = 512
MAX_ITEMS = 128
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 4_096
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SAFE_PATH = re.compile(r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{1,512}$")
_EVENT_TYPES = {
    "read", "tool_request", "tool_result", "edit", "test_request", "test_result",
    "abstain", "completion", "agent_event",
}
_ACTORS = {"agent", "runner", "learner", "evaluator", "operator", "system"}
_OUTCOMES = {"pass", "fail", "partial", "error"}
_PROCEDURE_STATES = {"draft", "candidate", "evaluated", "qualified", "suspended", "retired"}
_DECISIONS = {"recommend", "abstain"}
_REASONS = {
    "unverified_task_intent", "precondition_failed", "no_reproducible_failure",
    "conflicting_evidence", "source_mismatch", "prior_negative_transfer",
    "insufficient_support", "no_qualified_procedure", "catalog_unavailable",
    "expired", "revoked", "stale_evidence", "unsupported_context",
}
_PRECONDITION_KINDS = {
    "language_is", "toolchain_is", "dependency_digest_is", "file_present",
    "symbol_present", "failure_signature_is", "failure_signature_not",
}


class ContractError(ValueError):
    """A record is malformed, unknown-fielded, or exceeds a v1 bound."""


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _FrozenMapping({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    return value


class _FrozenMapping(Mapping):
    """Small immutable mapping used to keep frozen dataclasses deeply immutable."""

    def __init__(self, values):
        self._values = dict(values)

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


def _json_value(value: Any, *, depth: int = 0, counter: list[int] | None = None) -> Any:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        raise ContractError("JSON value exceeds the v1 structural bound")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > 2**63 - 1:
            raise ContractError("integer is outside the signed 64-bit range")
        return value
    if isinstance(value, str):
        if len(value) > MAX_TEXT_CHARS or any(ord(ch) < 32 and ch not in "\n\r\t" for ch in value):
            raise ContractError("text is too long or contains control characters")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS or any(not isinstance(k, str) for k in value):
            raise ContractError("JSON objects require string keys and at most 128 entries")
        return {k: _json_value(v, depth=depth + 1, counter=counter) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ContractError("JSON arrays may contain at most 128 entries")
        return [_json_value(v, depth=depth + 1, counter=counter) for v in value]
    raise ContractError("only null, Boolean, integer, string, array, and object JSON values are supported")


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes, enforcing shared v1 size limits."""
    if isinstance(value, V1Record):
        value = value.to_dict()
    normalized = _json_value(value)
    try:
        encoded = json.dumps(normalized, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractError("value cannot be canonically encoded") from exc
    if len(encoded) > MAX_RECORD_BYTES:
        raise ContractError("canonical record exceeds 64 KiB")
    return encoded


def canonical_digest(record_type: str, schema_version: int, value: Any) -> str:
    """Hash canonical content with an unambiguous SIS v3 type/version domain."""
    if not isinstance(record_type, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", record_type):
        raise ContractError("invalid record type for digest domain")
    if type(schema_version) is not int or schema_version < 1 or schema_version > 2**31 - 1:
        raise ContractError("invalid schema version for digest domain")
    domain = f"sis-v3:{record_type}:{schema_version}\0".encode("ascii")
    return hashlib.sha256(domain + canonical_json(value)).hexdigest()


def loads_json(raw: bytes | str) -> Any:
    """Parse bounded UTF-8 JSON and reject duplicate object keys."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_RECORD_BYTES:
            raise ContractError("JSON input exceeds 64 KiB")
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ContractError("JSON input must be UTF-8") from exc
    elif not isinstance(raw, str):
        raise ContractError("JSON input must be bytes or text")
    if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ContractError("JSON input exceeds 64 KiB")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ContractError("non-finite JSON number")))
    except ContractError:
        raise
    except (ValueError, TypeError) as exc:
        raise ContractError("invalid JSON") from exc
    _json_value(value)
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _text(value: Any, name: str, *, maximum: int = MAX_SHORT_TEXT_CHARS, nonempty: bool = True) -> None:
    _require(isinstance(value, str) and (not nonempty or bool(value.strip())) and len(value) <= maximum,
             f"{name} must be {'nonempty ' if nonempty else ''}text of at most {maximum} characters")
    _require(not any(ord(ch) < 32 and ch not in "\n\r\t" for ch in value), f"{name} contains control characters")


def _identifier(value: Any, name: str) -> None:
    _require(isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value)), f"{name} is not a valid identifier")


def _enum(value: Any, options: set[str], name: str) -> None:
    _require(isinstance(value, str) and value in options, f"{name} has an unsupported value")


def _relative_path(value: Any, name: str) -> None:
    _require(isinstance(value, str) and bool(_SAFE_PATH.fullmatch(value)) and "\\" not in value,
             f"{name} must be a normalized relative path")
    _require(all(part not in {"", ".", ".."} for part in value.split("/")),
             f"{name} must be a normalized relative path")


def _digest(value: Any, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    _require(isinstance(value, str) and bool(_HEX_256.fullmatch(value)), f"{name} must be a lowercase SHA-256 digest")


def _revision(value: Any, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    _require(isinstance(value, str) and bool(_REVISION.fullmatch(value)), f"{name} must be a 7-64 character lowercase Git revision")


def _sequence(value: Any, name: str, *, minimum: int = 0, maximum: int = MAX_ITEMS) -> list:
    _require(isinstance(value, (list, tuple)) and minimum <= len(value) <= maximum,
             f"{name} must contain {minimum}-{maximum} entries")
    return list(value)


def _timestamp(value: Any, name: str) -> None:
    _text(value, name, maximum=64)
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ContractError(f"{name} must be an ISO-8601 timestamp") from exc
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None, f"{name} must include a UTC offset")


def _precondition(value: Any, name: str) -> None:
    _require(isinstance(value, Mapping), f"{name} must be a structured precondition object")
    kind = value.get("kind")
    _enum(kind, _PRECONDITION_KINDS, name + ".kind")
    if kind == "dependency_digest_is":
        _require(set(value) == {"kind", "name", "digest"}, f"{name} has invalid dependency precondition fields")
        _identifier(value["name"], f"{name}.name")
        _digest(value["digest"], f"{name}.digest")
    else:
        _require(set(value) == {"kind", "value"}, f"{name} has invalid precondition fields")
        _text(value["value"], f"{name}.value", maximum=256)
        if kind == "file_present":
            _relative_path(value["value"], name + ".value")


@dataclass(frozen=True, kw_only=True)
class V1Record:
    schema_version: int

    RECORD_TYPE: ClassVar[str] = "record"

    def __post_init__(self):
        for item in fields(self):
            object.__setattr__(self, item.name, _freeze(getattr(self, item.name)))
        _validate_record(self)
        canonical_json(self)

    def to_dict(self) -> dict[str, Any]:
        def thaw(value):
            if isinstance(value, Mapping):
                return {key: thaw(item) for key, item in value.items()}
            if isinstance(value, (tuple, list)):
                return [thaw(item) for item in value]
            return value
        return {item.name: thaw(getattr(self, item.name)) for item in fields(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]):
        if not isinstance(value, Mapping):
            raise ContractError("record must be a JSON object")
        if any(not isinstance(key, str) for key in value):
            raise ContractError("record object keys must be strings")
        expected = {item.name for item in fields(cls)}
        if set(value) != expected:
            unknown = sorted(set(value) - expected)
            missing = sorted(expected - set(value))
            raise ContractError(f"record fields differ from v1 schema; unknown={unknown[:4]} missing={missing[:4]}")
        return cls(**dict(value))

    @classmethod
    def from_json(cls, raw: bytes | str):
        return cls.from_dict(loads_json(raw))

    def canonical_bytes(self) -> bytes:
        return canonical_json(self)

    @property
    def digest(self) -> str:
        return canonical_digest(self.RECORD_TYPE, self.schema_version, self)


@dataclass(frozen=True, kw_only=True)
class TaskEnvelopeV1(V1Record):
    task_id: str
    repo_snapshot_digest: str
    base_commit: str | None
    task_statement_digest: str
    permitted_commands: tuple[str, ...]
    isolation_profile: str
    time_budget_seconds: int
    token_budget: int
    tool_budget: int
    actor_id: str
    evaluator_task_ref: str | None

    RECORD_TYPE: ClassVar[str] = "task_envelope"


@dataclass(frozen=True, kw_only=True)
class ObservationEventV1(V1Record):
    event_id: str
    episode_id: str
    attempt_id: str
    seq: int
    event_type: str
    timestamp: str
    actor: str
    inputs_digest: str | None
    outputs_digest: str | None
    artifact_refs: tuple[str, ...]
    prior_event_digest: str | None
    idempotency_key: str
    payload_digest: str
    payload: Mapping[str, Any]

    RECORD_TYPE: ClassVar[str] = "observation_event"


@dataclass(frozen=True, kw_only=True)
class PatchProposalV1(V1Record):
    source_blob_digest: str
    target_path: str
    exact_span_fingerprint: str
    generated_diff_digest: str
    purpose: str
    procedure_ids: tuple[str, ...]
    precondition_evidence_refs: tuple[str, ...]
    proposer_id: str

    RECORD_TYPE: ClassVar[str] = "patch_proposal"


@dataclass(frozen=True, kw_only=True)
class ExecutionReceiptV1(V1Record):
    execution_id: str
    worker_identity: str
    environment_digest: str
    before_tree_digest: str
    after_tree_digest: str
    command_spec_digest: str
    exit_status: int
    stdout_digest: str | None
    stderr_digest: str | None
    resource_usage: Mapping[str, int]
    timeout: bool
    security_errors: tuple[str, ...]

    RECORD_TYPE: ClassVar[str] = "execution_receipt"


@dataclass(frozen=True, kw_only=True)
class OutcomeReceiptV1(V1Record):
    receipt_id: str
    evaluator_identity: str
    task_id: str
    evaluated_repo_digest: str
    test_suite_commitment: str
    criterion_version: str
    outcome: str
    regression_evidence: tuple[str, ...]
    signer_key_id: str
    signature: str

    RECORD_TYPE: ClassVar[str] = "outcome_receipt"


@dataclass(frozen=True, kw_only=True)
class OutcomeEnvelopeV2(V1Record):
    """V2 outcome envelope: binds attempt, environment, execution receipt,
    nonce and expiry without altering the V1 receipt serialization."""

    envelope_id: str
    evaluator_identity: str
    task_id: str
    attempt_id: str
    evaluated_repo_digest: str
    environment_digest: str
    test_suite_commitment: str
    execution_receipt_digest: str
    criterion_version: str
    outcome: str
    regression_evidence: tuple[str, ...]
    nonce: str
    issued_at: str
    expires_at: str | None
    key_purpose: str
    signer_key_id: str
    signature: str

    RECORD_TYPE: ClassVar[str] = "outcome_envelope"


@dataclass(frozen=True, kw_only=True)
class ProcedureRecordV1(V1Record):
    procedure_id: str
    revision: int
    intent: str
    language: str
    frameworks: tuple[str, ...]
    task_signatures: tuple[str, ...]
    failure_signatures: tuple[str, ...]
    preconditions: tuple[Mapping[str, Any], ...]
    contraindications: tuple[Mapping[str, Any], ...]
    steps: tuple[str, ...]
    required_verification: tuple[str, ...]
    counterexample_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    outcome_distribution: Mapping[str, int]
    status: str
    expires_at: str | None

    RECORD_TYPE: ClassVar[str] = "procedure_record"


@dataclass(frozen=True, kw_only=True)
class PromotionDecisionV1(V1Record):
    decision_id: str
    candidate_digest: str
    evaluation_protocol_digest: str
    receipt_refs: tuple[str, ...]
    actor_identity: str
    approved: bool
    policy_version: str
    prior_status: str
    new_status: str
    old_qualified_head: str | None
    new_qualified_head: str | None
    rollback_ref: str | None
    evaluator_signature: str
    operator_authorization: str

    RECORD_TYPE: ClassVar[str] = "promotion_decision"


@dataclass(frozen=True, kw_only=True)
class PromotionDecisionV2(V1Record):
    """V2 promotion decision: the complete post-state (new record digest and
    qualified head) is inside the signed body, so signatures cover the exact
    committed outcome rather than a precomputed prefix."""

    decision_id: str
    candidate_digest: str
    new_record_digest: str
    evaluation_protocol_digest: str
    receipt_refs: tuple[str, ...]
    actor_identity: str
    approved: bool
    policy_version: str
    prior_status: str
    new_status: str
    old_qualified_head: str | None
    new_qualified_head: str | None
    rollback_ref: str | None
    evaluator_signature: str
    operator_authorization: str

    RECORD_TYPE: ClassVar[str] = "promotion_decision_v2"


@dataclass(frozen=True, kw_only=True)
class GuidanceRequestV1(V1Record):
    task_id: str
    repo_snapshot_digest: str
    base_commit: str | None
    namespace: str
    language: str
    toolchain: str
    lockfile_digests: Mapping[str, str]
    task_summary: str
    failure_signatures: tuple[str, ...]
    present_symbols: tuple[str, ...]
    semantic_contract_digest: str | None

    RECORD_TYPE: ClassVar[str] = "guidance_request"


@dataclass(frozen=True, kw_only=True)
class GuidanceV1(V1Record):
    decision: str
    procedure_ids: tuple[str, ...]
    revision: str | None
    matched_preconditions: tuple[Mapping[str, Any], ...]
    contraindications: tuple[Mapping[str, Any], ...]
    evidence_ids: tuple[str, ...]
    policy_digest: str
    helpful_next_checks: tuple[str, ...]
    reason_code: str | None
    approximate_tokens: int

    RECORD_TYPE: ClassVar[str] = "guidance"


def _validate_record(record: V1Record) -> None:
    d = record.to_dict() if is_dataclass(record) else {}
    _require(type(d.get("schema_version")) is int and d["schema_version"] == 1, "schema_version must be integer 1")

    if isinstance(record, TaskEnvelopeV1):
        _identifier(d["task_id"], "task_id")
        _digest(d["repo_snapshot_digest"], "repo_snapshot_digest")
        _revision(d["base_commit"], "base_commit", optional=True)
        _digest(d["task_statement_digest"], "task_statement_digest")
        commands = _sequence(d["permitted_commands"], "permitted_commands", maximum=32)
        _require(all(isinstance(x, str) and _CAPABILITY.fullmatch(x) for x in commands), "permitted_commands must use capability IDs, not shell text")
        _require(len(set(commands)) == len(commands), "permitted_commands must be unique")
        _enum(d["isolation_profile"], {"worker_linux_rootless", "worker_microvm", "unverified_local"}, "isolation_profile")
        for name, maximum in (("time_budget_seconds", 86_400), ("token_budget", 10_000_000), ("tool_budget", 100_000)):
            _require(type(d[name]) is int and 1 <= d[name] <= maximum, f"{name} is outside its v1 bound")
        _identifier(d["actor_id"], "actor_id")
        _text(d["evaluator_task_ref"], "evaluator_task_ref", maximum=128, nonempty=False) if d["evaluator_task_ref"] is not None else None
    elif isinstance(record, ObservationEventV1):
        for name in ("event_id", "episode_id", "attempt_id", "idempotency_key"):
            _identifier(d[name], name)
        _require(type(d["seq"]) is int and d["seq"] >= 0, "seq must be a nonnegative integer")
        _enum(d["event_type"], _EVENT_TYPES, "event_type")
        _timestamp(d["timestamp"], "timestamp")
        _enum(d["actor"], _ACTORS, "actor")
        _digest(d["inputs_digest"], "inputs_digest", optional=True)
        _digest(d["outputs_digest"], "outputs_digest", optional=True)
        for ref in _sequence(d["artifact_refs"], "artifact_refs"):
            _digest(ref, "artifact_refs[]")
        _digest(d["prior_event_digest"], "prior_event_digest", optional=True)
        _digest(d["payload_digest"], "payload_digest")
        _require(isinstance(d["payload"], Mapping), "payload must be an object")
        _require(d["payload_digest"] == canonical_digest("event_payload", 1, d["payload"]),
                 "payload_digest does not bind the event payload")
    elif isinstance(record, PatchProposalV1):
        for name in ("source_blob_digest", "generated_diff_digest", "exact_span_fingerprint"):
            _digest(d[name], name)
        _relative_path(d["target_path"], "target_path")
        _text(d["purpose"], "purpose", maximum=MAX_TEXT_CHARS)
        for name in ("procedure_ids", "precondition_evidence_refs"):
            items = _sequence(d[name], name)
            _require(all(isinstance(x, str) and (bool(_IDENTIFIER.fullmatch(x)) if name == "procedure_ids" else bool(_HEX_256.fullmatch(x))) for x in items), f"invalid {name} entry")
        _identifier(d["proposer_id"], "proposer_id")
    elif isinstance(record, ExecutionReceiptV1):
        _identifier(d["execution_id"], "execution_id")
        _identifier(d["worker_identity"], "worker_identity")
        for name in ("environment_digest", "before_tree_digest", "after_tree_digest", "command_spec_digest"):
            _digest(d[name], name)
        _require(type(d["exit_status"]) is int and -255 <= d["exit_status"] <= 255, "exit_status must be an integer in [-255,255]")
        for name in ("stdout_digest", "stderr_digest"):
            _digest(d[name], name, optional=True)
        usage = d["resource_usage"]
        allowed = {"cpu_seconds", "wall_seconds", "memory_bytes", "disk_bytes", "process_count", "output_bytes"}
        _require(isinstance(usage, Mapping) and bool(usage) and set(usage) <= allowed, "resource_usage has unsupported fields")
        _require(all(type(v) is int and 0 <= v <= 2**63 - 1 for v in usage.values()), "resource_usage values must be bounded nonnegative integers")
        _require(type(d["timeout"]) is bool, "timeout must be Boolean")
        for message in _sequence(d["security_errors"], "security_errors", maximum=32):
            _text(message, "security_errors[]", maximum=512)
    elif isinstance(record, OutcomeReceiptV1):
        _identifier(d["receipt_id"], "receipt_id")
        _identifier(d["evaluator_identity"], "evaluator_identity")
        _identifier(d["task_id"], "task_id")
        for name in ("evaluated_repo_digest", "test_suite_commitment"):
            _digest(d[name], name)
        _text(d["criterion_version"], "criterion_version", maximum=128)
        _enum(d["outcome"], _OUTCOMES, "outcome")
        for ref in _sequence(d["regression_evidence"], "regression_evidence"):
            _digest(ref, "regression_evidence[]")
        _identifier(d["signer_key_id"], "signer_key_id")
        _require(isinstance(d["signature"], str) and bool(re.fullmatch(r"[0-9a-f]{128}", d["signature"])), "signature must be a 64-byte lowercase hexadecimal Ed25519 signature")
    elif isinstance(record, OutcomeEnvelopeV2):
        for name in ("envelope_id", "evaluator_identity", "task_id", "attempt_id", "nonce"):
            _identifier(d[name], name)
        for name in ("evaluated_repo_digest", "environment_digest",
                     "test_suite_commitment", "execution_receipt_digest"):
            _digest(d[name], name)
        _text(d["criterion_version"], "criterion_version", maximum=128)
        _enum(d["outcome"], _OUTCOMES, "outcome")
        for ref in _sequence(d["regression_evidence"], "regression_evidence"):
            _digest(ref, "regression_evidence[]")
        _timestamp(d["issued_at"], "issued_at")
        _timestamp(d["expires_at"], "expires_at") if d["expires_at"] is not None else None
        _enum(d["key_purpose"], {"outcome_signing"}, "key_purpose")
        _identifier(d["signer_key_id"], "signer_key_id")
        _require(isinstance(d["signature"], str) and bool(re.fullmatch(r"[0-9a-f]{128}", d["signature"])), "signature must be a 64-byte lowercase hexadecimal Ed25519 signature")
    elif isinstance(record, ProcedureRecordV1):
        _identifier(d["procedure_id"], "procedure_id")
        _require(type(d["revision"]) is int and 1 <= d["revision"] <= 2**31 - 1, "revision must be a positive integer")
        for name in ("intent",):
            _text(d[name], name, maximum=MAX_TEXT_CHARS)
        _text(d["language"], "language", maximum=64)
        for name in ("frameworks", "task_signatures", "failure_signatures", "steps", "required_verification"):
            items = _sequence(d[name], name, maximum=32 if name in {"steps", "required_verification"} else MAX_ITEMS)
            _require(all(isinstance(x, str) and 0 < len(x) <= (MAX_TEXT_CHARS if name in {"steps", "required_verification"} else 512) for x in items), f"invalid {name} entry")
        for name in ("preconditions", "contraindications"):
            for condition in _sequence(d[name], name):
                _precondition(condition, name + "[]")
        for name in ("counterexample_refs", "evidence_refs"):
            for ref in _sequence(d[name], name):
                _digest(ref, name + "[]")
        distribution = d["outcome_distribution"]
        allowed = {"tasks", "successes", "failures", "regressions"}
        _require(isinstance(distribution, Mapping) and set(distribution) == allowed, "outcome_distribution must contain tasks, successes, failures, regressions")
        _require(all(type(v) is int and 0 <= v <= 1_000_000 for v in distribution.values()), "outcome_distribution values must be bounded nonnegative integers")
        _require(distribution["successes"] + distribution["failures"] <= distribution["tasks"], "outcome counts exceed tasks")
        _enum(d["status"], _PROCEDURE_STATES, "status")
        if d["expires_at"] is not None:
            _timestamp(d["expires_at"], "expires_at")
    elif isinstance(record, PromotionDecisionV1):
        _identifier(d["decision_id"], "decision_id")
        for name in ("candidate_digest", "evaluation_protocol_digest"):
            _digest(d[name], name)
        for ref in _sequence(d["receipt_refs"], "receipt_refs", minimum=1):
            _digest(ref, "receipt_refs[]")
        _identifier(d["actor_identity"], "actor_identity")
        _require(type(d["approved"]) is bool, "approved must be Boolean")
        for name in ("policy_version", "prior_status", "new_status"):
            _text(d[name], name, maximum=128)
        for name in ("old_qualified_head", "new_qualified_head", "rollback_ref"):
            _digest(d[name], name, optional=True)
        _text(d["evaluator_signature"], "evaluator_signature", maximum=512)
        _text(d["operator_authorization"], "operator_authorization", maximum=512)
    elif isinstance(record, PromotionDecisionV2):
        _identifier(d["decision_id"], "decision_id")
        for name in ("candidate_digest", "new_record_digest", "evaluation_protocol_digest"):
            _digest(d[name], name)
        for ref in _sequence(d["receipt_refs"], "receipt_refs", minimum=1):
            _digest(ref, "receipt_refs[]")
        _identifier(d["actor_identity"], "actor_identity")
        _require(type(d["approved"]) is bool, "approved must be Boolean")
        for name in ("policy_version", "prior_status", "new_status"):
            _text(d[name], name, maximum=128)
        for name in ("old_qualified_head", "new_qualified_head", "rollback_ref"):
            _digest(d[name], name, optional=True)
        _text(d["evaluator_signature"], "evaluator_signature", maximum=512)
        _text(d["operator_authorization"], "operator_authorization", maximum=512)
    elif isinstance(record, GuidanceRequestV1):
        _identifier(d["task_id"], "task_id")
        _digest(d["repo_snapshot_digest"], "repo_snapshot_digest")
        _revision(d["base_commit"], "base_commit", optional=True)
        _identifier(d["namespace"], "namespace")
        _text(d["language"], "language", maximum=64)
        _text(d["toolchain"], "toolchain", maximum=128)
        _require(isinstance(d["lockfile_digests"], Mapping) and len(d["lockfile_digests"]) <= 32, "lockfile_digests must be a bounded object")
        for name, digest_value in d["lockfile_digests"].items():
            _text(name, "lockfile_digests key", maximum=128)
            _digest(digest_value, "lockfile_digests value")
        _text(d["task_summary"], "task_summary", maximum=2_000)
        for name in ("failure_signatures", "present_symbols"):
            items = _sequence(d[name], name, maximum=32)
            _require(all(isinstance(x, str) and 0 < len(x) <= 256 for x in items), f"invalid {name} entry")
        _digest(d["semantic_contract_digest"], "semantic_contract_digest", optional=True)
    elif isinstance(record, GuidanceV1):
        _enum(d["decision"], _DECISIONS, "decision")
        procedure_ids = _sequence(d["procedure_ids"], "procedure_ids", maximum=3)
        _require(all(isinstance(x, str) and bool(_IDENTIFIER.fullmatch(x)) for x in procedure_ids), "invalid procedure_ids entry")
        _digest(d["revision"], "revision", optional=True)
        for name in ("matched_preconditions", "contraindications"):
            for condition in _sequence(d[name], name, maximum=32):
                _precondition(condition, name + "[]")
        for ref in _sequence(d["evidence_ids"], "evidence_ids"):
            _digest(ref, "evidence_ids[]")
        _digest(d["policy_digest"], "policy_digest")
        for check in _sequence(d["helpful_next_checks"], "helpful_next_checks", maximum=8):
            _text(check, "helpful_next_checks[]", maximum=512)
        if d["reason_code"] is not None:
            _enum(d["reason_code"], _REASONS, "reason_code")
        _require(type(d["approximate_tokens"]) is int and 0 <= d["approximate_tokens"] <= 2_000, "approximate_tokens must be in [0,2000]")
        if d["decision"] == "abstain":
            _require(not procedure_ids and d["reason_code"] is not None, "abstain guidance must not include procedures and must include a reason")
        else:
            _require(bool(procedure_ids) and d["revision"] is not None and bool(d["evidence_ids"])
                     and bool(d["matched_preconditions"]) and d["reason_code"] is None,
                     "recommend guidance requires a revision, evidence, matched preconditions, and no abstain reason")
    else:
        raise ContractError("unsupported record type")

    # Generic JSON-tree validation and byte limit also apply to direct constructors.
    _json_value(d)
