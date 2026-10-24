"""OutcomeEnvelopeV2 issuance and verification (SIS3-131).

The envelope binds the full evaluation context — task, attempt, after-tree,
environment, test-suite commitment, execution receipt, outcome, issuance and
expiry — under one domain-separated Ed25519 signature. Verification checks
the pinned key registry for the exact ``outcome_signing`` purpose, key
validity windows, a revocation set, nonce replay, and expiry. Envelopes are
signed only with evaluator-custodied keys; this module never accepts a
signature produced in the agent process.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import signatures
from .contracts import (
    ContractError, OutcomeEnvelopeV2, canonical_json, loads_json)
from .verifier import EvaluatorKeyStore

_SIGNATURE_DOMAIN = b"sis-v3:outcome_envelope:1\0"
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")


class EnvelopeRejected(RuntimeError):
    """An envelope failed verification."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    parsed = datetime.fromisoformat(
        ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    # Naive timestamps are treated as UTC so comparisons never mix awareness.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class TrustedKey:
    """One pinned evaluator key with its declared purpose and validity window."""

    public_key: str
    purpose: str = "outcome_signing"
    valid_from: str | None = None
    valid_until: str | None = None


class TrustedKeyRegistry:
    """Pinned evaluator keys; callers freeze this set per deployment."""

    def __init__(self, keys: Mapping[str, TrustedKey | Mapping] | None = None) -> None:
        self._keys: dict[str, TrustedKey] = {}
        for key_id, entry in (keys or {}).items():
            if isinstance(entry, TrustedKey):
                self._keys[key_id] = entry
            else:
                self._keys[key_id] = TrustedKey(**entry)

    def add(self, key_id: str, key: TrustedKey) -> None:
        if key_id in self._keys and self._keys[key_id] != key:
            raise EnvelopeRejected("trusted_key_conflict", key_id)
        self._keys[key_id] = key

    def get(self, key_id: str) -> TrustedKey | None:
        return self._keys.get(key_id)


def issue_envelope(
    *,
    keystore: EvaluatorKeyStore,
    task_id: str,
    attempt_id: str,
    evaluated_repo_digest: str,
    environment_digest: str,
    test_suite_commitment: str,
    execution_receipt_digest: str,
    criterion_version: str,
    outcome: str,
    nonce: str | None = None,
    expires_at: str | None = None,
    regression_evidence: tuple[str, ...] = (),
) -> OutcomeEnvelopeV2:
    """Sign a V2 envelope with the evaluator-custodied key."""
    unsigned = {
        "schema_version": 1,
        "envelope_id": "env-" + secrets.token_hex(12),
        "evaluator_identity": "sis-v3-evaluator",
        "task_id": task_id,
        "attempt_id": attempt_id,
        "evaluated_repo_digest": evaluated_repo_digest,
        "environment_digest": environment_digest,
        "test_suite_commitment": test_suite_commitment,
        "execution_receipt_digest": execution_receipt_digest,
        "criterion_version": criterion_version,
        "outcome": outcome,
        "regression_evidence": list(regression_evidence),
        "nonce": nonce or "nonce-" + secrets.token_hex(12),
        "issued_at": _utcnow(),
        "expires_at": expires_at,
        "key_purpose": "outcome_signing",
        "signer_key_id": keystore.key_id,
    }
    signature = signatures.sign(
        keystore._seed or keystore.load_or_create()[0],
        _SIGNATURE_DOMAIN + canonical_json(unsigned),
    ).hex()
    return OutcomeEnvelopeV2.from_dict({**unsigned, "signature": signature})


def verify_envelope(
    envelope: OutcomeEnvelopeV2 | Mapping,
    registry: TrustedKeyRegistry,
    *,
    revoked_keys: frozenset[str] | set[str] = frozenset(),
    seen_nonces: set[str] | None = None,
    at_time: str | None = None,
) -> bool:
    """Fail-closed envelope verification; returns False on any violation."""
    try:
        env = envelope if isinstance(envelope, OutcomeEnvelopeV2) else OutcomeEnvelopeV2.from_dict(envelope)
    except ContractError:
        return False
    key = registry.get(env.signer_key_id)
    if key is None or key.purpose != "outcome_signing":
        return False
    if env.signer_key_id in revoked_keys:
        return False
    try:
        now = _parse(at_time) if at_time else datetime.now(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ContractError("at_time must be an ISO-8601 timestamp") from exc
    try:
        issued = _parse(env.issued_at)
        if key.valid_from and issued < _parse(key.valid_from):
            return False
        if key.valid_until and issued > _parse(key.valid_until):
            return False
        if env.expires_at and now > _parse(env.expires_at):
            return False
    except (ValueError, TypeError):
        return False
    if seen_nonces is not None and env.nonce in seen_nonces:
        return False
    unsigned = env.to_dict()
    unsigned.pop("signature")
    return signatures.verify(
        bytes.fromhex(env.signature),
        _SIGNATURE_DOMAIN + canonical_json(unsigned),
        bytes.fromhex(key.public_key),
    )


class ConsumedOutcomeLedger:
    """Durable, transactional ``verify_and_consume`` anti-replay ledger.

    ``verify_envelope`` stays pure for read-only audits; this ledger is the
    write path. Validate-and-record runs under an exclusive ``flock`` on a
    lockfile inside the ledger directory, so racing processes serialize:
    the first valid consumer wins, later consumers — even simultaneous —
    are rejected. The consumption key is ``(signer_key_id, nonce)``.

    A failed verification never mutates the ledger. An ``operation_id``
    makes retries idempotent: the same operation re-presented with the
    same envelope returns the envelope again; the same id with a different
    envelope is an ``operation_conflict``. ``is_consumed`` is the
    read-only existence query.
    """

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "consumed.jsonl"
        self._lock_path = self._dir / ".consumed.lock"
        self._prior: str | None = None
        self._entries: dict[tuple[str, str], dict] = {}
        self._by_operation: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        for position, raw in enumerate(self._path.read_bytes().splitlines()):
            line = raw.rstrip(b"\n")
            try:
                entry = loads_json(line)
            except ContractError as exc:
                raise EnvelopeRejected(
                    "consumed_ledger_corrupt", f"line {position}") from exc
            if (entry.get("prior_entry_digest") or None) != self._prior:
                raise EnvelopeRejected(
                    "consumed_ledger_corrupt", f"chain at line {position}")
            key = (entry["signer_key_id"], entry["nonce"])
            self._entries[key] = entry
            if entry.get("operation_id"):
                self._by_operation[entry["operation_id"]] = entry
            self._prior = hashlib.sha256(line).hexdigest()

    def is_consumed(self, signer_key_id: str, nonce: str) -> bool:
        """Read-only: has this (signer, nonce) pair been consumed?"""
        return (signer_key_id, nonce) in self._entries

    def consumed_operations(self) -> frozenset[str]:
        return frozenset(self._by_operation)

    def verify_and_consume(
        self,
        envelope: OutcomeEnvelopeV2 | Mapping,
        registry: TrustedKeyRegistry,
        *,
        revoked_keys: frozenset[str] | set[str] = frozenset(),
        operation_id: str | None = None,
        at_time: str | None = None,
        expected_task_id: str | None = None,
        expected_environment_digest: str | None = None,
        expected_test_suite_commitment: str | None = None,
    ) -> OutcomeEnvelopeV2:
        """Verify then durably consume an envelope — atomic across processes."""
        env = envelope if isinstance(envelope, OutcomeEnvelopeV2) \
            else OutcomeEnvelopeV2.from_dict(envelope)
        if operation_id is not None and not (
                isinstance(operation_id, str) and 1 <= len(operation_id) <= 128):
            raise EnvelopeRejected("invalid_operation_id")

        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._reload_locked()

            prior_op = self._by_operation.get(operation_id) \
                if operation_id else None
            if prior_op is not None:
                if prior_op["envelope_digest"] == env.digest:
                    return env  # idempotent retry of the same operation
                raise EnvelopeRejected(
                    "operation_conflict", operation_id)

            # Verify BEFORE consuming: invalid envelopes never spend nonces.
            if not verify_envelope(
                    env, registry, revoked_keys=revoked_keys,
                    at_time=at_time):
                raise EnvelopeRejected("envelope_verification_failed")
            for name, expected, actual in (
                ("task", expected_task_id, env.task_id),
                ("environment", expected_environment_digest,
                 env.environment_digest),
                ("test_suite", expected_test_suite_commitment,
                 env.test_suite_commitment),
            ):
                if expected is not None and expected != actual:
                    raise EnvelopeRejected("binding_mismatch", name)

            if (env.signer_key_id, env.nonce) in self._entries:
                raise EnvelopeRejected("replayed_nonce", env.nonce)

            entry = {
                "envelope_digest": env.digest,
                "signer_key_id": env.signer_key_id,
                "nonce": env.nonce,
                "operation_id": operation_id,
                "consumed_at": _utcnow(),
                "prior_entry_digest": self._prior,
            }
            line = canonical_json(entry)
            with open(self._path, "ab") as handle:
                handle.write(line + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._fsync_dir()
            self._entries[(env.signer_key_id, env.nonce)] = entry
            if operation_id:
                self._by_operation[operation_id] = entry
            self._prior = hashlib.sha256(line).hexdigest()
            return env
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _reload_locked(self) -> None:
        """Re-read the ledger under the held lock (another process may have
        appended since construction); corruption fails closed."""
        self._prior = None
        self._entries = {}
        self._by_operation = {}
        self._load()

    def _fsync_dir(self) -> None:
        try:
            dir_fd = os.open(self._dir, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)
