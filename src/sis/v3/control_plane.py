"""Shared control plane for cross-process serving authority.

The v3.3.1 serving gateway kept replay state in a process-local set and
outcome bindings in a process-local dict. Neither survives a restart and
neither is shared by replicas, so one signed session could authorize one
decision per process and two replicas could both accept the same nonce.

This module provides the transactional substrate:

- ``session_nonce`` is the uniqueness constraint replay protection needs.
  ``commit_authorization`` inserts the nonce and the decision receipt in
  one transaction, so exactly one racing replica wins.
- ``authorization_receipt`` is the durable decision record. A guidance
  outcome can only be attached to a receipt this control plane issued.
- ``guidance_outcome`` replaces the in-memory ``_served`` map.
- ``authority_head`` records the witnessed authority snapshot a decision
  was committed against, so a stale snapshot cannot be committed after a
  revocation publication advanced the head.

Schema 2 adds the bound evidence chain (PR-03):

- ``authorization_v2`` binds one authorization to exactly one attempt
  (``UNIQUE(attempt_id)``) and one signed guidance digest.
- ``attempt_exposure`` records what the attempt did with the guidance,
  at most once per attempt.
- ``evaluator_receipt_v2`` binds one evaluator measurement to one
  authorization (``UNIQUE(authorization_id)``) and one receipt nonce.
- ``outcome_v2`` is the verified learning record. ``UNIQUE
  (authorization_id)`` plus a partial unique index on ``receipt_digest``
  where ``independence='independent'`` make a duplicate measurement
  impossible to record, including under concurrent submission.

Rows in the schema-1 ``guidance_outcome`` table are legacy evidence: they
stay readable for audit and are never counted as independent trials.

Two deployment profiles share the same interface:

- SQLite (``SqliteControlPlane``) for single-host development and tests.
- PostgreSQL (``PostgresControlPlane``) for multi-process production,
  where ``INSERT ... ON CONFLICT`` plus a real transaction provides the
  cross-replica serialization point. SQLite WAL must not be shared
  across hosts over a network filesystem.
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .contracts import (
    AuthoritySnapshotV2,
    AuthorizationV2,
    ContractError,
    EvaluatorReceiptV2,
    ExecutionAttemptV2,
    OutcomeV2,
    canonical_digest,
    canonical_json,
)
from .evidence_binding import (
    LEGACY_EVIDENCE_CLASS,
    VERIFIED_EVIDENCE_CLASS,
    SigningKey,
    attempt_exposure_digest,
    attempt_id_for_digest,
    sign_authorization,
    unreported_exposure_digest,
)

_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_NONCE = 256
_MAX_ID = 256
_DECISIONS = frozenset({"recommend", "advisory", "abstain"})
_OUTCOMES = frozenset({"pass", "fail", "partial", "error"})

SCHEMA_VERSION = 3

_EXPOSURE_COLUMNS = (
    "attempt_id", "authorization_id", "execution_identity_digest",
    "requester_principal_id", "task_id", "repository_id",
    "repository_tree_digest", "base_commit_digest", "guidance_digest",
    "exposure_state", "exposure_digest", "harness_identity", "signer_key_id",
    "record_digest", "record_json", "reported_at")

_RECEIPT_COLUMNS = (
    "receipt_id", "authorization_id", "attempt_id", "nonce", "task_id",
    "requester_principal_id", "repository_id", "repository_tree_digest",
    "base_commit_digest", "guidance_digest", "submitted_artifact_digest",
    "guidance_exposure_digest", "test_suite_commitment", "environment_digest",
    "criterion_version", "result", "independence",
    "dependency_receipt_digest", "evaluator_identity", "signer_key_id",
    "issued_at", "expires_at", "receipt_digest", "record_json", "committed_at")

_OUTCOME_COLUMNS = (
    "outcome_id", "authorization_id", "receipt_digest", "attempt_id",
    "task_id", "requester_principal_id", "repository_id", "guidance_digest",
    "guidance_exposure_digest", "result", "independence",
    "dependency_receipt_digest", "authority_snapshot_digest",
    "bindings_digest", "evidence_class", "recorded_at", "record_json")

#: Columns added after schema 2 shipped in this branch. Applied
#: idempotently on every start so a database created by an earlier
#: v3.4.0 build gains them without a version bump.
_ADDITIVE_COLUMNS = (
    ("evaluator_receipt_v2", "independence",
     "TEXT NOT NULL DEFAULT 'independent'"),
    ("evaluator_receipt_v2", "dependency_receipt_digest", "TEXT"),
)

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS schema_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS session_nonce (
        nonce TEXT PRIMARY KEY,
        session_digest TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        reserved_at TEXT NOT NULL,
        authorization_id TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS authorization_receipt (
        authorization_id TEXT PRIMARY KEY,
        nonce TEXT NOT NULL UNIQUE,
        task_id TEXT NOT NULL,
        repository_id TEXT,
        guidance_digest TEXT NOT NULL,
        decision TEXT NOT NULL,
        snapshot_digest TEXT NOT NULL,
        committed_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS guidance_outcome (
        authorization_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        served_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        outcome TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS authority_head (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        sequence INTEGER NOT NULL,
        checkpoint_digest TEXT NOT NULL,
        journal_head TEXT NOT NULL,
        revocation_head TEXT NOT NULL,
        supersession_head TEXT NOT NULL,
        custody_entry_count INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    # ---- schema 2: bound evidence chain ------------------------------ #
    """CREATE TABLE IF NOT EXISTS authorization_v2 (
        authorization_id TEXT PRIMARY KEY,
        nonce TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL UNIQUE,
        execution_identity_digest TEXT NOT NULL,
        requester_principal_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        repository_tree_digest TEXT NOT NULL,
        base_commit_digest TEXT,
        guidance_digest TEXT NOT NULL,
        authority_snapshot_digest TEXT NOT NULL,
        authority_epoch INTEGER NOT NULL,
        decision TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        record_digest TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL,
        committed_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS attempt_exposure (
        attempt_id TEXT PRIMARY KEY,
        authorization_id TEXT NOT NULL,
        execution_identity_digest TEXT NOT NULL,
        requester_principal_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        repository_tree_digest TEXT NOT NULL,
        base_commit_digest TEXT,
        guidance_digest TEXT NOT NULL,
        exposure_state TEXT NOT NULL,
        exposure_digest TEXT NOT NULL UNIQUE,
        harness_identity TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        record_digest TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL,
        reported_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS evaluator_receipt_v2 (
        receipt_id TEXT PRIMARY KEY,
        authorization_id TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL,
        nonce TEXT NOT NULL UNIQUE,
        task_id TEXT NOT NULL,
        requester_principal_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        repository_tree_digest TEXT NOT NULL,
        base_commit_digest TEXT,
        guidance_digest TEXT NOT NULL,
        submitted_artifact_digest TEXT NOT NULL,
        guidance_exposure_digest TEXT NOT NULL,
        test_suite_commitment TEXT NOT NULL,
        environment_digest TEXT NOT NULL,
        criterion_version TEXT NOT NULL,
        result TEXT NOT NULL,
        independence TEXT NOT NULL,
        dependency_receipt_digest TEXT,
        evaluator_identity TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT,
        receipt_digest TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL,
        committed_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS outcome_v2 (
        outcome_id TEXT PRIMARY KEY,
        authorization_id TEXT NOT NULL UNIQUE,
        receipt_digest TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        requester_principal_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        guidance_digest TEXT NOT NULL,
        guidance_exposure_digest TEXT NOT NULL,
        result TEXT NOT NULL,
        independence TEXT NOT NULL,
        dependency_receipt_digest TEXT,
        authority_snapshot_digest TEXT NOT NULL,
        bindings_digest TEXT NOT NULL UNIQUE,
        evidence_class TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        record_json TEXT NOT NULL
    )""",
    """CREATE UNIQUE INDEX IF NOT EXISTS outcome_v2_independent_receipt
        ON outcome_v2 (receipt_digest) WHERE independence = 'independent'""",
    """CREATE UNIQUE INDEX IF NOT EXISTS outcome_v2_attempt
        ON outcome_v2 (attempt_id)""",
    # ---- schema 3: unified authority ledger -------------------------- #
    """CREATE TABLE IF NOT EXISTS authority_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        epoch INTEGER NOT NULL,
        global_disable INTEGER NOT NULL DEFAULT 0,
        disable_reason TEXT,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS authority_subject (
        subject_kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (subject_kind, subject_id)
    )""",
    """CREATE TABLE IF NOT EXISTS authority_revocation (
        revocation_kind TEXT NOT NULL,
        target TEXT NOT NULL,
        reason TEXT,
        revoked_at TEXT NOT NULL,
        PRIMARY KEY (revocation_kind, target)
    )""",
    """CREATE TABLE IF NOT EXISTS authority_snapshot_v2 (
        epoch INTEGER PRIMARY KEY,
        snapshot_digest TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL,
        issued_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS authority_event (
        seq INTEGER PRIMARY KEY,
        epoch INTEGER NOT NULL,
        event_kind TEXT NOT NULL,
        subject TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )""",
)


class ControlPlaneError(RuntimeError):
    """A durable control-plane operation failed closed."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    # Microsecond precision keeps "latest authorization for task" ordered
    # even when a task is served twice within one wall-clock second.
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


def _identifier(value, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not (isinstance(value, str) and 0 < len(value) <= _MAX_ID):
        raise ControlPlaneError(f"{name}_invalid")
    return value


def _digest(value, name: str) -> str:
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ControlPlaneError(f"{name}_invalid")
    return value


def _instant(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _revision(value, name: str) -> str | None:
    if value is None:
        return None
    if not (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{7,64}", value)):
        raise ControlPlaneError(f"{name}_invalid")
    return value


def ledger_snapshot_digest(epoch: int, global_disable: bool) -> str:
    """The digest an authorization pins for the ledger state it decided on.

    Both commit paths use this function, so ``authority_epoch`` and
    ``authority_snapshot_digest`` mean the same thing whether or not a
    signing ledger is configured.
    """
    return canonical_digest("authority_epoch", 1, {
        "epoch": epoch,
        "global_disable": bool(global_disable),
    })


def _nonce(value) -> str:
    if not (isinstance(value, str) and 0 < len(value) <= _MAX_NONCE):
        raise ControlPlaneError("session_nonce_invalid")
    return value


class ControlPlane(Protocol):
    """Durable authority operations shared by every serving replica."""

    def commit_authorization(
        self,
        *,
        nonce: str,
        session_digest: str,
        expires_at: str,
        task_id: str,
        repository_id: str | None,
        guidance_digest: str,
        decision: str,
        snapshot_digest: str,
        expected_head: dict | None = None,
        committed_at: str | None = None,
    ) -> dict: ...

    def authorization(self, authorization_id: str) -> dict | None: ...

    def authorization_for_nonce(self, nonce: str) -> dict | None: ...

    def authorization_for_task(self, task_id: str) -> dict | None: ...

    def record_outcome(
        self,
        *,
        authorization_id: str,
        task_id: str,
        served_digest: str,
        receipt_digest: str,
        outcome: str,
        recorded_at: str | None = None,
    ) -> dict: ...

    def outcome(self, authorization_id: str) -> dict | None: ...

    def advance_authority_head(self, head: dict) -> dict: ...

    def authority_head(self) -> dict | None: ...

    def schema_version(self) -> int: ...

    def close(self) -> None: ...

    # ---- schema 2: bound evidence chain ------------------------------ #
    def supports_bound_authorization(self) -> bool: ...

    def commit_bound_authorization(
        self, *, attempt_id: str, nonce: str, session_digest: str,
        execution_identity_digest: str, requester_principal_id: str,
        task_id: str, repository_id: str, repository_tree_digest: str,
        base_commit_digest: str | None, guidance_digest: str,
        authority_snapshot_digest: str, authority_epoch: int, decision: str,
        expires_at: str, expected_head: dict | None = None,
        committed_at: str | None = None,
    ) -> AuthorizationV2: ...

    def bound_authorization(self, authorization_id: str
                            ) -> AuthorizationV2 | None: ...

    def bound_authorization_for_nonce(self, nonce: str
                                      ) -> AuthorizationV2 | None: ...

    def bound_authorizations(self) -> list[dict]: ...

    def record_attempt_exposure(self, attempt: ExecutionAttemptV2) -> dict: ...

    def attempt_exposure(self, attempt_id: str) -> dict | None: ...

    def record_evaluator_receipt(self, receipt: EvaluatorReceiptV2) -> dict: ...

    def evaluator_receipt(self, receipt_id: str) -> dict | None: ...

    def record_bound_outcome(self, outcome: OutcomeV2) -> dict: ...

    def bound_outcome(self, authorization_id: str) -> dict | None: ...

    def independent_outcomes(self, *, task_id: str | None = None
                             ) -> list[dict]: ...

    def legacy_outcomes(self) -> list[dict]: ...

    def publish_authority_snapshot(self, build) -> AuthoritySnapshotV2: ...


def _validate_head(head: dict) -> dict:
    if not isinstance(head, dict):
        raise ControlPlaneError("authority_head_invalid")
    sequence = head.get("sequence")
    if type(sequence) is not int or sequence < 1:
        raise ControlPlaneError("authority_head_sequence_invalid")
    return {
        "sequence": sequence,
        "checkpoint_digest": _digest(
            head.get("checkpoint_digest"), "checkpoint_digest"),
        "journal_head": _digest(head.get("journal_head"), "journal_head"),
        "revocation_head": _digest(
            head.get("revocation_head"), "revocation_head"),
        "supersession_head": _digest(
            head.get("supersession_head"), "supersession_head"),
        "custody_entry_count": head.get("custody_entry_count"),
        "updated_at": head.get("updated_at") or _utcnow(),
    }


class AuthorityView:
    """Read-only ledger view handed to a guard inside the commit transaction.

    A guard runs with the epoch row already read, so anything it sees is
    the state the authorization will be pinned to. It returns ``True`` to
    authorize or a reason string to reject.
    """

    def __init__(self, plane, con, state: dict) -> None:
        self._plane = plane
        self._con = con
        self._state = state

    @property
    def epoch(self) -> int:
        return self._state["epoch"]

    @property
    def global_disable(self) -> bool:
        return self._state["global_disable"]

    @property
    def disable_reason(self) -> str | None:
        return self._state.get("disable_reason")

    def subject(self, subject_kind: str, subject_id: str) -> str | None:
        row = self._plane._subject_row(
            self._con, subject_kind, subject_id)
        return None if row is None else row["status"]

    def is_revoked(self, revocation_kind: str, target: str) -> bool:
        row = self._con.execute(
            "SELECT 1 FROM authority_revocation"
            " WHERE revocation_kind=? AND target=?",
            (revocation_kind, target)).fetchone()
        return row is not None

    def revocations(self, revocation_kind: str) -> frozenset[str]:
        rows = self._con.execute(
            "SELECT target FROM authority_revocation WHERE revocation_kind=?",
            (revocation_kind,)).fetchall()
        return frozenset(row[0] for row in rows)


class _SqlControlPlane:
    """Shared validation and head-conflict rules for both backends."""

    placeholder = "?"

    def _ensure_schema_version(self, con) -> None:
        # Additive columns are applied on every start, not only on a
        # version bump, so a database created by an earlier v3.4.0 build
        # gains them without a schema change.
        self._ensure_columns(con)
        row = con.execute(
            "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
        if row is None:
            con.execute(
                "INSERT INTO schema_meta (singleton, version)"
                f" VALUES (1, {self.placeholder})",
                (SCHEMA_VERSION,))
            return
        version = row[0]
        if type(version) is not int:
            raise ControlPlaneError("control_plane_schema_invalid")
        if version > SCHEMA_VERSION:
            raise ControlPlaneError(
                "control_plane_schema_too_new",
                f"database={version} supported={SCHEMA_VERSION}")
        if version < SCHEMA_VERSION:
            # No destructive migrations exist yet; a future version adds
            # its ALTER/CREATE steps here before the version bump.
            con.execute(
                "UPDATE schema_meta SET version="
                f"{self.placeholder} WHERE singleton=1",
                (SCHEMA_VERSION,))

    def _column_names(self, con, table: str) -> set[str]:
        if self.placeholder == "?":
            rows = con.execute(f"PRAGMA table_info({table})").fetchall()
            return {row[1] for row in rows}
        rows = con.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_name=? AND table_schema=current_schema()",
            (table,)).fetchall()
        return {row[0] for row in rows}

    def _ensure_columns(self, con) -> None:
        for table, column, ddl in _ADDITIVE_COLUMNS:
            columns = self._column_names(con, table)
            if not columns:
                # The table is not part of this schema yet; the CREATE
                # path already includes the column.
                continue
            if column not in columns:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    def _check_expected_head(self, current: dict | None,
                             expected: dict | None) -> None:
        if expected is None:
            return
        if current is None:
            # Production commits compare against a witnessed head. An
            # empty head table means no checkpoint was ever published
            # through this control plane, so there is nothing to compare
            # the decision against.
            raise ControlPlaneError("authority_head_uninitialized")
        for key in ("sequence", "checkpoint_digest", "journal_head",
                    "revocation_head", "supersession_head",
                    "custody_entry_count"):
            if expected.get(key) != current.get(key):
                raise ControlPlaneError(
                    "authority_head_stale",
                    f"{key}: expected={expected.get(key)!r}"
                    f" current={current.get(key)!r}")

    def _validate_commit(self, *, nonce, session_digest, expires_at,
                         task_id, repository_id, guidance_digest,
                         decision, snapshot_digest) -> dict:
        if decision not in _DECISIONS:
            raise ControlPlaneError("decision_invalid")
        return {
            "nonce": _nonce(nonce),
            "session_digest": _digest(session_digest, "session_digest"),
            "expires_at": _identifier(expires_at, "expires_at"),
            "task_id": _identifier(task_id, "task_id"),
            "repository_id": _identifier(
                repository_id, "repository_id", optional=True),
            "guidance_digest": _digest(guidance_digest, "guidance_digest"),
            "decision": _identifier(decision, "decision"),
            "snapshot_digest": _digest(snapshot_digest, "snapshot_digest"),
        }

    @staticmethod
    def _receipt_row(row, columns) -> dict | None:
        if row is None:
            return None
        return dict(zip(columns, row))

    @staticmethod
    def _head_row(row) -> dict | None:
        if row is None:
            return None
        keys = ("singleton", "sequence", "checkpoint_digest", "journal_head",
                "revocation_head", "supersession_head",
                "custody_entry_count", "updated_at")
        value = dict(zip(keys, row))
        value.pop("singleton", None)
        return value

    # ------------------------------------------------------------------ #
    # Schema 2: bound evidence chain (shared by both backends)
    # ------------------------------------------------------------------ #
    def _bind_signer(self, signing_key) -> None:
        self._signing_key = signing_key
        if signing_key is not None and not isinstance(
                signing_key, SigningKey):
            raise ControlPlaneError("authorization_signer_invalid")

    def supports_bound_authorization(self) -> bool:
        return getattr(self, "_signing_key", None) is not None

    def signing_key_id(self) -> str | None:
        """The key this plane signs authorizations with, if any.

        Exposed so a ledger can refuse to sign snapshots with the same
        identity that issues authorizations.
        """
        key = getattr(self, "_signing_key", None)
        return None if key is None else key.key_id

    def _insert(self, con, table: str, values: dict,
                conflict_reason: str) -> None:
        columns = list(values)
        sql = (f"INSERT INTO {table} ({', '.join(columns)}) VALUES "
               f"({', '.join([self.placeholder] * len(columns))})")
        try:
            con.execute(sql, tuple(values[column] for column in columns))
        except Exception as exc:  # noqa: BLE001 - mapped per backend
            if self._is_integrity_error(exc):
                raise ControlPlaneError(conflict_reason) from exc
            raise

    def _is_integrity_error(self, exc: BaseException) -> bool:
        raise NotImplementedError

    def commit_bound_authorization(
        self, *, attempt_id, nonce, session_digest,
        execution_identity_digest, requester_principal_id, task_id,
        repository_id, repository_tree_digest, base_commit_digest,
        guidance_digest, authority_snapshot_digest=None, authority_epoch=None,
        decision, expires_at, expected_head=None, committed_at=None,
        identity_expires_at=None,
    ) -> AuthorizationV2:
        key = getattr(self, "_signing_key", None)
        if key is None:
            raise ControlPlaneError("authorization_signer_required")
        if decision not in _DECISIONS:
            raise ControlPlaneError("decision_invalid")
        values = {
            "nonce": _nonce(nonce),
            "session_digest": _digest(session_digest, "session_digest"),
            "attempt_id": _identifier(attempt_id, "attempt_id"),
            "execution_identity_digest": _digest(
                execution_identity_digest, "execution_identity_digest"),
            "requester_principal_id": _identifier(
                requester_principal_id, "requester_principal_id"),
            "task_id": _identifier(task_id, "task_id"),
            "repository_id": _identifier(repository_id, "repository_id"),
            "repository_tree_digest": _digest(
                repository_tree_digest, "repository_tree_digest"),
            "base_commit_digest": _revision(
                base_commit_digest, "base_commit_digest"),
            "guidance_digest": _digest(guidance_digest, "guidance_digest"),
            "decision": decision,
            "expires_at": _identifier(expires_at, "expires_at"),
        }
        expected_attempt = attempt_id_for_digest(
            values["execution_identity_digest"])
        if values["attempt_id"] != expected_attempt:
            raise ControlPlaneError("attempt_id_not_derived",
                                    f"expected={expected_attempt}")
        issued_at = committed_at or _utcnow()
        identity_expiry = identity_expires_at or expires_at
        if _instant(issued_at) >= _instant(identity_expiry):
            # The identity that requested this guidance is already
            # expired; nothing may be authorized under it.
            raise ControlPlaneError("identity_expired")
        authorization_id = "auth-" + secrets.token_hex(16)
        with self._transaction() as con:
            # The epoch is read in the committing transaction on every
            # path, so an authorization never pins a state the ledger
            # moved away from before the row was written.
            state = self._ledger_state(con, for_update=True)
            epoch = state["epoch"]
            digest = ledger_snapshot_digest(
                state["epoch"], state["global_disable"])
            if authority_epoch is not None and authority_epoch != epoch:
                raise ControlPlaneError(
                    "authority_epoch_changed",
                    f"expected={authority_epoch} current={epoch}")
            if authority_snapshot_digest is not None and \
                    authority_snapshot_digest != digest:
                raise ControlPlaneError("authority_snapshot_mismatch")
            current = self._head(con)
            self._check_expected_head(current, expected_head)
            try:
                record = sign_authorization(
                    key.seed, authorization_id=authorization_id,
                    requester_principal_id=values["requester_principal_id"],
                    execution_identity_digest=values[
                        "execution_identity_digest"],
                    task_id=values["task_id"],
                    attempt_id=values["attempt_id"],
                    repository_id=values["repository_id"],
                    repository_tree_digest=values["repository_tree_digest"],
                    base_commit_digest=values["base_commit_digest"],
                    guidance_digest=values["guidance_digest"],
                    authority_snapshot_digest=digest,
                    authority_epoch=epoch,
                    decision=values["decision"],
                    issued_at=issued_at,
                    expires_at=values["expires_at"],
                    signer_key_id=key.key_id)
            except ContractError as exc:
                raise ControlPlaneError(
                    "authorization_malformed", str(exc)) from exc
            existing = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=?",
                (values["nonce"],)).fetchone()
            if existing is not None:
                raise ControlPlaneError("session_nonce_replayed")
            con.execute(
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (?,?,?,?,?)"
                if self.placeholder == "?" else
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (%s,%s,%s,%s,%s)",
                (values["nonce"], values["session_digest"],
                 values["expires_at"], issued_at, authorization_id))
            self._insert(con, "authorization_v2", {
                "authorization_id": authorization_id,
                "nonce": values["nonce"],
                "attempt_id": values["attempt_id"],
                "execution_identity_digest":
                    values["execution_identity_digest"],
                "requester_principal_id": values["requester_principal_id"],
                "task_id": values["task_id"],
                "repository_id": values["repository_id"],
                "repository_tree_digest": values["repository_tree_digest"],
                "base_commit_digest": values["base_commit_digest"],
                "guidance_digest": values["guidance_digest"],
                "authority_snapshot_digest": digest,
                "authority_epoch": epoch,
                "decision": values["decision"],
                "issued_at": issued_at,
                "expires_at": values["expires_at"],
                "signer_key_id": key.key_id,
                "record_digest": record.digest,
                "record_json": canonical_json(record).decode("utf-8"),
                "committed_at": issued_at,
            }, "authorization_conflict")
        return record

    def bound_authorization(self, authorization_id: str
                            ) -> AuthorizationV2 | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT record_json FROM authorization_v2"
                " WHERE authorization_id=?", (authorization_id,)).fetchone()
        return AuthorizationV2.from_json(row[0]) if row is not None else None

    def bound_authorizations(self) -> list[dict]:
        """Every committed authorization, oldest first (monitor/audit)."""
        with self._transaction() as con:
            rows = con.execute(
                "SELECT authorization_id, nonce, attempt_id, task_id,"
                " requester_principal_id, repository_id, guidance_digest,"
                " authority_epoch, decision, issued_at, expires_at,"
                " signer_key_id FROM authorization_v2"
                " ORDER BY issued_at, authorization_id").fetchall()
        columns = ("authorization_id", "nonce", "attempt_id", "task_id",
                   "requester_principal_id", "repository_id",
                   "guidance_digest", "authority_epoch", "decision",
                   "issued_at", "expires_at", "signer_key_id")
        return [dict(zip(columns, row)) for row in rows]

    def bound_authorization_for_nonce(self, nonce: str
                                      ) -> AuthorizationV2 | None:
        _nonce(nonce)
        with self._transaction() as con:
            row = con.execute(
                "SELECT record_json FROM authorization_v2 WHERE nonce=?",
                (nonce,)).fetchone()
        return AuthorizationV2.from_json(row[0]) if row is not None else None

    def record_attempt_exposure(self, attempt: ExecutionAttemptV2) -> dict:
        if not isinstance(attempt, ExecutionAttemptV2):
            try:
                attempt = ExecutionAttemptV2.from_dict(attempt)
            except (ContractError, TypeError, ValueError) as exc:
                raise ControlPlaneError("attempt_malformed", str(exc)) from exc
        with self._transaction() as con:
            row = con.execute(
                "SELECT attempt_id, execution_identity_digest,"
                " requester_principal_id, task_id, repository_id,"
                " repository_tree_digest, base_commit_digest, guidance_digest"
                " FROM authorization_v2 WHERE authorization_id=?",
                (attempt.authorization_id,)).fetchone()
            if row is None:
                raise ControlPlaneError("authorization_unknown")
            bound = dict(zip(
                ("attempt_id", "execution_identity_digest",
                 "requester_principal_id", "task_id", "repository_id",
                 "repository_tree_digest", "base_commit_digest",
                 "guidance_digest"), row))
            for name, value in bound.items():
                if getattr(attempt, name) != value:
                    raise ControlPlaneError(f"attempt_{name}_mismatch")
            existing = con.execute(
                "SELECT record_digest FROM attempt_exposure WHERE attempt_id=?",
                (attempt.attempt_id,)).fetchone()
            if existing is not None:
                if existing[0] == attempt.digest:
                    return self._select_one(
                        con, "attempt_exposure", _EXPOSURE_COLUMNS,
                        "attempt_id", attempt.attempt_id,
                        ExecutionAttemptV2)
                raise ControlPlaneError("attempt_already_reported")
            self._insert(con, "attempt_exposure", {
                "attempt_id": attempt.attempt_id,
                "authorization_id": attempt.authorization_id,
                "execution_identity_digest":
                    attempt.execution_identity_digest,
                "requester_principal_id": attempt.requester_principal_id,
                "task_id": attempt.task_id,
                "repository_id": attempt.repository_id,
                "repository_tree_digest": attempt.repository_tree_digest,
                "base_commit_digest": attempt.base_commit_digest,
                "guidance_digest": attempt.guidance_digest,
                "exposure_state": attempt.exposure_state,
                "exposure_digest": attempt_exposure_digest(attempt),
                "harness_identity": attempt.harness_identity,
                "signer_key_id": attempt.signer_key_id,
                "record_digest": attempt.digest,
                "record_json": canonical_json(attempt).decode("utf-8"),
                "reported_at": attempt.ended_at or attempt.started_at,
            }, "attempt_already_reported")
        return self.attempt_exposure(attempt.attempt_id)

    def attempt_exposure(self, attempt_id: str) -> dict | None:
        _identifier(attempt_id, "attempt_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT attempt_id, authorization_id, execution_identity_digest,"
                " requester_principal_id, task_id, repository_id,"
                " repository_tree_digest, base_commit_digest, guidance_digest,"
                " exposure_state, exposure_digest, harness_identity,"
                " signer_key_id, record_digest, record_json, reported_at"
                " FROM attempt_exposure WHERE attempt_id=?",
                (attempt_id,)).fetchone()
        return self._record_row(row, _EXPOSURE_COLUMNS, ExecutionAttemptV2)

    def record_evaluator_receipt(self, receipt: EvaluatorReceiptV2) -> dict:
        if not isinstance(receipt, EvaluatorReceiptV2):
            try:
                receipt = EvaluatorReceiptV2.from_dict(receipt)
            except (ContractError, TypeError, ValueError) as exc:
                raise ControlPlaneError("receipt_malformed", str(exc)) from exc
        with self._transaction() as con:
            row = con.execute(
                "SELECT attempt_id, requester_principal_id, task_id,"
                " repository_id, repository_tree_digest, base_commit_digest,"
                " authorization_id, record_json FROM authorization_v2"
                " WHERE authorization_id=?",
                (receipt.authorization_id,)).fetchone()
            if row is None:
                raise ControlPlaneError("authorization_unknown")
            bound = dict(zip(
                ("attempt_id", "requester_principal_id", "task_id",
                 "repository_id", "repository_tree_digest",
                 "base_commit_digest", "authorization_id"), row[:7]))
            for name, value in bound.items():
                if getattr(receipt, name) != value:
                    raise ControlPlaneError(f"receipt_{name}_mismatch")
            authorization = AuthorizationV2.from_json(row[7])
            exposure = con.execute(
                "SELECT exposure_digest FROM attempt_exposure"
                " WHERE attempt_id=?", (receipt.attempt_id,)).fetchone()
            expected_exposure = (
                exposure[0] if exposure is not None
                else unreported_exposure_digest(authorization))
            if receipt.guidance_exposure_digest != expected_exposure:
                raise ControlPlaneError("receipt_exposure_mismatch")
            existing = con.execute(
                "SELECT receipt_id FROM evaluator_receipt_v2"
                " WHERE authorization_id=?", (receipt.authorization_id,)
            ).fetchone()
            if existing is not None:
                if existing[0] == receipt.receipt_id:
                    return self._select_one(
                        con, "evaluator_receipt_v2", _RECEIPT_COLUMNS,
                        "receipt_id", receipt.receipt_id, EvaluatorReceiptV2)
                raise ControlPlaneError(
                    "receipt_authorization_already_measured")
            self._insert(con, "evaluator_receipt_v2", {
                "receipt_id": receipt.receipt_id,
                "authorization_id": receipt.authorization_id,
                "attempt_id": receipt.attempt_id,
                "nonce": receipt.nonce,
                "task_id": receipt.task_id,
                "requester_principal_id": receipt.requester_principal_id,
                "repository_id": receipt.repository_id,
                "repository_tree_digest": receipt.repository_tree_digest,
                "base_commit_digest": receipt.base_commit_digest,
                "guidance_digest": authorization.guidance_digest,
                "submitted_artifact_digest":
                    receipt.submitted_artifact_digest,
                "guidance_exposure_digest": receipt.guidance_exposure_digest,
                "test_suite_commitment": receipt.test_suite_commitment,
                "environment_digest": receipt.environment_digest,
                "criterion_version": receipt.criterion_version,
                "result": receipt.result,
                "independence": receipt.independence,
                "dependency_receipt_digest":
                    receipt.dependency_receipt_digest,
                "evaluator_identity": receipt.evaluator_identity,
                "signer_key_id": receipt.signer_key_id,
                "issued_at": receipt.issued_at,
                "expires_at": receipt.expires_at,
                "receipt_digest": receipt.digest,
                "record_json": canonical_json(receipt).decode("utf-8"),
                "committed_at": _utcnow(),
            }, "receipt_already_recorded")
        return self.evaluator_receipt(receipt.receipt_id)

    def evaluator_receipt(self, receipt_id: str) -> dict | None:
        _identifier(receipt_id, "receipt_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT receipt_id, authorization_id, attempt_id, nonce,"
                " task_id, requester_principal_id, repository_id,"
                " repository_tree_digest, base_commit_digest,"
                " guidance_digest, submitted_artifact_digest,"
                " guidance_exposure_digest,"
                " test_suite_commitment, environment_digest,"
                " criterion_version, result, independence,"
                " dependency_receipt_digest, evaluator_identity,"
                " signer_key_id, issued_at, expires_at, receipt_digest,"
                " record_json, committed_at FROM evaluator_receipt_v2"
                " WHERE receipt_id=?", (receipt_id,)).fetchone()
        return self._record_row(row, _RECEIPT_COLUMNS, EvaluatorReceiptV2)

    def record_bound_outcome(self, outcome: OutcomeV2) -> dict:
        if not isinstance(outcome, OutcomeV2):
            try:
                outcome = OutcomeV2.from_dict(outcome)
            except (ContractError, TypeError, ValueError) as exc:
                raise ControlPlaneError("outcome_malformed", str(exc)) from exc
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, attempt_id, task_id,"
                " requester_principal_id, repository_id, guidance_digest,"
                " guidance_exposure_digest, result, receipt_digest,"
                " independence, dependency_receipt_digest"
                " FROM evaluator_receipt_v2 WHERE receipt_digest=?",
                (outcome.receipt_digest,)).fetchone()
            if row is None:
                raise ControlPlaneError("receipt_unknown")
            bound = dict(zip(
                ("authorization_id", "attempt_id", "task_id",
                 "requester_principal_id", "repository_id", "guidance_digest",
                 "guidance_exposure_digest", "result", "receipt_digest",
                 "independence", "dependency_receipt_digest"),
                row))
            for name, value in bound.items():
                if getattr(outcome, name) != value:
                    raise ControlPlaneError(f"outcome_{name}_mismatch")
            authorization = con.execute(
                "SELECT authority_snapshot_digest FROM authorization_v2"
                " WHERE authorization_id=?",
                (outcome.authorization_id,)).fetchone()
            if authorization is None:
                raise ControlPlaneError("authorization_unknown")
            if outcome.authority_snapshot_digest != authorization[0]:
                raise ControlPlaneError("outcome_authority_snapshot_mismatch")
            if outcome.independence == "dependent":
                dependency = con.execute(
                    "SELECT task_id FROM evaluator_receipt_v2"
                    " WHERE receipt_digest=?",
                    (outcome.dependency_receipt_digest,)).fetchone()
                if dependency is None:
                    raise ControlPlaneError("dependency_receipt_unknown")
                if dependency[0] != outcome.task_id:
                    raise ControlPlaneError("dependency_receipt_task_mismatch")
            self._insert(con, "outcome_v2", {
                "outcome_id": outcome.outcome_id,
                "authorization_id": outcome.authorization_id,
                "receipt_digest": outcome.receipt_digest,
                "attempt_id": outcome.attempt_id,
                "task_id": outcome.task_id,
                "requester_principal_id": outcome.requester_principal_id,
                "repository_id": outcome.repository_id,
                "guidance_digest": outcome.guidance_digest,
                "guidance_exposure_digest":
                    outcome.guidance_exposure_digest,
                "result": outcome.result,
                "independence": outcome.independence,
                "dependency_receipt_digest":
                    outcome.dependency_receipt_digest,
                "authority_snapshot_digest":
                    outcome.authority_snapshot_digest,
                "bindings_digest": outcome.bindings_digest,
                "evidence_class": VERIFIED_EVIDENCE_CLASS,
                "recorded_at": outcome.recorded_at,
                "record_json": canonical_json(outcome).decode("utf-8"),
            }, "outcome_already_recorded")
        return self.bound_outcome(outcome.authorization_id)

    def bound_outcome(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT outcome_id, authorization_id, receipt_digest,"
                " attempt_id, task_id, requester_principal_id, repository_id,"
                " guidance_digest, guidance_exposure_digest, result,"
                " independence, dependency_receipt_digest,"
                " authority_snapshot_digest, bindings_digest, evidence_class,"
                " recorded_at, record_json FROM outcome_v2"
                " WHERE authorization_id=?", (authorization_id,)).fetchone()
        return self._record_row(row, _OUTCOME_COLUMNS, OutcomeV2)

    def independent_outcomes(self, *, task_id: str | None = None
                             ) -> list[dict]:
        query = (
            "SELECT outcome_id, authorization_id, receipt_digest, attempt_id,"
            " task_id, requester_principal_id, repository_id,"
            " guidance_digest, guidance_exposure_digest, result, independence,"
            " dependency_receipt_digest, authority_snapshot_digest,"
            " bindings_digest, evidence_class, recorded_at, record_json"
            " FROM outcome_v2 WHERE evidence_class=? AND independence='independent'")
        params: list = [VERIFIED_EVIDENCE_CLASS]
        if task_id is not None:
            query += " AND task_id=?"
            params.append(_identifier(task_id, "task_id"))
        query += " ORDER BY recorded_at, outcome_id"
        with self._transaction() as con:
            rows = con.execute(query, tuple(params)).fetchall()
        return [self._record_row(row, _OUTCOME_COLUMNS, OutcomeV2)
                for row in rows]

    def legacy_outcomes(self) -> list[dict]:
        with self._transaction() as con:
            rows = con.execute(
                "SELECT authorization_id, task_id, served_digest,"
                " receipt_digest, outcome, recorded_at FROM guidance_outcome"
                " ORDER BY recorded_at, authorization_id").fetchall()
        columns = ("authorization_id", "task_id", "served_digest",
                   "receipt_digest", "outcome", "recorded_at")
        return [{**dict(zip(columns, row)),
                 "evidence_class": LEGACY_EVIDENCE_CLASS}
                for row in rows]

    def _select_one(self, con, table: str, columns, key_column: str, key,
                    record_type) -> dict | None:
        row = con.execute(
            f"SELECT {', '.join(columns)} FROM {table}"
            f" WHERE {key_column}=?", (key,)).fetchone()
        return self._record_row(row, columns, record_type)

    @staticmethod
    def _record_row(row, columns, record_type) -> dict | None:
        if row is None:
            return None
        value = dict(zip(columns, row))
        raw = value.pop("record_json")
        value["record"] = record_type.from_json(raw)
        return value

    # ------------------------------------------------------------------ #
    # Schema 3: unified authority ledger
    # ------------------------------------------------------------------ #
    def _ensure_ledger_row(self, con) -> None:
        """Create the singleton epoch row if it does not exist.

        ``SELECT … FOR UPDATE`` on a missing row locks nothing, so the
        first authorization and the first revocation on a fresh ledger
        could otherwise race with no shared row to serialize on.
        """
        statement = (
            "INSERT OR IGNORE INTO authority_state"
            " (singleton, epoch, global_disable, disable_reason, updated_at)"
            " VALUES (1, 0, 0, NULL, ?)"
            if self.placeholder == "?" else
            "INSERT INTO authority_state"
            " (singleton, epoch, global_disable, disable_reason, updated_at)"
            " VALUES (1, 0, 0, NULL, ?)"
            " ON CONFLICT (singleton) DO NOTHING")
        con.execute(statement, (_utcnow(),))

    def _ledger_state(self, con, *, for_update: bool = False) -> dict:
        if for_update:
            self._ensure_ledger_row(con)
        query = (
            "SELECT epoch, global_disable, disable_reason, updated_at"
            " FROM authority_state WHERE singleton=1")
        if for_update and self.placeholder != "?":
            # PostgreSQL runs READ COMMITTED by default: without the row
            # lock a revocation that commits between this read and the
            # authorization INSERT is invisible, and the authorization
            # overtakes it. SQLite is already serialized by BEGIN
            # IMMEDIATE, so it needs no clause (and rejects one).
            query += " FOR UPDATE"
        row = con.execute(query).fetchone()
        if row is None:
            return {"epoch": 0, "global_disable": False,
                    "disable_reason": None, "updated_at": None}
        return {"epoch": row[0], "global_disable": bool(row[1]),
                "disable_reason": row[2], "updated_at": row[3]}

    def _bump_epoch(self, con, *, event_kind: str, subject: str,
                    payload: dict, now: str) -> int:
        state = self._ledger_state(con, for_update=True)
        epoch = state["epoch"] + 1
        # _ledger_state(for_update=True) seeds the singleton, so this is
        # always an update; there is no "row does not exist" branch left.
        con.execute(
            "UPDATE authority_state SET epoch=?, updated_at=?"
            " WHERE singleton=1", (epoch, now))
        # One writer holds the epoch row, so MAX(seq)+1 is stable here.
        seq = con.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM authority_event"
        ).fetchone()[0]
        self._insert(con, "authority_event", {
            "seq": seq, "epoch": epoch, "event_kind": event_kind,
            "subject": subject,
            "payload_digest": canonical_digest(
                "authority_event", 1, payload),
            "recorded_at": now,
        }, "authority_event_conflict")
        return epoch

    def authority_state(self) -> dict:
        with self._transaction() as con:
            return self._ledger_state(con)

    def set_global_disable(self, enabled: bool, *, reason: str | None = None,
                           now: str | None = None) -> dict:
        """Commit the kill switch; bumps the epoch in the same transaction."""
        if not isinstance(enabled, bool):
            raise ControlPlaneError("global_disable_invalid")
        stamp = now or _utcnow()
        with self._transaction() as con:
            state = self._ledger_state(con, for_update=True)
            if state["global_disable"] == enabled:
                return state
            epoch = self._bump_epoch(
                con, event_kind="global_disable" if enabled
                else "global_enable", subject="global",
                payload={"enabled": enabled, "reason": reason}, now=stamp)
            con.execute(
                "UPDATE authority_state SET global_disable=?,"
                " disable_reason=? WHERE singleton=1",
                (1 if enabled else 0, reason))
            state = self._ledger_state(con)
        return {**state, "epoch": epoch}

    def set_authority_subject(self, *, subject_kind: str, subject_id: str,
                              status: str, detail: str | None = None,
                              now: str | None = None) -> dict:
        _identifier(subject_kind, "subject_kind")
        _identifier(subject_id, "subject_id")
        _identifier(status, "status")
        stamp = now or _utcnow()
        with self._transaction() as con:
            # Serialize writers on the epoch row before deciding whether
            # this is a no-op, so two concurrent duplicates cannot both
            # decide to bump.
            self._ledger_state(con, for_update=True)
            existing = con.execute(
                "SELECT status, detail FROM authority_subject"
                " WHERE subject_kind=? AND subject_id=?",
                (subject_kind, subject_id)).fetchone()
            if existing is not None and existing[0] == status and \
                    existing[1] == detail:
                return {"epoch": self._ledger_state(con)["epoch"],
                        "status": status, "changed": False}
            epoch = self._bump_epoch(
                con, event_kind="subject_status", subject=subject_id,
                payload={"subject_kind": subject_kind,
                         "status": status, "detail": detail}, now=stamp)
            if existing is None:
                self._insert(con, "authority_subject", {
                    "subject_kind": subject_kind, "subject_id": subject_id,
                    "status": status, "detail": detail,
                    "updated_at": stamp,
                }, "authority_subject_conflict")
            else:
                con.execute(
                    "UPDATE authority_subject SET status=?, detail=?,"
                    " updated_at=? WHERE subject_kind=? AND subject_id=?",
                    (status, detail, stamp, subject_kind, subject_id))
        return {"epoch": epoch, "status": status, "changed": True}

    def authority_subject(self, subject_kind: str,
                          subject_id: str) -> dict | None:
        with self._transaction() as con:
            return self._subject_row(con, subject_kind, subject_id)

    @staticmethod
    def _subject_row(con, subject_kind, subject_id) -> dict | None:
        row = con.execute(
            "SELECT subject_kind, subject_id, status, detail, updated_at"
            " FROM authority_subject WHERE subject_kind=? AND subject_id=?",
            (subject_kind, subject_id)).fetchone()
        return None if row is None else dict(zip(
            ("subject_kind", "subject_id", "status", "detail", "updated_at"),
            row))

    def authority_subjects(self, subject_kind: str | None = None
                           ) -> list[dict]:
        query = ("SELECT subject_kind, subject_id, status, detail, updated_at"
                 " FROM authority_subject")
        params: tuple = ()
        if subject_kind is not None:
            query += " WHERE subject_kind=?"
            params = (_identifier(subject_kind, "subject_kind"),)
        query += " ORDER BY subject_kind, subject_id"
        with self._transaction() as con:
            rows = con.execute(query, params).fetchall()
        return [dict(zip(
            ("subject_kind", "subject_id", "status", "detail", "updated_at"),
            row)) for row in rows]

    def set_authority_revocation(self, *, revocation_kind: str,
                                 target: str, reason: str | None = None,
                                 now: str | None = None) -> dict:
        _identifier(revocation_kind, "revocation_kind")
        _identifier(target, "target")
        stamp = now or _utcnow()
        with self._transaction() as con:
            # Same serialization point as the subject setter: a duplicate
            # revocation is a no-op, not a conflict.
            self._ledger_state(con, for_update=True)
            existing = con.execute(
                "SELECT reason FROM authority_revocation"
                " WHERE revocation_kind=? AND target=?",
                (revocation_kind, target)).fetchone()
            if existing is not None:
                return {"epoch": self._ledger_state(con)["epoch"],
                        "changed": False}
            epoch = self._bump_epoch(
                con, event_kind="revocation", subject=target,
                payload={"revocation_kind": revocation_kind,
                         "reason": reason}, now=stamp)
            self._insert(con, "authority_revocation", {
                "revocation_kind": revocation_kind, "target": target,
                "reason": reason, "revoked_at": stamp,
            }, "authority_revocation_conflict")
        return {"epoch": epoch, "changed": True}

    def authority_revocations(self, revocation_kind: str | None = None
                              ) -> list[dict]:
        query = ("SELECT revocation_kind, target, reason, revoked_at"
                 " FROM authority_revocation")
        params: tuple = ()
        if revocation_kind is not None:
            query += " WHERE revocation_kind=?"
            params = (_identifier(revocation_kind, "revocation_kind"),)
        query += " ORDER BY revocation_kind, target"
        with self._transaction() as con:
            rows = con.execute(query, params).fetchall()
        return [dict(zip(("revocation_kind", "target", "reason",
                          "revoked_at"), row)) for row in rows]

    def record_authority_snapshot(self, snapshot: AuthoritySnapshotV2) -> dict:
        if not isinstance(snapshot, AuthoritySnapshotV2):
            raise ControlPlaneError("authority_snapshot_invalid")
        with self._transaction() as con:
            self._insert(con, "authority_snapshot_v2", {
                "epoch": snapshot.epoch,
                "snapshot_digest": snapshot.digest,
                "record_json": canonical_json(snapshot).decode("utf-8"),
                "issued_at": snapshot.issued_at,
            }, "authority_snapshot_conflict")
        return {"epoch": snapshot.epoch, "snapshot_digest": snapshot.digest,
                "record": snapshot}

    def authority_snapshot_v2(self, epoch: int | None = None
                              ) -> AuthoritySnapshotV2 | None:
        with self._transaction() as con:
            if epoch is None:
                row = con.execute(
                    "SELECT record_json FROM authority_snapshot_v2"
                    " ORDER BY epoch DESC LIMIT 1").fetchone()
            else:
                row = con.execute(
                    "SELECT record_json FROM authority_snapshot_v2"
                    " WHERE epoch=?", (epoch,)).fetchone()
        return AuthoritySnapshotV2.from_json(row[0]) if row is not None \
            else None

    def authority_events(self, limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ControlPlaneError("authority_event_limit_invalid")
        with self._transaction() as con:
            rows = con.execute(
                "SELECT seq, epoch, event_kind, subject, payload_digest,"
                " recorded_at FROM authority_event ORDER BY seq DESC"
                " LIMIT ?" if self.placeholder == "?" else
                "SELECT seq, epoch, event_kind, subject, payload_digest,"
                " recorded_at FROM authority_event ORDER BY seq DESC"
                " LIMIT %s", (limit,)).fetchall()
        return [dict(zip(("seq", "epoch", "event_kind", "subject",
                          "payload_digest", "recorded_at"), row))
                for row in rows]

    # -- atomic snapshot publication ----------------------------------- #
    def ledger_heads(self, con) -> dict:
        """Every head a snapshot covers, read on the caller's connection.

        One connection means one consistent view: a snapshot built from
        these heads describes a state the ledger actually held. The
        subject kinds and the digest-revocation kind are the ledger's
        vocabulary (``authority_ledger.CANDIDATE_KIND`` etc.); they are
        repeated here because the ledger imports this module.
        """
        def subject_head(kind: str) -> str:
            rows = con.execute(
                "SELECT subject_id, status FROM authority_subject"
                " WHERE subject_kind=? ORDER BY subject_id", (kind,)
            ).fetchall()
            return canonical_digest("authority_subject_head", 1, {
                "subject_kind": kind,
                "subjects": [{"subject_id": row[0], "status": row[1]}
                             for row in rows],
            })

        revocations = con.execute(
            "SELECT revocation_kind, target FROM authority_revocation"
            " ORDER BY revocation_kind, target").fetchall()
        superseded = sorted(
            row[1] for row in revocations if row[0] == "digest")
        subject_count = con.execute(
            "SELECT COUNT(*) FROM authority_subject").fetchone()[0]
        return {
            "candidate_head": subject_head("candidate"),
            "procedure_head": subject_head("procedure"),
            "scope_grant_head": subject_head("grant"),
            "revocation_head": canonical_digest(
                "authority_revocation_head", 1, {
                    "revocations": [{"kind": row[0], "target": row[1]}
                                    for row in revocations],
                }),
            "supersession_head": canonical_digest(
                "authority_supersession_head", 1,
                {"superseded": superseded}),
            "subject_count": subject_count,
        }

    def publish_authority_snapshot(self, build) -> AuthoritySnapshotV2:
        """Sign and store one snapshot inside a single transaction.

        ``build(epoch, state, heads)`` returns the signed record. The
        epoch row is locked (PostgreSQL) or the database is write-locked
        (SQLite) for the whole read-sign-write, so the snapshot cannot
        describe a mix of two states. Publication is idempotent per epoch.
        """
        with self._transaction() as con:
            state = self._ledger_state(con, for_update=True)
            epoch = state["epoch"]
            if epoch < 1:
                raise ControlPlaneError("authority_ledger_empty")
            existing = con.execute(
                "SELECT record_json FROM authority_snapshot_v2"
                " WHERE epoch=?", (epoch,)).fetchone()
            if existing is not None:
                return AuthoritySnapshotV2.from_json(existing[0])
            snapshot = build(epoch, state, self.ledger_heads(con))
            self._insert(con, "authority_snapshot_v2", {
                "epoch": snapshot.epoch,
                "snapshot_digest": snapshot.digest,
                "record_json": canonical_json(snapshot).decode("utf-8"),
                "issued_at": snapshot.issued_at,
            }, "authority_snapshot_conflict")
        return snapshot

    def authorize_bound(
        self, *, attempt_id, nonce, session_digest, execution_identity_digest,
        requester_principal_id, task_id, repository_id,
        repository_tree_digest, base_commit_digest, guidance_digest,
        decision, expires_at, identity_expires_at, guard=None,
        expected_epoch=None, expected_head=None, committed_at=None,
    ) -> AuthorizationV2:
        """Commit an authorization inside the single ledger transaction.

        The epoch row is read inside the same transaction that writes the
        authorization, the guard is evaluated against that view, and the
        epoch is pinned into the signed record. A revocation or disable
        that commits first therefore cannot be overtaken, and an
        authorization that observed a stale epoch is refused.
        """
        key = getattr(self, "_signing_key", None)
        if key is None:
            raise ControlPlaneError("authorization_signer_required")
        if decision not in _DECISIONS:
            raise ControlPlaneError("decision_invalid")
        stamp = committed_at or _utcnow()
        identity_expiry = _identifier(identity_expires_at,
                                      "identity_expires_at")
        authorization_expiry = _identifier(expires_at, "expires_at")
        if _instant(authorization_expiry) > _instant(identity_expiry):
            # Guidance must never outlive the identity it was issued to.
            raise ControlPlaneError("authorization_outlives_identity")
        if _instant(stamp) >= _instant(identity_expiry):
            # Rechecked inside the committing transaction: an identity
            # that expired while guidance was composed cannot authorize.
            raise ControlPlaneError("identity_expired")
        identity_digest = _digest(execution_identity_digest,
                                  "execution_identity_digest")
        expected_attempt = attempt_id_for_digest(identity_digest)
        if attempt_id != expected_attempt:
            # The harness does not choose its own attempt id; the id is a
            # pure function of the signed identity digest.
            raise ControlPlaneError("attempt_id_not_derived",
                                    f"expected={expected_attempt}")
        authorization_id = "auth-" + secrets.token_hex(16)
        with self._transaction() as con:
            state = self._ledger_state(con, for_update=True)
            if state["global_disable"]:
                raise ControlPlaneError(
                    "global_disable", state.get("disable_reason") or "")
            if expected_epoch is not None and state["epoch"] != expected_epoch:
                raise ControlPlaneError(
                    "authority_epoch_changed",
                    f"expected={expected_epoch} current={state['epoch']}")
            current = self._head(con)
            self._check_expected_head(current, expected_head)
            if guard is not None:
                verdict = guard(AuthorityView(self, con, state))
                if verdict is not True:
                    raise ControlPlaneError(
                        verdict or "authority_rejected")
            record = sign_authorization(
                key.seed, authorization_id=authorization_id,
                requester_principal_id=_identifier(
                    requester_principal_id, "requester_principal_id"),
                execution_identity_digest=_digest(
                    execution_identity_digest, "execution_identity_digest"),
                task_id=_identifier(task_id, "task_id"),
                attempt_id=_identifier(attempt_id, "attempt_id"),
                repository_id=_identifier(repository_id, "repository_id"),
                repository_tree_digest=_digest(
                    repository_tree_digest, "repository_tree_digest"),
                base_commit_digest=_revision(
                    base_commit_digest, "base_commit_digest"),
                guidance_digest=_digest(guidance_digest, "guidance_digest"),
                authority_snapshot_digest=ledger_snapshot_digest(
                    state["epoch"], state["global_disable"]),
                authority_epoch=state["epoch"],
                decision=decision, issued_at=stamp,
                expires_at=authorization_expiry,
                signer_key_id=key.key_id)
            existing = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=?",
                (_nonce(nonce),)).fetchone()
            if existing is not None:
                raise ControlPlaneError("session_nonce_replayed")
            con.execute(
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (?,?,?,?,?)"
                if self.placeholder == "?" else
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (%s,%s,%s,%s,%s)",
                (_nonce(nonce), _digest(session_digest, "session_digest"),
                 authorization_expiry, stamp, authorization_id))
            self._insert(con, "authorization_v2", {
                "authorization_id": authorization_id,
                "nonce": _nonce(nonce),
                "attempt_id": record.attempt_id,
                "execution_identity_digest":
                    record.execution_identity_digest,
                "requester_principal_id": record.requester_principal_id,
                "task_id": record.task_id,
                "repository_id": record.repository_id,
                "repository_tree_digest": record.repository_tree_digest,
                "base_commit_digest": record.base_commit_digest,
                "guidance_digest": record.guidance_digest,
                "authority_snapshot_digest":
                    record.authority_snapshot_digest,
                "authority_epoch": record.authority_epoch,
                "decision": record.decision,
                "issued_at": record.issued_at,
                "expires_at": record.expires_at,
                "signer_key_id": record.signer_key_id,
                "record_digest": record.digest,
                "record_json": canonical_json(record).decode("utf-8"),
                "committed_at": stamp,
            }, "authorization_conflict")
        return record


class SqliteControlPlane(_SqlControlPlane):
    """Single-host durable control plane (SQLite, transactional).

    Suitable for development and single-host production. It is *not* the
    distributed qualification target: do not place the database on a
    network filesystem and expect cross-host atomicity.
    """

    def __init__(self, path: str | Path, *,
                 signing_key: SigningKey | None = None) -> None:
        self.path = Path(path)
        self._bind_signer(signing_key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=15.0,
            check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=FULL")
        self._con.execute("PRAGMA busy_timeout=15000")
        with self._lock:
            for statement in _SCHEMA:
                self._con.execute(statement)
        with self._transaction() as con:
            self._ensure_schema_version(con)

    def schema_version(self) -> int:
        with self._transaction() as con:
            row = con.execute(
                "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
        return row[0] if row is not None else 0

    def _transaction(self):
        return _SqliteTransaction(self._con, self._lock)

    def commit_authorization(self, *, nonce, session_digest, expires_at,
                             task_id, repository_id, guidance_digest,
                             decision, snapshot_digest, expected_head=None,
                             committed_at=None) -> dict:
        values = self._validate_commit(
            nonce=nonce, session_digest=session_digest,
            expires_at=expires_at, task_id=task_id,
            repository_id=repository_id, guidance_digest=guidance_digest,
            decision=decision, snapshot_digest=snapshot_digest)
        authorization_id = "auth-" + secrets.token_hex(16)
        with self._transaction() as con:
            current = self._head(con)
            self._check_expected_head(current, expected_head)
            existing = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=?",
                (values["nonce"],)).fetchone()
            if existing is not None:
                raise ControlPlaneError("session_nonce_replayed")
            con.execute(
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (?,?,?,?,?)",
                (values["nonce"], values["session_digest"],
                 values["expires_at"], committed_at or _utcnow(),
                 authorization_id))
            con.execute(
                "INSERT INTO authorization_receipt"
                " (authorization_id, nonce, task_id, repository_id,"
                "  guidance_digest, decision, snapshot_digest, committed_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (authorization_id, values["nonce"], values["task_id"],
                 values["repository_id"], values["guidance_digest"],
                 values["decision"], values["snapshot_digest"],
                 committed_at or _utcnow()))
        return self.authorization(authorization_id)

    def authorization(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, nonce, task_id, repository_id,"
                " guidance_digest, decision, snapshot_digest, committed_at"
                " FROM authorization_receipt WHERE authorization_id=?",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "nonce", "task_id", "repository_id",
            "guidance_digest", "decision", "snapshot_digest",
            "committed_at"))

    def authorization_for_nonce(self, nonce: str) -> dict | None:
        _nonce(nonce)
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=?",
                (nonce,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def authorization_for_task(self, task_id: str) -> dict | None:
        _identifier(task_id, "task_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM authorization_receipt"
                " WHERE task_id=? ORDER BY committed_at DESC,"
                " authorization_id DESC LIMIT 1", (task_id,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def record_outcome(self, *, authorization_id, task_id, served_digest,
                       receipt_digest, outcome, recorded_at=None) -> dict:
        _identifier(authorization_id, "authorization_id")
        _identifier(task_id, "task_id")
        _digest(served_digest, "served_digest")
        _digest(receipt_digest, "receipt_digest")
        if outcome not in _OUTCOMES:
            raise ControlPlaneError("outcome_invalid")
        with self._transaction() as con:
            receipt = con.execute(
                "SELECT task_id, guidance_digest FROM authorization_receipt"
                " WHERE authorization_id=?", (authorization_id,)).fetchone()
            if receipt is None:
                raise ControlPlaneError("authorization_unknown")
            if receipt[0] != task_id:
                raise ControlPlaneError("authorization_task_mismatch")
            if receipt[1] != served_digest:
                raise ControlPlaneError("served_guidance_unknown")
            existing = con.execute(
                "SELECT 1 FROM guidance_outcome WHERE authorization_id=?",
                (authorization_id,)).fetchone()
            if existing is not None:
                raise ControlPlaneError("outcome_already_recorded")
            con.execute(
                "INSERT INTO guidance_outcome"
                " (authorization_id, task_id, served_digest, receipt_digest,"
                "  outcome, recorded_at) VALUES (?,?,?,?,?,?)",
                (authorization_id, task_id, served_digest, receipt_digest,
                 outcome, recorded_at or _utcnow()))
        return self.outcome(authorization_id)

    def outcome(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, task_id, served_digest,"
                " receipt_digest, outcome, recorded_at"
                " FROM guidance_outcome WHERE authorization_id=?",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "task_id", "served_digest", "receipt_digest",
            "outcome", "recorded_at"))

    def _head(self, con) -> dict | None:
        row = con.execute(
            "SELECT singleton, sequence, checkpoint_digest, journal_head,"
            " revocation_head, supersession_head, custody_entry_count,"
            " updated_at FROM authority_head WHERE singleton=1").fetchone()
        return self._head_row(row)

    def authority_head(self) -> dict | None:
        with self._transaction() as con:
            return self._head(con)

    def advance_authority_head(self, head: dict) -> dict:
        values = _validate_head(head)
        if type(values["custody_entry_count"]) is not int or \
                values["custody_entry_count"] < 0:
            raise ControlPlaneError("custody_entry_count_invalid")
        with self._transaction() as con:
            current = self._head(con)
            if current is not None:
                if values["sequence"] < current["sequence"]:
                    raise ControlPlaneError("authority_head_rollback")
                if values["sequence"] == current["sequence"]:
                    if all(values[key] == current[key] for key in (
                            "checkpoint_digest", "journal_head",
                            "revocation_head", "supersession_head",
                            "custody_entry_count")):
                        return current
                    raise ControlPlaneError("authority_head_conflict")
                if values["custody_entry_count"] < \
                        current["custody_entry_count"]:
                    raise ControlPlaneError("custody_entry_count_regression")
            con.execute(
                "INSERT INTO authority_head"
                " (singleton, sequence, checkpoint_digest, journal_head,"
                "  revocation_head, supersession_head, custody_entry_count,"
                "  updated_at) VALUES (1,?,?,?,?,?,?,?)"
                " ON CONFLICT(singleton) DO UPDATE SET"
                " sequence=excluded.sequence,"
                " checkpoint_digest=excluded.checkpoint_digest,"
                " journal_head=excluded.journal_head,"
                " revocation_head=excluded.revocation_head,"
                " supersession_head=excluded.supersession_head,"
                " custody_entry_count=excluded.custody_entry_count,"
                " updated_at=excluded.updated_at",
                (values["sequence"], values["checkpoint_digest"],
                 values["journal_head"], values["revocation_head"],
                 values["supersession_head"],
                 values["custody_entry_count"], values["updated_at"]))
        return self.authority_head()

    def _is_integrity_error(self, exc: BaseException) -> bool:
        return isinstance(exc, sqlite3.IntegrityError)

    def close(self) -> None:
        with self._lock:
            self._con.close()


class _SqliteTransaction:
    def __init__(self, con, lock) -> None:
        self._con = con
        self._lock = lock

    def __enter__(self):
        self._lock.acquire()
        try:
            self._con.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            self._lock.release()
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        except BaseException:
            self._lock.release()
            raise
        return self._con

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._con.execute("COMMIT")
            else:
                self._con.execute("ROLLBACK")
        except sqlite3.Error as error:
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        finally:
            self._lock.release()
        if exc_type is not None and issubclass(exc_type, sqlite3.Error):
            raise ControlPlaneError(
                "control_plane_unavailable", str(exc)) from exc
        return False


class PostgresControlPlane(_SqlControlPlane):
    """Multi-process production control plane (PostgreSQL).

    Uniqueness constraints plus a single transaction provide the
    cross-replica serialization point. The signing/custody principals are
    expected to be separate database roles in a real deployment.
    """

    placeholder = "%s"

    def __init__(self, dsn: str, *, connect_timeout: int = 10,
                 signing_key: SigningKey | None = None) -> None:
        self._bind_signer(signing_key)
        if not isinstance(dsn, str) or not dsn:
            raise ControlPlaneError("postgres_dsn_required")
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ControlPlaneError("postgres_driver_missing") from exc
        self._psycopg = psycopg
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._lock = threading.RLock()
        with self._transaction() as con:
            for statement in _SCHEMA:
                con.execute(statement)
        with self._transaction() as con:
            self._ensure_schema_version(con)

    def schema_version(self) -> int:
        with self._transaction() as con:
            row = con.execute(
                "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
        return row[0] if row is not None else 0

    def _transaction(self):
        return _PostgresTransaction(
            self._psycopg, self._dsn, self._connect_timeout, self._lock)

    def commit_authorization(self, *, nonce, session_digest, expires_at,
                             task_id, repository_id, guidance_digest,
                             decision, snapshot_digest, expected_head=None,
                             committed_at=None) -> dict:
        values = self._validate_commit(
            nonce=nonce, session_digest=session_digest,
            expires_at=expires_at, task_id=task_id,
            repository_id=repository_id, guidance_digest=guidance_digest,
            decision=decision, snapshot_digest=snapshot_digest)
        authorization_id = "auth-" + secrets.token_hex(16)
        with self._transaction() as con:
            current = self._head(con)
            self._check_expected_head(current, expected_head)
            inserted = con.execute(
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (%s,%s,%s,%s,%s)"
                " ON CONFLICT (nonce) DO NOTHING RETURNING nonce",
                (values["nonce"], values["session_digest"],
                 values["expires_at"], committed_at or _utcnow(),
                 authorization_id)).fetchone()
            if inserted is None:
                raise ControlPlaneError("session_nonce_replayed")
            con.execute(
                "INSERT INTO authorization_receipt"
                " (authorization_id, nonce, task_id, repository_id,"
                "  guidance_digest, decision, snapshot_digest, committed_at)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (authorization_id, values["nonce"], values["task_id"],
                 values["repository_id"], values["guidance_digest"],
                 values["decision"], values["snapshot_digest"],
                 committed_at or _utcnow()))
        return self.authorization(authorization_id)

    def authorization(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, nonce, task_id, repository_id,"
                " guidance_digest, decision, snapshot_digest, committed_at"
                " FROM authorization_receipt WHERE authorization_id=%s",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "nonce", "task_id", "repository_id",
            "guidance_digest", "decision", "snapshot_digest",
            "committed_at"))

    def authorization_for_nonce(self, nonce: str) -> dict | None:
        _nonce(nonce)
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=%s",
                (nonce,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def authorization_for_task(self, task_id: str) -> dict | None:
        _identifier(task_id, "task_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM authorization_receipt"
                " WHERE task_id=%s ORDER BY committed_at DESC,"
                " authorization_id DESC LIMIT 1", (task_id,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def record_outcome(self, *, authorization_id, task_id, served_digest,
                       receipt_digest, outcome, recorded_at=None) -> dict:
        _identifier(authorization_id, "authorization_id")
        _identifier(task_id, "task_id")
        _digest(served_digest, "served_digest")
        _digest(receipt_digest, "receipt_digest")
        if outcome not in _OUTCOMES:
            raise ControlPlaneError("outcome_invalid")
        with self._transaction() as con:
            receipt = con.execute(
                "SELECT task_id, guidance_digest FROM authorization_receipt"
                " WHERE authorization_id=%s", (authorization_id,)).fetchone()
            if receipt is None:
                raise ControlPlaneError("authorization_unknown")
            if receipt[0] != task_id:
                raise ControlPlaneError("authorization_task_mismatch")
            if receipt[1] != served_digest:
                raise ControlPlaneError("served_guidance_unknown")
            inserted = con.execute(
                "INSERT INTO guidance_outcome"
                " (authorization_id, task_id, served_digest, receipt_digest,"
                "  outcome, recorded_at) VALUES (%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (authorization_id) DO NOTHING RETURNING"
                " authorization_id",
                (authorization_id, task_id, served_digest, receipt_digest,
                 outcome, recorded_at or _utcnow())).fetchone()
            if inserted is None:
                raise ControlPlaneError("outcome_already_recorded")
        return self.outcome(authorization_id)

    def outcome(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, task_id, served_digest,"
                " receipt_digest, outcome, recorded_at"
                " FROM guidance_outcome WHERE authorization_id=%s",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "task_id", "served_digest", "receipt_digest",
            "outcome", "recorded_at"))

    def _head(self, con) -> dict | None:
        row = con.execute(
            "SELECT singleton, sequence, checkpoint_digest, journal_head,"
            " revocation_head, supersession_head, custody_entry_count,"
            " updated_at FROM authority_head WHERE singleton=1").fetchone()
        return self._head_row(row)

    def authority_head(self) -> dict | None:
        with self._transaction() as con:
            return self._head(con)

    def advance_authority_head(self, head: dict) -> dict:
        values = _validate_head(head)
        if type(values["custody_entry_count"]) is not int or \
                values["custody_entry_count"] < 0:
            raise ControlPlaneError("custody_entry_count_invalid")
        with self._transaction() as con:
            current = self._head(con)
            if current is not None:
                if values["sequence"] < current["sequence"]:
                    raise ControlPlaneError("authority_head_rollback")
                if values["sequence"] == current["sequence"]:
                    if all(values[key] == current[key] for key in (
                            "checkpoint_digest", "journal_head",
                            "revocation_head", "supersession_head",
                            "custody_entry_count")):
                        return current
                    raise ControlPlaneError("authority_head_conflict")
                if values["custody_entry_count"] < \
                        current["custody_entry_count"]:
                    raise ControlPlaneError("custody_entry_count_regression")
            con.execute(
                "INSERT INTO authority_head"
                " (singleton, sequence, checkpoint_digest, journal_head,"
                "  revocation_head, supersession_head, custody_entry_count,"
                "  updated_at) VALUES (1,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (singleton) DO UPDATE SET"
                " sequence=excluded.sequence,"
                " checkpoint_digest=excluded.checkpoint_digest,"
                " journal_head=excluded.journal_head,"
                " revocation_head=excluded.revocation_head,"
                " supersession_head=excluded.supersession_head,"
                " custody_entry_count=excluded.custody_entry_count,"
                " updated_at=excluded.updated_at",
                (values["sequence"], values["checkpoint_digest"],
                 values["journal_head"], values["revocation_head"],
                 values["supersession_head"],
                 values["custody_entry_count"], values["updated_at"]))
        return self.authority_head()

    def _is_integrity_error(self, exc: BaseException) -> bool:
        base = getattr(self._psycopg.errors, "IntegrityError", None)
        return base is not None and isinstance(exc, base)

    def close(self) -> None:
        return None


class _ParamStyle:
    """Adapts ``?`` parameters to the backend's placeholder style.

    Every statement shared by both backends is written with ``?`` so the
    SQL is identical for SQLite and PostgreSQL; the PostgreSQL connection
    is wrapped so the driver receives ``%s``. Statements that already use
    ``%s`` pass through unchanged, so backend-specific methods keep
    working. Without this, a shared statement works under SQLite and
    fails under PostgreSQL with "0 placeholders but 1 parameters passed"
    — a defect no SQLite-only run can catch.
    """

    def __init__(self, connection) -> None:
        self._connection = connection

    def execute(self, sql: str, params=()):
        return self._connection.execute(_to_psycopg_placeholders(sql), params)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def _to_psycopg_placeholders(sql: str) -> str:
    """Rewrite ``?`` outside string literals to ``%s``.

    A blind ``str.replace`` would also rewrite a question mark inside a
    quoted literal (a LIKE pattern, a JSON path), which silently changes
    the statement's meaning. Quoted regions are copied verbatim.
    """
    out: list[str] = []
    quote: str | None = None
    for char in sql:
        if quote is not None:
            out.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            out.append(char)
        elif char == "?":
            out.append("%s")
        else:
            out.append(char)
    return "".join(out)


class _PostgresTransaction:
    def __init__(self, psycopg, dsn, timeout, lock) -> None:
        self._psycopg = psycopg
        self._dsn = dsn
        self._timeout = timeout
        self._lock = lock
        self._con = None

    def __enter__(self):
        self._lock.acquire()
        try:
            self._con = self._psycopg.connect(
                self._dsn, connect_timeout=self._timeout)
            return _ParamStyle(self._con)
        except Exception as error:
            self._lock.release()
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        except BaseException:
            self._lock.release()
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._con.commit()
            else:
                self._con.rollback()
        except Exception as error:
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        finally:
            self._con.close()
            self._lock.release()
        if exc_type is not None and issubclass(exc_type, Exception) and \
                not issubclass(exc_type, ControlPlaneError):
            raise ControlPlaneError(
                "control_plane_unavailable", str(exc)) from exc
        return False


def open_control_plane(location: str | Path, *,
                       postgres_dsn: str | None = None) -> ControlPlane:
    """Open the configured profile: ``postgresql://`` DSN or SQLite path."""
    if postgres_dsn is not None:
        return PostgresControlPlane(postgres_dsn)
    if isinstance(location, str) and location.startswith(
            ("postgresql://", "postgres://")):
        return PostgresControlPlane(location)
    return SqliteControlPlane(str(location).removeprefix("sqlite:///"))


__all__ = [
    "ControlPlane",
    "ControlPlaneError",
    "PostgresControlPlane",
    "SqliteControlPlane",
    "open_control_plane",
]
