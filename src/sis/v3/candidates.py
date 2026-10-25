"""Typed, governed candidate registry (SIS v3.3, milestone 3).

One registry for every learnable artifact type: symbolic procedures,
diagnostic strategies, experience memories, skill instructions/bundles and
prompt variants. ``CandidateV1`` records are immutable and
content-addressed; mutable evaluation state lives only in this store.

State machine (spec):

    PROPOSED -> VALIDATED -> EVALUATING -> REJECTED
                                        -> INCONCLUSIVE
                                        -> QUALIFIED -> REVOKED

Every transition is role-gated through ``policy.require_permission`` and
committed inside one ``BEGIN IMMEDIATE`` transaction with an audit row —
a transition and its audit entry land together or not at all. Only the
``operator`` role (``promotion:approve``) may qualify a candidate, and
qualification requires at least one bound evaluator receipt digest:
candidate generators can never confer promotion authority. Revocation is
a first-class terminal state so promoted artifacts always support audit,
rollback, and takedown.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .contracts import CandidateV1, ContractError, canonical_digest, loads_json
from .policy import require_permission

_HEX = re.compile(r"^[0-9a-f]{64}$")

CANDIDATE_TYPES = frozenset({
    "symbolic_procedure", "diagnostic_strategy", "experience_memory",
    "skill_instruction", "skill_bundle", "prompt_variant",
})
STATES = ("proposed", "validated", "evaluating", "rejected",
          "inconclusive", "qualified", "revoked")

_EDGES = {
    "proposed": frozenset({"validated", "rejected"}),
    "validated": frozenset({"evaluating", "rejected"}),
    "evaluating": frozenset({"qualified", "rejected", "inconclusive"}),
    "inconclusive": frozenset(),
    "rejected": frozenset(),
    "qualified": frozenset({"revoked"}),
    "revoked": frozenset(),
}

_TRANSITION_ROLE = {
    ("proposed", "validated"): ("candidate:write",),
    ("proposed", "rejected"): ("outcome:evaluate", "promotion:approve"),
    ("validated", "evaluating"): ("outcome:evaluate",),
    ("validated", "rejected"): ("outcome:evaluate", "promotion:approve"),
    ("evaluating", "qualified"): ("promotion:approve",),
    ("evaluating", "rejected"): ("outcome:evaluate",),
    ("evaluating", "inconclusive"): ("outcome:evaluate",),
    ("qualified", "revoked"): ("promotion:approve",),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate (
    candidate_id TEXT PRIMARY KEY,
    candidate_digest TEXT NOT NULL UNIQUE,
    candidate_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidate_transition (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    actor_identity TEXT NOT NULL,
    receipt_refs_json TEXT NOT NULL,
    note TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def content_digest(candidate_type: str, payload) -> str:
    """Domain-separated digest over the typed payload (helper for builders)."""
    return canonical_digest("candidate_content", 1,
                            {"type": candidate_type, "payload": payload})


def _check_digest(value, name):
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")


class CandidateError(RuntimeError):
    """The candidate registry cannot complete an operation."""


class CandidateConflict(CandidateError):
    """A write conflicts with committed state or an illegal transition."""


def _permitted(role: str, action: str) -> bool:
    try:
        require_permission(role, action)
        return True
    except Exception:
        return False


class CandidateRegistry:
    """Single-writer transactional store for governed learning candidates."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=15.0,
            check_same_thread=False)
        con = self._con
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=15000")
        con.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            if self._con is not None:
                try:
                    self._con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                self._con.close()
                self._con = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _conn(self) -> sqlite3.Connection:
        if self._con is None:
            raise CandidateError("candidate_registry_closed")
        return self._con

    # ------------------------------------------------------------------ #
    # intake — learners only; a submission can never mint elevated state
    # ------------------------------------------------------------------ #
    def submit(self, candidate: CandidateV1, *, actor_role: str) -> str:
        """Persist a new candidate at PROPOSED; idempotent on identical."""
        require_permission(actor_role, "candidate:write")
        if not isinstance(candidate, CandidateV1):
            candidate = CandidateV1.from_dict(candidate)
        with self._lock:
            con = self._conn()
            row = con.execute(
                "SELECT candidate_digest, state FROM candidate WHERE candidate_id=?",
                (candidate.candidate_id,),
            ).fetchone()
            if row is not None:
                if row[0] == candidate.digest:
                    return candidate.digest
                raise CandidateConflict("candidate_id_conflict")
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO candidate"
                    " (candidate_id, candidate_digest, candidate_json, state, created_at)"
                    " VALUES (?, ?, ?, 'proposed', ?)",
                    (candidate.candidate_id, candidate.digest,
                     candidate.canonical_bytes().decode("utf-8"), _utcnow()))
                self._audit(con, candidate.candidate_id, "", "proposed",
                            actor_role, (), "submitted")
                con.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise CandidateConflict(f"submit_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise
            return candidate.digest

    # ------------------------------------------------------------------ #
    # governed transitions
    # ------------------------------------------------------------------ #
    def transition(self, candidate_id: str, target: str, *,
                   actor_role: str, actor_identity: str = "",
                   receipt_refs=(), note: str = "") -> None:
        """Move ``candidate_id`` along a legal edge; role-gated + audited.

        QUALIFIED additionally requires ``promotion:approve`` *and* at
        least one bound evaluator receipt digest — the evidence handle the
        qualification stands on. Every check is re-evaluated inside the
        write transaction so stale readers cannot interleave.
        """
        if target not in STATES:
            raise ContractError(f"unknown candidate state: {target}")
        refs = tuple(receipt_refs or ())
        for ref in refs:
            _check_digest(ref, "receipt_refs[]")
        if target == "qualified" and not refs:
            raise CandidateConflict(
                "qualification_requires_bound_receipts")

        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute(
                    "SELECT state FROM candidate WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                if row is None:
                    raise CandidateConflict("candidate_missing")
                current = row[0]
                if target not in _EDGES[current]:
                    raise CandidateConflict(
                        f"illegal_transition:{current}->{target}")
                actions = _TRANSITION_ROLE[(current, target)]
                if not any(_permitted(actor_role, a) for a in actions):
                    raise CandidateConflict(
                        f"role_denied:{actor_role} cannot {current}->{target}")
                con.execute(
                    "UPDATE candidate SET state=? WHERE candidate_id=?",
                    (target, candidate_id))
                self._audit(con, candidate_id, current, target,
                            actor_identity or actor_role, refs, note)
                con.execute("COMMIT")
            except CandidateError:
                _safe_rollback(con)
                raise
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise CandidateConflict(f"transition_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise

    def qualify(self, candidate_id: str, *,
                actor_role: str, actor_identity: str = "",
                receipt_refs, note: str = "") -> None:
        """Explicit qualification — operator only, receipts mandatory."""
        self.transition(candidate_id, "qualified", actor_role=actor_role,
                        actor_identity=actor_identity,
                        receipt_refs=receipt_refs, note=note)

    def revoke(self, candidate_id: str, *,
               actor_role: str, actor_identity: str = "",
               note: str = "") -> None:
        self.transition(candidate_id, "revoked", actor_role=actor_role,
                        actor_identity=actor_identity, note=note)

    def _audit(self, con, candidate_id, from_state, to_state,
               actor_identity, receipt_refs, note) -> None:
        import json as _json
        con.execute(
            "INSERT INTO candidate_transition"
            " (candidate_id, from_state, to_state, actor_identity,"
            "  receipt_refs_json, note, committed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (candidate_id, from_state, to_state, actor_identity,
             _json.dumps(list(receipt_refs), sort_keys=True),
             note, _utcnow()))

    # ------------------------------------------------------------------ #
    # reads — digest re-verified on every read; corrupt rows fail closed
    # ------------------------------------------------------------------ #
    def _row_to_record(self, row) -> CandidateV1:
        record = CandidateV1.from_dict(loads_json(row[1].encode("utf-8")))
        if record.digest != row[0]:
            raise CandidateError(
                f"candidate_tampered:{record.candidate_id}")
        return record

    def get(self, candidate_id: str) -> tuple[CandidateV1, str]:
        row = self._conn().execute(
            "SELECT candidate_digest, candidate_json, state FROM candidate"
            " WHERE candidate_id=?", (candidate_id,),
        ).fetchone()
        if row is None:
            raise CandidateError("candidate_missing")
        return self._row_to_record(row[:2]), row[2]

    def by_state(self, state: str) -> list[CandidateV1]:
        if state not in STATES:
            raise ContractError(f"unknown candidate state: {state}")
        rows = self._conn().execute(
            "SELECT candidate_digest, candidate_json FROM candidate"
            " WHERE state=? ORDER BY candidate_id", (state,),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def qualified(self) -> list[CandidateV1]:
        return self.by_state("qualified")

    def state_of(self, candidate_id: str) -> str:
        return self.get(candidate_id)[1]

    def audit(self, candidate_id: str | None = None) -> list[dict]:
        import json as _json
        sql = ("SELECT seq, candidate_id, from_state, to_state,"
               " actor_identity, receipt_refs_json, note, committed_at"
               " FROM candidate_transition")
        args: tuple = ()
        if candidate_id is not None:
            sql += " WHERE candidate_id=?"
            args = (candidate_id,)
        sql += " ORDER BY seq"
        out = []
        for seq, cid, frm, to, actor, refs, note, at in \
                self._conn().execute(sql, args):
            out.append({
                "seq": seq, "candidate_id": cid, "from_state": frm,
                "to_state": to, "actor_identity": actor,
                "receipt_refs": _json.loads(refs), "note": note,
                "committed_at": at})
        return out


def _safe_rollback(con) -> None:
    try:
        con.execute("ROLLBACK")
    except sqlite3.Error:
        pass
