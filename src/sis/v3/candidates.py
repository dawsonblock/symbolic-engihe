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

Audit rows are hash-chained (``prev_digest`` → ``entry_digest``) inside
the same transaction and re-verified end-to-end on every ``audit()``
read — rewritten, reordered or deleted history fails closed, the same
tamper-evidence model as the v3.2 authority journal.
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
    committed_at TEXT NOT NULL,
    prev_digest TEXT NOT NULL DEFAULT '',
    entry_digest TEXT NOT NULL DEFAULT ''
);
"""

_GENESIS = "0" * 64


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


def _entry_digest(seq, candidate_id, from_state, to_state,
                  actor_identity, receipt_refs_json, note,
                  committed_at, prev_digest) -> str:
    """Domain-separated digest over one audit row plus its chain link."""
    import json as _json
    return canonical_digest("candidate_audit", 1, {
        "seq": seq,
        "candidate_id": candidate_id,
        "from_state": from_state,
        "to_state": to_state,
        "actor_identity": actor_identity,
        "receipt_refs": _json.loads(receipt_refs_json),
        "note": note,
        "committed_at": committed_at,
        "prev_digest": prev_digest,
    })


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
        self._migrate(con)

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

    def _migrate(self, con) -> None:
        """Seal legacy audit rows: add chain columns, backfill digests.

        Rows written before the chain existed are sealed over their
        current content — backfill makes them verifiable, it cannot
        prove they were not already altered. New writes are always
        chained inside the same BEGIN IMMEDIATE transaction.
        """
        cols = {row[1] for row in con.execute(
            "PRAGMA table_info(candidate_transition)")}
        missing = {"prev_digest", "entry_digest"} - cols
        if not missing:
            return
        con.execute("BEGIN IMMEDIATE")
        try:
            for col in missing:
                con.execute(
                    f"ALTER TABLE candidate_transition"
                    f" ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
            rows = con.execute(
                "SELECT seq, candidate_id, from_state, to_state,"
                " actor_identity, receipt_refs_json, note, committed_at"
                " FROM candidate_transition ORDER BY seq").fetchall()
            prev = _GENESIS
            for (seq, cid, frm, to, actor, refs, note, at) in rows:
                digest = _entry_digest(seq, cid, frm, to, actor,
                                       refs, note, at, prev)
                con.execute(
                    "UPDATE candidate_transition SET prev_digest=?,"
                    " entry_digest=? WHERE seq=?", (prev, digest, seq))
                prev = digest
            con.execute("COMMIT")
        except Exception:
            _safe_rollback(con)
            raise

    def _audit(self, con, candidate_id, from_state, to_state,
               actor_identity, receipt_refs, note) -> None:
        import json as _json
        refs_json = _json.dumps(list(receipt_refs), sort_keys=True)
        at = _utcnow()
        row = con.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM candidate_transition"
        ).fetchone()
        seq = row[0] + 1
        tail = con.execute(
            "SELECT entry_digest FROM candidate_transition"
            " ORDER BY seq DESC LIMIT 1").fetchone()
        prev = tail[0] if tail is not None and tail[0] else _GENESIS
        digest = _entry_digest(seq, candidate_id, from_state, to_state,
                               actor_identity, refs_json, note, at, prev)
        con.execute(
            "INSERT INTO candidate_transition"
            " (seq, candidate_id, from_state, to_state, actor_identity,"
            "  receipt_refs_json, note, committed_at, prev_digest,"
            "  entry_digest)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, candidate_id, from_state, to_state, actor_identity,
             refs_json, note, at, prev, digest))

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
        """Return the transition log after verifying the hash chain.

        Every row's ``entry_digest`` is recomputed from stored content and
        its ``prev_digest`` link; a rewritten, reordered, deleted or
        truncated row raises ``audit_chain_tampered`` — history integrity
        is checked on every read, same as record integrity.
        """
        import json as _json
        rows = self._conn().execute(
            "SELECT seq, candidate_id, from_state, to_state,"
            " actor_identity, receipt_refs_json, note, committed_at,"
            " prev_digest, entry_digest"
            " FROM candidate_transition ORDER BY seq").fetchall()
        # The chain is only meaningful end-to-end: verify the full log,
        # then filter — a filtered read must never skip verification.
        self._verify_chain(rows)
        out = []
        for seq, cid, frm, to, actor, refs, note, at, prev, dg in rows:
            if candidate_id is not None and cid != candidate_id:
                continue
            out.append({
                "seq": seq, "candidate_id": cid, "from_state": frm,
                "to_state": to, "actor_identity": actor,
                "receipt_refs": _json.loads(refs), "note": note,
                "committed_at": at, "entry_digest": dg})
        return out

    @staticmethod
    def _verify_chain(rows) -> None:
        prev = _GENESIS
        for seq, cid, frm, to, actor, refs, note, at, p, dg in rows:
            if p != prev:
                raise CandidateError(
                    f"audit_chain_tampered:link_at_{seq}")
            expected = _entry_digest(seq, cid, frm, to, actor,
                                     refs, note, at, p)
            if dg != expected or not _HEX.fullmatch(dg):
                raise CandidateError(
                    f"audit_chain_tampered:row_at_{seq}")
            prev = dg


def _safe_rollback(con) -> None:
    try:
        con.execute("ROLLBACK")
    except sqlite3.Error:
        pass
