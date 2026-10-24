"""Procedure candidate records and the offline miner (SIS3-007).

``ProcedureStore`` keeps every ``ProcedureRecordV1`` revision in an
append-only, hash-chained JSONL log; the same (procedure_id, revision) pair is
idempotent on identical content and rejected on conflict, and ``verify``
re-digests every stored record plus the chain.

``mine_candidates`` is a deterministic offline pass over episodes whose
outcome was produced by an ``OutcomeVerifier``-signed receipt. A passing
episode yields a ``candidate`` procedure recording its observed failure
signatures, context, and evidence references; a failing episode yields a
candidate carrying the receipt as a ``counterexample_refs`` entry, which the
retrieval layer later uses for negative-transfer handling. Mining never sets
``qualified`` — only the promotion controller can.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .contracts import (
    ContractError,
    ObservationEventV1,
    OutcomeReceiptV1,
    ProcedureRecordV1,
    canonical_digest,
    canonical_json,
)
from .policy import require_permission

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")


class ProcedureStoreError(RuntimeError):
    """The procedure store cannot complete an operation."""


class ProcedureConflict(ProcedureStoreError):
    """A record conflicts with already-persisted catalog state."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ProcedureStore:
    """Append-only catalog of procedure revisions keyed by content digest."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._log = self.root / "procedures.jsonl"
        self._records: dict[str, dict[int, ProcedureRecordV1]] = {}
        self._digests: dict[tuple[str, int], str] = {}
        self._by_digest: dict[str, ProcedureRecordV1] = {}
        self._backing: dict[str, str] = {}  # record_digest -> decision digest
        self._prior: str | None = None
        self._lock = threading.Lock()
        self._load()

    #: Statuses an unprivileged write may mint directly. Every governed
    #: status (evaluated/qualified/suspended/retired) exists only inside a
    #: committed signed promotion decision — there is no caller-side flag.
    WRITABLE_STATUSES = frozenset({"draft", "candidate"})

    def add(self, record: ProcedureRecordV1 | Mapping) -> str:
        """Append a draft/candidate revision; idempotent on identical content.

        Governed statuses are refused outright: there is no code-level
        bypass. Only ``_commit_record`` — invoked by the promotion
        controller with the digest of a committed signed decision — may
        persist a governed status.
        """
        if not isinstance(record, ProcedureRecordV1):
            record = ProcedureRecordV1.from_dict(record)
        if record.status not in self.WRITABLE_STATUSES:
            raise ProcedureConflict("governed_status_requires_decision")
        with self._lock:
            return self._append_locked(record, backing_decision=None)

    def _append_locked(
        self, record: ProcedureRecordV1, backing_decision: str | None
    ) -> str:
        """Append under ``self._lock``; the only writer that accepts any status."""
        key = (record.procedure_id, record.revision)
        existing = self._digests.get(key)
        if existing is not None:
            if existing == record.digest:
                return existing
            raise ProcedureConflict("procedure_revision_conflict")
        entry = {
            "record": record.to_dict(),
            "record_digest": record.digest,
            "prior_record_digest": self._prior,
        }
        if backing_decision is not None:
            entry["backing_decision"] = backing_decision
        line = canonical_json(entry)
        with open(self._log, "ab") as handle:
            handle.write(line + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._records.setdefault(record.procedure_id, {})[record.revision] = record
        self._digests[key] = record.digest
        self._by_digest[record.digest] = record
        if backing_decision is not None:
            self._backing[record.digest] = backing_decision
        self._prior = hashlib.sha256(line).hexdigest()
        return record.digest

    def _commit_record(
        self, record: ProcedureRecordV1, *, backing_decision: str
    ) -> str:
        """Internal: persist a governed revision bound to a decision digest.

        Only the promotion controller's atomic commit path calls this; the
        ``backing_decision`` is stored in the log entry so replay can prove
        every governed record traces to a signed decision.
        """
        if not isinstance(backing_decision, str) or not re.fullmatch(
            r"[0-9a-f]{64}", backing_decision
        ):
            raise ContractError("backing_decision must be a SHA-256 digest")
        with self._lock:
            return self._append_locked(record, backing_decision)

    def get(self, procedure_id: str, revision: int | None = None) -> ProcedureRecordV1:
        """Return the latest (or a specific) revision of a procedure."""
        versions = self._records.get(procedure_id)
        if not versions:
            raise ProcedureStoreError("unknown_procedure")
        rev = max(versions) if revision is None else revision
        if rev not in versions:
            raise ProcedureStoreError("unknown_revision")
        return versions[rev]

    def get_by_digest(self, digest: str) -> ProcedureRecordV1 | None:
        """Resolve a record by its content digest, or None."""
        return self._by_digest.get(digest)

    def backing_decision(self, digest: str) -> str | None:
        """The decision digest this record revision was committed under."""
        return self._backing.get(digest)

    def refresh(self) -> None:
        """Re-read the log from disk so another process's commits are visible."""
        with self._lock:
            self._records = {}
            self._digests = {}
            self._by_digest = {}
            self._backing = {}
            self._prior = None
            self._load()

    def by_status(self, status: str) -> list[ProcedureRecordV1]:
        """Latest revision of each procedure filtered by status."""
        return [rec for rec in (self.get(pid) for pid in self._records) if rec.status == status]

    def all_latest(self) -> list[ProcedureRecordV1]:
        return [self.get(pid) for pid in sorted(self._records)]

    def catalog_digest(self) -> str:
        """Digest over the sorted latest-revision records — the catalog head."""
        return canonical_digest("procedure_catalog", 1, {
            "head": sorted(rec.digest for rec in self.all_latest()),
        })

    def qualified_head_digest(self) -> str:
        """Digest over currently qualified records only."""
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(rec.digest for rec in self.by_status("qualified")),
        })

    def replace_record(self, record: ProcedureRecordV1) -> str:
        """Append a new revision (status change); revision must increment."""
        latest = self._records.get(record.procedure_id)
        if latest is not None and record.revision <= max(latest):
            raise ProcedureConflict("revision must strictly increase")
        return self.add(record)

    def verify(self) -> dict:
        """Replay the log; digests, chain, and decision-backing must hold.

        Records carrying a governed status without a ``backing_decision``
        are flagged ``unbacked_status`` — legacy qualified records are never
        silently grandfathered into servable state.
        """
        problems: list[str] = []
        prior: str | None = None
        seen: set[tuple[str, int]] = set()
        count = 0
        if self._log.exists():
            with open(self._log, "rb") as handle:
                for position, raw in enumerate(handle):
                    count += 1
                    line = raw.rstrip(b"\n")
                    try:
                        entry = _bounded_entry(line)
                    except (ContractError, ValueError):
                        problems.append(f"undecodable_entry_at_{position}")
                        continue
                    if entry["prior_record_digest"] != prior:
                        problems.append(f"chain_conflict_at_{position}")
                    record = ProcedureRecordV1.from_dict(entry["record"])
                    if record.digest != entry["record_digest"]:
                        problems.append(f"record_digest_mismatch_at_{position}")
                    if record.status not in self.WRITABLE_STATUSES \
                            and entry.get("backing_decision") is None:
                        problems.append(f"unbacked_status_at_{position}")
                    key = (record.procedure_id, record.revision)
                    if key in seen:
                        problems.append(f"duplicate_revision_at_{position}")
                    seen.add(key)
                    prior = hashlib.sha256(line).hexdigest()
        return {"ok": not problems, "entries": count, "head": prior, "problems": problems}

    def _load(self) -> None:
        if not self._log.exists():
            return
        raw = self._log.read_bytes()
        lines = raw.splitlines()
        # Crash-tail repair: an undecodable trailing line is a torn write —
        # truncate to the last complete entry; mid-file damage fails closed.
        while lines:
            try:
                _bounded_entry(lines[-1].rstrip(b"\n"))
                break
            except (ContractError, ValueError):
                lines.pop()
        if not lines and raw.splitlines():
            raise ProcedureStoreError("catalog log is corrupt: no valid entries")
        if len(lines) < len(raw.splitlines()):
            with open(self._log, "wb") as handle:
                handle.write(b"".join(line.rstrip(b"\n") + b"\n" for line in lines))
                handle.flush()
                os.fsync(handle.fileno())
        for position, raw_line in enumerate(lines):
            line = raw_line.rstrip(b"\n")
            try:
                entry = _bounded_entry(line)
                record = ProcedureRecordV1.from_dict(entry["record"])
            except (ContractError, ValueError) as exc:
                raise ProcedureStoreError(f"catalog line {position} is corrupt") from exc
            if record.digest != entry["record_digest"]:
                raise ProcedureStoreError(f"catalog line {position} fails digest check")
            if entry["prior_record_digest"] != self._prior:
                raise ProcedureStoreError(f"catalog line {position} breaks the hash chain")
            key = (record.procedure_id, record.revision)
            if key in self._digests:
                raise ProcedureStoreError(f"catalog line {position} duplicates a revision")
            self._records.setdefault(record.procedure_id, {})[record.revision] = record
            self._digests[key] = record.digest
            self._by_digest[record.digest] = record
            if entry.get("backing_decision") is not None:
                self._backing[record.digest] = entry["backing_decision"]
            self._prior = hashlib.sha256(line).hexdigest()


def _bounded_entry(line: bytes) -> dict:
    from .contracts import loads_json
    entry = loads_json(line)
    if not isinstance(entry, dict) or not (
        {"record", "record_digest", "prior_record_digest"} <= set(entry)
        <= {"record", "record_digest", "prior_record_digest", "backing_decision"}
    ):
        raise ContractError("catalog entry has an unexpected shape")
    if not (isinstance(entry["record_digest"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["record_digest"])):
        raise ContractError("catalog entry digest is malformed")
    if entry["prior_record_digest"] is not None and not (
        isinstance(entry["prior_record_digest"], str)
        and re.fullmatch(r"[0-9a-f]{64}", entry["prior_record_digest"])
    ):
        raise ContractError("catalog chain digest is malformed")
    if entry.get("backing_decision") is not None and not (
        isinstance(entry["backing_decision"], str)
        and re.fullmatch(r"[0-9a-f]{64}", entry["backing_decision"])
    ):
        raise ContractError("catalog backing decision digest is malformed")
    return entry


@dataclass(frozen=True)
class MiningContext:
    """Trusted context the miner may use for applicability statements."""

    language: str
    toolchain: str
    frameworks: tuple[str, ...] = ()
    task_signatures: tuple[str, ...] = ()
    file_paths: tuple[str, ...] = ()
    expires_at: str | None = None


def failure_signatures(events: Sequence[ObservationEventV1]) -> tuple[str, ...]:
    """Extract deterministic failure signatures from observed events."""
    signatures_: set[str] = set()
    for event in events:
        if event.event_type not in {"tool_result", "tool_request"}:
            continue
        summary = event.payload.get("summary")
        if not isinstance(summary, Mapping):
            continue
        item_type = summary.get("item_type")
        code = summary.get("exit_code")
        if isinstance(item_type, str) and type(code) is int and code != 0:
            signatures_.add(f"{item_type}:exit_{code}")
        status = summary.get("item_status")
        if isinstance(item_type, str) and status in {"failed", "error"}:
            signatures_.add(f"{item_type}:status_{status}")
    return tuple(sorted(signatures_))


def mine_candidates(
    *,
    actor_role: str,
    episode_id: str,
    events: Sequence[ObservationEventV1],
    receipt: OutcomeReceiptV1,
    context: MiningContext,
    miner_identity: str = "sis-v3-miner",
) -> list[ProcedureRecordV1]:
    """Derive candidate procedures from one independently evaluated episode.

    The miner is deterministic and records only what the episode evidence
    supports. It requires the ``learner`` role's ``candidate:write`` action;
    the caller must supply an outcome receipt it has already verified.
    """
    require_permission(actor_role, "candidate:write")
    if not isinstance(receipt, OutcomeReceiptV1):
        raise ContractError("receipt must be an OutcomeReceiptV1")
    if not events:
        raise ContractError("cannot mine an empty episode")
    for event in events:
        if event.episode_id != episode_id:
            raise ContractError("events do not belong to the stated episode")

    failures = failure_signatures(events)
    edits = sum(1 for e in events if e.event_type == "edit")
    tool_calls = sum(1 for e in events if e.event_type in {"tool_request", "tool_result"})
    evidence = tuple(sorted({e.digest for e in events}))[:16] + (receipt.digest,)
    seed = {
        "episode_id": episode_id,
        "receipt_digest": receipt.digest,
        "language": context.language,
        "failures": list(failures),
    }
    procedure_id = "proc-" + hashlib.sha256(canonical_json(seed)).hexdigest()[:24]

    if receipt.outcome == "pass":
        intent = (
            f"Episode observed a fix for failure signatures {', '.join(failures) or 'unspecified'} "
            f"in a {context.language} project; diagnose the failing command, apply the minimal "
            "recorded edit class, then re-run the same verification."
        )
        steps = (
            "Reproduce the failure with the project's own commands before editing.",
            "Apply the smallest change consistent with the task's stated contract.",
            "Re-run the observed failing command and the project's test suite.",
        )
        required_verification = (
            "Independent evaluator re-runs the registered acceptance command on the edited tree.",
        )
        counterexamples: tuple[str, ...] = ()
        distribution = {"tasks": 1, "successes": 1, "failures": 0, "regressions": 0}
    else:
        intent = (
            f"Episode attempted a fix for failure signatures {', '.join(failures) or 'unspecified'} "
            f"in a {context.language} project and the independent evaluator recorded "
            f"'{receipt.outcome}'. Treat the observed approach as unproven for this context."
        )
        steps = (
            "Do not assume the previously observed edit resolves this context.",
            "Reproduce the failure independently before proposing any change.",
        )
        required_verification = (
            "Independent evaluator re-runs the registered acceptance command on the edited tree.",
        )
        counterexamples = (receipt.digest,)
        distribution = {"tasks": 1, "successes": 0, "failures": 1, "regressions": 0}

    preconditions: list[Mapping[str, str]] = [{"kind": "language_is", "value": context.language}]
    if context.toolchain:
        preconditions.append({"kind": "toolchain_is", "value": context.toolchain})
    for path in context.file_paths[:8]:
        preconditions.append({"kind": "file_present", "value": path})
    for signature in failures[:8]:
        preconditions.append({"kind": "failure_signature_is", "value": signature})
    contraindications: list[Mapping[str, str]] = []
    if receipt.outcome != "pass":
        for signature in failures[:8]:
            contraindications.append({"kind": "failure_signature_is", "value": signature})

    record = ProcedureRecordV1(
        schema_version=1,
        procedure_id=procedure_id,
        revision=1,
        intent=intent[:4096],
        language=context.language,
        frameworks=tuple(context.frameworks),
        task_signatures=tuple(context.task_signatures),
        failure_signatures=failures,
        preconditions=tuple(preconditions),
        contraindications=tuple(contraindications),
        steps=steps,
        required_verification=required_verification,
        counterexample_refs=counterexamples,
        evidence_refs=evidence[:32],
        outcome_distribution=distribution,
        status="candidate",
        expires_at=context.expires_at,
    )
    return [record]
