"""Governed procedure lifecycle: draft→candidate→evaluated→qualified→suspended→retired (SIS3-011).

Every transition is an append-only, hash-chained ``PromotionDecisionV1`` that
requires operator authority (role gate + operator token digest) and, for the
``evaluated → qualified`` step, at least one distinct verified outcome
receipt plus an evaluator Ed25519 signature over the decision payload. Status
changes mint a new immutable ``ProcedureRecordV1`` revision — history is never
rewritten, and the qualified head is recomputed after each decision.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import signatures
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    ProcedureRecordV1,
    PromotionDecisionV1,
    PromotionDecisionV2,
    ScopeGrantV1,
    canonical_digest,
    canonical_json,
    loads_json,
)
from .policy import require_permission
from .procedures import ProcedureStore
from .verifier import (
    EvaluationRejected,
    ExpectedProtocol,
    verify_and_resolve_receipt,
)

_SIGNATURE_DOMAIN = b"sis-v3:promotion_decision:1\0"
_SCOPE_DOMAIN = b"sis-v3:scope_grant:1\0"
_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"candidate", "retired"}),
    "candidate": frozenset({"evaluated", "retired"}),
    "evaluated": frozenset({"qualified", "suspended", "retired"}),
    "qualified": frozenset({"suspended", "retired"}),
    "suspended": frozenset({"qualified", "retired"}),
    "retired": frozenset(),
}


class PromotionRejected(RuntimeError):
    """A transition lacks authority, evidence, or a legal status edge."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class EligibilitySnapshot:
    """Committed, signature-verified servable state — the only authority.

    Constructed solely by ``PromotionController.eligibility_snapshot`` from
    a fresh replay of the decision log resolved against the record store.
    Serving code must consume this, never raw ``ProcedureRecordV1.status``.

    ``inconsistencies`` non-empty means the evidence base cannot be
    projected cleanly; every guidance surface must abstain while it is
    non-empty.
    """

    records: Mapping[str, ProcedureRecordV1]   # record_digest -> record
    statuses: Mapping[str, str]                # record_digest -> committed status
    qualified_digests: frozenset[str]
    qualified_head: str
    decision_head: str | None
    inconsistencies: tuple[str, ...]
    scopes: Mapping[str, ScopeGrantV1] = field(default_factory=dict)
    # procedure_id -> {"scope", "repo_ids": frozenset, "family_id"} — the
    # grant binding when signed, else the evidence-derived repository scope.
    scope_bindings: Mapping[str, Mapping] = field(default_factory=dict)

    @property
    def qualified(self) -> tuple[ProcedureRecordV1, ...]:
        return tuple(
            self.records[d] for d in sorted(self.qualified_digests) if d in self.records
        )


class PromotionController:
    """Append-only decision log over a ``ProcedureStore``.

    Commits are atomic across the record log and decision log through a
    durable intent journal: the signed pair is journaled before either file
    is appended, and recovery completes any intent interrupted mid-commit.
    """

    def __init__(
        self,
        store: ProcedureStore,
        log_dir: str | Path,
        *,
        operator_token_digest: str | None,
        trusted_evaluator_keys: Mapping[str, str],
        receipt_resolver: Callable[[str], OutcomeReceiptV1] | None = None,
        repo_resolver: Callable[[str], Mapping | None] | None = None,
        min_pass_receipts: int = 1,
        min_distinct_repos: int = 1,
        expected_protocol: ExpectedProtocol | None = None,
        revoked_evaluator_keys: frozenset[str] | set[str] = frozenset(),
        consumed_ledger=None,
        envelope_registry=None,
        policy_version: str = "promotion-policy-v1",
        trusted_operator_keys: Mapping[str, str] | None = None,
    ) -> None:
        if operator_token_digest is not None and not (
            isinstance(operator_token_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", operator_token_digest)
        ):
            raise ContractError("operator_token_digest must be a SHA-256 hex digest")
        if type(min_pass_receipts) is not int or min_pass_receipts < 1:
            raise ContractError("min_pass_receipts must be positive")
        if type(min_distinct_repos) is not int or min_distinct_repos < 1:
            raise ContractError("min_distinct_repos must be positive")
        if expected_protocol is not None and not isinstance(expected_protocol, ExpectedProtocol):
            raise ContractError("expected_protocol must be an ExpectedProtocol")
        self.store = store
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log = self.log_dir / "decisions.jsonl"
        self._token_digest = operator_token_digest
        self._operator_keys = dict(trusted_operator_keys or {})
        self._trusted = dict(trusted_evaluator_keys)
        self._resolve_receipt = receipt_resolver
        self._repo_resolver = repo_resolver
        self._min_receipts = min_pass_receipts
        self._min_repos = min_distinct_repos
        self._protocol = expected_protocol
        self._revoked_eval_keys = set(revoked_evaluator_keys)
        self._consumed_ledger = consumed_ledger
        self._envelope_registry = envelope_registry
        self.policy_version = policy_version
        self._journal_dir = self.log_dir / "journal"
        self._journal_dir.mkdir(parents=True, exist_ok=True)
        self._scopes_log = self.log_dir / "scopes.jsonl"
        self._prior: str | None = None
        self._grants_prior: str | None = None
        self._decisions: list[PromotionDecisionV1 | PromotionDecisionV2] = []
        self._projected: dict[str, str] = {}  # record_digest -> decided status
        self._grants: dict[str, ScopeGrantV1] = {}  # procedure_id -> grant
        self._lock = threading.Lock()
        self._recover()
        self._load()

    def transition(
        self,
        procedure_id: str,
        new_status: str,
        *,
        actor_role: str,
        actor_identity: str,
        operator_token: str | None = None,
        receipt_digests: tuple[str, ...] = (),
        outcome_envelopes: tuple = (),
        evaluator_signer: Callable[[bytes], tuple[str, str]] | None = None,
        operator_signer: Callable[[bytes], tuple[str, str]] | None = None,
        rollback_ref: str | None = None,
        expected_old_head: str | None = None,
    ) -> PromotionDecisionV2:
        """Move a procedure along a legal edge under full authority.

        The complete post-state — new record digest and expected qualified
        head — is computed *before* either signature, so both signatures bind
        the exact committed outcome. ``expected_old_head`` is an
        optimistic-concurrency guard against stale views.
        """
        require_permission(actor_role, "promotion:approve")
        with self._lock:
            record = self.store.get(procedure_id)
            current_status = self._status_of(record)
            if new_status not in _TRANSITIONS.get(current_status, frozenset()):
                raise PromotionRejected(
                    "illegal_transition", f"{current_status} -> {new_status}"
                )
            verified_receipts = self._verify_receipts(receipt_digests)
            verified_receipts += self._consume_envelopes(outcome_envelopes)
            if new_status == "qualified":
                # Qualification and requalification (suspended -> qualified)
                # both run the full evidence check — no transition exception.
                self._require_qualification_evidence(verified_receipts)
            if new_status == "evaluated" and not verified_receipts:
                raise PromotionRejected(
                    "missing_receipts", "evaluation requires verified receipts"
                )

            old_head = self.store.qualified_head_digest()
            if expected_old_head is not None and expected_old_head != old_head:
                raise PromotionRejected(
                    "stale_qualified_head",
                    f"expected {expected_old_head}, actual {old_head}",
                )
            next_revision = replace(
                record, revision=record.revision + 1, status=new_status
            )
            expected_new_head = self._simulate_head(record, next_revision)
            unsigned = {
                "schema_version": 1,
                "decision_id": "dec-" + secrets.token_hex(12),
                "candidate_digest": record.digest,
                "new_record_digest": next_revision.digest,
                "evaluation_protocol_digest": canonical_digest(
                    "evaluation_protocol", 1,
                    {"policy_version": self.policy_version,
                     "min_pass_receipts": self._min_receipts},
                ),
                "receipt_refs": list(dict.fromkeys(r.digest for r in verified_receipts)) or ["0" * 64],
                "actor_identity": actor_identity,
                "approved": True,
                "policy_version": self.policy_version,
                "prior_status": current_status,
                "new_status": new_status,
                "old_qualified_head": old_head,
                "new_qualified_head": expected_new_head,
                "rollback_ref": rollback_ref,
            }
            body = _SIGNATURE_DOMAIN + canonical_json(unsigned)
            if new_status in {"qualified", "evaluated"}:
                if evaluator_signer is None:
                    raise PromotionRejected("evaluator_signature_required")
                key_id, sig_hex = evaluator_signer(body)
                if key_id not in self._trusted or not signatures.verify(
                    bytes.fromhex(sig_hex), body,
                    bytes.fromhex(self._trusted[key_id]),
                ):
                    raise PromotionRejected("evaluator_signature_invalid")
                unsigned["evaluator_signature"] = f"{key_id}:{sig_hex}"
            else:
                unsigned["evaluator_signature"] = "not-required"
            unsigned["operator_authorization"] = self._authorize_operator(
                unsigned, operator_signer, operator_token
            )
            decision = PromotionDecisionV2.from_dict(unsigned)

            # Atomic commit: durable intent, then record, then decision.
            self._commit(next_revision, decision)
            actual_head = self.store.qualified_head_digest()
            if actual_head != expected_new_head:
                raise PromotionRejected(
                    "qualified_head_divergence",
                    f"declared {expected_new_head}, actual {actual_head}",
                )
            self._decisions.append(decision)
            self._projected.pop(decision.candidate_digest, None)
            self._projected[decision.new_record_digest] = decision.new_status
            return decision

    def grant_scope(
        self,
        procedure_id: str,
        scope: str,
        *,
        actor_role: str,
        actor_identity: str,
        operator_token: str | None = None,
        evidence_receipt_digests: tuple[str, ...] = (),
        evaluator_signer: Callable[[bytes], tuple[str, str]] | None = None,
        family_id: str | None = None,
    ) -> ScopeGrantV1:
        """Issue a signed scope grant for a currently-qualified procedure.

        Scope is a signed decision, never a mutable sidecar. ``repository``
        binds the evaluator-attested repo identities behind the supplied
        evidence receipts; ``family`` additionally names an attested family;
        ``cross_repository`` requires receipts resolving to at least two
        DISTINCT repository identities — a second tree of the same repo is
        not transfer evidence.
        """
        require_permission(actor_role, "promotion:approve")
        if scope not in ("repository", "family", "cross_repository"):
            raise ContractError("unsupported catalog scope")
        with self._lock:
            record = self.store.get(procedure_id)  # raises on unknown id
            if self._status_of(record) != "qualified":
                raise PromotionRejected(
                    "scope_requires_qualified",
                    f"{procedure_id} is not qualified",
                )
            receipts = self._verify_receipts(evidence_receipt_digests)
            repo_ids: list[str] = []
            families: set[str] = set()
            for receipt in receipts:
                if self._repo_resolver is None:
                    raise PromotionRejected(
                        "repo_identity_unbound",
                        "no repo resolver configured",
                    )
                identity = self._repo_resolver(receipt.evaluated_repo_digest)
                if not identity or not identity.get("repository_id"):
                    raise PromotionRejected(
                        "repo_identity_unresolved",
                        receipt.evaluated_repo_digest[:16],
                    )
                repo_ids.append(identity["repository_id"])
                if identity.get("family_id"):
                    families.add(identity["family_id"])
            distinct = set(repo_ids)
            if scope == "repository" and not distinct:
                raise PromotionRejected(
                    "insufficient_evidence",
                    "repository scope needs at least one resolved identity",
                )
            if scope == "family":
                if not family_id:
                    raise PromotionRejected(
                        "family_binding_required",
                        "family scope needs a family_id binding",
                    )
                if not distinct:
                    raise PromotionRejected(
                        "insufficient_evidence",
                        "family scope needs resolved repo identities",
                    )
            if scope == "cross_repository" and len(distinct) < 2:
                raise PromotionRejected(
                    "insufficient_transfer_evidence",
                    "cross-repository scope requires evidence from at least "
                    "two distinct repository identities",
                )
            unsigned = {
                "schema_version": 1,
                "grant_id": "sg-" + secrets.token_hex(12),
                "procedure_id": procedure_id,
                "scope": scope,
                "repo_identities": sorted(distinct),
                "family_id": family_id,
                "evidence_refs": list(
                    dict.fromkeys(r.digest for r in receipts)),
                "actor_identity": actor_identity,
            }
            body = _SCOPE_DOMAIN + canonical_json(unsigned)
            if scope != "repository":
                if evaluator_signer is None:
                    raise PromotionRejected("evaluator_signature_required")
                key_id, sig_hex = evaluator_signer(body)
                if key_id not in self._trusted or not signatures.verify(
                    bytes.fromhex(sig_hex), body,
                    bytes.fromhex(self._trusted[key_id]),
                ):
                    raise PromotionRejected("evaluator_signature_invalid")
                unsigned["evaluator_signature"] = f"{key_id}:{sig_hex}"
            else:
                unsigned["evaluator_signature"] = "not-required"
            unsigned["operator_authorization"] = self._authorize_operator(
                {**unsigned, "evaluator_signature":
                 unsigned["evaluator_signature"]},
                None, operator_token,
            )
            grant = ScopeGrantV1.from_dict(unsigned)
            line = canonical_json({
                "grant": grant.to_dict(),
                "grant_digest": grant.digest,
                "prior_grant_digest": self._grants_prior,
            })
            with open(self._scopes_log, "ab") as handle:
                handle.write(line + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._grants_prior = hashlib.sha256(line).hexdigest()
            self._fsync_dir(self.log_dir)
            self._grants[procedure_id] = grant
            return grant

    def _status_of(self, record: ProcedureRecordV1) -> str:
        """Decision-backed status of a record — never raw status alone.

        A record claiming a governed status without a committed decision is
        inconsistent; transitions on it fail closed.
        """
        decided = self._projected.get(record.digest)
        if decided is not None:
            return decided
        if record.status in ProcedureStore.WRITABLE_STATUSES:
            return record.status
        raise PromotionRejected(
            "uncommitted_record",
            f"{record.procedure_id}@{record.revision} carries governed status "
            "without a committed decision",
        )

    def _commit(self, record: ProcedureRecordV1, decision: PromotionDecisionV2) -> None:
        """Atomically persist record revision + signed decision.

        1. Durable intent containing both payloads (fsync file + directory).
        2. Append the record line (fsync).
        3. Append the decision line (fsync).
        4. Clear the intent (unlink + directory fsync).

        A crash anywhere leaves either nothing or a recoverable intent that
        ``_recover`` completes idempotently at next start.
        """
        intent_path = self._journal_dir / f"{decision.decision_id}.intent"
        intent = {
            "schema": 1,
            "record": record.to_dict(),
            "decision": decision.to_dict(),
            "record_entry_prior": self.store._prior,
            "decision_entry_prior": self._prior,
        }
        fd, tmp = tempfile.mkstemp(dir=self._journal_dir, prefix=".txn-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(intent) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, intent_path)
            self._fsync_dir(self._journal_dir)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self.store._commit_record(record, backing_decision=decision.digest)
        line = canonical_json({
            "decision": decision.to_dict(),
            "decision_digest": decision.digest,
            "prior_decision_digest": self._prior,
        })
        with open(self._log, "ab") as handle:
            handle.write(line + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._prior = hashlib.sha256(line).hexdigest()
        intent_path.unlink()
        self._fsync_dir(self._journal_dir)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        try:
            dir_fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)

    def _recover(self) -> None:
        """Complete any commit interrupted between the two appends.

        Runs before ``_load``. For each pending intent: append the record
        line if absent, append the decision line only when its recorded
        prior matches the current log head (single-writer invariant), then
        clear the intent. Anything else is corruption — fail closed.
        """
        if not self._journal_dir.exists():
            return
        for intent_path in sorted(self._journal_dir.glob("*.intent")):
            try:
                intent = loads_json(intent_path.read_bytes())
                record = ProcedureRecordV1.from_dict(intent["record"])
                decision = self._decode_decision(intent["decision"])
            except (ContractError, KeyError, TypeError, ValueError) as exc:
                raise PromotionRejected(
                    "intent_journal_corrupt", intent_path.name
                ) from exc
            if intent["decision_entry_prior"] != self._head_of_log():
                raise PromotionRejected(
                    "intent_journal_conflict",
                    "decision head diverged from the journaled commit",
                )
            existing = self.store._digests.get(
                (record.procedure_id, record.revision)
            )
            if existing is None:
                if intent["record_entry_prior"] != self.store._prior:
                    raise PromotionRejected(
                        "intent_journal_conflict",
                        "record head diverged from the journaled commit",
                    )
                self.store._commit_record(record, backing_decision=decision.digest)
            elif existing != record.digest:
                raise PromotionRejected(
                    "intent_journal_conflict", "record revision conflict"
                )
            if not self._decision_present(decision.digest):
                line = canonical_json({
                    "decision": decision.to_dict(),
                    "decision_digest": decision.digest,
                    "prior_decision_digest": intent["decision_entry_prior"],
                })
                with open(self._log, "ab") as handle:
                    handle.write(line + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            intent_path.unlink()
            self._fsync_dir(self._journal_dir)

    def _head_of_log(self) -> str | None:
        """Digest of the last complete decision line, or None for empty."""
        if not self._log.exists():
            return None
        lines = self._log.read_bytes().splitlines()
        if not lines:
            return None
        return hashlib.sha256(lines[-1].rstrip(b"\n")).hexdigest()

    def _decision_present(self, digest: str) -> bool:
        if not self._log.exists():
            return False
        for raw in self._log.read_bytes().splitlines():
            try:
                entry = loads_json(raw.rstrip(b"\n"))
            except ContractError:
                continue
            if entry.get("decision_digest") == digest:
                return True
        return False

    def qualified_head(self) -> str:
        return self.store.qualified_head_digest()

    def decisions(self) -> list[PromotionDecisionV1]:
        return list(self._decisions)

    def projected_statuses(self) -> dict[str, str]:
        """The decision-backed status map — the catalog's authority view."""
        return dict(self._projected)

    def _replay(self):
        """Replay the decision log: chain, signatures, transitions, heads.

        Returns ``(statuses, qualified, decided_by, problems, head, legacy)``.
        Shared by ``verify()`` and ``eligibility_snapshot()`` so both read
        identical committed state.
        """
        problems: list[str] = []
        qualified: set[str] = set()
        statuses: dict[str, str] = {}
        decided_by: dict[str, str] = {}  # record_digest -> decision digest
        legacy = 0
        prior: str | None = None
        if self._log.exists():
            with open(self._log, "rb") as handle:
                for position, raw in enumerate(handle):
                    line = raw.rstrip(b"\n")
                    try:
                        entry = loads_json(line)
                        decision = self._decode_decision(entry["decision"])
                        if decision.digest != entry["decision_digest"]:
                            problems.append(f"decision_digest_mismatch_at_{position}")
                    except (ContractError, KeyError, TypeError):
                        problems.append(f"undecodable_decision_at_{position}")
                        continue
                    if entry.get("prior_decision_digest") != prior:
                        problems.append(f"chain_conflict_at_{position}")
                    if isinstance(decision, PromotionDecisionV1):
                        legacy += 1  # legacy entries: chain/digest verified only
                    else:
                        problems.extend(
                            p + f"_at_{position}" for p in self._verify_v2(
                                decision, statuses, qualified))
                        statuses.pop(decision.candidate_digest, None)
                        statuses[decision.new_record_digest] = decision.new_status
                        decided_by.pop(decision.candidate_digest, None)
                        decided_by[decision.new_record_digest] = decision.digest
                    prior = hashlib.sha256(line).hexdigest()
        return statuses, qualified, decided_by, problems, prior, legacy

    def verify(self) -> dict:
        """Replay the log: chain, signatures, transitions, head continuity."""
        statuses, qualified, _decided_by, problems, prior, legacy = self._replay()
        count = len(self._decisions)
        if not problems:
            problems.extend(self._projection_drift(qualified, statuses))
        return {"ok": not problems, "entries": count, "legacy_v1": legacy,
                "head": prior, "problems": problems}

    def eligibility_snapshot(self) -> EligibilitySnapshot:
        """Fresh committed, verified servable state.

        Re-reads the record store and replays the decision log from disk, so
        revocations and commits by other processes take effect at read time.
        Every projected record digest must resolve to a stored record, and
        every governed record must trace to a committed decision; otherwise
        ``inconsistencies`` is non-empty and serving must abstain.
        """
        self.store.refresh()
        statuses, qualified_set, decided_by, problems, head, _legacy = self._replay()
        inconsistencies = list(problems)
        records: dict[str, ProcedureRecordV1] = {}
        for digest in statuses:
            rec = self.store.get_by_digest(digest)
            if rec is None:
                inconsistencies.append(f"orphan_decision:{digest[:16]}")
                continue
            records[digest] = rec
            backing = self.store.backing_decision(digest)
            if backing is not None and backing != decided_by.get(digest):
                inconsistencies.append(f"backing_mismatch:{digest[:16]}")
        decided_digests = set(decided_by.values())
        for backing_source in self.store.all_latest():
            backing = self.store.backing_decision(backing_source.digest)
            if backing is not None and backing not in decided_digests:
                inconsistencies.append(f"phantom_backing:{backing_source.digest[:16]}")
            if backing_source.status not in ProcedureStore.WRITABLE_STATUSES \
                    and backing_source.digest not in statuses:
                inconsistencies.append(f"uncommitted_record:{backing_source.digest[:16]}")
            # Undecided (draft/candidate) records are still resolvable —
            # benchmark ablations may inspect them, they are never servable.
            records.setdefault(backing_source.digest, backing_source)
        qualified_digests = frozenset(
            d for d in qualified_set if d in records
        )
        qualified_head = canonical_digest("qualified_catalog", 1, {
            "head": sorted(qualified_digests),
        })
        return EligibilitySnapshot(
            records=records,
            statuses=dict(statuses),
            qualified_digests=qualified_digests,
            qualified_head=qualified_head,
            decision_head=head,
            inconsistencies=tuple(sorted(set(inconsistencies))),
            scopes=dict(self._grants),
            scope_bindings=self._scope_bindings(
                records, qualified_digests),
        )

    def _scope_bindings(
        self,
        records: Mapping[str, ProcedureRecordV1],
        qualified_digests: frozenset[str],
    ) -> dict[str, dict]:
        """Effective serving scope per qualified procedure.

        A signed grant wins; otherwise the default is ``repository`` bound
        to the evaluator-attested identities behind the qualifying
        decision's receipts (empty when no attestation exists — callers
        apply the documented unbound policy).
        """
        bindings: dict[str, dict] = {}
        # digest -> latest qualifying decision (for evidence-derived scope)
        qualifying: dict[str, PromotionDecisionV2] = {}
        for decision in self._decisions:
            if isinstance(decision, PromotionDecisionV2) \
                    and decision.new_status == "qualified":
                qualifying[decision.new_record_digest] = decision
        for digest in sorted(qualified_digests):
            record = records.get(digest)
            if record is None:
                continue
            pid = record.procedure_id
            grant = self._grants.get(pid)
            if grant is not None:
                bindings[pid] = {
                    "scope": grant.scope,
                    "repo_ids": frozenset(grant.repo_identities),
                    "family_id": grant.family_id,
                    "granted": True,
                }
                continue
            repo_ids: set[str] = set()
            decision = qualifying.get(digest)
            if decision is not None and self._resolve_receipt \
                    and self._repo_resolver:
                for ref in decision.receipt_refs:
                    try:
                        receipt = self._resolve_receipt(ref)
                    except Exception:
                        continue
                    identity = self._repo_resolver(
                        receipt.evaluated_repo_digest)
                    if identity and identity.get("repository_id"):
                        repo_ids.add(identity["repository_id"])
            bindings[pid] = {
                "scope": "repository",
                "repo_ids": frozenset(repo_ids),
                "family_id": None,
                "granted": False,
            }
        return bindings

    @staticmethod
    def _decode_decision(body):
        if isinstance(body, Mapping) and "new_record_digest" in body:
            return PromotionDecisionV2.from_dict(body)
        return PromotionDecisionV1.from_dict(body)

    def _verify_v2(self, decision, statuses, qualified) -> list[str]:
        """Check one V2 decision against replayed state and signatures."""
        problems: list[str] = []
        base = decision.to_dict()
        base.pop("evaluator_signature")
        base.pop("operator_authorization")
        body = _SIGNATURE_DOMAIN + canonical_json(base)
        if decision.new_status in {"qualified", "evaluated"} and \
                decision.evaluator_signature == "not-required":
            problems.append("evaluator_signature_required")
        elif decision.evaluator_signature != "not-required":
            try:
                key_id, sig_hex = decision.evaluator_signature.split(":", 1)
                if key_id not in self._trusted or not signatures.verify(
                    bytes.fromhex(sig_hex), body, bytes.fromhex(self._trusted[key_id])
                ):
                    problems.append("evaluator_signature_invalid")
            except (ValueError, TypeError):
                problems.append("evaluator_signature_malformed")
        auth = decision.operator_authorization
        if auth.startswith("ed25519:"):
            try:
                _, key_id, sig_hex = auth.split(":", 2)
                signed = _SIGNATURE_DOMAIN + canonical_json(
                    {**base, "evaluator_signature": decision.evaluator_signature})
                if key_id not in self._operator_keys or not signatures.verify(
                    bytes.fromhex(sig_hex), signed, bytes.fromhex(self._operator_keys[key_id])
                ):
                    problems.append("operator_signature_invalid")
            except (ValueError, TypeError):
                problems.append("operator_authorization_malformed")
        elif auth != f"operator_token_sha256:{self._token_digest}":
            problems.append("operator_authorization_mismatch")
        if decision.prior_status not in _TRANSITIONS or \
                decision.new_status not in _TRANSITIONS[decision.prior_status]:
            problems.append("illegal_transition")
        if statuses.get(decision.candidate_digest, decision.prior_status) != decision.prior_status:
            problems.append("nonmonotonic_status")
        expected_old = canonical_digest(
            "qualified_catalog", 1, {"head": sorted(qualified)})
        if decision.old_qualified_head not in {expected_old, None}:
            problems.append("old_head_mismatch")
        if decision.prior_status == "qualified":
            qualified.discard(decision.candidate_digest)
        if decision.new_status == "qualified":
            qualified.add(decision.new_record_digest)
        expected_new = canonical_digest(
            "qualified_catalog", 1, {"head": sorted(qualified)})
        if decision.new_qualified_head is not None and \
                decision.new_qualified_head != expected_new:
            problems.append("new_head_mismatch")
        statuses[decision.new_record_digest] = decision.new_status
        statuses.pop(decision.candidate_digest, None)
        return problems

    def _projection_drift(self, qualified, statuses) -> list[str]:
        """Report store/catalog state the ledger cannot account for."""
        problems: list[str] = []
        projected_q = {r.digest for r in self.store.by_status("qualified")}
        if projected_q != qualified:
            problems.append("qualified_projection_drift")
        return problems

    def _authorize_operator(
        self,
        unsigned: dict,
        operator_signer: Callable[[bytes], tuple[str, str]] | None,
        operator_token: str | None,
    ) -> str:
        """Authorize via operator Ed25519 signature, else shared token digest."""
        payload = _SIGNATURE_DOMAIN + canonical_json(unsigned)
        if operator_signer is not None:
            key_id, sig_hex = operator_signer(payload)
            trusted = self._operator_keys.get(key_id)
            if trusted is None or not signatures.verify(
                bytes.fromhex(sig_hex), payload, bytes.fromhex(trusted)
            ):
                raise PromotionRejected("operator_signature_invalid")
            return f"ed25519:{key_id}:{sig_hex}"
        if operator_token is not None and self._token_digest is not None:
            if hashlib.sha256(operator_token.encode()).hexdigest() == self._token_digest:
                return "operator_token_sha256:" + self._token_digest
        raise PromotionRejected("operator_authorization_failed")

    def _verify_receipts(self, digests: tuple[str, ...]) -> list[OutcomeReceiptV1]:
        """Resolve then verify every referenced receipt; resolver is transport."""
        receipts = []
        for digest in dict.fromkeys(digests):
            if self._resolve_receipt is None:
                raise PromotionRejected("no_receipt_resolver_configured")
            try:
                receipts.append(verify_and_resolve_receipt(
                    digest,
                    self._resolve_receipt,
                    trusted_keys=self._trusted,
                    revoked_keys=self._revoked_eval_keys,
                    protocol=self._protocol,
                ))
            except EvaluationRejected as exc:
                raise PromotionRejected(exc.reason, str(exc)) from exc
        return receipts

    def _consume_envelopes(self, envelopes: tuple) -> list:
        """Verify AND durably consume outcome envelopes for this transition.

        Consumption is atomic under the ledger's inter-process lock: a
        spent (signer, nonce) can never back a second promotion — the
        replay check fires before the decision is written.
        """
        from .outcome_v2 import EnvelopeRejected
        consumed = []
        for env in envelopes:
            if self._consumed_ledger is None or self._envelope_registry is None:
                raise PromotionRejected(
                    "envelope_consumption_unconfigured",
                    "consumed_ledger and envelope_registry are required",
                )
            try:
                consumed.append(self._consumed_ledger.verify_and_consume(
                    env, self._envelope_registry,
                    revoked_keys=self._revoked_eval_keys,
                ))
            except EnvelopeRejected as exc:
                raise PromotionRejected(exc.reason, str(exc)) from exc
        return consumed

    def _simulate_head(
        self, record: ProcedureRecordV1, next_revision: ProcedureRecordV1
    ) -> str:
        """Project the qualified head as if ``next_revision`` were applied."""
        digests = {
            r.digest for r in self.store.by_status("qualified")
            if r.procedure_id != record.procedure_id
        }
        if next_revision.status == "qualified":
            digests.add(next_revision.digest)
        return canonical_digest("qualified_catalog", 1, {"head": sorted(digests)})

    def _require_qualification_evidence(self, receipts: list[OutcomeReceiptV1]) -> None:
        """Count independent evidence units — never raw outcome strings.

        Cloned receipts collapse to the same (task, repo) unit and cannot
        inflate the count. ``min_distinct_repos`` counts distinct evaluated
        *tree* digests — a proxy for repository disjointness, not proof of
        it: two different submissions to the same repository still digest
        differently. Genuine repository disjointness must be established
        through evaluator task-registration lineage, outside this gate.
        """
        pass_receipts = [r for r in receipts if r.outcome == "pass"]
        units = {(r.task_id, r.evaluated_repo_digest) for r in pass_receipts}
        repos = {r.evaluated_repo_digest for r in pass_receipts}
        if len(units) < self._min_receipts or len(repos) < self._min_repos:
            raise PromotionRejected(
                "insufficient_evidence",
                f"need {self._min_receipts} distinct pass task(s) across "
                f"{self._min_repos} repositories, have {len(units)}/{len(repos)}",
            )

    def _load(self) -> None:
        if not self._log.exists():
            self._load_scopes()
            return
        raw = self._log.read_bytes()
        lines = raw.splitlines()
        # Crash-tail repair: an undecodable trailing line is a torn write —
        # truncate to the last complete entry; mid-file damage fails closed.
        # If EVERY line is undecodable that is corruption, not a torn write —
        # never truncate the whole ledger away.
        while lines:
            try:
                loads_json(lines[-1].rstrip(b"\n"))
                break
            except ContractError:
                lines.pop()
        if not lines:
            raise PromotionRejected("decision_log_corrupt", "no valid entries")
        if len(lines) < len(raw.splitlines()):
            with open(self._log, "wb") as handle:
                handle.write(b"".join(line.rstrip(b"\n") + b"\n" for line in lines))
                handle.flush()
                os.fsync(handle.fileno())
        for position, line in enumerate(lines):
            line = line.rstrip(b"\n")
            try:
                entry = loads_json(line)
                decision = self._decode_decision(entry["decision"])
            except (ContractError, KeyError, TypeError) as exc:
                raise PromotionRejected(
                    "decision_log_corrupt", f"line {position}"
                ) from exc
            if decision.digest != entry["decision_digest"]:
                raise PromotionRejected(
                    "decision_log_corrupt", f"digest at line {position}"
                )
            if entry["prior_decision_digest"] != self._prior:
                raise PromotionRejected(
                    "decision_log_corrupt", f"chain at line {position}"
                )
            self._decisions.append(decision)
            if isinstance(decision, PromotionDecisionV2):
                self._projected.pop(decision.candidate_digest, None)
                self._projected[decision.new_record_digest] = decision.new_status
            self._prior = hashlib.sha256(line).hexdigest()
        self._load_scopes()

    def _load_scopes(self) -> None:
        """Replay the signed scope-grant log; any corruption fails closed."""
        if not self._scopes_log.exists():
            return
        for position, raw in enumerate(
                self._scopes_log.read_bytes().splitlines()):
            line = raw.rstrip(b"\n")
            try:
                entry = loads_json(line)
                grant = ScopeGrantV1.from_dict(entry["grant"])
            except (ContractError, KeyError, TypeError) as exc:
                raise PromotionRejected(
                    "scope_log_corrupt", f"line {position}") from exc
            if grant.digest != entry["grant_digest"] or \
                    entry["prior_grant_digest"] != self._grants_prior:
                raise PromotionRejected(
                    "scope_log_corrupt", f"chain at line {position}")
            problems = self._verify_grant(grant)
            if problems:
                raise PromotionRejected(
                    "scope_log_corrupt",
                    f"line {position}: {problems[0]}")
            self._grants[grant.procedure_id] = grant
            self._grants_prior = hashlib.sha256(line).hexdigest()

    def _verify_grant(self, grant: ScopeGrantV1) -> list[str]:
        problems: list[str] = []
        base = grant.to_dict()
        base.pop("evaluator_signature")
        base.pop("operator_authorization")
        body = _SCOPE_DOMAIN + canonical_json(base)
        if grant.scope != "repository":
            if grant.evaluator_signature == "not-required":
                problems.append("evaluator_signature_required")
            else:
                try:
                    key_id, sig_hex = grant.evaluator_signature.split(":", 1)
                    if key_id not in self._trusted or not signatures.verify(
                        bytes.fromhex(sig_hex), body,
                        bytes.fromhex(self._trusted[key_id]),
                    ):
                        problems.append("evaluator_signature_invalid")
                except (ValueError, TypeError):
                    problems.append("evaluator_signature_malformed")
        if grant.operator_authorization != \
                f"operator_token_sha256:{self._token_digest}":
            problems.append("operator_authorization_mismatch")
        if grant.scope == "cross_repository" and \
                len(set(grant.repo_identities)) < 2:
            problems.append("insufficient_transfer_evidence")
        return problems


def operator_token_digest(token: str) -> str:
    """Derive the configured operator token digest (never log the token)."""
    if not isinstance(token, str) or len(token) < 16:
        raise ContractError("operator token must be at least 16 characters")
    return hashlib.sha256(token.encode()).hexdigest()
