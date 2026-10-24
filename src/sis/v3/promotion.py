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
import threading
from contextlib import contextmanager
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

try:
    import fcntl  # POSIX advisory process-wide writer lock
except ImportError:  # pragma: no cover - Windows requires a single-writer service
    fcntl = None

from . import signatures
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    ProcedureRecordV1,
    PromotionDecisionV1,
    PromotionDecisionV2,
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


class PromotionController:
    """Append-only decision log over a ``ProcedureStore``."""

    def __init__(
        self,
        store: ProcedureStore,
        log_dir: str | Path,
        *,
        operator_token_digest: str | None,
        trusted_evaluator_keys: Mapping[str, str],
        receipt_resolver: Callable[[str], OutcomeReceiptV1] | None = None,
        min_pass_receipts: int = 1,
        min_distinct_repos: int = 1,
        expected_protocol: ExpectedProtocol | None = None,
        revoked_evaluator_keys: frozenset[str] | set[str] = frozenset(),
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
        self._min_receipts = min_pass_receipts
        self._min_repos = min_distinct_repos
        self._protocol = expected_protocol
        self._revoked_eval_keys = set(revoked_evaluator_keys)
        self.policy_version = policy_version
        self._prior: str | None = None
        self._decisions: list[PromotionDecisionV1 | PromotionDecisionV2] = []
        self._projected: dict[str, str] = {}  # record_digest -> decided status
        self._lock = threading.Lock()
        self._writer_path = self.log_dir / "promotion.writer.lock"
        with self._exclusive_writer():
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
        with self._lock, self._exclusive_writer():
            self._check_fresh_authority()
            record = self.store.get(procedure_id)
            if new_status not in _TRANSITIONS.get(record.status, frozenset()):
                raise PromotionRejected(
                    "illegal_transition", f"{record.status} -> {new_status}"
                )
            verified_receipts = self._verify_receipts(receipt_digests)
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
                "prior_status": record.status,
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

            # WRITE-AHEAD AUTHORITY: durably commit the fully signed decision
            # before materializing its record. If the process crashes in the
            # gap, guidance fails closed on drift and a fresh controller can
            # replay the signed, digest-bound record deterministically.
            decision = PromotionDecisionV2.from_dict(unsigned)
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
            self._decisions.append(decision)
            self._projected.pop(decision.candidate_digest, None)
            self._projected[decision.new_record_digest] = decision.new_status
            self.store.add(next_revision, allow_qualified=True)
            actual_head = self.store.qualified_head_digest()
            if actual_head != expected_new_head:
                raise PromotionRejected(
                    "qualified_head_divergence",
                    f"declared {expected_new_head}, actual {actual_head}",
                )
            return decision

    @contextmanager
    def _exclusive_writer(self):
        """Prevent two POSIX writers/recovery workers from interleaving fsyncs.

        This is advisory, not a security boundary against hostile local
        processes. Windows deployments require an external single-writer
        authority service or equivalent OS lock.
        """
        if fcntl is None:
            yield
            return
        fd = os.open(self._writer_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _check_fresh_authority(self) -> None:
        """Prevent writes from a stale in-memory controller or damaged state.

        This is an optimistic guard; exclusive multi-process writers must
        additionally use an OS-level lock or a single-writer service.
        """
        if self._log.exists():
            raw = self._log.read_bytes()
            if not raw.endswith(b"\n"):
                raise PromotionRejected("incomplete_decision_tail")
            last = raw.splitlines()[-1] if raw else None
            disk_head = hashlib.sha256(last).hexdigest() if last else None
        else:
            disk_head = None
        if disk_head != self._prior or self.store.verify()["head"] != self.store._prior:
            raise PromotionRejected("stale_controller")
        result = self.verify()
        if not result["ok"]:
            raise PromotionRejected("authority_state_invalid", ",".join(result["problems"][:5]))

    def qualified_head(self) -> str:
        return self.store.qualified_head_digest()

    def decisions(self) -> list[PromotionDecisionV1]:
        return list(self._decisions)

    def projected_statuses(self) -> dict[str, str]:
        """The decision-backed status map — the catalog's authority view."""
        return dict(self._projected)

    def verify(self, *, check_projection: bool = True) -> dict:
        """Replay journal: signatures, authorization, head continuity and store state."""
        problems: list[str] = []
        qualified: set[str] = set()
        statuses: dict[str, str] = {}
        legacy = 0
        prior: str | None = None
        count = 0
        if self._log.exists():
            with open(self._log, "rb") as handle:
                for position, raw in enumerate(handle):
                    count += 1
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
                    prior = hashlib.sha256(line).hexdigest()
        if not problems and check_projection:
            problems.extend(self._projection_drift(qualified, statuses))
        return {"ok": not problems, "entries": count, "legacy_v1": legacy,
                "head": prior, "problems": problems}

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
        # Every committed decision must have materialized its new record.
        # This is necessary even for non-qualified transitions; otherwise a
        # crash between the journal and catalog fsyncs can go undetected.
        latest = {r.digest: r.status for r in self.store.all_latest()}
        for digest, status in statuses.items():
            if latest.get(digest) != status:
                problems.append("decision_materialization_drift")
                break
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
            return
        raw = self._log.read_bytes()
        lines = raw.splitlines()
        # Crash-tail repair applies ONLY to a non-newline-terminated write.
        # A malformed newline-terminated final record is tampering/corruption,
        # not an interrupted write and must fail closed.
        # If EVERY line is undecodable that is corruption, not a torn write —
        # never truncate the whole ledger away.
        if raw.endswith(b"\n"):
            try:
                loads_json(lines[-1].rstrip(b"\n"))
            except ContractError as exc:
                raise PromotionRejected("decision_log_corrupt", "terminated invalid record") from exc
        else:
            try:
                loads_json(lines[-1].rstrip(b"\n"))
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
        # Never replay an unauthenticated or structurally corrupt decision.
        # Projection drift is expected after a crash between the two fsyncs.
        preflight = self.verify(check_projection=False)
        if not preflight["ok"]:
            raise PromotionRejected("decision_log_corrupt", ",".join(preflight["problems"][:8]))
        self._recover_materialization()
        after = self.verify()
        if not after["ok"]:
            raise PromotionRejected("authority_recovery_failed", ",".join(after["problems"][:8]))

    def _recover_materialization(self) -> None:
        """Redo signed write-ahead transitions missing from the store.

        A decision can only construct a record by replacing status/revision
        on its exact digest-bound predecessor. Invalid or ambiguous history
        is never automatically repaired.
        """
        from .procedures import ProcedureConflict, ProcedureStoreError
        for decision in self._decisions:
            if not isinstance(decision, PromotionDecisionV2):
                continue
            prior_record = next((r for versions in self.store._records.values()
                                 for r in versions.values()
                                 if r.digest == decision.candidate_digest), None)
            new_record = next((r for versions in self.store._records.values()
                               for r in versions.values()
                               if r.digest == decision.new_record_digest), None)
            if new_record is not None:
                if (prior_record is None or new_record.procedure_id != prior_record.procedure_id
                        or new_record.revision != prior_record.revision + 1
                        or new_record.status != decision.new_status):
                    raise PromotionRejected("recovery_record_mismatch")
                continue
            if prior_record is None:
                raise PromotionRejected("recovery_predecessor_missing")
            expected = replace(prior_record, revision=prior_record.revision + 1,
                               status=decision.new_status)
            if expected.digest != decision.new_record_digest:
                raise PromotionRejected("recovery_digest_mismatch")
            try:
                latest = self.store.get(prior_record.procedure_id)
                if latest.digest != prior_record.digest:
                    raise PromotionRejected("recovery_conflicting_revision")
                self.store.add(expected, allow_qualified=True)
            except (ProcedureConflict, ProcedureStoreError) as exc:
                raise PromotionRejected("authority_recovery_failed", str(exc)) from exc


def operator_token_digest(token: str) -> str:
    """Derive the configured operator token digest (never log the token)."""
    if not isinstance(token, str) or len(token) < 16:
        raise ContractError("operator token must be at least 16 characters")
    return hashlib.sha256(token.encode()).hexdigest()
