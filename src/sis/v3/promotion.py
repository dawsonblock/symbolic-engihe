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
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

from . import signatures
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    ProcedureRecordV1,
    PromotionDecisionV1,
    canonical_digest,
    canonical_json,
    loads_json,
)
from .policy import require_permission
from .procedures import ProcedureStore, ProcedureStoreError

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
        operator_token_digest: str,
        trusted_evaluator_keys: Mapping[str, str],
        receipt_resolver: Callable[[str], OutcomeReceiptV1] | None = None,
        min_pass_receipts: int = 1,
        policy_version: str = "promotion-policy-v1",
    ) -> None:
        if not isinstance(operator_token_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", operator_token_digest
        ):
            raise ContractError("operator_token_digest must be a SHA-256 hex digest")
        if type(min_pass_receipts) is not int or min_pass_receipts < 1:
            raise ContractError("min_pass_receipts must be positive")
        self.store = store
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log = self.log_dir / "decisions.jsonl"
        self._token_digest = operator_token_digest
        self._trusted = dict(trusted_evaluator_keys)
        self._resolve_receipt = receipt_resolver
        self._min_receipts = min_pass_receipts
        self.policy_version = policy_version
        self._prior: str | None = None
        self._decisions: list[PromotionDecisionV1] = []
        self._lock = threading.Lock()
        self._load()

    def transition(
        self,
        procedure_id: str,
        new_status: str,
        *,
        actor_role: str,
        actor_identity: str,
        operator_token: str,
        receipt_digests: tuple[str, ...] = (),
        evaluator_signer: Callable[[bytes], tuple[str, str]] | None = None,
        rollback_ref: str | None = None,
    ) -> PromotionDecisionV1:
        """Move a procedure along a legal edge under full authority."""
        require_permission(actor_role, "promotion:approve")
        if hashlib.sha256(operator_token.encode()).hexdigest() != self._token_digest:
            raise PromotionRejected("operator_authorization_failed")
        with self._lock:
            record = self.store.get(procedure_id)
            if new_status not in _TRANSITIONS.get(record.status, frozenset()):
                raise PromotionRejected(
                    "illegal_transition", f"{record.status} -> {new_status}"
                )
            verified_receipts = self._verify_receipts(receipt_digests)
            if new_status == "qualified" and record.status == "evaluated":
                self._require_qualification_evidence(verified_receipts)
            if new_status == "evaluated" and not verified_receipts:
                raise PromotionRejected(
                    "missing_receipts", "evaluation requires verified receipts"
                )

            old_head = self.store.qualified_head_digest()
            unsigned = {
                "schema_version": 1,
                "decision_id": "dec-" + secrets.token_hex(12),
                "candidate_digest": record.digest,
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
                "rollback_ref": rollback_ref,
            }
            if new_status in {"qualified", "evaluated"}:
                if evaluator_signer is None:
                    raise PromotionRejected("evaluator_signature_required")
                key_id, sig_hex = evaluator_signer(
                    _SIGNATURE_DOMAIN + canonical_json(unsigned)
                )
                if key_id not in self._trusted or not signatures.verify(
                    bytes.fromhex(sig_hex),
                    _SIGNATURE_DOMAIN + canonical_json(unsigned),
                    bytes.fromhex(self._trusted[key_id]),
                ):
                    raise PromotionRejected("evaluator_signature_invalid")
                unsigned["evaluator_signature"] = f"{key_id}:{sig_hex}"
            else:
                unsigned["evaluator_signature"] = "not-required"
            unsigned["operator_authorization"] = (
                "operator_token_sha256:" + self._token_digest
            )
            unsigned["new_qualified_head"] = None  # filled after record update

            next_revision = replace(
                record, revision=record.revision + 1, status=new_status
            )
            self.store.add(next_revision)
            unsigned["new_qualified_head"] = self.store.qualified_head_digest()
            decision = PromotionDecisionV1.from_dict(unsigned)
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
            return decision

    def qualified_head(self) -> str:
        return self.store.qualified_head_digest()

    def decisions(self) -> list[PromotionDecisionV1]:
        return list(self._decisions)

    def verify(self) -> dict:
        """Replay the decision log and check the hash chain."""
        problems: list[str] = []
        prior: str | None = None
        count = 0
        if self._log.exists():
            with open(self._log, "rb") as handle:
                for position, raw in enumerate(handle):
                    count += 1
                    line = raw.rstrip(b"\n")
                    try:
                        entry = loads_json(line)
                        decision = PromotionDecisionV1.from_dict(entry["decision"])
                        if decision.digest != entry["decision_digest"]:
                            problems.append(f"decision_digest_mismatch_at_{position}")
                    except (ContractError, KeyError, TypeError):
                        problems.append(f"undecodable_decision_at_{position}")
                        continue
                    if entry.get("prior_decision_digest") != prior:
                        problems.append(f"chain_conflict_at_{position}")
                    prior = hashlib.sha256(line).hexdigest()
        return {"ok": not problems, "entries": count, "head": prior, "problems": problems}

    def _verify_receipts(self, digests: tuple[str, ...]) -> list[OutcomeReceiptV1]:
        receipts = []
        for digest in dict.fromkeys(digests):
            if self._resolve_receipt is None:
                raise PromotionRejected("no_receipt_resolver_configured")
            try:
                receipt = self._resolve_receipt(digest)
            except (ProcedureStoreError, RuntimeError, ContractError) as exc:
                raise PromotionRejected("receipt_unresolvable", digest) from exc
            receipts.append(receipt)
        return receipts

    def _require_qualification_evidence(self, receipts: list[OutcomeReceiptV1]) -> None:
        passes = {
            (r.task_id, r.evaluated_repo_digest) for r in receipts if r.outcome == "pass"
        }
        if len(passes) < self._min_receipts:
            raise PromotionRejected(
                "insufficient_evidence",
                f"need {self._min_receipts} distinct pass receipt(s), have {len(passes)}",
            )

    def _load(self) -> None:
        if not self._log.exists():
            return
        with open(self._log, "rb") as handle:
            for position, raw in enumerate(handle):
                line = raw.rstrip(b"\n")
                try:
                    entry = loads_json(line)
                    decision = PromotionDecisionV1.from_dict(entry["decision"])
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
                self._prior = hashlib.sha256(line).hexdigest()


def operator_token_digest(token: str) -> str:
    """Derive the configured operator token digest (never log the token)."""
    if not isinstance(token, str) or len(token) < 16:
        raise ContractError("operator token must be at least 16 characters")
    return hashlib.sha256(token.encode()).hexdigest()
