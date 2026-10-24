"""Test support: mint governed procedure state through the REAL authority.

Fixtures never fake ``record.status`` — every governed state is produced by
actual signed promotion decisions over signed receipts, exactly as
production code requires. ``FixtureAuthority`` wraps a ProcedureStore, a
PromotionController, a test evaluator keypair and a receipt resolver.
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sis.v3 import signatures
from sis.v3.contracts import OutcomeReceiptV1
from sis.v3.procedures import ProcedureStore
from sis.v3.promotion import PromotionController, operator_token_digest

_TOKEN = "fixture-operator-token-0000"


class FixtureAuthority:
    """A fully wired promotion authority for tests."""

    token = _TOKEN

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or tempfile.mkdtemp(prefix="sis-v3-auth-"))
        self.store = ProcedureStore(self.root / "catalog")
        self.eval_seed, self.eval_public = signatures.generate_keypair()
        self.eval_key_id = (
            "key-" + hashlib.sha256(self.eval_public).hexdigest()[:24]
        )
        self._receipts: dict[str, OutcomeReceiptV1] = {}
        self.controller = PromotionController(
            self.store,
            self.root / "decisions",
            operator_token_digest=operator_token_digest(_TOKEN),
            trusted_evaluator_keys={self.eval_key_id: self.eval_public.hex()},
            receipt_resolver=self._resolve,
        )

    def _resolve(self, digest: str):
        return self._receipts[digest]

    def _eval_signer(self, payload: bytes):
        return self.eval_key_id, signatures.sign(self.eval_seed, payload).hex()

    def issue_receipt(
        self,
        *,
        task_id: str = "t1",
        outcome: str = "pass",
        repo_digest: str = "ab" * 32,
        criterion_version: str = "v1",
    ) -> OutcomeReceiptV1:
        """Sign a receipt with the test evaluator key; register for resolve."""
        import secrets as _s
        unsigned = {
            "schema_version": 1,
            "receipt_id": "rcpt-" + _s.token_hex(12),
            "evaluator_identity": "fixture-evaluator",
            "task_id": task_id,
            "evaluated_repo_digest": repo_digest,
            "test_suite_commitment": hashlib.sha256(
                f"{task_id}:{criterion_version}".encode()
            ).hexdigest(),
            "criterion_version": criterion_version,
            "outcome": outcome,
            "regression_evidence": [],
            "signer_key_id": self.eval_key_id,
        }
        body = b"sis-v3:outcome_receipt:1\x00" + __import__(
            "sis.v3.contracts", fromlist=["canonical_json"]
        ).canonical_json(unsigned)
        unsigned["signature"] = signatures.sign(self.eval_seed, body).hex()
        receipt = OutcomeReceiptV1.from_dict(unsigned)
        self._receipts[receipt.digest] = receipt
        return receipt

    def _transition(self, pid: str, status: str, receipts=()):
        return self.controller.transition(
            pid,
            status,
            actor_role="operator",
            actor_identity="fixture-op",
            operator_token=_TOKEN,
            receipt_digests=tuple(r.digest for r in receipts),
            evaluator_signer=self._eval_signer if status in {"evaluated", "qualified"} else None,
        )

    def qualify(self, record, *, receipts=None):
        """Drive draft->candidate->evaluated->qualified via real decisions."""
        receipts = receipts if receipts is not None else (self.issue_receipt(),)
        pid = record.procedure_id
        self.store.add(record) if record.status in {"draft", "candidate"} else None
        if record.status == "draft":
            self._transition(pid, "candidate")
        self._transition(pid, "evaluated", receipts=receipts)
        return self._transition(pid, "qualified", receipts=receipts)

    def snapshot(self):
        return self.controller.eligibility_snapshot()
