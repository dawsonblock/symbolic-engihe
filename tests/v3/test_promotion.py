"""SIS3-011: governed lifecycle, signed decisions, rollback."""
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import TaskEnvelopeV1
from sis.v3.policy import AuthorizationDenied
from sis.v3.procedures import ProcedureStore
from sis.v3.promotion import PromotionController, PromotionRejected, operator_token_digest
from sis.v3.rollback import checkpoint, restore
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier

from tests.v3.test_retrieval import _proc

TOKEN = "operator-token-0123456789"


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ProcedureStore(self.root / "catalog")
        self.seed, self.public = signatures.generate_keypair()
        self.key_id = "key-" + __import__("hashlib").sha256(self.public).hexdigest()[:24]
        self.controller = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()},
            receipt_resolver=self._resolve,
        )
        self._receipts = {}
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"print('ok')\n"},
        )
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "x.py").write_text("x = 1\n")

    def _resolve(self, digest):
        return self.verifier.load_receipt(digest)

    def _signer(self, payload: bytes):
        return self.key_id, signatures.sign(self.seed, payload).hex()

    def _receipt(self):
        task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )
        import secrets
        receipt = self.verifier.evaluate(
            actor_role="evaluator", task=task, submission_dir=self.repo,
            evaluation_nonce="n-" + secrets.token_hex(6),
        )
        self._receipts[receipt.digest] = receipt
        return receipt

    def _kw(self, **over):
        base = dict(actor_role="operator", actor_identity="op-1",
                    operator_token=TOKEN, evaluator_signer=self._signer)
        base.update(over)
        return base

    def test_full_lifecycle(self):
        self.store.add(_proc(status="draft"))
        receipt = self._receipt()
        self.controller.transition("p1", "candidate", **self._kw(evaluator_signer=None))
        self.controller.transition("p1", "evaluated",
                                   **self._kw(receipt_digests=(receipt.digest,)))
        decision = self.controller.transition(
            "p1", "qualified", **self._kw(receipt_digests=(receipt.digest,)))
        self.assertEqual(decision.new_status, "qualified")
        self.assertEqual(self.store.get("p1").status, "qualified")
        self.assertTrue(self.controller.verify()["ok"])

    def test_illegal_transition(self):
        self.store.add(_proc(status="draft"))
        with self.assertRaisesRegex(PromotionRejected, "illegal_transition"):
            self.controller.transition("p1", "qualified", **self._kw())

    def test_agent_role_denied(self):
        self.store.add(_proc(status="draft"))
        with self.assertRaises(AuthorizationDenied):
            self.controller.transition("p1", "candidate", **self._kw(actor_role="agent"))

    def test_wrong_token_denied(self):
        self.store.add(_proc(status="draft"))
        with self.assertRaisesRegex(PromotionRejected, "operator_authorization_failed"):
            self.controller.transition("p1", "candidate",
                                       **self._kw(operator_token="wrong-token-0000"))

    def test_qualified_requires_verified_receipts_and_signature(self):
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "insufficient_evidence"):
            self.controller.transition("p1", "qualified",
                                       **self._kw(receipt_digests=()))
        receipt = self._receipt()
        with self.assertRaisesRegex(PromotionRejected, "evaluator_signature_required"):
            self.controller.transition("p1", "qualified",
                                       **self._kw(receipt_digests=(receipt.digest,),
                                                  evaluator_signer=None))
        bad_seed, _ = signatures.generate_keypair()
        bad_signer = lambda payload: (self.key_id, signatures.sign(bad_seed, payload).hex())
        with self.assertRaisesRegex(PromotionRejected, "evaluator_signature_invalid"):
            self.controller.transition("p1", "qualified",
                                       **self._kw(receipt_digests=(receipt.digest,),
                                                  evaluator_signer=bad_signer))

    def test_evaluated_requires_receipts(self):
        self.store.add(_proc(status="candidate"))
        with self.assertRaisesRegex(PromotionRejected, "missing_receipts"):
            self.controller.transition("p1", "evaluated", **self._kw())

    def test_decision_log_survives_restart_and_detects_tamper(self):
        self.store.add(_proc(status="draft"))
        self.controller.transition("p1", "candidate", **self._kw(evaluator_signer=None))
        fresh = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()},
        )
        self.assertEqual(len(fresh.decisions()), 1)
        log = self.root / "decisions" / "decisions.jsonl"
        log.write_bytes(log.read_bytes().replace(b'"candidate"', b'"retired"', 1))
        with self.assertRaisesRegex(PromotionRejected, "decision_log_corrupt"):
            PromotionController(
                self.store, self.root / "decisions",
                operator_token_digest=operator_token_digest(TOKEN),
                trusted_evaluator_keys={self.key_id: self.public.hex()},
            )

    def test_checkpoint_restore(self):
        self.store.add(_proc(status="draft"))
        receipt = self._receipt()
        self.controller.transition("p1", "candidate", **self._kw(evaluator_signer=None))
        self.controller.transition("p1", "evaluated",
                                   **self._kw(receipt_digests=(receipt.digest,)))
        before = checkpoint(self.controller)
        self.controller.transition("p1", "qualified",
                                   **self._kw(receipt_digests=(receipt.digest,)))
        self.assertNotEqual(self.controller.qualified_head(), before.qualified_head)
        restore(self.controller, before, actor_role="operator",
                actor_identity="op-1", operator_token=TOKEN)
        self.assertFalse(self.store.by_status("qualified"))


if __name__ == "__main__":
    unittest.main()
