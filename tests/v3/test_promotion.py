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
        self._receipts = {}
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.controller = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={
                self.key_id: self.public.hex(),
                self.verifier.keystore.key_id: self.verifier.keystore.public.hex(),
            },
            receipt_resolver=self._resolve,
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

    def test_operator_signature_authorizes_without_token(self):
        import hashlib
        op_seed, op_public = signatures.generate_keypair()
        op_key_id = "key-" + hashlib.sha256(op_public).hexdigest()[:24]
        controller = PromotionController(
            self.store, self.root / "decisions-signed",
            operator_token_digest=None,
            trusted_evaluator_keys={self.key_id: self.public.hex()},
            trusted_operator_keys={op_key_id: op_public.hex()},
        )
        self.store.add(_proc(status="draft"))
        op_signer = lambda payload: (op_key_id, signatures.sign(op_seed, payload).hex())
        decision = controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_signer=op_signer,
        )
        self.assertTrue(decision.operator_authorization.startswith(f"ed25519:{op_key_id}:"))

    def test_wrong_operator_key_denied(self):
        import hashlib
        op_seed, op_public = signatures.generate_keypair()
        op_key_id = "key-" + hashlib.sha256(op_public).hexdigest()[:24]
        bad_seed, _ = signatures.generate_keypair()
        controller = PromotionController(
            self.store, self.root / "decisions-signed2",
            operator_token_digest=None,
            trusted_evaluator_keys={self.key_id: self.public.hex()},
            trusted_operator_keys={op_key_id: op_public.hex()},
        )
        self.store.add(_proc(status="draft"))
        bad_signer = lambda payload: (op_key_id, signatures.sign(bad_seed, payload).hex())
        with self.assertRaisesRegex(PromotionRejected, "operator_signature_invalid"):
            controller.transition(
                "p1", "candidate", actor_role="operator", actor_identity="op-1",
                operator_signer=bad_signer,
            )
        with self.assertRaisesRegex(PromotionRejected, "operator_authorization_failed"):
            controller.transition(
                "p1", "candidate", actor_role="operator", actor_identity="op-1",
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


class ReceiptAuthorityTests(unittest.TestCase):
    """SIS-311: resolver output is transport, never authority."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ProcedureStore(self.root / "catalog")
        self.seed, self.public = signatures.generate_keypair()
        import hashlib
        self.key_id = "key-" + hashlib.sha256(self.public).hexdigest()[:24]
        self._receipts = {}
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "x.py").write_text("x = 1\n")
        self.controller = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={
                self.key_id: self.public.hex(),
                self.verifier.keystore.key_id: self.verifier.keystore.public.hex(),
            },
            receipt_resolver=self._resolve,
        )

    def _resolve(self, digest):
        return self._receipts.get(digest) or self.verifier.load_receipt(digest)

    def _signer(self, payload: bytes):
        return self.key_id, signatures.sign(self.seed, payload).hex()

    def _eval_signer(self, payload: bytes):
        seed, _ = self.verifier.keystore.load_or_create()
        return self.verifier.keystore.key_id, signatures.sign(seed, payload).hex()

    def _receipt(self, *, argv=("acc.py",), files=None, task_id="t1"):
        import secrets as _s
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id, criterion_version="v1",
            argv=(sys.executable, *argv),
            files=files or {"acc.py": b"print('ok')\n"},
        )
        task = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref=task_id,
        )
        receipt = self.verifier.evaluate(
            actor_role="evaluator", task=task, submission_dir=self.repo,
            evaluation_nonce="n-" + _s.token_hex(6),
        )
        self._receipts[receipt.digest] = receipt
        return receipt

    def _to_evaluated(self):
        self.store.add(_proc(status="draft"))
        receipt = self._receipt()
        self.controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        self.controller.transition(
            "p1", "evaluated", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN, receipt_digests=(receipt.digest,),
            evaluator_signer=self._eval_signer)
        return receipt

    def test_tampered_fail_to_pass_receipt_rejected_head_unchanged(self):
        receipt = self._receipt(files={"acc.py": b"import sys; sys.exit(1)\n"})
        self.assertEqual(receipt.outcome, "fail")
        forged = dict(receipt.to_dict())
        forged["outcome"] = "pass"
        self._receipts[receipt.digest] = forged  # resolver serves the forgery
        head = self.controller.qualified_head()
        self.store.add(_proc(status="evaluated"))
        with self.assertRaises(PromotionRejected):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(receipt.digest,),
                evaluator_signer=self._eval_signer)
        self.assertEqual(self.controller.qualified_head(), head)
        self.assertNotEqual(self.store.get("p1").status, "qualified")

    def test_substituted_receipt_rejected(self):
        real = self._receipt()
        other = self._receipt(task_id="t2")  # different task, valid signature
        self._receipts[real.digest] = other  # resolver substitutes Y for X
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "receipt_digest_mismatch"):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(real.digest,),
                evaluator_signer=self._eval_signer)
        self.assertNotEqual(self.store.get("p1").status, "qualified")

    def test_forged_signature_rejected(self):
        receipt = self._receipt()
        forged = dict(receipt.to_dict())
        forged["signature"] = "0" * 128
        from sis.v3.contracts import OutcomeReceiptV1
        forged_rec = OutcomeReceiptV1.from_dict(forged)
        self._receipts[forged_rec.digest] = forged_rec  # attacker-presented digest
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "receipt_signature_invalid"):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(forged_rec.digest,),
                evaluator_signer=self._eval_signer)

    def test_untrusted_and_revoked_signer_rejected(self):
        foreign_seed, foreign_pub = signatures.generate_keypair()
        foreign_keys = {
            self.key_id: self.public.hex(),
            self.verifier.keystore.key_id: self.verifier.keystore.public.hex(),
        }
        controller = PromotionController(
            self.store, self.root / "d2",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()},  # verifier key absent
            receipt_resolver=self._resolve,
        )
        receipt = self._receipt()
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "untrusted_signer"):
            controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(receipt.digest,),
                evaluator_signer=self._eval_signer)
        controller2 = PromotionController(
            self.store, self.root / "d3",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys=foreign_keys,
            revoked_evaluator_keys={self.verifier.keystore.key_id},
            receipt_resolver=self._resolve,
        )
        with self.assertRaisesRegex(PromotionRejected, "signer_revoked"):
            controller2.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(receipt.digest,),
                evaluator_signer=self._eval_signer)

    def test_protocol_binding_mismatch_rejected(self):
        from sis.v3.verifier import ExpectedProtocol
        controller = PromotionController(
            self.store, self.root / "d4",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={
                self.key_id: self.public.hex(),
                self.verifier.keystore.key_id: self.verifier.keystore.public.hex(),
            },
            expected_protocol=ExpectedProtocol(criterion_version="v9"),
            receipt_resolver=self._resolve,
        )
        receipt = self._receipt()
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "protocol_binding_mismatch"):
            controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(receipt.digest,),
                evaluator_signer=self._eval_signer)

    def test_requalification_requires_fresh_evidence(self):
        receipt = self._to_evaluated()
        self.controller.transition(
            "p1", "qualified", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN, receipt_digests=(receipt.digest,),
            evaluator_signer=self._eval_signer)
        self.controller.transition(
            "p1", "suspended", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        with self.assertRaisesRegex(PromotionRejected, "insufficient_evidence"):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN,
                evaluator_signer=self._eval_signer)  # no receipts
        with self.assertRaises(PromotionRejected):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(receipt.digest,))
        self.assertEqual(self.store.get("p1").status, "suspended")

    def test_distinct_repo_policy(self):
        controller = PromotionController(
            self.store, self.root / "d5",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={
                self.key_id: self.public.hex(),
                self.verifier.keystore.key_id: self.verifier.keystore.public.hex(),
            },
            min_pass_receipts=1, min_distinct_repos=2,
            receipt_resolver=self._resolve,
        )
        receipt = self._receipt()
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "insufficient_evidence"):
            controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=(receipt.digest,),
                evaluator_signer=self._eval_signer)

    def test_malformed_and_unresolvable_receipts_rejected(self):
        self._receipts["e" * 64] = {"not": "a receipt"}
        self.store.add(_proc(status="evaluated"))
        with self.assertRaisesRegex(PromotionRejected, "receipt_malformed"):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=("e" * 64,),
                evaluator_signer=self._eval_signer)
        with self.assertRaisesRegex(PromotionRejected, "receipt_unresolvable"):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=("d" * 64,),
                evaluator_signer=self._eval_signer)
        with self.assertRaisesRegex(PromotionRejected, "receipt_digest_invalid"):
            self.controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, receipt_digests=("not-hex",),
                evaluator_signer=self._eval_signer)


class LedgerProjectionTests(unittest.TestCase):
    """SIS-312: transactional ledger + replayable catalog projection."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ProcedureStore(self.root / "catalog")
        self.seed, self.public = signatures.generate_keypair()
        import hashlib
        self.key_id = "key-" + hashlib.sha256(self.public).hexdigest()[:24]
        self.controller = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()},
        )

    def test_direct_qualified_write_rejected(self):
        from sis.v3.procedures import ProcedureConflict
        with self.assertRaisesRegex(ProcedureConflict, "qualified_write_requires_decision"):
            self.store.add(_proc(status="qualified"))
        digest = self.store.add(_proc(status="draft"))
        self.assertEqual(len(digest), 64)

    def test_v2_decision_binds_post_state_and_replays(self):
        self.store.add(_proc(status="draft"))
        d1 = self.controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        self.assertIn("new_record_digest", d1.to_dict())
        self.assertIsNotNone(d1.new_qualified_head)
        fresh = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()},
        )
        report = fresh.verify()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(fresh.projected_statuses()[d1.new_record_digest], "candidate")

    def test_stale_head_optimistic_concurrency(self):
        self.store.add(_proc(status="draft"))
        with self.assertRaisesRegex(PromotionRejected, "stale_qualified_head"):
            self.controller.transition(
                "p1", "candidate", actor_role="operator", actor_identity="op-1",
                operator_token=TOKEN, expected_old_head="f" * 64)

    def test_forged_and_tampered_log_rejected_on_restart(self):
        self.store.add(_proc(status="draft"))
        self.controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        log = self.root / "decisions" / "decisions.jsonl"
        log.write_bytes(log.read_bytes().replace(b'"candidate"', b'"retired"', 1))
        with self.assertRaisesRegex(PromotionRejected, "decision_log_corrupt"):
            PromotionController(
                self.store, self.root / "decisions",
                operator_token_digest=operator_token_digest(TOKEN),
                trusted_evaluator_keys={self.key_id: self.public.hex()})

    def test_crash_tail_truncation_recovers(self):
        self.store.add(_proc(status="draft"))
        self.controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        log = self.root / "decisions" / "decisions.jsonl"
        with open(log, "ab") as handle:
            handle.write(b'{"schema_version":1,"decision":{"partial')
        fresh = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()},
        )
        self.assertTrue(fresh.verify()["ok"])
        self.assertEqual(len(fresh.decisions()), 1)

    def test_signature_tampering_detected_on_verify(self):
        self.store.add(_proc(status="draft"))
        self.controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        decision = self.controller.decisions()[0]
        entry = {
            "decision": {**decision.to_dict(),
                         "new_status": "qualified",
                         "new_record_digest": decision.new_record_digest[:-2] + "aa"},
            "decision_digest": "0" * 64,
            "prior_decision_digest": self.controller._prior,
        }
        import json
        with open(self.root / "decisions" / "decisions.jsonl", "ab") as handle:
            handle.write(json.dumps(entry, sort_keys=True).encode() + b"\n")
        # Forged entry fails closed at load: digest and chain both broken.
        with self.assertRaisesRegex(PromotionRejected, "decision_log_corrupt"):
            PromotionController(
                self.store, self.root / "decisions",
                operator_token_digest=operator_token_digest(TOKEN),
                trusted_evaluator_keys={self.key_id: self.public.hex()})

    def test_fully_corrupt_log_is_not_truncated_away(self):
        log = self.root / "decisions" / "decisions.jsonl"
        log.write_bytes(b"garbage-not-json\nalso-broken\n")
        with self.assertRaisesRegex(PromotionRejected, "decision_log_corrupt"):
            PromotionController(
                self.store, self.root / "decisions",
                operator_token_digest=operator_token_digest(TOKEN),
                trusted_evaluator_keys={self.key_id: self.public.hex()})
        # Corrupt bytes preserved — no silent data loss.
        self.assertTrue(log.read_bytes().startswith(b"garbage"))

    def test_forged_qualified_without_evaluator_signature_detected(self):
        self.store.add(_proc(status="draft"))
        self.controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN)
        forged = dict(self.controller.decisions()[0].to_dict())
        forged.update({"new_status": "qualified",
                       "evaluator_signature": "not-required"})
        from sis.v3.contracts import PromotionDecisionV2
        from sis.v3.contracts import canonical_json
        forged_dec = PromotionDecisionV2.from_dict(forged)
        entry = {"decision": forged_dec.to_dict(),
                 "decision_digest": forged_dec.digest,
                 "prior_decision_digest": self.controller._prior}
        with open(self.root / "decisions" / "decisions.jsonl", "ab") as handle:
            handle.write(canonical_json(entry) + b"\n")
        fresh = PromotionController(
            self.store, self.root / "decisions",
            operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.key_id: self.public.hex()})
        report = fresh.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("evaluator_signature_required" in p
                            for p in report["problems"]))


if __name__ == "__main__":
    unittest.main()
