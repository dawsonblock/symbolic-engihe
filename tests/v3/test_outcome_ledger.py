"""SIS3-132: transactional verify_and_consume anti-replay (v3.2.1)."""
import threading
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import OutcomeEnvelopeV2
from sis.v3.outcome_v2 import (
    ConsumedOutcomeLedger,
    EnvelopeRejected,
    TrustedKey,
    TrustedKeyRegistry,
    issue_envelope,
    verify_envelope,
)
from sis.v3.verifier import EvaluatorKeyStore

D = "0" * 64


class ConsumeLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keystore = EvaluatorKeyStore(self.root / "keys")
        _, self.public = self.keystore.load_or_create()
        self.registry = TrustedKeyRegistry({
            self.keystore.key_id: TrustedKey(public_key=self.public.hex()),
        })
        self.kw = dict(
            keystore=self.keystore, task_id="t1", attempt_id="att-1",
            evaluated_repo_digest=D, environment_digest="1" * 64,
            test_suite_commitment="2" * 64, execution_receipt_digest="3" * 64,
            criterion_version="v1", outcome="pass",
        )
        self.ledger_dir = self.root / "ledger"

    def _ledger(self):
        return ConsumedOutcomeLedger(self.ledger_dir)

    def test_consume_then_replay_rejected(self):
        env = issue_envelope(**self.kw)
        ledger = self._ledger()
        self.assertIs(ledger.verify_and_consume(env, self.registry), env)
        self.assertTrue(ledger.is_consumed(env.signer_key_id, env.nonce))
        with self.assertRaisesRegex(EnvelopeRejected, "replayed_nonce"):
            ledger.verify_and_consume(env, self.registry)

    def test_consumption_survives_restart(self):
        env = issue_envelope(**self.kw)
        self._ledger().verify_and_consume(env, self.registry)
        fresh = self._ledger()
        self.assertTrue(fresh.is_consumed(env.signer_key_id, env.nonce))
        with self.assertRaisesRegex(EnvelopeRejected, "replayed_nonce"):
            fresh.verify_and_consume(env, self.registry)

    def test_invalid_signature_does_not_consume(self):
        env = issue_envelope(**self.kw)
        forged = dict(env.to_dict())
        forged["signature"] = "0" * 128
        forged_env = OutcomeEnvelopeV2.from_dict(forged)
        ledger = self._ledger()
        with self.assertRaisesRegex(EnvelopeRejected,
                                    "envelope_verification_failed"):
            ledger.verify_and_consume(forged_env, self.registry)
        self.assertFalse(ledger.is_consumed(
            forged_env.signer_key_id, forged_env.nonce))
        # The genuine envelope with the same nonce is still consumable.
        ledger.verify_and_consume(env, self.registry)

    def test_expired_and_revoked_do_not_consume(self):
        expired = issue_envelope(**self.kw,
                                 expires_at="2020-01-01T00:00:00Z")
        ledger = self._ledger()
        with self.assertRaises(EnvelopeRejected):
            ledger.verify_and_consume(expired, self.registry)
        self.assertFalse(ledger.is_consumed(
            expired.signer_key_id, expired.nonce))
        env = issue_envelope(**self.kw)
        with self.assertRaises(EnvelopeRejected):
            ledger.verify_and_consume(
                env, self.registry, revoked_keys={env.signer_key_id})
        self.assertFalse(ledger.is_consumed(env.signer_key_id, env.nonce))

    def test_operation_id_idempotent_retry(self):
        env = issue_envelope(**self.kw)
        ledger = self._ledger()
        ledger.verify_and_consume(env, self.registry, operation_id="op-1")
        again = ledger.verify_and_consume(
            env, self.registry, operation_id="op-1")
        self.assertEqual(again.digest, env.digest)
        other = issue_envelope(**{**self.kw, "nonce": "nonce-other"})
        with self.assertRaisesRegex(EnvelopeRejected, "operation_conflict"):
            ledger.verify_and_consume(
                other, self.registry, operation_id="op-1")

    def test_binding_mismatch_rejected_without_consumption(self):
        env = issue_envelope(**self.kw)
        ledger = self._ledger()
        with self.assertRaisesRegex(EnvelopeRejected, "binding_mismatch"):
            ledger.verify_and_consume(
                env, self.registry, expected_task_id="t-other")
        self.assertFalse(ledger.is_consumed(env.signer_key_id, env.nonce))

    def test_concurrent_consumers_exactly_one_wins(self):
        env = issue_envelope(**self.kw)
        results, errors = [], []
        barrier = threading.Barrier(8)

        def consume():
            ledger = self._ledger()
            barrier.wait()
            try:
                results.append(ledger.verify_and_consume(env, self.registry))
            except EnvelopeRejected as exc:
                errors.append(exc)

        threads = [threading.Thread(target=consume) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 7)
        self.assertTrue(all(e.reason == "replayed_nonce" for e in errors))

    def test_corrupt_ledger_fails_closed(self):
        env = issue_envelope(**self.kw)
        self._ledger().verify_and_consume(env, self.registry)
        path = self.ledger_dir / "consumed.jsonl"
        path.write_bytes(path.read_bytes() + b'{"broken": 1}\n')
        with self.assertRaisesRegex(EnvelopeRejected,
                                    "consumed_ledger_corrupt"):
            self._ledger().verify_and_consume(
                issue_envelope(**{**self.kw, "nonce": "n2"}), self.registry)

    def test_pure_verify_never_consumes(self):
        # Audit path stays side-effect free (v3.1.x behavior preserved).
        env = issue_envelope(**self.kw)
        self.assertTrue(verify_envelope(env, self.registry))
        self.assertTrue(verify_envelope(env, self.registry))
        self.assertFalse(
            self._ledger().is_consumed(env.signer_key_id, env.nonce))


class EnvelopePromotionWiringTests(unittest.TestCase):
    """Consumed outcomes authorize promotion exactly once."""

    def setUp(self):
        from tests.v3.support import FixtureAuthority
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.auth = FixtureAuthority(root / "auth")
        self.keystore = EvaluatorKeyStore(root / "keys")
        _, self.public = self.keystore.load_or_create()
        self.registry = TrustedKeyRegistry({
            self.keystore.key_id: TrustedKey(public_key=self.public.hex()),
        })
        self.ledger = ConsumedOutcomeLedger(root / "consumed")
        # Rewire the fixture controller to consume envelopes.
        from sis.v3.promotion import PromotionController, operator_token_digest
        self.auth.controller = PromotionController(
            self.auth.store, self.auth.root / "decisions",
            operator_token_digest=operator_token_digest(self.auth.token),
            trusted_evaluator_keys={
                self.auth.eval_key_id: self.auth.eval_public.hex(),
                self.keystore.key_id: self.public.hex(),
            },
            receipt_resolver=self.auth._resolve,
            repo_resolver=self.auth._resolve_repo,
            consumed_ledger=self.ledger,
            envelope_registry=self.registry,
        )
        self.kw = dict(
            keystore=self.keystore, task_id="t1", attempt_id="att-1",
            evaluated_repo_digest=D, environment_digest="1" * 64,
            test_suite_commitment="2" * 64, execution_receipt_digest="3" * 64,
            criterion_version="v1", outcome="pass",
        )

    def test_spent_envelope_cannot_back_second_promotion(self):
        from tests.v3.test_retrieval import _proc
        from dataclasses import replace
        env = issue_envelope(**self.kw)
        self.auth.store.add(replace(_proc(pid="p1", status="candidate")))
        ctl = self.auth.controller
        receipt = self.auth.issue_receipt()
        ctl.transition(
            "p1", "evaluated", actor_role="operator", actor_identity="op",
            operator_token=self.auth.token,
            receipt_digests=(receipt.digest,),
            evaluator_signer=self.auth._eval_signer)
        ctl.transition(
            "p1", "qualified", actor_role="operator", actor_identity="op",
            operator_token=self.auth.token, outcome_envelopes=(env,),
            evaluator_signer=self.auth._eval_signer)
        self.assertEqual(self.auth.store.get("p1").status, "qualified")
        # A second procedure cannot reuse the spent envelope.
        from sis.v3.promotion import PromotionRejected
        self.auth.store.add(replace(_proc(pid="p2", status="candidate")))
        with self.assertRaisesRegex(PromotionRejected, "replayed_nonce"):
            ctl.transition(
                "p2", "evaluated", actor_role="operator",
                actor_identity="op", operator_token=self.auth.token,
                outcome_envelopes=(env,),
                evaluator_signer=self.auth._eval_signer)


if __name__ == "__main__":
    unittest.main()
