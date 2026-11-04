"""v3.5.0 PR-04: custody readiness, crypto backend and utility semantics."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import signatures
from sis.v3.evidence_policy import CalibrationPolicy, RuleEvidence
from sis.v3.key_custody import EVALUATOR, PROMOTION_AUTHORITY, four_identity_custody
from sis.v3.retrieval import RetrievalContext


class CustodyReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.custody = four_identity_custody(Path(self.temp.name) / "keys")

    def test_a_complete_custody_is_ready(self):
        report = self.custody.custody_report()
        self.assertTrue(report["ready"])
        self.assertEqual(report["missing_roles"], [])
        self.assertTrue(all(entry["valid"] for entry in report["roles"]
                            if entry["enrolled"]))

    def test_a_chmod_after_enrollment_makes_readiness_false(self):
        self.custody.key(EVALUATOR).seed_path.chmod(0o644)
        report = self.custody.custody_report()
        self.assertFalse(report["ready"])
        self.assertIn(EVALUATOR, report["missing_roles"])
        evaluator = next(entry for entry in report["roles"]
                         if entry["role"] == EVALUATOR)
        self.assertFalse(evaluator["valid"])
        self.assertEqual(evaluator["problem"], "seed_permissions_too_open")

    def test_a_deleted_seed_makes_readiness_false(self):
        self.custody.key(PROMOTION_AUTHORITY).seed_path.unlink()
        report = self.custody.custody_report()
        self.assertFalse(report["ready"])
        self.assertIn(PROMOTION_AUTHORITY, report["missing_roles"])

    def test_a_symlinked_seed_is_not_valid(self):
        key = self.custody.key(EVALUATOR)
        link = key.seed_path.parent / "link.seed"
        link.symlink_to(key.seed_path)
        key.seed_path.unlink()
        link.rename(key.seed_path)
        report = self.custody.custody_report()
        self.assertFalse(report["ready"])

    def test_the_report_never_contains_seed_material(self):
        rendered = str(self.custody.custody_report())
        for role in (EVALUATOR, PROMOTION_AUTHORITY):
            seed = self.custody.key(role).seed_path.read_bytes().hex()
            self.assertNotIn(seed, rendered)


class CryptoBackendTests(unittest.TestCase):
    def test_production_refuses_the_vendored_backend(self):
        with mock.patch("sis.v3.signatures.backend",
                        return_value="vendored-python"):
            with self.assertRaisesRegex(
                    signatures.CryptoBackendError,
                    "crypto_backend_not_vetted"):
                signatures.require_vetted_backend(production=True)

    def test_development_may_report_the_vendored_backend(self):
        with mock.patch("sis.v3.signatures.backend",
                        return_value="vendored-python"):
            self.assertEqual(
                signatures.require_vetted_backend(production=False),
                "vendored-python")

    def test_the_active_backend_is_reported(self):
        self.assertIn(signatures.backend(),
                      {"cryptography", "vendored-python"})

    def test_a_receipt_round_trips_under_the_active_backend(self):
        seed, public = signatures.generate_keypair()
        signature = signatures.sign(seed, b"payload")
        self.assertTrue(signatures.verify(signature, b"payload", public))
        self.assertFalse(signatures.verify(signature, b"other", public))


class UtilityPolicyTests(unittest.TestCase):
    def evidence(self, **overrides):
        values = dict(
            candidate_id="cand-1", qualification_status="qualified",
            supporting_attempts=5, counterexamples=0,
            expected_gain_milli=50, gain_lower_milli=10,
            gain_upper_milli=90, token_cost=200, latency_ms=10,
            regression_risk_milli=0)
        values.update(overrides)
        return RuleEvidence(**values)

    def context(self):
        return RetrievalContext(language="python")

    def test_ranking_mode_serves_negative_utility(self):
        decision = CalibrationPolicy().decide(self.evidence(), self.context())
        self.assertTrue(decision.serve)
        self.assertLess(decision.utility_milli, 0)

    def test_abstention_mode_refuses_below_the_threshold(self):
        policy = CalibrationPolicy(utility_mode="abstention",
                                   min_net_utility_milli=0)
        decision = policy.decide(self.evidence(), self.context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "net_utility_below_threshold")

    def test_abstention_mode_serves_above_the_threshold(self):
        policy = CalibrationPolicy(utility_mode="abstention",
                                   min_net_utility_milli=0)
        decision = policy.decide(
            self.evidence(token_cost=1, expected_gain_milli=500,
                          gain_lower_milli=400, gain_upper_milli=600),
            self.context())
        self.assertTrue(decision.serve)
        self.assertEqual(decision.reason, "served")

    def test_the_policy_digest_is_stable_and_binds_the_mode(self):
        first = CalibrationPolicy()
        second = CalibrationPolicy()
        abstaining = CalibrationPolicy(utility_mode="abstention")
        self.assertEqual(first.digest(), second.digest())
        self.assertNotEqual(first.digest(), abstaining.digest())

    def test_an_unknown_utility_mode_is_refused(self):
        from sis.v3.evidence_policy import EvidencePolicyError
        with self.assertRaisesRegex(EvidencePolicyError,
                                    "utility_mode_invalid"):
            CalibrationPolicy(utility_mode="guess")


if __name__ == "__main__":
    unittest.main()
