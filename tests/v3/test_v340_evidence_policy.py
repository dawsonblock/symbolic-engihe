"""PR-11: evidence-calibrated selection and negative-transfer controls."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sis.v3.evidence_policy import (
    CalibrationPolicy,
    EvidencePolicyError,
    RuleEvidence,
    negative_transfer_guard,
    select,
)
from sis.v3.retrieval import RetrievalContext
from sis.v3.serving import GovernedServingGateway
from tests.v3.authority_testkit import make_registry, register_repo
from tests.v3.candidate_testkit import CandidateStack
from tests.v3.test_candidates import make_candidate
from tests.v3.test_serving_package import _request


def context(**overrides):
    fields = {"language": "python", "toolchain": "pytest",
              "files_present": frozenset({"src/app.py"}),
              "symbols_present": frozenset({"parse"}),
              "failure_signatures": frozenset({"sig-x"})}
    fields.update(overrides)
    return RetrievalContext(**fields)


def evidence(candidate_id="cand-1", **overrides):
    fields = dict(
        candidate_id=candidate_id, qualification_status="qualified",
        supporting_attempts=6, counterexamples=0,
        expected_gain_milli=200, gain_lower_milli=80, gain_upper_milli=320,
        token_cost=40, latency_ms=200, regression_risk_milli=10)
    fields.update(overrides)
    return RuleEvidence(**fields)


class RuleEvidenceTests(unittest.TestCase):
    def test_interval_must_be_ordered(self):
        with self.assertRaisesRegex(EvidencePolicyError,
                                    "gain_interval_inconsistent"):
            evidence(gain_lower_milli=300, expected_gain_milli=200)

    def test_status_must_be_known(self):
        with self.assertRaisesRegex(EvidencePolicyError,
                                    "qualification_status_invalid"):
            evidence(qualification_status="probably")

    def test_uncertainty_is_the_interval_width(self):
        self.assertEqual(evidence().uncertainty_milli, 240)

    def test_declaration_round_trips(self):
        original = evidence(
            applicability=({"kind": "language_is", "value": "python"},),
            abstain_when=({"kind": "file_present", "value": "vendor/x.py"},))
        restored = RuleEvidence(**original.to_dict())
        self.assertEqual(restored, original)


class DecisionTests(unittest.TestCase):
    def test_a_well_supported_rule_is_served(self):
        decision = CalibrationPolicy().decide(evidence(), context())
        self.assertTrue(decision.serve)
        self.assertEqual(decision.reason, "served")

    def test_revoked_evidence_is_never_served(self):
        decision = CalibrationPolicy().decide(
            evidence(qualification_status="revoked"), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "revoked")

    def test_exploratory_evidence_is_not_served_by_default(self):
        decision = CalibrationPolicy().decide(
            evidence(qualification_status="exploratory"), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "not_qualified")

    def test_exploratory_evidence_may_be_opted_in(self):
        policy = CalibrationPolicy(allow_exploratory=True)
        self.assertTrue(policy.decide(
            evidence(qualification_status="exploratory"),
            context()).serve)

    def test_thin_support_is_refused(self):
        decision = CalibrationPolicy().decide(
            evidence(supporting_attempts=1), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "insufficient_support")

    def test_counterexamples_outweighing_support_are_refused(self):
        decision = CalibrationPolicy().decide(
            evidence(supporting_attempts=3, counterexamples=4), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "counterexamples_outweigh_support")

    def test_a_nonpositive_lower_bound_is_refused(self):
        decision = CalibrationPolicy().decide(
            evidence(gain_lower_milli=-20, expected_gain_milli=200),
            context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "gain_interval_not_positive")

    def test_high_regression_risk_is_refused(self):
        decision = CalibrationPolicy().decide(
            evidence(regression_risk_milli=400), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "regression_risk_too_high")

    def test_token_cost_ceiling_is_enforced(self):
        decision = CalibrationPolicy(max_token_cost=10).decide(
            evidence(token_cost=40), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "token_cost_too_high")

    def test_latency_ceiling_is_enforced(self):
        decision = CalibrationPolicy(max_latency_ms=100).decide(
            evidence(latency_ms=500), context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "latency_too_high")

    def test_an_abstention_condition_is_decisive(self):
        rule = evidence(abstain_when=(
            {"kind": "file_present", "value": "src/app.py"},))
        decision = CalibrationPolicy().decide(rule, context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "abstention_condition")

    def test_an_unmet_applicability_predicate_is_refused(self):
        rule = evidence(applicability=(
            {"kind": "language_is", "value": "rust"},))
        decision = CalibrationPolicy().decide(rule, context())
        self.assertFalse(decision.serve)
        self.assertEqual(decision.reason, "not_applicable")

    def test_utility_penalizes_cost_latency_and_uncertainty(self):
        policy = CalibrationPolicy()
        cheap = policy.utility(evidence(
            token_cost=10, latency_ms=100, gain_lower_milli=80,
            expected_gain_milli=100, gain_upper_milli=120))
        expensive = policy.utility(evidence(
            token_cost=200, latency_ms=900, gain_lower_milli=80,
            expected_gain_milli=200, gain_upper_milli=900))
        self.assertGreater(cheap, expensive)


class SelectionTests(unittest.TestCase):
    def test_higher_utility_ranks_first(self):
        decisions = select(
            [evidence("weak", expected_gain_milli=60, gain_lower_milli=10,
                      gain_upper_milli=90),
             evidence("strong", expected_gain_milli=400,
                      gain_lower_milli=200, gain_upper_milli=520)],
            context())
        served = [d.candidate_id for d in decisions if d.serve]
        self.assertEqual(served, ["strong", "weak"])

    def test_the_token_budget_is_a_hard_stop(self):
        decisions = select(
            [evidence("a", token_cost=40), evidence("b", token_cost=40)],
            context(), token_budget=50)
        served = [d for d in decisions if d.serve]
        self.assertEqual(len(served), 1)
        self.assertIn("token_budget_exhausted",
                      [d.reason for d in decisions])

    def test_the_rule_limit_is_respected(self):
        decisions = select(
            [evidence(f"c{i}") for i in range(5)], context(), max_rules=2)
        self.assertEqual(len([d for d in decisions if d.serve]), 2)
        self.assertIn("rule_limit_reached",
                      [d.reason for d in decisions])

    def test_rejected_rules_are_reported_with_reasons(self):
        decisions = select(
            [evidence("ok"), evidence("revoked",
                                      qualification_status="revoked")],
            context())
        reasons = {d.candidate_id: d.reason for d in decisions}
        self.assertEqual(reasons["ok"], "served")
        self.assertEqual(reasons["revoked"], "revoked")


class NegativeTransferTests(unittest.TestCase):
    def test_an_identical_failure_signature_blocks_the_rule(self):
        self.assertEqual(
            negative_transfer_guard(evidence(), task_signature="fix/balance",
                                    known_failures=["fix/balance"]),
            "prior_negative_transfer")

    def test_a_resembling_task_blocks_the_rule(self):
        self.assertEqual(
            negative_transfer_guard(
                evidence(), task_signature="fix/balance/rounding",
                known_failures=["fix/balance/truncate"]),
            "prior_negative_transfer")

    def test_an_unrelated_task_does_not_block(self):
        self.assertIsNone(negative_transfer_guard(
            evidence(), task_signature="feat/parser",
            known_failures=["fix/balance"]))


class GatewayIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.registry, seed = make_registry()
        register_repo(self.registry, seed, registry_id="repo-a",
                      family_id="fam-a")
        self.stack = CandidateStack(root / "c.db")
        self.addCleanup(self.stack.close)
        self.audit = []
        self.candidate = make_candidate(
            scope={"kind": "family_id", "value": "fam-a"})
        self.stack.prepare(self.candidate)
        self.stack.qualify(self.candidate)

    def gateway(self, provider, policy=None):
        return GovernedServingGateway(
            self.stack.registry, repository_registry=self.registry,
            audit_sink=self.audit.append,
            receipt_authority=self.stack.resolve_receipt,
            evidence_policy=policy or CalibrationPolicy(),
            evidence_provider=provider)

    def test_a_calibrated_candidate_is_served(self):
        gateway = self.gateway(
            lambda candidate: evidence(candidate.candidate_id))
        guidance = gateway.serve(_request(), repository_id="repo-a")
        self.assertIn("do the thing", guidance.helpful_next_checks)
        self.assertEqual(self.audit[-1]["policy_decisions"][0]["serve"], True)

    def test_a_low_confidence_candidate_is_not_served(self):
        gateway = self.gateway(
            lambda candidate: evidence(candidate.candidate_id,
                                       gain_lower_milli=-50))
        guidance = gateway.serve(_request(), repository_id="repo-a")
        self.assertNotIn("do the thing", guidance.helpful_next_checks)
        reasons = [r["reason"] for r in self.audit[-1]["rejections"]]
        self.assertIn("gain_interval_not_positive", reasons)

    def test_a_provider_failure_fails_closed(self):
        def provider(candidate):
            raise RuntimeError("evidence store down")
        gateway = self.gateway(provider)
        guidance = gateway.serve(_request(), repository_id="repo-a")
        self.assertNotIn("do the thing", guidance.helpful_next_checks)
        reasons = [r["reason"] for r in self.audit[-1]["rejections"]]
        self.assertIn("evidence_unavailable", reasons)


if __name__ == "__main__":
    unittest.main()
