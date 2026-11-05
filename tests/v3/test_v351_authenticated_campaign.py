"""SIS v3.5.1: the authenticated chain has a producer.

``five_arm.assess`` always required signed measurements. Until this
module existed, only the test fixtures produced them: a real campaign
ran the arms and wrote numbers nobody had signed. These tests run the
producer end to end and check that the chain it emits is the one the
assessment authenticates.
"""
from __future__ import annotations

import unittest
from dataclasses import replace

from sis.v3.authenticated_campaign import (
    CampaignCommitments,
    CampaignError,
    run_authenticated_campaign,
)
from sis.v3.evidence_binding import EvidenceBindingAuthority
from sis.v3 import signatures
from tools import authenticated_campaign as campaign


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = campaign.tempfile.TemporaryDirectory(
            prefix="sis-auth-campaign-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = campaign.Path(self.temp.name)
        self.harness, self.tasks = campaign._build(self.root)
        self.experiment_seed = b"\x53" * 32
        self.evaluator_seed = b"\x51" * 32
        self.timestamp_seed = b"\x01" * 32
        self.analysis_seed = b"\x52" * 32
        self.authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={
                "eval-key-1":
                    signatures.public_key(self.evaluator_seed).hex()},
            trusted_harness_keys={},
            trusted_experiment_keys={
                "experiment-key-1":
                    signatures.public_key(self.experiment_seed).hex()})
        protocol = campaign.preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=1.0,
            sample_size=len(self.tasks),
            budget={"wall_seconds": 120, "token_budget": 1000,
                    "tool_budget": 100},
            arms=campaign.GOVERNED_ARMS)
        self.power = campaign.PowerRequirement(
            design="paired_mcnemar", effect_milli=800, discordant_milli=800)
        self.preregistration = campaign.sign_preregistration(
            self.timestamp_seed, preregistration_id="pre-test",
            protocol_digest=protocol["protocol_digest"],
            primary_metric="paired solved_delta E vs A",
            power=self.power.to_dict(),
            holdout_lineages=("lin-h",), training_lineages=("lin-t",),
            registered_at="2026-01-01T00:00:00Z",
            timestamp_authority="tsa", signer_key_id="tsa-key")
        self.analysis = campaign._manifest(
            self.analysis_seed, "analysis-key-1", self.preregistration,
            protocol["protocol_digest"])
        self.plan = campaign.CampaignPlan(
            protocol=protocol, power_requirement=self.power,
            task_ids=tuple(task.task_id for task, _ in self.tasks),
            seed=20260101)
        self.commitments = CampaignCommitments(
            experiment_id="exp-test", model_identity="scripted-agent",
            model_digest="7" * 64, environment_digest="8" * 64,
            criterion_version="v1", test_suite_commitment="1" * 64,
            repository_id="repo-1", requester_principal_id="requester",
            authorization_id="authz-test", evaluator_build_digest="4" * 64)

    def run_campaign(self, **overrides):
        kwargs = dict(
            plan=self.plan, tasks=self.tasks, harness=self.harness,
            agent=campaign._agent,
            budget=campaign.BudgetCaps(wall_seconds=120, token_budget=1000,
                                       tool_budget=100),
            context_provider=campaign._provider,
            commitments=self.commitments,
            preregistration=self.preregistration, analysis=self.analysis,
            experiment_seed=self.experiment_seed,
            experiment_key_id="experiment-key-1",
            evaluator_seed=self.evaluator_seed,
            evaluator_key_id="eval-key-1",
            receipt_authority=self.authority,
            trusted_analysis_keys={
                "analysis-key-1":
                    signatures.public_key(self.analysis_seed).hex()},
            trusted_timestamp_keys={
                "tsa-key": signatures.public_key(self.timestamp_seed).hex()})
        kwargs.update(overrides)
        return run_authenticated_campaign(**kwargs)


class ProducerTests(_Fixture):
    def test_a_real_campaign_produces_a_fully_authenticated_chain(self):
        result = self.run_campaign()
        verdict = result["verdict"]
        self.assertTrue(verdict["validation"]["ok"], verdict["problems"])
        self.assertTrue(verdict["measurements_verified"], verdict["problems"])
        self.assertTrue(verdict["receipts_verified"], verdict["problems"])
        self.assertTrue(verdict["analysis_verified"], verdict["problems"])
        self.assertTrue(verdict["preregistration_verified"],
                        verdict["problems"])
        self.assertEqual(verdict["observed_sample_size"], len(self.tasks))

    def test_the_verdict_is_honest_about_a_tiny_demo(self):
        # Four tasks cannot reach significance: 4 wins and 0 losses is
        # p=0.125. The chain authenticates and the verdict still refuses.
        verdict = self.run_campaign()["verdict"]
        self.assertEqual(verdict["decisive_contrast"]["wins"], 4)
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertIn("underpowered", verdict["problems"])

    def test_one_key_cannot_authorize_and_measure(self):
        with self.assertRaises(CampaignError) as caught:
            self.run_campaign(experiment_key_id="eval-key-1")
        self.assertEqual(caught.exception.reason,
                         "authority_roles_not_separated")

    def test_guidance_exposure_is_recorded_per_arm(self):
        report = self.run_campaign()["report"]
        row = report["per_task"][0]["arms"]
        baseline = row["A"]["receipt"]["guidance_exposure_digest"]
        treatment = row["E"]["receipt"]["guidance_exposure_digest"]
        self.assertNotEqual(baseline, treatment)

    def test_the_report_carries_a_measurement_for_every_cell(self):
        report = self.run_campaign()["report"]
        cells = [(row["task_id"], arm)
                 for row in report["per_task"] for arm in row["arms"]]
        self.assertEqual(len(cells), len(self.tasks) * 5)
        for row in report["per_task"]:
            for arm, outcome in row["arms"].items():
                self.assertIsNotNone(outcome["measurement"], (row, arm))
                self.assertIsNotNone(outcome["receipt"], (row, arm))

    def test_a_budget_change_after_the_run_is_refused(self):
        # The producer froze the plan; re-assessing the same report
        # against a different budget is a different experiment.
        from sis.v3.five_arm import assess
        result = self.run_campaign()
        squeezed = replace(self.plan, max_tokens_per_task=1)
        verdict = assess(
            result["report"], plan=squeezed, analysis=self.analysis,
            receipt_authority=self.authority,
            trusted_analysis_keys={
                "analysis-key-1":
                    signatures.public_key(self.analysis_seed).hex()},
            trusted_timestamp_keys={
                "tsa-key": signatures.public_key(self.timestamp_seed).hex()},
            experiment_authorization=result["authorization"])
        self.assertEqual(verdict["verdict"], "invalid_report")
        self.assertIn("experiment_plan_mismatch", verdict["problems"])


if __name__ == "__main__":
    unittest.main()
