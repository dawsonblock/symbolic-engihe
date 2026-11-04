"""PR-10: the controlled five-arm campaign and its after-cost verdict."""
from __future__ import annotations

import unittest

from sis.v3.five_arm import (
    ARMS,
    AnalysisManifest,
    ArmConfiguration,
    ArmOutcome,
    CampaignError,
    CampaignPlan,
    FIVE_ARM_DESIGN,
    assess,
    build_report,
    validate_design,
)
from sis.v3.statistical_power import (
    LineageRegistry,
    PowerRequirement,
    RepositoryLineage,
    sign_preregistration,
)
from tests.v3 import five_arm_testkit as kit
from tests.v3.test_evaluation_certificates import PROTOCOL_DIGEST


def power(effect=400, discordant=300):
    return PowerRequirement(design="paired_mcnemar", effect_milli=effect,
                            discordant_milli=discordant)


def protocol(**overrides):
    fields = {"protocol_digest": PROTOCOL_DIGEST, "arms": list(ARMS),
              "alpha": 0.05, "sample_size": 29}
    fields.update(overrides)
    return fields


def plan(tasks=29, **overrides):
    fields = dict(protocol=protocol(), power_requirement=power(),
                  task_ids=tuple(f"t{i}" for i in range(tasks)), seed=7)
    fields.update(overrides)
    return CampaignPlan(**fields)


class DesignTests(unittest.TestCase):
    def test_the_declared_design_is_controlled(self):
        validate_design(FIVE_ARM_DESIGN)
        by_arm = {config.arm: config for config in FIVE_ARM_DESIGN}
        self.assertEqual(by_arm["A"].components, ())
        self.assertEqual(by_arm["B"].components, ("memory",))
        self.assertEqual(by_arm["C"].components, ("skills",))
        self.assertEqual(by_arm["D"].components, ("procedures",))
        self.assertEqual(set(by_arm["E"].components),
                         {"memory", "skills", "procedures"})
        self.assertTrue(by_arm["E"].integrated)

    def test_baseline_with_a_component_is_refused(self):
        design = (ArmConfiguration(arm="A", label="bare", memory=True),) + \
            FIVE_ARM_DESIGN[1:]
        with self.assertRaisesRegex(CampaignError,
                                    "arm_component_mapping_invalid"):
            validate_design(design)

    def test_component_arm_with_two_components_is_refused(self):
        design = tuple(
            ArmConfiguration(arm="B", label="two", memory=True, skills=True)
            if config.arm == "B" else config for config in FIVE_ARM_DESIGN)
        with self.assertRaisesRegex(
                CampaignError, "arm_component_mapping_invalid"):
            validate_design(design)

    def test_integrated_arm_must_enable_everything(self):
        design = tuple(
            ArmConfiguration(arm="E", label="partial", memory=True,
                             skills=True)
            if config.arm == "E" else config for config in FIVE_ARM_DESIGN)
        with self.assertRaisesRegex(CampaignError,
                                    "arm_component_mapping_invalid"):
            validate_design(design)

    def test_arms_must_be_A_through_E(self):
        with self.assertRaisesRegex(CampaignError,
                                    "design_must_be_A_B_C_D_E"):
            validate_design(FIVE_ARM_DESIGN[:4])


class PlanTests(unittest.TestCase):
    def test_a_powered_plan_reports_powered(self):
        self.assertTrue(plan(tasks=40).powered)

    def test_an_undersized_plan_is_not_powered(self):
        self.assertFalse(plan(tasks=5).powered)

    def test_task_ids_must_be_unique(self):
        with self.assertRaisesRegex(CampaignError,
                                    "task_ids_must_be_unique"):
            plan(task_ids=("t1", "t1"))

    def test_arm_order_is_deterministic_and_seeded(self):
        first = plan().arm_order()
        self.assertEqual(first, plan().arm_order())
        self.assertEqual(set(first), set(ARMS))
        self.assertNotEqual(first, plan(seed=8).arm_order())

    def test_protocol_arms_must_match(self):
        with self.assertRaisesRegex(
                CampaignError, "protocol_arms_do_not_match_the_design"):
            plan(protocol=protocol(arms=["A", "E"]))


def outcomes(tasks, *, e_solves=(), b_solves=(), e_tokens=1000,
             a_tokens=1000):
    """A fully signed run: every arm carries a receipt and a measurement.

    The measurement is bound to an experiment authorization for this
    plan, so the fixture is what a real evaluator would produce — not a
    report-shaped claim.
    """
    campaign = plan(tasks=tasks)
    authorization = kit.experiment_authorization(campaign)
    rows = []
    for index in range(tasks):
        task = f"t{index}"
        solved = {
            "A": False,
            "B": task in b_solves,
            "C": False,
            "D": False,
            "E": task in e_solves,
        }
        arms = {}
        for arm in ARMS:
            tokens = e_tokens if arm == "E" else a_tokens
            receipt = kit.receipt_for(
                task, arm, "pass" if solved[arm] else "fail")
            arms[arm] = ArmOutcome(
                arm=arm, valid_solve=solved[arm],
                tokens=tokens, wall_seconds=10.0, tool_calls=5,
                receipt=receipt,
                measurement=kit.measurement_for(
                    task, arm, "pass" if solved[arm] else "fail",
                    campaign=campaign, authorization=authorization,
                    receipt=receipt,
                    tokens_in=tokens // 2, tokens_out=tokens - tokens // 2))
        rows.append((task, arms))
    return rows


def manifest(protocol_digest=PROTOCOL_DIGEST, *, training=("lin-t",),
             holdout=("lin-h",), registered_at="2026-01-01T00:00:00Z",
             first_evaluation="2026-02-01T00:00:00Z", signed=True):
    return kit.manifest(
        protocol_digest=protocol_digest, training=training, holdout=holdout,
        registered_at=registered_at, first_evaluation=first_evaluation,
        signed=signed)


def authority():
    return kit.receipt_authority()


def trusted_analysis():
    return kit.trusted_analysis_keys()


def trusted_timestamp():
    return kit.trusted_timestamp_keys()


def signed_outcome(task, arm, solved, *, campaign, authorization,
                   tokens=1000):
    """One arm outcome carrying a receipt and a matching measurement."""
    receipt = kit.receipt_for(task, arm, "pass" if solved else "fail")
    return ArmOutcome(
        arm=arm, valid_solve=solved, tokens=tokens, wall_seconds=10.0,
        tool_calls=5, receipt=receipt,
        measurement=kit.measurement_for(
            task, arm, "pass" if solved else "fail", campaign=campaign,
            authorization=authorization, receipt=receipt,
            tokens_in=tokens // 2, tokens_out=tokens - tokens // 2))


def verdict_for(report, campaign, analysis=None):
    return assess(report, plan=campaign, analysis=analysis,
                  receipt_authority=authority(),
                  trusted_analysis_keys=trusted_analysis(),
                  trusted_timestamp_keys=trusted_timestamp(),
                  experiment_authorization=kit.experiment_authorization(
                      campaign))


class AssessmentTests(unittest.TestCase):
    def test_a_real_improvement_at_comparable_cost_is_supported(self):
        tasks = 29
        report = build_report(
            plan(tasks=tasks),
            outcomes(tasks, e_solves={f"t{i}" for i in range(20)}),
            evidence_class="confirmatory")
        verdict = verdict_for(report, plan(tasks=tasks),
                              analysis=manifest())
        self.assertEqual(verdict["verdict"], "supported")
        self.assertEqual(verdict["evidence_class"], "confirmatory")

    def test_the_same_solve_rate_is_no_evidence(self):
        tasks = 29
        report = build_report(plan(tasks=tasks), outcomes(tasks))
        verdict = verdict_for(report, plan(tasks=tasks))
        self.assertEqual(verdict["verdict"], "no_evidence")

    def test_more_tokens_for_the_same_rate_is_not_an_advantage(self):
        tasks = 29
        report = build_report(
            plan(tasks=tasks),
            outcomes(tasks, e_solves={f"t{i}" for i in range(20)},
                     e_tokens=3000, a_tokens=1000))
        verdict = verdict_for(report, plan(tasks=tasks))
        self.assertEqual(verdict["verdict"], "no_advantage_after_cost")
        self.assertGreater(verdict["token_ratio"], 2.0)

    def test_a_regression_is_reported(self):
        tasks = 29
        report = build_report(
            plan(tasks=tasks),
            outcomes(tasks, e_solves=set(), b_solves={
                f"t{i}" for i in range(10)}))
        # E solves nothing while A also solves nothing: no delta. Force a
        # real regression by giving A solves instead.
        campaign = plan(tasks=tasks)
        authorization = kit.experiment_authorization(campaign)
        rows = []
        for task, arms in outcomes(tasks):
            rows.append((task, {
                **arms,
                "A": signed_outcome(task, "A", True, campaign=campaign,
                                    authorization=authorization),
                "E": signed_outcome(task, "E", False, campaign=campaign,
                                    authorization=authorization),
            }))
        report = build_report(plan(tasks=tasks), rows)
        verdict = verdict_for(report, plan(tasks=tasks))
        self.assertEqual(verdict["verdict"], "regressed")

    def test_an_undersized_run_is_underpowered(self):
        tasks = 10
        report = build_report(
            plan(tasks=tasks),
            outcomes(tasks, e_solves={f"t{i}" for i in range(9)}))
        verdict = verdict_for(report, plan(tasks=tasks))
        self.assertEqual(verdict["verdict"], "underpowered")
        self.assertTrue(verdict["underpowered"])

    def test_an_overlapping_holdout_is_invalid(self):
        tasks = 29
        report = build_report(
            plan(tasks=tasks),
            outcomes(tasks, e_solves={f"t{i}" for i in range(20)}),
            holdout_disjoint=False)
        verdict = verdict_for(report, plan(tasks=tasks))
        self.assertEqual(verdict["verdict"], "invalid_holdout")

    def test_component_contrasts_are_reported(self):
        tasks = 29
        report = build_report(
            plan(tasks=tasks),
            outcomes(tasks, e_solves={f"t{i}" for i in range(20)},
                     b_solves={f"t{i}" for i in range(15)}))
        verdict = verdict_for(report, plan(tasks=tasks))
        self.assertEqual(set(verdict["component_contrasts"]),
                         {"B", "C", "D"})
        self.assertEqual(verdict["overhead"]["A"]["mean_tokens_per_task"],
                         1000)


if __name__ == "__main__":
    unittest.main()
