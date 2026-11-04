"""v3.5.0 PR-03: a five-arm report must validate against its plan.

The audit reproduced a report with undeclared, exploratory rows being
classified ``supported`` and ``confirmatory``. These tests pin the
refusals: undeclared/duplicate/missing tasks, missing arms, a reordered
run, forged aggregates, duplicated receipts, a mismatched configuration,
and any attempt to promote exploratory or post-hoc evidence.
"""
from __future__ import annotations

import copy
import unittest

from sis.v3.five_arm import (
    AnalysisManifest,
    ArmConfiguration,
    CampaignError,
    FIVE_ARM_DESIGN,
    assess,
    build_report,
    validate_design,
    validate_report,
)
from tests.v3.test_v340_five_arm import manifest, outcomes, plan


def report_for(tasks=29, **overrides):
    return build_report(
        plan(tasks=tasks),
        outcomes(tasks, e_solves={f"t{i}" for i in range(20)}),
        evidence_class="confirmatory", **overrides)


class ReportValidationTests(unittest.TestCase):
    def test_a_well_formed_report_validates(self):
        validation = validate_report(report_for(), plan(tasks=29))
        self.assertTrue(validation.ok, validation.problems)
        self.assertAlmostEqual(
            validation.metrics["E"]["solved_task_rate"], 20 / 29)

    def test_an_undeclared_task_is_invalid(self):
        report = report_for()
        row = copy.deepcopy(report["per_task"][0])
        row["task_id"] = "t99"
        report["per_task"].append(row)
        validation = validate_report(report, plan(tasks=29))
        self.assertFalse(validation.ok)
        self.assertIn("task_set_mismatch", validation.problems)
        self.assertIn("task_count_mismatch", validation.problems)

    def test_a_duplicated_task_is_invalid(self):
        report = report_for()
        report["per_task"].append(copy.deepcopy(report["per_task"][0]))
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("task_id_duplicated", validation.problems)

    def test_a_missing_task_is_invalid(self):
        report = report_for()
        report["per_task"].pop()
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("task_set_mismatch", validation.problems)

    def test_a_missing_arm_is_invalid(self):
        report = report_for()
        del report["per_task"][3]["arms"]["C"]
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("arm_set_mismatch:t3", validation.problems)

    def test_a_reordered_run_is_invalid(self):
        report = report_for()
        report["per_task"][0]["arm_order"] = list(reversed(
            report["per_task"][0]["arm_order"]))
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("arm_order_mismatch:t0", validation.problems)

    def test_a_forged_aggregate_is_invalid(self):
        report = report_for()
        report["governed"]["metrics"]["A"]["solved_task_rate"] = 1.0
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("metrics_mismatch", validation.problems)

    def test_a_duplicated_receipt_is_invalid(self):
        report = report_for()
        report["per_task"][0]["arms"]["A"]["receipt_id"] = "rcpt-1"
        report["per_task"][0]["arms"]["B"]["receipt_id"] = "rcpt-1"
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("receipt_duplicated", validation.problems)

    def test_a_wrong_arm_configuration_is_invalid(self):
        report = report_for()
        report["per_task"][0]["arms"]["B"]["arm_config_digest"] = "0" * 64
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("arm_config_mismatch:t0/B", validation.problems)

    def test_a_different_plan_is_invalid(self):
        report = report_for()
        validation = validate_report(report, plan(tasks=28))
        self.assertFalse(validation.ok)

    def test_the_report_plan_is_bound_by_digest(self):
        report = report_for()
        report["plan_digest"] = "0" * 64
        validation = validate_report(report, plan(tasks=29))
        self.assertIn("plan_digest_mismatch", validation.problems)


class VerdictTests(unittest.TestCase):
    def test_a_well_formed_signed_run_is_supported(self):
        verdict = assess(report_for(), plan=plan(tasks=29),
                         analysis=manifest())
        self.assertEqual(verdict["verdict"], "supported")
        self.assertEqual(verdict["evidence_class"], "confirmatory")
        self.assertEqual(verdict["problems"], [])

    def test_an_invalid_report_is_never_supported(self):
        report = report_for()
        report["per_task"].append(copy.deepcopy(report["per_task"][0]))
        verdict = assess(report, plan=plan(tasks=29), analysis=manifest())
        self.assertEqual(verdict["verdict"], "invalid_report")
        self.assertEqual(verdict["evidence_class"], "invalid")
        self.assertIn("task_id_duplicated", verdict["problems"])

    def test_an_exploratory_input_cannot_be_promoted(self):
        report = build_report(
            plan(tasks=29),
            outcomes(29, e_solves={f"t{i}" for i in range(20)}),
            evidence_class="exploratory")
        verdict = assess(report, plan=plan(tasks=29), analysis=manifest())
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertEqual(verdict["evidence_class"], "exploratory")
        self.assertIn("input_evidence_not_confirmatory", verdict["problems"])

    def test_a_missing_analysis_manifest_is_not_confirmatory(self):
        verdict = assess(report_for(), plan=plan(tasks=29))
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertEqual(verdict["evidence_class"], "exploratory")
        self.assertIn("analysis_manifest_missing", verdict["problems"])

    def test_a_post_hoc_preregistration_is_not_confirmatory(self):
        late = manifest(registered_at="2026-03-01T00:00:00Z",
                        first_evaluation="2026-02-01T00:00:00Z")
        verdict = assess(report_for(), plan=plan(tasks=29), analysis=late)
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertIn("preregistration_not_before_evaluation",
                      verdict["problems"])

    def test_lineage_leakage_is_not_confirmatory(self):
        leaked = manifest(training=("lin-h",))
        verdict = assess(report_for(), plan=plan(tasks=29), analysis=leaked)
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertIn("lineage_leakage", verdict["problems"])

    def test_a_mismatched_analysis_protocol_is_refused(self):
        other = manifest(protocol_digest="9" * 64)
        verdict = assess(report_for(), plan=plan(tasks=29), analysis=other)
        self.assertIn("analysis_protocol_mismatch", verdict["problems"])

    def test_a_component_arm_beating_e_is_reported(self):
        rows = outcomes(29, e_solves={f"t{i}" for i in range(10)},
                        b_solves={f"t{i}" for i in range(20)})
        report = build_report(plan(tasks=29), rows,
                              evidence_class="confirmatory")
        verdict = assess(report, plan=plan(tasks=29), analysis=manifest())
        # The contrast is E minus B; a negative delta means B solved more.
        self.assertLess(
            verdict["component_contrasts"]["B"]["delta"], 0)


class DesignMappingTests(unittest.TestCase):
    def test_b_must_be_memory_not_any_singleton(self):
        design = (
            ArmConfiguration(arm="A", label="bare"),
            ArmConfiguration(arm="B", label="skills", skills=True),
            ArmConfiguration(arm="C", label="memory", memory=True),
            ArmConfiguration(arm="D", label="procedures", procedures=True),
            FIVE_ARM_DESIGN[4],
        )
        with self.assertRaisesRegex(CampaignError,
                                    "arm_component_mapping_invalid"):
            validate_design(design)

    def test_the_declared_design_still_validates(self):
        validate_design(FIVE_ARM_DESIGN)


if __name__ == "__main__":
    unittest.main()
