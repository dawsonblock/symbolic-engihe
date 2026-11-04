"""SIS v3.5.1 PR-01/PR-02: authenticated trial evidence.

Every test here is a forgery attempt. The invariant under test is the
one the release exists for:

    a valid signature is not enough. The signature must be valid for the
    exact trial, authorized model, experiment arm, task, outcome and
    measurement being claimed.

The "honest" fixture is a real signed run (experiment authorization ->
per-trial measurement -> evaluator receipt). Each test breaks exactly one
link of that chain and asserts the assessment refuses to promote it.
"""
from __future__ import annotations

import copy
import unittest

from sis.v3.contracts import EvaluatorReceiptV2
from sis.v3.evidence_binding import sign_receipt
from sis.v3.five_arm import (
    ARMS,
    AnalysisManifest,
    ArmOutcome,
    _holm_adjusted,
    _recompute_metrics,
    assess,
    authorize_experiment,
    build_report,
    validate_report,
)
from sis.v3.statistical_power import LineageRegistry, RepositoryLineage
from sis.v3.trial_evidence import (
    TrialEvidenceError,
    TrialMeasurementV1,
)
from tests.v3 import five_arm_testkit as kit
from tests.v3.test_v340_five_arm import manifest, plan

TASKS = 29


def signed_rows(campaign, authorization, *, a_solves=(), e_solves=(),
                tokens=1000, wall_seconds=10.0, tool_calls=5,
                receipt_seed=kit.EVALUATOR_SEED,
                receipt_key_id=kit.EVALUATOR_KEY_ID,
                measurement_seed=kit.EVALUATOR_SEED,
                measurement_key_id=kit.EVALUATOR_KEY_ID):
    rows = []
    for index in range(len(campaign.task_ids)):
        task = campaign.task_ids[index]
        solved = {"A": task in a_solves, "B": False, "C": False, "D": False,
                  "E": task in e_solves}
        arms = {}
        for arm in ARMS:
            result = "pass" if solved[arm] else "fail"
            receipt = kit.receipt_for(
                task, arm, result, seed=receipt_seed,
                signer_key_id=receipt_key_id)
            arms[arm] = ArmOutcome(
                arm=arm, valid_solve=solved[arm], tokens=tokens,
                wall_seconds=wall_seconds, tool_calls=tool_calls,
                receipt=receipt,
                measurement=kit.measurement_for(
                    task, arm, result, campaign=campaign,
                    authorization=authorization, receipt=receipt,
                    tokens_in=tokens // 2, tokens_out=tokens - tokens // 2,
                    wall_seconds_milli=int(wall_seconds * 1000),
                    tool_calls=tool_calls,
                    seed=measurement_seed,
                    signer_key_id=measurement_key_id))
        rows.append((task, arms))
    return rows


def supported_rows(campaign, authorization):
    """A fully signed run whose honest verdict is ``supported``."""
    rows = []
    for index, task in enumerate(campaign.task_ids):
        arms = {}
        for arm in ARMS:
            solved = arm == "E" and index < 20
            result = "pass" if solved else "fail"
            receipt = kit.receipt_for(task, arm, result)
            arms[arm] = ArmOutcome(
                arm=arm, valid_solve=solved, tokens=1000,
                wall_seconds=10.0, tool_calls=5, receipt=receipt,
                measurement=kit.measurement_for(
                    task, arm, result, campaign=campaign,
                    authorization=authorization, receipt=receipt))
        rows.append((task, arms))
    return rows


class ChainFixture(unittest.TestCase):
    """An honest, fully authenticated run that individual tests tamper with."""

    def setUp(self):
        self.campaign = plan(tasks=TASKS)
        self.authorization = kit.experiment_authorization(self.campaign)
        self.authority = kit.receipt_authority()
        self.rows = signed_rows(
            self.campaign, self.authorization,
            a_solves={f"t{i}" for i in range(20)}, e_solves=set())
        self.report = build_report(self.campaign, self.rows,
                                   evidence_class="confirmatory")

    def verdict(self, report=None, *, authority=None, authorization=None,
                analysis=None, now=None, allow_expired=False):
        return assess(
            self.report if report is None else report,
            plan=self.campaign,
            analysis=manifest() if analysis is None else analysis,
            receipt_authority=self.authority if authority is None
            else authority,
            trusted_analysis_keys=kit.trusted_analysis_keys(),
            trusted_timestamp_keys=kit.trusted_timestamp_keys(),
            experiment_authorization=(self.authorization
                                      if authorization is None
                                      else authorization),
            now=now, allow_expired=allow_expired)

    def assertRefused(self, verdict, reason: str):
        self.assertNotIn(verdict["verdict"], ("supported",),
                         verdict["problems"])
        self.assertNotEqual(verdict["evidence_class"], "confirmatory")
        self.assertTrue(
            any(reason in problem for problem in verdict["problems"]),
            f"{reason} not in {verdict['problems'][:8]}")

    def row(self, task, arm):
        for row in self.report["per_task"]:
            if row["task_id"] == task:
                return row["arms"][arm]
        raise AssertionError(task)

    def outcome(self, task, arm):
        for candidate, arms in self.rows:
            if candidate == task:
                return arms[arm]
        raise AssertionError(task)

    def rebuilt(self, changes):
        rows = []
        for task, arms in self.rows:
            arms = dict(arms)
            for (changed_task, changed_arm), outcome in changes.items():
                if changed_task == task:
                    arms[changed_arm] = outcome
            rows.append((task, arms))
        return build_report(self.campaign, rows,
                            evidence_class="confirmatory")

    def replace_receipt(self, task, arm, receipt, **measurement):
        original = self.outcome(task, arm)
        return self.rebuilt({(task, arm): ArmOutcome(
            arm=arm, valid_solve=original.valid_solve,
            tokens=original.tokens, wall_seconds=original.wall_seconds,
            tool_calls=original.tool_calls, receipt=receipt,
            measurement=kit.measurement_for(
                task, arm, receipt["result"], campaign=self.campaign,
                authorization=self.authorization, receipt=receipt,
                **measurement))})


class SupportedChainFixture(ChainFixture):
    """An honest run that is ``supported`` before a test tampers with it."""

    def setUp(self):
        super().setUp()
        self.rows = supported_rows(self.campaign, self.authorization)
        self.report = build_report(self.campaign, self.rows,
                                   evidence_class="confirmatory")


class AttributionTests(ChainFixture):
    """PR-01: evidence must be bound to the arm that produced it."""

    def test_the_honest_run_is_a_real_baseline_win(self):
        # A solves 20/29 and E solves 0/29, so the honest verdict is a
        # regression. This is the fixture the swap attack inverts.
        verdict = self.verdict()
        self.assertEqual(verdict["verdict"], "regressed")
        self.assertEqual(verdict["solve_rate"]["A"], 20 / 29)
        self.assertEqual(verdict["solve_rate"]["E"], 0.0)

    def test_swapping_two_arms_genuine_outcomes_is_refused(self):
        swapped = []
        for task, arms in self.rows:
            exchanged = dict(arms)
            exchanged["A"], exchanged["E"] = arms["E"], arms["A"]
            swapped.append((task, exchanged))
        report = build_report(self.campaign, swapped,
                              evidence_class="confirmatory")
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_arm_mismatch")
        self.assertRefused(verdict, "measurement_arm_config_mismatch")

    def test_swapping_a_receipt_and_measurement_together_is_refused(self):
        report = copy.deepcopy(self.report)
        a = report["per_task"][0]["arms"]["A"]
        e = report["per_task"][0]["arms"]["E"]
        a["receipt"], e["receipt"] = e["receipt"], a["receipt"]
        a["receipt_id"], e["receipt_id"] = e["receipt_id"], a["receipt_id"]
        a["measurement"], e["measurement"] = e["measurement"], a["measurement"]
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_arm_mismatch")

    def test_a_measurement_for_another_experiment_is_refused(self):
        other = kit.experiment_authorization(
            self.campaign, experiment_id="exp-other")
        report = copy.deepcopy(self.report)
        task, arm = "t0", "E"
        receipt = kit.receipt_for(task, arm, "fail")
        report["per_task"][0]["arms"]["E"]["measurement"] = \
            kit.measurement_for(task, arm, "fail", campaign=self.campaign,
                                authorization=other, receipt=receipt)
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_experiment_mismatch")
        self.assertRefused(verdict, "measurement_authorization_mismatch")

    def test_a_measurement_for_another_task_is_refused(self):
        report = copy.deepcopy(self.report)
        task, arm = "t0", "E"
        receipt = kit.receipt_for(task, arm, "fail")
        report["per_task"][0]["arms"]["E"]["measurement"] = \
            kit.measurement_for("t1", arm, "fail", campaign=self.campaign,
                                authorization=self.authorization,
                                receipt=receipt)
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_task_mismatch")

    def test_a_measurement_for_an_unauthorized_task_is_refused(self):
        authorization = kit.experiment_authorization(
            self.campaign,
            task_digests={task: kit.task_digest(task, f"content:{task}")
                          for task in self.campaign.task_ids if task != "t0"})
        verdict = self.verdict(authorization=authorization)
        self.assertRefused(verdict, "experiment_task_set_mismatch")

    def test_a_measurement_for_another_model_is_refused(self):
        report = copy.deepcopy(self.report)
        task, arm = "t0", "E"
        receipt = kit.receipt_for(task, arm, "fail")
        measurement = kit.measurement_for(
            task, arm, "fail", campaign=self.campaign,
            authorization=self.authorization, receipt=receipt)
        record = TrialMeasurementV1.from_dict(measurement)
        from dataclasses import replace
        forged = replace(record, model_digest="9" * 64).sign(
            kit.EVALUATOR_SEED, kit.EVALUATOR_KEY_ID)
        report["per_task"][0]["arms"]["E"]["measurement"] = forged.to_dict()
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_model_mismatch")

    def test_an_altered_arm_configuration_digest_is_refused(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["measurement"][
            "arm_config_digest"] = "0" * 64
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_untrusted")

    def test_a_duplicated_trial_is_refused(self):
        report = copy.deepcopy(self.report)
        report["per_task"][1]["arms"]["E"]["measurement"]["trial_id"] = \
            report["per_task"][0]["arms"]["E"]["measurement"]["trial_id"]
        # Re-sign so only the duplication itself is wrong.
        record = TrialMeasurementV1.from_dict(
            report["per_task"][1]["arms"]["E"]["measurement"])
        report["per_task"][1]["arms"]["E"]["measurement"] = record.sign(
            kit.EVALUATOR_SEED, kit.EVALUATOR_KEY_ID).to_dict()
        validation = validate_report(
            report, self.campaign, receipt_authority=self.authority,
            experiment_authorization=self.authorization)
        self.assertIn("measurement_duplicated", validation.problems)

    def test_a_replayed_receipt_digest_is_refused(self):
        report = copy.deepcopy(self.report)
        report["per_task"][1]["arms"]["E"]["measurement"][
            "receipt_digest"] = report["per_task"][0]["arms"]["E"][
                "measurement"]["receipt_digest"]
        record = TrialMeasurementV1.from_dict(
            report["per_task"][1]["arms"]["E"]["measurement"])
        report["per_task"][1]["arms"]["E"]["measurement"] = record.sign(
            kit.EVALUATOR_SEED, kit.EVALUATOR_KEY_ID).to_dict()
        validation = validate_report(
            report, self.campaign, receipt_authority=self.authority,
            experiment_authorization=self.authorization)
        self.assertIn("receipt_replayed", validation.problems)

    def test_a_mismatched_authorization_identifier_is_refused(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["measurement"][
            "authorization_id"] = "auth-somewhere-else"
        record = TrialMeasurementV1.from_dict(
            report["per_task"][0]["arms"]["E"]["measurement"])
        report["per_task"][0]["arms"]["E"]["measurement"] = record.sign(
            kit.EVALUATOR_SEED, kit.EVALUATOR_KEY_ID).to_dict()
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_authorization_id_mismatch")

    def test_a_measurement_naming_another_receipt_is_refused(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["measurement"]["receipt_id"] = \
            "rcpt-elsewhere"
        record = TrialMeasurementV1.from_dict(
            report["per_task"][0]["arms"]["E"]["measurement"])
        report["per_task"][0]["arms"]["E"]["measurement"] = record.sign(
            kit.EVALUATOR_SEED, kit.EVALUATOR_KEY_ID).to_dict()
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_receipt_id_mismatch")

    def test_a_report_without_measurements_is_never_supported(self):
        report = copy.deepcopy(self.report)
        for row in report["per_task"]:
            for arm in ARMS:
                row["arms"][arm]["measurement"] = None
        verdict = self.verdict(report)
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertIn("measurement_missing", verdict["problems"])
        self.assertFalse(verdict["measurements_verified"])


class MeasurementTests(ChainFixture):
    """PR-02: resource measurements are signed, not declared."""

    def test_authenticated_tokens_cannot_be_rewritten(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["tokens"] = 1
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_tokens_mismatch")

    def test_a_budget_flag_cannot_be_cleared(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["budget_exceeded"] = True
        verdict = self.verdict(report)
        self.assertRefused(verdict, "budget_flag_mismatch")

    def test_a_budget_flag_cannot_be_faked_over_budget(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["budget_exceeded"] = True
        report["per_task"][0]["arms"]["E"]["valid_solve"] = False
        report["per_task"][0]["arms"]["E"]["outcome"] = "fail"
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_budget_mismatch")

    def test_execution_duration_cannot_be_rewritten(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["wall_seconds"] = 0.001
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_wall_mismatch")

    def test_a_half_millisecond_wall_time_is_not_a_mismatch(self):
        # Banker's rounding turns x.xxx5 into the even millisecond, which
        # would reject an honest report whose measurement rounded up.
        campaign = self.campaign
        authorization = self.authorization
        rows = []
        for index, task in enumerate(campaign.task_ids):
            arms = {}
            for arm in ARMS:
                solved = arm == "E" and index < 20
                result = "pass" if solved else "fail"
                receipt = kit.receipt_for(task, arm, result)
                arms[arm] = ArmOutcome(
                    arm=arm, valid_solve=solved, tokens=1000,
                    wall_seconds=10.0005, tool_calls=5, receipt=receipt,
                    measurement=kit.measurement_for(
                        task, arm, result, campaign=campaign,
                        authorization=authorization, receipt=receipt,
                        wall_seconds_milli=10_001))
            rows.append((task, arms))
        report = build_report(campaign, rows, evidence_class="confirmatory")
        verdict = self.verdict(report)
        self.assertFalse(
            any("measurement_wall_mismatch" in problem
                for problem in verdict["problems"]),
            verdict["problems"][:8])

    def test_tool_counts_cannot_be_rewritten(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["tool_calls"] = 0
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_tool_calls_mismatch")

    def test_removing_resource_fields_is_refused(self):
        report = copy.deepcopy(self.report)
        for field in ("tokens", "wall_seconds", "tool_calls"):
            del report["per_task"][0]["arms"]["E"][field]
        verdict = self.verdict(report)
        self.assertRefused(verdict, "tokens_invalid")

    def test_conflicting_totals_cannot_be_signed(self):
        measurement = dict(self.report["per_task"][0]["arms"]["E"][
            "measurement"])
        measurement["tokens_total"] = measurement["tokens_total"] + 1
        with self.assertRaises(TrialEvidenceError) as caught:
            TrialMeasurementV1.from_dict(measurement)
        self.assertEqual(caught.exception.reason,
                         "tokens_total_inconsistent")

    def test_negative_counters_are_refused(self):
        measurement = dict(self.report["per_task"][0]["arms"]["E"][
            "measurement"])
        measurement["tokens_in"] = -1
        measurement["tokens_total"] = measurement["tokens_in"] + \
            measurement["tokens_out"]
        with self.assertRaises(TrialEvidenceError):
            TrialMeasurementV1.from_dict(measurement)

    def test_non_finite_and_non_integer_counters_are_refused(self):
        for value in (float("nan"), float("inf"), 1.5, True, "1000"):
            measurement = dict(self.report["per_task"][0]["arms"]["E"][
                "measurement"])
            measurement["tokens_total"] = value
            with self.assertRaises(TrialEvidenceError):
                TrialMeasurementV1.from_dict(measurement)

    def test_a_budget_change_after_execution_is_detected(self):
        # The run is measured against the plan's budget. Shrinking the
        # budget after the fact makes the signed measurement over-budget,
        # and the report's flag then disagrees with it.
        tighter = plan(tasks=TASKS, max_tokens_per_task=100)
        verdict = assess(
            self.report, plan=tighter, analysis=manifest(),
            receipt_authority=self.authority,
            trusted_analysis_keys=kit.trusted_analysis_keys(),
            trusted_timestamp_keys=kit.trusted_timestamp_keys(),
            experiment_authorization=self.authorization)
        self.assertNotEqual(verdict["verdict"], "supported")
        self.assertEqual(verdict["verdict"], "invalid_report")

    def test_recomputed_aggregates_after_tampering_are_refused(self):
        report = copy.deepcopy(self.report)
        for row in report["per_task"]:
            arm = row["arms"]["A"]
            if arm["valid_solve"]:
                arm["tokens"] = self.campaign.max_tokens_per_task + 1
                arm["budget_exceeded"] = True
                arm["valid_solve"] = False
                arm["outcome"] = "fail"
        report["budget_exceeded"] = sum(
            1 for row in report["per_task"] for arm in ARMS
            if row["arms"][arm]["budget_exceeded"])
        report["governed"]["metrics"] = _recompute_metrics(
            report["per_task"])
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_tokens_mismatch")

    def test_an_unmetered_run_cannot_support_a_claim(self):
        rows = []
        for task, arms in self.rows:
            arms = dict(arms)
            e = arms["E"]
            measurement = kit.measurement_for(
                task, "E", "pass", campaign=self.campaign,
                authorization=self.authorization, receipt=e.receipt,
                termination_reason="unmetered")
            arms["E"] = ArmOutcome(
                arm="E", valid_solve=True, tokens=e.tokens,
                wall_seconds=e.wall_seconds, tool_calls=e.tool_calls,
                receipt=e.receipt, measurement=measurement)
            rows.append((task, arms))
        report = build_report(self.campaign, rows,
                              evidence_class="confirmatory")
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_unmetered")


class SignerAuthorityTests(ChainFixture):
    """PR-03: expiry, revocation and role are part of the decision."""

    def test_an_unknown_evaluator_key_is_refused(self):
        rows = signed_rows(
            self.campaign, self.authorization,
            a_solves={f"t{i}" for i in range(20)},
            receipt_seed=b"\x99" * 32,
            measurement_seed=b"\x99" * 32)
        report = build_report(self.campaign, rows,
                              evidence_class="confirmatory")
        verdict = self.verdict(report)
        self.assertRefused(verdict, "receipt_untrusted")
        self.assertRefused(verdict, "measurement_untrusted")

    def test_a_measurement_signed_in_the_wrong_role_is_refused(self):
        report = copy.deepcopy(self.report)
        measurement = TrialMeasurementV1.from_dict(
            report["per_task"][0]["arms"]["E"]["measurement"])
        from dataclasses import replace
        forged = replace(measurement, signer_key_id=kit.ANALYSIS_KEY_ID)
        forged = forged.sign(kit.ANALYSIS_SEED, kit.ANALYSIS_KEY_ID)
        report["per_task"][0]["arms"]["E"]["measurement"] = forged.to_dict()
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_untrusted_signer")

    def test_a_replaced_trust_registry_is_refused(self):
        other = kit.receipt_authority()
        other._evaluator.clear()
        other.add_evaluator_key("some-other-key",
                                kit.evaluation_public_hex())
        verdict = self.verdict(authority=other)
        self.assertRefused(verdict, "measurement_untrusted_signer")

    def test_a_revoked_evaluator_is_refused(self):
        authority = kit.receipt_authority(
            revocation_provider=lambda: ({kit.EVALUATOR_KEY_ID}, set()))
        verdict = self.verdict(authority=authority)
        self.assertRefused(verdict, "signer_revoked")

    def test_a_revoked_receipt_digest_is_refused(self):
        revoked = self.report["per_task"][0]["arms"]["E"]["receipt_id"]
        from sis.v3.contracts import EvaluatorReceiptV2
        digest = EvaluatorReceiptV2.from_dict(
            self.report["per_task"][0]["arms"]["E"]["receipt"]).digest
        authority = kit.receipt_authority(
            revocation_provider=lambda: (set(), {digest}))
        verdict = self.verdict(authority=authority)
        self.assertRefused(verdict, "evidence_revoked")
        self.assertIn("E", revoked)

    def test_a_signing_key_expired_before_the_run_is_refused(self):
        authority = kit.receipt_authority(key_validity={
            kit.EVALUATOR_KEY_ID: ("2026-01-01T00:00:00Z",
                                   "2026-01-15T00:00:00Z")})
        verdict = self.verdict(authority=authority)
        self.assertRefused(verdict, "signing_key_expired")

    def test_a_signing_key_not_yet_valid_at_the_run_is_refused(self):
        authority = kit.receipt_authority(key_validity={
            kit.EVALUATOR_KEY_ID: ("2026-06-01T00:00:00Z",
                                   "2027-01-01T00:00:00Z")})
        verdict = self.verdict(authority=authority)
        self.assertRefused(verdict, "signing_key_not_yet_valid")

    def test_an_expired_authorization_is_refused(self):
        authorization = kit.experiment_authorization(
            self.campaign, issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-03-01T00:00:00Z")
        verdict = self.verdict(authorization=authorization,
                               now="2026-04-01T00:00:00Z")
        self.assertRefused(verdict, "experiment_authorization_invalid:"
                                    "evidence_expired")

    def test_historically_valid_evidence_is_accepted_under_policy(self):
        # Same expired window, but the evidence was signed inside it and
        # the operator explicitly accepts historically valid evidence.
        authorization = kit.experiment_authorization(
            self.campaign, issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-03-01T00:00:00Z")
        verdict = self.verdict(authorization=authorization,
                               now="2026-04-01T00:00:00Z",
                               allow_expired=True)
        self.assertNotIn("experiment_authorization_invalid:evidence_expired",
                         verdict["problems"])

    def test_an_untampered_timestamp_is_required(self):
        report = copy.deepcopy(self.report)
        report["per_task"][0]["arms"]["E"]["measurement"]["issued_at"] = \
            "2026-02-02T00:00:00Z"
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_untrusted")

    def test_a_missing_timestamp_is_malformed(self):
        report = copy.deepcopy(self.report)
        del report["per_task"][0]["arms"]["E"]["measurement"]["issued_at"]
        verdict = self.verdict(report)
        self.assertRefused(verdict, "measurement_malformed")

    def test_an_authorization_for_another_protocol_is_refused(self):
        from dataclasses import replace
        # Validly signed by the trusted experiment key, but for a
        # different protocol: the signature is real, the claim is not.
        authorization = replace(
            self.authorization, protocol_digest="b" * 64).sign(
                kit.EXPERIMENT_SEED, kit.EXPERIMENT_KEY_ID)
        verdict = self.verdict(authorization=authorization)
        self.assertRefused(verdict, "experiment_protocol_mismatch")

    def test_a_forged_authorization_signature_is_refused(self):
        from dataclasses import replace
        forged = replace(self.authorization, model_identity="other-model")
        verdict = self.verdict(authorization=forged)
        self.assertRefused(verdict, "experiment_authorization_untrusted")

    def test_an_authorization_signed_by_an_untrusted_key_is_refused(self):
        authorization = kit.experiment_authorization(
            self.campaign, seed=b"\x88" * 32)
        verdict = self.verdict(authorization=authorization)
        self.assertRefused(verdict, "experiment_authorization_untrusted")


class AuthorizationCommitmentTests(ChainFixture):
    """The authorization freezes the run's environment, criterion and suite."""

    def _resigned(self, task, arm, **changes):
        base = dict(kit.receipt_for(task, arm, "fail"))
        base.pop("evaluator_signature")
        base.update(changes)
        return sign_receipt(kit.EVALUATOR_SEED, **base).to_dict()

    def test_a_receipt_from_another_environment_is_refused(self):
        receipt = self._resigned("t0", "E", environment_digest="9" * 64)
        verdict = self.verdict(self.replace_receipt("t0", "E", receipt))
        self.assertRefused(verdict, "measurement_environment_mismatch")

    def test_a_receipt_from_another_criterion_is_refused(self):
        receipt = self._resigned("t0", "E", criterion_version="v2")
        verdict = self.verdict(self.replace_receipt("t0", "E", receipt))
        self.assertRefused(verdict, "measurement_criterion_mismatch")

    def test_a_receipt_from_another_test_suite_is_refused(self):
        receipt = self._resigned("t0", "E", test_suite_commitment="2" * 64)
        verdict = self.verdict(self.replace_receipt("t0", "E", receipt))
        self.assertRefused(verdict, "measurement_test_suite_mismatch")

    def test_a_dependent_receipt_is_not_an_independent_trial(self):
        dependency = EvaluatorReceiptV2.from_dict(
            kit.receipt_for("t0", "A", "fail")).digest
        receipt = self._resigned("t0", "E", independence="dependent",
                                 dependency_receipt_digest=dependency)
        verdict = self.verdict(self.replace_receipt("t0", "E", receipt))
        self.assertRefused(verdict, "receipt_not_independent")


class StatusTests(ChainFixture):
    """The measurement status is richer than the receipt result."""

    def test_an_infrastructure_failure_blocks_a_claim(self):
        changes = {}
        for index in range(5):
            task = self.campaign.task_ids[index]
            original = self.outcome(task, "E")
            changes[(task, "E")] = ArmOutcome(
                arm="E", valid_solve=False, tokens=original.tokens,
                wall_seconds=original.wall_seconds,
                tool_calls=original.tool_calls, receipt=original.receipt,
                measurement=kit.measurement_for(
                    task, "E", "fail", campaign=self.campaign,
                    authorization=self.authorization,
                    receipt=original.receipt, status="error"))
        verdict = self.verdict(self.rebuilt(changes))
        self.assertEqual(verdict["verdict"], "no_evidence")
        self.assertIn("infrastructure_failure_present", verdict["problems"])
        self.assertEqual(verdict["infrastructure_failures"], 5)

    def test_a_limit_violation_is_valid_evidence_but_not_a_solve(self):
        task = self.campaign.task_ids[0]
        original = self.outcome(task, "E")
        outcome = ArmOutcome(
            arm="E", valid_solve=False, tokens=original.tokens,
            wall_seconds=original.wall_seconds,
            tool_calls=original.tool_calls, receipt=original.receipt,
            limit_violations=("wall_clock",),
            measurement=kit.measurement_for(
                task, "E", "fail", campaign=self.campaign,
                authorization=self.authorization, receipt=original.receipt,
                limit_violations=("wall_clock",)))
        verdict = self.verdict(self.rebuilt({(task, "E"): outcome}))
        self.assertNotEqual(verdict["verdict"], "invalid_report",
                            verdict["problems"])
        self.assertGreaterEqual(verdict["budget_exceeded"], 1)

    def test_a_partial_status_is_a_non_solve(self):
        task = self.campaign.task_ids[0]
        original = self.outcome(task, "E")
        outcome = ArmOutcome(
            arm="E", valid_solve=False, tokens=original.tokens,
            wall_seconds=original.wall_seconds,
            tool_calls=original.tool_calls, receipt=original.receipt,
            measurement=kit.measurement_for(
                task, "E", "fail", campaign=self.campaign,
                authorization=self.authorization, receipt=original.receipt,
                status="partial"))
        verdict = self.verdict(self.rebuilt({(task, "E"): outcome}))
        self.assertNotEqual(verdict["verdict"], "invalid_report",
                            verdict["problems"])


class StatisticalTests(SupportedChainFixture):
    """The family-wise correction is part of the decision."""

    def test_holm_step_down_is_monotone(self):
        adjusted = _holm_adjusted({"a": 0.005, "b": 0.02, "c": 0.9,
                                   "d": 0.04})
        self.assertAlmostEqual(adjusted["a"], 0.02)
        self.assertAlmostEqual(adjusted["b"], 0.06)
        self.assertAlmostEqual(adjusted["d"], 0.08)
        self.assertAlmostEqual(adjusted["c"], 0.9)

    def test_a_marginal_win_does_not_survive_the_correction(self):
        # 7 wins and 0 losses is p=0.015625 unadjusted; Holm across four
        # contrasts makes it 0.0625, which is not confirmatory.
        rows = []
        for index, task in enumerate(self.campaign.task_ids):
            arms = {}
            for arm in ARMS:
                solved = arm == "E" and index < 7
                result = "pass" if solved else "fail"
                receipt = kit.receipt_for(task, arm, result)
                arms[arm] = ArmOutcome(
                    arm=arm, valid_solve=solved, tokens=1000,
                    wall_seconds=10.0, tool_calls=5, receipt=receipt,
                    measurement=kit.measurement_for(
                        task, arm, result, campaign=self.campaign,
                        authorization=self.authorization, receipt=receipt))
            rows.append((task, arms))
        report = build_report(self.campaign, rows,
                              evidence_class="confirmatory")
        verdict = self.verdict(report)
        self.assertTrue(verdict["decisive_contrast"]["significant"])
        self.assertLessEqual(
            verdict["decisive_contrast"]["mcnemar_exact_p"], 0.05)
        self.assertGreater(verdict["holm_adjusted_p"]["E_vs_A"], 0.05)
        self.assertEqual(verdict["verdict"], "no_evidence")


class HistoricalEvidenceTests(SupportedChainFixture):
    def test_expired_receipts_are_accepted_under_the_historical_policy(self):
        verdict = self.verdict(now="2100-01-01T00:00:00Z",
                               allow_expired=True)
        self.assertEqual(verdict["verdict"], "supported", verdict["problems"])
        self.assertFalse(any("evidence_expired" in problem
                             for problem in verdict["problems"]))

    def test_expired_receipts_are_refused_by_default(self):
        verdict = self.verdict(now="2100-01-01T00:00:00Z")
        self.assertRefused(verdict, "evidence_expired")


class ChainConsistencyTests(SupportedChainFixture):
    def test_a_preregistration_for_another_protocol_is_refused(self):
        foreign = kit.preregistration(protocol_digest="b" * 64)
        authorization = authorize_experiment(
            self.campaign, experiment_id=kit.EXPERIMENT_ID,
            model_identity=kit.MODEL_IDENTITY,
            model_digest=kit.MODEL_DIGEST,
            task_digests=kit.default_task_digests(self.campaign),
            environment_digest=kit.ENVIRONMENT_DIGEST,
            criterion_version=kit.CRITERION_VERSION,
            test_suite_commitment=kit.TEST_SUITE_COMMITMENT,
            preregistration_digest=foreign.digest,
            issued_at=kit.ISSUED_AT, expires_at=kit.EXPIRES_AT,
            seed=kit.EXPERIMENT_SEED, key_id=kit.EXPERIMENT_KEY_ID)
        lineages = LineageRegistry()
        lineages.add(RepositoryLineage(
            registry_id="repo-1", lineage_id="lin-h", family_id="fam"))
        analysis = AnalysisManifest(
            protocol_digest=self.campaign.protocol.get("protocol_digest"),
            preregistration=foreign, lineages=lineages,
            first_evaluation_at="2026-02-01T00:00:00Z",
            holdout_repositories=("repo-1",)).sign(
                kit.ANALYSIS_SEED, kit.ANALYSIS_KEY_ID)
        # The authorization and the analysis both name the foreign
        # preregistration, so only the plan binding can catch it.
        rows = supported_rows(self.campaign, authorization)
        report = build_report(self.campaign, rows,
                              evidence_class="confirmatory")
        verdict = assess(
            report, plan=self.campaign, analysis=analysis,
            receipt_authority=self.authority,
            trusted_analysis_keys=kit.trusted_analysis_keys(),
            trusted_timestamp_keys=kit.trusted_timestamp_keys(),
            experiment_authorization=authorization)
        self.assertNotEqual(verdict["verdict"], "supported",
                            verdict["problems"])


class AuthorityPolicyTests(ChainFixture):
    def test_a_predicate_authority_fails_closed_on_falsy_returns(self):
        for value in (None, 0, "", []):
            validation = validate_report(
                self.report, self.campaign,
                receipt_authority=lambda record, v=value: v)
            self.assertFalse(validation.ok)
            self.assertTrue(any("receipt_rejected" in problem
                                for problem in validation.problems),
                            validation.problems[:3])


if __name__ == "__main__":
    unittest.main()
