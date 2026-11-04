"""SIS v3.5.1 PR-04: report validation is total over untrusted input.

A report is a JSON document produced by someone else. Validation must
therefore be a *function* from every shape that document can take to a
documented result — never an exception. The v3.5.0 validator raised
``OverflowError`` on a 400-digit ``wall_seconds`` and ``AttributeError``
on a non-mapping ``governed`` block; ``assess`` raised ``TypeError`` on a
``per_task`` list of integers.

These tests are property-based (Hypothesis) plus explicit mutation of a
valid report, so a regression in any branch is caught even if nobody
thinks to write the matching example.
"""
from __future__ import annotations

import copy
import unittest

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sis.v3.five_arm import (
    ARMS,
    _recompute_metrics,
    assess,
    build_report,
    validate_report,
)
from tests.v3 import five_arm_testkit as kit
from tests.v3.test_v340_five_arm import manifest, plan

VERDICTS = {
    "invalid_report", "invalid_holdout", "regressed", "no_evidence",
    "underpowered", "no_advantage_after_cost", "supported",
}

TASKS = 29
CAMPAIGN = plan(tasks=TASKS)

json_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(), st.floats(),
    st.text(max_size=32), st.just(float("nan")), st.just(float("inf")),
    st.just(10 ** 400),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=8), children, max_size=3),
    ),
    max_leaves=6,
)
documents = st.one_of(
    json_values,
    st.dictionaries(st.text(max_size=10), json_values, max_size=6),
    st.builds(dict, per_task=st.one_of(
        st.none(), st.lists(json_values, max_size=3), json_values)),
)


def _signed_report():
    campaign = CAMPAIGN
    authorization = kit.experiment_authorization(campaign)
    rows = []
    for index, task in enumerate(campaign.task_ids):
        arms = {}
        for arm in ARMS:
            # A solves none; E solves 20. The honest, fully signed
            # baseline is a supported verdict, so a mutation that leaves
            # it supported is a real failure of the validator.
            solved = arm == "E" and index < 20
            result = "pass" if solved else "fail"
            receipt = kit.receipt_for(task, arm, result)
            arms[arm] = __import__(
                "sis.v3.five_arm", fromlist=["ArmOutcome"]).ArmOutcome(
                    arm=arm, valid_solve=solved, tokens=1000,
                    wall_seconds=10.0, tool_calls=5, receipt=receipt,
                    measurement=kit.measurement_for(
                        task, arm, result, campaign=campaign,
                        authorization=authorization, receipt=receipt))
        rows.append((task, arms))
    return build_report(campaign, rows, evidence_class="confirmatory")


def _verdict(document):
    """The full-chain assessment a real caller would run."""
    return assess(
        document, plan=CAMPAIGN, analysis=manifest(),
        receipt_authority=kit.receipt_authority(),
        trusted_analysis_keys=kit.trusted_analysis_keys(),
        trusted_timestamp_keys=kit.trusted_timestamp_keys(),
        experiment_authorization=kit.experiment_authorization(CAMPAIGN))


class TotalityTests(unittest.TestCase):
    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(document=documents)
    def test_validate_report_never_raises(self, document):
        result = validate_report(document, CAMPAIGN)
        self.assertIsInstance(result.problems, tuple)
        self.assertIsInstance(result.ok, bool)

    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(document=documents)
    def test_assess_never_raises(self, document):
        verdict = assess(document, plan=CAMPAIGN)
        self.assertIn(verdict["verdict"], VERDICTS)
        self.assertEqual(verdict["verdict"], "invalid_report")

    def test_the_specific_shapes_that_used_to_crash(self):
        cases = {
            "none": None,
            "list": [],
            "string": "not a report",
            "per_task of ints": {"per_task": [1, 2, 3]},
            "governed list": {"per_task": [], "governed": []},
            "governed none": {"per_task": [], "governed": None},
            "plan list": {"per_task": [], "plan": []},
            "rows without arms": {"per_task": [{"task_id": "t0"}]},
        }
        for label, document in cases.items():
            with self.subTest(label):
                self.assertFalse(validate_report(document, CAMPAIGN).ok)
                self.assertEqual(
                    assess(document, plan=CAMPAIGN)["verdict"],
                    "invalid_report")

    def test_an_extreme_integer_is_rejected_not_raised(self):
        # A 400-digit integer is a valid Python int and a finite number,
        # so it is not "invalid" — but it is over any budget, and a
        # report that claims otherwise is rejected rather than crashing.
        report = _signed_report()
        report["per_task"][0]["arms"]["A"]["wall_seconds"] = 10 ** 400
        validation = validate_report(report, CAMPAIGN)
        self.assertFalse(validation.ok)
        self.assertIn("budget_flag_mismatch:t0/A", validation.problems)

    def test_non_finite_numbers_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            report = _signed_report()
            report["per_task"][0]["arms"]["A"]["wall_seconds"] = value
            validation = validate_report(report, CAMPAIGN)
            self.assertIn("wall_seconds_invalid:t0/A", validation.problems)

    def test_a_finite_wall_time_whose_milliseconds_overflow_is_rejected(self):
        # 1e308 is finite, so it passes the finiteness check, but its
        # millisecond value is infinite and ``math.floor`` would raise.
        report = _signed_report()
        report["per_task"][0]["arms"]["A"]["wall_seconds"] = 1e308
        validation = validate_report(report, CAMPAIGN,
                                     receipt_authority=kit.receipt_authority())
        self.assertFalse(validation.ok)
        self.assertIn("measurement_wall_mismatch:t0/A", validation.problems)

    def test_boolean_is_not_an_integer(self):
        report = _signed_report()
        report["per_task"][0]["arms"]["A"]["tokens"] = True
        validation = validate_report(report, CAMPAIGN)
        self.assertIn("tokens_invalid:t0/A", validation.problems)

    def test_a_boolean_schema_version_is_not_version_one(self):
        report = _signed_report()
        report["schema_version"] = True
        validation = validate_report(report, CAMPAIGN)
        self.assertIn("schema_version_invalid", validation.problems)

    def test_nested_nulls_do_not_crash(self):
        report = _signed_report()
        report["per_task"][0]["arms"]["A"]["receipt"] = {
            "receipt_id": None, "task_id": None}
        validation = validate_report(report, CAMPAIGN)
        self.assertFalse(validation.ok)
        self.assertIn("receipt_untrusted:t0/A:receipt_malformed",
                      validation.problems)

    def test_a_string_replacing_a_number_is_rejected(self):
        report = _signed_report()
        report["per_task"][0]["arms"]["A"]["tokens"] = "1000"
        validation = validate_report(report, CAMPAIGN)
        self.assertIn("tokens_invalid:t0/A", validation.problems)

    def test_duplicate_task_records_are_rejected(self):
        report = _signed_report()
        report["per_task"].append(copy.deepcopy(report["per_task"][0]))
        validation = validate_report(report, CAMPAIGN)
        self.assertIn("task_id_duplicated", validation.problems)

    def test_a_missing_arm_configuration_is_rejected(self):
        report = _signed_report()
        del report["per_task"][2]["arms"]["D"]
        validation = validate_report(report, CAMPAIGN)
        self.assertIn("arm_set_mismatch:t2", validation.problems)

    def test_an_inconsistent_schema_version_is_rejected(self):
        report = _signed_report()
        report["schema_version"] = 2
        validation = validate_report(report, CAMPAIGN)
        self.assertIn("schema_version_invalid", validation.problems)

    def test_mutating_any_leaf_fails_closed(self):
        """Every single-field mutation either invalidates or stays safe."""
        baseline = _signed_report()
        baseline_verdict = _verdict(baseline)
        self.assertEqual(baseline_verdict["verdict"], "supported",
                         baseline_verdict["problems"])
        bad_values = [None, True, -1, float("nan"), [], "x"]
        paths = list(_leaf_paths(baseline))
        self.assertGreater(len(paths), 50)
        # Sample the leaf space: the point is breadth of shape, and the
        # full cross-product costs minutes of Ed25519 verification.
        paths = paths[::max(1, len(paths) // 30)]
        for path in paths:
            for bad in bad_values:
                mutated = copy.deepcopy(baseline)
                original = _get(mutated, path)
                if original == bad and type(original) is type(bad):
                    continue
                _set(mutated, path, bad)
                # Recompute the aggregate so the mutation is the only
                # inconsistency the validator could notice.
                if "per_task" in path:
                    try:
                        mutated["budget_exceeded"] = sum(
                            1 for row in mutated["per_task"]
                            for arm in ARMS
                            if isinstance(row.get("arms"), dict)
                            and isinstance(row["arms"].get(arm), dict)
                            and row["arms"][arm].get(
                                "budget_exceeded") is True)
                        mutated["governed"]["metrics"] = _recompute_metrics(
                            mutated["per_task"])
                    except Exception:  # noqa: BLE001 - the mutation broke it
                        pass
                with self.subTest(path=path, bad=repr(bad)):
                    verdict = _verdict(mutated)
                    self.assertIn(verdict["verdict"], VERDICTS)
                    if path[-1] not in ("abstained", "negative_transfer",
                                        "integrity_failures"):
                        self.assertNotEqual(
                            verdict["verdict"], "supported",
                            f"{path} = {bad!r} still supported")

    def test_holdout_disjoint_must_be_a_boolean(self):
        for value in (None, -1, "yes", [], 1.0):
            report = _signed_report()
            report["holdout_disjoint"] = value
            validation = validate_report(report, CAMPAIGN)
            self.assertIn("holdout_disjoint_invalid", validation.problems,
                          repr(value))
            self.assertNotEqual(_verdict(report)["verdict"], "supported")

    def test_a_malformed_now_is_invalid_not_raised(self):
        authority = kit.receipt_authority()
        authorization = kit.experiment_authorization(CAMPAIGN)
        for value in ("not-a-time", 123, None):
            validation = validate_report(
                _signed_report(), CAMPAIGN, receipt_authority=authority,
                experiment_authorization=authorization, now=value)
            if value is None:
                self.assertTrue(validation.ok, validation.problems)
                continue
            self.assertFalse(validation.ok)
            self.assertTrue(
                any("validity_error" in problem
                    for problem in validation.problems),
                validation.problems[:5])

    def test_validation_distinguishes_structure_from_authentication(self):
        # Structural validation passes without an authority...
        structural = validate_report(_signed_report(), CAMPAIGN)
        self.assertTrue(structural.ok, structural.problems)
        self.assertFalse(structural.authenticated)
        self.assertIsNone(structural.verified)
        # ...and authentication is what a caller must check before
        # publishing.
        authenticated = validate_report(
            _signed_report(), CAMPAIGN,
            receipt_authority=kit.receipt_authority(),
            experiment_authorization=kit.experiment_authorization(CAMPAIGN))
        self.assertTrue(authenticated.authenticated)
        self.assertIsNotNone(authenticated.verified)


def _leaf_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaf_paths(item, prefix + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _leaf_paths(item, prefix + (index,))
    else:
        yield prefix


def _get(document, path):
    target = document
    for step in path:
        target = target[step]
    return target


def _set(document, path, value):
    target = document
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value


if __name__ == "__main__":
    unittest.main()
