"""Governed evaluation plane + end-to-end campaign (v3.3 M6/M9)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.governed_eval import (EvaluationPartition,
                                  assert_partition_disjoint,
                                  compute_metrics, preregister,
                                  required_sample_size)

REPO = Path(__file__).resolve().parents[2]


def _task(task_id, digest):
    return TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest=digest, base_commit="a1b2c3d",
        task_statement_digest="e" * 64, permitted_commands=("pytest",),
        isolation_profile="unverified_local", time_budget_seconds=60,
        token_budget=1000, tool_budget=10, actor_id="t",
        evaluator_task_ref=task_id)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + str(REPO)
    return env


class PartitionTests(unittest.TestCase):
    def test_overlap_and_empty_holdout_rejected(self):
        with self.assertRaises(ContractError):
            assert_partition_disjoint(EvaluationPartition(
                induction=(_task("i", "a" * 64),),
                holdout=(_task("h", "a" * 64),)))
        with self.assertRaisesRegex(ContractError, "holdout"):
            assert_partition_disjoint(EvaluationPartition(
                induction=(_task("i", "a" * 64),)))

    def test_disjoint_partition_passes(self):
        assert_partition_disjoint(EvaluationPartition(
            induction=(_task("i", "a" * 64),),
            development=(_task("d", "b" * 64),),
            holdout=(_task("h", "c" * 64),)))


class ProtocolTests(unittest.TestCase):
    def test_preregistration_freezes_digest(self):
        p = preregister(primary_metric="paired solved_delta E vs A",
                        method="mcnemar_exact", alpha=0.05,
                        min_effect=1.0, sample_size=8,
                        budget={"wall_seconds": 60})
        self.assertEqual(len(p["protocol_digest"]), 64)
        q = preregister(primary_metric="x", method="m", alpha=0.01,
                        min_effect=1.0, sample_size=4,
                        budget={"wall_seconds": 60})
        self.assertNotEqual(p["protocol_digest"], q["protocol_digest"])

    def test_sample_size_power_analysis(self):
        n = required_sample_size(0.7, 0.3)
        self.assertIsInstance(n, int)
        self.assertGreaterEqual(n, 4)
        with self.assertRaises(ContractError):
            required_sample_size(0.3, 0.7)


class MetricsTests(unittest.TestCase):
    def _report(self):
        return {"per_task": [
            {"task_id": "t1", "arms": {
                "A": {"outcome": "pass", "wall_seconds": 1.0,
                      "tokens_used": 10, "tools_used": 2},
                "E": {"outcome": "pass", "wall_seconds": 1.0}}},
            {"task_id": "t2", "arms": {
                "A": {"outcome": "fail", "wall_seconds": 2.0},
                "E": {"outcome": "fail", "wall_seconds": 2.0}}},
        ]}

    def test_metrics_math_and_abstention(self):
        m = compute_metrics(
            self._report(),
            served={("t1", "E"): True, ("t2", "E"): False})
        self.assertEqual(m["A"]["solved_task_rate"], 0.5)
        self.assertEqual(m["A"]["verified_regression_rate"], 0.5)
        self.assertEqual(m["A"]["abstention_rate"], 1.0)  # never served
        self.assertEqual(m["E"]["abstention_rate"], 0.5)
        self.assertIsNone(m["E"]["negative_transfer_rate"])
        self.assertEqual(m["A"]["mean_tokens_per_task"], 10.0)
        self.assertIsNone(m["E"]["mean_tokens_per_task"])  # not fabricated
        self.assertEqual(m["A"]["evaluation_integrity_failures"], 0)

    def test_negative_transfer_measured(self):
        m = compute_metrics(
            self._report(),
            served={("t2", "E"): True},
            misleading_tasks={"t2"})
        # served a misleading task and it failed -> negative transfer = 1.0
        self.assertEqual(m["E"]["negative_transfer_rate"], 1.0)

    def test_errors_count_as_integrity_failures(self):
        report = self._report()
        report["per_task"][0]["arms"]["A"]["error"] = "boom"
        m = compute_metrics(report)
        self.assertEqual(m["A"]["evaluation_integrity_failures"], 1)


class CampaignCLITests(unittest.TestCase):
    def test_deterministic_campaign_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            proc = subprocess.run(
                [sys.executable,
                 str(REPO / "tools" / "governed_campaign.py"),
                 "-o", str(out)],
                capture_output=True, text=True, env=_env(), cwd=REPO,
                timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            evidence = json.loads(
                (out / "campaign_evidence.json").read_text())
            self.assertEqual(evidence["kind"], "governed_campaign")
            counts = evidence["evaluation"]["solved_counts"]
            self.assertGreater(counts.get("E", 0), counts.get("A", -1))
            self.assertTrue(evidence["registry"]["qualified"])
            self.assertTrue(evidence["registry"]["audit"])
            # revocation demonstration actually ran: the revoked
            # candidate's lesson text no longer serves
            post = evidence["served_after_revocation"]
            self.assertIsNotNone(post)
            self.assertTrue(all(
                "round_money" not in step for step in post["checks"]))
            self.assertTrue(evidence["skill_bundle"])
            stdout = json.loads(proc.stdout)
            self.assertEqual(len(stdout["digest"]), 64)


if __name__ == "__main__":
    unittest.main()
