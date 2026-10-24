"""SIS3-012: paired four-arm harness with independent scoring."""
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, report_digest
from sis.v3.contracts import TaskEnvelopeV1
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"},
        )
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work",
        )
        self.budget = BudgetCaps(wall_seconds=60, token_budget=1000, tool_budget=10)

    def test_d_guided_agent_wins_paired(self):
        """D arm gets guidance and fixes; A/B/C leave the bug in place."""
        def agent(ctx):
            if ctx.arm == "D" and ctx.guidance is not None:
                (ctx.workspace / "calc.py").write_text(
                    "def scale(a, b):\n    return a * b\n")

        seen_arms = []
        def provider(task, arm):
            seen_arms.append(arm)
            return object() if arm == "D" else None

        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
            context_provider=provider,
        )
        self.assertEqual(report["solved_counts"]["D"], 1)
        self.assertEqual(report["solved_counts"]["A"], 0)
        self.assertEqual(report["paired"]["D_vs_A"]["wins"], 1)
        self.assertEqual(report["paired"]["D_vs_C"]["solved_delta"], 1)
        self.assertTrue(report_digest(report))

    def test_arm_exception_is_error_observation_not_verdict(self):
        def agent(ctx):
            raise RuntimeError("boom")
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
            arms=("A",),
        )
        self.assertEqual(report["per_task"][0]["arms"]["A"]["outcome"], "error")

    def test_all_arms_same_pass_counts(self):
        def agent(ctx):
            (ctx.workspace / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
        )
        self.assertTrue(all(v == 1 for v in report["solved_counts"].values()))
        self.assertEqual(report["paired"]["D_vs_A"]["ties"], 1)

    def test_budget_violation_flagged(self):
        import time
        def agent(ctx):
            time.sleep(2.1)
        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=1, token_budget=1000, tool_budget=10),
            arms=("A",),
        )
        self.assertEqual(report["budget_violations"], 1)
        self.assertTrue(report["per_task"][0]["arms"]["A"]["budget_exceeded"])

    def test_fresh_workspace_per_arm(self):
        seen = []
        def agent(ctx):
            # Each arm must see the pristine buggy file, not a prior arm's edit.
            seen.append((ctx.arm, (ctx.workspace / "calc.py").read_text()))
        self.harness.run([(self.task, self.repo)], agent, budget=self.budget)
        self.assertEqual(len(seen), 4)
        self.assertTrue(all("a - b" in text for _, text in seen))


class BenchmarkTruthTests(unittest.TestCase):
    """v3.1.2 hard negatives: nothing invalid may count as a solve/win."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"},
        )
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work")

    def _fix(self, ctx):
        (ctx.workspace / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n")

    def test_timeout_passing_artifact_never_counts(self):
        import time
        def agent(ctx):
            self._fix(ctx)
            time.sleep(5)
        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=1, token_budget=1000, tool_budget=10),
            arms=("A",))
        arm = report["per_task"][0]["arms"]["A"]
        self.assertEqual(arm["category"], "timeout")
        self.assertFalse(arm["valid_solve"])
        self.assertTrue(arm["budget_exceeded"])
        self.assertFalse(arm["termination_verified"])
        self.assertEqual(report["solved_counts"]["A"], 0)
        self.assertEqual(report["raw_pass_counts"]["A"], 0)

    def test_token_overrun_pass_is_excluded(self):
        def agent(ctx):
            self._fix(ctx)
            ctx.usage.tokens_used = 10 ** 9
        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=60, token_budget=1000, tool_budget=10))
        for arm in "ABCD":
            row = report["per_task"][0]["arms"][arm]
            self.assertEqual(row["category"], "budget_exceeded", arm)
            self.assertFalse(row["valid_solve"])
            self.assertEqual(row["tokens_used"], 10 ** 9)
        self.assertEqual(report["solved_counts"]["D"], 0)
        self.assertEqual(report["paired"]["D_vs_A"]["pairs_n"], 0)
        self.assertEqual(report["paired"]["D_vs_A"]["excluded_tasks"], 1)

    def test_metered_usage_certifies_equal_budget(self):
        def agent(ctx):
            self._fix(ctx)
            ctx.usage.tokens_used = 10
            ctx.usage.tools_used = 1
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=BudgetCaps(
                wall_seconds=60, token_budget=1000, tool_budget=10))
        cert = report["budget_certification"]
        self.assertTrue(cert["equal_budget_certified"])
        self.assertEqual(report["solved_counts"]["A"], 1)

    def test_unmetered_usage_is_not_certified(self):
        def agent(ctx):
            self._fix(ctx)
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=BudgetCaps(
                wall_seconds=60, token_budget=1000, tool_budget=10))
        cert = report["budget_certification"]
        self.assertFalse(cert["equal_budget_certified"])
        self.assertEqual(cert["token"], "declared_only")
        # Still a valid solve: the artifact passed in-budget on the
        # enforced dimension; certification is a separate disclosure.
        self.assertEqual(report["solved_counts"]["A"], 1)

    def test_arm_order_seeded_and_recorded(self):
        def agent(ctx):
            pass
        r1 = self.harness.run([(self.task, self.repo)], agent,
                              budget=BudgetCaps(60, 1000, 10), seed="s-fixed")
        order = r1["per_task"][0]["arm_order"]
        self.assertEqual(sorted(order), list("ABCD"))
        self.assertEqual(r1["arm_seed"], "s-fixed")
        harness2 = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work2")
        r2 = harness2.run([(self.task, self.repo)], agent,
                          budget=BudgetCaps(60, 1000, 10), seed="s-fixed")
        self.assertEqual(r2["per_task"][0]["arm_order"], order)

    def test_agent_exception_excluded_from_pairs(self):
        def agent(ctx):
            if ctx.arm == "D":
                raise RuntimeError("crash")
            self._fix(ctx)
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=BudgetCaps(60, 1000, 10))
        row = report["per_task"][0]["arms"]["D"]
        self.assertEqual(row["category"], "agent_error")
        self.assertEqual(report["paired"]["D_vs_A"]["pairs_n"], 0)
        self.assertEqual(report["paired"]["D_vs_A"]["wins"], 0)

    def test_subsecond_overrun_is_not_floored_to_pass(self):
        # The v3.1.1 defect: 1.05s slept under a 1s cap read as wall=1.
        import time
        def agent(ctx):
            self._fix(ctx)
            time.sleep(1.05)
        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=1, token_budget=1000, tool_budget=10),
            arms=("A",))
        row = report["per_task"][0]["arms"]["A"]
        self.assertFalse(row["valid_solve"])
        self.assertEqual(report["solved_counts"]["A"], 0)


if __name__ == "__main__":
    unittest.main()
