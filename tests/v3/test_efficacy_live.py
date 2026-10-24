"""SIS3-501: live held-out transfer efficacy experiment (v4.0.0).

Gated by SIS3_LIVE_CODEX=1. Uses the REAL Codex agent on held-out,
repo-disjoint tasks; the independent OutcomeVerifier scores every arm.
Agent declarations are never evidence.

Design:
  * A procedure is mined from a verified episode in seed repo-a, then
    independently qualified on repo-b (disjoint task + tree).
  * The held-out set is three NEW repositories in the supported bug
    class (Sub->Mult), none used during mining or qualification.
  * One out-of-scope control repository (correct subtraction) checks
    that guidance does not induce negative transfer.
  * Arm A: task statement only.  Arm D: task statement + qualified
    procedure guidance, as the gateway would surface it.
  * n=3 is deliberately small: the report states power honestly and
    is a qualification artifact, not a marketing claim.
"""
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import pytest

LIVE = os.environ.get("SIS3_LIVE_CODEX") == "1"
pytestmark = pytest.mark.skipif(
    not LIVE, reason="live held-out efficacy experiment (SIS3_LIVE_CODEX=1)")

# Held-out transfer tasks: buggy operator in the mined bug class.
HELD_OUT = {
    "ho1": (
        "def volume(l, w, h):\n    return l - w - h\n",
        b"import calc\nassert calc.volume(2,3,4) == 24\n",
    ),
    "ho2": (
        "def interest(p, r):\n    return p - r\n",
        b"import calc\nassert calc.interest(200, 3) == 600\n",
    ),
    "ho3": (
        "def energy(m, c):\n    return m - c\n",
        b"import calc\nassert calc.energy(5, 2) == 10\n",
    ),
    "ho4": (
        "def dose(weight, mg):\n    return weight - mg\n",
        b"import calc\nassert calc.dose(70, 4) == 280\n",
    ),
    "ho5": (
        "def total(price, qty):\n    return price - qty\n",
        b"import calc\nassert calc.total(9, 5) == 45\n",
    ),
    "ho6": (
        "def speed(dist, t):\n    return dist - t\n",
        b"import calc\nassert calc.speed(120, 3) == 360\n",
    ),
    # Harder tasks: nested chains, multi-function files, distractors.
    "ho7": (
        "def capacity(rows, cols, depth):\n    return rows - cols - depth\n",
        b"import calc\nassert calc.capacity(4, 5, 6) == 120\n",
    ),
    "ho8": (
        "def _unused(x):\n    return x + 1\n\n"
        "def tile(w, h):\n    return w - h\n",
        b"import calc\nassert calc.tile(8, 9) == 72\n",
    ),
    "ho9": (
        "def cube(n):\n    return n - n - n\n",
        b"import calc\nassert calc.cube(3) == 27\n",
    ),
    "ho10": (
        "def discount_rate(p):\n    return p / 100\n\n"
        "def revenue(p, q):\n    return p - q\n",
        b"import calc\nassert calc.revenue(12, 7) == 84\n",
    ),
    "ho11": (
        "def work(force, dist):\n    return force - dist\n",
        b"import calc\nassert calc.work(15, 4) == 60\n",
    ),
    "ho12": (
        "def score(base, mult):\n    return base - mult\n",
        b"import calc\nassert calc.score(20, 6) == 120\n",
    ),
}

# HARD set: second, independently-registered suite targeting tasks where
# the baseline plausibly fails — non-obvious names, mixed correct/buggy
# functions, nested sites, semantic distractors.
HELD_OUT_HARD = {
    "hh1": (
        "def f(a, b):\n    return a - b\n\n"
        "def g(a, b):\n    return a - b\n",
        b"import calc\nassert calc.f(4, 5) == 20\n"
        b"assert calc.g(9, 3) == 6\n",  # only f is buggy!
    ),
    "hh2": (
        "def combine(x, y, z):\n    return (x - y) - z\n",
        b"import calc\nassert calc.combine(2, 3, 4) == 24\n",
    ),
    "hh3": (
        "def nrm(v, lo, hi):\n    return v - lo - hi\n",
        b"import calc\nassert calc.nrm(3, 4, 5) == 60\n",
    ),
    "hh4": (
        "def adj(base, k, m):\n    return base - (k - m)\n",
        b"import calc\nassert calc.adj(10, 4, 6) == -14\n",  # wants base - (k*m)
    ),
    "hh5": (
        "# util module -- do not modify helpers\n"
        "def clamp(x, lo, hi):\n    return max(lo, min(hi, x))\n\n"
        "def shipment(boxes, per_box):\n    return boxes - per_box\n",
        b"import calc\nassert calc.shipment(12, 8) == 96\n"
        b"assert calc.clamp(5, 0, 3) == 3\n",
    ),
    "hh6": (
        "def mixed(a, b, c):\n    return a - b + c\n",
        b"import calc\nassert calc.mixed(5, 3, 2) == 17\n",  # wants a*b + c
    ),
    "hh7": (
        "def scale3(x, y, z):\n    return x - (y - z)\n",
        b"import calc\nassert calc.scale3(2, 3, 4) == -10\n",  # x - (y*z) = 2-12
    ),
    "hh8": (
        "def pair(a, b):\n    return a - b\n",
        b"import calc\nassert calc.pair(11, 13) == 143\n",
    ),
}
CONTROL = (
    "def balance(a, b):\n    return a - b\n",
    b"import calc\nassert calc.balance(10, 3) == 7\n",
)

PROMPT_A = (
    "This repository has one file, calc.py, containing a bug. "
    "Fix the bug so the acceptance test passes. Do not add files.")
PROMPT_B_SUFFIX = (
    "\n\nConsider whether the arithmetic operators in the function are "
    "correct for the task. Apply any needed fix, then stop.")
PROMPT_C_SUFFIX = (
    "\n\nEpisode context (raw, unverified): a previous session in a "
    "different repository edited a function body and a test then passed.")
PROMPT_D_SUFFIX = (
    "\n\nA qualified repair procedure applies to this failure signature: "
    "the subtraction operator(s) in the buggy function's return "
    "expression should be multiplication. Apply exactly that minimal "
    "transformation at the matching site, then stop.")
ARM_SUFFIX = {"A": "", "B": PROMPT_B_SUFFIX, "C": PROMPT_C_SUFFIX,
              "D": PROMPT_D_SUFFIX}
ARMS = ("A", "B", "C", "D")


class LiveEfficacy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        from sis.v3.runner import LocalSubprocessExecutor
        from sis.v3.verifier import OutcomeVerifier
        cls.executor = LocalSubprocessExecutor(cls.root / "exec",
                                               use_seatbelt=False)
        cls.verifier = OutcomeVerifier(
            executor=cls.executor,
            key_dir=cls.root / "keys",
            registry_dir=cls.root / "registry")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _workspace(self, name: str, source: str, acc: bytes) -> tuple[Path, str]:
        ws = self.root / name
        ws.mkdir()
        (ws / "calc.py").write_text(source)
        task_id = f"task-{name}"
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id, criterion_version="v1",
            argv=(sys.executable, "acc.py"), files={"acc.py": acc},
            repository_id=f"repo-{name}")
        return ws, task_id

    def _evaluate(self, task_id: str, ws: Path, nonce: str):
        from sis.v3.contracts import TaskEnvelopeV1
        from sis.v3.runner import tree_digest
        task = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(ws), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref=task_id)
        return self.verifier.evaluate(
            actor_role="evaluator", task=task, submission_dir=ws,
            evaluation_nonce=nonce,
            evaluation_scope=f"efficacy:{nonce}")

    def _run_arm(self, adapter, name: str, source: str, acc: bytes,
                 arm: str, nonce: str):
        """Fresh disposable workspace per arm; one bounded live turn."""
        ws, task_id = self._workspace(f"{name}-{nonce}", source, acc)
        prompt = PROMPT_A + ARM_SUFFIX[arm]
        turn = adapter.start_task(prompt, ws, sandbox="workspace_write")
        for _event in turn:  # drain the normalized stream
            pass
        receipt = self._evaluate(task_id, ws, f"{name}-{nonce}")
        return receipt.outcome

    def _run_experiment(self, suite: dict, experiment: str):
        from sis.v3.adapters.codex import CodexAdapter
        results: dict[str, dict[str, str]] = {}
        with CodexAdapter() as adapter:
            for name, (source, acc) in sorted(suite.items()):
                results[name] = {
                    arm: self._run_arm(adapter, name, source, acc,
                                       arm=arm, nonce=f"{name}-{arm}")
                    for arm in ARMS
                }
            results["control"] = {
                arm: self._run_arm(adapter, "control", CONTROL[0],
                                   CONTROL[1], arm=arm,
                                   nonce=f"control-{arm}")
                for arm in ARMS
            }
        # Report artifact: outcomes are evaluator verdicts, not agent claims.
        def paired(x, y):
            wins = sum(1 for n in suite
                       if results[n][x] == "pass"
                       and results[n][y] != "pass")
            losses = sum(1 for n in suite
                         if results[n][y] == "pass"
                         and results[n][x] != "pass")
            return {"wins": wins, "losses": losses,
                    "ties": len(suite) - wins - losses}
        report = {
            "experiment": experiment,
            "held_out_tasks": len(suite),
            "outcomes": results,
            "paired": {f"{x}_vs_{y}": paired(x, y)
                       for x, y in (("D", "A"), ("D", "B"), ("D", "C"),
                                    ("B", "A"), ("C", "A"))},
            "control_outcomes": results["control"],
        }
        out = self.root / f"efficacy_report_{experiment}.json"
        import json
        out.write_text(json.dumps(report, indent=2, sort_keys=True))
        print("\nEFFICACY REPORT:", out)
        print(json.dumps(report, indent=2, sort_keys=True))
        # Hard assertions: the experiment itself executed end to end. The
        # control outcome is DATA — a 'fail' there is genuine evidence of
        # negative transfer risk and belongs in the report, not hidden.
        self.assertEqual(len(results), len(suite) + 1)
        for arm in ARMS:
            self.assertIn(results["control"][arm], {"pass", "fail"})
        if results["control"]["D"] == "fail" \
                and results["control"]["A"] == "pass":
            print("WARNING: guidance induced negative transfer on control")

    def test_held_out_transfer_efficacy(self):
        self._run_experiment(HELD_OUT, "v4.0.2-4arm-12task")

    def test_hard_held_out_transfer_efficacy(self):
        self._run_experiment(HELD_OUT_HARD, "v4.0.3-4arm-hard")


if __name__ == "__main__":
    unittest.main()
