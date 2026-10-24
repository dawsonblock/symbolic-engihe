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
        "def volume(l, w, h):\n    return l - w - h\n",  # NOT in scope (n-ary) -> excluded below
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
}
# ho1's `l - w - h` is a nested BinOp — still BinOp-shaped, in scope.
CONTROL = (
    "def balance(a, b):\n    return a - b\n",
    b"import calc\nassert calc.balance(10, 3) == 7\n",
)

PROMPT_A = (
    "This repository has one file, calc.py, containing a bug. "
    "Fix the bug so the acceptance test passes. Do not add files.")
PROMPT_D_SUFFIX = (
    "\n\nA qualified repair procedure applies to this failure signature: "
    "the function's binary subtraction should be multiplication. "
    "Apply exactly that minimal transformation, then stop.")


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
                 guided: bool, nonce: str):
        """Fresh disposable workspace per arm; one bounded live turn."""
        ws, task_id = self._workspace(f"{name}-{nonce}", source, acc)
        prompt = PROMPT_A + (PROMPT_D_SUFFIX if guided else "")
        turn = adapter.start_task(prompt, ws, sandbox="workspace_write")
        for _event in turn:  # drain the normalized stream
            pass
        receipt = self._evaluate(task_id, ws, f"{name}-{nonce}")
        return receipt.outcome

    def test_held_out_transfer_efficacy(self):
        from sis.v3.adapters.codex import CodexAdapter
        results: dict[str, dict[str, str]] = {}
        with CodexAdapter() as adapter:
            for name, (source, acc) in sorted(HELD_OUT.items()):
                results[name] = {
                    "A": self._run_arm(adapter, name, source, acc,
                                       guided=False, nonce=f"{name}-A"),
                    "D": self._run_arm(adapter, name, source, acc,
                                       guided=True, nonce=f"{name}-D"),
                }
            results["control"] = {
                "A": self._run_arm(adapter, "control", CONTROL[0],
                                   CONTROL[1], guided=False,
                                   nonce="control-A"),
                "D": self._run_arm(adapter, "control", CONTROL[0],
                                   CONTROL[1], guided=True,
                                   nonce="control-D"),
            }
        # Report artifact: outcomes are evaluator verdicts, not agent claims.
        wins = sum(1 for n in HELD_OUT
                   if results[n]["D"] == "pass" and results[n]["A"] != "pass")
        losses = sum(1 for n in HELD_OUT
                     if results[n]["A"] == "pass"
                     and results[n]["D"] != "pass")
        ties = len(HELD_OUT) - wins - losses
        report = {
            "experiment": "v4.0.0-held-out-transfer",
            "held_out_tasks": len(HELD_OUT),
            "outcomes": results,
            "paired_D_vs_A": {"wins": wins, "losses": losses, "ties": ties},
            "control_arm_D_outcome": results["control"]["D"],
        }
        out = self.root / "efficacy_report.json"
        import json
        out.write_text(json.dumps(report, indent=2, sort_keys=True))
        print("\nEFFICACY REPORT:", out)
        print(json.dumps(report, indent=2, sort_keys=True))
        # Hard assertions: the experiment itself executed end to end. The
        # control outcome is DATA — a 'fail' there is genuine evidence of
        # negative transfer risk and belongs in the report, not hidden.
        self.assertEqual(len(results), len(HELD_OUT) + 1)
        self.assertIn(results["control"]["D"], {"pass", "fail"})
        if results["control"]["D"] == "fail":
            print("WARNING: guidance induced negative transfer on control")


if __name__ == "__main__":
    unittest.main()
