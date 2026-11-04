"""The qualification harness must compute its decision, not assert it."""
from __future__ import annotations

import sys
import unittest

from tools import v351_qualify as qualify


class DecisionTests(unittest.TestCase):
    def test_all_passes_with_no_blocking_limitation_is_go(self):
        self.assertEqual(qualify._decide({"pass"}, ()), "GO")

    def test_a_declared_blocking_limitation_is_conditional(self):
        decision = qualify._decide({"pass"}, qualify.LIMITATIONS)
        self.assertEqual(decision, "CONDITIONAL_GO")

    def test_a_non_blocking_limitation_still_permits_go(self):
        decision = qualify._decide(
            {"pass"}, ("local-image-pin: not a registry chain",))
        self.assertEqual(decision, "GO")

    def test_any_failure_is_no_go(self):
        self.assertEqual(qualify._decide({"pass", "fail"}, ()), "NO_GO")

    def test_a_blocked_gate_is_conditional(self):
        self.assertEqual(qualify._decide({"pass", "blocked"}, ()),
                         "CONDITIONAL_GO")


class CountTests(unittest.TestCase):
    def test_the_summary_line_is_used(self):
        output = (
            "test_x.py::test_one PASSED  [ 50%]\n"
            "3 passed, 2 skipped in 0.10s\n"
        )
        self.assertEqual(qualify._counts(output),
                         {"passed": 3, "failed": 0, "skipped": 2, "error": 0})

    def test_an_earlier_line_does_not_override_the_summary(self):
        output = (
            "collected 5 items\n"
            "4 passed in 0.01s\n"
            "1 failed, 4 passed in 0.02s\n"
        )
        counts = qualify._counts(output)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["passed"], 4)


class GateTests(unittest.TestCase):
    def _result(self, returncode=0, stdout="1 passed in 0.1s"):
        return {"argv": ["pytest"], "returncode": returncode,
                "seconds": 0.1, "stdout": stdout, "stderr": ""}

    def test_a_passing_command_is_a_pass(self):
        gate = qualify._gate("g", "i", self._result())
        self.assertEqual(gate["status"], "pass")

    def test_a_blocked_gate_never_reports_pass(self):
        gate = qualify._gate("g", "i", self._result(),
                             blocked_reason="no runtime")
        self.assertEqual(gate["status"], "blocked")

    def test_a_failing_command_is_a_failure(self):
        gate = qualify._gate("g", "i", self._result(returncode=1))
        self.assertEqual(gate["status"], "fail")


class TimeoutTests(unittest.TestCase):
    def test_a_hung_gate_fails_instead_of_crashing_the_harness(self):
        # A gate that never returns must still produce a record; the
        # harness is not allowed to die before writing its disposition.
        result = qualify._run(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout=1)
        self.assertEqual(result["returncode"], -1)
        self.assertIn("timed out", result["stderr"])
        self.assertEqual(qualify._gate("g", "i", result)["status"], "fail")


if __name__ == "__main__":
    unittest.main()
