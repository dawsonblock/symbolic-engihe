"""SIS3-402: typed symbolic repair induction demo (v3.4.0).

A -> B -> C demonstration plus a lookalike counterexample:

  A (mine):    verified pass episode fixes ``scale`` (a-b -> a*b); the
               miner emits an operator_substitution hypothesis.
  B (qualify): the hypothesis is applied to a DIFFERENT buggy function in
               a DIFFERENT repository and passes that repo's independent
               acceptance test.
  C (transfer): the same hypothesis repairs an unseen third repo's file,
               again verified by the evaluator's own acceptance command.
  Counterexample: a lookalike subtraction that is CORRECT — the pattern
               matches structurally, the acceptance test fails, and the
               hypothesis must not qualify guidance for it.
"""
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.policy import AuthorizationDenied
from sis.v3.repair_induction import (
    InductionError,
    apply_hypothesis,
    find_matches,
    mine_repairs,
)
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier

from tests.v3.support import FixtureAuthority

_CONTRACT = "0" * 64  # demo binds the evaluator suite commitment digest


class InductionDemo(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        executor = LocalSubprocessExecutor(self.root / "exec",
                                           use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.auth = FixtureAuthority(self.root / "auth")
        self.receipt = self.auth.issue_receipt()

    def _repo(self, name: str, source: str, acc: bytes):
        """Materialize a repo with its own registered acceptance task."""
        repo = self.root / name
        repo.mkdir()
        (repo / "calc.py").write_text(textwrap.dedent(source))
        task_id = f"task-{name}"
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id, criterion_version="v1",
            argv=(sys.executable, "acc.py"), files={"acc.py": acc},
            repository_id=f"repo-{name}")
        return repo, task_id

    def _eval(self, task_id: str, repo: Path):
        task = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref=task_id)
        return self.verifier.evaluate(
            actor_role="evaluator", task=task, submission_dir=repo,
            evaluation_nonce=f"eval-{task_id}",
            evaluation_scope=f"demo:{task_id}")

    def _mine(self, before, after, receipt=None):
        return mine_repairs(
            actor_role="learner",
            before_source=before, after_source=after,
            receipt=receipt or self.receipt,
            failure_signature="test_scale:exit_1",
            semantic_contract_digest=_CONTRACT,
            test_recipe=("registered_task",),
            repository_identity="repo-a",
        )

    def test_mine_qualify_transfer_and_counterexample(self):
        # ---- A: mine from the verified repo-a episode --------------------
        hyp = self._mine(
            "def scale(a, b):\n    return a - b\n",
            "def scale(a, b):\n    return a * b\n")
        self.assertEqual(hyp.transformation_kind, "operator_substitution")
        self.assertEqual(sorted(hyp.metavariables),
                         ["expr:l0", "expr:l1"])
        self.assertEqual(hyp.source_pattern["op"], "Sub")
        self.assertEqual(hyp.target_pattern["op"], "Mult")
        self.assertIn(self.receipt.digest, hyp.evidence_refs)

        # ---- B: independently qualify on a disjoint repo ----------------
        repo_b, task_b = self._repo(
            "b", "def area(w, h):\n    return w - h\n",
            b"import calc; assert calc.area(3, 4) == 12\n")
        patched = apply_hypothesis((repo_b / "calc.py").read_text(), hyp)
        self.assertIsNotNone(patched)
        self.assertIn("w * h", patched)
        (repo_b / "calc.py").write_text(patched)
        self.assertEqual(self._eval(task_b, repo_b).outcome, "pass")

        # ---- C: transfer to an unseen third repo -------------------------
        repo_c, task_c = self._repo(
            "c", "def product(x, y):\n    return x - y\n",
            b"import calc; assert calc.product(6, 7) == 42\n")
        patched_c = apply_hypothesis((repo_c / "calc.py").read_text(), hyp)
        self.assertIn("x * y", patched_c)
        (repo_c / "calc.py").write_text(patched_c)
        self.assertEqual(self._eval(task_c, repo_c).outcome, "pass")

        # ---- Counterexample: lookalike subtraction is CORRECT ------------
        repo_bad, task_bad = self._repo(
            "bad", "def debt(a, b):\n    return a - b\n",
            b"import calc; assert calc.debt(10, 3) == 7\n")
        self.assertEqual(
            len(find_matches((repo_bad / "calc.py").read_text(), hyp)), 1)
        patched_bad = apply_hypothesis(
            (repo_bad / "calc.py").read_text(), hyp)
        (repo_bad / "calc.py").write_text(patched_bad)
        # Executable contract discharges it: abstain, never serve.
        self.assertEqual(self._eval(task_bad, repo_bad).outcome, "fail")

    def test_no_match_abstains(self):
        hyp = self._mine(
            "def f(a, b):\n    return a - b\n",
            "def f(a, b):\n    return a * b\n")
        source = "def neg(x):\n    return -x\n"
        self.assertIsNone(apply_hypothesis(source, hyp))
        self.assertEqual(find_matches(source, hyp), ())

    def test_nested_left_diff_mines_and_transfers(self):
        """l-w-h -> l*w*h: the outer Sub is shared context; the inner
        Sub->Mult is the typed transformation."""
        hyp = self._mine(
            "def volume(l, w, h):\n    return l - w - h\n",
            "def volume(l, w, h):\n    return l * w * h\n")
        self.assertEqual(hyp.transformation_kind, "operator_substitution")
        self.assertEqual(sorted(hyp.metavariables),
                         ["expr:l0", "expr:l1", "expr:l2"])
        out = apply_hypothesis(
            "def f(x, y, z):\n    return x - y - z\n", hyp)
        self.assertIsNotNone(out)
        # Spine-consistent map: every Sub in the chain becomes Mult.
        self.assertIn("x * y * z", out)

    def test_nested_right_diff_mines_and_transfers(self):
        hyp = self._mine(
            "def f(a, b, c):\n    return a - (b - c)\n",
            "def f(a, b, c):\n    return a - (b * c)\n")
        # Shared sibling `a` generalized to a context metavar.
        self.assertIn("expr:c0", hyp.metavariables)
        out = apply_hypothesis(
            "def g(p, q, r):\n    return p - (q - r)\n", hyp)
        self.assertIsNotNone(out)
        import ast
        expected = ast.dump(ast.parse(
            "def g(p, q, r):\n    return p - (q * r)\n"))
        self.assertEqual(ast.dump(ast.parse(out)), expected)

    def test_compare_operator_diff_mines_and_transfers(self):
        hyp = self._mine(
            "def f(a, b):\n    return a < b\n",
            "def f(a, b):\n    return a <= b\n")
        self.assertEqual(hyp.transformation_kind, "operator_substitution")
        out = apply_hypothesis(
            "def g(p, q):\n    return p < q\n", hyp)
        self.assertIsNotNone(out)
        import ast
        self.assertEqual(ast.dump(ast.parse(out)),
                         ast.dump(ast.parse("def g(p, q):\n    return p <= q\n")))

    def test_compare_with_nested_binop_diff(self):
        """x < y - z -> x < y * z: Compare spine holds, inner Sub->Mult."""
        hyp = self._mine(
            "def f(x, y, z):\n    return x < y - z\n",
            "def f(x, y, z):\n    return x < y * z\n")
        self.assertEqual(hyp.transformation_kind, "operator_substitution")
        out = apply_hypothesis(
            "def g(p, q, r):\n    return p < q - r\n", hyp)
        self.assertIsNotNone(out)
        import ast
        self.assertEqual(ast.dump(ast.parse(out)),
                         ast.dump(ast.parse("def g(p, q, r):\n    return p < q * r\n")))

    def test_nested_both_sides_differ_still_refused(self):
        with self.assertRaisesRegex(InductionError, "compounded_difference"):
            self._mine(
                "def f(a, b, c):\n    return a - b - c\n",
                "def f(a, b, c):\n    return a * b * c + a\n")

    def test_operand_reorder_is_typed(self):
        hyp = self._mine(
            "def f(a, b):\n    return a - b\n",
            "def f(a, b):\n    return b - a\n")
        self.assertEqual(hyp.transformation_kind, "operand_reorder")

    def test_compounded_difference_refuses_hypothesis(self):
        with self.assertRaisesRegex(InductionError, "compounded_difference"):
            self._mine(
                "def f(a, b):\n    return a - b\n",
                "def f(a, b):\n    return b * a\n")

    def test_failed_episode_cannot_seed_transformation(self):
        fail_receipt = self.auth.issue_receipt(task_id="t2", outcome="fail")
        with self.assertRaisesRegex(InductionError, "unverified_repair"):
            self._mine(
                "def f(a, b):\n    return a - b\n",
                "def f(a, b):\n    return a * b\n",
                receipt=fail_receipt)

    def test_agent_role_cannot_mine(self):
        with self.assertRaises(AuthorizationDenied):
            mine_repairs(
                actor_role="agent",
                before_source="def f(a, b):\n    return a - b\n",
                after_source="def f(a, b):\n    return a * b\n",
                receipt=self.receipt,
                failure_signature="sig",
                semantic_contract_digest=_CONTRACT,
                test_recipe=("registered_task",),
            )

    def test_typed_hypothesis_requires_contract_digest(self):
        with self.assertRaises(ContractError):
            self._mine(
                "def f(a, b):\n    return a - b\n",
                "def f(a, b):\n    return a * b\n",
            ) if False else mine_repairs(
                actor_role="learner",
                before_source="def f(a, b):\n    return a - b\n",
                after_source="def f(a, b):\n    return a * b\n",
                receipt=self.receipt,
                failure_signature="sig",
                semantic_contract_digest=None,
                test_recipe=("registered_task",),
            )

    def test_mined_candidate_enters_governed_flow_as_candidate(self):
        """A mined hypothesis seeds only a candidate ProcedureRecordV1 —
        governed status still requires the signed promotion path."""
        hyp = self._mine(
            "def scale(a, b):\n    return a - b\n",
            "def scale(a, b):\n    return a * b\n")
        record = _proc_from_hypothesis(hyp)
        self.auth.store.add(record)
        self.assertEqual(
            self.auth.store.get(record.procedure_id).status, "candidate")


class HypothesisStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth = FixtureAuthority(self.root / "auth")
        self.receipt = self.auth.issue_receipt()

    def _mine(self):
        from sis.v3.repair_induction import mine_repairs
        return mine_repairs(
            actor_role="learner",
            before_source="def f(a, b):\n    return a - b\n",
            after_source="def f(a, b):\n    return a * b\n",
            receipt=self.receipt,
            failure_signature="sig",
            semantic_contract_digest=_CONTRACT,
            test_recipe=("registered_task",),
        )

    def test_append_get_and_reload(self):
        from sis.v3.repair_induction import HypothesisStore
        store = HypothesisStore(self.root / "hyps")
        hyp = self._mine()
        digest = store.add(hyp)
        self.assertEqual(store.add(hyp), digest)  # idempotent
        reopened = HypothesisStore(self.root / "hyps")
        self.assertEqual(reopened.get(hyp.hypothesis_id).digest, digest)
        self.assertEqual(reopened.get_by_digest(digest).hypothesis_id,
                         hyp.hypothesis_id)
        self.assertEqual(reopened.verify(), [])

    def test_conflicting_id_fails_closed(self):
        from dataclasses import replace
        from sis.v3.repair_induction import HypothesisStore, InductionError
        store = HypothesisStore(self.root / "hyps")
        hyp = self._mine()
        store.add(hyp)
        tampered = replace(hyp, miner_identity="forged-miner")
        with self.assertRaisesRegex(InductionError, "hypothesis_conflict"):
            store.add(tampered)

    def test_corrupt_tail_detected_on_load(self):
        from sis.v3.repair_induction import HypothesisStore, InductionError
        store = HypothesisStore(self.root / "hyps")
        store.add(self._mine())
        with open(self.root / "hyps" / "hypotheses.jsonl", "ab") as fh:
            fh.write(b'{"garbage": true}\n')
        with self.assertRaisesRegex(InductionError, "hypothesis_log_corrupt"):
            HypothesisStore(self.root / "hyps")


def _proc_from_hypothesis(hyp):
    """Project a hypothesis into a candidate ProcedureRecordV1."""
    from sis.v3.contracts import ProcedureRecordV1
    return ProcedureRecordV1(
        schema_version=1,
        procedure_id="proc-" + hyp.hypothesis_id.removeprefix("hyp-"),
        revision=1,
        intent=(f"Apply typed {hyp.transformation_kind} per hypothesis "
                f"{hyp.hypothesis_id}; verify against the bound semantic "
                "contract before serving."),
        language=hyp.language,
        frameworks=(),
        task_signatures=(hyp.failure_signature,),
        failure_signatures=(hyp.failure_signature,),
        preconditions=hyp.preconditions,
        contraindications=hyp.contraindications,
        steps=(f"Match source_pattern of {hyp.hypothesis_id}.",
               "Apply target_pattern; run the bound acceptance recipe.",
               "Serve only after an independent pass receipt."),
        required_verification=(
            ("Independent evaluator runs the registered acceptance command "
             "on the transformed tree."),),
        counterexample_refs=(),
        evidence_refs=hyp.evidence_refs,
        outcome_distribution={
            "tasks": 1, "successes": 1, "failures": 0, "regressions": 0},
        status="candidate",
        expires_at=None,
    )


if __name__ == "__main__":
    unittest.main()
