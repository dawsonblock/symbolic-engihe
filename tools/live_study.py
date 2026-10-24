#!/usr/bin/env python3
"""Live paired study against authenticated Codex CLI (M6 attempt).

Builds two held-out mini-repositories, a real authority stack (signed
promotion -> committed cross-repo grant), an evaluator-private
OutcomeVerifier, and runs the four-arm harness with `codex exec` as the
agent. Arm D receives gateway-served qualified guidance; arms A-C do
not. Grading is independent: the verifier injects its own private test
files into the submission and runs them.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sis.v3 import signatures
from sis.v3.authority_db import AuthorityDB
from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, report_digest
from sis.v3.contracts import GuidanceRequestV1, ProcedureRecordV1, TaskEnvelopeV1
from sis.v3.evaluation import assert_repository_disjoint, paired_summary
from sis.v3.promotion import PromotionController, operator_token_digest
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.secure_guidance import StrictGuidanceGateway
from sis.v3.verifier import OutcomeVerifier
from tests.v3.authority_testkit import (TEST_TOKEN, drive, evaluator_keypair,
                                        issue_and_commit_grant,
                                        make_grant_authority, make_registry,
                                        register_repo, seed, signed_receipt)

PROMPT = (
    "In the workspace there is a Python module {mod} and NO tests. "
    "Task: {statement} Edit the source so the described contract holds "
    "for all inputs. Do not create tests; do not ask questions.")


def make_fixture(root: Path, name: str, mod: str, src: str) -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    (repo / mod).write_text(src)
    return repo


def codex_agent(ctx, *, task_statements):
    statement = task_statements[ctx.task.task_id]
    mod = task_statements[ctx.task.task_id + ":mod"]
    parts = [PROMPT.format(mod=mod, statement=statement)]
    if ctx.guidance is not None and ctx.guidance.decision == "recommend":
        hints = "\n".join("- " + h for h in ctx.guidance.helpful_next_checks)
        parts.append("Reviewer guidance (advisory):\n" + hints)
    proc = subprocess.run(
        ["codex", "exec", "-C", str(ctx.workspace),
         "-s", "workspace-write", "--skip-git-repo-check",
         "".join(parts)],
        capture_output=True, text=True, timeout=max(60, int(ctx.budget.wall_seconds) - 15))
    (ctx.workspace / ".codex_exec.log").write_text(
        (proc.stdout or "") + "\n" + (proc.stderr or ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--wall", type=float, default=420)
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="sis-live-study-"))
    fixtures = root / "fixtures"
    # Two held-out repos; neither supplies learning evidence.
    repo1 = make_fixture(fixtures, "calc-fix", "calc.py",
                         "def scale(a, b):\n    return a - b\n")
    repo2 = make_fixture(fixtures, "text-clean", "textutil.py",
                         "def collapse(s):\n    return s.split()[0]\n")
    statements = {
        "task-calc": ("scale(a, b) must return the arithmetic product "
                      "a * b of its two numeric arguments."),
        "task-text": ("collapse(s) must return the string with every "
                      "run of whitespace replaced by a single space, "
                      "with leading and trailing whitespace removed."),
        "task-calc:mod": "calc.py", "task-text:mod": "textutil.py",
    }
    tests = {
        "task-calc": b"from calc import scale\ndef test_scale():\n"
                     b"    assert scale(3, 4) == 12\n"
                     b"    assert scale(-2, 5) == -10\n"
                     b"    assert scale(0, 9) == 0\n",
        "task-text": b"from textutil import collapse\ndef test_collapse():\n"
                     b"    assert collapse('  a  b\\tc ') == 'a b c'\n"
                     b"    assert collapse('one') == 'one'\n"
                     b"    assert collapse('x   y') == 'x y'\n",
    }

    # Authority: registry, grant authority, promoted qualified procedure.
    registry, reg_seed = make_registry()
    grants, grant_seed, grant_key = make_grant_authority(registry)
    ident = {}
    for name, repo in (("eval-calc", repo1), ("eval-text", repo2)):
        ident[name] = register_repo(
            registry, reg_seed, registry_id=name,
            base_tree_digest=tree_digest(repo))
    src_tree = "f" * 64
    register_repo(registry, reg_seed, registry_id="repo-src",
                  base_tree_digest=src_tree)
    eval_seed, eval_pub, eval_key = evaluator_keypair()
    db = AuthorityDB(root / "authority.db")
    controller = PromotionController(
        db, operator_token_digest=operator_token_digest(TEST_TOKEN),
        trusted_evaluator_keys={eval_key: eval_pub.hex()})
    proc = ProcedureRecordV1(
        schema_version=1, procedure_id="strat-contract-first", revision=1,
        intent="Derive edits from the stated contract, not the current code.",
        language="python", frameworks=(), task_signatures=(),
        failure_signatures=("contract-violation",),
        preconditions=({"kind": "language_is", "value": "python"},
                       {"kind": "failure_signature_is",
                        "value": "contract-violation"}),
        contraindications=(),
        steps=("State the required output for a concrete input before editing.",
               "Change the minimal expression that violates the contract.",
               "Sanity-check boundary inputs (zero, negative, single token)."),
        required_verification=("Task-owned acceptance suite must pass.",),
        counterexample_refs=(), evidence_refs=("1" * 64,),
        outcome_distribution={"tasks": 2, "successes": 2, "failures": 0,
                              "regressions": 0},
        status="candidate", expires_at=None)
    seed(db, proc)
    receipt = signed_receipt(eval_seed, eval_key,
                             repo_digest=tree_digest(repo1))
    receipt2 = signed_receipt(eval_seed, eval_key, task_id="t2",
                              repo_digest=tree_digest(repo2))
    receipt_src = signed_receipt(eval_seed, eval_key, task_id="t-src",
                                 repo_digest=src_tree)
    controller._resolve_receipt = {r.digest: r for r in
                                   (receipt, receipt2, receipt_src)}.__getitem__
    drive(db, controller, proc.procedure_id, "qualified", token=TEST_TOKEN,
          seed=eval_seed, key_id=eval_key, receipts=[receipt])
    qualified = db.get(proc.procedure_id)
    for name, tgt_receipt in (("eval-calc", receipt),
                              ("eval-text", receipt2)):
        issue_and_commit_grant(
            db, controller, grants, record=qualified,
            source_registry_id="repo-src",
            target_registry_id=name, seed=grant_seed, key_id=grant_key,
            evidence_receipts=(receipt_src, tgt_receipt),
            grant_nonce="g-" + name)
    gateway = StrictGuidanceGateway(
        db, controller, repository_registry=registry,
        grant_authority=grants)

    # Verifier: evaluator-private pytest injected per task.
    executor = LocalSubprocessExecutor(root / "exec")
    verifier = OutcomeVerifier(
        executor=executor, key_dir=root / "eval-keys",
        registry_dir=root / "eval-reg")
    envelopes = []
    for task_id, repo, ident_name in (("task-calc", repo1, "eval-calc"),
                                      ("task-text", repo2, "eval-text")):
        verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1", argv=(sys.executable, "-m", "pytest",
                                          "-q", "eval_tests.py"),
            files={"eval_tests.py": tests[task_id]},
            base_commit="a1b2c3d")
        env = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(repo), base_commit="a1b2c3d",
            task_statement_digest=signatures.public_key(
                bytes([len(task_id)] * 32)).hex()[:64],
            permitted_commands=("codex",), isolation_profile="unverified_local",
            time_budget_seconds=int(args.wall), token_budget=1_000_000,
            tool_budget=10_000,
            actor_id="study-operator", evaluator_task_ref=task_id)
        envelopes.append((env, repo, ident_name))

    assert_repository_disjoint(
        [src_tree], [e for e, _, _ in envelopes])
    repo_of = {e.task_id: name for e, _, name in envelopes}

    def context_provider(task, arm):
        if arm != "D":
            return None
        req = GuidanceRequestV1(
            schema_version=1, task_id=task.task_id,
            repo_snapshot_digest=task.repo_snapshot_digest,
            base_commit=task.base_commit, namespace="ns",
            language="python", toolchain="pytest", lockfile_digests={},
            task_summary=statements[task.task_id],
            failure_signatures=("contract-violation",),
            present_symbols=(), semantic_contract_digest="c" * 64)
        return gateway.recommend(req, repository_id=repo_of[task.task_id])

    harness = BenchmarkHarness(
        verifier=verifier, work_root=root / "work")
    report = harness.run(
        [(e, r) for e, r, _ in envelopes],
        lambda ctx: codex_agent(ctx, task_statements=statements),
        budget=BudgetCaps(wall_seconds=int(args.wall), token_budget=1_000_000,
                          tool_budget=10_000),
        context_provider=context_provider)
    summary = paired_summary(report)
    out = {"report_digest": report_digest(report), "report": report,
           "summary": summary, "study_root": str(root)}
    args.output.write_text(json.dumps(out, indent=2, sort_keys=True))
    delta = summary["contrast"]["solved_delta"]
    p = float(summary["contrast"]["mcnemar_exact_p"])
    print(json.dumps({"digest": out["report_digest"],
                      "delta": delta, "mcnemar_p": p,
                      "gate": delta > 0 and p <= 0.05}, indent=2))
    return 0 if (delta > 0 and p <= 0.05) else 2


if __name__ == "__main__":
    raise SystemExit(main())
