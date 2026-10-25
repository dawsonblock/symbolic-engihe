#!/usr/bin/env python3
"""Live paired study against authenticated Codex CLI (M6 attempt).

Held-out mini-repositories, a real authority stack (signed promotion ->
committed per-task grants), evaluator-private OutcomeVerifier, and the
four-arm harness with `codex exec` as the agent. Arm D receives
gateway-served qualified guidance whose steps state the project
convention the task's private tests enforce; arms A-C get no hints.
Grading is independent: private tests are injected only at evaluation.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    "for all inputs. Follow the project's conventions. "
    "Do not create tests; do not ask questions.")

# name, module, buggy source, terse statement, convention steps (guidance),
# private test
TASKS = [
    ("money", "money.py",
     "def round_money(x):\n    return round(float(x), 2)\n",
     "round_money(x) must round a decimal amount to cents using the "
     "project's rounding convention.",
     ("The project rounds half values away from zero (ROUND_HALF_UP).",
      "Use decimal.Decimal, not float, for money."),
     "from decimal import Decimal\nfrom money import round_money\n"
     "def test_round():\n"
     "    assert str(round_money('2.675')) == '2.68'\n"
     "    assert str(round_money('2.665')) == '2.67'\n"
     "    assert str(round_money('1.1')) == '1.10'\n"),
    ("slug", "slug.py",
     "def slugify(s):\n    return s.lower().replace(' ', '-')\n",
     "slugify(s) must convert a title into the project's URL slug form.",
     ("Convention: lowercase, words joined by single hyphens, every "
      "non-alphanumeric character removed."),
     "from slug import slugify\n"
     "def test_slug():\n"
     "    assert slugify('Hello, World!') == 'hello-world'\n"
     "    assert slugify(\"It's 100% Great\") == 'its-100-great'\n"
     "    assert slugify('a  b') == 'a-b'\n"),
    ("dates", "dates.py",
     "def day_of_year(s):\n    return int(s.split('-')[1])\n",
     "day_of_year(s) must return the day-of-year for the project's date "
     "string convention.",
     ("Convention: dates are ISO 8601 'YYYY-MM-DD'; day-of-year is the "
      "1-based ordinal."),
     "from dates import day_of_year\n"
     "def test_doy():\n"
     "    assert day_of_year('2024-01-01') == 1\n"
     "    assert day_of_year('2024-03-01') == 61\n"
     "    assert day_of_year('2023-12-31') == 365\n"),
    ("csv", "csvx.py",
     "def split_csv(line):\n    return line.split(',')\n",
     "split_csv(line) must split one CSV record into fields per the "
     "project's CSV convention.",
     ("Convention: double-quoted fields may contain commas; a doubled "
      "quote inside quotes is an escaped quote."),
     "from csvx import split_csv\n"
     "def test_csv():\n"
     "    assert split_csv('a,b,c') == ['a','b','c']\n"
     "    assert split_csv('\"a,b\",c') == ['a,b','c']\n"
     "    assert split_csv('\"x\"\"y\",z') == ['x\"y','z']\n"),
    ("dedup", "dedup.py",
     "def unique_stable(xs):\n    return sorted(set(xs))\n",
     "unique_stable(xs) must remove duplicates per the project's "
     "uniqueness convention.",
     ("Convention: keep the first occurrence, preserving original order; "
      "the result is not sorted."),
     "from dedup import unique_stable\n"
     "def test_dedup():\n"
     "    assert unique_stable([3,1,3,2,1]) == [3,1,2]\n"
     "    assert unique_stable([2,2]) == [2]\n"
     "    assert unique_stable([]) == []\n"),
    ("clamp", "clamp.py",
     "def clamp(v, lo, hi):\n    return max(lo, min(hi, v))\n",
     "clamp(v, lo, hi) must bound v to [lo, hi] per the project's "
     "bounds convention.",
     ("Convention: if lo > hi the bounds are swapped before clamping."),
     "from clamp import clamp\n"
     "def test_clamp():\n"
     "    assert clamp(5, 0, 3) == 3\n"
     "    assert clamp(5, 3, 0) == 3\n"
     "    assert clamp(-1, 0, 3) == 0\n"),
]


def codex_agent(ctx, *, statements):
    statement, mod = statements[ctx.task.task_id]
    parts = [PROMPT.format(mod=mod, statement=statement)]
    if ctx.guidance is not None and ctx.guidance.decision == "recommend":
        hints = "\n".join("- " + h for h in ctx.guidance.helpful_next_checks)
        parts.append("\nProject conventions (advisory):\n" + hints)
    proc = subprocess.run(
        ["codex", "exec", "-C", str(ctx.workspace),
         "-s", "workspace-write", "--skip-git-repo-check",
         "".join(parts)],
        capture_output=True, text=True,
        timeout=max(60, int(ctx.budget.wall_seconds) - 15))
    (ctx.workspace / ".codex_exec.log").write_text(
        (proc.stdout or "") + "\n" + (proc.stderr or ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--wall", type=float, default=420)
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="sis-live-study-"))
    registry, reg_seed = make_registry()
    grants, grant_seed, grant_key = make_grant_authority(registry)
    src_tree = "f" * 64
    register_repo(registry, reg_seed, registry_id="repo-src",
                  base_tree_digest=src_tree)
    eval_seed, eval_pub, eval_key = evaluator_keypair()
    db = AuthorityDB(root / "authority.db")
    controller = PromotionController(
        db, operator_token_digest=operator_token_digest(TEST_TOKEN),
        trusted_evaluator_keys={eval_key: eval_pub.hex()})
    receipt_src = signed_receipt(eval_seed, eval_key, task_id="t-src",
                                 repo_digest=src_tree)
    receipt_table = {receipt_src.digest: receipt_src}
    controller._resolve_receipt = receipt_table.__getitem__
    executor = LocalSubprocessExecutor(root / "exec")
    verifier = OutcomeVerifier(executor=executor, key_dir=root / "eval-keys",
                               registry_dir=root / "eval-reg")

    statements, envelopes, repo_of = {}, [], {}
    for name, mod, src, statement, steps, test in TASKS:
        task_id = "task-" + name
        ident_name = "eval-" + name
        repo = root / "fixtures" / name
        repo.mkdir(parents=True)
        (repo / mod).write_text(src)
        repo_tree = tree_digest(repo)
        register_repo(registry, reg_seed, registry_id=ident_name,
                      base_tree_digest=repo_tree)
        statements[task_id] = (statement, mod)

        # Qualified procedure carrying the convention, granted to this repo.
        sig = "sig-" + name
        proc = ProcedureRecordV1(
            schema_version=1, procedure_id="strat-" + name, revision=1,
            intent="Project convention for " + name,
            language="python", frameworks=(), task_signatures=(),
            failure_signatures=(sig,),
            preconditions=({"kind": "language_is", "value": "python"},
                           {"kind": "failure_signature_is", "value": sig}),
            contraindications=(),
            steps=(steps,) if isinstance(steps, str) else tuple(steps),
            required_verification=("Task-owned acceptance suite must pass.",),
            counterexample_refs=(), evidence_refs=("1" * 64,),
            outcome_distribution={"tasks": 1, "successes": 1, "failures": 0,
                                  "regressions": 0},
            status="candidate", expires_at=None)
        seed(db, proc)
        receipt = signed_receipt(eval_seed, eval_key, task_id="r-" + name,
                                 repo_digest=repo_tree)
        receipt_table[receipt.digest] = receipt
        drive(db, controller, proc.procedure_id, "qualified",
              token=TEST_TOKEN, seed=eval_seed, key_id=eval_key,
              receipts=[receipt])
        issue_and_commit_grant(
            db, controller, grants, record=db.get(proc.procedure_id),
            source_registry_id="repo-src", target_registry_id=ident_name,
            seed=grant_seed, key_id=grant_key,
            evidence_receipts=(receipt_src, receipt),
            grant_nonce="g-" + name)

        verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1",
            argv=(sys.executable, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py": test.encode()}, base_commit="a1b2c3d")
        env = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=repo_tree, base_commit="a1b2c3d",
            task_statement_digest="d" * 64, permitted_commands=("codex",),
            isolation_profile="unverified_local",
            time_budget_seconds=int(args.wall), token_budget=1_000_000,
            tool_budget=10_000, actor_id="study-operator",
            evaluator_task_ref=task_id)
        envelopes.append((env, repo))
        repo_of[task_id] = ident_name

    assert_repository_disjoint([src_tree], [e for e, _ in envelopes])
    gateway = StrictGuidanceGateway(
        db, controller, repository_registry=registry,
        grant_authority=grants)

    def context_provider(task, arm):
        if arm != "D":
            return None
        req = GuidanceRequestV1(
            schema_version=1, task_id=task.task_id,
            repo_snapshot_digest=task.repo_snapshot_digest,
            base_commit=task.base_commit, namespace="ns",
            language="python", toolchain="pytest", lockfile_digests={},
            task_summary=statements[task.task_id][0],
            failure_signatures=("sig-" + task.task_id.removeprefix("task-"),),
            present_symbols=(), semantic_contract_digest="c" * 64)
        return gateway.recommend(req, repository_id=repo_of[task.task_id])

    harness = BenchmarkHarness(verifier=verifier, work_root=root / "work")
    report = harness.run(
        envelopes, lambda ctx: codex_agent(ctx, statements=statements),
        budget=BudgetCaps(wall_seconds=int(args.wall),
                          token_budget=1_000_000, tool_budget=10_000),
        context_provider=context_provider)
    summary = paired_summary(report)
    out = {"report_digest": report_digest(report), "report": report,
           "summary": summary, "study_root": str(root)}
    args.output.write_text(json.dumps(out, indent=2, sort_keys=True))
    delta = summary["contrast"]["solved_delta"]
    p = float(summary["contrast"]["mcnemar_exact_p"])
    print(json.dumps({"digest": out["report_digest"], "solved":
                      report["solved_counts"], "delta": delta,
                      "mcnemar_p": p,
                      "gate": delta > 0 and p <= 0.05}, indent=2))
    return 0 if (delta > 0 and p <= 0.05) else 2


if __name__ == "__main__":
    raise SystemExit(main())
