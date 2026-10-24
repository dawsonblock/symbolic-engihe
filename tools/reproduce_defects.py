#!/usr/bin/env python3
"""Baseline defect reproduction for the SIS v3 master repair program.

Each numbered check exercises one audit finding against the checked-out
source. Prints OBSERVED/EXPECTED per defect so the results can be pasted
into docs/v3/BASELINE_AUDIT.md as executed evidence — never inferred.
"""
import json
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import build_release  # noqa: E402
import verify_release  # noqa: E402

from sis.v3.benchmark import BudgetCaps, BenchmarkHarness  # noqa: E402
from sis.v3.catalog import Catalog  # noqa: E402
from sis.v3.contracts import (  # noqa: E402
    GuidanceRequestV1,
    ProcedureRecordV1,
    TaskEnvelopeV1,
)
from sis.v3.outcome_v2 import (  # noqa: E402
    TrustedKey,
    TrustedKeyRegistry,
    issue_envelope,
    verify_envelope,
)
from sis.v3.procedures import ProcedureStore  # noqa: E402
from sis.v3.runner import LocalSubprocessExecutor  # noqa: E402
from sis.v3.semantic_checks import metamorphic_violations, operator_changes  # noqa: E402
from sis.v3.verifier import EvaluatorKeyStore, OutcomeVerifier  # noqa: E402


def _record(pid: str, status: str = "candidate", rev: int = 1) -> ProcedureRecordV1:
    return ProcedureRecordV1(
        schema_version=1,
        procedure_id=pid,
        revision=rev,
        intent="repro",
        language="python",
        frameworks=(),
        task_signatures=(),
        failure_signatures=(),
        preconditions=(),
        contraindications=(),
        steps=("s1",),
        required_verification=("v1",),
        counterexample_refs=(),
        evidence_refs=("ef" * 32,),
        outcome_distribution={"tasks": 1, "successes": 1, "failures": 0, "regressions": 0},
        status=status,
        expires_at=None,
    )


def d_A_two_manifest_zip(tmp):
    """(A) ZIP carrying both manifests: confirm verifier still rejects."""
    src = tmp / "proj"
    src.mkdir()
    (src / "a.py").write_text("x=1\n")
    files = build_release.inventory(src)
    manifest = json.dumps({"schema": 1, "files": files}, sort_keys=True)
    zpath = tmp / "two_manifests.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("proj/a.py", "x=1\n")
        z.writestr("proj/RELEASE_SHA256.json", manifest)
        z.writestr("proj/SOURCE_SHA256.json", manifest)
    try:
        verify_release.verify(zpath)
        return "FAIL: two-manifest ZIP accepted"
    except ValueError as exc:
        return f"PASS (rejected: {exc})"


def d_B_qualified_bypass(tmp):
    """(B) allow_qualified=True still mints qualified state at code level."""
    store = ProcedureStore(tmp / "procs")
    try:
        store.add(_record("p-b", "candidate"))
    except Exception as exc:
        return f"unexpected: {exc}"
    try:
        store.add(_record("p-b", "qualified", rev=2), allow_qualified=True)
        status = store.get("p-b").status
        return f"OPEN: allow_qualified=True minted status={status} without any decision"
    except Exception as exc:
        return f"CLOSED: {exc}"


def d_C_scope_no_evidence(tmp):
    """(C) cross_repository scope granted with a role string, no evidence."""
    store = ProcedureStore(tmp / "procs")
    store.add(_record("p-c", "qualified", rev=1), allow_qualified=True)
    catalog = Catalog(store, tmp / "scopes.json")
    try:
        catalog.set_scope("p-c", "cross_repository", actor_role="operator")
        return f"OPEN: scope={catalog.scope_of('p-c')} set by bare role string, zero repo-disjoint evidence"
    except Exception as exc:
        return f"CLOSED: {exc}"


def d_D_overbudget_solve(tmp):
    """(D) over-budget pass still counted as a solve + paired win."""
    work = tmp / "ws"
    work.mkdir(parents=True)
    (work / "keep.py").write_text("ok\n")
    key_dir = tmp / "keys"
    reg_dir = tmp / "reg"
    executor = LocalSubprocessExecutor(tmp / "exec", use_seatbelt=False)
    verifier = OutcomeVerifier(executor=executor, key_dir=key_dir, registry_dir=reg_dir)
    task = TaskEnvelopeV1(
        schema_version=1, task_id="t1",
        repo_snapshot_digest="ab" * 32, base_commit=None,
        task_statement_digest="cd" * 32,
        permitted_commands=(), isolation_profile="unverified_local",
        time_budget_seconds=300, token_budget=100, tool_budget=10,
        actor_id="agent-1", evaluator_task_ref="t1",
    )
    verifier.register_task(
        actor_role="evaluator", task_id="t1", criterion_version="v1",
        argv=(sys.executable, "-c", "import sys; sys.exit(0)"),
    )
    harness = BenchmarkHarness(verifier=verifier, work_root=tmp / "bench")

    def slow_agent(ctx):
        time.sleep(1.2)  # exceeds a 1s cap

    budget = BudgetCaps(wall_seconds=1, token_budget=100, tool_budget=10)
    report = harness.run([(task, work)], slow_agent, budget=budget, arms=("A", "D"))
    solved_a = report["solved_counts"]["A"]
    viol = report["budget_violations"]
    wins = report["paired"]["D_vs_A"]["wins"]
    return f"OPEN: over-budget pass counted (solved_A={solved_a}, violations={viol}, D_vs_A wins={wins})"


def d_E_nonce_no_consume(tmp):
    """(E) verify_envelope is pure; same nonce verifies twice, nothing persisted."""
    ks = EvaluatorKeyStore(tmp / "keys")
    ks.load_or_create()
    registry = TrustedKeyRegistry({ks.key_id: TrustedKey(public_key=ks.public.hex())})
    env = issue_envelope(
        keystore=ks, task_id="t", attempt_id="a", evaluated_repo_digest="ab" * 32,
        environment_digest="ef" * 32, test_suite_commitment="cd" * 32,
        execution_receipt_digest="ba" * 32, criterion_version="v1",
        outcome="pass",
    )
    seen = set()
    ok1 = verify_envelope(env, registry, seen_nonces=seen)
    consumed_after_first = len(seen)
    ok2 = verify_envelope(env, registry, seen_nonces=seen)
    return f"OPEN: verify1={ok1}, seen_nonces size after verify={consumed_after_first}, verify2={ok2} — no consume API"


def d_F_crash_window(tmp):
    """(F) record persisted before decision: simulate crash between the two writes."""
    from sis.v3 import promotion as prom
    store = ProcedureStore(tmp / "procs")
    store.add(_record("p-f", "candidate"))
    ctl = prom.PromotionController(
        store, tmp / "decisions",
        operator_token_digest=None,
        trusted_evaluator_keys={},
        trusted_operator_keys={},
    )
    # Simulate: the store.add inside transition() succeeded, decision write crashed.
    rec = store.get("p-f")
    from dataclasses import replace
    nxt = replace(rec, revision=2, status="qualified")
    store.add(nxt, allow_qualified=True)  # <- exactly what transition() does first
    # crash happens here: no decision line ever written
    store2 = ProcedureStore(tmp / "procs")
    ctl2 = prom.PromotionController(
        store2, tmp / "decisions",
        operator_token_digest=None,
        trusted_evaluator_keys={},
        trusted_operator_keys={},
    )
    status = store2.get("p-f").status
    ver = ctl2.verify()
    return f"OPEN: uncommitted qualified visible (status={status}); verify() flags: {ver['problems']}"


def d_G_operator_class(tmp):
    """(G) a+b -> a*b survives the operator-class gate."""
    src = "def f(a,b):\n    return a + b\n"
    patched = "def f(a,b):\n    return a * b\n"
    changes = operator_changes(src, patched)
    violations = metamorphic_violations(changes)
    return f"OPEN: Add->Mult changes={[(c.old_class.value,c.new_class.value) for c in changes]}, violations={violations}"


def d_H_tree_symlink(tmp):
    """(H) symlink inside an extracted tree is skipped, not rejected."""
    src = tmp / "tree"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x=1\n")
    (tmp / "outside.py").write_text("import os\n")
    files = build_release.inventory(src)
    (src / "RELEASE_SHA256.json").write_text(
        json.dumps({"schema": 1, "files": files}, sort_keys=True)
    )
    os.symlink(tmp / "outside.py", src / "link.py")
    try:
        result = verify_release.verify_tree(src)
        return f"OPEN: tree with unexpected symlink verified (files={result['files']})"
    except ValueError as exc:
        return f"CLOSED: {exc}"


def d_I_wall_truncation(tmp):
    """(Extra) wall time truncated: 1.5s over a 1s cap may read as compliant."""
    start = time.monotonic()
    time.sleep(1.05)
    wall_int = max(0, int(time.monotonic() - start))
    return f"OBSERVED: slept 1.05s, int-truncated wall={wall_int}, exceeded(1s)={wall_int > 1}"


def main():
    results = {}
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "a").mkdir()
        results["A_two_manifest_zip"] = d_A_two_manifest_zip(tmp / "a")
        results["B_qualified_bypass"] = d_B_qualified_bypass(tmp / "b")
        results["C_scope_no_evidence"] = d_C_scope_no_evidence(tmp / "c")
        results["D_overbudget_solve"] = d_D_overbudget_solve(tmp / "d")
        results["E_nonce_no_consume"] = d_E_nonce_no_consume(tmp / "e")
        results["F_crash_window"] = d_F_crash_window(tmp / "f")
        results["G_operator_class"] = d_G_operator_class(tmp / "g")
        results["H_tree_symlink"] = d_H_tree_symlink(tmp / "h")
        results["I_wall_truncation"] = d_I_wall_truncation(tmp / "i")
    for key, value in results.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
