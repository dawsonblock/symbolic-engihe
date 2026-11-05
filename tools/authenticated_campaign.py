#!/usr/bin/env python3
"""End-to-end authenticated five-arm campaign.

Runs the arms for real, signs a receipt and a trial measurement per
(task, arm) cell, builds the controlled report and returns the verdict.
This is the producer ``five_arm.assess`` always needed: without it the
authenticated chain existed only in the test fixtures.

The demo path uses a scripted agent and says so in the artifact. It is
machinery evidence, not a claim about coding-agent efficacy. A real run
supplies its own tasks, agent and keys.

Usage:
    python3 tools/authenticated_campaign.py --demo -o evidence/evaluation/authenticated.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sis.v3 import signatures  # noqa: E402
from sis.v3.authenticated_campaign import (  # noqa: E402
    CampaignCommitments,
    run_authenticated_campaign,
)
from sis.v3.benchmark import BenchmarkHarness, BudgetCaps  # noqa: E402
from sis.v3.contracts import GuidanceV1, TaskEnvelopeV1  # noqa: E402
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.evidence_binding import (  # noqa: E402
    EvidenceBindingAuthority,
    SigningKey,
)
from sis.v3.five_arm import CampaignPlan  # noqa: E402
from sis.v3.governed_eval import GOVERNED_ARMS, preregister  # noqa: E402
from sis.v3.runner import (  # noqa: E402
    LocalSubprocessExecutor,
    ResourceLimits,
    tree_digest,
)
from sis.v3.statistical_power import (  # noqa: E402
    LineageRegistry,
    PowerRequirement,
    RepositoryLineage,
    sign_preregistration,
)
from sis.v3.verifier import OutcomeVerifier  # noqa: E402

PY = sys.executable
TASKS = 4


def _guidance(text="WRITE_OK"):
    return GuidanceV1(
        schema_version=1, decision="recommend", procedure_ids=("p",),
        revision="0" * 64,
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=("0" * 64,),
        policy_digest="0" * 64, helpful_next_checks=(text,),
        reason_code=None, approximate_tokens=20)


def _agent(ctx):
    text = " ".join(ctx.guidance.helpful_next_checks) \
        if ctx.guidance is not None else ""
    if "WRITE_OK" in text:
        (ctx.workspace / "solution.py").write_text("OK = 1\n")
    ctx.usage_meter.record_tokens(10)
    ctx.usage_meter.record_tool_call(1)


def _provider(task, arm):
    return None if arm == "A" else _guidance()


def _build(root: Path):
    repo = root / "repo"
    repo.mkdir()
    (repo / "solution.py").write_text("NO = 1\n")
    profile = EvaluationRuntimeProfile(
        cpu_seconds=60, wall_seconds=120, process_count=None)
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(
            root / "exec",
            protected_paths=(root / "keys", root / "registry")),
        key_dir=root / "keys", registry_dir=root / "registry",
        limits=ResourceLimits(wall_seconds=120, cpu_seconds=60,
                              memory_bytes=profile.task_memory_bytes,
                              process_count=None),
        runtime_profile=profile)
    tasks = []
    for index in range(TASKS):
        task_id = f"demo-task-{index}"
        verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py":
                   b"from pathlib import Path\n\n"
                   b"def test_solution():\n"
                   b"    assert 'OK' in Path('solution.py').read_text()\n"},
            base_commit="abc1234")
        tasks.append((TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(repo),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(
                task_id.encode()).hexdigest(),
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=120, token_budget=1000, tool_budget=100,
            actor_id="agent", evaluator_task_ref=task_id), repo))
    harness = BenchmarkHarness(verifier=verifier, work_root=root / "work")
    return harness, tasks


def _manifest(seed: bytes, key_id: str, preregistration, protocol_digest):
    from sis.v3.five_arm import AnalysisManifest
    lineages = LineageRegistry()
    lineages.add(RepositoryLineage(
        registry_id="repo-1", lineage_id="lin-h", family_id="fam"))
    return AnalysisManifest(
        protocol_digest=protocol_digest, preregistration=preregistration,
        lineages=lineages, first_evaluation_at="2026-02-01T00:00:00Z",
        holdout_repositories=("repo-1",)).sign(seed, key_id)


def run_demo(output: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="sis-authenticated-") as temp:
        root = Path(temp)
        harness, tasks = _build(root)
        experiment_seed = b"\x53" * 32
        evaluator_seed = b"\x51" * 32
        timestamp_seed = b"\x01" * 32
        analysis_seed = b"\x52" * 32
        experiment_key, evaluator_key = "experiment-key-1", "eval-key-1"
        timestamp_key, analysis_key = "tsa-key", "analysis-key-1"

        authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={
                evaluator_key: signatures.public_key(evaluator_seed).hex()},
            trusted_harness_keys={},
            trusted_experiment_keys={
                experiment_key:
                    signatures.public_key(experiment_seed).hex()})

        protocol = preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=1.0,
            sample_size=len(tasks),
            budget={"wall_seconds": 120, "token_budget": 1000,
                    "tool_budget": 100},
            arms=GOVERNED_ARMS)
        # A 4-task demo cannot be powered for a realistic effect; the
        # plan says so and the verdict reports `underpowered`.
        power = PowerRequirement(design="paired_mcnemar", effect_milli=800,
                                 discordant_milli=800)
        preregistration = sign_preregistration(
            timestamp_seed,
            preregistration_id="pre-demo",
            protocol_digest=protocol["protocol_digest"],
            primary_metric="paired solved_delta E vs A",
            power=power.to_dict(),
            holdout_lineages=("lin-h",), training_lineages=("lin-t",),
            registered_at="2026-01-01T00:00:00Z",
            timestamp_authority="tsa", signer_key_id=timestamp_key)
        analysis = _manifest(analysis_seed, analysis_key, preregistration,
                             protocol["protocol_digest"])
        plan = CampaignPlan(
            protocol=protocol,
            power_requirement=power,
            task_ids=tuple(task.task_id for task, _ in tasks),
            seed=20260101)
        commitments = CampaignCommitments(
            experiment_id="exp-demo",
            model_identity="scripted-agent",
            model_digest="7" * 64,
            environment_digest="8" * 64,
            criterion_version="v1",
            test_suite_commitment="1" * 64,
            repository_id="repo-1",
            requester_principal_id="demo-requester",
            authorization_id="authz-demo",
            evaluator_build_digest="4" * 64)
        result = run_authenticated_campaign(
            plan=plan, tasks=tasks, harness=harness, agent=_agent,
            budget=BudgetCaps(wall_seconds=120, token_budget=1000,
                              tool_budget=100),
            context_provider=_provider, commitments=commitments,
            preregistration=preregistration, analysis=analysis,
            experiment_seed=experiment_seed,
            experiment_key_id=experiment_key,
            evaluator_seed=evaluator_seed, evaluator_key_id=evaluator_key,
            receipt_authority=authority,
            trusted_analysis_keys={
                analysis_key: signatures.public_key(analysis_seed).hex()},
            trusted_timestamp_keys={
                timestamp_key:
                    signatures.public_key(timestamp_seed).hex()})
        verdict = result["verdict"]
        document = {
            "schema_version": 1,
            "kind": "authenticated_five_arm_campaign",
            "evidence": (
                "scripted demonstration; machinery evidence only, not a "
                "claim about real coding-agent efficacy"),
            "authorization": result["authorization"].to_dict(),
            "report": result["report"],
            "verdict": verdict,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, indent=2, sort_keys=True)
                          + "\n")
        print(json.dumps({
            "kind": document["kind"],
            "verdict": verdict["verdict"],
            "evidence_class": verdict["evidence_class"],
            "measurements_verified": verdict["measurements_verified"],
            "receipts_verified": verdict["receipts_verified"],
            "analysis_verified": verdict["analysis_verified"],
            "preregistration_verified": verdict["preregistration_verified"],
            "observed_sample_size": verdict["observed_sample_size"],
            "decisive_contrast": verdict["decisive_contrast"],
            "decision_policy": verdict["decision_policy"],
            "problems": verdict["problems"],
            "output": str(output),
        }, indent=2))
        authenticated = (verdict["measurements_verified"]
                         and verdict["receipts_verified"]
                         and verdict["analysis_verified"]
                         and verdict["preregistration_verified"]
                         and verdict["validation"]["ok"])
        return 0 if authenticated else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true",
                        help="run the scripted demonstration")
    parser.add_argument("-o", "--output", type=Path,
                        default=Path("evidence/evaluation/authenticated.json"))
    args = parser.parse_args(argv)
    if not args.demo:
        parser.error("only --demo is implemented; a real run supplies its "
                     "own tasks, agent and custody keys")
    return run_demo(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
