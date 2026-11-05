"""SIS v3.5.1 qualification harness.

Runs each release gate as a separate process, records the exact command,
environment, expected result, actual result and disposition, and writes
``qualification/qualification.json``.

A gate that cannot run is reported as ``blocked`` — never as ``pass``.
The final decision is computed from the gates, not asserted.

Usage::

    python tools/v351_qualify.py
    SIS_POSTGRES_DSN=... python tools/v351_qualify.py --with-postgres
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "qualification"
SUMMARY = re.compile(r"(\d+) (passed|failed|skipped|error)")

#: Controls that are satisfied but bounded, or capabilities not exercised.
#: These do not fail a gate; they prevent an unrestricted GO claim.
LIMITATIONS = (
    "evaluator-key-compromise: a compromised evaluator key can forge that "
    "evaluator's measurements (arm, task, model and preregistration come "
    "from other keys, so cross-arm re-attribution is still refused)",
    "unsigned-telemetry: abstained / negative_transfer / integrity_failures "
    "are report fields and do not feed the supported verdict",
    "evaluator-metering-trust: signed token and wall-clock values are what "
    "the evaluator reports; 'unmetered' runs cannot support a claim",
    "single-container-runtime: the enforced boundary was demonstrated with "
    "Docker only; podman is supported by name and unexercised",
    "local-image-pin: image integrity is a re-checked local image id, not a "
    "registry attestation chain",
    "manifest-not-publisher-signed: RELEASE_SHA256.json is locally generated "
    "and detects drift, not authorship; the v3.5.1 provenance statement is "
    "unsigned, a downgrade from the signed DSSE envelope shipped in v3.3.2",
    "no-capability-evaluation: no model-weight or task-success benchmark was "
    "run; no reasoning-capability improvement is claimed",
    "audit-baseline-unexplained: the prior audit's 45 baseline failures did "
    "not reproduce in the pinned environment and remain unattributed",
)

#: Declared only when the tree the archive was built from is dirty.
UNCOMMITTED = (
    "uncommitted-source: the archive was built from a working tree with "
    "uncommitted changes; it is bound to its own manifest, not to a commit",
)


def _limitations(root: Path = ROOT) -> tuple[str, ...]:
    """The declared limitations, including the dirty-tree one when true."""
    import subprocess
    try:
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain",
             "--untracked-files=all"],
            capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return LIMITATIONS
    dirty = [line for line in status.splitlines()
             if line[3:].strip() and not line[3:].strip().startswith(
                 ("release/", "qualification/"))
             and line[3:].strip() not in {
                 "RELEASE_SHA256.json",
                 "evidence/release/build_record.json"}]
    return (*LIMITATIONS, UNCOMMITTED) if dirty else LIMITATIONS


def _run(argv, *, env_extra=None, timeout=1800):
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", f"{ROOT / 'src'}:{ROOT}")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env_extra:
        env.update(env_extra)
    started = time.time()
    try:
        completed = subprocess.run(argv, cwd=str(ROOT), env=env,
                                   capture_output=True, timeout=timeout)
        returncode = completed.returncode
        stdout = completed.stdout.decode("utf-8", "replace")
        stderr = completed.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as expired:
        # A hung gate is a failed gate, not a crashed harness: the run
        # record must still be written with the gate's disposition.
        returncode = -1
        stdout = (expired.stdout or b"").decode("utf-8", "replace")
        stderr = (expired.stderr or b"").decode("utf-8", "replace")
        stderr += f"\ngate timed out after {timeout}s"
    return {
        "argv": argv,
        "returncode": returncode,
        "seconds": round(time.time() - started, 1),
        "stdout": stdout,
        "stderr": stderr,
    }


#: Limitations that prevent an unrestricted ``GO`` even when every gate
#: passes. Removing one from ``LIMITATIONS`` is what makes ``GO`` possible.
BLOCKING_LIMITATIONS = frozenset({
    "evaluator-key-compromise",
    "no-capability-evaluation",
    "uncommitted-source",
})


def _counts(output: str) -> dict:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
    for line in reversed(output.splitlines()):
        if " passed" in line or " failed" in line or " skipped" in line:
            for value, kind in SUMMARY.findall(line):
                counts[kind] = max(counts.get(kind, 0), int(value))
            break
    return counts


def _decide(statuses, limitations) -> str:
    """The release decision, computed from gates and blocking limitations."""
    if "fail" in statuses:
        return "NO_GO"
    if "blocked" in statuses:
        return "CONDITIONAL_GO"
    blocking = [item.split(":", 1)[0] for item in limitations]
    if any(name in BLOCKING_LIMITATIONS for name in blocking):
        return "CONDITIONAL_GO"
    return "GO"


def _gate(name, invariant, result, *, expected="exit 0",
          blocked_reason=None):
    counts = _counts(result["stdout"] + result["stderr"])
    if blocked_reason:
        status = "blocked"
    elif result["returncode"] == 0:
        status = "pass"
    else:
        status = "fail"
    return {
        "gate": name,
        "invariant": invariant,
        "command": " ".join(result["argv"]),
        "expected": expected,
        "actual_returncode": result["returncode"],
        "counts": counts,
        "status": status,
        "seconds": result["seconds"],
        "blocked_reason": blocked_reason,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-postgres", action="store_true",
                        help="require the PostgreSQL gate to run")
    args = parser.parse_args(argv)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    python = sys.executable
    gates = []

    focused = _run([python, "-m", "pytest", "-q",
                    "tests/v3/test_v351_evidence_chain.py",
                    "tests/v3/test_v351_report_totality.py",
                    "tests/v3/test_v340_five_arm.py",
                    "tests/v3/test_v350_campaign_integrity.py",
                    "tests/v3/test_v350_production_profile.py"])
    gates.append(_gate(
        "evidence_and_report_integrity",
        "A valid signature must be valid for the exact trial, arm, task, "
        "outcome and measurement claimed.", focused))
    (EVIDENCE / "focused_tests.log").write_text(
        focused["stdout"] + focused["stderr"])

    isolation = _run([python, "-m", "pytest", "-q",
                      "tests/v3/test_v351_container_isolation.py"])
    isolation_counts = _counts(isolation["stdout"] + isolation["stderr"])
    blocked = None if (isolation_counts["passed"] and
                       not isolation_counts["skipped"]) else \
        "container runtime unavailable or isolation tests skipped; " \
        "boundary unproven"
    gates.append(_gate(
        "evaluator_isolation",
        "The workload cannot reach the network, the host filesystem, or "
        "the signing key.", isolation, blocked_reason=blocked))
    (EVIDENCE / "container_isolation.log").write_text(
        isolation["stdout"] + isolation["stderr"])

    dsn = os.environ.get("SIS_POSTGRES_DSN")
    destructive = os.environ.get("SIS_POSTGRES_ALLOW_DESTRUCTIVE") == "1"
    postgres = _run([python, "-m", "pytest", "-q",
                     "tests/v3/test_control_plane_postgres.py",
                     "tests/v3/test_v351_postgres_qualification.py"])
    gates.append(_gate(
        "postgres_cross_process",
        "Two processes cannot both commit the same authorization.",
        postgres,
        blocked_reason=None if (dsn and destructive) else
        "SIS_POSTGRES_DSN and SIS_POSTGRES_ALLOW_DESTRUCTIVE=1 not both "
        "configured; cross-replica claims unqualified"))
    (EVIDENCE / "postgres.log").write_text(
        postgres["stdout"] + postgres["stderr"])

    full = _run([python, "-m", "pytest", "tests", "-q"])
    gates.append(_gate(
        "full_regression",
        "No unexplained regression against the v3.5.0 baseline (1362 passed).",
        full))
    (EVIDENCE / "full_suite.log").write_text(full["stdout"] + full["stderr"])

    manifest = _run([python, "tools/build_release.py", "--check"])
    gates.append(_gate(
        "release_manifest",
        "Every distributed file matches RELEASE_SHA256.json.",
        manifest))

    verify = _run([python, "tools/verify_release.py", "."])
    gates.append(_gate(
        "release_verification",
        "A fresh extraction verifies against its own manifest.",
        verify))

    statuses = {gate["status"] for gate in gates}
    limitations = _limitations()
    decision = _decide(statuses, limitations)
    if args.with_postgres and not dsn:
        decision = "NO_GO"

    document = {
        "schema_version": 1,
        "release": "3.5.1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "python": sys.version.split()[0],
            "executable": sys.executable,
            "platform": platform.platform(),
            "postgres_dsn_configured": bool(dsn),
            "container_runtime": _runtime(),
        },
        "gates": gates,
        "decision": decision,
        "decision_basis": {
            "fail": sorted(g["gate"] for g in gates if g["status"] == "fail"),
            "blocked": sorted(g["gate"] for g in gates
                              if g["status"] == "blocked"),
            "limitations": list(limitations),
        },
    }
    (EVIDENCE / "qualification.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n")

    for gate in gates:
        print(f"{gate['status']:8} {gate['gate']:32} "
              f"{gate['counts']} ({gate['seconds']}s)"
              + (f"  [{gate['blocked_reason']}]"
                 if gate["blocked_reason"] else ""))
    print(f"\nrelease decision: {decision}")
    if limitations:
        print("declared limitations (restrict the deployment scope):")
        for item in limitations:
            print(f"  - {item}")
    return 0 if decision in ("GO", "CONDITIONAL_GO") else 1


def _runtime() -> str | None:
    from shutil import which
    for candidate in ("docker", "podman"):
        if which(candidate):
            return candidate
    return None


if __name__ == "__main__":
    raise SystemExit(main())
