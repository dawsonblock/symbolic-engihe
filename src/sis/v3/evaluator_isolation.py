"""Isolated evaluator execution (PR-08).

The evaluator is a separate trusted subsystem, not a helper the agent
starts. This module describes the isolation an evaluation ran under,
refuses to call an unisolated run a production evaluation, and treats a
worker crash as an error rather than a result.

What is actually enforced here, on every platform:

- a fresh process group, so a timeout kills the whole tree;
- a clean environment (no inherited ``SIS_*``, no proxy variables);
- POSIX resource limits (address space, CPU, file size, open files);
- a wall-clock bound enforced by the parent;
- a submission directory copied into the evaluator's own workspace.

What is *declared* and must be provided by the platform: network
isolation and an immutable image. ``IsolationProfile.production_ready``
is only true when both are declared, and the receipt records the declared
profile so a reader can see which claims were verified and which were
assumed.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    EvaluatorReceiptV2,
    ExecutionAttemptV2,
    AuthorizationV2,
    ContractError,
    canonical_digest,
)
from .evidence_binding import (
    attempt_exposure_digest,
    sign_receipt,
    unreported_exposure_digest,
)

NETWORK_NONE = "none"
NETWORK_LOOPBACK = "loopback"
NETWORK_HOST = "host"

_EXEC_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")


class IsolationError(RuntimeError):
    """The requested isolation is not acceptable for this mode."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class IsolationProfile:
    """Declared isolation of one evaluator run."""

    network: str = NETWORK_NONE
    memory_bytes: int = 2 * 1024 * 1024 * 1024
    cpu_seconds: int = 300
    wall_seconds: int = 600
    open_files: int = 256
    file_bytes: int = 64 * 1024 * 1024
    read_only_root: bool = True
    inherit_env: bool = False
    image_digest: str | None = None

    def __post_init__(self) -> None:
        if self.network not in (NETWORK_NONE, NETWORK_LOOPBACK, NETWORK_HOST):
            raise IsolationError("network_mode_invalid", self.network)
        for name, maximum in (("memory_bytes", 1 << 40),
                              ("cpu_seconds", 86_400),
                              ("wall_seconds", 86_400),
                              ("open_files", 65_536),
                              ("file_bytes", 1 << 40)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise IsolationError(f"{name}_invalid", str(value))
        if self.image_digest is not None and not (
                isinstance(self.image_digest, str)
                and len(self.image_digest) == 64):
            raise IsolationError("image_digest_invalid")

    @property
    def production_ready(self) -> bool:
        return (self.network == NETWORK_NONE
                and self.read_only_root
                and not self.inherit_env
                and self.image_digest is not None)

    def digest(self) -> str:
        return canonical_digest("isolation_profile", 1, {
            "network": self.network,
            "memory_bytes": self.memory_bytes,
            "cpu_seconds": self.cpu_seconds,
            "wall_seconds": self.wall_seconds,
            "open_files": self.open_files,
            "file_bytes": self.file_bytes,
            "read_only_root": self.read_only_root,
            "inherit_env": self.inherit_env,
            "image_digest": self.image_digest,
        })

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "network": self.network,
            "memory_bytes": self.memory_bytes,
            "cpu_seconds": self.cpu_seconds,
            "wall_seconds": self.wall_seconds,
            "open_files": self.open_files,
            "file_bytes": self.file_bytes,
            "read_only_root": self.read_only_root,
            "inherit_env": self.inherit_env,
            "image_digest": self.image_digest,
            "production_ready": self.production_ready,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "IsolationProfile":
        """Rebuild the declared profile a parent sent to the worker."""
        if not isinstance(value, dict):
            raise IsolationError("profile_invalid")
        fields = {name: value[name] for name in (
            "network", "memory_bytes", "cpu_seconds", "wall_seconds",
            "open_files", "file_bytes", "read_only_root", "inherit_env",
            "image_digest") if name in value}
        return cls(**fields)


def development_profile() -> IsolationProfile:
    return IsolationProfile(network=NETWORK_HOST, read_only_root=False,
                            image_digest=None)


def production_profile(image_digest: str) -> IsolationProfile:
    return IsolationProfile(network=NETWORK_NONE, read_only_root=True,
                            inherit_env=False, image_digest=image_digest)


def verify_profile(profile: IsolationProfile, *, production: bool) -> None:
    """Fail closed when a production evaluation is not actually isolated."""
    if not isinstance(profile, IsolationProfile):
        raise IsolationError("profile_invalid")
    if not production:
        return
    if profile.network != NETWORK_NONE:
        raise IsolationError("production_requires_network_isolation",
                             profile.network)
    if not profile.read_only_root:
        raise IsolationError("production_requires_read_only_root")
    if profile.inherit_env:
        raise IsolationError("production_requires_clean_environment")
    if profile.image_digest is None:
        raise IsolationError("production_requires_pinned_image")


@dataclass(frozen=True)
class IsolatedResult:
    """Outcome of one isolated run. A crash never yields a receipt."""

    result: str
    exit_status: int | None
    crashed: bool
    timed_out: bool
    receipt: EvaluatorReceiptV2 | None
    profile: IsolationProfile
    stderr_tail: str = ""

    def as_dict(self) -> dict:
        return {
            "result": self.result,
            "exit_status": self.exit_status,
            "crashed": self.crashed,
            "timed_out": self.timed_out,
            "signed": self.receipt is not None,
            "isolation": self.profile.to_dict(),
            "stderr_tail": self.stderr_tail,
        }


def _clean_env() -> dict:
    env = {"PYTHONPATH": str(Path(__file__).resolve().parents[2]),
           "PYTHONDONTWRITEBYTECODE": "1"}
    for name in _EXEC_ENV_ALLOWLIST:
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def apply_limits(profile: IsolationProfile) -> tuple[str, ...]:
    """Apply the POSIX limits this platform supports, in this process.

    Called by the worker itself rather than through ``preexec_fn``:
    ``preexec_fn`` runs between fork and exec and is documented as unsafe
    in a threaded parent. The child applies the same limits to itself and
    to every process it starts, and reports which ones took.

    Each limit is applied independently: a kernel that does not support
    ``RLIMIT_AS`` (macOS in several configurations) must not turn every
    evaluation into a launch failure.
    """
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return ()
    applied: list[str] = []
    for name, value in (
        ("RLIMIT_AS", profile.memory_bytes),
        ("RLIMIT_CPU", profile.cpu_seconds),
        ("RLIMIT_FSIZE", profile.file_bytes),
        ("RLIMIT_NOFILE", profile.open_files),
    ):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            continue
        applied.append(name)
    return tuple(applied)


def run_isolated(
    *,
    seed_path: str | Path,
    key_id: str,
    authorization: AuthorizationV2,
    attempt: ExecutionAttemptV2 | None,
    submission_dir: str | Path,
    task,
    key_dir: str | Path,
    registry_dir: str | Path,
    profile: IsolationProfile,
    production: bool = False,
    receipt_nonce: str,
    issued_at: str,
    expires_at: str | None = None,
    measurement_nonce: str | None = None,
    executor_root: str | Path | None = None,
    python: str = sys.executable,
    extra_argv: tuple[str, ...] = (),
) -> IsolatedResult:
    """Run the evaluator in a bounded child; the child measures and signs.

    The parent sends only the binding: which authorization and attempt,
    which submission and task, and the isolation profile. It does **not**
    send a result. The child runs the registered acceptance command in its
    own executor, derives the outcome, artifact digest, suite commitment
    and environment digest from that measurement, and only then signs the
    receipt with the evaluator seed. If the child dies, nothing is signed.
    """
    verify_profile(profile, production=production)
    if production:
        # The worker is an ordinary host process: the profile above is a
        # declaration, not a boundary, and the submission can read
        # whatever the worker can read — including the evaluator seed it
        # is handed to sign with. ``sis.v3.container_isolation`` is the
        # enforced boundary, but the verifier's bootstrap probe runs the
        # host interpreter with a host-relative argv and writes under the
        # registry root, so wiring it in is a change to that contract and
        # not a flag. Until then a production evaluation refuses to start
        # rather than claim an isolation it does not provide.
        raise IsolationError(
            "production_boundary_not_enforced",
            "run_isolated executes on the host; "
            "sis.v3.container_isolation is not wired into this path")
    if not isinstance(authorization, AuthorizationV2):
        raise IsolationError("authorization_required")
    if attempt is not None and not isinstance(attempt, ExecutionAttemptV2):
        raise IsolationError("attempt_invalid")
    submission = Path(submission_dir)
    if not submission.is_dir():
        raise IsolationError("submission_dir_missing", str(submission))
    for name, value in (("key_dir", key_dir), ("registry_dir", registry_dir)):
        if not Path(value).is_dir():
            raise IsolationError(f"{name}_missing", str(value))
    for token in extra_argv:
        # The receipt path and the mode are the parent's decision; a
        # caller-supplied flag must not redirect the signed output.
        if token in {"--receipt-out", "--bound-receipt"}:
            raise IsolationError("extra_argv_override_refused", token)

    exposure_digest = (attempt_exposure_digest(attempt) if attempt is not None
                       else unreported_exposure_digest(authorization))
    binding = {
        "seed_path": str(seed_path),
        "key_id": key_id,
        "receipt_nonce": receipt_nonce,
        "measurement_nonce": measurement_nonce or receipt_nonce,
        "guidance_exposure_digest": exposure_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "authorization": authorization.to_dict(),
        "isolation": profile.to_dict(),
        "submission": str(submission),
        "key_dir": str(key_dir),
        "registry_dir": str(registry_dir),
        "task": (task.to_dict() if hasattr(task, "to_dict") else dict(task)),
        "executor_root": None if executor_root is None else str(executor_root),
    }
    out_dir = Path(tempfile.mkdtemp(prefix="sis-eval-v2-"))
    out_path = out_dir / "receipt_v2.json"
    argv = [python, "-m", "sis.v3.evaluator_worker", "--bound-receipt",
            "--receipt-out", str(out_path), *extra_argv]
    try:
        try:
            launch = {
                "stdin": subprocess.PIPE, "stdout": subprocess.DEVNULL,
                "stderr": subprocess.PIPE, "env": _clean_env(),
            }
            if os.name == "posix":
                launch["start_new_session"] = True
            proc = subprocess.Popen(argv, **launch)
        except OSError as exc:
            raise IsolationError("worker_launch_failed", str(exc)) from exc
        payload = json.dumps(binding, sort_keys=True).encode("utf-8")
        timed_out = False
        try:
            _, stderr = proc.communicate(payload, timeout=profile.wall_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
            _, stderr = proc.communicate()
        tail = stderr.decode("utf-8", "replace")[-512:]
        if timed_out or proc.returncode != 0:
            # A crashed or timed-out worker measured nothing. It must never
            # be reported as a pass, and it signs nothing.
            return IsolatedResult(
                result="error", exit_status=proc.returncode, crashed=True,
                timed_out=timed_out, receipt=None, profile=profile,
                stderr_tail=tail)
        try:
            receipt = EvaluatorReceiptV2.from_json(out_path.read_bytes())
        except (OSError, ContractError):
            return IsolatedResult(
                result="error", exit_status=proc.returncode, crashed=True,
                timed_out=False, receipt=None, profile=profile,
                stderr_tail=tail)
        return IsolatedResult(
            result=receipt.result, exit_status=proc.returncode, crashed=False,
            timed_out=False, receipt=receipt, profile=profile,
            stderr_tail=tail)
    finally:
        # The receipt has been read into memory; the temporary directory
        # (and the worker's signed output) does not outlive this call.
        shutil.rmtree(out_dir, ignore_errors=True)


def sign_bound_receipt(binding: dict, seed: bytes) -> EvaluatorReceiptV2:
    """Sign an EvaluatorReceiptV2 from a binding plus a real measurement.

    ``binding["measured"]`` is written by the worker after it ran the
    acceptance command; it is the only source of the result, artifact
    digest, suite commitment, criterion version and environment digest.
    A binding without a measurement is refused, so the evaluator key can
    never be used to sign a claim the caller supplied.
    """
    authorization = AuthorizationV2.from_dict(binding["authorization"])
    measured = binding.get("measured")
    if not isinstance(measured, dict):
        raise IsolationError("measurement_missing")
    for name in ("result", "artifact_digest", "test_suite_commitment",
                 "environment_digest", "criterion_version"):
        if name not in measured:
            raise IsolationError("measurement_incomplete", name)
    return sign_receipt(
        seed,
        receipt_id="rcpt-" + canonical_digest("evaluator_receipt_id", 1, {
            "authorization_id": authorization.authorization_id,
            "nonce": binding["receipt_nonce"],
        })[:32],
        authorization_id=authorization.authorization_id,
        attempt_id=authorization.attempt_id,
        task_id=authorization.task_id,
        requester_principal_id=authorization.requester_principal_id,
        repository_id=authorization.repository_id,
        repository_tree_digest=authorization.repository_tree_digest,
        base_commit_digest=authorization.base_commit_digest,
        submitted_artifact_digest=measured["artifact_digest"],
        guidance_exposure_digest=binding["guidance_exposure_digest"],
        test_suite_commitment=measured["test_suite_commitment"],
        environment_digest=measured["environment_digest"],
        criterion_version=measured["criterion_version"],
        result=measured["result"],
        independence=binding.get("independence", "independent"),
        dependency_receipt_digest=binding.get("dependency_receipt_digest"),
        evaluator_identity="sis-v3-evaluator",
        issued_at=binding["issued_at"],
        expires_at=binding.get("expires_at"),
        nonce=binding["receipt_nonce"],
        signer_key_id=binding["key_id"],
    )


__all__ = [
    "IsolatedResult",
    "IsolationError",
    "IsolationProfile",
    "NETWORK_HOST",
    "NETWORK_LOOPBACK",
    "NETWORK_NONE",
    "apply_limits",
    "development_profile",
    "production_profile",
    "run_isolated",
    "sign_bound_receipt",
    "verify_profile",
]
