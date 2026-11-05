"""Enforced OS-boundary isolation for evaluator workloads (SIS v3.5.1 PR-07).

``evaluator_isolation`` described the isolation a run *declared*: a
process group, a clean environment, POSIX rlimits and a wall-clock bound.
Those are real controls, but they are not a boundary — a subprocess shares
the host filesystem, the host network namespace and the host user.

This module provides the boundary. The workload runs in a container with:

* ``--network none``            no network namespace access
* ``--read-only`` + tmpfs       an immutable root filesystem
* explicit mounts only          one input tree (ro) and one output tree (rw)
* ``--cap-drop ALL``            no Linux capabilities
* ``--security-opt no-new-privileges``
* ``--memory`` / ``--cpus`` / ``--pids-limit``
* a non-root uid
* a wall-clock bound enforced by the parent

and — the part that matters for evidence — **the evaluator signing seed is
never in the container**. The container produces a measurement; the
trusted parent reads it and signs. A compromised workload therefore
cannot forge a receipt, because it never holds the key.

``ContainerProfile.verified_controls`` reports what this module actually
passed to the runtime. ``production_ready`` is only true when the image is
pinned and every boundary control is on; a profile that cannot be
satisfied fails closed rather than silently degrading.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from .contracts import canonical_digest

RUNTIME_ENV = "SIS_CONTAINER_RUNTIME"

#: The output mount is writable by the workload, so the parent reads at
#: most this much of any one stream or record.
MAX_MEASUREMENT_BYTES = 64 * 1024
MAX_CAPTURE_BYTES = 64 * 1024


class ContainerIsolationError(RuntimeError):
    """The requested container boundary is unavailable or unenforceable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class ContainerProfile:
    """The boundary this deployment promises for one workload run."""

    image: str
    memory_bytes: int = 512 * 1024 * 1024
    cpu_milli: int = 1000
    pids_limit: int = 128
    wall_seconds: int = 300
    tmpfs_bytes: int = 64 * 1024 * 1024
    user: str = "65534:65534"
    image_digest: str | None = None
    network: str = "none"
    read_only_root: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True

    def __post_init__(self) -> None:
        if (not isinstance(self.image, str) or not self.image
                or self.image.startswith("-")):
            # An image beginning with ``-`` is a runtime flag, not an
            # image: ``docker run ... --privileged <command>`` would
            # promote the workload command to the image position.
            raise ContainerIsolationError("image_invalid", str(self.image))
        for name, maximum in (("memory_bytes", 1 << 40),
                              ("pids_limit", 65_536),
                              ("wall_seconds", 86_400),
                              ("tmpfs_bytes", 1 << 30)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ContainerIsolationError(f"{name}_invalid", str(value))
        if type(self.cpu_milli) is not int or not (
                1 <= self.cpu_milli <= 256_000):
            raise ContainerIsolationError("cpu_milli_invalid")
        if self.network not in ("none", "loopback", "host"):
            raise ContainerIsolationError("network_mode_invalid", self.network)
        if self.image_digest is not None and not (
                isinstance(self.image_digest, str)
                and self.image_digest.startswith("sha256:")):
            raise ContainerIsolationError("image_digest_invalid")
        if not (isinstance(self.user, str)
                and re.fullmatch(r"\d+:\d+", self.user)):
            raise ContainerIsolationError("user_invalid", str(self.user))
        if type(self.read_only_root) is not bool:
            raise ContainerIsolationError("read_only_root_invalid")
        if type(self.no_new_privileges) is not bool:
            raise ContainerIsolationError("no_new_privileges_invalid")
        if not isinstance(self.cap_drop, (list, tuple)) or not all(
                isinstance(name, str) and name for name in self.cap_drop):
            raise ContainerIsolationError("cap_drop_invalid")
        object.__setattr__(self, "cap_drop", tuple(self.cap_drop))

    @property
    def non_root(self) -> bool:
        """Whether the workload uid is not 0 (root); ``00`` is root too.

        The uid is compared as an integer because the runtime parses
        ``00`` as uid 0, so a string comparison would report a root
        workload as non-root.
        """
        return int(self.user.split(":", 1)[0]) != 0

    @property
    def production_ready(self) -> bool:
        return (self.network == "none" and self.read_only_root
                and self.no_new_privileges and "ALL" in self.cap_drop
                and self.non_root
                and self.image_digest is not None)

    def verified_controls(self) -> tuple[str, ...]:
        controls = ["mount_allowlist", "wall_clock_bound"]
        if self.non_root:
            controls.append("non_root_user")
        if self.network == "none":
            controls.append("network_none")
        if self.read_only_root:
            controls.append("read_only_root")
        if "ALL" in self.cap_drop:
            controls.append("capabilities_all_dropped")
        elif self.cap_drop:
            controls.append("capabilities_partially_dropped")
        if self.no_new_privileges:
            controls.append("no_new_privileges")
        controls.extend(["memory_limit", "cpu_limit", "pids_limit"])
        if self.image_digest is not None:
            controls.append("pinned_image")
        return tuple(controls)

    def digest(self) -> str:
        return canonical_digest("container_profile", 1, self.to_dict())

    @classmethod
    def from_dict(cls, value) -> "ContainerProfile":
        """Rebuild the profile from its canonical form.

        ``to_dict`` carries two derived fields (``production_ready`` and
        ``verified_controls``); they are recomputed here rather than
        trusted, so a record cannot declare itself ready.
        """
        if not isinstance(value, dict):
            raise ContainerIsolationError("profile_invalid")
        expected = {"schema_version", "image", "image_digest", "network",
                    "read_only_root", "cap_drop", "no_new_privileges",
                    "memory_bytes", "cpu_milli", "pids_limit",
                    "wall_seconds", "tmpfs_bytes", "user"}
        supplied = {key: value[key] for key in expected if key in value}
        missing = expected - set(supplied)
        if missing - {"schema_version"}:
            raise ContainerIsolationError(
                "profile_invalid", ",".join(sorted(missing)))
        if value.get("schema_version") != 1:
            raise ContainerIsolationError("profile_invalid")
        supplied.pop("schema_version", None)
        return cls(**supplied)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "image": self.image,
            "image_digest": self.image_digest,
            "network": self.network,
            "read_only_root": self.read_only_root,
            "cap_drop": list(self.cap_drop),
            "no_new_privileges": self.no_new_privileges,
            "memory_bytes": self.memory_bytes,
            "cpu_milli": self.cpu_milli,
            "pids_limit": self.pids_limit,
            "wall_seconds": self.wall_seconds,
            "tmpfs_bytes": self.tmpfs_bytes,
            "user": self.user,
            "production_ready": self.production_ready,
            "verified_controls": list(self.verified_controls()),
        }


@dataclass(frozen=True)
class ContainerResult:
    """What one bounded workload run produced."""

    exit_status: int | None
    timed_out: bool
    stdout: str
    stderr: str
    measurement: dict | None
    profile: ContainerProfile
    signed_by: str | None = None
    signature_reason: str | None = None

    @property
    def ok(self) -> bool:
        return (not self.timed_out and self.exit_status == 0
                and self.measurement is not None)

    def as_dict(self) -> dict:
        return {
            "exit_status": self.exit_status,
            "timed_out": self.timed_out,
            "measurement": self.measurement,
            "isolation": self.profile.to_dict(),
            "signed_by": self.signed_by,
            "signature_reason": self.signature_reason,
            "stderr_tail": self.stderr[-512:],
        }


def runtime_name() -> str | None:
    """The container runtime binary this host provides, if any."""
    preferred = os.environ.get(RUNTIME_ENV)
    if preferred:
        return preferred if shutil.which(preferred) else None
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    return None


def runtime_available(runtime: str | None = None) -> bool:
    binary = runtime or runtime_name()
    if binary is None:
        return False
    try:
        probe = subprocess.run([binary, "info", "--format", "{{.ServerVersion}}"],
                               capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def resolve_image_digest(image: str, *, runtime: str | None = None) -> str:
    """The local image id, used to detect a moved tag between runs."""
    binary = runtime or runtime_name()
    if binary is None:
        raise ContainerIsolationError("container_runtime_unavailable")
    probe = subprocess.run(
        [binary, "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True, timeout=60)
    if probe.returncode != 0:
        raise ContainerIsolationError(
            "image_not_present", probe.stderr.decode("utf-8", "replace")[-200:])
    return probe.stdout.decode("utf-8", "replace").strip()


def pin_profile(profile: ContainerProfile, *,
                runtime: str | None = None) -> ContainerProfile:
    """Return the profile with the image pinned to its current local id."""
    return replace(profile,
                   image_digest=resolve_image_digest(profile.image,
                                                     runtime=runtime))


def _verify_image(profile: ContainerProfile, runtime: str | None) -> None:
    if profile.image_digest is None:
        return
    current = resolve_image_digest(profile.image, runtime=runtime)
    if current != profile.image_digest:
        raise ContainerIsolationError("image_digest_changed",
                                      f"{profile.image_digest}->{current}")


def build_argv(profile: ContainerProfile, *, command: list[str],
               input_dir: Path, output_dir: Path,
               runtime: str | None = None,
               name: str | None = None,
               read_only_input: bool = True) -> list[str]:
    """The exact runtime invocation, including every boundary flag."""
    binary = runtime or runtime_name()
    if binary is None:
        raise ContainerIsolationError("container_runtime_unavailable")
    for path in (input_dir, output_dir):
        # ``--mount`` splits its specification on commas. A path that
        # contains one could append options (e.g. ``readonly=false``) to
        # the mount, so it is refused rather than escaped.
        if "," in str(path) or "\n" in str(path):
            raise ContainerIsolationError("mount_path_invalid", str(path))
    argv = [binary, "run", "--rm", "--init"]
    if name is not None:
        # A named container can be removed when it outlives its bound;
        # killing the ``docker run`` client alone leaves it running.
        argv += ["--name", name]
    argv += ["--network", profile.network]
    if profile.read_only_root:
        argv += ["--read-only"]
    argv += ["--tmpfs", f"/tmp:rw,noexec,nosuid,size={profile.tmpfs_bytes}"]
    for capability in profile.cap_drop:
        argv += ["--cap-drop", capability]
    if profile.no_new_privileges:
        argv += ["--security-opt", "no-new-privileges"]
    # ``--memory-swap`` equal to ``--memory`` disables swap: a workload
    # that exceeds its budget is killed rather than paged, so the
    # measured wall-clock is not distorted by host memory pressure.
    argv += ["--memory", str(profile.memory_bytes),
             "--memory-swap", str(profile.memory_bytes),
             "--cpus", f"{profile.cpu_milli / 1000:.3f}",
             "--pids-limit", str(profile.pids_limit),
             "--user", profile.user]
    # Only two mounts exist, and neither is the key directory. The input
    # tree is read-only unless the caller owns a private copy it needs
    # the command to write into (an acceptance run needs its caches).
    argv += ["--mount",
             "type=bind,source={},target=/work/input{}".format(
                 input_dir, ",readonly" if read_only_input else "")]
    argv += ["--mount",
             f"type=bind,source={output_dir},target=/work/output"]
    argv += ["--workdir", "/work/input", profile.image]
    argv += command
    return argv


def _force_remove(binary: str, name: str) -> None:
    """Stop a container that outlived the parent's wall-clock bound.

    ``subprocess`` kills the ``docker run`` client on timeout; the
    container itself is owned by the daemon and keeps running until it
    is removed explicitly.
    """
    try:
        subprocess.run([binary, "rm", "--force", name],
                       capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass


def _tail(handle, limit: int = MAX_CAPTURE_BYTES) -> str:
    """The last ``limit`` bytes of a captured stream."""
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    handle.seek(max(0, size - limit))
    return handle.read().decode("utf-8", "replace")


def _read_measurement(path: Path) -> dict | None:
    """Read the workload's measurement without following a symlink.

    The output mount is writable by the workload, so ``measurement.json``
    may be a link to a file the parent can read but the workload cannot:
    only a regular file reached without following a link is evidence, and
    only up to a bounded size.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_size > MAX_MEASUREMENT_BYTES):
            return None
        raw = os.read(descriptor, MAX_MEASUREMENT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_MEASUREMENT_BYTES:
        return None
    try:
        candidate = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return candidate if isinstance(candidate, dict) else None


def run_workload(
    profile: ContainerProfile,
    command: list[str],
    *,
    input_dir: str | Path,
    output_dir: str | Path,
    runtime: str | None = None,
    measurement_name: str = "measurement.json",
    read_only_input: bool = True,
) -> ContainerResult:
    """Run ``command`` inside the boundary and read its measurement.

    The caller supplies no result: the workload writes
    ``measurement.json`` into the output mount and the trusted parent
    reads it. Nothing the workload prints is treated as a measurement.
    """
    binary = runtime or runtime_name()
    if binary is None:
        raise ContainerIsolationError("container_runtime_unavailable")
    source = Path(input_dir)
    sink = Path(output_dir)
    if not source.is_dir():
        raise ContainerIsolationError("input_dir_missing", str(source))
    sink.mkdir(parents=True, exist_ok=True)
    target = sink / measurement_name
    if os.path.lexists(target):
        # A measurement from an earlier run — or a link planted by one —
        # is not this run's evidence. The sink is never trusted to be
        # empty.
        try:
            target.unlink()
        except OSError as exc:
            raise ContainerIsolationError(
                "measurement_path_occupied", str(target)) from exc
    _verify_image(profile, binary)
    name = f"sis-eval-{secrets.token_hex(8)}"
    argv = build_argv(profile, command=command, input_dir=source,
                      output_dir=sink, runtime=binary, name=name,
                      read_only_input=read_only_input)
    with tempfile.TemporaryFile() as out_handle, \
            tempfile.TemporaryFile() as err_handle:
        try:
            completed = subprocess.run(argv, stdout=out_handle,
                                       stderr=err_handle,
                                       timeout=profile.wall_seconds)
            timed_out = False
            status = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            status = None
            _force_remove(binary, name)
        except OSError:
            _force_remove(binary, name)
            raise
        stdout = _tail(out_handle)
        stderr = _tail(err_handle)
    _verify_image(profile, binary)
    measurement = (_read_measurement(target)
                   if not timed_out and status == 0 else None)
    return ContainerResult(exit_status=status, timed_out=timed_out,
                           stdout=stdout, stderr=stderr,
                           measurement=measurement, profile=profile)


def measure_with_python(
    profile: ContainerProfile,
    script: str,
    *,
    input_dir: str | Path,
    output_dir: str | Path,
    runtime: str | None = None,
) -> ContainerResult:
    """Convenience wrapper: run a Python script that writes its measurement."""
    return run_workload(
        profile, ["python", "-I", "-c", script],
        input_dir=input_dir, output_dir=output_dir, runtime=runtime)


def sign_measurement(result: ContainerResult, *, signer,
                     signer_key_id: str) -> ContainerResult:
    """Sign the measurement of one completed, verified workload run.

    ``result`` is the ``ContainerResult`` returned by ``run_workload``.
    Signing is refused unless the run completed successfully and its
    profile satisfies every boundary control, so the signature cannot be
    detached from the run it describes. ``signer`` is a callable
    ``(measurement) -> signed-record``; it runs in the trusted parent,
    after the container has exited and after the image digest has been
    re-checked, so the workload never holds the key.
    """
    if not isinstance(result, ContainerResult):
        raise ContainerIsolationError("container_result_required")
    if not result.ok:
        raise ContainerIsolationError("measurement_unverified")
    if not result.profile.production_ready:
        raise ContainerIsolationError("boundary_not_production_ready")
    if not callable(signer):
        raise ContainerIsolationError("signer_required")
    signed = signer(result.measurement)
    return replace(result, measurement=signed, signed_by=signer_key_id)


def production_profile(image: str, *, runtime: str | None = None,
                       **overrides) -> ContainerProfile:
    """A profile that satisfies every boundary control, image pinned."""
    base = ContainerProfile(image=image, **overrides)
    pinned = pin_profile(base, runtime=runtime)
    if not pinned.production_ready:
        raise ContainerIsolationError("production_boundary_incomplete")
    return pinned


__all__ = [
    "ContainerIsolationError",
    "ContainerProfile",
    "ContainerResult",
    "RUNTIME_ENV",
    "build_argv",
    "measure_with_python",
    "pin_profile",
    "production_profile",
    "resolve_image_digest",
    "run_workload",
    "runtime_available",
    "runtime_name",
    "sign_measurement",
]
