"""SIS v3.5.1 PR-07: the evaluator boundary is enforced, not declared.

``evaluator_isolation`` gives a process group, rlimits and a timeout.
Those are controls, not a boundary: a subprocess shares the host
filesystem and the host network. These tests assert the properties that
only a real OS boundary provides, by trying to violate them from inside
the workload.

Every test is skipped with an explicit reason when no container runtime
is available. A skipped isolation test is *not* a passed isolation test;
``tools/v351_qualify.py`` reports it as BLOCKED, and the release decision
accounts for it.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from sis.v3.container_isolation import (
    ContainerIsolationError,
    ContainerProfile,
    ContainerResult,
    build_argv,
    measure_with_python,
    pin_profile,
    production_profile,
    run_workload,
    runtime_available,
    runtime_name,
    sign_measurement,
)

IMAGE = os.environ.get("SIS_CONTAINER_IMAGE", "python:3.12-slim")
AVAILABLE = runtime_available()
SKIP_REASON = (f"no container runtime available (runtime={runtime_name()!r}); "
               "the enforced boundary is BLOCKED, not satisfied")

SCRIPT_TEMPLATE = """
import json, os, sys, traceback
result = {{"probe": {name!r}}}
try:
{body}
except BaseException as exc:
    result["raised"] = type(exc).__name__
    result["detail"] = str(exc)[:200]
with open("/work/output/measurement.json", "w") as handle:
    json.dump(result, handle)
"""


def _indent(body: str) -> str:
    return "".join("    " + line if line.strip() else line
                   for line in body.strip("\n").splitlines(keepends=True))


def _profile(**overrides) -> ContainerProfile:
    values = dict(image=IMAGE, memory_bytes=256 * 1024 * 1024,
                  wall_seconds=60, pids_limit=64, tmpfs_bytes=16 * 1024 * 1024)
    values.update(overrides)
    return pin_profile(ContainerProfile(**values))


def _probe(name: str, body: str, **overrides):
    with tempfile.TemporaryDirectory() as source, \
            tempfile.TemporaryDirectory() as sink:
        profile = _profile(**overrides)
        script = SCRIPT_TEMPLATE.format(name=name, body=_indent(body))
        return measure_with_python(profile, script, input_dir=source,
                                   output_dir=sink)


@unittest.skipUnless(AVAILABLE, SKIP_REASON)
class BoundaryTests(unittest.TestCase):
    def test_the_container_can_run_at_all(self):
        result = _probe("hello", 'result["ok"] = True')
        self.assertTrue(result.ok, result.as_dict())
        self.assertEqual(result.measurement["ok"], True)

    def test_network_is_denied(self):
        result = _probe("network", """
import socket
socket.setdefaulttimeout(3)
sock = socket.create_connection(("1.1.1.1", 53), timeout=3)
result["connected"] = True
sock.close()
""")
        self.assertTrue(result.ok, result.as_dict())
        self.assertNotIn("connected", result.measurement)
        self.assertIn(result.measurement.get("raised"),
                      {"OSError", "TimeoutError", "socket.gaierror"})

    def test_the_host_filesystem_is_not_visible(self):
        with tempfile.NamedTemporaryFile("w", suffix=".marker",
                                         delete=False) as handle:
            handle.write("host-only")
            marker = handle.name
        self.addCleanup(os.unlink, marker)
        result = _probe("hostfs", f"""
result["read"] = open({marker!r}).read()
""")
        self.assertTrue(result.ok, result.as_dict())
        self.assertNotIn("read", result.measurement)
        self.assertIn(result.measurement.get("raised"),
                      {"FileNotFoundError", "PermissionError"})

    def test_the_signing_key_is_not_present(self):
        # The boundary's whole point: the workload never holds the key.
        with tempfile.TemporaryDirectory() as keys:
            seed = Path(keys) / "evaluator.seed"
            seed.write_bytes(b"\x51" * 32)
            result = _probe("keys", f"""
result["read"] = open({str(seed)!r}).read()
""")
        self.assertTrue(result.ok, result.as_dict())
        self.assertNotIn("read", result.measurement)
        self.assertIn(result.measurement.get("raised"),
                      {"FileNotFoundError", "PermissionError"})

    def test_the_root_filesystem_is_read_only(self):
        result = _probe("readonly", """
with open("/root-escape", "w") as handle:
    handle.write("x")
result["wrote"] = True
""")
        self.assertTrue(result.ok, result.as_dict())
        self.assertNotIn("wrote", result.measurement)
        self.assertIn(result.measurement.get("raised"),
                      {"OSError", "PermissionError"})

    def test_the_process_count_is_bounded(self):
        result = _probe("pids", """
import subprocess
children = []
for _ in range(200):
    children.append(subprocess.Popen(["sleep", "5"]))
result["spawned"] = len(children)
""", pids_limit=16)
        self.assertTrue(result.ok, result.as_dict())
        self.assertNotIn("spawned", result.measurement)
        self.assertIn(result.measurement.get("raised"),
                      {"BlockingIOError", "OSError", "RuntimeError"})

    def test_memory_is_bounded(self):
        result = _probe("memory", """
chunk = bytearray(400 * 1024 * 1024)
result["allocated"] = len(chunk)
""", memory_bytes=128 * 1024 * 1024)
        self.assertFalse(result.ok and result.measurement.get("allocated"))
        if result.measurement:
            self.assertNotIn("allocated", result.measurement)

    def test_a_hung_workload_is_terminated(self):
        result = _probe("timeout", """
import time
time.sleep(120)
""", wall_seconds=3)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.measurement)

    def test_a_hung_workload_is_actually_stopped(self):
        # Killing the ``docker run`` client on timeout leaves the
        # container running on the daemon, so the workload outlives the
        # bound that ``verified_controls`` claims. Nothing may survive.
        result = _probe("timeout", """
import time
time.sleep(120)
""", wall_seconds=3)
        self.assertTrue(result.timed_out)
        listing = subprocess.run(
            [runtime_name(), "ps", "--all", "--quiet",
             "--filter", "name=sis-eval-"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(listing.stdout.strip(), "", listing.stdout)

    def test_the_workload_cannot_write_to_the_host_root(self):
        result = _probe("output", """
with open("/etc/host-escape", "w") as handle:
    handle.write("x")
result["wrote"] = True
""")
        self.assertTrue(result.ok, result.as_dict())
        self.assertNotIn("wrote", result.measurement)
        self.assertIn(result.measurement.get("raised"),
                      {"OSError", "PermissionError"})

    def test_a_stale_measurement_is_not_this_runs_evidence(self):
        with tempfile.TemporaryDirectory() as source, \
                tempfile.TemporaryDirectory() as sink:
            stale = Path(sink) / "measurement.json"
            stale.write_text('{"tokens": 999999, "probe": "previous-run"}')
            result = run_workload(
                _profile(), ["true"], input_dir=source, output_dir=sink)
            self.assertEqual(result.exit_status, 0)
            self.assertIsNone(result.measurement)


@unittest.skipUnless(AVAILABLE, SKIP_REASON)
class ProfileTests(unittest.TestCase):
    def test_every_boundary_flag_is_on_the_command_line(self):
        with tempfile.TemporaryDirectory() as source, \
                tempfile.TemporaryDirectory() as sink:
            argv = build_argv(_profile(), command=["python", "-c", "pass"],
                              input_dir=Path(source), output_dir=Path(sink))
        joined = " ".join(argv)
        for flag in ("--network none", "--read-only", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--memory",
                     "--cpus", "--pids-limit", "--user"):
            self.assertIn(flag, joined)
        self.assertIn("readonly", joined)

    def test_a_production_profile_requires_a_pinned_image(self):
        # An unpinned profile is not production-ready...
        self.assertFalse(ContainerProfile(image=IMAGE).production_ready)
        # ...and the production constructor pins it.
        pinned = production_profile(IMAGE)
        self.assertTrue(pinned.production_ready)
        self.assertIsNotNone(pinned.image_digest)
        self.assertIn("pinned_image", pinned.verified_controls())
        # A profile that cannot satisfy a boundary control is refused.
        with self.assertRaises(ContainerIsolationError) as caught:
            production_profile(IMAGE, network="host")
        self.assertEqual(caught.exception.reason,
                         "production_boundary_incomplete")

    def test_a_moved_image_is_refused(self):
        profile = _profile()
        moved = ContainerProfile(
            image=profile.image, image_digest="sha256:" + "0" * 64)
        with tempfile.TemporaryDirectory() as source, \
                tempfile.TemporaryDirectory() as sink:
            with self.assertRaises(ContainerIsolationError) as caught:
                run_workload(moved, ["true"], input_dir=source,
                             output_dir=sink)
        self.assertEqual(caught.exception.reason, "image_digest_changed")

    def test_the_profile_digest_is_stable_and_covers_the_boundary(self):
        first = _profile()
        second = _profile()
        self.assertEqual(first.digest(), second.digest())
        self.assertNotEqual(
            first.digest(),
            _profile(network="host", read_only_root=False).digest())


class ProfileValidationTests(unittest.TestCase):
    """Profile rules that do not need a container runtime."""

    def test_a_root_user_is_not_a_verified_control(self):
        pinned = ContainerProfile(image=IMAGE, user="0:0",
                                  image_digest="sha256:" + "a" * 64)
        self.assertFalse(pinned.non_root)
        self.assertFalse(pinned.production_ready)
        self.assertNotIn("non_root_user", pinned.verified_controls())
        # ...and an unparseable user is refused outright.
        with self.assertRaises(ContainerIsolationError):
            ContainerProfile(image=IMAGE, user="root")

    def test_a_leading_zero_uid_is_root(self):
        # The runtime parses ``00`` as uid 0, so a string comparison
        # would report a root workload as a verified non-root control.
        for user in ("00:00", "00:65534", "000:0"):
            with self.subTest(user=user):
                profile = ContainerProfile(
                    image=IMAGE, user=user, image_digest="sha256:" + "a" * 64)
                self.assertFalse(profile.non_root)
                self.assertFalse(profile.production_ready)
                self.assertNotIn("non_root_user", profile.verified_controls())

    def test_a_partial_capability_drop_is_not_a_boundary(self):
        # The documented control is ``--cap-drop ALL``. A profile that
        # drops one capability is not that control.
        partial = ContainerProfile(image=IMAGE, cap_drop=("NET_RAW",),
                                   image_digest="sha256:" + "a" * 64)
        self.assertFalse(partial.production_ready)
        self.assertNotIn("capabilities_all_dropped",
                         partial.verified_controls())
        self.assertIn("capabilities_partially_dropped",
                      partial.verified_controls())
        full = ContainerProfile(image=IMAGE, cap_drop=("ALL",),
                                image_digest="sha256:" + "a" * 64)
        self.assertTrue(full.production_ready)
        self.assertIn("capabilities_all_dropped", full.verified_controls())

    def test_an_image_cannot_be_a_runtime_flag(self):
        # ``image`` is positional; a leading ``-`` would be parsed as a
        # flag and promote the workload command to the image position.
        with self.assertRaises(ContainerIsolationError) as caught:
            ContainerProfile(image="--privileged")
        self.assertEqual(caught.exception.reason, "image_invalid")

    def test_a_comma_in_a_mount_path_is_refused(self):
        with tempfile.TemporaryDirectory() as source:
            comma = Path(str(source) + ",readonly=false")
            comma.mkdir()
            with self.assertRaises(ContainerIsolationError) as caught:
                build_argv(ContainerProfile(image=IMAGE), command=["true"],
                           input_dir=comma, output_dir=source,
                           runtime="docker")
            self.assertEqual(caught.exception.reason, "mount_path_invalid")


class SigningTests(unittest.TestCase):
    """The trusted parent signs one completed, verified run."""

    def _result(self, measurement, *, user="65534:65534"):
        profile = ContainerProfile(
            image=IMAGE, user=user, image_digest="sha256:" + "a" * 64)
        return ContainerResult(exit_status=0, timed_out=False, stdout="",
                               stderr="", measurement=measurement,
                               profile=profile)

    def test_the_parent_signs_the_measured_record(self):
        seen = {}

        def signer(measurement):
            seen.update(measurement)
            return {"signed": True, "measurement": measurement}

        result = sign_measurement(self._result({"tokens": 10}), signer=signer,
                                  signer_key_id="eval-key-1")
        self.assertEqual(result.signed_by, "eval-key-1")
        self.assertEqual(seen, {"tokens": 10})
        self.assertTrue(result.measurement["signed"])

    def test_a_missing_measurement_cannot_be_signed(self):
        with self.assertRaises(ContainerIsolationError) as caught:
            sign_measurement(self._result(None),
                             signer=lambda value: value,
                             signer_key_id="eval-key-1")
        self.assertEqual(caught.exception.reason, "measurement_unverified")

    def test_an_unverified_boundary_cannot_be_signed(self):
        with self.assertRaises(ContainerIsolationError) as caught:
            sign_measurement(self._result({"tokens": 10}, user="0:0"),
                             signer=lambda value: value,
                             signer_key_id="eval-key-1")
        self.assertEqual(caught.exception.reason,
                         "boundary_not_production_ready")


if __name__ == "__main__":
    unittest.main()
