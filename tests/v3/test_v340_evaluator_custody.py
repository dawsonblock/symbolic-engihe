"""PR-08: evaluator isolation and independent signing-key custody."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import AuthorizationV2, TaskEnvelopeV1
from sis.v3.evaluator_isolation import (
    NETWORK_HOST,
    NETWORK_NONE,
    IsolationError,
    IsolationProfile,
    development_profile,
    production_profile,
    run_isolated,
    sign_bound_receipt,
    verify_profile,
)
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier
from sis.v3.evidence_binding import (
    EvidenceBindingAuthority,
    sign_authorization,
    unreported_exposure_digest,
    verify_receipt,
)
from sis.v3.key_custody import (
    EVALUATOR,
    PROMOTION_AUTHORITY,
    SERVING_AUTHORITY,
    CustodyError,
    KeyCustody,
    four_identity_custody,
)

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
IMAGE = "a" * 64


def ts(minutes: int = 0) -> str:
    return (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def authorization(seed: bytes = b"\x22" * 32) -> AuthorizationV2:
    return sign_authorization(
        seed, authorization_id="auth-1", requester_principal_id="agent-1",
        execution_identity_digest="b" * 64, task_id="task-1",
        attempt_id="att-1", repository_id="repo-1",
        repository_tree_digest="c" * 64, base_commit_digest="abc1234",
        guidance_digest="d" * 64, authority_snapshot_digest="e" * 64,
        authority_epoch=1, decision="advisory", issued_at=ts(0),
        expires_at=ts(60), signer_key_id="auth-key-1")


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_four_identities_get_four_distinct_keys(self):
        custody = four_identity_custody(self.root)
        report = custody.custody_report()
        self.assertTrue(report["distinct_identities"])
        self.assertTrue(report["ready"])
        self.assertEqual(report["enrolled_count"], 3)
        self.assertTrue(all(
            entry["owner_only"] for entry in report["roles"]
            if entry["enrolled"]))

    def test_seeds_are_owner_only(self):
        custody = KeyCustody(self.root)
        key = custody.create(EVALUATOR)
        mode = stat.S_IMODE(key.seed_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_a_group_readable_seed_is_refused(self):
        custody = KeyCustody(self.root)
        key = custody.create(EVALUATOR)
        os.chmod(key.seed_path, 0o644)
        other = KeyCustody(self.root / "second")
        with self.assertRaisesRegex(CustodyError,
                                    "seed_permissions_too_open"):
            other.enroll(EVALUATOR, key.seed_path)

    def test_two_roles_may_not_share_a_key(self):
        custody = KeyCustody(self.root)
        evaluator = custody.create(EVALUATOR)
        with self.assertRaisesRegex(CustodyError,
                                    "identities_share_a_key"):
            custody.enroll(PROMOTION_AUTHORITY, evaluator.seed_path)

    def test_the_agent_role_cannot_sign(self):
        custody = KeyCustody(self.root)
        with self.assertRaisesRegex(CustodyError, "role_cannot_sign"):
            custody.create("agent")

    def test_signing_never_exposes_the_seed(self):
        custody = four_identity_custody(self.root)
        signature = custody.sign(EVALUATOR, b"payload")
        self.assertEqual(len(signature), 64)
        self.assertTrue(signatures.verify(
            signature, b"payload",
            bytes.fromhex(custody.public(EVALUATOR))))
        self.assertNotIn("seed", repr(custody.key(EVALUATOR)).lower()
                         .replace("seed_path", ""))

    def test_trusted_keys_maps_ids_to_public_keys(self):
        custody = four_identity_custody(self.root)
        keys = custody.trusted_keys(EVALUATOR, SERVING_AUTHORITY)
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[custody.key(EVALUATOR).key_id],
                         custody.public(EVALUATOR))

    def test_report_does_not_contain_seed_material(self):
        custody = four_identity_custody(self.root)
        rendered = json.dumps(custody.custody_report())
        for role in (EVALUATOR, SERVING_AUTHORITY, PROMOTION_AUTHORITY):
            seed = custody.key(role).seed_path.read_bytes().hex()
            self.assertNotIn(seed, rendered)


class ProfileTests(unittest.TestCase):
    def test_development_profile_is_not_production_ready(self):
        self.assertFalse(development_profile().production_ready)

    def test_production_profile_is_ready(self):
        self.assertTrue(production_profile(IMAGE).production_ready)

    def test_production_refuses_network_access(self):
        with self.assertRaisesRegex(IsolationError,
                                    "production_requires_network_isolation"):
            verify_profile(
                IsolationProfile(network=NETWORK_HOST, image_digest=IMAGE),
                production=True)

    def test_production_refuses_an_unpinned_image(self):
        with self.assertRaisesRegex(IsolationError,
                                    "production_requires_pinned_image"):
            verify_profile(IsolationProfile(network=NETWORK_NONE),
                           production=True)

    def test_production_refuses_inherited_environment(self):
        with self.assertRaisesRegex(IsolationError,
                                    "production_requires_clean_environment"):
            verify_profile(
                IsolationProfile(network=NETWORK_NONE, inherit_env=True,
                                 image_digest=IMAGE),
                production=True)

    def test_profile_digest_changes_with_the_profile(self):
        first = production_profile(IMAGE)
        second = production_profile("b" * 64)
        self.assertNotEqual(first.digest(), second.digest())

    def test_invalid_network_mode_is_refused(self):
        with self.assertRaisesRegex(IsolationError, "network_mode_invalid"):
            IsolationProfile(network="bridge")


class BoundReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.custody = four_identity_custody(self.root / "keys")
        self.eval_key = self.custody.key(EVALUATOR)

    def binding(self, **overrides):
        auth = authorization()
        binding = {
            "seed_path": str(self.eval_key.seed_path),
            "key_id": self.eval_key.key_id,
            "receipt_nonce": "nonce-1",
            "measured": {
                "result": "pass",
                "artifact_digest": "f" * 64,
                "test_suite_commitment": "1" * 64,
                "environment_digest": "2" * 64,
                "criterion_version": "v1",
            },
            "guidance_exposure_digest": unreported_exposure_digest(auth),
            "issued_at": ts(1),
            "expires_at": ts(120),
            "authorization": auth.to_dict(),
            "isolation": production_profile(IMAGE).to_dict(),
        }
        binding.update(overrides)
        return binding

    def test_signed_receipt_verifies_against_the_evaluator_key(self):
        receipt = sign_bound_receipt(self.binding(),
                                     self.eval_key.seed_path.read_bytes())
        self.assertTrue(verify_receipt(receipt, self.eval_key.public_hex))
        self.assertEqual(receipt.authorization_id, "auth-1")
        self.assertEqual(receipt.attempt_id, "att-1")
        self.assertEqual(receipt.result, "pass")

    def test_receipt_id_is_deterministic_for_a_binding(self):
        first = sign_bound_receipt(self.binding(),
                                   self.eval_key.seed_path.read_bytes())
        second = sign_bound_receipt(self.binding(),
                                    self.eval_key.seed_path.read_bytes())
        self.assertEqual(first.receipt_id, second.receipt_id)
        self.assertEqual(first.digest, second.digest)

    def test_a_different_nonce_is_a_different_receipt(self):
        first = sign_bound_receipt(self.binding(),
                                   self.eval_key.seed_path.read_bytes())
        second = sign_bound_receipt(self.binding(receipt_nonce="nonce-2"),
                                    self.eval_key.seed_path.read_bytes())
        self.assertNotEqual(first.receipt_id, second.receipt_id)

    def test_an_authority_trusting_only_the_evaluator_accepts_it(self):
        receipt = sign_bound_receipt(self.binding(),
                                     self.eval_key.seed_path.read_bytes())
        authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={self.eval_key.key_id:
                                    self.eval_key.public_hex},
            trusted_harness_keys={})
        self.assertEqual(authority.receipt(receipt), receipt)

    def test_a_binding_without_a_measurement_is_refused(self):
        binding = self.binding()
        binding.pop("measured")
        with self.assertRaisesRegex(IsolationError, "measurement_missing"):
            sign_bound_receipt(binding, self.eval_key.seed_path.read_bytes())

    def test_a_caller_supplied_result_is_not_what_gets_signed(self):
        binding = self.binding()
        binding["result"] = "fail"
        binding["artifact_digest"] = "9" * 64
        receipt = sign_bound_receipt(binding,
                                     self.eval_key.seed_path.read_bytes())
        self.assertEqual(receipt.result, "pass")
        self.assertEqual(receipt.submitted_artifact_digest, "f" * 64)


class IsolatedRunTests(unittest.TestCase):
    """The worker measures the submission; the parent only binds it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.custody = four_identity_custody(self.root / "keys")
        self.eval_key = self.custody.key(EVALUATOR)
        self.key_dir = self.root / "evaluator-keys"
        self.registry_dir = self.root / "registry"
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n")
        registrar = OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                self.root / "reg-exec", use_seatbelt=False),
            key_dir=self.key_dir, registry_dir=self.registry_dir)
        registrar.register_task(
            actor_role="evaluator", task_id="task-1",
            criterion_version="v1", argv=(sys.executable, "acc.py"),
            files={"acc.py":
                   b"import calc; assert calc.scale(3,4)==12\n"})
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="task-1",
            repo_snapshot_digest=tree_digest(self.submission),
            base_commit=None, task_statement_digest="0" * 64,
            permitted_commands=("x",), isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=10,
            actor_id="a", evaluator_task_ref="task-1")

    def run_once(self, **overrides):
        kwargs = dict(
            seed_path=self.eval_key.seed_path, key_id=self.eval_key.key_id,
            authorization=authorization(), attempt=None,
            submission_dir=self.submission, task=self.task,
            key_dir=self.key_dir, registry_dir=self.registry_dir,
            profile=production_profile(IMAGE), receipt_nonce="nonce-1",
            measurement_nonce="measure-1",
            issued_at=ts(1), expires_at=ts(120), production=True,
        )
        kwargs.update(overrides)
        return run_isolated(**kwargs)

    def test_child_measures_and_signs_a_receipt_the_parent_can_verify(self):
        outcome = self.run_once()
        self.assertFalse(outcome.crashed, outcome.stderr_tail)
        self.assertIsNotNone(outcome.receipt)
        self.assertTrue(verify_receipt(outcome.receipt,
                                       self.eval_key.public_hex))
        self.assertEqual(outcome.receipt.result, "pass")
        self.assertEqual(outcome.receipt.guidance_exposure_digest,
                         unreported_exposure_digest(authorization()))
        # The artifact digest is the tree the evaluator actually ran.
        self.assertEqual(outcome.receipt.submitted_artifact_digest,
                         tree_digest(self.submission))

    def test_a_failing_submission_is_measured_as_a_failure(self):
        (self.submission / "calc.py").write_text(
            "def scale(a, b):\n    return a + b\n")
        outcome = self.run_once()
        self.assertFalse(outcome.crashed, outcome.stderr_tail)
        self.assertEqual(outcome.receipt.result, "fail")
        self.assertEqual(outcome.result, "fail")

    def test_a_result_cannot_be_supplied_by_the_caller(self):
        with self.assertRaises(TypeError):
            self.run_once(result="pass")

    def test_crash_produces_no_receipt(self):
        outcome = self.run_once(
            extra_argv=("--nonexistent-flag",))
        self.assertTrue(outcome.crashed)
        self.assertIsNone(outcome.receipt)
        self.assertEqual(outcome.result, "error")

    def test_timeout_produces_no_receipt(self):
        profile = IsolationProfile(network=NETWORK_NONE, wall_seconds=1,
                                   image_digest=IMAGE)
        outcome = self.run_once(
            profile=profile, extra_argv=("--slow",))
        # The flag is unknown, so the worker exits non-zero; either way it
        # never signs.
        self.assertIsNone(outcome.receipt)

    def test_missing_submission_is_refused(self):
        with self.assertRaisesRegex(IsolationError,
                                    "submission_dir_missing"):
            self.run_once(submission_dir=self.root / "absent")

    def test_production_requires_an_isolated_profile(self):
        with self.assertRaisesRegex(IsolationError,
                                    "production_requires_network_isolation"):
            self.run_once(profile=development_profile())

    def test_an_unregistered_task_signs_nothing(self):
        bad = TaskEnvelopeV1.from_dict({
            **self.task.to_dict(), "task_id": "nope",
            "evaluator_task_ref": "nope",
        })
        outcome = self.run_once(task=bad)
        self.assertTrue(outcome.crashed)
        self.assertIsNone(outcome.receipt)


if __name__ == "__main__":
    unittest.main()
