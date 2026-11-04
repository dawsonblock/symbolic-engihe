"""v3.5.0 PR-01: a production gateway may not be missing any control.

The profile is checked in the constructor, in ``health()`` and in
``serve()``: a caller that invokes the gateway directly must not be able
to serve with a ledger, monitor, custody, evidence policy or rollout
missing.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import signatures
from sis.v3.evidence_binding import EvidenceBindingAuthority
from sis.v3.serving import GovernedServingGateway, ProductionRequirements
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = ProductionFixture(self.root / "stack")
        self.addCleanup(self.fixture.close)

    def requirements(self, **overrides):
        values = dict(
            control_plane=self.fixture.control_plane,
            binding_authority=self.fixture.binding_authority,
            ledger=self.fixture.ledger,
            monitor=self.fixture.monitor,
            custody=self.fixture.key_custody,
            evidence_policy=self.fixture.evidence_policy,
            evidence_provider=self.fixture.evidence_provider,
            rollout=self.fixture.rollout)
        values.update(overrides)
        return ProductionRequirements(**values)

    def gateway(self, **kwargs):
        kwargs.setdefault("production", True)
        kwargs.setdefault("execution_identity_authority",
                          self.fixture.identity_authority)
        kwargs.setdefault("control_plane", self.fixture.control_plane)
        kwargs.setdefault("binding_authority",
                          self.fixture.binding_authority)
        for key, value in self.fixture.production_kwargs().items():
            kwargs.setdefault(key, value)
        return GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            **kwargs)


class RequirementTests(_Fixture):
    def test_a_complete_profile_has_no_problems(self):
        self.assertEqual(self.requirements().problems(), ())
        self.assertTrue(self.requirements().complete)

    def test_each_missing_component_is_named(self):
        for name in ("control_plane", "binding_authority", "ledger",
                     "monitor", "custody", "evidence_policy",
                     "evidence_provider", "rollout"):
            requirements = self.requirements(**{name: None})
            self.assertIn(f"{name}_missing", requirements.problems(), name)

    def test_a_ledger_bound_to_another_plane_is_refused(self):
        from sis.v3.authority_ledger import AuthorityLedger
        from sis.v3.control_plane import SqliteControlPlane
        from sis.v3.evidence_binding import SigningKey
        seed, _ = signatures.generate_keypair()
        other_plane = SqliteControlPlane(
            self.root / "other.db", signing_key=SigningKey(seed, "other"))
        self.addCleanup(other_plane.close)
        ledger = AuthorityLedger(other_plane,
                                 signing_key=self.fixture.ledger_key)
        self.assertIn("ledger_plane_mismatch",
                      self.requirements(ledger=ledger).problems())

    def test_a_monitor_bound_to_another_plane_is_refused(self):
        from sis.v3.control_plane import SqliteControlPlane
        from sis.v3.operations import AuthorityMonitor
        other = SqliteControlPlane(self.root / "monitor.db")
        self.addCleanup(other.close)
        monitor = AuthorityMonitor(control_plane=other)
        self.assertIn("monitor_plane_mismatch",
                      self.requirements(monitor=monitor).problems())

    def test_shared_signer_keys_are_refused(self):
        public = self.fixture.cert.stack.eval_public_hex
        shared = EvidenceBindingAuthority(
            trusted_evaluator_keys={"shared": public},
            trusted_harness_keys={"shared": public},
            trusted_authorization_keys={"shared": public})
        problems = self.requirements(binding_authority=shared).problems()
        self.assertIn("evaluator_and_harness_share_a_key", problems)
        self.assertIn("evaluator_and_authorization_share_a_key", problems)

    def test_a_missing_key_role_is_refused(self):
        no_harness = EvidenceBindingAuthority(
            trusted_evaluator_keys={
                self.fixture.cert.stack.eval_key:
                    self.fixture.cert.stack.eval_public_hex},
            trusted_harness_keys={})
        self.assertIn("harness_keys_missing",
                      self.requirements(
                          binding_authority=no_harness).problems())

    def test_custody_drift_is_refused(self):
        self.fixture.key_custody.key("evaluator").seed_path.chmod(0o644)
        self.assertIn("custody_not_ready", self.requirements().problems())

    def test_a_non_vetted_backend_is_refused(self):
        with mock.patch("sis.v3.signatures.backend",
                        return_value="vendored-python"):
            self.assertIn("crypto_backend_not_vetted",
                          self.requirements().problems())

    def test_an_invalid_rollout_state_is_refused(self):
        self.assertIn("rollout_invalid",
                      self.requirements(rollout=object()).problems())


class ConstructorTests(_Fixture):
    def test_the_constructor_refuses_an_incomplete_profile(self):
        with self.assertRaisesRegex(
                ValueError, "production_requirements_missing"):
            self.gateway(authority_ledger=None)

    def test_the_constructor_names_every_missing_component(self):
        with self.assertRaisesRegex(
                ValueError,
                "monitor_missing.*custody_missing.*evidence_policy_missing"):
            self.gateway(monitor=None, custody=None, evidence_policy=None,
                         evidence_provider=None)

    def test_a_complete_production_gateway_is_ready(self):
        gateway = self.gateway()
        health = gateway.health()
        self.assertTrue(health["ready"], health["checks"])
        self.assertTrue(health["checks"]["production_profile"]["ok"])

    def test_a_development_gateway_is_not_subject_to_the_profile(self):
        gateway = GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            production=False)
        self.assertTrue(gateway.health()["alive"])
        self.assertNotIn("production_profile", gateway.health()["checks"])


class ServeTests(_Fixture):
    def test_serve_refuses_when_the_profile_degrades_after_construction(self):
        gateway = self.gateway()
        # A component that was present at construction can degrade at
        # runtime; serve() re-checks instead of trusting /readyz.
        gateway._production_requirements = self.requirements(monitor=None)
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code,
                         "production_profile_incomplete")

    def test_a_complete_production_gateway_serves(self):
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertNotEqual(guidance.decision, "abstain")


if __name__ == "__main__":
    unittest.main()
