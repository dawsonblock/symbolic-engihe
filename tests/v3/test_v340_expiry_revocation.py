"""PR-07: expiry, revocation, kill switch and readiness repairs."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sis.server import create_server
from sis.v3.authority_ledger import AuthorityLedger
from sis.v3.control_plane import ControlPlaneError, SqliteControlPlane
from sis.v3.evidence_binding import attempt_id_for_digest, SigningKey
from sis.v3.serving import GovernedServingGateway
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture


class _Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = ProductionFixture(Path(self.temp.name) / "stack")
        self.addCleanup(self.fixture.close)

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

    def serve(self, gateway, nonce="nonce-pr07"):
        return gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity(session_nonce=nonce))


class KillSwitchTests(_Base):
    def test_disable_committed_by_another_replica_blocks_serving(self):
        gateway = self.gateway()
        other = SqliteControlPlane(
            self.fixture.control_plane.path,
            signing_key=SigningKey(self.fixture.auth_seed,
                                   self.fixture.auth_key))
        self.addCleanup(other.close)
        other.set_global_disable(True, reason="incident")
        guidance = self.serve(gateway)
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_enable_restores_serving(self):
        gateway = self.gateway()
        self.fixture.control_plane.set_global_disable(True)
        self.assertEqual(self.serve(gateway, "nonce-a").decision, "abstain")
        self.fixture.control_plane.set_global_disable(False)
        self.assertEqual(self.serve(gateway, "nonce-b").decision, "advisory")

    def test_disable_is_visible_without_a_restart(self):
        gateway = self.gateway()
        self.assertEqual(self.serve(gateway, "nonce-c").decision, "advisory")
        self.fixture.control_plane.set_global_disable(True)
        self.assertEqual(self.serve(gateway, "nonce-d").decision, "abstain")

    def test_disable_bumps_the_ledger_epoch(self):
        before = self.fixture.control_plane.authority_state()["epoch"]
        self.fixture.control_plane.set_global_disable(True, reason="incident")
        after = self.fixture.control_plane.authority_state()
        self.assertEqual(after["epoch"], before + 1)
        self.assertTrue(after["global_disable"])
        self.assertEqual(after["disable_reason"], "incident")


class IdentityExpiryTests(_Base):
    def test_commit_after_identity_expiry_is_refused(self):
        identity = self.fixture.identity()
        with self.assertRaisesRegex(ControlPlaneError, "identity_expired"):
            self.fixture.control_plane.commit_bound_authorization(
                attempt_id=attempt_id_for_digest(identity.digest),
                nonce="nonce-expired",
                session_digest=identity.digest,
                execution_identity_digest=identity.digest,
                requester_principal_id="agent-1", task_id="task-1",
                repository_id="repo-1", repository_tree_digest="a" * 64,
                base_commit_digest="abc1234", guidance_digest="c" * 64,
                decision="advisory",
                expires_at="2032-01-01T00:00:00Z",
                identity_expires_at="2030-01-01T00:00:00Z",
                committed_at="2031-01-01T00:00:00Z")

    def test_authorization_may_not_outlive_the_identity(self):
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authorization_outlives_identity"):
            self.fixture.ledger.authorize(_ledger_request(
                expires_at="2030-01-01T00:00:00Z",
                identity_expires_at="2029-01-01T00:00:00Z"))


class RecheckTests(_Base):
    def _authorization(self):
        gateway = self.gateway()
        self.serve(gateway, "nonce-recheck")
        return gateway, self.fixture.bound_authorization("nonce-recheck")

    def test_recheck_accepts_a_live_authorization(self):
        gateway, authorization = self._authorization()
        verdict = gateway.recheck(authorization.authorization_id)
        self.assertEqual(verdict["attempt_id"], authorization.attempt_id)

    def test_recheck_refuses_after_disable(self):
        gateway, authorization = self._authorization()
        self.fixture.control_plane.set_global_disable(True)
        with self.assertRaisesRegex(ValueError, "global_disable"):
            gateway.recheck(authorization.authorization_id)

    def test_recheck_refuses_after_revocation(self):
        gateway, authorization = self._authorization()
        self.fixture.binding_authority._revocations = lambda: (
            set(), {authorization.digest})
        with self.assertRaisesRegex(ValueError, "authorization_revoked"):
            gateway.recheck(authorization.authorization_id)

    def test_recheck_refuses_after_expiry(self):
        gateway, authorization = self._authorization()
        self.fixture.binding_authority._clock = lambda: "2031-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "authorization_expired"):
            gateway.recheck(authorization.authorization_id)

    def test_recheck_refuses_an_unknown_authorization(self):
        gateway, _ = self._authorization()
        with self.assertRaisesRegex(ValueError, "authorization_unknown"):
            gateway.recheck("auth-unknown")


class ReadinessTests(_Base):
    def test_health_separates_liveness_from_readiness(self):
        gateway = self.gateway()
        health = gateway.health()
        self.assertTrue(health["alive"])
        self.assertTrue(health["ready"])
        self.assertTrue(health["checks"]["outcome_binding"]["ok"])

    def test_unbound_production_is_refused_at_construction(self):
        with self.assertRaisesRegex(
                ValueError, "production_requirements_missing"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                production=True,
                execution_identity_authority=self.fixture.identity_authority,
                control_plane=self.fixture.control_plane)
        unbound = GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            production=False,
            execution_identity_authority=self.fixture.identity_authority,
            control_plane=self.fixture.control_plane)
        health = unbound.health()
        self.assertTrue(health["alive"])
        self.assertTrue(health["ready"])
        self.assertEqual(health["outcome_binding"], "legacy")

    def test_disabled_ledger_is_not_ready(self):
        ledger = self.fixture.ledger
        ledger.set_candidate_status("cert-cand", "qualified")
        ledger.publish()
        self.assertTrue(ledger.readiness()["ok"])
        ledger.disable(reason="incident")
        self.assertFalse(ledger.readiness()["ok"])

    def test_livez_answers_while_readyz_fails(self):
        from sis.server import create_server as _create
        service = _Service(self.gateway())
        server, _ = _serve(_create, service)
        self.assertEqual(_get(server, "/livez")[0], 200)
        self.assertEqual(_get(server, "/readyz")[0], 200)
        self.fixture.control_plane.close()
        self.assertEqual(_get(server, "/livez")[0], 200)
        self.assertEqual(_get(server, "/readyz")[0], 503)
        server.shutdown()
        server.server_close()


class _Service:
    """Minimal v3 service shim: only what /readyz touches."""

    def __init__(self, gateway):
        self.gateway = gateway

    def health(self):
        return self.gateway.health()


def _serve(create, service):
    import threading
    server = create("127.0.0.1", 0, v3_service=service,
                    db_path=str(Path(tempfile.mkdtemp()) / "legacy.db"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _get(server, path):
    import http.client
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        response.read()
        return response.status, response
    finally:
        connection.close()


def _ledger_request(**overrides):
    from sis.v3.authority_ledger import AuthorizationRequest
    fields = dict(
        attempt_id="att-1", nonce="nonce-1", session_digest="b" * 64,
        execution_identity_digest="b" * 64,
        requester_principal_id="agent-1", task_id="task-1",
        repository_id="repo-1", repository_tree_digest="a" * 64,
        base_commit_digest="abc1234", guidance_digest="c" * 64,
        decision="advisory", expires_at="2029-01-01T00:00:00Z",
        identity_expires_at="2029-01-01T00:00:00Z")
    fields.update(overrides)
    return AuthorizationRequest(**fields)


if __name__ == "__main__":
    unittest.main()
