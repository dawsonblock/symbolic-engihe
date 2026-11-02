"""PR-06: one authority ledger, one serialization point, one predicate."""
from __future__ import annotations

import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3 import signatures
from sis.v3.authority_ledger import (
    AuthorityLedger,
    AuthorizationRequest,
    LedgerError,
    verify_snapshot,
)
from sis.v3.control_plane import ControlPlaneError, SqliteControlPlane
from sis.v3.evidence_binding import SigningKey, attempt_id_for_digest

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


def ts(minutes: int = 0) -> str:
    return (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


class _Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth_seed, self.auth_public = signatures.generate_keypair()
        self.signer = SigningKey(self.auth_seed, "auth-key-1")
        self.ledger_seed, self.ledger_public = signatures.generate_keypair()
        self.ledger_signer = SigningKey(self.ledger_seed, "ledger-key-1")
        self.plane = SqliteControlPlane(
            self.root / "plane.db", signing_key=self.signer)
        self.addCleanup(self.plane.close)
        self.ledger = AuthorityLedger(
            self.plane, signing_key=self.ledger_signer,
            clock=lambda: ts(0))

    def request(self, *, candidate_ids=("cand-1",), nonce="nonce-1",
                expires_at=None, identity_expires_at=None,
                expected_epoch=None, basis_digests=(), signer_ids=(),
                procedure_ids=(), grant_ids=()):
        return AuthorizationRequest(
            attempt_id=attempt_id_for_digest("b" * 64),
            nonce=nonce,
            session_digest="b" * 64,
            execution_identity_digest="b" * 64,
            requester_principal_id="agent-1",
            task_id="task-1",
            repository_id="repo-1",
            repository_tree_digest="a" * 64,
            base_commit_digest="abc1234",
            guidance_digest="c" * 64,
            decision="advisory",
            expires_at=expires_at or ts(10),
            identity_expires_at=identity_expires_at or ts(10),
            candidate_ids=tuple(candidate_ids),
            procedure_ids=tuple(procedure_ids),
            grant_ids=tuple(grant_ids),
            basis_digests=tuple(basis_digests),
            signer_ids=tuple(signer_ids),
            expected_epoch=expected_epoch,
        )


class EpochTests(_Base):
    def test_epoch_starts_empty_and_advances_on_every_change(self):
        self.assertEqual(self.ledger.state()["epoch"], 0)
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.assertEqual(self.ledger.state()["epoch"], 1)
        self.ledger.set_candidate_status("cand-2", "proposed")
        self.assertEqual(self.ledger.state()["epoch"], 2)

    def test_an_unchanged_write_does_not_advance_the_epoch(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        epoch = self.ledger.state()["epoch"]
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.assertEqual(self.ledger.state()["epoch"], epoch)

    def test_every_change_is_journalled(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.revoke_signer("eval-key-1", reason="rotated")
        events = self.plane.authority_events()
        self.assertEqual([event["event_kind"] for event in events],
                         ["revocation", "subject_status"])
        self.assertEqual(events[0]["epoch"], 2)

    def test_snapshot_is_signed_and_monotonic(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        first = self.ledger.publish()
        self.assertTrue(verify_snapshot(first, self.ledger_public.hex()))
        self.assertEqual(first.epoch, 1)
        self.assertEqual(first.candidate_head,
                         self.ledger.publish().candidate_head)
        self.ledger.set_candidate_status("cand-1", "revoked")
        second = self.ledger.publish()
        self.assertEqual(second.epoch, 2)
        self.assertNotEqual(second.candidate_head, first.candidate_head)
        self.assertEqual(self.plane.authority_snapshot_v2(1), first)

    def test_snapshot_of_an_empty_ledger_is_refused(self):
        with self.assertRaisesRegex(LedgerError, "authority_ledger_empty"):
            self.ledger.publish()

    def test_tampered_snapshot_does_not_verify(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        snapshot = self.ledger.publish()
        tampered = type(snapshot).from_dict(
            {**snapshot.to_dict(), "global_disable": True})
        self.assertFalse(verify_snapshot(tampered, self.ledger_public.hex()))


class AuthorizationPredicateTests(_Base):
    def test_qualified_candidate_authorizes(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        record = self.ledger.authorize(self.request())
        self.assertEqual(record.authority_epoch, 1)
        self.assertEqual(record.attempt_id,
                         attempt_id_for_digest("b" * 64))

    def test_unknown_candidate_is_refused(self):
        with self.assertRaisesRegex(ControlPlaneError, "candidate_unknown"):
            self.ledger.authorize(self.request())

    def test_unqualified_candidate_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "proposed")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "candidate_not_qualified"):
            self.ledger.authorize(self.request())

    def test_unqualified_procedure_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.set_procedure_status("proc-1", "suspended")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "procedure_not_qualified"):
            self.ledger.authorize(self.request(procedure_ids=("proc-1",)))

    def test_inactive_grant_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.set_grant_status("grant-1", "expired")
        with self.assertRaisesRegex(ControlPlaneError, "grant_not_active"):
            self.ledger.authorize(self.request(grant_ids=("grant-1",)))

    def test_revoked_basis_digest_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.revoke_digest("e" * 64, reason="retracted")
        with self.assertRaisesRegex(ControlPlaneError, "evidence_revoked"):
            self.ledger.authorize(self.request(basis_digests=("e" * 64,)))

    def test_revoked_signer_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.revoke_signer("eval-key-1")
        with self.assertRaisesRegex(ControlPlaneError, "signer_revoked"):
            self.ledger.authorize(self.request(signer_ids=("eval-key-1",)))

    def test_global_disable_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.disable(reason="incident")
        with self.assertRaisesRegex(ControlPlaneError, "global_disable"):
            self.ledger.authorize(self.request())

    def test_enable_restores_authorization(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.disable()
        self.ledger.enable()
        record = self.ledger.authorize(self.request())
        self.assertIsNotNone(record)

    def test_authorization_may_not_outlive_the_identity(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authorization_outlives_identity"):
            self.ledger.authorize(
                self.request(expires_at=ts(30), identity_expires_at=ts(10)))

    def test_stale_epoch_is_refused(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.set_candidate_status("cand-2", "proposed")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authority_epoch_changed"):
            self.ledger.authorize(self.request(expected_epoch=1))

    def test_current_epoch_is_accepted(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        epoch = self.ledger.state()["epoch"]
        record = self.ledger.authorize(self.request(expected_epoch=epoch))
        self.assertEqual(record.authority_epoch, epoch)


class OrderingTests(_Base):
    """No authorization may overtake a committed revocation or disable."""

    def test_revocation_committed_first_blocks_every_later_commit(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.revoke_digest("e" * 64)
        for index in range(5):
            with self.assertRaisesRegex(ControlPlaneError,
                                        "evidence_revoked"):
                self.ledger.authorize(
                    self.request(nonce=f"after-{index}",
                                 basis_digests=("e" * 64,)))

    def test_disable_committed_first_blocks_every_later_commit(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.disable(reason="incident")
        for index in range(5):
            with self.assertRaisesRegex(ControlPlaneError, "global_disable"):
                self.ledger.authorize(self.request(nonce=f"after-{index}"))

    def test_concurrent_revocation_and_authorization_never_invert(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        barrier = threading.Barrier(2)
        results: dict[str, object] = {}
        lock = threading.Lock()

        def authorize():
            plane = SqliteControlPlane(
                self.root / "plane.db", signing_key=self.signer)
            ledger = AuthorityLedger(plane, signing_key=self.ledger_signer,
                                     clock=lambda: ts(0))
            barrier.wait()
            try:
                record = ledger.authorize(self.request(
                    nonce="race-1", basis_digests=("e" * 64,)))
                with lock:
                    results["authorization"] = record
            except ControlPlaneError as exc:
                with lock:
                    results["authorization"] = exc.reason
            finally:
                plane.close()

        def revoke():
            plane = SqliteControlPlane(
                self.root / "plane.db", signing_key=self.signer)
            ledger = AuthorityLedger(plane, signing_key=self.ledger_signer,
                                     clock=lambda: ts(0))
            barrier.wait()
            try:
                ledger.revoke_digest("e" * 64, reason="race")
                with lock:
                    results["revocation_epoch"] = ledger.state()["epoch"]
            finally:
                plane.close()

        threads = [threading.Thread(target=authorize),
                   threading.Thread(target=revoke)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("authorization", results)
        self.assertIn("revocation_epoch", results)
        outcome = results["authorization"]
        if isinstance(outcome, str):
            # It lost the race: it must say why, and it must be a
            # revocation-shaped reason, not a silent success.
            self.assertEqual(outcome, "evidence_revoked")
        else:
            # It committed before the revocation, so its pinned epoch
            # must be strictly older than the revocation's.
            self.assertLess(outcome.authority_epoch,
                            results["revocation_epoch"])
        # Whatever the interleaving, the next attempt is refused.
        with self.assertRaisesRegex(ControlPlaneError, "evidence_revoked"):
            self.ledger.authorize(self.request(
                nonce="race-after", basis_digests=("e" * 64,)))


class ReadinessTests(_Base):
    def test_readiness_reports_the_epoch_and_disable_state(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.publish()
        ready = self.ledger.readiness()
        self.assertTrue(ready["ok"])
        self.assertEqual(ready["epoch"], 1)
        self.assertTrue(ready["snapshot_current"])

    def test_disable_makes_readiness_false(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.disable(reason="incident")
        ready = self.ledger.readiness()
        self.assertFalse(ready["ok"])
        self.assertTrue(ready["global_disable"])

    def test_stale_snapshot_is_reported(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.publish()
        self.ledger.set_candidate_status("cand-2", "proposed")
        ready = self.ledger.readiness()
        self.assertFalse(ready["snapshot_current"])


if __name__ == "__main__":
    unittest.main()


class GatewayLedgerTests(unittest.TestCase):
    """A production gateway bound to the ledger abstains on disable."""

    def setUp(self):
        from tests.v3.test_execution_identity_custody import ProductionFixture
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = ProductionFixture(Path(self.temp.name) / "stack")
        self.addCleanup(self.fixture.close)
        self.fixture.ledger.set_candidate_status("cert-cand", "qualified")

    def gateway(self, **kwargs):
        from sis.v3.serving import GovernedServingGateway
        return GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            production=True,
            execution_identity_authority=self.fixture.identity_authority,
            control_plane=self.fixture.control_plane,
            binding_authority=self.fixture.binding_authority,
            authority_ledger=self.fixture.ledger,
            **kwargs)

    def serve(self, gateway, nonce="nonce-ledger-1"):
        from tests.v3.test_authority_checkpoints import _request
        return gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity(session_nonce=nonce))

    def test_ledger_authorizes_a_qualified_candidate(self):
        guidance = self.serve(self.gateway())
        self.assertEqual(guidance.decision, "advisory")
        record = self.fixture.control_plane.bound_authorization_for_nonce(
            "nonce-ledger-1")
        self.assertIsNotNone(record)
        self.assertEqual(record.authority_epoch,
                         self.fixture.ledger.state()["epoch"])

    def test_ledger_abstains_after_global_disable(self):
        self.fixture.ledger.disable(reason="incident")
        guidance = self.serve(self.gateway())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_ledger_abstains_when_the_candidate_is_not_mirrored(self):
        self.fixture.ledger.set_candidate_status("cert-cand", "revoked")
        guidance = self.serve(self.gateway())
        self.assertEqual(guidance.decision, "abstain")
