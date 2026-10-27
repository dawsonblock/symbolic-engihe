"""PostgreSQL control-plane qualification (opt-in).

Set ``SIS_POSTGRES_DSN`` to a disposable database to run these tests.
The default suite uses SQLite; a multi-host deployment must run this
file against its production PostgreSQL profile before claiming
cross-replica replay protection.
"""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path

from sis.v3.control_plane import (ControlPlaneError, PostgresControlPlane)
from sis.v3.serving import GovernedServingGateway
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture

DSN = os.getenv("SIS_POSTGRES_DSN")


@unittest.skipUnless(DSN, "SIS_POSTGRES_DSN not configured")
class PostgresControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.plane = PostgresControlPlane(DSN)
        self.addCleanup(self.plane.close)
        with self.plane._transaction() as con:
            for table in ("guidance_outcome", "authorization_receipt",
                          "session_nonce", "authority_head"):
                con.execute(f"DROP TABLE IF EXISTS {table}")
        self.plane.close()
        self.plane = PostgresControlPlane(DSN)
        self.addCleanup(self.plane.close)

    def values(self, nonce="nonce-pg-1", digest="c" * 64):
        return dict(
            nonce=nonce, session_digest="b" * 64,
            expires_at="2030-01-01T00:00:00Z", task_id="task-pg",
            repository_id="repo-pg", guidance_digest=digest,
            decision="advisory", snapshot_digest="d" * 64)

    def test_duplicate_nonce_is_rejected(self):
        self.plane.commit_authorization(**self.values())
        with self.assertRaisesRegex(ControlPlaneError,
                                    "session_nonce_replayed"):
            self.plane.commit_authorization(**self.values())

    def test_concurrent_replicas_produce_one_commit(self):
        results = []
        barrier = threading.Barrier(4)

        def race():
            plane = PostgresControlPlane(DSN)
            try:
                barrier.wait(timeout=10)
                results.append(
                    plane.commit_authorization(**self.values()))
            except ControlPlaneError as exc:
                results.append(exc.reason)
            finally:
                plane.close()

        threads = [threading.Thread(target=race) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        committed = [item for item in results if isinstance(item, dict)]
        rejected = [item for item in results if item == "session_nonce_replayed"]
        self.assertEqual(len(committed), 1, results)
        self.assertEqual(len(rejected), 3, results)

    def test_outcome_binds_to_receipt(self):
        receipt = self.plane.commit_authorization(**self.values())
        self.plane.record_outcome(
            authorization_id=receipt["authorization_id"],
            task_id="task-pg", served_digest="c" * 64,
            receipt_digest="e" * 64, outcome="pass")
        outcome = self.plane.outcome(receipt["authorization_id"])
        self.assertEqual(outcome["outcome"], "pass")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_already_recorded"):
            self.plane.record_outcome(
                authorization_id=receipt["authorization_id"],
                task_id="task-pg", served_digest="c" * 64,
                receipt_digest="e" * 64, outcome="pass")

    def test_two_replicas_share_one_serving_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ProductionFixture(Path(tmp))
            try:
                latest = fixture.store.get_latest()
                head = {
                    "sequence": latest.sequence,
                    "checkpoint_digest": latest.digest,
                    "journal_head": latest.journal_head,
                    "revocation_head": latest.revocation_head,
                    "supersession_head": latest.supersession_head,
                    "custody_entry_count": latest.custody_entry_count,
                    "updated_at": latest.issued_at,
                }
                first_plane = PostgresControlPlane(DSN)
                second_plane = PostgresControlPlane(DSN)
                self.addCleanup(first_plane.close)
                self.addCleanup(second_plane.close)
                first_plane.advance_authority_head(head)

                def gateway(plane):
                    return GovernedServingGateway(
                        fixture.registry,
                        repository_registry=fixture.repo_registry,
                        production=True,
                        execution_identity_authority=(
                            fixture.identity_authority),
                        control_plane=plane)

                identity = fixture.identity()
                first = gateway(first_plane).serve(
                    _request(), repository_id="repo-1",
                    execution_identity=identity)
                second = gateway(second_plane).serve(
                    _request(), repository_id="repo-1",
                    execution_identity=identity)
                self.assertEqual(first.decision, "advisory")
                self.assertEqual(second.decision, "abstain")
                self.assertEqual(second.reason_code, "catalog_unavailable")
            finally:
                fixture.close()

    def test_head_is_monotonic(self):
        head = {
            "sequence": 1, "checkpoint_digest": "a" * 64,
            "journal_head": "b" * 64, "revocation_head": "0" * 64,
            "supersession_head": "0" * 64, "custody_entry_count": 0,
            "updated_at": "2026-10-27T00:00:00Z",
        }
        self.plane.advance_authority_head(head)
        self.plane.advance_authority_head({**head, "sequence": 2})
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authority_head_rollback"):
            self.plane.advance_authority_head(
                {**head, "sequence": 1})
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authority_head_conflict"):
            self.plane.advance_authority_head(
                {**head, "sequence": 2, "checkpoint_digest": "f" * 64})


if __name__ == "__main__":
    unittest.main()
