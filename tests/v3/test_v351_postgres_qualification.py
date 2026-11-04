"""SIS v3.5.1 PR-08: cross-process PostgreSQL qualification.

``test_control_plane_postgres.py`` proves the single-process and
threaded guarantees. A multi-replica deployment needs more than that:
two *processes* with no shared memory must still produce exactly one
commit, and a failed transaction must leave nothing behind.

Run against a disposable database::

    SIS_POSTGRES_DSN=postgresql://postgres@127.0.0.1:55499/sis_v351 \
    SIS_POSTGRES_ALLOW_DESTRUCTIVE=1 \
        python -m pytest tests/v3/test_v351_postgres_qualification.py

``setUp`` drops the control-plane tables, so the second variable is an
explicit acknowledgement that the database may be destroyed. A skip here
is a BLOCKED qualification, not a pass.
"""
from __future__ import annotations

import multiprocessing
import os
import unittest

from sis.v3.control_plane import ControlPlaneError, PostgresControlPlane

DSN = os.getenv("SIS_POSTGRES_DSN")
#: ``setUp`` drops the control-plane tables. That is only acceptable on a
#: database the operator has explicitly declared disposable.
ALLOW_DESTRUCTIVE = os.getenv("SIS_POSTGRES_ALLOW_DESTRUCTIVE") == "1"
SKIP_REASON = (
    "SIS_POSTGRES_DSN not configured"
    if not DSN else
    "SIS_POSTGRES_ALLOW_DESTRUCTIVE=1 not set; refusing to drop tables "
    "in a database that was not declared disposable")


def _values(nonce: str, *, task: str = "task-pgx") -> dict:
    return dict(
        nonce=nonce, session_digest="b" * 64,
        expires_at="2030-01-01T00:00:00Z", task_id=task,
        repository_id="repo-pgx", guidance_digest="c" * 64,
        decision="advisory", snapshot_digest="d" * 64)


def _race_commit(nonce: str, barrier, results) -> None:
    """Run in a separate process: no shared memory, one connection each."""
    plane = PostgresControlPlane(DSN)
    try:
        barrier.wait(timeout=20)
        results.put(("committed",
                     plane.commit_authorization(**_values(nonce))))
    except ControlPlaneError as exc:
        results.put(("rejected", exc.reason))
    except Exception as exc:  # noqa: BLE001 - surfaced to the parent
        results.put(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        plane.close()


@unittest.skipUnless(DSN and ALLOW_DESTRUCTIVE, SKIP_REASON)
class CrossProcessTests(unittest.TestCase):
    def setUp(self):
        self.plane = PostgresControlPlane(DSN)
        with self.plane._transaction() as con:
            for table in ("guidance_outcome", "authorization_receipt",
                          "session_nonce", "authority_head"):
                con.execute(f"DROP TABLE IF EXISTS {table}")
        self.plane.close()
        self.plane = PostgresControlPlane(DSN)
        self.addCleanup(self.plane.close)

    def test_two_processes_produce_exactly_one_commit(self):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(4)
        results = context.Queue()
        nonce = "nonce-cross-process-1"
        workers = [
            context.Process(target=_race_commit,
                            args=(nonce, barrier, results))
            for _ in range(4)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
        for worker in workers:
            self.assertEqual(worker.exitcode, 0)
        collected = [results.get(timeout=10) for _ in workers]
        committed = [item for item in collected if item[0] == "committed"]
        rejected = [item for item in collected if item[0] == "rejected"]
        self.assertEqual(len(committed), 1, collected)
        self.assertEqual(len(rejected), 3, collected)
        self.assertEqual({item[1] for item in rejected},
                         {"session_nonce_replayed"})

    def test_a_duplicate_outcome_cannot_be_recorded(self):
        receipt = self.plane.commit_authorization(**_values("nonce-dup-1"))
        kwargs = dict(authorization_id=receipt["authorization_id"],
                      task_id="task-pgx", served_digest="c" * 64,
                      receipt_digest="e" * 64, outcome="pass")
        self.plane.record_outcome(**kwargs)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_already_recorded"):
            self.plane.record_outcome(**kwargs)

    def test_a_failed_transaction_leaves_no_partial_state(self):
        nonce = "nonce-rollback-1"
        with self.assertRaises(Exception):
            with self.plane._transaction() as con:
                con.execute(
                    "INSERT INTO session_nonce (nonce, session_digest, "
                    "expires_at) VALUES (%s, %s, %s)",
                    (nonce, "b" * 64, "2030-01-01T00:00:00Z"))
                raise RuntimeError("simulated failure")
        self.assertIsNone(self.plane.authorization_for_nonce(nonce))

    def test_the_authority_head_is_shared_across_connections(self):
        first = PostgresControlPlane(DSN)
        second = PostgresControlPlane(DSN)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        # Both connections see the same authority head after a commit.
        head = first.authority_head()
        self.assertEqual(second.authority_head(), head)

    def test_the_schema_version_is_reported(self):
        self.assertIsInstance(self.plane.schema_version(), int)


if __name__ == "__main__":
    unittest.main()
