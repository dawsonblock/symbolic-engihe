"""PR-05: atomic attribution across processes and restarts.

The constraints that make attribution exact are database constraints, not
Python guards. These tests therefore run real child processes against a
real database file: if the guarantee only held inside one interpreter,
the cross-process tests would fail.
"""
from __future__ import annotations

import multiprocessing
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import OutcomeV2
from sis.v3.control_plane import (
    ControlPlaneError,
    PostgresControlPlane,
    SqliteControlPlane,
)
from sis.v3.evidence_binding import (
    SigningKey,
    attempt_id_for_identity,
    bindings_digest,
    sign_authorization,
    sign_receipt,
    unreported_exposure_digest,
)
from sis.v3.execution_identity import sign_execution_identity

TREE = "a" * 64
COMMIT = "abc1234"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
DSN = os.getenv("SIS_POSTGRES_DSN")


def ts(minutes: int = 0) -> str:
    return (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def identity(nonce="nonce-1"):
    return sign_execution_identity(
        b"\x11" * 32, schema_version=1, identity_id="id-1",
        requester_identity="agent-1", repository_id="repo-1",
        repository_commit=COMMIT, repository_tree_digest=TREE,
        workspace_identity="ws-1", task_id="task-1", task_family="fam-a",
        harness_identity="harness-1", session_nonce=nonce,
        issued_at=ts(0), expires_at=ts(60), signer_key_id="harness-key-1")


def build_chain(seed: bytes, key_id: str):
    """A consistent authorization/receipt/outcome triple, as plain dicts."""
    ident = identity()
    attempt_id = attempt_id_for_identity(ident)
    authorization = sign_authorization(
        seed, authorization_id="auth-fixed-1",
        requester_principal_id="agent-1",
        execution_identity_digest=ident.digest, task_id="task-1",
        attempt_id=attempt_id, repository_id="repo-1",
        repository_tree_digest=TREE, base_commit_digest=COMMIT,
        guidance_digest="c" * 64,
        authority_snapshot_digest="d" * 64,
        authority_epoch=1, decision="advisory", issued_at=ts(0),
        expires_at=ts(30), signer_key_id=key_id)
    receipt = sign_receipt(
        seed, receipt_id="rcpt-fixed-1",
        authorization_id=authorization.authorization_id,
        attempt_id=attempt_id, task_id="task-1",
        requester_principal_id="agent-1", repository_id="repo-1",
        repository_tree_digest=TREE, base_commit_digest=COMMIT,
        submitted_artifact_digest="f" * 64,
        guidance_exposure_digest=unreported_exposure_digest(authorization),
        test_suite_commitment="1" * 64, environment_digest="2" * 64,
        criterion_version="v1", result="pass",
        independence="independent", dependency_receipt_digest=None,
        evaluator_identity="sis-v3-test-evaluator", issued_at=ts(3),
        expires_at=ts(60), nonce="receipt-nonce-fixed-1",
        signer_key_id=key_id)
    outcome = OutcomeV2(
        schema_version=1, outcome_id="out-fixed-1",
        authorization_id=authorization.authorization_id,
        receipt_digest=receipt.digest, attempt_id=attempt_id,
        task_id="task-1", requester_principal_id="agent-1",
        repository_id="repo-1", guidance_digest="c" * 64,
        guidance_exposure_digest=receipt.guidance_exposure_digest,
        result="pass", independence="independent",
        dependency_receipt_digest=None,
        authority_snapshot_digest=authorization.authority_snapshot_digest,
        bindings_digest=bindings_digest(authorization, receipt),
        recorded_at=ts(5))
    return ident, authorization, receipt, outcome


def _seed_plane(db_path: str, seed_hex: str, key_id: str) -> None:
    plane = SqliteControlPlane(
        db_path, signing_key=SigningKey(bytes.fromhex(seed_hex), key_id))
    plane.close()


def _submit_outcome_worker(db_path: str, seed_hex: str, key_id: str,
                           outcome_dict: dict, queue) -> None:
    plane = SqliteControlPlane(
        db_path, signing_key=SigningKey(bytes.fromhex(seed_hex), key_id))
    try:
        plane.record_bound_outcome(OutcomeV2.from_dict(outcome_dict))
        verdict = "accepted"
    except ControlPlaneError as exc:
        verdict = exc.reason
    except Exception as exc:  # noqa: BLE001 - surfaced to the parent
        verdict = f"error:{type(exc).__name__}:{exc}"
    finally:
        plane.close()
    queue.put(verdict)


def _authorize_worker(db_path: str, seed_hex: str, key_id: str,
                      nonce: str, queue) -> None:
    plane = SqliteControlPlane(
        db_path, signing_key=SigningKey(bytes.fromhex(seed_hex), key_id))
    try:
        ident = identity(nonce=nonce)
        plane.commit_bound_authorization(
            attempt_id=attempt_id_for_identity(ident), nonce=nonce,
            session_digest=ident.digest,
            execution_identity_digest=ident.digest,
            requester_principal_id="agent-1", task_id="task-1",
            repository_id="repo-1", repository_tree_digest=TREE,
            base_commit_digest=COMMIT, guidance_digest="c" * 64,
            decision="advisory", expires_at=ts(30), committed_at=ts(0))
        verdict = "accepted"
    except ControlPlaneError as exc:
        verdict = exc.reason
    except Exception as exc:  # noqa: BLE001
        verdict = f"error:{type(exc).__name__}:{exc}"
    finally:
        plane.close()
    queue.put(verdict)


class CrossProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "plane.db")
        self.seed, self.public = signatures.generate_keypair()
        self.key_id = "auth-key-1"
        self.eval_seed, _ = signatures.generate_keypair()
        _seed_plane(self.db, self.seed.hex(), self.key_id)

    def _run(self, target, args, count):
        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        procs = [context.Process(target=target, args=(*args, queue))
                 for _ in range(count)]
        for proc in procs:
            proc.start()
        results = [queue.get(timeout=120) for _ in procs]
        for proc in procs:
            proc.join(timeout=120)
        return results

    def _seed_bound(self, nonce="nonce-1"):
        """Commit one authorization and one receipt; return the outcome."""
        plane = SqliteControlPlane(
            self.db, signing_key=SigningKey(self.seed, self.key_id))
        ident = identity(nonce=nonce)
        plane.commit_bound_authorization(
            attempt_id=attempt_id_for_identity(ident), nonce=nonce,
            session_digest=ident.digest,
            execution_identity_digest=ident.digest,
            requester_principal_id="agent-1", task_id="task-1",
            repository_id="repo-1", repository_tree_digest=TREE,
            base_commit_digest=COMMIT, guidance_digest="c" * 64,
            decision="advisory", expires_at=ts(60), committed_at=ts(0))
        committed = plane.bound_authorization_for_nonce(nonce)
        receipt = sign_receipt(
            self.seed, receipt_id="rcpt-" + nonce,
            authorization_id=committed.authorization_id,
            attempt_id=committed.attempt_id, task_id="task-1",
            requester_principal_id="agent-1", repository_id="repo-1",
            repository_tree_digest=TREE, base_commit_digest=COMMIT,
            submitted_artifact_digest="f" * 64,
            guidance_exposure_digest=unreported_exposure_digest(committed),
            test_suite_commitment="1" * 64, environment_digest="2" * 64,
            criterion_version="v1", result="pass",
        independence="independent", dependency_receipt_digest=None,
            evaluator_identity="sis-v3-test-evaluator", issued_at=ts(3),
            expires_at=ts(120), nonce="receipt-" + nonce,
            signer_key_id=self.key_id)
        plane.record_evaluator_receipt(receipt)
        outcome = OutcomeV2(
            schema_version=1, outcome_id="out-" + nonce,
            authorization_id=committed.authorization_id,
            receipt_digest=receipt.digest, attempt_id=committed.attempt_id,
            task_id="task-1", requester_principal_id="agent-1",
            repository_id="repo-1", guidance_digest="c" * 64,
            guidance_exposure_digest=receipt.guidance_exposure_digest,
            result="pass", independence="independent",
            dependency_receipt_digest=None,
            authority_snapshot_digest=committed.authority_snapshot_digest,
            bindings_digest=bindings_digest(committed, receipt),
            recorded_at=ts(5))
        plane.close()
        return outcome

    def test_concurrent_outcomes_accept_exactly_one(self):
        outcome = self._seed_bound()
        results = self._run(
            _submit_outcome_worker,
            (self.db, self.seed.hex(), self.key_id, outcome.to_dict()), 6)
        self.assertEqual(results.count("accepted"), 1, results)
        self.assertTrue(all(r == "outcome_already_recorded"
                            for r in results if r != "accepted"), results)

        check = SqliteControlPlane(
            self.db, signing_key=SigningKey(self.seed, self.key_id))
        self.addCleanup(check.close)
        self.assertEqual(len(check.independent_outcomes()), 1)

    def test_concurrent_authorizations_accept_exactly_one(self):
        results = self._run(
            _authorize_worker,
            (self.db, self.seed.hex(), self.key_id, "nonce-race"), 6)
        self.assertEqual(results.count("accepted"), 1, results)
        self.assertTrue(all(r == "session_nonce_replayed"
                            for r in results if r != "accepted"), results)

    def test_constraint_survives_process_restart(self):
        outcome = self._seed_bound(nonce="nonce-restart")
        results = self._run(
            _submit_outcome_worker,
            (self.db, self.seed.hex(), self.key_id, outcome.to_dict()), 2)
        self.assertEqual(results.count("accepted"), 1, results)
        # A fresh interpreter re-running the same submission is still
        # refused: the guarantee is in the file, not in memory.
        again = self._run(
            _submit_outcome_worker,
            (self.db, self.seed.hex(), self.key_id, outcome.to_dict()), 1)
        self.assertEqual(again, ["outcome_already_recorded"])


@unittest.skipUnless(DSN, "SIS_POSTGRES_DSN not configured")
class PostgresConstraintTests(unittest.TestCase):
    """The same invariants under the multi-replica profile."""

    def setUp(self):
        self.plane = PostgresControlPlane(DSN)
        with self.plane._transaction() as con:
            for table in ("outcome_v2", "evaluator_receipt_v2",
                          "attempt_exposure", "authorization_v2",
                          "guidance_outcome", "authorization_receipt",
                          "session_nonce", "authority_head"):
                con.execute(f"DROP TABLE IF EXISTS {table}")
        self.plane.close()
        self.seed, _ = signatures.generate_keypair()
        self.key_id = "pg-auth-key-1"
        self.plane = PostgresControlPlane(
            DSN, signing_key=SigningKey(self.seed, self.key_id))
        self.addCleanup(self.plane.close)

    def test_schema_version_is_current(self):
        from sis.v3.control_plane import SCHEMA_VERSION
        self.assertEqual(self.plane.schema_version(), SCHEMA_VERSION)

    def test_duplicate_outcome_is_refused_by_the_database(self):
        _, authorization, receipt, outcome = build_chain(
            self.seed, self.key_id)
        self.plane.commit_bound_authorization(
            attempt_id=authorization.attempt_id, nonce="pg-nonce-1",
            session_digest="b" * 64,
            execution_identity_digest=authorization.execution_identity_digest,
            requester_principal_id="agent-1", task_id="task-1",
            repository_id="repo-1", repository_tree_digest=TREE,
            base_commit_digest=COMMIT, guidance_digest="c" * 64,
            decision="advisory", expires_at=ts(30), committed_at=ts(0))
        committed = self.plane.bound_authorization_for_nonce("pg-nonce-1")
        receipt = sign_receipt(
            self.seed, receipt_id="pg-rcpt-1",
            authorization_id=committed.authorization_id,
            attempt_id=committed.attempt_id, task_id="task-1",
            requester_principal_id="agent-1", repository_id="repo-1",
            repository_tree_digest=TREE, base_commit_digest=COMMIT,
            submitted_artifact_digest="f" * 64,
            guidance_exposure_digest=unreported_exposure_digest(committed),
            test_suite_commitment="1" * 64, environment_digest="2" * 64,
            criterion_version="v1", result="pass",
        independence="independent", dependency_receipt_digest=None,
            evaluator_identity="sis-v3-test-evaluator", issued_at=ts(3),
            expires_at=ts(60), nonce="pg-receipt-nonce-1",
            signer_key_id=self.key_id)
        self.plane.record_evaluator_receipt(receipt)
        outcome = OutcomeV2(
            schema_version=1, outcome_id="pg-out-1",
            authorization_id=committed.authorization_id,
            receipt_digest=receipt.digest, attempt_id=committed.attempt_id,
            task_id="task-1", requester_principal_id="agent-1",
            repository_id="repo-1", guidance_digest="c" * 64,
            guidance_exposure_digest=receipt.guidance_exposure_digest,
            result="pass", independence="independent",
            dependency_receipt_digest=None,
            authority_snapshot_digest=committed.authority_snapshot_digest,
            bindings_digest=bindings_digest(committed, receipt),
            recorded_at=ts(5))
        self.plane.record_bound_outcome(outcome)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_already_recorded"):
            self.plane.record_bound_outcome(outcome)
        self.assertEqual(len(self.plane.independent_outcomes()), 1)


if __name__ == "__main__":
    unittest.main()
