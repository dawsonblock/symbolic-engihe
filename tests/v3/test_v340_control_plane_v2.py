"""PR-03: schema-2 persistence and the atomic attribution constraints."""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import (
    ContractError,
    OutcomeV2,
    canonical_digest,
)
from sis.v3.control_plane import (
    SCHEMA_VERSION,
    ControlPlaneError,
    SqliteControlPlane,
)
from sis.v3.evidence_binding import (
    SigningKey,
    attempt_exposure_digest,
    attempt_id_for_digest,
    attempt_id_for_identity,
    bindings_digest,
    sign_attempt,
    sign_receipt,
    unreported_exposure_digest,
)
from sis.v3.execution_identity import sign_execution_identity

TREE = "a" * 64
COMMIT = "abc1234"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


def ts(minutes: int = 0) -> str:
    return (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def identity(nonce="nonce-1", **overrides):
    fields = {
        "schema_version": 1, "identity_id": "id-1",
        "requester_identity": "agent-1", "repository_id": "repo-1",
        "repository_commit": COMMIT, "repository_tree_digest": TREE,
        "workspace_identity": "ws-1", "task_id": "task-1",
        "task_family": "fam-a", "harness_identity": "harness-1",
        "session_nonce": nonce, "issued_at": ts(0), "expires_at": ts(10),
        "signer_key_id": "harness-key-1",
    }
    fields.update(overrides)
    return sign_execution_identity(b"\x11" * 32, **fields)


class PlaneFixture:
    """A control plane plus the keys needed to build a bound chain."""

    def __init__(self, root: Path):
        self.root = root
        self.auth_seed, self.auth_public = signatures.generate_keypair()
        self.signer = SigningKey(self.auth_seed, "auth-key-1")
        self.eval_seed, self.eval_public = signatures.generate_keypair()
        self.harness_seed, self.harness_public = signatures.generate_keypair()
        self.plane = SqliteControlPlane(
            root / "plane.db", signing_key=self.signer)

    def close(self):
        self.plane.close()

    def authorize(self, *, nonce="nonce-1", guidance="c" * 64,
                  requester="agent-1", repository="repo-1",
                  tree=TREE, commit=COMMIT, task="task-1",
                  expires_at=None, attempt_id=None, ident=None):
        ident = ident or identity(nonce=nonce)
        return self.plane.commit_bound_authorization(
            attempt_id=attempt_id or attempt_id_for_identity(ident),
            nonce=nonce, session_digest=ident.digest,
            execution_identity_digest=ident.digest,
            requester_principal_id=requester, task_id=task,
            repository_id=repository, repository_tree_digest=tree,
            base_commit_digest=commit, guidance_digest=guidance,
            decision="advisory", expires_at=expires_at or ts(30),
            committed_at=ts(0))

    def exposure(self, authorization, *, state="used", sequence=1,
                 started=ts(1), ended=ts(2), harness="harness-1",
                 authorization_id=None, attempt_id=None,
                 guidance=None):
        attempt = sign_attempt(
            self.harness_seed,
            attempt_id=attempt_id or authorization.attempt_id,
            execution_identity_digest=authorization.execution_identity_digest,
            requester_principal_id=authorization.requester_principal_id,
            task_id=authorization.task_id,
            repository_id=authorization.repository_id,
            repository_tree_digest=authorization.repository_tree_digest,
            base_commit_digest=authorization.base_commit_digest,
            authorization_id=authorization_id
            or authorization.authorization_id,
            guidance_digest=guidance or authorization.guidance_digest,
            exposure_state=state, exposure_evidence_digest="e" * 64,
            attempt_sequence=sequence, started_at=started, ended_at=ended,
            harness_identity=harness, signer_key_id="harness-key-1")
        return attempt

    def receipt(self, authorization, *, exposure_digest=None, result="pass",
                receipt_id="rcpt-1", nonce=None,
                attempt_id=None, repository=None, tree=None,
                authorization_id=None, expires_at=None, issued=ts(3),
                independence="independent", dependency=None):
        return sign_receipt(
            self.eval_seed, receipt_id=receipt_id,
            authorization_id=authorization_id
            or authorization.authorization_id,
            attempt_id=attempt_id or authorization.attempt_id,
            task_id=authorization.task_id,
            requester_principal_id=authorization.requester_principal_id,
            repository_id=repository or authorization.repository_id,
            repository_tree_digest=tree
            or authorization.repository_tree_digest,
            base_commit_digest=authorization.base_commit_digest,
            submitted_artifact_digest="f" * 64,
            guidance_exposure_digest=exposure_digest
            or unreported_exposure_digest(authorization),
            test_suite_commitment="1" * 64, environment_digest="2" * 64,
            criterion_version="v1", result=result,
            independence=independence, dependency_receipt_digest=dependency,
            evaluator_identity="sis-v3-test-evaluator", issued_at=issued,
            expires_at=expires_at,
            nonce=nonce or "receipt-nonce-" + receipt_id,
            signer_key_id="eval-key-1")

    def outcome(self, authorization, receipt, *, independence=None,
                dependency=None, result="pass", outcome_id=None):
        return OutcomeV2(
            schema_version=1,
            outcome_id=outcome_id or "out-" + receipt.receipt_id,
            authorization_id=authorization.authorization_id,
            receipt_digest=receipt.digest,
            attempt_id=authorization.attempt_id,
            task_id=authorization.task_id,
            requester_principal_id=authorization.requester_principal_id,
            repository_id=authorization.repository_id,
            guidance_digest=authorization.guidance_digest,
            guidance_exposure_digest=receipt.guidance_exposure_digest,
            result=result,
            independence=independence or receipt.independence,
            dependency_receipt_digest=(
                dependency if dependency is not None
                else receipt.dependency_receipt_digest),
            authority_snapshot_digest=authorization.authority_snapshot_digest,
            bindings_digest=bindings_digest(authorization, receipt),
            recorded_at=ts(5))


class _Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fx = PlaneFixture(Path(self.temp.name))
        self.addCleanup(self.fx.close)


class SchemaTests(_Base):
    def test_schema_version_is_current(self):
        self.assertEqual(SCHEMA_VERSION, 3)
        self.assertEqual(self.fx.plane.schema_version(), SCHEMA_VERSION)

    def test_bound_tables_exist(self):
        con = sqlite3.connect(str(self.fx.root / "plane.db"))
        try:
            names = {row[0] for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            con.close()
        for table in ("authorization_v2", "attempt_exposure",
                      "evaluator_receipt_v2", "outcome_v2"):
            self.assertIn(table, names)

    def test_v1_database_upgrades_in_place(self):
        path = self.fx.root / "v1.db"
        con = sqlite3.connect(str(path))
        con.execute("CREATE TABLE schema_meta (singleton INTEGER PRIMARY KEY,"
                    " version INTEGER NOT NULL)")
        con.execute("INSERT INTO schema_meta VALUES (1, 1)")
        con.execute("CREATE TABLE guidance_outcome (authorization_id TEXT"
                    " PRIMARY KEY, task_id TEXT, served_digest TEXT,"
                    " receipt_digest TEXT, outcome TEXT, recorded_at TEXT)")
        con.execute("INSERT INTO guidance_outcome VALUES"
                    " ('auth-old','task-1','a','b','pass','2026-01-01T00:00:00Z')")
        con.commit()
        con.close()
        plane = SqliteControlPlane(path)
        self.addCleanup(plane.close)
        self.assertEqual(plane.schema_version(), SCHEMA_VERSION)
        legacy = plane.legacy_outcomes()
        self.assertEqual(len(legacy), 1)
        self.assertEqual(legacy[0]["evidence_class"], "legacy_unverified")
        self.assertEqual(plane.independent_outcomes(), [])

    def test_authorization_requires_a_signer(self):
        plane = SqliteControlPlane(self.fx.root / "unsigned.db")
        self.addCleanup(plane.close)
        self.assertFalse(plane.supports_bound_authorization())
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authorization_signer_required"):
            plane.commit_bound_authorization(
                attempt_id="att-1", nonce="n-1", session_digest="a" * 64,
                execution_identity_digest="a" * 64,
                requester_principal_id="agent-1", task_id="task-1",
                repository_id="repo-1", repository_tree_digest=TREE,
                base_commit_digest=COMMIT, guidance_digest="c" * 64,
                decision="advisory", expires_at=ts(30),
                committed_at=ts(0))


class AuthorizationBindingTests(_Base):
    def test_authorization_is_signed_and_readable(self):
        record = self.fx.authorize()
        stored = self.fx.plane.bound_authorization(record.authorization_id)
        self.assertEqual(stored, record)
        self.assertEqual(stored.signer_key_id, "auth-key-1")

    def test_same_nonce_cannot_authorize_twice(self):
        self.fx.authorize(nonce="nonce-1")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "session_nonce_replayed"):
            self.fx.authorize(nonce="nonce-1")

    def test_same_attempt_cannot_authorize_twice(self):
        first = self.fx.authorize(nonce="nonce-1")
        with self.assertRaises(ControlPlaneError):
            self.fx.authorize(nonce="nonce-2",
                              attempt_id=first.attempt_id)

    def test_two_attempts_get_two_authorizations(self):
        first = self.fx.authorize(nonce="nonce-1")
        second = self.fx.authorize(nonce="nonce-2")
        self.assertNotEqual(first.authorization_id, second.authorization_id)
        self.assertNotEqual(first.attempt_id, second.attempt_id)


class ExposureTests(_Base):
    def test_exposure_is_recorded_once(self):
        authorization = self.fx.authorize()
        attempt = self.fx.exposure(authorization)
        stored = self.fx.plane.record_attempt_exposure(attempt)
        self.assertEqual(stored["exposure_state"], "used")
        self.assertEqual(stored["record"], attempt)
        self.assertEqual(stored["exposure_digest"],
                         attempt_exposure_digest(attempt))

    def test_identical_report_is_idempotent(self):
        authorization = self.fx.authorize()
        attempt = self.fx.exposure(authorization)
        first = self.fx.plane.record_attempt_exposure(attempt)
        second = self.fx.plane.record_attempt_exposure(attempt)
        self.assertEqual(first["record_digest"], second["record_digest"])

    def test_contradictory_report_is_rejected(self):
        authorization = self.fx.authorize()
        self.fx.plane.record_attempt_exposure(self.fx.exposure(authorization))
        with self.assertRaisesRegex(ControlPlaneError,
                                    "attempt_already_reported"):
            self.fx.plane.record_attempt_exposure(
                self.fx.exposure(authorization, state="not_delivered"))

    def test_exposure_for_unknown_authorization_is_rejected(self):
        authorization = self.fx.authorize()
        attempt = self.fx.exposure(authorization,
                                   authorization_id="auth-missing")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authorization_unknown"):
            self.fx.plane.record_attempt_exposure(attempt)

    def test_exposure_must_match_the_authorized_guidance(self):
        authorization = self.fx.authorize()
        attempt = self.fx.exposure(authorization, guidance="9" * 64)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "attempt_guidance_digest_mismatch"):
            self.fx.plane.record_attempt_exposure(attempt)


class ReceiptBindingTests(_Base):
    def test_receipt_is_bound_to_the_authorization(self):
        authorization = self.fx.authorize()
        receipt = self.fx.receipt(authorization)
        stored = self.fx.plane.record_evaluator_receipt(receipt)
        self.assertEqual(stored["receipt_digest"], receipt.digest)
        self.assertEqual(stored["record"], receipt)

    def test_one_authorization_accepts_one_receipt(self):
        authorization = self.fx.authorize()
        self.fx.plane.record_evaluator_receipt(self.fx.receipt(authorization))
        with self.assertRaisesRegex(
                ControlPlaneError, "receipt_authorization_already_measured"):
            self.fx.plane.record_evaluator_receipt(
                self.fx.receipt(authorization, receipt_id="rcpt-2",
                                nonce="receipt-nonce-2"))

    def test_receipt_nonce_cannot_be_reused(self):
        first = self.fx.authorize(nonce="nonce-1")
        second = self.fx.authorize(nonce="nonce-2")
        first_receipt = self.fx.receipt(first)
        self.fx.plane.record_evaluator_receipt(first_receipt)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "receipt_already_recorded"):
            self.fx.plane.record_evaluator_receipt(
                self.fx.receipt(second, receipt_id="rcpt-2",
                                nonce=first_receipt.nonce))

    def test_receipt_for_another_repository_is_rejected(self):
        authorization = self.fx.authorize()
        receipt = self.fx.receipt(authorization, repository="repo-2")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "receipt_repository_id_mismatch"):
            self.fx.plane.record_evaluator_receipt(receipt)

    def test_receipt_for_another_attempt_is_rejected(self):
        authorization = self.fx.authorize()
        receipt = self.fx.receipt(authorization, attempt_id="att-other")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "receipt_attempt_id_mismatch"):
            self.fx.plane.record_evaluator_receipt(receipt)


class OutcomeBindingTests(_Base):
    def _bound(self, *, receipt_id=None, **kwargs):
        authorization = self.fx.authorize(**kwargs)
        receipt = self.fx.receipt(
            authorization,
            receipt_id=receipt_id or "rcpt-" + kwargs.get("nonce", "nonce-1"))
        self.fx.plane.record_evaluator_receipt(receipt)
        return authorization, receipt

    def test_outcome_is_recorded_as_verified(self):
        authorization, receipt = self._bound()
        stored = self.fx.plane.record_bound_outcome(
            self.fx.outcome(authorization, receipt))
        self.assertEqual(stored["evidence_class"], "verified")
        self.assertEqual(stored["independence"], "independent")

    def test_duplicate_outcome_is_rejected(self):
        authorization, receipt = self._bound()
        self.fx.plane.record_bound_outcome(
            self.fx.outcome(authorization, receipt))
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_already_recorded"):
            self.fx.plane.record_bound_outcome(
                self.fx.outcome(authorization, receipt,
                                outcome_id="out-second"))

    def test_outcome_requires_a_known_receipt(self):
        authorization = self.fx.authorize()
        receipt = self.fx.receipt(authorization)
        with self.assertRaisesRegex(ControlPlaneError, "receipt_unknown"):
            self.fx.plane.record_bound_outcome(
                self.fx.outcome(authorization, receipt))

    def test_outcome_result_must_match_the_receipt(self):
        authorization, receipt = self._bound()
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_result_mismatch"):
            self.fx.plane.record_bound_outcome(
                self.fx.outcome(authorization, receipt, result="fail"))

    def test_independent_outcomes_exclude_dependent_measurements(self):
        first_auth, first_receipt = self._bound(nonce="nonce-1")
        self.fx.plane.record_bound_outcome(
            self.fx.outcome(first_auth, first_receipt))
        second_auth = self.fx.authorize(nonce="nonce-2")
        second_receipt = self.fx.receipt(
            second_auth, receipt_id="rcpt-nonce-2",
            independence="dependent", dependency=first_receipt.digest)
        self.fx.plane.record_evaluator_receipt(second_receipt)
        self.fx.plane.record_bound_outcome(
            self.fx.outcome(second_auth, second_receipt))
        independent = self.fx.plane.independent_outcomes()
        self.assertEqual(len(independent), 1)
        self.assertEqual(independent[0]["authorization_id"],
                         first_auth.authorization_id)
        self.assertEqual(
            len(self.fx.plane.independent_outcomes(task_id="task-1")), 1)

    def test_one_receipt_cannot_be_credited_to_two_authorizations(self):
        first_auth, receipt = self._bound(nonce="nonce-1")
        self.fx.plane.record_bound_outcome(
            self.fx.outcome(first_auth, receipt))
        # A second authorization cannot reuse the receipt at all: the
        # receipt table pins it to the first authorization.
        second_auth = self.fx.authorize(nonce="nonce-2")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_authorization_id_mismatch"):
            self.fx.plane.record_bound_outcome(
                self.fx.outcome(second_auth, receipt,
                                independence="dependent",
                                dependency="7" * 64))

    def test_dependent_outcome_names_a_different_receipt(self):
        first_auth, first_receipt = self._bound(nonce="nonce-1")
        second_auth = self.fx.authorize(nonce="nonce-2")
        dependent = self.fx.receipt(
            second_auth, receipt_id="rcpt-dependent",
            independence="dependent", dependency=first_receipt.digest)
        self.fx.plane.record_evaluator_receipt(dependent)
        with self.assertRaises(ContractError):
            self.fx.outcome(second_auth, dependent, dependency=dependent.digest)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "independence"):
            self.fx.plane.record_bound_outcome(OutcomeV2.from_dict({
                **self.fx.outcome(second_auth, dependent).to_dict(),
                "independence": "independent",
                "dependency_receipt_digest": None,
            }))
        stored = self.fx.plane.record_bound_outcome(
            self.fx.outcome(second_auth, dependent))
        self.assertEqual(stored["independence"], "dependent")

    def test_a_dependent_receipt_must_name_a_known_receipt(self):
        authorization, receipt = self._bound(nonce="nonce-1")
        second_auth = self.fx.authorize(nonce="nonce-2")
        orphan = self.fx.receipt(
            second_auth, receipt_id="rcpt-orphan",
            independence="dependent", dependency="7" * 64)
        self.fx.plane.record_evaluator_receipt(orphan)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "dependency_receipt_unknown"):
            self.fx.plane.record_bound_outcome(
                self.fx.outcome(second_auth, orphan))


class ConcurrencyTests(_Base):
    def test_concurrent_duplicate_outcomes_accept_exactly_one(self):
        authorization = self.fx.authorize()
        receipt = self.fx.receipt(authorization)
        self.fx.plane.record_evaluator_receipt(receipt)
        outcome = self.fx.outcome(authorization, receipt)
        results: list[str] = []
        lock = threading.Lock()

        def submit():
            plane = SqliteControlPlane(
                self.fx.root / "plane.db", signing_key=self.fx.signer)
            try:
                plane.record_bound_outcome(outcome)
                verdict = "accepted"
            except ControlPlaneError as exc:
                verdict = exc.reason
            finally:
                plane.close()
            with lock:
                results.append(verdict)

        threads = [threading.Thread(target=submit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count("accepted"), 1, results)
        self.assertTrue(all(reason == "outcome_already_recorded"
                            for reason in results if reason != "accepted"),
                        results)
        self.assertEqual(len(self.fx.plane.independent_outcomes()), 1)

    def test_concurrent_duplicate_authorizations_accept_exactly_one(self):
        results: list[str] = []
        lock = threading.Lock()

        def submit(nonce):
            plane = SqliteControlPlane(
                self.fx.root / "plane.db", signing_key=self.fx.signer)
            try:
                plane.commit_bound_authorization(
                    attempt_id=attempt_id_for_digest("b" * 64),
                    nonce=nonce, session_digest="b" * 64,
                    execution_identity_digest="b" * 64,
                    requester_principal_id="agent-1", task_id="task-1",
                    repository_id="repo-1", repository_tree_digest=TREE,
                    base_commit_digest=COMMIT, guidance_digest="c" * 64,
                    decision="advisory", expires_at=ts(30),
                    committed_at=ts(0))
                verdict = "accepted"
            except ControlPlaneError as exc:
                verdict = exc.reason
            finally:
                plane.close()
            with lock:
                results.append(verdict)

        threads = [threading.Thread(target=submit, args=("nonce-race",))
                   for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count("accepted"), 1, results)


if __name__ == "__main__":
    unittest.main()
