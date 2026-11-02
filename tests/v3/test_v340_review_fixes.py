"""Regressions for the review findings on the v3.4.0 branch.

Every test here pins a defect that was found by reviewing the branch, not
by running it: each one fails against the pre-review code and passes now.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.authority_ledger import AuthorityLedger
from sis.v3.control_plane import (
    ControlPlaneError,
    SqliteControlPlane,
    _to_psycopg_placeholders,
)
from sis.v3.evidence_binding import SigningKey, attempt_id_for_digest
from sis.v3.evidence_policy import RuleEvidence, select
from sis.v3.five_arm import ArmOutcome, build_report, assess
from sis.v3.learning_qualification import analyze_report
from sis.v3.operations import AuthorityMonitor
from sis.v3.retrieval import RetrievalContext
from sis.v3.rollout import ADVISORY, FULL, SHADOW, evaluate, rollback
from sis.v3.serving import GovernedServingGateway
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_evaluation_certificates import PROTOCOL_DIGEST
from tests.v3.test_execution_identity_custody import ProductionFixture
from tests.v3.test_v340_five_arm import plan

ROOT = Path(__file__).resolve().parents[2]


def _for(candidate, evidence):
    """The same evidence, attributed to the candidate being calibrated."""
    return RuleEvidence(
        candidate_id=candidate.candidate_id,
        qualification_status=evidence.qualification_status,
        supporting_attempts=evidence.supporting_attempts,
        counterexamples=evidence.counterexamples,
        expected_gain_milli=evidence.expected_gain_milli,
        gain_lower_milli=evidence.gain_lower_milli,
        gain_upper_milli=evidence.gain_upper_milli,
        token_cost=evidence.token_cost,
        latency_ms=evidence.latency_ms,
        regression_risk_milli=evidence.regression_risk_milli,
        applicability=evidence.applicability,
        abstain_when=evidence.abstain_when,
        known_failure_signatures=evidence.known_failure_signatures)


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = ProductionFixture(self.root / "stack")
        self.addCleanup(self.fixture.close)

    def gateway(self, **kwargs):
        kwargs.setdefault("production", True)
        kwargs.setdefault("execution_identity_authority",
                          self.fixture.identity_authority)
        kwargs.setdefault("control_plane", self.fixture.control_plane)
        kwargs.setdefault("binding_authority",
                          self.fixture.binding_authority)
        return GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            **kwargs)


class RecheckTimestampTests(_Fixture):
    """``recheck`` compared ISO strings; an offset expiry passed."""

    def _authorization(self, expires_at, now):
        authorization = self.fixture.control_plane.commit_bound_authorization(
            attempt_id=attempt_id_for_digest("b" * 64),
            nonce="nonce-offset-1", session_digest="b" * 64,
            execution_identity_digest="b" * 64,
            requester_principal_id="agent-1", task_id="task-1",
            repository_id="repo-1", repository_tree_digest="a" * 64,
            base_commit_digest="abc1234", guidance_digest="c" * 64,
            decision="advisory", expires_at=expires_at,
            identity_expires_at=expires_at,
            committed_at="2026-11-02T01:00:00Z")
        self.fixture.binding_authority._clock = lambda: now
        return authorization

    def test_an_expired_authorization_with_a_non_utc_offset_is_refused(self):
        # 14:00+05:00 is 09:00Z, four hours before "now".
        authorization = self._authorization(
            "2026-11-02T14:00:00+05:00", "2026-11-02T13:00:00Z")
        with self.assertRaisesRegex(ValueError, "authorization_expired"):
            self.gateway().recheck(authorization.authorization_id)

    def test_a_live_authorization_with_a_non_utc_offset_is_accepted(self):
        # 18:00+05:00 is 13:00Z, two hours after "now".
        authorization = self._authorization(
            "2026-11-02T18:00:00+05:00", "2026-11-02T11:00:00Z")
        verdict = self.gateway().recheck(authorization.authorization_id)
        self.assertEqual(verdict["attempt_id"], authorization.attempt_id)

    def test_an_epoch_change_invalidates_a_delayed_delivery(self):
        authorization = self._authorization(
            "2030-01-01T00:00:00Z", "2026-11-02T11:00:00Z")
        gateway = self.gateway()
        self.assertEqual(
            gateway.recheck(authorization.authorization_id)["ledger_epoch"], 0)
        self.fixture.control_plane.set_authority_subject(
            subject_kind="candidate", subject_id="cand-1",
            status="qualified")
        with self.assertRaisesRegex(ValueError, "authority_epoch_changed"):
            gateway.recheck(authorization.authorization_id)


class LedgerSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth_seed, self.auth_public = __import__(
            "sis.v3.signatures", fromlist=["signatures"]).generate_keypair()
        self.signer = SigningKey(self.auth_seed, "auth-key-1")
        self.ledger_seed, _ = __import__(
            "sis.v3.signatures", fromlist=["signatures"]).generate_keypair()
        self.ledger_signer = SigningKey(self.ledger_seed, "ledger-key-1")
        self.plane = SqliteControlPlane(
            self.root / "plane.db", signing_key=self.signer)
        self.addCleanup(self.plane.close)
        self.ledger = AuthorityLedger(self.plane,
                                      signing_key=self.ledger_signer)

    def test_the_ledger_may_not_share_the_authorization_key(self):
        from sis.v3.authority_ledger import LedgerError
        with self.assertRaisesRegex(LedgerError, "ledger_signer_not_distinct"):
            AuthorityLedger(self.plane, signing_key=self.signer)

    def test_a_snapshot_is_signed_and_verified_on_read(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        snapshot = self.ledger.publish()
        self.assertTrue(snapshot.epoch >= 1)
        readiness = self.ledger.readiness()
        self.assertTrue(readiness["snapshot_verified"])
        self.assertTrue(readiness["ok"])

    def test_a_tampered_snapshot_is_not_ready(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.publish()
        con = sqlite3.connect(str(self.plane.path))
        try:
            row = con.execute(
                "SELECT epoch, record_json FROM authority_snapshot_v2"
            ).fetchone()
            record = json.loads(row[1])
            record["subject_count"] = record["subject_count"] + 1
            con.execute(
                "UPDATE authority_snapshot_v2 SET record_json=? WHERE epoch=?",
                (json.dumps(record), row[0]))
            con.commit()
        finally:
            con.close()
        readiness = self.ledger.readiness()
        self.assertFalse(readiness["snapshot_verified"])
        self.assertFalse(readiness["ok"])

    def test_publish_is_idempotent_per_epoch(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        first = self.ledger.publish()
        second = self.ledger.publish()
        self.assertEqual(first.digest, second.digest)

    def test_heads_reflect_the_state_at_publication(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        snapshot = self.ledger.publish()
        self.assertEqual(snapshot.subject_count, 1)
        self.ledger.set_candidate_status("cand-2", "qualified")
        readiness = self.ledger.readiness()
        self.assertFalse(readiness["snapshot_current"])


class PostgresLockTests(unittest.TestCase):
    """The epoch row is locked on PostgreSQL and untouched on SQLite."""

    class _Con:
        def __init__(self):
            self.sql = []

        def execute(self, sql, params=()):
            self.sql.append(sql)

            class _Cursor:
                def fetchone(self):
                    return (1, 0, None, "2026-01-01T00:00:00Z")

            return _Cursor()

    def _plane(self, placeholder):
        plane = object.__new__(SqliteControlPlane)
        plane.placeholder = placeholder
        return plane

    def test_postgres_reads_the_epoch_row_for_update(self):
        con = self._Con()
        self._plane("%s")._ledger_state(con, for_update=True)
        self.assertIn("FOR UPDATE", con.sql[0])

    def test_sqlite_does_not_use_for_update(self):
        con = self._Con()
        self._plane("?")._ledger_state(con, for_update=True)
        self.assertNotIn("FOR UPDATE", con.sql[0])

    def test_authorize_bound_locks_the_epoch_row(self):
        source = (ROOT / "src/sis/v3/control_plane.py").read_text()
        body = source.split("def authorize_bound(")[1].split(
            "def ", 1)[0]
        self.assertIn("for_update=True", body)
        body = source.split("def _bump_epoch(")[1].split("def ", 1)[0]
        self.assertIn("for_update=True", body)


class PlaceholderTests(unittest.TestCase):
    def test_a_question_mark_inside_a_literal_is_preserved(self):
        sql = "SELECT * FROM t WHERE note LIKE '%?%' AND id=?"
        self.assertEqual(
            _to_psycopg_placeholders(sql),
            "SELECT * FROM t WHERE note LIKE '%?%' AND id=%s")

    def test_shared_statements_are_rewritten(self):
        self.assertEqual(
            _to_psycopg_placeholders("SELECT 1 FROM t WHERE a=? AND b=?"),
            "SELECT 1 FROM t WHERE a=%s AND b=%s")


class AdditiveColumnTests(unittest.TestCase):
    """A database created by an earlier v3.4.0 build gains new columns."""

    def test_missing_receipt_columns_are_added_on_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plane.db"
            plane = SqliteControlPlane(path)
            plane.close()
            con = sqlite3.connect(str(path))
            try:
                con.execute(
                    "ALTER TABLE evaluator_receipt_v2"
                    " DROP COLUMN independence")
                con.execute(
                    "ALTER TABLE evaluator_receipt_v2"
                    " DROP COLUMN dependency_receipt_digest")
                con.commit()
            finally:
                con.close()
            plane = SqliteControlPlane(path)
            try:
                columns = {
                    row[1] for row in sqlite3.connect(str(path)).execute(
                        "PRAGMA table_info(evaluator_receipt_v2)")}
            finally:
                plane.close()
            self.assertIn("independence", columns)
            self.assertIn("dependency_receipt_digest", columns)


class EvidenceSelectionTests(unittest.TestCase):
    def evidence(self):
        return RuleEvidence(
            candidate_id="cand-1", qualification_status="qualified",
            supporting_attempts=5, counterexamples=0,
            expected_gain_milli=300, gain_lower_milli=100,
            gain_upper_milli=500, token_cost=10, latency_ms=10,
            regression_risk_milli=0)

    def test_select_accepts_a_generator(self):
        decisions = select((item for item in [self.evidence()]),
                           RetrievalContext(language="python"))
        self.assertEqual(len(decisions), 1)
        self.assertTrue(decisions[0].serve)


class ServingRolloutTests(_Fixture):
    def test_shadow_delivers_nothing(self):
        gateway = self.gateway(rollout=evaluate({}, stage=SHADOW))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "rollout_shadow")

    def test_advisory_delivers_no_procedure_grants(self):
        gateway = self.gateway(rollout=evaluate({}, stage=ADVISORY))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertNotEqual(guidance.decision, "recommend")
        self.assertEqual(guidance.procedure_ids, ())

    def test_full_delivers_normally(self):
        gateway = self.gateway(rollout=evaluate({}, stage=FULL))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertNotEqual(guidance.reason_code, "rollout_shadow")

    def test_a_critical_monitor_finding_makes_the_gateway_not_ready(self):
        gateway = self.gateway()
        gateway.serve(_request(), repository_id="repo-1",
                      execution_identity=self.fixture.identity())
        monitor = AuthorityMonitor(control_plane=self.fixture.control_plane)
        # A revoked signer that already authorized guidance is critical.
        self.fixture.control_plane.set_authority_revocation(
            revocation_kind="signer", target=self.fixture.auth_key)
        gateway = self.gateway(monitor=monitor)
        health = gateway.health()
        self.assertFalse(health["ready"])
        self.assertFalse(health["checks"]["authority_monitor"]["ok"])


class NegativeTransferServingTests(_Fixture):
    def test_a_known_failure_signature_blocks_the_rule(self):
        blocked = RuleEvidence(
            candidate_id="ignored", qualification_status="qualified",
            supporting_attempts=5, counterexamples=0,
            expected_gain_milli=300, gain_lower_milli=100,
            gain_upper_milli=500, token_cost=10, latency_ms=10,
            regression_risk_milli=0,
            known_failure_signatures=("task-1",))
        gateway = self.gateway(
            evidence_policy=__import__(
                "sis.v3.evidence_policy", fromlist=["CalibrationPolicy"]
            ).CalibrationPolicy(),
            evidence_provider=lambda candidate: _for(candidate, blocked))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")

    def test_an_unrelated_failure_signature_does_not_block(self):
        evidence = RuleEvidence(
            candidate_id="ignored", qualification_status="qualified",
            supporting_attempts=5, counterexamples=0,
            expected_gain_milli=300, gain_lower_milli=100,
            gain_upper_milli=500, token_cost=10, latency_ms=10,
            regression_risk_milli=0,
            known_failure_signatures=("task-zzzz",))
        gateway = self.gateway(
            evidence_policy=__import__(
                "sis.v3.evidence_policy", fromlist=["CalibrationPolicy"]
            ).CalibrationPolicy(),
            evidence_provider=lambda candidate: _for(candidate, evidence))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertNotEqual(guidance.decision, "abstain")


class AttemptDerivationTests(_Fixture):
    def test_a_chosen_attempt_id_is_refused(self):
        with self.assertRaisesRegex(ControlPlaneError,
                                    "attempt_id_not_derived"):
            self.fixture.control_plane.commit_bound_authorization(
                attempt_id="att-chosen", nonce="nonce-chosen",
                session_digest="b" * 64,
                execution_identity_digest="b" * 64,
                requester_principal_id="agent-1", task_id="task-1",
                repository_id="repo-1", repository_tree_digest="a" * 64,
                base_commit_digest="abc1234", guidance_digest="c" * 64,
                decision="advisory", expires_at="2030-01-01T00:00:00Z")


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "plane.db"

    def run_tool(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/migrate_control_plane.py"),
             "--db", str(self.db), *args],
            capture_output=True, text=True, env=env, timeout=60)

    def version(self):
        con = sqlite3.connect(str(self.db))
        try:
            return con.execute(
                "SELECT version FROM schema_meta WHERE singleton=1"
            ).fetchone()[0]
        finally:
            con.close()

    def tables(self):
        con = sqlite3.connect(str(self.db))
        try:
            return {row[0] for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            con.close()

    def test_upgrade_to_schema_two_lands_at_two(self):
        plane = SqliteControlPlane(self.db)
        plane.close()
        result = self.run_tool("--to", "1", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_tool("--to", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version(), 2)
        self.assertIn("authorization_v2", self.tables())
        self.assertNotIn("authority_state", self.tables())

    def test_the_backup_is_owner_only(self):
        plane = SqliteControlPlane(self.db)
        plane.close()
        result = self.run_tool("--to", "1", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        backups = [path for path in self.root.glob("plane.db.bak-*")
                   if not path.name.endswith(("-shm", "-wal"))]
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o077, 0)


class ReportPowerTests(unittest.TestCase):
    def report(self, tasks):
        return {
            "per_task": [
                {"task_id": task, "arms": {"A": {"valid_solve": False},
                                           "E": {"valid_solve": True}}}
                for task in tasks
            ],
            "governed": {"metrics": {}, "conformance": {"conforms": True}},
        }

    def test_a_malformed_power_requirement_is_exploratory(self):
        protocol = {
            "protocol_digest": PROTOCOL_DIGEST,
            "primary_metric": "paired solved_delta E vs A",
            "alpha": 0.05,
            "sample_size": 29,
            "power_requirement": {"design": "not_a_design"},
        }
        report = analyze_report(
            self.report([f"t{i}" for i in range(29)]), protocol=protocol,
            real_agent=True, hidden_holdout=True)
        self.assertEqual(report["evidence_class"], "exploratory")
        self.assertIsNotNone(report["power_requirement_error"])
        self.assertTrue(any("power requirement is invalid" in item
                            for item in report["limitations"]))


class FiveArmBudgetTests(unittest.TestCase):
    def test_a_budget_exceeded_run_is_not_a_solve(self):
        campaign = plan(tasks=29)
        outcomes = []
        for index in range(29):
            arms = {
                arm: ArmOutcome(
                    arm=arm, valid_solve=True,
                    tokens=(10 ** 6 if arm == "E" else 100),
                    wall_seconds=1.0)
                for arm in ("A", "B", "C", "D", "E")
            }
            outcomes.append((f"t{index}", arms))
        report = build_report(campaign, outcomes)
        verdict = assess(report, plan=campaign)
        self.assertEqual(report["budget_exceeded"], 29)
        self.assertEqual(verdict["solve_rate"]["E"], 0.0)


class RollbackTests(unittest.TestCase):
    def test_rollback_preserves_the_gate_status(self):
        status = {"evidence_chain_bound": True, "kill_switch_effective": True}
        state = rollback(FULL, reason="incident", status=status)
        self.assertEqual(state.stage, ADVISORY)
        self.assertTrue(state.status["evidence_chain_bound"])
        self.assertTrue(state.status["rollback_reason"])


class HealthEndpointTests(unittest.TestCase):
    def setUp(self):
        from sis.server import create_server
        self.service = mock.Mock()
        self.service.health.return_value = {"ready": True, "checks": {}}
        env = {"SIS_API_KEY": "review-token-0000000000000001",
               "SIS_ALLOW_LEGACY_V1": "0"}
        with mock.patch.dict(os.environ, env, clear=False):
            self.httpd = create_server(
                "127.0.0.1", 0, db_path=str(ROOT / "unused.db"),
                v3_service=self.service)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.httpd.sis_service is not None:
            self.httpd.sis_service.registry.close()
        self.thread.join(timeout=5)

    def get(self, path):
        import http.client
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=8)
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response.status, body

    def test_livez_answers_without_a_key(self):
        status, _ = self.get("/livez")
        self.assertEqual(status, 200)

    def test_readyz_answers_without_a_key(self):
        status, _ = self.get("/readyz")
        self.assertEqual(status, 200)

    def test_other_routes_still_require_a_key(self):
        status, _ = self.get("/health")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
