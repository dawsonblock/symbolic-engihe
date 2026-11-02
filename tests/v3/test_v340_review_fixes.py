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

from sis.v3 import signatures
from sis.v3.authority_ledger import AuthorityLedger, verify_snapshot
from sis.v3.control_plane import (
    ControlPlaneError,
    SqliteControlPlane,
    _to_psycopg_placeholders,
)
from sis.v3.evidence_binding import SigningKey, attempt_id_for_digest
from sis.v3.evidence_policy import RuleEvidence, select
from sis.v3.key_custody import four_identity_custody
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

    def test_serving_commits_against_the_epoch_it_observed(self):
        gateway = self.gateway(authority_ledger=self.fixture.ledger)
        captured = []
        real = self.fixture.ledger.authorize

        def spy(request):
            captured.append(request)
            return real(request)

        with mock.patch.object(self.fixture.ledger, "authorize", spy):
            gateway.serve(_request(), repository_id="repo-1",
                          execution_identity=self.fixture.identity())
        self.assertTrue(captured)
        self.assertEqual(captured[0].expected_epoch,
                         self.fixture.control_plane.authority_state()["epoch"])

    def test_a_configured_ledger_gates_readiness(self):
        gateway = self.gateway(authority_ledger=self.fixture.ledger)
        self.assertFalse(gateway.health()["ready"])
        self.fixture.ledger.set_candidate_status("cand-1", "qualified")
        self.fixture.ledger.publish()
        self.assertTrue(gateway.health()["ready"])


class LedgerSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth_seed, self.auth_public = signatures.generate_keypair()
        self.signer = SigningKey(self.auth_seed, "auth-key-1")
        self.ledger_seed, _ = signatures.generate_keypair()
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

    def test_publishing_an_epoch_returns_a_verified_snapshot(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        first = self.ledger.publish()
        self.assertTrue(verify_snapshot(first, self.ledger.public_key))
        # Idempotent: the stored record is returned, and it verifies.
        second = self.ledger.publish()
        self.assertEqual(first.digest, second.digest)
        self.assertTrue(verify_snapshot(second, self.ledger.public_key))

    def test_a_tampered_stored_snapshot_is_not_returned_as_published(self):
        from sis.v3.authority_ledger import LedgerError
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
        with self.assertRaisesRegex(LedgerError, "snapshot_unverifiable"):
            self.ledger.publish()

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
        # The first statement seeds the singleton row (a missing row
        # cannot be locked); the read that follows takes the lock.
        self.assertIn("INSERT", con.sql[0])
        self.assertIn("FOR UPDATE", con.sql[-1])

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
            plane.close()
            con = sqlite3.connect(str(path))
            try:
                columns = {
                    row[1] for row in con.execute(
                        "PRAGMA table_info(evaluator_receipt_v2)")}
            finally:
                con.close()
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


class ServingConfigurationTests(_Fixture):
    def test_a_ledger_without_a_control_plane_is_refused(self):
        with self.assertRaisesRegex(
                ValueError, "authority_ledger_requires_bound_gateway"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                authority_ledger=object())

    def test_a_ledger_without_a_binding_authority_is_refused(self):
        with self.assertRaisesRegex(
                ValueError, "authority_ledger_requires_bound_gateway"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                control_plane=self.fixture.control_plane,
                authority_ledger=object())

    def test_a_policy_without_a_provider_is_refused(self):
        with self.assertRaisesRegex(
                ValueError, "must_be_configured_together"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                evidence_policy=object())

    def test_a_provider_without_a_policy_is_refused(self):
        with self.assertRaisesRegex(
                ValueError, "must_be_configured_together"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                evidence_provider=lambda candidate: None)


class ServingRolloutTests(_Fixture):
    def test_shadow_delivers_nothing(self):
        gateway = self.gateway(rollout=evaluate({}, stage=SHADOW))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "rollout_shadow")

    def test_shadow_still_authenticates_the_caller(self):
        gateway = self.gateway(rollout=evaluate({}, stage=SHADOW))
        tampered = self.fixture.identity().to_dict()
        tampered["signer_key_id"] = "not-trusted"
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=tampered)
        # Identity is checked before the stage: a shadow replica does not
        # accept an unauthenticated caller just because it serves nothing.
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

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

    def test_a_non_digest_identity_is_refused(self):
        from sis.v3.evidence_binding import BindingError
        with self.assertRaisesRegex(BindingError,
                                    "execution_identity_digest_invalid"):
            attempt_id_for_digest("not-a-digest")


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


class PowerValidationTests(unittest.TestCase):
    def test_a_treatment_rate_above_one_is_refused(self):
        from sis.v3.statistical_power import PowerRequirement, StatisticsError
        with self.assertRaisesRegex(StatisticsError,
                                    "treatment_rate_exceeds_one"):
            PowerRequirement(design="two_proportion", effect_milli=500,
                             baseline_milli=600)

    def test_a_malformed_preregistration_is_refused(self):
        from sis.v3.statistical_power import (
            PowerRequirement,
            PreregistrationRecord,
            StatisticsError,
        )
        fields = dict(
            preregistration_id="pre-1",
            protocol_digest="0" * 64,
            primary_metric="paired solved_delta E vs A",
            power=PowerRequirement(design="paired_mcnemar",
                                   effect_milli=400,
                                   discordant_milli=300),
            holdout_lineages=(),
            training_lineages=(),
            registered_at="not-a-timestamp",
            timestamp_authority="tsa",
            signer_key_id="tsa-key",
            signature="0" * 128,
        )
        with self.assertRaisesRegex(StatisticsError,
                                    "registered_at_invalid"):
            PreregistrationRecord(**fields)
        with self.assertRaisesRegex(StatisticsError,
                                    "protocol_digest_invalid"):
            PreregistrationRecord(**{**fields, "protocol_digest": "short",
                                     "registered_at": "2026-01-01T00:00:00Z"})


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


class CustodyHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.custody = four_identity_custody(self.root / "keys")

    def test_a_symlinked_seed_is_refused(self):
        from sis.v3.key_custody import EVALUATOR, CustodyError, KeyCustody
        key = self.custody.key(EVALUATOR)
        link = self.root / "link.seed"
        link.symlink_to(key.seed_path)
        other = KeyCustody(self.root / "second")
        with self.assertRaisesRegex(CustodyError, "seed_is_a_symlink"):
            other.enroll(EVALUATOR, link)

    def test_a_non_hex_public_key_is_refused(self):
        from sis.v3.key_custody import CustodianKey, CustodyError
        with self.assertRaisesRegex(CustodyError, "public_key_invalid"):
            CustodianKey(role="evaluator", key_id="k",
                         public_hex="z" * 64, seed_path=self.root / "x")

    def test_a_filename_outside_the_custody_root_is_refused(self):
        from sis.v3.key_custody import EVALUATOR, CustodyError, KeyCustody
        custody = KeyCustody(self.root / "third")
        with self.assertRaisesRegex(CustodyError, "seed_filename_invalid"):
            custody.create(EVALUATOR, filename="../escaped.seed")
        self.assertFalse((self.root / "escaped.seed").exists())


class MonitorCacheTests(unittest.TestCase):
    def test_a_scan_is_reused_until_the_cache_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            plane = SqliteControlPlane(Path(tmp) / "plane.db")
            self.addCleanup(plane.close)
            clock = [0.0]
            monitor = AuthorityMonitor(control_plane=plane,
                                       clock=lambda: clock[0],
                                       cache_seconds=30)
            first = monitor.scan()
            self.assertIs(monitor.scan(), first)
            clock[0] = 31.0
            second = monitor.scan()
            self.assertIsNot(second, first)
            third = monitor.refresh()
            self.assertIsNot(third, second)
            self.assertIs(monitor.scan(), third)

    def test_a_zero_cache_scans_every_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            plane = SqliteControlPlane(Path(tmp) / "plane.db")
            self.addCleanup(plane.close)
            monitor = AuthorityMonitor(control_plane=plane, cache_seconds=0)
            self.assertIsNot(monitor.scan(), monitor.scan())


class PolicyValidationTests(unittest.TestCase):
    def test_a_negative_weight_is_refused(self):
        from sis.v3.evidence_policy import CalibrationPolicy, EvidencePolicyError
        with self.assertRaisesRegex(EvidencePolicyError,
                                    "token_weight_milli_invalid"):
            CalibrationPolicy(token_weight_milli=-1)

    def test_a_zero_token_ceiling_is_refused(self):
        from sis.v3.evidence_policy import CalibrationPolicy, EvidencePolicyError
        with self.assertRaisesRegex(EvidencePolicyError,
                                    "max_token_cost_invalid"):
            CalibrationPolicy(max_token_cost=0)

    def test_duplicate_candidate_declarations_are_refused(self):
        from sis.v3.evidence_policy import (
            EvidencePolicyError,
            RuleEvidence,
            select,
        )
        evidence = RuleEvidence(
            candidate_id="cand-1", qualification_status="qualified",
            supporting_attempts=5, counterexamples=0,
            expected_gain_milli=300, gain_lower_milli=100,
            gain_upper_milli=500, token_cost=10, latency_ms=10,
            regression_risk_milli=0)
        with self.assertRaisesRegex(EvidencePolicyError,
                                    "duplicate_candidate_id"):
            select([evidence, evidence], RetrievalContext(language="python"))


class FiveArmOrderTests(unittest.TestCase):
    def test_the_arm_order_is_a_stable_permutation_per_task(self):
        campaign = plan(tasks=3)
        for task_id in campaign.task_ids:
            order = campaign.arm_order(task_id)
            self.assertEqual(sorted(order), sorted(("A", "B", "C", "D", "E")))
            self.assertEqual(order, campaign.arm_order(task_id))
        orders = {campaign.arm_order(task) for task in campaign.task_ids}
        self.assertGreater(len(orders), 1)

    def test_a_long_task_id_is_accepted(self):
        # blake2b keys are capped at 64 bytes; a 256-char task id is legal.
        campaign = plan(tasks=1)
        long_id = "t" * 200
        order = campaign.arm_order(long_id)
        self.assertEqual(len(order), 5)

    def test_a_nonpositive_budget_is_refused(self):
        from sis.v3.five_arm import CampaignError, CampaignPlan
        with self.assertRaisesRegex(CampaignError,
                                    "max_tokens_per_task_invalid"):
            CampaignPlan(protocol=plan().protocol,
                         power_requirement=plan().power_requirement,
                         task_ids=("t0",), seed=1,
                         max_tokens_per_task=0)

    def test_the_report_records_the_order_and_the_metrics(self):
        campaign = plan(tasks=2)
        outcomes = [
            ("t0", {arm: ArmOutcome(arm=arm, valid_solve=True, tokens=10,
                                    wall_seconds=1.0, abstained=(arm == "B"),
                                    negative_transfer=(arm == "C"),
                                    integrity_failures=(1 if arm == "D" else 0))
                    for arm in ("A", "B", "C", "D", "E")}),
            ("t1", {arm: ArmOutcome(arm=arm, valid_solve=True, tokens=10,
                                    wall_seconds=1.0)
                    for arm in ("A", "B", "C", "D", "E")}),
        ]
        report = build_report(campaign, outcomes)
        self.assertEqual(report["per_task"][0]["arm_order"],
                         list(campaign.arm_order("t0")))
        self.assertEqual(report["governed"]["metrics"]["B"]["abstention_rate"],
                         0.5)
        self.assertEqual(
            report["governed"]["metrics"]["C"]["negative_transfer_rate"], 0.5)
        self.assertEqual(
            report["governed"]["metrics"]["D"][
                "evaluation_integrity_failures"], 1)


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
        self.service.health.return_value = {
            "ready": True, "checks": {"control_plane": {"ok": True}}}
        env = {"SIS_API_KEY": "review-token-0000000000000001",
               "SIS_ALLOW_LEGACY_V1": "0"}
        with mock.patch.dict(os.environ, env, clear=False):
            self.temp = tempfile.TemporaryDirectory()
            self.addCleanup(self.temp.cleanup)
            self.httpd = create_server(
                "127.0.0.1", 0,
                db_path=str(Path(self.temp.name) / "legacy.db"),
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

    def test_readyz_answers_without_a_key_but_hides_the_checks(self):
        status, body = self.get("/readyz")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ready"])
        self.assertNotIn("checks", payload)

    def test_readyz_shows_the_checks_to_an_authenticated_operator(self):
        import http.client
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=8)
        connection.request(
            "GET", "/readyz",
            headers={"X-SIS-Key": "review-token-0000000000000001"})
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        self.assertIn("checks", payload)

    def test_other_routes_still_require_a_key(self):
        status, _ = self.get("/health")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
