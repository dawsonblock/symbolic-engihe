"""PR-12: monitoring, staged rollout, migrations and recovery drills."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.authority_ledger import AuthorityLedger
from sis.v3.control_plane import SCHEMA_VERSION, SqliteControlPlane
from sis.v3.evidence_binding import SigningKey, attempt_id_for_digest
from sis.v3.key_custody import four_identity_custody
from sis.v3.operations import AuthorityMonitor
from sis.v3.rollout import (
    ADVISORY,
    DEFAULT_GATES,
    FULL,
    SHADOW,
    RolloutError,
    advance,
    evaluate,
    rollback,
)

ROOT = Path(__file__).resolve().parents[2]


def all_gates() -> dict:
    return {gate.name: True for gate in DEFAULT_GATES}


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed, _ = signatures.generate_keypair()
        self.signer = SigningKey(self.seed, "auth-key-1")
        self.ledger_seed, self.ledger_public = signatures.generate_keypair()
        self.ledger_signer = SigningKey(self.ledger_seed, "ledger-key-1")
        self.plane = SqliteControlPlane(
            self.root / "plane.db", signing_key=self.signer)
        self.addCleanup(self.plane.close)
        self.ledger = AuthorityLedger(
            self.plane, signing_key=self.ledger_signer)

    def monitor(self, **kwargs):
        return AuthorityMonitor(control_plane=self.plane, ledger=self.ledger,
                                **kwargs)

    def test_a_fresh_deployment_reports_no_snapshot(self):
        report = self.monitor().scan()
        self.assertTrue(report["ok"])
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("snapshot_missing", codes)

    def test_a_published_snapshot_clears_the_warning(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.publish()
        report = self.monitor().scan()
        codes = [f["code"] for f in report["findings"]]
        self.assertNotIn("snapshot_missing", codes)
        self.assertNotIn("snapshot_stale", codes)

    def test_a_stale_snapshot_is_reported(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.publish()
        self.ledger.set_candidate_status("cand-2", "proposed")
        report = self.monitor().scan()
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("snapshot_stale", codes)

    def test_global_disable_is_reported(self):
        self.plane.set_global_disable(True, reason="incident")
        report = self.monitor().scan()
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("global_disable_active", codes)

    def test_legacy_evidence_is_reported_as_information(self):
        self.plane.commit_authorization(
            nonce="n-1", session_digest="b" * 64,
            expires_at="2030-01-01T00:00:00Z", task_id="task-1",
            repository_id="repo-1", guidance_digest="c" * 64,
            decision="advisory", snapshot_digest="d" * 64)
        legacy = self.plane.bound_authorizations()
        self.assertEqual(legacy, [])
        record = self.plane.authorization_for_task("task-1")
        self.plane.record_outcome(
            authorization_id=record["authorization_id"], task_id="task-1",
            served_digest="c" * 64, receipt_digest="e" * 64, outcome="pass")
        report = self.monitor().scan()
        codes = {f["code"]: f["severity"] for f in report["findings"]}
        self.assertEqual(codes.get("legacy_evidence_present"), "info")
        self.assertEqual(report["counts"]["legacy_outcomes"], 1)

    def test_a_revoked_signer_that_authorized_is_critical(self):
        self.plane.set_authority_revocation(
            revocation_kind="signer", target="auth-key-1")
        self.plane.commit_bound_authorization(
            attempt_id=attempt_id_for_digest("b" * 64),
            nonce="n-1", session_digest="b" * 64,
            execution_identity_digest="b" * 64,
            requester_principal_id="agent-1", task_id="task-1",
            repository_id="repo-1", repository_tree_digest="a" * 64,
            base_commit_digest="abc1234", guidance_digest="c" * 64,
            decision="advisory", expires_at="2030-01-01T00:00:00Z")
        report = self.monitor().scan()
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("revoked_signer_authorized", codes)
        self.assertFalse(report["serving_allowed"])

    def test_open_custody_permissions_are_critical(self):
        custody = four_identity_custody(self.root / "keys")
        seed_path = custody.key("evaluator").seed_path
        seed_path.chmod(0o644)
        report = self.monitor(custody=custody).scan()
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("custody_permissions_too_open", codes)
        self.assertFalse(report["ok"])

    def test_a_healthy_deployment_allows_serving(self):
        self.ledger.set_candidate_status("cand-1", "qualified")
        self.ledger.publish()
        custody = four_identity_custody(self.root / "keys")
        report = self.monitor(custody=custody).scan()
        self.assertTrue(report["ok"])
        self.assertTrue(report["serving_allowed"])


class RolloutTests(unittest.TestCase):
    def test_shadow_serves_nothing(self):
        state = evaluate(all_gates(), stage=SHADOW)
        self.assertFalse(state.may_serve())
        self.assertFalse(state.may_grant_procedures())

    def test_advisory_serves_text_but_grants_nothing(self):
        state = evaluate(all_gates(), stage=ADVISORY)
        self.assertTrue(state.may_serve())
        self.assertFalse(state.may_grant_procedures())
        self.assertFalse(state.may_promote())

    def test_full_serves_and_grants(self):
        state = evaluate(all_gates(), stage=FULL)
        self.assertTrue(state.may_serve())
        self.assertTrue(state.may_grant_procedures())
        self.assertTrue(state.may_promote())

    def test_a_missing_gate_is_a_failed_gate(self):
        status = all_gates()
        status.pop("evidence_chain_bound")
        state = evaluate(status, stage=FULL)
        self.assertFalse(state.ready)
        self.assertIn("evidence_chain_bound", state.failed_gates)
        self.assertFalse(state.may_promote())

    def test_advance_requires_every_gate(self):
        status = all_gates()
        status["kill_switch_effective"] = False
        with self.assertRaisesRegex(RolloutError, "gates_not_met"):
            advance(SHADOW, ADVISORY, status)

    def test_advance_must_be_stepwise(self):
        with self.assertRaisesRegex(RolloutError,
                                    "rollout_must_be_stepwise"):
            advance(SHADOW, FULL, all_gates())

    def test_advance_cannot_go_backwards(self):
        with self.assertRaisesRegex(RolloutError, "rollout_must_advance"):
            advance(FULL, ADVISORY, all_gates())

    def test_rollback_is_always_available(self):
        state = rollback(FULL, reason="incident")
        self.assertEqual(state.stage, ADVISORY)
        state = rollback(ADVISORY, reason="incident")
        self.assertEqual(state.stage, SHADOW)
        state = rollback(SHADOW, reason="incident")
        self.assertEqual(state.stage, SHADOW)

    def test_the_default_gates_cover_the_release_blockers(self):
        names = {gate.name for gate in DEFAULT_GATES}
        for required in ("evidence_chain_bound", "concurrency_verified",
                         "kill_switch_effective", "key_custody_independent",
                         "release_provenance_verified"):
            self.assertIn(required, names)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "plane.db"
        SqliteControlPlane(self.db).close()

    def run_tool(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / "migrate_control_plane.py"),
             "--db", str(self.db), *args],
            capture_output=True, text=True, cwd=str(ROOT),
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})

    def version(self) -> int:
        con = sqlite3.connect(str(self.db))
        try:
            return con.execute(
                "SELECT version FROM schema_meta WHERE singleton=1"
            ).fetchone()[0]
        finally:
            con.close()

    def tables(self) -> set[str]:
        con = sqlite3.connect(str(self.db))
        try:
            return {row[0] for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            con.close()

    def test_upgrade_to_the_current_schema_is_a_no_op(self):
        result = self.run_tool("--to", str(SCHEMA_VERSION))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version(), SCHEMA_VERSION)

    def test_downgrade_requires_confirmation(self):
        result = self.run_tool("--to", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--yes", result.stderr)
        self.assertEqual(self.version(), SCHEMA_VERSION)

    def test_downgrade_then_upgrade_round_trips(self):
        result = self.run_tool("--to", "1", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version(), 1)
        self.assertNotIn("authorization_v2", self.tables())
        self.assertNotIn("authority_state", self.tables())
        self.assertIn("guidance_outcome", self.tables())
        result = self.run_tool("--to", str(SCHEMA_VERSION))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version(), SCHEMA_VERSION)
        self.assertIn("authorization_v2", self.tables())
        self.assertIn("authority_state", self.tables())

    def test_a_target_newer_than_the_build_is_refused(self):
        result = self.run_tool("--to", "99")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("newer than this build", result.stderr)


class RecoveryDrillTests(unittest.TestCase):
    """The drills an operator runs before trusting the deployment."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed, _ = signatures.generate_keypair()
        self.signer = SigningKey(self.seed, "auth-key-1")
        self.ledger_seed, _ = signatures.generate_keypair()
        self.ledger_signer = SigningKey(self.ledger_seed, "ledger-key-1")

    def test_kill_switch_survives_a_restart(self):
        path = self.root / "plane.db"
        plane = SqliteControlPlane(path, signing_key=self.signer)
        plane.set_global_disable(True, reason="drill")
        plane.close()
        reopened = SqliteControlPlane(path, signing_key=self.signer)
        self.addCleanup(reopened.close)
        self.assertTrue(reopened.authority_state()["global_disable"])

    def test_ledger_epoch_survives_a_restart(self):
        path = self.root / "plane.db"
        plane = SqliteControlPlane(path, signing_key=self.signer)
        ledger = AuthorityLedger(plane, signing_key=self.ledger_signer)
        ledger.set_candidate_status("cand-1", "qualified")
        epoch = ledger.state()["epoch"]
        plane.close()
        reopened = SqliteControlPlane(path, signing_key=self.signer)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.authority_state()["epoch"], epoch)
        self.assertEqual(
            reopened.authority_subject("candidate", "cand-1")["status"],
            "qualified")

    def test_an_interrupted_commit_leaves_no_partial_authorization(self):
        path = self.root / "plane.db"
        plane = SqliteControlPlane(path, signing_key=self.signer)
        plane.close()
        # Simulate a torn write: the nonce row exists, the authorization
        # row does not.
        con = sqlite3.connect(str(path))
        con.execute(
            "INSERT INTO session_nonce (nonce, session_digest, expires_at,"
            " reserved_at, authorization_id) VALUES (?,?,?,?,?)",
            ("torn-nonce", "b" * 64, "2030-01-01T00:00:00Z",
             "2026-01-01T00:00:00Z", "auth-torn"))
        con.commit()
        con.close()
        reopened = SqliteControlPlane(path, signing_key=self.signer)
        self.addCleanup(reopened.close)
        self.assertIsNone(reopened.bound_authorization("auth-torn"))
        # The orphaned nonce still blocks a replay, which is the safe
        # direction: it refuses rather than authorizing twice.
        with self.assertRaises(Exception):
            reopened.commit_bound_authorization(
                attempt_id="att-torn", nonce="torn-nonce",
                session_digest="b" * 64,
                execution_identity_digest="b" * 64,
                requester_principal_id="agent-1", task_id="task-1",
                repository_id="repo-1", repository_tree_digest="a" * 64,
                base_commit_digest="abc1234", guidance_digest="c" * 64,
                decision="advisory", expires_at="2030-01-01T00:00:00Z")

    def test_a_backup_is_taken_before_a_destructive_migration(self):
        path = self.root / "plane.db"
        SqliteControlPlane(path).close()
        result = subprocess.run(
            [sys.executable,
             str(ROOT / "tools" / "migrate_control_plane.py"),
             "--db", str(path), "--to", "1", "--yes"],
            capture_output=True, text=True, cwd=str(ROOT),
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 0, result.stderr)
        backups = [path for path in self.root.glob("plane.db.bak-*")
                   if not path.name.endswith(("-shm", "-wal"))]
        self.assertEqual(len(backups), 1)
        con = sqlite3.connect(str(backups[0]))
        try:
            self.assertEqual(
                con.execute("SELECT version FROM schema_meta"
                            " WHERE singleton=1").fetchone()[0],
                SCHEMA_VERSION)
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
