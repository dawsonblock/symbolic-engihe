"""CandidateRegistry: typed candidates, role-gated transitions, audit."""
import tempfile
import unittest
from pathlib import Path

from sis.v3.candidates import (CandidateConflict, CandidateError,
                               CandidateRegistry, content_digest)
from sis.v3.contracts import CandidateV1, ContractError
from sis.v3.policy import AuthorizationDenied

NOW = "2026-10-24T12:00:00Z"


def make_candidate(cid="cand-1", ctype="skill_instruction",
                   payload=None, scope=None, episodes=("ep-1",)):
    payload = payload if payload is not None else {
        "title": "t", "steps": ["do the thing"]}
    return CandidateV1(
        schema_version=1,
        candidate_id=cid,
        candidate_type=ctype,
        content_digest=content_digest(ctype, payload),
        parent_candidate_ids=(),
        source_episode_ids=episodes,
        generator_identity="test-generator",
        target_agent="any",
        target_task_family="fam",
        repository_scope=scope or {"kind": "family_id", "value": "fam-a"},
        applicability_predicate=({"kind": "language_is", "value": "python"},),
        known_counterexamples=(),
        payload=payload,
        created_at=NOW)


class RegistryFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.reg = CandidateRegistry(Path(self.temp.name) / "c.db")
        self.addCleanup(self.reg.close)


class CandidateContractTests(unittest.TestCase):
    def test_all_types_accepted(self):
        for i, t in enumerate(("symbolic_procedure", "diagnostic_strategy",
                               "experience_memory", "skill_instruction",
                               "skill_bundle", "prompt_variant")):
            payload = {"steps": ["s"], "lesson": "l"}
            make_candidate(cid=f"c-{i}", ctype=t, payload=payload)
        with self.assertRaises(ContractError):
            make_candidate(ctype="bogus_type")

    def test_content_digest_must_bind_payload(self):
        cand = make_candidate()
        forged = dict(cand.to_dict())
        forged["payload"] = {"steps": ["evil"]}
        with self.assertRaisesRegex(ContractError, "content_digest"):
            CandidateV1.from_dict(forged)

    def test_scope_shape_enforced(self):
        with self.assertRaises(ContractError):
            make_candidate(scope={"kind": "everywhere", "value": "x"})
        with self.assertRaises(ContractError):
            make_candidate(scope={"kind": "global", "value": "x"})
        make_candidate(scope={"kind": "global", "value": ""})


class RegistryLifecycleTests(RegistryFixture):
    def test_full_lifecycle_with_audit(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.assertEqual(self.reg.state_of(cand.candidate_id), "proposed")
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        self.reg.transition(cand.candidate_id, "evaluating",
                            actor_role="evaluator")
        self.reg.qualify(cand.candidate_id, actor_role="operator",
                         actor_identity="op-1",
                         receipt_refs=("a" * 64,))
        self.assertEqual(self.reg.state_of(cand.candidate_id), "qualified")
        self.reg.revoke(cand.candidate_id, actor_role="operator")
        self.assertEqual(self.reg.state_of(cand.candidate_id), "revoked")
        states = [(e["from_state"], e["to_state"])
                  for e in self.reg.audit(cand.candidate_id)]
        self.assertEqual(
            states, [("", "proposed"), ("proposed", "validated"),
                     ("validated", "evaluating"),
                     ("evaluating", "qualified"),
                     ("qualified", "revoked")])

    def test_submit_is_idempotent_and_conflicts(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.assertEqual(self.reg.submit(cand, actor_role="learner"),
                         cand.digest)
        other = make_candidate(payload={"steps": ["different"]})
        with self.assertRaises(CandidateConflict):
            self.reg.submit(other, actor_role="learner")

    def test_unauthorized_roles_denied(self):
        cand = make_candidate()
        for role in ("agent", "evaluator", "operator", "forged"):
            with self.assertRaises(AuthorizationDenied):
                self.reg.submit(cand, actor_role=role)
        self.reg.submit(cand, actor_role="learner")
        # proposed->validated is intake (candidate:write): learner only
        for role in ("agent", "runner", "evaluator", "operator"):
            with self.assertRaisesRegex(CandidateConflict, "role_denied"):
                self.reg.transition(cand.candidate_id, "validated",
                                    actor_role=role)
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        # validated->evaluating is evaluator-only: learner cannot self-escalate
        for role in ("agent", "runner", "learner", "operator"):
            with self.assertRaisesRegex(CandidateConflict, "role_denied"):
                self.reg.transition(cand.candidate_id, "evaluating",
                                    actor_role=role)

    def test_qualify_requires_operator_and_receipts(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        self.reg.transition(cand.candidate_id, "evaluating",
                            actor_role="evaluator")
        # learner cannot qualify itself — generation never confers authority
        with self.assertRaisesRegex(CandidateConflict, "role_denied"):
            self.reg.qualify(cand.candidate_id, actor_role="learner",
                             receipt_refs=("a" * 64,))
        # no receipts — no qualification
        with self.assertRaisesRegex(CandidateConflict, "receipts"):
            self.reg.qualify(cand.candidate_id, actor_role="operator",
                             receipt_refs=())
        # malformed receipt ref
        with self.assertRaises(ContractError):
            self.reg.qualify(cand.candidate_id, actor_role="operator",
                             receipt_refs=("nothex",))
        self.reg.qualify(cand.candidate_id, actor_role="operator",
                         receipt_refs=("a" * 64, "b" * 64))
        audit = self.reg.audit(cand.candidate_id)
        self.assertEqual(audit[-1]["receipt_refs"], ["a" * 64, "b" * 64])

    def test_illegal_transitions_rejected(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        for target in ("evaluating", "qualified", "revoked"):
            with self.assertRaisesRegex(CandidateConflict,
                                        "illegal_transition"):
                self.reg.transition(cand.candidate_id, target,
                                    actor_role="operator",
                                    receipt_refs=("a" * 64,))
        self.reg.transition(cand.candidate_id, "rejected",
                            actor_role="evaluator")
        with self.assertRaisesRegex(CandidateConflict,
                                    "illegal_transition"):
            self.reg.transition(cand.candidate_id, "validated",
                                actor_role="learner")

    def test_tampered_row_fails_closed(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        # corrupt the stored JSON without touching the digest column
        self.reg._conn().execute(
            "UPDATE candidate SET candidate_json=? WHERE candidate_id=?",
            ('{"schema_version":1,"candidate_id":"cand-1"}',
             cand.candidate_id))
        self.reg._conn().commit()
        with self.assertRaises((CandidateError, ContractError)):
            self.reg.get(cand.candidate_id)

    def test_persistence_across_restart(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.close()
        reg2 = CandidateRegistry(Path(self.temp.name) / "c.db")
        self.assertEqual(reg2.state_of(cand.candidate_id), "proposed")
        reg2.close()

    def test_audit_chain_detects_row_tamper(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        audit = self.reg.audit()
        self.assertEqual(len(audit), 2)
        self.assertTrue(all(len(e["entry_digest"]) == 64
                            for e in audit))
        # rewrite history: change the recorded actor of a transition
        self.reg._conn().execute(
            "UPDATE candidate_transition SET actor_identity='mallory'"
            " WHERE seq=2")
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError,
                                    "audit_chain_tampered"):
            self.reg.audit()
        # filtered reads must not bypass verification either
        with self.assertRaisesRegex(CandidateError,
                                    "audit_chain_tampered"):
            self.reg.audit(cand.candidate_id)

    def test_audit_chain_detects_deleted_row(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        self.reg._conn().execute(
            "DELETE FROM candidate_transition WHERE seq=1")
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError,
                                    "audit_chain_tampered"):
            self.reg.audit()

    def test_legacy_audit_rows_backfilled_on_open(self):
        # A pre-chain database is sealed in place at open: entries gain
        # digests, and reads then verify the chain normally.
        import sqlite3
        path = Path(self.temp.name) / "legacy.db"
        con = sqlite3.connect(str(path))
        con.executescript("""
            CREATE TABLE candidate (
                candidate_id TEXT PRIMARY KEY,
                candidate_digest TEXT NOT NULL UNIQUE,
                candidate_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE candidate_transition (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                actor_identity TEXT NOT NULL,
                receipt_refs_json TEXT NOT NULL,
                note TEXT NOT NULL,
                committed_at TEXT NOT NULL);""")
        con.execute(
            "INSERT INTO candidate_transition"
            " (candidate_id, from_state, to_state, actor_identity,"
            "  receipt_refs_json, note, committed_at)"
            " VALUES ('c-1', '', 'proposed', 'learner', '[]',"
            "         'submitted', '2026-10-24T00:00:00Z')")
        con.commit()
        con.close()
        reg = CandidateRegistry(path)
        self.addCleanup(reg.close)
        audit = reg.audit()  # verifies the backfilled chain
        self.assertEqual(len(audit), 1)
        self.assertEqual(len(audit[0]["entry_digest"]), 64)


if __name__ == "__main__":
    unittest.main()
