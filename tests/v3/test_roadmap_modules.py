"""SIS3-122/131/141/150/161/170: projection, V2 envelopes, semantic gates,
counterexample index, scoped catalog, guidance phases, benchmark stats."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.benchmark import mcnemar_p, wilson_ci
from sis.v3.catalog import Catalog, CatalogError
from sis.v3.contracts import (
    ContractError, ObservationEventV1, OutcomeEnvelopeV2, canonical_digest,
)
from sis.v3.counterexamples import CounterexampleIndex
from sis.v3.episode_projection import agent_view, project_episode
from sis.v3.episode_store import EpisodeStore
from sis.v3.guidance_gateway import GuidanceGateway
from sis.v3.outcome_v2 import (
    EnvelopeRejected, TrustedKey, TrustedKeyRegistry, issue_envelope,
    verify_envelope,
)
from sis.v3.policy import AuthorizationDenied
from sis.v3.procedures import ProcedureStore
from sis.v3.promotion import (
    PromotionController, PromotionRejected, operator_token_digest)
from sis.v3.retrieval import AblationFlags, retrieve
from sis.v3.semantic_checks import (
    OpClass, metamorphic_violations, op_class, operator_changes,
    requires_semantic_contract,
)
from sis.v3.verifier import EvaluatorKeyStore

from tests.v3.test_episode_replay import make_event
from tests.v3.test_retrieval import _authority, _proc, _request

D = "0" * 64
TOKEN = "operator-token-0123456789"


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EpisodeStore(Path(self.temp.name) / "evidence")

    def _chain(self, events):
        prior = None
        for spec in events:
            ev = make_event("ep-1", spec.get("seq", 0), prior,
                            payload=spec.get("payload"), key=spec.get("key"),
                            event_id=spec.get("event_id"))
            self.store.append_event(ev)
            prior = ev.digest

    def test_deterministic_projection(self):
        self._chain([
            {"seq": 0, "payload": {"note": "start"}},
            {"seq": 1, "payload": {"note": "tool",
                                   "summary": {"item_type": "command_execution",
                                               "exit_code": 0}}},
            {"seq": 2, "payload": {"note": "fail",
                                   "summary": {"item_type": "command_execution",
                                               "exit_code": 1}}},
        ])
        first = project_episode(self.store, "ep-1")
        second = project_episode(self.store, "ep-1")
        self.assertEqual(first, second)
        self.assertEqual(first.event_count, 3)
        self.assertTrue(first.chain_ok)
        self.assertIn("command_execution:exit_1", first.failure_signatures)
        self.assertEqual(len(first.attempts), 1)
        self.assertEqual(first.attempts[0].event_count, 3)

    def test_agent_view_redacts_payloads_and_artifacts(self):
        self._chain([{"seq": 0, "payload": {"note": "secret-detail"}}])
        view = agent_view(project_episode(self.store, "ep-1"))
        self.assertNotIn("secret-detail", repr(view))
        self.assertIn("redaction", view)
        self.assertEqual(view["event_count"], 1)


class EnvelopeV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.keystore = EvaluatorKeyStore(Path(self.temp.name) / "keys")
        _, self.public = self.keystore.load_or_create()
        self.registry = TrustedKeyRegistry({
            self.keystore.key_id: TrustedKey(public_key=self.public.hex()),
        })
        self.kw = dict(
            keystore=self.keystore, task_id="t1", attempt_id="att-1",
            evaluated_repo_digest=D, environment_digest="1" * 64,
            test_suite_commitment="2" * 64, execution_receipt_digest="3" * 64,
            criterion_version="v1", outcome="pass",
        )

    def test_signed_envelope_verifies(self):
        env = issue_envelope(**self.kw)
        self.assertIsInstance(env, OutcomeEnvelopeV2)
        self.assertTrue(verify_envelope(env, self.registry))

    def test_forgery_and_tampering_rejected(self):
        env = issue_envelope(**self.kw)
        forged = dict(env.to_dict())
        forged["outcome"] = "fail"
        self.assertFalse(verify_envelope(forged, self.registry))
        bad_seed, _ = signatures.generate_keypair()
        forged2 = dict(env.to_dict())
        forged2["signature"] = signatures.sign(
            bad_seed, b"sis-v3:outcome_envelope:1\0" + b"{}").hex()
        self.assertFalse(verify_envelope(forged2, self.registry))

    def test_unknown_revoked_and_wrong_purpose_keys_rejected(self):
        env = issue_envelope(**self.kw)
        self.assertFalse(verify_envelope(env, TrustedKeyRegistry()))
        self.assertFalse(verify_envelope(
            env, self.registry, revoked_keys={env.signer_key_id}))
        wrong = TrustedKeyRegistry({
            self.keystore.key_id: TrustedKey(
                public_key=self.public.hex(), purpose="anchor_signing"),
        })
        self.assertFalse(verify_envelope(env, wrong))

    def test_nonce_replay_and_expiry_enforced(self):
        env = issue_envelope(**self.kw)
        self.assertFalse(verify_envelope(
            env, self.registry, seen_nonces={env.nonce}))
        expired = issue_envelope(**self.kw, expires_at="2020-01-01T00:00:00Z")
        self.assertFalse(verify_envelope(expired, self.registry))
        future = issue_envelope(**self.kw, expires_at="2999-01-01T00:00:00Z")
        self.assertTrue(verify_envelope(future, self.registry))

    def test_key_validity_window_enforced(self):
        windowed = TrustedKeyRegistry({
            self.keystore.key_id: TrustedKey(
                public_key=self.public.hex(),
                valid_from="2999-01-01T00:00:00Z"),
        })
        env = issue_envelope(**self.kw)
        self.assertFalse(verify_envelope(env, windowed))

    def test_bad_at_time_raises_contract_not_crash(self):
        env = issue_envelope(**self.kw)
        with self.assertRaises(ContractError):
            verify_envelope(env, self.registry, at_time="not-a-date")
        # Naive timestamps normalize to UTC rather than TypeError-crashing.
        self.assertTrue(verify_envelope(
            env, self.registry, at_time="2030-01-01T00:00:00"))

    def test_registry_conflict_rejected(self):
        other_seed, other_pub = signatures.generate_keypair()
        reg = TrustedKeyRegistry({"k": TrustedKey(public_key=other_pub.hex())})
        with self.assertRaises(EnvelopeRejected):
            reg.add("k", TrustedKey(public_key=self.public.hex()))


class SemanticCheckTests(unittest.TestCase):
    def test_sub_to_add_is_flagged(self):
        changes = operator_changes(
            "def f(a, b):\n    return a - b\n",
            "def f(a, b):\n    return a + b\n",
        )
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].old_class, OpClass.NONCOMMUTATIVE)
        self.assertEqual(changes[0].new_class, OpClass.COMMUTATIVE)
        self.assertTrue(metamorphic_violations(changes))

    def test_same_class_swap_is_flagged_not_proven(self):
        # v3.1.x defect: a+b -> a*b slipped through as "same-class".
        # Every operator substitution is a flag; only an executable
        # contract can discharge it — class is never proof.
        changes = operator_changes(
            "def f(a, b):\n    return a + b\n",
            "def f(a, b):\n    return a * b\n",
        )
        self.assertEqual(len(changes), 1)
        self.assertTrue(metamorphic_violations(changes))

    def test_operand_reorder_is_flagged(self):
        changes = operator_changes(
            "def f(a, b):\n    return a - b\n",
            "def f(a, b):\n    return b - a\n",
        )
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, "operand_reorder")
        self.assertTrue(metamorphic_violations(changes))

    def test_structural_change_and_syntax_errors(self):
        changes = operator_changes("x = a - b\n", "x = a - b\ny = a + b\n")
        self.assertEqual(changes[0].old_class, OpClass.OTHER)
        with self.assertRaises(ValueError):
            operator_changes("def :\n", "x = 1\n")

    def test_semantic_contract_required_for_patch_effect(self):
        self.assertTrue(requires_semantic_contract(False, None))
        self.assertTrue(requires_semantic_contract(True, D))
        self.assertFalse(requires_semantic_contract(True, None))


class CounterexampleIndexTests(unittest.TestCase):
    def test_index_reports_counterexamples_and_contraindications(self):
        record = _proc(
            contra=({"kind": "language_is", "value": "python"},),
            cex=("a" * 64,),
        )
        index = CounterexampleIndex(_authority(record).store)
        ctx = __import__("sis.v3.retrieval", fromlist=["RetrievalContext"]).RetrievalContext(
            language="python", toolchain="t", dependency_digests={},
            files_present=frozenset(), symbols_present=frozenset(),
            failure_signatures=frozenset({"sig-x"}),
        )
        negatives = index.negatives_for(ctx)
        kinds = {n.kind for n in negatives}
        self.assertIn("counterexample_receipt", kinds)
        self.assertIn("contraindication", kinds)
        self.assertTrue(index.blocked(ctx))
        ctx2 = ctx.__class__(language="rust", toolchain="t", dependency_digests={},
                             files_present=frozenset(), symbols_present=frozenset(),
                             failure_signatures=frozenset())
        self.assertFalse(index.blocked(ctx2))


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth = _authority()
        self.store = self.auth.store
        self.catalog = Catalog(self.store, self.auth.controller.eligibility_snapshot)

    def _grant(self, pid, scope, receipts=(), family_id=None):
        return self.auth.controller.grant_scope(
            pid, scope, actor_role="operator", actor_identity="op-1",
            operator_token=self.auth.token,
            evidence_receipt_digests=tuple(r.digest for r in receipts),
            evaluator_signer=self.auth._eval_signer,
            family_id=family_id)

    def test_scope_roundtrip_and_filtering(self):
        self.auth.qualify(_proc(pid="p1", status="candidate"))
        self.auth.qualify(_proc(pid="p2", status="candidate"))
        r1 = self.auth.issue_receipt(repo_id="repo-1", family_id="fam-1")
        r2 = self.auth.issue_receipt(repo_id="repo-2")
        self._grant("p1", "family", receipts=(r1,), family_id="fam-1")
        self._grant("p2", "cross_repository", receipts=(r1, r2))
        self.assertEqual(self.catalog.scope_of("p1"), "family")
        self.assertEqual(self.catalog.scope_of("p2"), "cross_repository")
        self.assertEqual(
            {r.procedure_id for r in self.catalog.procedures(scope="family")},
            {"p1"})
        fresh = Catalog(self.store, self.auth.controller.eligibility_snapshot)
        self.assertEqual(fresh.scope_of("p1"), "family")

    def test_cross_repo_needs_distinct_repo_identities(self):
        # Two receipts on the SAME repository identity is not transfer.
        self.auth.qualify(_proc(pid="p1", status="candidate"))
        r1 = self.auth.issue_receipt(repo_id="repo-1")
        r2 = self.auth.issue_receipt(repo_id="repo-1")
        with self.assertRaisesRegex(PromotionRejected,
                                    "insufficient_transfer_evidence"):
            self._grant("p1", "cross_repository", receipts=(r1, r2))
        r3 = self.auth.issue_receipt(repo_id="repo-2")
        self._grant("p1", "cross_repository", receipts=(r1, r3))
        self.assertEqual(self.catalog.scope_of("p1"), "cross_repository")

    def test_scope_requires_operator_and_valid_scope(self):
        self.auth.qualify(_proc(pid="p1", status="candidate"))
        r1 = self.auth.issue_receipt(repo_id="repo-1", family_id="fam-1")
        with self.assertRaises(AuthorizationDenied):
            self.auth.controller.grant_scope(
                "p1", "family", actor_role="agent", actor_identity="x",
                operator_token=self.auth.token,
                evaluator_signer=self.auth._eval_signer,
                evidence_receipt_digests=(r1.digest,), family_id="fam-1")
        with self.assertRaises(ContractError):
            self._grant("p1", "universe", receipts=(r1,))
        with self.assertRaises(Exception):
            self._grant("missing", "family", receipts=(r1,),
                        family_id="fam-1")
        # Unqualified procedures cannot be granted scope.
        self.auth.store.add(_proc(pid="p3", status="candidate"))
        with self.assertRaisesRegex(PromotionRejected,
                                    "scope_requires_qualified"):
            self._grant("p3", "repository", receipts=(r1,))

    def test_corrupt_scope_metadata_fails_closed(self):
        from sis.v3.promotion import (
    PromotionController, PromotionRejected, operator_token_digest)
        scopes_log = self.auth.root / "decisions" / "scopes.jsonl"
        scopes_log.write_bytes(b"not-json\n")
        with self.assertRaisesRegex(PromotionRejected, "scope_log_corrupt"):
            PromotionController(
                self.store, self.auth.root / "decisions",
                operator_token_digest=operator_token_digest(self.auth.token),
                trusted_evaluator_keys={
                    self.auth.eval_key_id: self.auth.eval_public.hex()})

    def test_cascade_suspend_invalidates_dependents(self):
        from dataclasses import replace
        receipt = "b" * 64
        self.auth.qualify(replace(_proc(pid="p1", status="candidate"),
                                  evidence_refs=(receipt,)))
        self.auth.qualify(_proc(pid="p2", status="candidate"))
        controller = self.auth.controller
        suspended = self.catalog.cascade_suspend(
            receipt,
            lambda pid: controller.transition(
                pid, "suspended", actor_role="operator",
                actor_identity="op-1", operator_token=self.auth.token).decision_id,
        )
        self.assertEqual(len(suspended), 1)
        self.assertTrue(all(d.startswith("dec-") for d in suspended))
        self.assertEqual(self.store.get("p1").status, "suspended")
        self.assertEqual(self.store.get("p2").status, "qualified")
        self.assertEqual(len(self.auth.controller.eligibility_snapshot().qualified), 1)
        self.assertEqual(
            self.auth.controller.eligibility_snapshot().qualified[0].procedure_id, "p2")

    def test_scoped_qualified_head_differs_from_global(self):
        self.auth.qualify(_proc(pid="p1", status="candidate"))
        r1 = self.auth.issue_receipt(repo_id="repo-1", family_id="fam-1")
        self._grant("p1", "family", receipts=(r1,), family_id="fam-1")
        self.assertNotEqual(
            self.catalog.qualified_head("family"),
            self.catalog.qualified_head("cross_repository"))


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth = _authority(_proc(pid="p1"), root=self.root / "auth")
        self.request = _request()

    def test_shadow_abstains_but_logs_would_recommend(self):
        gw = GuidanceGateway(
            self.auth.snapshot, phase="shadow", log_dir=self.root / "logs")
        result = gw.recommend(self.request)
        self.assertEqual(result.decision, "abstain")
        self.assertEqual(result.reason_code, "catalog_unavailable")
        log = gw.shadow_log()
        self.assertEqual(log[-1]["evaluated_decision"], "recommend")
        self.assertEqual(log[-1]["would_recommend"], ["p1"])

    def test_diagnostic_abstains_with_reason_but_no_procedures(self):
        gw = GuidanceGateway(
            self.auth.snapshot, phase="diagnostic", log_dir=self.root / "logs")
        result = gw.recommend(self.request)
        self.assertEqual(result.decision, "abstain")
        self.assertEqual(result.procedure_ids, ())
        self.assertEqual(result.reason_code, "insufficient_support")

    def test_conditional_serves_recommendation(self):
        gw = GuidanceGateway(self.auth.snapshot, phase="conditional")
        result = gw.recommend(self.request)
        self.assertEqual(result.decision, "recommend")
        self.assertEqual(result.procedure_ids, ("p1",))

    def test_kill_switch_file_and_env(self):
        kill = self.root / "KILL"
        gw = GuidanceGateway(
            self.auth.snapshot, phase="conditional", kill_switch_path=kill)
        self.assertEqual(gw.recommend(self.request).decision, "recommend")
        kill.touch()
        result = gw.recommend(self.request)
        self.assertEqual(result.reason_code, "catalog_unavailable")
        kill.unlink()
        import os
        os.environ["SIS3_DISABLE"] = "1"
        try:
            self.assertEqual(
                gw.recommend(self.request).reason_code, "catalog_unavailable")
        finally:
            del os.environ["SIS3_DISABLE"]

    def test_record_outcome_validation_and_log(self):
        gw = GuidanceGateway(
            self.auth.snapshot, phase="conditional", log_dir=self.root / "logs")
        result = gw.recommend(self.request)
        gw.record_outcome(result.digest, True)
        gw.record_outcome(result.digest, None)
        with self.assertRaises(ContractError):
            gw.record_outcome("not-a-digest", True)
        with self.assertRaises(ContractError):
            gw.record_outcome(result.digest, "yes")
        entries = gw.shadow_log()
        self.assertEqual(entries[-2]["accepted"], True)
        self.assertEqual(entries[-1]["accepted"], None)

    def test_unknown_phase_rejected(self):
        with self.assertRaises(ContractError):
            GuidanceGateway(self.auth.snapshot, phase="full-auto")


class AblationTests(unittest.TestCase):
    def test_skip_contraindications_surfaces_blocked_procedure(self):
        record = _proc(contra=({"kind": "language_is", "value": "python"},))
        snapshot = _authority(record).snapshot()
        result = retrieve(_request(), snapshot)
        self.assertEqual(result.candidates, ())
        ablated = retrieve(
            _request(), snapshot,
            ablations=AblationFlags(skip_contraindications=True))
        self.assertEqual(len(ablated.candidates), 1)

    def test_skip_preconditions_and_include_unqualified(self):
        record = _proc(
            pre=({"kind": "language_is", "value": "rust"},),
            status="draft",
        )
        snapshot = _authority(record).snapshot()
        self.assertEqual(retrieve(_request(), snapshot).candidates, ())
        ablated = retrieve(
            _request(), snapshot,
            ablations=AblationFlags(
                skip_preconditions=True, include_unqualified=True))
        self.assertEqual(len(ablated.candidates), 1)
        with self.assertRaises(ContractError):
            retrieve(_request(), snapshot, ablations="yes")


class BenchmarkStatsTests(unittest.TestCase):
    def test_wilson_interval_contains_rate_and_shrinks(self):
        lo, hi = wilson_ci(5, 10)
        self.assertLessEqual(lo, 0.5)
        self.assertGreaterEqual(hi, 0.5)
        lo2, hi2 = wilson_ci(50, 100)
        self.assertGreater(lo2, lo)
        self.assertLess(hi2, hi)
        self.assertEqual(wilson_ci(0, 10)[0], 0.0)
        self.assertEqual(wilson_ci(10, 10)[1], 1.0)
        with self.assertRaises(ContractError):
            wilson_ci(11, 10)
        with self.assertRaises(ContractError):
            wilson_ci(0, 0)

    def test_mcnemar_exact(self):
        self.assertEqual(mcnemar_p(0, 0), 1.0)
        self.assertEqual(mcnemar_p(5, 5), 1.0)
        self.assertLess(mcnemar_p(9, 0), 0.01)
        self.assertGreater(mcnemar_p(6, 4), 0.5)
        with self.assertRaises(ContractError):
            mcnemar_p(-1, 0)


if __name__ == "__main__":
    unittest.main()
