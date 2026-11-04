"""PR-04: the P0 acceptance matrix for outcome attribution.

These began as the PR-01 reproduction (marked ``xfail(strict=True)``
against v3.3.2). They now assert the required behavior directly: every
attack in the plan's acceptance table is rejected with a stable reason,
and the one legitimate submission is accepted.

Reproduce outside pytest with ``tools/reproduce_v340_defects.py``.
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3.control_plane import ControlPlaneError
from sis.v3.contracts import EvaluatorReceiptV2
from sis.v3.serving import GovernedServingGateway
from sis.v3.serving_service import V3ServingService
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture

TOKEN_A = "v340-token-agent-a-0000000000001"
TOKEN_B = "v340-token-agent-b-0000000000002"


class _Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = ProductionFixture(Path(self.temp.name) / "stack")
        self.addCleanup(self.fixture.close)
        self.service = V3ServingService(
            self.gateway(),
            api_keys={TOKEN_A: "agent-1", TOKEN_B: "agent-2"})

    def gateway(self, **kwargs):
        kwargs.setdefault("production", True)
        kwargs.setdefault("execution_identity_authority",
                          self.fixture.identity_authority)
        kwargs.setdefault("control_plane", self.fixture.control_plane)
        kwargs.setdefault("binding_authority",
                          self.fixture.binding_authority)
        for key, value in self.fixture.production_kwargs().items():
            kwargs.setdefault(key, value)
        kwargs.setdefault("receipt_authority",
                          self.fixture.cert.stack.resolve_receipt)
        return GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            **kwargs)

    def serve(self, identity=None, token=TOKEN_A):
        code, body = self.service.handle(
            "/v3/guidance",
            {
                "request": _request().to_dict(),
                "repository_id": "repo-1",
                "execution_identity":
                    (identity or self.fixture.identity()).to_dict(),
            },
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(code, 200, body)
        return body

    def submit(self, authorization, receipt, *, token=TOKEN_A,
               served_digest=None, independence=None,
               dependency=None):
        payload = {
            "authorization_id": authorization.authorization_id,
            "task_id": authorization.task_id,
            "served_digest": served_digest or authorization.guidance_digest,
            "evaluator_receipt": receipt.to_dict(),
        }
        if independence is not None:
            payload["independence"] = independence
        if dependency is not None:
            payload["dependency_receipt_digest"] = dependency
        return self.service.handle(
            "/v3/outcome", payload, {"Authorization": f"Bearer {token}"})


class AcceptanceTests(_Base):
    def test_authorized_evaluator_submits_correctly_bound_outcome(self):
        served = self.serve()
        authorization = self.fixture.bound_authorization()
        self.assertEqual(authorization.guidance_digest,
                         served["guidance_digest"])
        receipt = self.fixture.bound_receipt(authorization)
        code, body = self.submit(authorization, receipt)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["evidence_class"], "verified")
        self.assertEqual(body["attempt_id"], authorization.attempt_id)
        stored = self.fixture.control_plane.bound_outcome(
            authorization.authorization_id)
        self.assertEqual(stored["result"], "pass")
        self.assertEqual(stored["independence"], "independent")

    def test_agent_b_cannot_submit_agent_a_outcome(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        code, body = self.submit(authorization, receipt, token=TOKEN_B)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "outcome_requester_mismatch")

    def test_receipt_from_another_repository_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        foreign = self.fixture.bound_receipt(authorization,
                                             repository_id="repo-9")
        code, body = self.submit(authorization, foreign)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "receipt_repository_mismatch")

    def test_receipt_for_another_tree_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        foreign = self.fixture.bound_receipt(
            authorization, repository_tree_digest="9" * 64)
        code, body = self.submit(authorization, foreign)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "receipt_tree_mismatch")

    def test_receipt_for_another_attempt_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        foreign = self.fixture.bound_receipt(authorization,
                                             attempt_id="att-other")
        code, body = self.submit(authorization, foreign)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "receipt_attempt_mismatch")

    def test_receipt_reused_for_another_attempt_is_rejected(self):
        self.serve(self.fixture.identity(session_nonce="nonce-reuse-a"))
        first = self.fixture.bound_authorization("nonce-reuse-a")
        self.serve(self.fixture.identity(session_nonce="nonce-reuse-b"))
        second = self.fixture.bound_authorization("nonce-reuse-b")
        receipt = self.fixture.bound_receipt(first)
        code, _ = self.submit(first, receipt)
        self.assertEqual(code, 200)
        code, body = self.submit(second, receipt)
        self.assertEqual(code, 400)
        self.assertIn(body["error"],
                      {"receipt_authorization_mismatch",
                       "receipt_authorization_already_measured"})
        self.assertEqual(
            len(self.fixture.control_plane.independent_outcomes()), 1)

    def test_modified_guidance_digest_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        code, body = self.submit(authorization, receipt,
                                 served_digest="f" * 64)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "served_guidance_unknown")

    def test_modified_result_after_signature_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        tampered = EvaluatorReceiptV2.from_dict(
            {**receipt.to_dict(), "result": "fail"})
        code, body = self.submit(authorization, tampered)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "receipt_signature_invalid")

    def test_receipt_from_an_untrusted_signer_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization,
                                             signer_key_id="not-trusted")
        code, body = self.submit(authorization, receipt)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "receipt_untrusted_signer")

    def test_expired_authorization_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        expiry = datetime.fromisoformat(
            authorization.expires_at.replace("Z", "+00:00"))
        later = (expiry + timedelta(minutes=1)).isoformat()
        self.fixture.binding_authority._clock = lambda: \
            later.replace("+00:00", "Z")
        code, body = self.submit(authorization, receipt)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "authorization_expired")

    def test_revoked_authorization_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        self.fixture.binding_authority._revocations = lambda: (
            set(), {authorization.digest})
        code, body = self.submit(authorization, receipt)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "authorization_revoked")

    def test_missing_receipt_is_rejected(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        code, body = self.service.handle(
            "/v3/outcome",
            {"authorization_id": authorization.authorization_id,
             "task_id": authorization.task_id,
             "served_digest": authorization.guidance_digest},
            {"Authorization": f"Bearer {TOKEN_A}"})
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "evaluator_receipt_required")

    def test_implicit_authorization_is_refused(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        code, body = self.service.handle(
            "/v3/outcome",
            {"task_id": authorization.task_id,
             "served_digest": authorization.guidance_digest,
             "evaluator_receipt": receipt.to_dict()},
            {"Authorization": f"Bearer {TOKEN_A}"})
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "authorization_id_required")

    def test_production_gateway_refuses_legacy_outcome_path(self):
        # v3.5.0: a production gateway that cannot bind outcomes is now
        # refused at construction rather than serving and failing later.
        with self.assertRaisesRegex(
                ValueError, "production_requirements_missing"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                production=True,
                execution_identity_authority=self.fixture.identity_authority,
                control_plane=self.fixture.control_plane)
        unbound = GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            production=False,
            execution_identity_authority=self.fixture.identity_authority,
            control_plane=self.fixture.control_plane)
        self.assertEqual(unbound.health()["outcome_binding"], "legacy")
        # The dev path validates the served digest before the production
        # refusal; either way the legacy outcome is not recorded.
        with self.assertRaisesRegex(ValueError,
                                    "served_guidance_unknown"):
            unbound.record_outcome(
                task_id="task-1", served_digest="a" * 64,
                receipt_digest="b" * 64, outcome="pass")


class DependentEvidenceTests(_Base):
    def test_dependent_outcome_is_not_counted_as_an_independent_trial(self):
        self.serve(self.fixture.identity(session_nonce="nonce-ind"))
        first = self.fixture.bound_authorization("nonce-ind")
        first_receipt = self.fixture.bound_receipt(first)
        code, _ = self.submit(first, first_receipt)
        self.assertEqual(code, 200)

        self.serve(self.fixture.identity(session_nonce="nonce-dep"))
        second = self.fixture.bound_authorization("nonce-dep")
        cached = self.fixture.bound_receipt(
            second, independence="dependent",
            dependency_receipt_digest=first_receipt.digest)
        code, body = self.submit(second, cached)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["independence"], "dependent")

        independent = self.fixture.control_plane.independent_outcomes()
        self.assertEqual(len(independent), 1)
        self.assertEqual(independent[0]["authorization_id"],
                         first.authorization_id)

    def test_a_requester_cannot_restate_an_independent_receipt(self):
        self.serve()
        authorization = self.fixture.bound_authorization()
        receipt = self.fixture.bound_receipt(authorization)
        code, body = self.submit(authorization, receipt,
                                 independence="dependent",
                                 dependency="7" * 64)
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "independence_mismatch")


class LegacyQuarantineTests(_Base):
    def test_legacy_rows_never_appear_as_independent_evidence(self):
        legacy = self.fixture.control_plane.commit_authorization(
            nonce="legacy-nonce-1", session_digest="b" * 64,
            expires_at="2030-01-01T00:00:00Z", task_id="task-legacy",
            repository_id="repo-1", guidance_digest="c" * 64,
            decision="advisory", snapshot_digest="d" * 64)
        self.fixture.control_plane.record_outcome(
            authorization_id=legacy["authorization_id"],
            task_id="task-legacy", served_digest="c" * 64,
            receipt_digest="e" * 64, outcome="pass")
        legacy = self.fixture.control_plane.legacy_outcomes()
        self.assertEqual(len(legacy), 1)
        self.assertEqual(legacy[0]["evidence_class"], "legacy_unverified")
        self.assertEqual(self.fixture.control_plane.independent_outcomes(), [])


if __name__ == "__main__":
    unittest.main()
