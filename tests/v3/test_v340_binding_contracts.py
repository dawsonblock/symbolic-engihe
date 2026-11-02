"""PR-02: V2 evidence-chain contracts, signatures and exact matching."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from sis.v3 import signatures
from sis.v3.contracts import (
    AuthorizationV2,
    ContractError,
    EvaluatorReceiptV2,
    ExecutionAttemptV2,
    OutcomeV2,
    canonical_digest,
)
from sis.v3.evidence_binding import (
    BindingError,
    EvidenceBindingAuthority,
    attempt_id_for_identity,
    bindings_digest,
    guidance_exposure_digest,
    match_chain,
    sign_attempt,
    sign_authorization,
    sign_receipt,
    unreported_exposure_digest,
    verify_attempt,
    verify_authorization,
    verify_receipt,
)
from sis.v3.execution_identity import sign_execution_identity

TREE = "a" * 64
COMMIT = "abc1234"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(minutes: int = 0) -> str:
    return (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def identity(**overrides):
    seed = overrides.pop("_seed", b"\x11" * 32)
    fields = {
        "schema_version": 1,
        "identity_id": "id-1",
        "requester_identity": "agent-1",
        "repository_id": "repo-1",
        "repository_commit": COMMIT,
        "repository_tree_digest": TREE,
        "workspace_identity": "ws-1",
        "task_id": "task-1",
        "task_family": "fam-a",
        "harness_identity": "harness-1",
        "session_nonce": "nonce-1",
        "issued_at": _ts(0),
        "expires_at": _ts(10),
        "signer_key_id": "harness-key-1",
    }
    fields.update(overrides)
    return sign_execution_identity(seed, **fields)


class _Chain:
    """A fully signed, mutually consistent V2 chain."""

    def __init__(self, *, exposure="used", independence="independent"):
        self.eval_seed, self.eval_public = signatures.generate_keypair()
        self.harness_seed, self.harness_public = signatures.generate_keypair()
        self.auth_seed, self.auth_public = signatures.generate_keypair()
        self.identity = identity()
        self.attempt_id = attempt_id_for_identity(self.identity)
        self.authorization = sign_authorization(
            self.auth_seed,
            authorization_id="auth-1",
            requester_principal_id="agent-1",
            execution_identity_digest=self.identity.digest,
            task_id="task-1",
            attempt_id=self.attempt_id,
            repository_id="repo-1",
            repository_tree_digest=TREE,
            base_commit_digest=COMMIT,
            guidance_digest="c" * 64,
            authority_snapshot_digest="d" * 64,
            authority_epoch=3,
            decision="advisory",
            issued_at=_ts(0),
            expires_at=_ts(30),
            signer_key_id="auth-key-1",
        )
        self.attempt = sign_attempt(
            self.harness_seed,
            attempt_id=self.attempt_id,
            execution_identity_digest=self.identity.digest,
            requester_principal_id="agent-1",
            task_id="task-1",
            repository_id="repo-1",
            repository_tree_digest=TREE,
            base_commit_digest=COMMIT,
            authorization_id="auth-1",
            guidance_digest="c" * 64,
            exposure_state=exposure,
            exposure_evidence_digest="e" * 64,
            attempt_sequence=1,
            started_at=_ts(1),
            ended_at=_ts(2),
            harness_identity="harness-1",
            signer_key_id="harness-key-1",
        )
        self.exposure_digest = guidance_exposure_digest(
            authorization_id="auth-1",
            attempt_id=self.attempt_id,
            guidance_digest="c" * 64,
            exposure_state=exposure,
            harness_identity="harness-1",
            reported_at=_ts(2),
            exposure_evidence_digest="e" * 64,
            attempt_sequence=1,
        )
        self.dependency_digest = (
            "9" * 64 if independence == "dependent" else None)
        self.receipt = sign_receipt(
            self.eval_seed,
            receipt_id="rcpt-1",
            authorization_id="auth-1",
            attempt_id=self.attempt_id,
            task_id="task-1",
            requester_principal_id="agent-1",
            repository_id="repo-1",
            repository_tree_digest=TREE,
            base_commit_digest=COMMIT,
            submitted_artifact_digest="f" * 64,
            guidance_exposure_digest=self.exposure_digest,
            test_suite_commitment="1" * 64,
            environment_digest="2" * 64,
            criterion_version="v1",
            result="pass",
            independence=independence,
            dependency_receipt_digest=self.dependency_digest,
            evaluator_identity="sis-v3-test-evaluator",
            issued_at=_ts(3),
            expires_at=_ts(20),
            nonce="receipt-nonce-1",
            signer_key_id="eval-key-1",
        )
        self.independence = independence

    def match(self, **overrides):
        kwargs = dict(
            authorization=self.authorization,
            attempt=self.attempt,
            receipt=self.receipt,
            requester_principal_id="agent-1",
            now=_ts(5),
        )
        kwargs.update(overrides)
        return match_chain(**kwargs)


class ContractRoundTripTests(unittest.TestCase):
    def test_authorization_round_trips_with_a_stable_digest(self):
        chain = _Chain()
        record = chain.authorization
        restored = AuthorizationV2.from_json(record.canonical_bytes())
        self.assertEqual(restored, record)
        self.assertEqual(restored.digest, record.digest)

    def test_outcome_round_trips(self):
        record = OutcomeV2(
            schema_version=1, outcome_id="out-1", authorization_id="auth-1",
            receipt_digest="a" * 64, attempt_id="att-1", task_id="task-1",
            requester_principal_id="agent-1", repository_id="repo-1",
            guidance_digest="b" * 64, guidance_exposure_digest="c" * 64,
            result="pass", independence="independent",
            dependency_receipt_digest=None,
            authority_snapshot_digest="d" * 64, bindings_digest="e" * 64,
            recorded_at=_ts(1))
        self.assertEqual(OutcomeV2.from_json(record.canonical_bytes()), record)

    def test_dependent_outcome_must_name_a_different_receipt(self):
        with self.assertRaises(ContractError):
            OutcomeV2(
                schema_version=1, outcome_id="out-1",
                authorization_id="auth-1", receipt_digest="a" * 64,
                attempt_id="att-1", task_id="task-1",
                requester_principal_id="agent-1", repository_id="repo-1",
                guidance_digest="b" * 64, guidance_exposure_digest="c" * 64,
                result="pass", independence="dependent",
                dependency_receipt_digest=None,
                authority_snapshot_digest="d" * 64, bindings_digest="e" * 64,
                recorded_at=_ts(1))

    def test_independent_outcome_must_not_name_a_dependency(self):
        with self.assertRaises(ContractError):
            OutcomeV2(
                schema_version=1, outcome_id="out-1",
                authorization_id="auth-1", receipt_digest="a" * 64,
                attempt_id="att-1", task_id="task-1",
                requester_principal_id="agent-1", repository_id="repo-1",
                guidance_digest="b" * 64, guidance_exposure_digest="c" * 64,
                result="pass", independence="independent",
                dependency_receipt_digest="f" * 64,
                authority_snapshot_digest="d" * 64, bindings_digest="e" * 64,
                recorded_at=_ts(1))

    def test_authorization_expiry_must_follow_issue(self):
        with self.assertRaisesRegex(ContractError, "expires_at must be after"):
            sign_authorization(
                b"\x01" * 32, authorization_id="auth-1",
                requester_principal_id="agent-1",
                execution_identity_digest="a" * 64, task_id="task-1",
                attempt_id="att-1", repository_id="repo-1",
                repository_tree_digest="b" * 64, base_commit_digest=None,
                guidance_digest="c" * 64, authority_snapshot_digest="d" * 64,
                authority_epoch=1, decision="advisory", issued_at=_ts(10),
                expires_at=_ts(0), signer_key_id="k-1")

    def test_unknown_exposure_state_is_rejected(self):
        with self.assertRaises(ContractError):
            _Chain(exposure="probably")


class SignatureTests(unittest.TestCase):
    def test_all_three_records_verify(self):
        chain = _Chain()
        self.assertTrue(verify_authorization(
            chain.authorization, chain.auth_public.hex()))
        self.assertTrue(verify_attempt(
            chain.attempt, chain.harness_public.hex()))
        self.assertTrue(verify_receipt(chain.receipt, chain.eval_public.hex()))

    def test_tampering_with_any_bound_field_breaks_the_signature(self):
        chain = _Chain()
        tampered = AuthorizationV2.from_dict(
            {**chain.authorization.to_dict(), "repository_id": "repo-2"})
        self.assertFalse(verify_authorization(
            tampered, chain.auth_public.hex()))

    def test_tampering_with_the_result_breaks_the_receipt(self):
        chain = _Chain()
        tampered = EvaluatorReceiptV2.from_dict(
            {**chain.receipt.to_dict(), "result": "fail"})
        self.assertFalse(verify_receipt(tampered, chain.eval_public.hex()))

    def test_tampering_with_exposure_breaks_the_attempt(self):
        chain = _Chain()
        tampered = ExecutionAttemptV2.from_dict(
            {**chain.attempt.to_dict(),
             "exposure_state": "delivered_unread"})
        self.assertFalse(verify_attempt(tampered, chain.harness_public.hex()))

    def test_wrong_public_key_is_rejected(self):
        chain = _Chain()
        _, other = signatures.generate_keypair()
        self.assertFalse(verify_receipt(chain.receipt, other.hex()))


class AttemptIdentityTests(unittest.TestCase):
    def test_attempt_id_is_derived_from_the_signed_identity(self):
        first = attempt_id_for_identity(identity())
        self.assertEqual(first, attempt_id_for_identity(identity()))
        self.assertTrue(first.startswith("att-"))

    def test_a_different_identity_gets_a_different_attempt(self):
        seed = b"\x11" * 32
        first = attempt_id_for_identity(identity(_seed=seed))
        second = attempt_id_for_identity(
            identity(_seed=seed, session_nonce="nonce-2"))
        self.assertNotEqual(first, second)


class MatchChainTests(unittest.TestCase):
    def test_matching_chain_is_accepted(self):
        chain = _Chain()
        result = chain.match()
        self.assertEqual(result.authorization.authorization_id, "auth-1")
        self.assertEqual(result.bindings_digest,
                         bindings_digest(chain.authorization, chain.receipt))
        self.assertEqual(result.independence, "independent")

    def test_other_principal_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError,
                                    "outcome_requester_mismatch"):
            chain.match(requester_principal_id="agent-2")

    def test_other_repository_is_rejected(self):
        chain = _Chain()
        foreign = sign_receipt(
            chain.eval_seed,
            **_foreign_fields(chain, repository_id="repo-2"))
        with self.assertRaisesRegex(BindingError,
                                    "receipt_repository_mismatch"):
            chain.match(receipt=foreign)

    def test_other_tree_is_rejected(self):
        chain = _Chain()
        foreign = sign_receipt(chain.eval_seed,
                               **_foreign_fields(chain,
                                                 repository_tree_digest="9" * 64))
        with self.assertRaisesRegex(BindingError, "receipt_tree_mismatch"):
            chain.match(receipt=foreign)

    def test_other_attempt_is_rejected(self):
        chain = _Chain()
        foreign = sign_receipt(chain.eval_seed,
                               **_foreign_fields(chain, attempt_id="att-other"))
        with self.assertRaisesRegex(BindingError, "receipt_attempt_mismatch"):
            chain.match(receipt=foreign)

    def test_other_authorization_is_rejected(self):
        chain = _Chain()
        foreign = sign_receipt(chain.eval_seed,
                               **_foreign_fields(chain,
                                                 authorization_id="auth-2"))
        with self.assertRaisesRegex(BindingError,
                                    "receipt_authorization_mismatch"):
            chain.match(receipt=foreign)

    def test_other_task_is_rejected(self):
        chain = _Chain()
        foreign = sign_receipt(chain.eval_seed,
                               **_foreign_fields(chain, task_id="task-2"))
        with self.assertRaisesRegex(BindingError, "receipt_task_mismatch"):
            chain.match(receipt=foreign)

    def test_exposure_mismatch_is_rejected(self):
        chain = _Chain()
        foreign = sign_receipt(chain.eval_seed,
                               **_foreign_fields(chain,
                                                 guidance_exposure_digest="0" * 64))
        with self.assertRaisesRegex(BindingError, "receipt_exposure_mismatch"):
            chain.match(receipt=foreign)

    def test_unreported_attempt_requires_the_unreported_digest(self):
        chain = _Chain()
        expected = unreported_exposure_digest(chain.authorization)
        foreign = sign_receipt(
            chain.eval_seed,
            **_foreign_fields(chain, guidance_exposure_digest=expected))
        result = chain.match(attempt=None, receipt=foreign)
        self.assertIsNone(result.attempt)
        with self.assertRaisesRegex(BindingError, "receipt_exposure_mismatch"):
            chain.match(attempt=None)

    def test_attempt_for_another_authorization_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError,
                                    "attempt_authorization_mismatch"):
            chain.match(attempt=ExecutionAttemptV2.from_dict(
                {**chain.attempt.to_dict(), "authorization_id": "auth-2"}))

    def test_expired_authorization_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError, "authorization_expired"):
            chain.match(now=_ts(31))

    def test_expired_receipt_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError, "receipt_expired"):
            chain.match(now=_ts(25))

    def test_revoked_signer_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError, "receipt_signer_revoked"):
            chain.match(revoked_signers={"eval-key-1"})

    def test_revoked_receipt_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError, "receipt_revoked"):
            chain.match(revoked_digests={chain.receipt.digest})

    def test_missing_authorization_is_rejected(self):
        chain = _Chain()
        with self.assertRaisesRegex(BindingError, "authorization_unknown"):
            chain.match(authorization=None)

    def test_independence_comes_from_the_receipt(self):
        chain = _Chain(independence="dependent")
        result = chain.match()
        self.assertEqual(result.independence, "dependent")
        self.assertEqual(result.dependency_receipt_digest,
                         chain.dependency_digest)

    def test_a_caller_cannot_declare_its_own_independence(self):
        chain = _Chain()
        with self.assertRaises(TypeError):
            chain.match(declared_independence="dependent")

    def test_a_dependent_receipt_without_a_dependency_is_refused(self):
        chain = _Chain()
        with self.assertRaisesRegex(ContractError,
                                    "dependency_receipt_digest"):
            EvaluatorReceiptV2.from_dict({
                **chain.receipt.to_dict(),
                "independence": "dependent",
                "dependency_receipt_digest": None,
            })


class AuthorityTests(unittest.TestCase):
    def test_untrusted_signer_is_rejected(self):
        chain = _Chain()
        authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={},
            trusted_harness_keys={"harness-key-1":
                                  chain.harness_public.hex()})
        with self.assertRaisesRegex(BindingError, "receipt_untrusted_signer"):
            authority.receipt(chain.receipt)

    def test_trusted_records_verify(self):
        chain = _Chain()
        authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={"eval-key-1": chain.eval_public.hex()},
            trusted_harness_keys={"harness-key-1":
                                  chain.harness_public.hex()},
            trusted_authorization_keys={"auth-key-1":
                                        chain.auth_public.hex()})
        self.assertEqual(authority.receipt(chain.receipt), chain.receipt)
        self.assertEqual(authority.attempt(chain.attempt), chain.attempt)
        self.assertEqual(authority.authorization(chain.authorization),
                         chain.authorization)

    def test_revocation_provider_failure_fails_closed(self):
        chain = _Chain()
        authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={"eval-key-1": chain.eval_public.hex()},
            trusted_harness_keys={},
            revocation_provider=lambda: (_ for _ in ()).throw(
                RuntimeError("custody down")))
        with self.assertRaisesRegex(BindingError,
                                    "revocation_state_unavailable"):
            authority.revocation_state()

    def test_revocation_provider_state_is_visible(self):
        authority = EvidenceBindingAuthority(
            trusted_evaluator_keys={}, trusted_harness_keys={},
            revocation_provider=lambda: ({"k-1"}, {"d" * 64}))
        signers, digests = authority.revocation_state()
        self.assertEqual(signers, frozenset({"k-1"}))
        self.assertEqual(digests, frozenset({"d" * 64}))


def _foreign_fields(chain, **overrides):
    fields = dict(chain.receipt.to_dict())
    fields.pop("evaluator_signature")
    fields.update(overrides)
    return fields


if __name__ == "__main__":
    unittest.main()
