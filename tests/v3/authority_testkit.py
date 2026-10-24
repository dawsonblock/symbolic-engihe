"""Authenticated test factories for the v3 authority stack.

These helpers mint *real* signed receipts and drive *real* promotion
decisions through ``PromotionController`` + ``AuthorityDB``. They never set
status fields directly and never bypass the transactional commit path —
qualified state in tests is produced exactly the way production produces it,
with test-custody keys instead of evaluator-custody keys.
"""
from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

from sis.v3 import signatures
from sis.v3.authority_db import AuthorityDB
from sis.v3.contracts import OutcomeReceiptV1, ProcedureRecordV1, canonical_json
from sis.v3.promotion import PromotionController, operator_token_digest

TEST_TOKEN = "test-operator-token-for-authority-0001"
_RECEIPT_DOMAIN = b"sis-v3:outcome_receipt:1\0"


def evaluator_keypair() -> tuple[bytes, bytes, str]:
    """A fresh test evaluator key: (seed, public_key, key_id)."""
    seed, public = signatures.generate_keypair()
    return seed, public, "key-" + hashlib.sha256(public).hexdigest()[:24]


def signed_receipt(
    seed: bytes,
    key_id: str,
    *,
    task_id: str = "t1",
    repo_digest: str = "0" * 64,
    outcome: str = "pass",
    criterion_version: str = "v1",
    suite_commitment: str = "0" * 64,
    evaluator_identity: str = "sis-v3-test-evaluator",
) -> OutcomeReceiptV1:
    """Mint a real Ed25519-signed outcome receipt under a test key."""
    unsigned = {
        "schema_version": 1,
        "receipt_id": "rcpt-test-" + hashlib.sha256(seed + task_id.encode()).hexdigest()[:12],
        "evaluator_identity": evaluator_identity,
        "task_id": task_id,
        "evaluated_repo_digest": repo_digest,
        "test_suite_commitment": suite_commitment,
        "criterion_version": criterion_version,
        "outcome": outcome,
        "regression_evidence": [],
        "signer_key_id": key_id,
    }
    signature = signatures.sign(seed, _RECEIPT_DOMAIN + canonical_json(unsigned)).hex()
    return OutcomeReceiptV1.from_dict({**unsigned, "signature": signature})


def make_authority(
    root: str | Path,
    *,
    token: str = TEST_TOKEN,
    evaluator_public_hex: str | None = None,
    evaluator_key_id: str | None = None,
    extra_trusted: dict[str, str] | None = None,
    min_pass_receipts: int = 1,
    min_distinct_repos: int = 1,
    receipt_resolver=None,
    trusted_operator_keys: dict[str, str] | None = None,
    **controller_kwargs,
):
    """Open an AuthorityDB at ``root`` and bind a PromotionController.

    Returns ``(db, controller)``. ``receipt_resolver`` defaults to a dict
    resolver over ``receipts`` passed later via ``drive``; tests usually pass
    their own resolver.
    """
    db = AuthorityDB(Path(root) / "authority.db")
    trusted = dict(extra_trusted or {})
    if evaluator_key_id and evaluator_public_hex:
        trusted[evaluator_key_id] = evaluator_public_hex
    controller = PromotionController(
        db,
        operator_token_digest=operator_token_digest(token),
        trusted_evaluator_keys=trusted,
        receipt_resolver=receipt_resolver,
        min_pass_receipts=min_pass_receipts,
        min_distinct_repos=min_distinct_repos,
        trusted_operator_keys=trusted_operator_keys,
        **controller_kwargs,
    )
    return db, controller


def seed(db: AuthorityDB, record: ProcedureRecordV1) -> str:
    """Intake-write a draft/candidate record (revision forced to 1)."""
    if record.revision != 1 or record.status not in {"draft", "candidate"}:
        record = ProcedureRecordV1.from_dict(
            {**record.to_dict(), "status": "draft", "revision": 1})
    return db.add_seed(record)


def drive(
    db: AuthorityDB,
    controller: PromotionController,
    procedure_id: str,
    target: str,
    *,
    token: str = TEST_TOKEN,
    seed: bytes | None = None,
    key_id: str | None = None,
    receipts: list[OutcomeReceiptV1] | None = None,
):
    """Drive ``procedure_id`` from its current status to ``target``.

    Only legal forward edges are taken. ``evaluated`` and ``qualified``
    transitions carry a real signed receipt + evaluator signature when
    ``seed``/``key_id`` are provided.
    """
    receipts = receipts or []
    resolver = controller._resolve_receipt
    if resolver is None and receipts:
        table = {r.digest: r for r in receipts}
        resolver = table.__getitem__
        controller._resolve_receipt = resolver
    signer = None
    if seed is not None and key_id is not None:
        signer = lambda body: (key_id, signatures.sign(seed, body).hex())

    path = {"draft": ["candidate"], "candidate": ["evaluated"],
            "evaluated": ["qualified", "suspended"], "qualified": ["suspended"],
            "suspended": ["qualified"]}
    while True:
        current = db.get(procedure_id).status
        if current == target:
            return
        nxt = target if target in path.get(current, ()) else path[current][0]
        needs_receipts = nxt in {"evaluated", "qualified"}
        controller.transition(
            procedure_id, nxt,
            actor_role="operator", actor_identity="test-operator",
            operator_token=token,
            receipt_digests=tuple(r.digest for r in receipts) if needs_receipts else (),
            evaluator_signer=signer if needs_receipts else None,
        )


def authority_stack(
    root: str | Path,
    *records: ProcedureRecordV1,
    token: str = TEST_TOKEN,
) -> tuple[AuthorityDB, PromotionController]:
    """Build a populated AuthorityDB + bound controller.

    ``_proc(...)-style records with status in {evaluated, qualified,
    suspended, retired}`` are seeded as revision-1 drafts and promoted through
    real signed decisions — fixture qualified state never bypasses authority.
    """
    seed_bytes, public, key_id = evaluator_keypair()
    db, controller = make_authority(
        root,
        token=token,
        evaluator_key_id=key_id,
        evaluator_public_hex=public.hex(),
    )
    receipt = signed_receipt(seed_bytes, key_id)
    resolver = {receipt.digest: receipt}.__getitem__
    controller._resolve_receipt = resolver
    for record in records:
        target = record.status
        seed(db, record)
        drive(db, controller, record.procedure_id, target,
              token=token, seed=seed_bytes, key_id=key_id, receipts=[receipt])
    return db, controller


def authority_catalog(
    root: str | Path,
    *records: ProcedureRecordV1,
    token: str = TEST_TOKEN,
) -> AuthorityDB:
    """authority_stack's read model only, for retrieval/guidance tests."""
    return authority_stack(root, *records, token=token)[0]
