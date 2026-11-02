"""Reproduce the three P0 outcome-attribution defects of SIS v3.3.2.

Run from the tree root:

    PYTHONPATH=src:. python3 tools/reproduce_v340_defects.py

Each check drives the real production serving stack (signed execution
identity, committed authorization receipt, shared control plane, bound
evidence chain) and reports whether the attack was ACCEPTED. On pristine
v3.3.2 all three report OPEN. After PR-04/PR-05 every check must report
CLOSED with the expected rejection reason.

The defects are:

  D1  cross-principal outcome submission: an authenticated requester can
      record the outcome of another requester's authorization.
  D2  cross-repository receipt: a receipt signed for a different
      repository tree is accepted for this one.
  D3  receipt reuse across interventions: one evaluator receipt is
      credited to two different authorizations, so one measurement
      counts as two independent trials.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sis.v3.evidence_binding import sign_receipt
from sis.v3.serving import GovernedServingGateway
from sis.v3.serving_service import V3ServingService
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture

TOKEN_A = "v340-token-agent-a-0000000000001"
TOKEN_B = "v340-token-agent-b-0000000000002"
OTHER_REPO_DIGEST = "9" * 64

RESULTS: dict[str, dict] = {}


def record(name: str, observed: dict, expected: dict) -> None:
    RESULTS[name] = {
        "observed": observed,
        "expected": expected,
        "defect": any(observed.get(k) != v for k, v in expected.items()),
    }


def _service(fixture):
    gateway = GovernedServingGateway(
        fixture.registry,
        repository_registry=fixture.repo_registry,
        production=True,
        execution_identity_authority=fixture.identity_authority,
        control_plane=fixture.control_plane,
        binding_authority=fixture.binding_authority,
        receipt_authority=fixture.cert.stack.resolve_receipt,
    )
    return V3ServingService(
        gateway, api_keys={TOKEN_A: "agent-1", TOKEN_B: "agent-2"})


def _serve(service, identity):
    code, body = service.handle(
        "/v3/guidance",
        {
            "request": _request().to_dict(),
            "repository_id": "repo-1",
            "execution_identity": identity.to_dict(),
        },
        {"Authorization": f"Bearer {TOKEN_A}"},
    )
    assert code == 200, (code, body)
    return body


def _submit(service, authorization, receipt, *, token=TOKEN_A,
            served_digest=None):
    return service.handle(
        "/v3/outcome",
        {
            "authorization_id": authorization.authorization_id,
            "task_id": authorization.task_id,
            "served_digest": served_digest or authorization.guidance_digest,
            "evaluator_receipt": receipt.to_dict(),
        },
        {"Authorization": f"Bearer {token}"},
    )


def defect_cross_principal(root: Path) -> None:
    fixture = ProductionFixture(root / "d1")
    try:
        service = _service(fixture)
        served = _serve(service, fixture.identity())
        authorization = fixture.bound_authorization()
        receipt = fixture.bound_receipt(authorization)
        code, body = _submit(service, authorization, receipt, token=TOKEN_B)
        record(
            "D1_cross_principal_outcome",
            {"accepted": code == 200, "status": code,
             "error": body.get("error")},
            {"accepted": False, "error": "outcome_requester_mismatch"},
        )
        del served
    finally:
        fixture.close()


def defect_cross_repository(root: Path) -> None:
    fixture = ProductionFixture(root / "d2")
    try:
        service = _service(fixture)
        _serve(service, fixture.identity())
        authorization = fixture.bound_authorization()
        foreign = fixture.bound_receipt(authorization, repository_id="repo-9")
        code, body = _submit(service, authorization, foreign)
        record(
            "D2_cross_repository_receipt",
            {"accepted": code == 200, "status": code,
             "error": body.get("error"),
             "receipt_repo": foreign.repository_id,
             "served_repo": authorization.repository_id},
            {"accepted": False, "error": "receipt_repository_mismatch"},
        )
    finally:
        fixture.close()


def defect_receipt_reuse(root: Path) -> None:
    fixture = ProductionFixture(root / "d3")
    try:
        service = _service(fixture)
        _serve(service, fixture.identity(session_nonce="nonce-d3-a"))
        first = fixture.bound_authorization("nonce-d3-a")
        _serve(service, fixture.identity(session_nonce="nonce-d3-b"))
        second = fixture.bound_authorization("nonce-d3-b")
        receipt = fixture.bound_receipt(first)
        accepted = 0
        errors = []
        for authorization in (first, second):
            code, body = _submit(service, authorization, receipt)
            accepted += code == 200
            if code != 200:
                errors.append(body.get("error"))
        record(
            "D3_receipt_reuse_across_attempts",
            {"accepted_submissions": accepted, "errors": errors},
            {"accepted_submissions": 1},
        )
    finally:
        fixture.close()


def main() -> int:
    for fn in (defect_cross_principal, defect_cross_repository,
               defect_receipt_reuse):
        with tempfile.TemporaryDirectory() as tmp:
            fn(Path(tmp))
    print()
    for name, result in RESULTS.items():
        state = "OPEN" if result["defect"] else "CLOSED"
        print(f"{state:6} {name}")
        print(f"       observed={result['observed']}")
        print(f"       expected={result['expected']}")
    open_count = sum(1 for r in RESULTS.values() if r["defect"])
    print()
    print("open defects:", open_count)
    return 1 if open_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
