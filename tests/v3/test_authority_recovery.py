"""Independent fault-injection tests of write-ahead promotion recovery."""
from unittest.mock import patch
import pytest
from sis.v3.procedures import ProcedureStore
from sis.v3.promotion import PromotionController, PromotionRejected, operator_token_digest
from sis.v3.secure_guidance import StrictGuidanceGateway
from tests.v3.test_retrieval import _proc, _request

TOKEN = "test-long-promotion-token-for-recovery"

def _controller(store, path):
    return PromotionController(store, path, operator_token_digest=operator_token_digest(TOKEN), trusted_evaluator_keys={})

def test_replay_signed_transition_after_crash_before_procedure_fsync(tmp_path):
    store = ProcedureStore(tmp_path / "catalog")
    store.add(_proc(status="draft"))
    controller = _controller(store, tmp_path / "decisions")
    with patch.object(store, "add", side_effect=OSError("injected catalog fsync failure")):
        with pytest.raises(OSError, match="injected catalog"):
            controller.transition("p1", "candidate", actor_role="operator", actor_identity="owner", operator_token=TOKEN)
    with pytest.raises(PromotionRejected, match="authority_state_invalid"):
        controller.transition("p1", "candidate", actor_role="operator", actor_identity="owner", operator_token=TOKEN)
    disk_store = ProcedureStore(tmp_path / "catalog")
    disk_controller = _controller(disk_store, tmp_path / "decisions")
    assert disk_controller.verify()["ok"]
    assert disk_store.get("p1").status == "candidate"
    assert len(disk_controller.decisions()) == 1
    assert _controller(ProcedureStore(tmp_path / "catalog"), tmp_path / "decisions").verify()["ok"]

def test_fail_closed_if_signed_transition_predecessor_disappears(tmp_path):
    store = ProcedureStore(tmp_path / "catalog")
    store.add(_proc(status="draft"))
    controller = _controller(store, tmp_path / "decisions")
    with patch.object(store, "add", side_effect=OSError("crash")):
        with pytest.raises(OSError):
            controller.transition("p1", "candidate", actor_role="operator", actor_identity="owner", operator_token=TOKEN)
    (tmp_path / "catalog" / "procedures.jsonl").unlink()
    with pytest.raises(PromotionRejected, match="recovery_predecessor_missing"):
        _controller(ProcedureStore(tmp_path / "catalog"), tmp_path / "decisions")

def test_terminated_corrupt_tail_never_silently_truncated(tmp_path):
    store = ProcedureStore(tmp_path / "catalog")
    store.add(_proc(status="draft"))
    controller = _controller(store, tmp_path / "decisions")
    controller.transition("p1", "candidate", actor_role="operator", actor_identity="owner", operator_token=TOKEN)
    log = tmp_path / "decisions" / "decisions.jsonl"
    corrupted = log.read_bytes() + b"{corrupt record}\n"
    log.write_bytes(corrupted)
    with pytest.raises(PromotionRejected, match="decision_log_corrupt"):
        _controller(ProcedureStore(tmp_path / "catalog"), tmp_path / "decisions")
    assert log.read_bytes() == corrupted

def test_stale_controller_cannot_append_after_independent_commit(tmp_path):
    store = ProcedureStore(tmp_path / "catalog")
    store.add(_proc(status="draft"))
    first = _controller(store, tmp_path / "decisions")
    stale = _controller(store, tmp_path / "decisions")
    first.transition("p1", "candidate", actor_role="operator", actor_identity="owner", operator_token=TOKEN)
    with pytest.raises(PromotionRejected, match="stale_controller"):
        stale.transition("p1", "evaluated", actor_role="operator", actor_identity="owner", operator_token=TOKEN)

def test_strict_gateway_abstains_on_pending_authority(tmp_path):
    store = ProcedureStore(tmp_path / "catalog")
    store.add(_proc(status="draft"))
    controller = _controller(store, tmp_path / "decisions")
    with patch.object(store, "add", side_effect=OSError("injected crash")):
        with pytest.raises(OSError):
            controller.transition("p1", "candidate", actor_role="operator", actor_identity="owner", operator_token=TOKEN)
    gateway = StrictGuidanceGateway(store, controller, procedure_owners={"p1": "repo-a"})
    assert gateway.recommend(_request(), repository_id="repo-a").decision == "abstain"

def test_recover_signed_qualification_and_serve_only_after_replay(tmp_path):
    """Qualified state is unservable in the crash gap; an authorized replay restores it."""
    import hashlib
    import sys
    from sis.v3 import signatures
    from sis.v3.contracts import TaskEnvelopeV1
    from sis.v3.runner import LocalSubprocessExecutor, tree_digest
    from sis.v3.verifier import OutcomeVerifier

    store = ProcedureStore(tmp_path / "catalog")
    store.add(_proc(pid="p1", status="evaluated"))
    seed, pub = signatures.generate_keypair()
    signer_id = "key-" + hashlib.sha256(pub).hexdigest()[:24]
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(tmp_path / "exec", use_seatbelt=False),
        key_dir=tmp_path / "keys", registry_dir=tmp_path / "registry")
    verifier.register_task(actor_role="evaluator", task_id="recovery-task",
                           criterion_version="v1", argv=(sys.executable, "acc.py"),
                           files={"acc.py": b"print('ok')\n"})
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "example.py").write_text("value = 10\n")
    task = TaskEnvelopeV1(
        schema_version=1, task_id="recovery-task", repo_snapshot_digest=tree_digest(repo),
        base_commit=None, task_statement_digest="0" * 64, permitted_commands=("x",),
        isolation_profile="unverified_local", time_budget_seconds=60,
        token_budget=1000, tool_budget=10, actor_id="agent", evaluator_task_ref="recovery-task")
    receipt = verifier.evaluate(actor_role="evaluator", task=task,
                                submission_dir=repo, evaluation_nonce="recovery-nonce-1")
    params = dict(operator_token_digest=operator_token_digest(TOKEN),
                  trusted_evaluator_keys={signer_id: pub.hex(), verifier.keystore.key_id: verifier.keystore.public.hex()},
                  receipt_resolver=verifier.load_receipt)
    controller = PromotionController(store, tmp_path / "decisions", **params)
    with patch.object(store, "add", side_effect=OSError("crash-after-journal")):
        with pytest.raises(OSError, match="crash-after-journal"):
            controller.transition(
                "p1", "qualified", actor_role="operator", actor_identity="owner",
                operator_token=TOKEN, receipt_digests=(receipt.digest,),
                evaluator_signer=lambda body: (signer_id, signatures.sign(seed, body).hex()))
    gateway = StrictGuidanceGateway(store, controller, procedure_owners={"p1": "repo-a"})
    assert gateway.recommend(_request(), repository_id="repo-a").decision == "abstain"
    fresh_store = ProcedureStore(tmp_path / "catalog")
    fresh_controller = PromotionController(fresh_store, tmp_path / "decisions", **params)
    assert fresh_controller.verify()["ok"]
    assert fresh_store.get("p1").status == "qualified"
    serving = StrictGuidanceGateway(fresh_store, fresh_controller,
                                     procedure_owners={"p1": "repo-a"})
    assert serving.recommend(_request(), repository_id="repo-a").decision == "recommend"
    assert serving.recommend(_request(), repository_id="repo-other").decision == "abstain"
