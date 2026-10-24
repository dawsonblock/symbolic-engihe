"""Independent outcome evaluation and signed receipts (SIS3-006).

The verifier is the only component that turns a submission into a labeled
outcome. It owns its task registry, its signing key, and its receipt journal
under directories the caller dedicates to evaluator custody; ``evaluate``
re-digests the submitted repository itself, replays registered acceptance
material into a fresh evaluator-owned workspace, and signs the resulting
``OutcomeReceiptV1`` over the canonical payload.

Custody model: ``key_dir`` holds the Ed25519 seed (mode 0700/0600) and must be
a distinct directory from the episode store and the agent workspace. The
public key record is separately exportable, so third parties can verify
receipts offline without touching the private key.

Rejected evidence: unregistered or mismatched tasks, source-commit mismatch,
replayed evaluation nonces, duplicate evaluations of the same tree, malformed
or corrupt journals, and forged signatures. Rejection raises
:class:`EvaluationRejected` with a stable ``reason`` code.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import signatures
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    TaskEnvelopeV1,
    canonical_digest,
    canonical_json,
)
from .policy import require_permission
from .runner import CommandSpec, ResourceLimits, WorkspaceExecutor, tree_digest

_SIGNATURE_DOMAIN = b"sis-v3:outcome_receipt:1\0"


class EvaluationRejected(RuntimeError):
    """The evaluator refuses to produce a receipt for this submission."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


class JournalIntegrityError(RuntimeError):
    """The evaluator's own receipt journal is unreadable or corrupt."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class EvaluatorKeyStore:
    """Loads or creates an Ed25519 seed under evaluator-only permissions."""

    def __init__(self, key_dir: str | Path) -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.key_dir, 0o700)
        self.seed_path = self.key_dir / "ed25519.seed"
        self.public_path = self.key_dir / "ed25519.pub"
        self._seed: bytes | None = None
        self._public: bytes | None = None

    def load_or_create(self) -> tuple[bytes, bytes]:
        """Return ``(seed, public_key)``, generating and persisting if absent."""
        if self.seed_path.exists():
            seed = self.seed_path.read_bytes()
            if len(seed) != 32:
                raise JournalIntegrityError("evaluator seed file is malformed")
            public = signatures.public_key(seed)
        else:
            seed, public = signatures.generate_keypair()
            fd = os.open(self.seed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(seed)
            finally:
                if self.seed_path.exists() and self.seed_path.stat().st_size != 32:
                    self.seed_path.unlink()
            self.public_path.write_bytes(public)
            os.chmod(self.seed_path, 0o600)
            os.chmod(self.public_path, 0o644)
        self._seed, self._public = seed, public
        return seed, public

    @property
    def key_id(self) -> str:
        if self._public is None:
            self.load_or_create()
        return "key-" + hashlib.sha256(self._public).hexdigest()[:24]

    @property
    def public(self) -> bytes:
        if self._public is None:
            self.load_or_create()
        return self._public


@dataclass(frozen=True)
class RegisteredTask:
    task_id: str
    criterion_version: str
    argv: tuple[str, ...]
    files: Mapping[str, bytes]
    base_commit: str | None
    suite_commitment: str


class OutcomeVerifier:
    """Produces signed outcome receipts; never trusts submitter-reported results."""

    def __init__(
        self,
        *,
        executor: WorkspaceExecutor,
        key_dir: str | Path,
        registry_dir: str | Path,
        identity: str = "sis-v3-evaluator",
        trusted_keys: Mapping[str, str] | None = None,
    ) -> None:
        self.executor = executor
        self.identity = identity
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.keystore = EvaluatorKeyStore(key_dir)
        self.keystore.load_or_create()
        self._tasks_path = self.registry_dir / "tasks.json"
        self._journal_path = self.registry_dir / "receipts.jsonl"
        self._tasks: dict[str, RegisteredTask] = {}
        self._nonces: set[str] = set()
        self._evaluated: set[tuple[str, str, str]] = set()
        self._trusted: dict[str, str] = dict(trusted_keys or {})
        self._trusted[self.keystore.key_id] = self.keystore.public.hex()
        self._load_state()

    def register_task(
        self,
        *,
        actor_role: str,
        task_id: str,
        criterion_version: str,
        argv: tuple[str, ...] | list[str],
        files: Mapping[str, bytes] | None = None,
        base_commit: str | None = None,
    ) -> RegisteredTask:
        """Record evaluator-private acceptance material for a task identity."""
        require_permission(actor_role, "outcome:evaluate")
        command = CommandSpec(argv=tuple(argv))
        material = dict(files or {})
        for name, data in material.items():
            CommandSpec(argv=("x",), cwd=name)  # reuse normalized-relative-path validation
            if name == ".":
                raise ContractError("registered file names must be file paths, not directories")
            if not isinstance(data, bytes) or len(data) > (1 << 20):
                raise ContractError("registered test files must be bounded bytes")
        commitment = canonical_digest("test_suite", 1, {
            "task_id": task_id,
            "criterion_version": criterion_version,
            "argv": list(command.argv),
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(material.items())},
            "base_commit": base_commit,
        })
        task = RegisteredTask(
            task_id=task_id,
            criterion_version=criterion_version,
            argv=command.argv,
            files=material,
            base_commit=base_commit,
            suite_commitment=commitment,
        )
        existing = self._tasks.get(task_id)
        if existing is not None:
            if existing.suite_commitment != task.suite_commitment:
                raise EvaluationRejected("task_registration_conflict", task_id)
            return existing
        self._tasks[task_id] = task
        self._persist_tasks()
        return task

    def evaluate(
        self,
        *,
        actor_role: str,
        task: TaskEnvelopeV1,
        submission_dir: str | Path,
        evaluation_nonce: str,
    ) -> OutcomeReceiptV1:
        """Independently evaluate a submission tree and sign the outcome."""
        require_permission(actor_role, "outcome:evaluate")
        if not isinstance(task, TaskEnvelopeV1):
            task = TaskEnvelopeV1.from_dict(task)
        task_ref = task.evaluator_task_ref or task.task_id
        registration = self._tasks.get(task_ref)
        if registration is None:
            raise EvaluationRejected("unregistered_task", task_ref)
        if registration.base_commit and registration.base_commit != task.base_commit:
            raise EvaluationRejected("source_mismatch", task.base_commit or "none")
        if not isinstance(evaluation_nonce, str) or not evaluation_nonce.strip() or len(evaluation_nonce) > 128:
            raise EvaluationRejected("missing_nonce")
        if evaluation_nonce in self._nonces:
            raise EvaluationRejected("replayed_nonce", evaluation_nonce)

        submission = Path(submission_dir)
        if not submission.is_dir():
            raise EvaluationRejected("submission_missing", str(submission))
        evaluated_repo_digest = tree_digest(submission)
        marker = (registration.task_id, evaluated_repo_digest, registration.criterion_version)
        if marker in self._evaluated:
            raise EvaluationRejected("duplicate_evaluation", registration.task_id)

        workspace = self.executor.prepare(submission, label="eval")
        try:
            for name, data in registration.files.items():
                target = workspace.path / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            receipt_exec = self.executor.run(
                workspace,
                CommandSpec(argv=registration.argv, limits=ResourceLimits(wall_seconds=120, cpu_seconds=60)),
            )
        finally:
            self.executor.destroy(workspace)

        if receipt_exec.timeout:
            outcome = "error"
        elif receipt_exec.exit_status == 0:
            outcome = "pass"
        else:
            outcome = "fail"

        unsigned = {
            "schema_version": 1,
            "receipt_id": "rcpt-" + secrets.token_hex(12),
            "evaluator_identity": self.identity,
            "task_id": registration.task_id,
            "evaluated_repo_digest": evaluated_repo_digest,
            "test_suite_commitment": registration.suite_commitment,
            "criterion_version": registration.criterion_version,
            "outcome": outcome,
            "regression_evidence": [],
            "signer_key_id": self.keystore.key_id,
        }
        signature = signatures.sign(
            self.keystore._seed or self.keystore.load_or_create()[0],
            _SIGNATURE_DOMAIN + canonical_json(unsigned),
        ).hex()
        receipt = OutcomeReceiptV1.from_dict({**unsigned, "signature": signature})
        self._record(receipt, evaluation_nonce, receipt_exec.digest)
        return receipt

    def verify_receipt(self, receipt: OutcomeReceiptV1 | Mapping) -> bool:
        """Verify a receipt's signature against the trusted key registry."""
        try:
            record = receipt if isinstance(receipt, OutcomeReceiptV1) else OutcomeReceiptV1.from_dict(receipt)
        except ContractError:
            return False
        public_hex = self._trusted.get(record.signer_key_id)
        if public_hex is None:
            return False
        return verify_receipt_signature(record, public_hex)

    def public_key_record(self) -> dict[str, str]:
        """Export the public verification material; never the seed."""
        return {"key_id": self.keystore.key_id, "public_key": self.keystore.public.hex()}

    def issued_receipts(self) -> list[str]:
        return [entry["receipt_digest"] for entry in self._journal]

    def load_receipt(self, receipt_digest: str) -> OutcomeReceiptV1:
        """Reload a persisted signed receipt by its canonical digest."""
        if not isinstance(receipt_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_digest):
            raise ContractError("receipt reference must be a lowercase SHA-256 digest")
        path = self.registry_dir / "receipts" / f"{receipt_digest}.json"
        try:
            return OutcomeReceiptV1.from_json(path.read_bytes())
        except OSError as exc:
            raise JournalIntegrityError("receipt_missing") from exc

    def _record(self, receipt: OutcomeReceiptV1, nonce: str, execution_digest: str) -> None:
        entry = {
            "receipt_digest": receipt.digest,
            "receipt_id": receipt.receipt_id,
            "task_id": receipt.task_id,
            "evaluated_repo_digest": receipt.evaluated_repo_digest,
            "criterion_version": receipt.criterion_version,
            "outcome": receipt.outcome,
            "execution_digest": execution_digest,
            "nonce": nonce,
            "issued_at": _utcnow(),
        }
        with open(self._journal_path, "ab") as handle:
            handle.write(canonical_json(entry) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        receipts_dir = self.registry_dir / "receipts"
        receipts_dir.mkdir(exist_ok=True)
        receipt_path = receipts_dir / f"{receipt.digest}.json"
        if not receipt_path.exists():
            fd, tmp = tempfile.mkstemp(dir=receipts_dir, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(receipt.canonical_bytes())
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, receipt_path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        self._nonces.add(nonce)
        self._evaluated.add(
            (receipt.task_id, receipt.evaluated_repo_digest, receipt.criterion_version)
        )
        self._journal.append(entry)

    def _load_state(self) -> None:
        self._journal: list[dict] = []
        if self._tasks_path.exists():
            try:
                document = json.loads(self._tasks_path.read_bytes())
            except (OSError, json.JSONDecodeError) as exc:
                raise JournalIntegrityError("task registry is unreadable") from exc
            if not isinstance(document, dict) or set(document) != {"schema_version", "tasks"}:
                raise JournalIntegrityError("task registry has an unexpected shape")
            for item in document["tasks"]:
                task = RegisteredTask(
                    task_id=item["task_id"],
                    criterion_version=item["criterion_version"],
                    argv=tuple(item["argv"]),
                    files={name: bytes.fromhex(data) for name, data in item["files"].items()},
                    base_commit=item["base_commit"],
                    suite_commitment=item["suite_commitment"],
                )
                self._tasks[task.task_id] = task
        if self._journal_path.exists():
            with open(self._journal_path, "rb") as handle:
                for position, raw in enumerate(handle):
                    try:
                        entry = json.loads(raw.rstrip(b"\n"))
                    except json.JSONDecodeError as exc:
                        raise JournalIntegrityError(f"receipt journal line {position} is corrupt") from exc
                    self._journal.append(entry)
                    self._nonces.add(entry["nonce"])
                    self._evaluated.add(
                        (entry["task_id"], entry["evaluated_repo_digest"], entry["criterion_version"])
                    )

    def _persist_tasks(self) -> None:
        document = {
            "schema_version": 1,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "criterion_version": task.criterion_version,
                    "argv": list(task.argv),
                    "files": {name: data.hex() for name, data in sorted(task.files.items())},
                    "base_commit": task.base_commit,
                    "suite_commitment": task.suite_commitment,
                }
                for task in sorted(self._tasks.values(), key=lambda t: t.task_id)
            ],
        }
        payload = canonical_json(document)
        fd, tmp = tempfile.mkstemp(dir=self.registry_dir, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._tasks_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def verify_receipt_signature(receipt: OutcomeReceiptV1 | Mapping, public_key_hex: str) -> bool:
    """Offline receipt check: signature over canonical payload, public key only."""
    try:
        record = receipt if isinstance(receipt, OutcomeReceiptV1) else OutcomeReceiptV1.from_dict(receipt)
    except ContractError:
        return False
    if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
        return False
    try:
        public = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(record.signature)
    except ValueError:
        return False
    unsigned = record.to_dict()
    unsigned.pop("signature")
    return signatures.verify(signature, _SIGNATURE_DOMAIN + canonical_json(unsigned), public)
