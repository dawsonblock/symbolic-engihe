"""Durable, content-addressed custody for qualification evidence.

A signed certificate is only useful if the evidence it cites still
exists, has not been altered, and has not been revoked or superseded.
This module stores immutable receipt/certificate/evidence objects by
digest, records certificate-to-receipt dependency manifests, and keeps a
signed, hash-chained revocation and supersession log.

Serving consults custody status: a missing object, an altered receipt, a
revoked certificate, or a superseded dependency prevents trusted serving.
Disappearance is never silently interpreted as continued qualification.

Offline policy is explicit. If durable certificates are sufficient for
offline verification, the deployment must say so and must state the
maximum revocation staleness it accepts; the default is to deny.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import signatures
from .contracts import canonical_digest, canonical_json, loads_json

GENESIS = "0" * 64
_HEX = re.compile(r"^[0-9a-f]{64}$")
REVOCATION_DOMAIN = b"sis-v3:evidence_revocation:1\0"
SUPERSESSION_DOMAIN = b"sis-v3:evidence_supersession:1\0"
_MAX_OBJECT_BYTES = 1 << 20
_MAX_LOG_BYTES = 8 << 20

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


class EvidenceCustodyError(RuntimeError):
    """Evidence cannot be stored, verified, or trusted for serving."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class OfflineEvidencePolicy:
    """Explicit offline-serving and revocation-freshness policy."""

    allow_offline_serving: bool = False
    max_revocation_age_seconds: int | None = None
    expected_revocation_head: str | None = None

    def __post_init__(self) -> None:
        if self.max_revocation_age_seconds is not None and (
                type(self.max_revocation_age_seconds) is not int
                or self.max_revocation_age_seconds < 0):
            raise EvidenceCustodyError("offline_policy_age_invalid")
        if self.expected_revocation_head is not None and not (
                isinstance(self.expected_revocation_head, str)
                and _HEX.fullmatch(self.expected_revocation_head)):
            raise EvidenceCustodyError("offline_policy_head_invalid")


def _record_digest(record) -> str:
    digest = getattr(record, "digest", None)
    if isinstance(digest, str) and _HEX.fullmatch(digest):
        return digest
    if isinstance(record, dict):
        return canonical_digest("evidence_object", 1, record)
    raise EvidenceCustodyError("evidence_record_unsupported")


def _record_bytes(record) -> bytes:
    encoder = getattr(record, "canonical_bytes", None)
    if callable(encoder):
        return encoder()
    if isinstance(record, dict):
        return canonical_json(record)
    raise EvidenceCustodyError("evidence_record_unsupported")


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise EvidenceCustodyError("object_already_exists", str(path))
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


@contextmanager
def _exclusive_lock(lock_path: Path, *, timeout: float = 10.0):
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    try:
        if fcntl is not None:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise EvidenceCustodyError("custody_store_locked")
                    time.sleep(0.05)
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


class EvidenceCustodyStore:
    """Immutable evidence objects plus signed revocation/supersession logs."""

    independent_custody = True

    def __init__(
        self,
        root: str | Path,
        *,
        trusted_revocation_keys: dict[str, str] | None = None,
        candidate_database_path: str | Path | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "objects").mkdir(exist_ok=True)
        (self.root / "links").mkdir(exist_ok=True)
        self._keys = dict(trusted_revocation_keys or {})
        for key_id, public_hex in self._keys.items():
            if not (isinstance(public_hex, str) and _HEX.fullmatch(public_hex)):
                raise EvidenceCustodyError("revocation_public_key_invalid")
        self._revocations_path = self.root / "revocations.jsonl"
        self._supersessions_path = self.root / "supersessions.jsonl"
        self._lock_path = self.root / "custody.lock"
        self._lock = threading.RLock()
        if candidate_database_path is not None:
            if self.root.resolve() == Path(
                    candidate_database_path).resolve().parent:
                raise EvidenceCustodyError(
                    "custody_store_must_not_share_candidate_database")
        self._revocations: list[dict] | None = None
        self._supersessions: list[dict] | None = None

    # ------------------------------------------------------------------ #
    # immutable objects
    # ------------------------------------------------------------------ #
    def _object_path(self, digest: str) -> Path:
        if not (isinstance(digest, str) and _HEX.fullmatch(digest)):
            raise EvidenceCustodyError("object_digest_invalid")
        return self.root / "objects" / digest[:2] / f"{digest}.json"

    def _meta_path(self, digest: str) -> Path:
        return self._object_path(digest).with_suffix(".meta.json")

    @staticmethod
    def _record_meta(record, digest: str, payload: bytes) -> dict:
        record_type = getattr(record, "RECORD_TYPE", None)
        schema_version = getattr(record, "schema_version", None)
        if record_type is None:
            record_type = "evidence_object"
            schema_version = 1
        return {
            "schema_version": 1,
            "digest": digest,
            "record_type": record_type,
            "record_schema_version": schema_version,
            "content_sha256": hashlib.sha256(payload).hexdigest(),
        }

    def put(self, record) -> str:
        """Store a record by its domain-separated digest (idempotent)."""
        digest = _record_digest(record)
        payload = _record_bytes(record)
        meta = self._record_meta(record, digest, payload)
        path = self._object_path(digest)
        meta_path = self._meta_path(digest)
        with self._lock:
            if path.exists():
                self.get(digest)
                return digest
            _atomic_write(path, payload)
            _atomic_write(meta_path, canonical_json(meta), mode=0o444)
        return digest

    def get(self, digest: str) -> dict:
        path = self._object_path(digest)
        meta_path = self._meta_path(digest)
        try:
            raw = path.read_bytes()
            meta = loads_json(meta_path.read_bytes())
        except OSError as exc:
            raise EvidenceCustodyError("object_missing", digest) from exc
        except ValueError as exc:
            raise EvidenceCustodyError("object_meta_corrupt", digest) from exc
        if len(raw) > _MAX_OBJECT_BYTES:
            raise EvidenceCustodyError("object_too_large")
        if not isinstance(meta, dict) or meta.get("digest") != digest:
            raise EvidenceCustodyError("object_meta_mismatch", digest)
        if hashlib.sha256(raw).hexdigest() != meta.get("content_sha256"):
            raise EvidenceCustodyError("object_altered", digest)
        parsed = loads_json(raw)
        record_type = meta.get("record_type")
        schema_version = meta.get("record_schema_version")
        if not (isinstance(record_type, str)
                and type(schema_version) is int):
            raise EvidenceCustodyError("object_meta_invalid", digest)
        try:
            expected = canonical_digest(record_type, schema_version, parsed)
        except (ValueError, TypeError) as exc:
            raise EvidenceCustodyError("object_digest_invalid") from exc
        if expected != digest:
            raise EvidenceCustodyError("object_digest_mismatch", digest)
        return parsed

    def has(self, digest: str) -> bool:
        try:
            self.get(digest)
            return True
        except EvidenceCustodyError:
            return False

    def object_digests(self) -> list[str]:
        out: list[str] = []
        for path in sorted((self.root / "objects").glob("*/*.json")):
            if path.name.endswith(".meta.json"):
                continue
            out.append(path.stem)
        return out

    # ------------------------------------------------------------------ #
    # dependency manifests
    # ------------------------------------------------------------------ #
    def _link_path(self, certificate_digest: str) -> Path:
        if not (isinstance(certificate_digest, str)
                and _HEX.fullmatch(certificate_digest)):
            raise EvidenceCustodyError("link_digest_invalid")
        return self.root / "links" / f"{certificate_digest}.json"

    def link(
        self,
        certificate_digest: str,
        *,
        candidate_digest: str | None = None,
        receipts=(),
        evidence=(),
        deliveries=(),
    ) -> str:
        manifest = {
            "schema_version": 1,
            "certificate_digest": certificate_digest,
            "candidate_digest": candidate_digest,
            "receipts": sorted(set(receipts)),
            "evidence": sorted(set(evidence)),
            "deliveries": sorted(set(deliveries)),
        }
        for value in [certificate_digest, candidate_digest,
                      *manifest["receipts"], *manifest["evidence"],
                      *manifest["deliveries"]]:
            if value is not None and not (
                    isinstance(value, str) and _HEX.fullmatch(value)):
                raise EvidenceCustodyError("link_dependency_invalid")
        digest = canonical_digest("evidence_link", 1, manifest)
        path = self._link_path(certificate_digest)
        payload = canonical_json(manifest)
        with self._lock:
            if path.exists():
                if path.read_bytes() != payload:
                    raise EvidenceCustodyError("link_conflict")
                return digest
            _atomic_write(path, payload)
        return digest

    def link_for(self, certificate_digest: str) -> dict | None:
        path = self._link_path(certificate_digest)
        if not path.exists():
            return None
        try:
            return loads_json(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise EvidenceCustodyError("link_unreadable") from exc

    # ------------------------------------------------------------------ #
    # revocation / supersession logs
    # ------------------------------------------------------------------ #
    def _sign_entry(self, seed: bytes, key_id: str, domain: bytes,
                    fields: dict) -> dict:
        if key_id not in self._keys:
            raise EvidenceCustodyError("revocation_key_not_trusted")
        body = {k: v for k, v in fields.items() if k != "signature"}
        signature = signatures.sign(seed, domain + canonical_json(body)).hex()
        return {**body, "signature": signature}

    def revoke(
        self,
        target_digest: str,
        *,
        kind: str,
        reason: str,
        seed: bytes,
        key_id: str,
        issued_at: str | None = None,
    ) -> dict:
        if not (isinstance(target_digest, str)
                and _HEX.fullmatch(target_digest)):
            raise EvidenceCustodyError("revocation_target_invalid")
        if kind not in {"receipt", "certificate", "evidence", "candidate",
                        "delivery"}:
            raise EvidenceCustodyError("revocation_kind_invalid")
        with self._lock, _exclusive_lock(self._lock_path):
            entries = self._load_revocations()
            previous = entries[-1]["entry_digest"] if entries else GENESIS
            fields = {
                "schema_version": 1,
                "revocation_id": "rev-" + secrets.token_hex(12),
                "target_digest": target_digest,
                "kind": kind,
                "reason": reason[:512],
                "issued_at": issued_at or _utcnow(),
                "signer_key_id": key_id,
                "prev_digest": previous,
            }
            signed = self._sign_entry(
                seed, key_id, REVOCATION_DOMAIN, fields)
            entry = {**signed,
                     "entry_digest": canonical_digest(
                         "evidence_revocation_entry", 1, signed)}
            self._append(self._revocations_path, entry)
            self._revocations = None
            return entry

    def supersede(
        self,
        superseded_digest: str,
        replacement_digest: str,
        *,
        reason: str,
        seed: bytes,
        key_id: str,
        issued_at: str | None = None,
    ) -> dict:
        for value in (superseded_digest, replacement_digest):
            if not (isinstance(value, str) and _HEX.fullmatch(value)):
                raise EvidenceCustodyError("supersession_target_invalid")
        with self._lock, _exclusive_lock(self._lock_path):
            entries = self._load_supersessions()
            previous = entries[-1]["entry_digest"] if entries else GENESIS
            fields = {
                "schema_version": 1,
                "supersession_id": "sup-" + secrets.token_hex(12),
                "superseded_digest": superseded_digest,
                "replacement_digest": replacement_digest,
                "reason": reason[:512],
                "issued_at": issued_at or _utcnow(),
                "signer_key_id": key_id,
                "prev_digest": previous,
            }
            signed = self._sign_entry(
                seed, key_id, SUPERSESSION_DOMAIN, fields)
            entry = {**signed,
                     "entry_digest": canonical_digest(
                         "evidence_supersession_entry", 1, signed)}
            self._append(self._supersessions_path, entry)
            self._supersessions = None
            return entry

    @staticmethod
    def _append(path: Path, entry: dict) -> None:
        payload = canonical_json(entry) + b"\n"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _load_log(self, path: Path, domain: bytes, kind: str) -> list[dict]:
        if not path.exists():
            return []
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise EvidenceCustodyError(f"{kind}_log_unreadable") from exc
        if len(raw) > _MAX_LOG_BYTES:
            raise EvidenceCustodyError(f"{kind}_log_too_large")
        entries: list[dict] = []
        previous = GENESIS
        for position, line in enumerate(raw.splitlines()):
            if not line.strip():
                continue
            try:
                entry = loads_json(line)
            except ValueError as exc:
                raise EvidenceCustodyError(
                    f"{kind}_log_malformed:{position}") from exc
            if entry.get("prev_digest") != previous:
                raise EvidenceCustodyError(
                    f"{kind}_log_chain_broken:{position}")
            signed = {k: v for k, v in entry.items()
                      if k != "entry_digest"}
            public_hex = self._keys.get(signed.get("signer_key_id"))
            if public_hex is None:
                raise EvidenceCustodyError(
                    f"{kind}_log_untrusted_signer:{position}")
            try:
                valid = signatures.verify(
                    bytes.fromhex(signed["signature"]),
                    domain + canonical_json(
                        {k: v for k, v in signed.items()
                         if k != "signature"}),
                    bytes.fromhex(public_hex))
            except (KeyError, ValueError, TypeError):
                valid = False
            if not valid:
                raise EvidenceCustodyError(
                    f"{kind}_log_signature_invalid:{position}")
            if entry.get("entry_digest") != canonical_digest(
                    f"evidence_{kind}_entry", 1, signed):
                raise EvidenceCustodyError(
                    f"{kind}_log_digest_invalid:{position}")
            previous = entry["entry_digest"]
            entries.append(entry)
        return entries

    def _load_revocations(self) -> list[dict]:
        if self._revocations is None:
            self._revocations = self._load_log(
                self._revocations_path, REVOCATION_DOMAIN, "revocation")
        return list(self._revocations)

    def _load_supersessions(self) -> list[dict]:
        if self._supersessions is None:
            self._supersessions = self._load_log(
                self._supersessions_path, SUPERSESSION_DOMAIN, "supersession")
        return list(self._supersessions)

    def revocations(self) -> list[dict]:
        return self._load_revocations()

    def supersessions(self) -> list[dict]:
        return self._load_supersessions()

    def revocation_head(self) -> str:
        entries = self._load_revocations()
        return entries[-1]["entry_digest"] if entries else GENESIS

    def supersession_head(self) -> str:
        entries = self._load_supersessions()
        return entries[-1]["entry_digest"] if entries else GENESIS

    def _revoked_set(self) -> set[str]:
        return {entry["target_digest"] for entry in self._load_revocations()}

    def _superseded_set(self) -> set[str]:
        return {entry["superseded_digest"]
                for entry in self._load_supersessions()}

    # ------------------------------------------------------------------ #
    # status
    # ------------------------------------------------------------------ #
    def status(self, digest: str, *, _seen=None) -> str:
        """Current status: active/revoked/superseded/missing/invalid/corrupt."""
        if not (isinstance(digest, str) and _HEX.fullmatch(digest)):
            return "invalid"
        revoked = self._revoked_set()
        superseded = self._superseded_set()
        if digest in revoked:
            return "revoked"
        if digest in superseded:
            return "superseded"
        seen = set() if _seen is None else _seen
        if digest in seen:
            return "invalid"
        seen.add(digest)
        path = self._object_path(digest)
        if not path.exists():
            return "missing"
        try:
            self.get(digest)
        except EvidenceCustodyError as exc:
            return "corrupt" if exc.reason == "object_altered" else "missing"
        link = self.link_for(digest)
        if link is None:
            return "active"
        for dependency in (*link.get("receipts", ()),
                           *link.get("evidence", ()),
                           *link.get("deliveries", ())):
            dependency_status = self.status(dependency, _seen=seen)
            if dependency_status in {"revoked", "superseded"}:
                return dependency_status
            if dependency_status != "active":
                return "invalid"
        return "active"

    def require_active(self, digest: str) -> str:
        status = self.status(digest)
        if status != "active":
            raise EvidenceCustodyError("evidence_not_active", status)
        return status

    def check_offline_serving(
        self,
        policy: OfflineEvidencePolicy,
        *,
        offline: bool,
        now: str | None = None,
    ) -> dict:
        """Apply the explicit offline/freshness policy before serving."""
        if offline and not policy.allow_offline_serving:
            raise EvidenceCustodyError("offline_serving_disabled")
        head = self.revocation_head()
        if policy.expected_revocation_head is not None and \
                head != policy.expected_revocation_head:
            raise EvidenceCustodyError("revocation_checkpoint_stale")
        entries = self._load_revocations()
        if policy.max_revocation_age_seconds is not None and entries:
            try:
                age = (_instant(now or _utcnow())
                       - _instant(entries[-1]["issued_at"])).total_seconds()
            except (TypeError, ValueError) as exc:
                raise EvidenceCustodyError(
                    "revocation_timestamp_invalid") from exc
            if age > policy.max_revocation_age_seconds:
                raise EvidenceCustodyError("revocation_evidence_stale")
        return {"ok": True, "revocation_head": head,
                "revocations": len(entries)}

    # ------------------------------------------------------------------ #
    # integrity
    # ------------------------------------------------------------------ #
    def verify(self) -> dict:
        problems: list[str] = []
        objects = 0
        for digest in self.object_digests():
            objects += 1
            try:
                self.get(digest)
            except EvidenceCustodyError as exc:
                problems.append(f"{digest[:12]}:{exc.reason}")
        links = 0
        for path in sorted((self.root / "links").glob("*.json")):
            links += 1
            try:
                manifest = loads_json(path.read_bytes())
            except (OSError, ValueError) as exc:
                problems.append(f"link:{path.stem[:12]}:unreadable")
                continue
            for key in ("receipts", "evidence", "deliveries"):
                for dependency in manifest.get(key, ()):
                    if not self.has(dependency):
                        problems.append(
                            f"link:{path.stem[:12]}:missing:{dependency[:12]}")
        try:
            revocations = self._load_revocations()
        except EvidenceCustodyError as exc:
            problems.append(str(exc))
            revocations = []
        try:
            supersessions = self._load_supersessions()
        except EvidenceCustodyError as exc:
            problems.append(str(exc))
            supersessions = []
        return {
            "ok": not problems,
            "objects": objects,
            "links": links,
            "revocations": len(revocations),
            "supersessions": len(supersessions),
            "revocation_head": revocations[-1]["entry_digest"]
            if revocations else GENESIS,
            "supersession_head": supersessions[-1]["entry_digest"]
            if supersessions else GENESIS,
            "problems": problems,
        }


__all__ = [
    "EvidenceCustodyError",
    "EvidenceCustodyStore",
    "GENESIS",
    "OfflineEvidencePolicy",
    "REVOCATION_DOMAIN",
    "SUPERSESSION_DOMAIN",
]
