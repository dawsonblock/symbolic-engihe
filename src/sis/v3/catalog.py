"""Namespace-scoped qualified catalog with revocation cascade (SIS3-150).

Scope metadata lives outside the immutable ProcedureRecordV1 (the v1 schema
is frozen), persisted as a signed-off sidecar map: ``repository`` for
repo-local procedures, ``family`` for a repository family, and
``cross_repository`` which the controller may only grant when the decision's
receipt refs cover at least two distinct evaluated trees. ``cascade_suspend``
walks evidence_refs: when a piece of evidence is revoked, every qualified
record depending on it is suspended in one deterministic pass — no stale
recommendations survive evidence invalidation.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path

from .contracts import ContractError, canonical_json, loads_json
from .policy import require_permission
from .procedures import ProcedureStore

SCOPES = frozenset({"repository", "family", "cross_repository"})


class CatalogError(RuntimeError):
    """The catalog cannot complete an operation."""


class Catalog:
    """Scope metadata + suspension cascade over a ProcedureStore."""

    def __init__(self, store: ProcedureStore, meta_path: str | Path) -> None:
        self.store = store
        self._meta_path = Path(meta_path)
        self._scopes: dict[str, str] = {}
        self._lock = threading.Lock()
        self._load()

    def set_scope(self, procedure_id: str, scope: str, *, actor_role: str) -> None:
        require_permission(actor_role, "promotion:approve")
        if scope not in SCOPES:
            raise ContractError("unsupported catalog scope")
        self.store.get(procedure_id)  # raises on unknown id
        with self._lock:
            self._scopes[procedure_id] = scope
            self._persist()

    def scope_of(self, procedure_id: str) -> str:
        return self._scopes.get(procedure_id, "repository")

    def procedures(self, *, status: str | None = None, scope: str | None = None):
        records = self.store.all_latest() if status is None else self.store.by_status(status)
        if scope is None:
            return records
        return [r for r in records if self.scope_of(r.procedure_id) == scope]

    def qualified_head(self, scope: str | None = None) -> str:
        if scope is None:
            return self.store.qualified_head_digest()
        from .contracts import canonical_digest
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(r.digest for r in self.procedures(status="qualified", scope=scope)),
            "scope": scope,
        })

    def cascade_suspend(
        self,
        revoked_evidence_digest: str,
        transition_fn,
    ) -> list[str]:
        """Suspend every qualified record citing ``revoked_evidence_digest``.

        ``transition_fn(procedure_id)`` performs one governed suspension and
        returns its decision id; callers wire in the promotion controller so
        every cascade step is itself an authorized signed decision.
        """
        targets = [
            r for r in self.store.by_status("qualified")
            if revoked_evidence_digest in r.evidence_refs
            or revoked_evidence_digest in r.counterexample_refs
        ]
        return [transition_fn(r.procedure_id) for r in sorted(targets, key=lambda r: r.procedure_id)]

    def _persist(self) -> None:
        document = {"schema_version": 1, "scopes": self._scopes}
        fd, tmp = tempfile.mkstemp(dir=self._meta_path.parent, prefix=".scopes-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(document) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._meta_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _load(self) -> None:
        if not self._meta_path.exists():
            return
        try:
            document = loads_json(self._meta_path.read_bytes())
        except ContractError as exc:
            raise CatalogError("scope metadata is corrupt") from exc
        if set(document) != {"schema_version", "scopes"} or document["schema_version"] != 1:
            raise CatalogError("scope metadata has an unexpected shape")
        scopes = document["scopes"]
        if not isinstance(scopes, dict) or any(s not in SCOPES for s in scopes.values()):
            raise CatalogError("scope metadata contains an invalid scope")
        self._scopes = dict(scopes)
