"""Namespace-scoped qualified catalog with revocation cascade (SIS3-150).

Scope is a signed decision: ``PromotionController.grant_scope`` appends
signed ``ScopeGrantV1`` entries to the authority's hash-chained grants log,
and this catalog exposes only the projected result. There is no mutable
sidecar and no caller-supplied role — the v3.1.x ``set_scope(actor_role=...)``
surface is removed; a legacy unsigned ``scopes.json`` must be migrated
explicitly (it is never honored). ``cascade_suspend`` walks evidence_refs:
when a piece of evidence is revoked, every qualified record depending on it
is suspended in one deterministic pass — but serving never waits on the
cascade, since read-time eligibility consults the revocation set directly.
"""
from __future__ import annotations

from pathlib import Path

from .contracts import canonical_digest
from .procedures import ProcedureStore

SCOPES = frozenset({"repository", "family", "cross_repository"})


class CatalogError(RuntimeError):
    """The catalog cannot complete an operation."""


class Catalog:
    """Read-only projection of signed scope state over a ProcedureStore.

    ``snapshot_provider`` returns the authority's ``EligibilitySnapshot``
    (typically ``PromotionController.eligibility_snapshot``); every read
    re-evaluates so grants and revocations are visible immediately.
    """

    def __init__(self, store: ProcedureStore, snapshot_provider) -> None:
        if not callable(snapshot_provider):
            raise CatalogError("snapshot_provider must be callable")
        self.store = store
        self._snapshot_provider = snapshot_provider

    @staticmethod
    def migrate_legacy_sidecar(meta_path: str | Path) -> None:
        """Explicitly retire a legacy unsigned ``scopes.json`` sidecar.

        Unsigned scope metadata must never be honored; the operator runs
        this once to quarantine the file, then re-issues scopes as signed
        grants. Refuses to overwrite an existing quarantine file.
        """
        path = Path(meta_path)
        if not path.exists():
            return
        target = path.with_suffix(path.suffix + ".unsigned-legacy")
        if target.exists():
            raise CatalogError("legacy quarantine file already exists")
        path.rename(target)

    def scope_of(self, procedure_id: str) -> str:
        binding = self._snapshot_provider().scope_bindings.get(procedure_id)
        return binding["scope"] if binding else "repository"

    def binding_of(self, procedure_id: str) -> dict:
        return dict(
            self._snapshot_provider().scope_bindings.get(procedure_id) or {
                "scope": "repository", "repo_ids": frozenset(),
                "family_id": None, "granted": False,
            })

    def procedures(self, *, status: str | None = None, scope: str | None = None):
        snap = self._snapshot_provider()
        if status is None:
            records = list(snap.records.values())
        elif status == "qualified":
            records = list(snap.qualified)
        else:
            records = [r for r in snap.records.values()
                       if snap.statuses.get(r.digest) == status]
        if scope is None:
            return records
        return [r for r in records
                if self.scope_of(r.procedure_id) == scope]

    def qualified_head(self, scope: str | None = None) -> str:
        snap = self._snapshot_provider()
        if scope is None:
            return snap.qualified_head
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(r.digest for r in self.procedures(
                status="qualified", scope=scope)),
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
        every cascade step is itself an authorized signed decision. This is
        a durable derived operation — read-time revocation is enforced by
        the snapshot independently of the cascade.
        """
        targets = [
            r for r in self._snapshot_provider().qualified
            if revoked_evidence_digest in r.evidence_refs
            or revoked_evidence_digest in r.counterexample_refs
        ]
        return [transition_fn(r.procedure_id) for r in sorted(targets, key=lambda r: r.procedure_id)]
