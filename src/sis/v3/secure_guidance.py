"""Production-oriented fail-closed guidance boundary.

The legacy phase-gated gateway moved to ``sis.v3.compat.guidance_gateway``
for fixture compatibility. Production code uses ``StrictGuidanceGateway``
over an ``AuthorityDB`` transactional store: verified promotion decisions are
necessary for any qualified record to exist at all, and cross-namespace
retrieval requires an independently supplied signed-grant predicate.
"""
from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path

from .authority import AuthorizedCatalogView, AuthorityError
from .authority_db import AuthorityDB
from .contracts import GuidanceRequestV1, GuidanceV1, canonical_digest
from .guidance import _abstain, sis_recommend
from .promotion import PromotionController
from .catalog import Catalog


class _ScopedCatalog:
    def __init__(self, view: AuthorizedCatalogView, allowed):
        self._view = view
        self._allowed = frozenset(allowed)

    def by_status(self, status):
        return [r for r in self._view.by_status(status) if r.procedure_id in self._allowed]

    def all_latest(self):
        return [r for r in self._view.all_latest() if r.procedure_id in self._allowed]

    def qualified_head_digest(self):
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(r.digest for r in self.by_status("qualified")),
        })


class StrictGuidanceGateway:
    """Read-only, decision-backed serving. No direct store write grants authority.

    `namespace_authorizer(record, repository_id, scope)` must validate signed
    scope grants and task-registry lineage *outside* untrusted request content.
    Without it, only explicit repo-local ownership matches are allowed.
    """

    def __init__(self, store: AuthorityDB, authority: PromotionController,
                 *, catalog: Catalog | None = None,
                 procedure_owners: dict[str, str] | None = None,
                 namespace_authorizer: Callable[[object, str, str], bool] | None = None,
                 revoked_digests: frozenset[str] = frozenset(),
                 kill_switch_path: str | Path | None = None):
        self._view = AuthorizedCatalogView(store, authority)
        self._catalog = catalog
        self._owners = dict(procedure_owners or {})
        self._grant = namespace_authorizer
        self._revoked = revoked_digests
        self._kill = Path(kill_switch_path) if kill_switch_path else None

    def recommend(self, request: GuidanceRequestV1 | dict, *, repository_id: str,
                  files_present=(), symbols_extra=(), now=None) -> GuidanceV1:
        if os.environ.get("SIS3_DISABLE") or (self._kill and self._kill.exists()):
            return _abstain("catalog_unavailable", ("SIS guidance disabled by operator.",))
        if not repository_id:
            return _abstain("insufficient_support", ("Trusted repository identity is required.",))
        try:
            records = self._view.by_status("qualified")
            allowed = []
            for record in records:
                scope = self._catalog.scope_of(record.procedure_id) if self._catalog else "repository"
                # Never infer authorization from untrusted task text.
                local = scope == "repository" and self._owners.get(record.procedure_id) == repository_id
                extended = self._grant is not None and bool(self._grant(record, repository_id, scope))
                if local or extended:
                    allowed.append(record.procedure_id)
            scoped = _ScopedCatalog(self._view, allowed)
            return sis_recommend(request, scoped, files_present=files_present,
                                 symbols_extra=symbols_extra, revoked=self._revoked, now=now)
        except (AuthorityError, ValueError, TypeError):
            return _abstain("catalog_unavailable", ("Authoritative qualification evidence could not be verified.",))
