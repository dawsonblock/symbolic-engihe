"""Operational monitoring for authority consistency (PR-12).

A passing unit suite says the code behaves; it does not say a running
deployment is consistent. This module scans the live stores for the
inconsistencies that silently corrupt learning: a missing or stale
snapshot, evidence that mixes quarantined and verified classes, a
revoked signer that authorized guidance, or a seed that became
world-readable.

Severities are deliberate: ``critical`` findings mean serving must be
disabled, ``warning`` means investigate before the next promotion, and
``info`` is context an operator wants in the report. ``serving_allowed``
is false when any critical finding exists; a gateway given a monitor
consults it in ``health()``, so an orchestrator removes the replica.
"""
from __future__ import annotations

import stat
import threading
import time
from dataclasses import dataclass
from typing import Iterable, Mapping

CRITICAL = "critical"
WARNING = "warning"
INFO = "info"


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity,
                "detail": self.detail}


class AuthorityMonitor:
    """Read-only consistency scan over the durable authority stores.

    A scan reads every verified and legacy outcome, so it is cached for
    ``cache_seconds`` (default 30): readiness probes run every few
    seconds and must not turn into a full-table scan per probe. Use
    ``refresh()`` to force a fresh report.
    """

    def __init__(self, *, control_plane, ledger=None, custody=None,
                 registry=None, clock=None, cache_seconds: float = 30.0):
        self._plane = control_plane
        self._ledger = ledger
        self._custody = custody
        self._registry = registry
        self._clock = clock or time.monotonic
        if not isinstance(cache_seconds, (int, float)) or cache_seconds < 0:
            raise ValueError("cache_seconds must be nonnegative")
        self._cache_seconds = float(cache_seconds)
        self._cached: dict | None = None
        self._cached_at: float | None = None
        self._lock = threading.RLock()

    def scan(self) -> dict:
        """Return the current report, reusing a fresh cached one."""
        with self._lock:
            now = self._clock()
            if (self._cached is not None and self._cached_at is not None
                    and now - self._cached_at < self._cache_seconds):
                return self._cached
            report = self._scan()
            self._cached, self._cached_at = report, now
            return report

    def refresh(self) -> dict:
        """Drop the cache and scan again (an incident, not a probe)."""
        with self._lock:
            self._cached = None
            self._cached_at = None
        return self.scan()

    def _scan(self) -> dict:
        findings: list[Finding] = []
        counts: dict[str, int] = {}
        try:
            state = self._plane.authority_state()
        except Exception as exc:  # noqa: BLE001 - a scan reports, never raises
            findings.append(Finding("control_plane_unavailable", CRITICAL,
                                    type(exc).__name__))
            return self._report(findings, counts)
        counts["epoch"] = state.get("epoch", 0)
        if state.get("global_disable"):
            findings.append(Finding("global_disable_active", WARNING,
                                    state.get("disable_reason") or ""))

        snapshot = None
        try:
            snapshot = self._plane.authority_snapshot_v2()
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding("snapshot_unreadable", CRITICAL,
                                    type(exc).__name__))
        if snapshot is None:
            findings.append(Finding("snapshot_missing", WARNING,
                                    "no signed authority snapshot"))
        elif snapshot.epoch != state.get("epoch"):
            findings.append(Finding(
                "snapshot_stale", WARNING,
                f"snapshot={snapshot.epoch} epoch={state.get('epoch')}"))

        try:
            verified = self._plane.independent_outcomes()
            legacy = self._plane.legacy_outcomes()
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding("evidence_unreadable", CRITICAL,
                                    type(exc).__name__))
            verified, legacy = [], []
        counts["verified_outcomes"] = len(verified)
        counts["legacy_outcomes"] = len(legacy)
        if legacy:
            findings.append(Finding(
                "legacy_evidence_present", INFO,
                f"{len(legacy)} quarantined schema-1 outcome(s)"))
        if verified and legacy:
            findings.append(Finding(
                "mixed_evidence_classes", WARNING,
                "verified and legacy outcomes coexist; analysis of the "
                "combined set is exploratory"))

        try:
            revocations = self._plane.authority_revocations()
        except Exception:  # noqa: BLE001
            revocations = []
        counts["revocations"] = len(revocations)
        revoked_signers = {row["target"] for row in revocations
                           if row["revocation_kind"] == "signer"}
        for authorization in self._iter_authorizations():
            if authorization.get("signer_key_id") in revoked_signers:
                findings.append(Finding(
                    "revoked_signer_authorized", CRITICAL,
                    authorization.get("authorization_id", "")))

        if self._ledger is not None:
            readiness = self._ledger.readiness()
            if not readiness.get("snapshot_current", False):
                findings.append(Finding(
                    "ledger_snapshot_stale", WARNING,
                    f"epoch={readiness.get('epoch')}"))

        if self._custody is not None:
            try:
                report = self._custody.custody_report()
            except Exception as exc:  # noqa: BLE001
                findings.append(Finding("custody_unreadable", CRITICAL,
                                        type(exc).__name__))
                report = None
            if report is not None:
                counts["custody_roles"] = report.get("enrolled_count", 0)
                if not report.get("distinct_identities", True):
                    findings.append(Finding(
                        "custody_shared_identity", CRITICAL,
                        "two roles share a signing key"))
                if not report.get("ready", False):
                    findings.append(Finding(
                        "custody_not_ready", WARNING,
                        "evaluator or serving-authority key missing"))
                for entry in report.get("roles", []):
                    if entry.get("enrolled") and not entry.get("owner_only",
                                                               True):
                        findings.append(Finding(
                            "custody_permissions_too_open", CRITICAL,
                            entry.get("role", "")))

        return self._report(findings, counts)

    def _iter_authorizations(self) -> Iterable[Mapping]:
        """Best-effort enumeration of committed authorizations."""
        query = getattr(self._plane, "bound_authorizations", None)
        if callable(query):
            return query()
        return ()

    @staticmethod
    def _report(findings: list[Finding], counts: dict) -> dict:
        critical = [f for f in findings if f.severity == CRITICAL]
        return {
            "schema_version": 1,
            "ok": not critical,
            "serving_allowed": not critical,
            "critical": len(critical),
            "warning": len([f for f in findings if f.severity == WARNING]),
            "findings": [f.to_dict() for f in findings],
            "counts": counts,
        }


def seed_permissions(path) -> str:
    """Octal mode of a seed file, or ``missing`` when it is not readable."""
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except OSError:
        return "missing"


__all__ = [
    "AuthorityMonitor",
    "CRITICAL",
    "Finding",
    "INFO",
    "WARNING",
    "seed_permissions",
]
