"""Read-only guidance gateway with operational phases (SIS3-161).

Phases control what reaches the agent while the same hard gates run:

- ``shadow``: retrieval is evaluated and logged internally; the agent sees
  only an abstention (``catalog_unavailable``). Used to measure would-be
  behavior before exposure.
- ``diagnostic``: the agent receives abstention reasons and next checks even
  when candidates matched; recommendations stay internal.
- ``conditional``: full recommend when gates pass — the only mode that can
  surface procedure IDs.

The kill switch (a file path the operator controls, or the ``SIS3_DISABLE``
environment variable) forces ``catalog_unavailable`` abstention in every
phase. ``record_outcome`` logs whether a returned guidance was later
accepted — compliance telemetry, never a success label.
"""
from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

from .contracts import ContractError, GuidanceRequestV1, GuidanceV1
from .guidance import _abstain, sis_recommend

PHASES = frozenset({"shadow", "diagnostic", "conditional"})


class GuidanceGateway:
    """Phase-gated read-only guidance surface.

    ``snapshot_provider`` is a callable returning a fresh
    ``EligibilitySnapshot`` — typically
    ``PromotionController.eligibility_snapshot``. The gateway rebuilds the
    snapshot on every request so revocations, suspensions, and ledger
    inconsistencies take effect at read time, never after a cascade.
    """

    def __init__(
        self,
        snapshot_provider,
        *,
        phase: str = "shadow",
        kill_switch_path: str | Path | None = None,
        log_dir: str | Path | None = None,
        revoked_provider=None,
    ) -> None:
        if phase not in PHASES:
            raise ContractError("unknown guidance phase")
        if not callable(snapshot_provider):
            raise ContractError("snapshot_provider must be callable")
        self._snapshot_provider = snapshot_provider
        self._revoked_provider = revoked_provider
        self.phase = phase
        self._kill_path = Path(kill_switch_path) if kill_switch_path else None
        self._log_dir = Path(log_dir) if log_dir else None
        if self._log_dir:
            self._log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def killed(self) -> bool:
        if os.environ.get("SIS3_DISABLE"):
            return True
        return bool(self._kill_path and self._kill_path.exists())

    def recommend(
        self,
        request: GuidanceRequestV1 | dict,
        *,
        files_present=(),
        symbols_extra=(),
    ) -> GuidanceV1:
        """Evaluate guidance under the active phase; never mutates state."""
        if self.killed():
            return _abstain(
                "catalog_unavailable",
                ("Guidance is disabled by the operator kill switch.",),
            )
        if not isinstance(request, GuidanceRequestV1):
            request = GuidanceRequestV1.from_dict(request)

        revoked = frozenset(
            self._revoked_provider() if self._revoked_provider else ())
        # Always run the full pipeline for the internal record.
        full = sis_recommend(
            request, self._snapshot_provider(),
            files_present=files_present, symbols_extra=symbols_extra,
            revoked=revoked,
        )
        with self._lock:
            self._log({
                "task_id": request.task_id,
                "phase": self.phase,
                "evaluated_decision": full.decision,
                "would_recommend": list(full.procedure_ids),
                "guidance_digest": full.digest,
            })
        if self.phase == "shadow":
            return _abstain(
                "catalog_unavailable",
                ("Guidance is in shadow mode; decisions are recorded, not served.",),
            )
        if self.phase == "diagnostic" and full.decision == "recommend":
            return _abstain(
                "insufficient_support",
                (
                    "Matching procedures exist but diagnostic mode only reports; re-check context preconditions manually.",
                    "Run the procedure's required verification independently.",
                ),
            )
        return full

    def record_outcome(self, guidance_digest: str, accepted: bool | None) -> None:
        """Log post-hoc acceptance telemetry for a served guidance."""
        if not isinstance(guidance_digest, str) or len(guidance_digest) != 64:
            raise ContractError("guidance_digest must be a SHA-256 hex digest")
        if accepted is not None and type(accepted) is not bool:
            raise ContractError("accepted must be true, false, or null")
        with self._lock:
            self._log({"guidance_digest": guidance_digest, "accepted": accepted})

    def shadow_log(self) -> list[dict]:
        path = (self._log_dir or Path("/dev/null")) / "guidance_log.jsonl"
        if not Path(path).exists():
            return []
        import json
        return [json.loads(line) for line in Path(path).read_bytes().splitlines() if line]

    def _log(self, entry: dict) -> None:
        if not self._log_dir:
            return
        import json
        path = self._log_dir / "guidance_log.jsonl"
        with open(path, "ab") as handle:
            handle.write(json.dumps(entry, sort_keys=True).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())


def retrieve_shadow(
    request: GuidanceRequestV1,
    snapshot,
    **kwargs,
):
    """Internal-only retrieval for shadow analysis; never served to agents."""
    from .retrieval import retrieve
    return retrieve(request, snapshot, **kwargs)
