"""Staged rollout and release gates (PR-12).

A system that can serve guidance should not start by serving it. The
rollout moves through three stages and each one has gates that are
checked, not assumed:

    shadow    observe and record, never deliver guidance
    advisory  deliver advisory text only; no procedure grants
    full      deliver recommendations under the normal authority gates

Promotion is only possible from ``full`` and only when every release gate
passes. A gate that is missing is a failed gate: the default for an
unmeasured property is "not demonstrated", never "probably fine".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

SHADOW = "shadow"
ADVISORY = "advisory"
FULL = "full"

STAGES = (SHADOW, ADVISORY, FULL)
_ORDER = {stage: index for index, stage in enumerate(STAGES)}


class RolloutError(RuntimeError):
    """A rollout transition is not permitted."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else detail)


@dataclass(frozen=True)
class ReleaseGate:
    """One property that must be demonstrated before promotion."""

    name: str
    required: bool = True
    description: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "required": self.required,
                "description": self.description}


DEFAULT_GATES: tuple[ReleaseGate, ...] = (
    ReleaseGate("evidence_chain_bound",
                description="every outcome is attributable to one attempt"),
    ReleaseGate("concurrency_verified",
                description="duplicate submissions rejected across processes"),
    ReleaseGate("authority_ledger_current",
                description="signed snapshot matches the committed epoch"),
    ReleaseGate("kill_switch_effective",
                description="disable blocks serving without a restart"),
    ReleaseGate("key_custody_independent",
                description="four identities, four keys, owner-only seeds"),
    ReleaseGate("evaluator_isolated",
                description="production evaluation runs isolated"),
    ReleaseGate("statistical_requirement_met",
                description="confirmatory evidence meets its preregistered "
                            "sample size"),
    ReleaseGate("release_provenance_verified",
                description="release artifact digest matches the attestation"),
)


@dataclass(frozen=True)
class RolloutState:
    stage: str
    gates: tuple[ReleaseGate, ...]
    status: Mapping[str, bool]

    def __post_init__(self) -> None:
        if self.stage not in _ORDER:
            raise RolloutError("stage_invalid", self.stage)

    @property
    def failed_gates(self) -> tuple[str, ...]:
        return tuple(
            gate.name for gate in self.gates
            if gate.required and not self.status.get(gate.name, False))

    @property
    def ready(self) -> bool:
        return not self.failed_gates

    def may_serve(self) -> bool:
        return self.stage != SHADOW

    def may_grant_procedures(self) -> bool:
        return self.stage == FULL

    def may_promote(self) -> bool:
        return self.stage == FULL and self.ready

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "stage": self.stage,
            "ready": self.ready,
            "failed_gates": list(self.failed_gates),
            "may_serve": self.may_serve(),
            "may_grant_procedures": self.may_grant_procedures(),
            "may_promote": self.may_promote(),
            "gates": [gate.to_dict() for gate in self.gates],
            "status": dict(self.status),
        }


def evaluate(status: Mapping[str, bool],
             gates: Iterable[ReleaseGate] = DEFAULT_GATES,
             *, stage: str = SHADOW) -> RolloutState:
    return RolloutState(stage=stage, gates=tuple(gates),
                        status=dict(status))


def advance(current: str, target: str,
            status: Mapping[str, bool],
            gates: Iterable[ReleaseGate] = DEFAULT_GATES) -> RolloutState:
    """Move to ``target`` only when every gate for that step passes."""
    if target not in _ORDER or current not in _ORDER:
        raise RolloutError("stage_invalid", f"{current}->{target}")
    if _ORDER[target] <= _ORDER[current]:
        raise RolloutError("rollout_must_advance", f"{current}->{target}")
    if _ORDER[target] - _ORDER[current] > 1:
        # Shadow -> full skips the advisory stage that proves the system
        # can deliver text without granting procedures.
        raise RolloutError("rollout_must_be_stepwise", f"{current}->{target}")
    state = evaluate(status, gates, stage=target)
    if not state.ready:
        raise RolloutError("gates_not_met", ",".join(state.failed_gates))
    return state


def rollback(current: str, *, reason: str,
             status: Mapping[str, bool] | None = None) -> RolloutState:
    """Rollback is always permitted and always one step at a time.

    ``status`` is the last known gate status; it is preserved so the
    rolled-back state still reports which gates were failing, instead of
    replacing them with a rollback marker.
    """
    if current not in _ORDER:
        raise RolloutError("stage_invalid", current)
    index = _ORDER[current]
    target = STAGES[max(0, index - 1)]
    return RolloutState(
        stage=target, gates=DEFAULT_GATES,
        status={**(status or {}), "rollback_reason": bool(reason)})


__all__ = [
    "ADVISORY",
    "DEFAULT_GATES",
    "FULL",
    "ReleaseGate",
    "RolloutError",
    "RolloutState",
    "SHADOW",
    "STAGES",
    "advance",
    "evaluate",
    "rollback",
]
