"""Statistically defensible qualification (PR-09).

v3.3.2 could accept a 29-task confirmatory protocol whose own example
power analysis estimated 103 tasks. That is not an arithmetic slip: it
means a certificate could be labelled confirmatory while its sample size
was chosen after the fact and could not detect the effect it claimed.

This module supplies the three things a confirmatory claim needs:

- a **predeclared power requirement** that fixes the sample size from the
  design, the target effect, alpha and power *before* the run;
- an **independently timestamped preregistration**, signed by a
  timestamping authority, whose instant must precede the first
  evaluation;
- **repository lineage separation**, so a holdout is disjoint from the
  training corpus by lineage rather than by individual snapshot digest.

``classify`` then decides the evidence class: a result that does not meet
its preregistered requirement is exploratory, however good it looks.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import NormalDist
from typing import Iterable, Mapping

from . import signatures
from .contracts import canonical_digest, canonical_json

PREREGISTRATION_DOMAIN = b"sis-v3:preregistration:1\0"

DESIGNS = ("paired_mcnemar", "two_proportion")

EXPLORATORY = "exploratory"
CONFIRMATORY = "confirmatory"


class StatisticsError(RuntimeError):
    """A statistical requirement could not be established."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _z(p: float) -> float:
    if not 0.0 < p < 1.0:
        raise StatisticsError("probability_out_of_range", str(p))
    return NormalDist().inv_cdf(p)


@dataclass(frozen=True)
class PowerRequirement:
    """A predeclared sample-size requirement for one study design.

    ``paired_mcnemar`` uses the Connor/Eliasziw paired binary formula;
    ``two_proportion`` uses the standard unpaired comparison. Both take
    milli-scale inputs so a serialized policy is exact integers rather
    than floats that round differently on different platforms.
    """

    design: str
    effect_milli: int
    alpha_milli: int = 50
    power_milli: int = 800
    discordant_milli: int | None = None
    baseline_milli: int | None = None

    def __post_init__(self) -> None:
        if self.design not in DESIGNS:
            raise StatisticsError("design_invalid", self.design)
        for name, maximum in (("effect_milli", 1000), ("alpha_milli", 500),
                              ("power_milli", 999)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise StatisticsError(f"{name}_invalid", str(value))
        if self.design == "paired_mcnemar":
            if self.discordant_milli is None:
                raise StatisticsError("discordant_milli_required")
            if not 1 <= self.discordant_milli <= 1000:
                raise StatisticsError("discordant_milli_invalid")
        else:
            if self.baseline_milli is None:
                raise StatisticsError("baseline_milli_required")
            if not 0 <= self.baseline_milli <= 1000:
                raise StatisticsError("baseline_milli_invalid")

    @property
    def alpha(self) -> float:
        return self.alpha_milli / 1000

    @property
    def power(self) -> float:
        return self.power_milli / 1000

    @property
    def effect(self) -> float:
        return self.effect_milli / 1000

    def required_sample_size(self) -> int:
        z_alpha = _z(1 - self.alpha / 2)
        z_beta = _z(self.power)
        if self.design == "paired_mcnemar":
            discordant = self.discordant_milli / 1000
            value = ((z_alpha + z_beta) ** 2) * discordant / (self.effect ** 2)
        else:
            p1 = self.baseline_milli / 1000
            p2 = min(1.0, p1 + self.effect)
            pooled = (p1 + p2) / 2
            numerator = (
                z_alpha * math.sqrt(2 * pooled * (1 - pooled))
                + z_beta * math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))) ** 2
            value = numerator / ((p2 - p1) ** 2)
        return max(1, math.ceil(value))

    def to_dict(self) -> dict:
        return {
            "design": self.design,
            "effect_milli": self.effect_milli,
            "alpha_milli": self.alpha_milli,
            "power_milli": self.power_milli,
            "discordant_milli": self.discordant_milli,
            "baseline_milli": self.baseline_milli,
            "required_sample_size": self.required_sample_size(),
        }

    def digest(self) -> str:
        return canonical_digest("power_requirement", 1, self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping) -> "PowerRequirement":
        """Accept a serialized requirement, ignoring derived fields."""
        fields = {name: value[name] for name in (
            "design", "effect_milli", "alpha_milli", "power_milli",
            "discordant_milli", "baseline_milli") if name in value}
        return cls(**fields)


# --------------------------------------------------------------------- #
# Preregistration
# --------------------------------------------------------------------- #
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
class PreregistrationRecord:
    """A study design frozen before the run and timestamped independently."""

    preregistration_id: str
    protocol_digest: str
    primary_metric: str
    power: PowerRequirement
    holdout_lineages: tuple[str, ...]
    training_lineages: tuple[str, ...]
    registered_at: str
    timestamp_authority: str
    signer_key_id: str
    signature: str

    @property
    def required_sample_size(self) -> int:
        return self.power.required_sample_size()

    def body(self) -> bytes:
        return PREREGISTRATION_DOMAIN + canonical_json({
            "schema_version": 1,
            "preregistration_id": self.preregistration_id,
            "protocol_digest": self.protocol_digest,
            "primary_metric": self.primary_metric,
            "power": self.power.to_dict(),
            "holdout_lineages": list(self.holdout_lineages),
            "training_lineages": list(self.training_lineages),
            "registered_at": self.registered_at,
            "timestamp_authority": self.timestamp_authority,
            "signer_key_id": self.signer_key_id,
        })

    @property
    def digest(self) -> str:
        return canonical_digest("preregistration", 1, {
            "preregistration_id": self.preregistration_id,
            "protocol_digest": self.protocol_digest,
            "primary_metric": self.primary_metric,
            "power": self.power.to_dict(),
            "holdout_lineages": list(self.holdout_lineages),
            "training_lineages": list(self.training_lineages),
            "registered_at": self.registered_at,
            "timestamp_authority": self.timestamp_authority,
            "signer_key_id": self.signer_key_id,
        })


def sign_preregistration(seed: bytes, **fields) -> PreregistrationRecord:
    power = fields.get("power")
    if isinstance(power, Mapping):
        fields["power"] = PowerRequirement(**power)
    unsigned = PreregistrationRecord(
        preregistration_id=fields["preregistration_id"],
        protocol_digest=fields["protocol_digest"],
        primary_metric=fields["primary_metric"],
        power=fields["power"],
        holdout_lineages=tuple(fields["holdout_lineages"]),
        training_lineages=tuple(fields["training_lineages"]),
        registered_at=fields["registered_at"],
        timestamp_authority=fields["timestamp_authority"],
        signer_key_id=fields["signer_key_id"],
        signature="0" * 128,
    )
    signature = signatures.sign(seed, unsigned.body()).hex()
    return PreregistrationRecord(
        preregistration_id=unsigned.preregistration_id,
        protocol_digest=unsigned.protocol_digest,
        primary_metric=unsigned.primary_metric,
        power=unsigned.power,
        holdout_lineages=unsigned.holdout_lineages,
        training_lineages=unsigned.training_lineages,
        registered_at=unsigned.registered_at,
        timestamp_authority=unsigned.timestamp_authority,
        signer_key_id=unsigned.signer_key_id,
        signature=signature,
    )


def verify_preregistration(record: PreregistrationRecord,
                           public_hex: str) -> bool:
    try:
        return signatures.verify(bytes.fromhex(record.signature),
                                 record.body(), bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


class PreregistrationRegistry:
    """Trusted, timestamp-authority-signed preregistrations by digest."""

    def __init__(self, *, trusted_timestamp_keys: Mapping[str, str]) -> None:
        self._keys = {key: value.lower()
                      for key, value in trusted_timestamp_keys.items()}
        self._records: dict[str, PreregistrationRecord] = {}
        self._by_protocol: dict[str, str] = {}

    def register(self, record: PreregistrationRecord) -> str:
        public = self._keys.get(record.signer_key_id)
        if public is None:
            raise StatisticsError("timestamp_authority_untrusted",
                                  record.signer_key_id)
        if not verify_preregistration(record, public):
            raise StatisticsError("preregistration_signature_invalid")
        existing = self._records.get(record.digest)
        if existing is not None and existing != record:
            raise StatisticsError("preregistration_conflict")
        self._records[record.digest] = record
        self._by_protocol.setdefault(record.protocol_digest, record.digest)
        return record.digest

    def resolve(self, digest: str) -> PreregistrationRecord | None:
        """Resolve by record digest, or by the protocol it preregisters.

        Certificates cite the protocol's preregistration digest, which is
        the protocol digest under the existing v3.3 convention; both
        lookups are supported so a certificate never fails merely because
        it named the protocol instead of the record.
        """
        record = self._records.get(digest)
        if record is not None:
            return record
        pointer = self._by_protocol.get(digest)
        return None if pointer is None else self._records.get(pointer)

    def __len__(self) -> int:
        return len(self._records)


# --------------------------------------------------------------------- #
# Repository lineage
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class RepositoryLineage:
    """Stable repository identity, independent of any one snapshot."""

    registry_id: str
    lineage_id: str
    family_id: str
    ancestor_registry_id: str | None = None


class LineageRegistry:
    """Maps repository identities to lineages; a lineage is the unit."""

    def __init__(self) -> None:
        self._by_registry: dict[str, RepositoryLineage] = {}

    def add(self, lineage: RepositoryLineage) -> None:
        if not lineage.registry_id or not lineage.lineage_id:
            raise StatisticsError("lineage_invalid")
        existing = self._by_registry.get(lineage.registry_id)
        if existing is not None and existing != lineage:
            raise StatisticsError("lineage_conflict", lineage.registry_id)
        self._by_registry[lineage.registry_id] = lineage

    def lineage_of(self, registry_id: str) -> str | None:
        entry = self._by_registry.get(registry_id)
        return None if entry is None else entry.lineage_id

    def resolve(self, registry_id: str) -> RepositoryLineage | None:
        return self._by_registry.get(registry_id)

    def __len__(self) -> int:
        return len(self._by_registry)


def check_lineage_holdout(
    *, holdout_repositories: Iterable[str],
    training_lineages: Iterable[str],
    lineages: LineageRegistry,
) -> list[str]:
    """Return the holdout repositories that share a training lineage."""
    training = set(training_lineages)
    violations: list[str] = []
    for registry_id in holdout_repositories:
        lineage = lineages.lineage_of(registry_id)
        if lineage is None:
            # An unknown repository has no proven lineage, so it cannot
            # be shown to be a disjoint holdout.
            violations.append(registry_id)
        elif lineage in training:
            violations.append(registry_id)
    return violations


# --------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class QualificationVerdict:
    evidence_class: str
    ok: bool
    reasons: tuple[str, ...]
    required_sample_size: int
    observed_sample_size: int
    details: Mapping[str, object]

    def as_dict(self) -> dict:
        return {
            "evidence_class": self.evidence_class,
            "ok": self.ok,
            "reasons": list(self.reasons),
            "required_sample_size": self.required_sample_size,
            "observed_sample_size": self.observed_sample_size,
            "details": dict(self.details),
        }


def classify(
    *,
    preregistration: PreregistrationRecord | None,
    observed_sample_size: int,
    first_evaluation_at: str | None,
    holdout_repositories: Iterable[str],
    lineages: LineageRegistry | None,
    extra_reasons: Iterable[str] = (),
) -> QualificationVerdict:
    """Decide confirmatory or exploratory for one result set.

    Every unmet requirement downgrades to exploratory and is reported.
    There is no path that upgrades an underpowered result to
    confirmatory because the effect happened to look large.
    """
    reasons: list[str] = list(extra_reasons)
    if preregistration is None:
        reasons.append("preregistration_missing")
        required = 0
    else:
        required = preregistration.required_sample_size
        if observed_sample_size < required:
            reasons.append("underpowered")
        if first_evaluation_at is None:
            reasons.append("evaluation_time_unknown")
        elif _instant(preregistration.registered_at) >= _instant(
                first_evaluation_at):
            # A "pre"registration that is not earlier than the data is
            # a description, not a prediction.
            reasons.append("preregistration_not_before_evaluation")
        if lineages is None:
            reasons.append("lineage_registry_missing")
        else:
            violations = check_lineage_holdout(
                holdout_repositories=holdout_repositories,
                training_lineages=preregistration.training_lineages,
                lineages=lineages)
            if violations:
                reasons.append("lineage_leakage")
    ok = not reasons
    return QualificationVerdict(
        evidence_class=CONFIRMATORY if ok else EXPLORATORY,
        ok=ok,
        reasons=tuple(reasons),
        required_sample_size=required,
        observed_sample_size=observed_sample_size,
        details={
            "preregistration": (preregistration.digest
                                if preregistration is not None else None),
            "first_evaluation_at": first_evaluation_at,
        },
    )


__all__ = [
    "CONFIRMATORY",
    "DESIGNS",
    "EXPLORATORY",
    "LineageRegistry",
    "PowerRequirement",
    "PreregistrationRecord",
    "PreregistrationRegistry",
    "QualificationVerdict",
    "RepositoryLineage",
    "StatisticsError",
    "check_lineage_holdout",
    "classify",
    "sign_preregistration",
    "verify_preregistration",
]
