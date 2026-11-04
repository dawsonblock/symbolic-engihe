"""Evidence-calibrated guidance and negative-transfer controls (PR-11).

Serving every qualified rule that matches is not a policy. A rule can be
qualified on evidence that is thin, expensive, slow, or drawn from
contexts that resemble this one only superficially. This module turns the
serving decision into an explicit trade-off:

    utility = expected_gain
              - token_cost_weight   * token_cost
              - latency_weight      * latency
              - uncertainty_weight  * interval_width
              - regression_risk

and refuses to serve when the *lower* bound of the gain interval is not
positive. That is the negative-transfer control: an uncertain rule with a
plausible upside and a plausible downside is not a recommendation.

Every rule carries its own applicability predicates and abstention
conditions. An abstention condition that holds is decisive; it is not
outweighed by a good utility score.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .contracts import canonical_digest
from .retrieval import RetrievalContext, precondition_holds


class EvidencePolicyError(RuntimeError):
    """A rule's evidence declaration is malformed."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


#: Shared leading characters that count as "a resembling task".
MIN_RESEMBLANCE_PREFIX = 12

QUALIFIED = "qualified"
EXPLORATORY = "exploratory"
REVOKED = "revoked"
_STATUSES = (QUALIFIED, EXPLORATORY, REVOKED)

UTILITY_MODES = ("ranking", "abstention")


@dataclass(frozen=True)
class RuleEvidence:
    """What is actually known about one candidate rule."""

    candidate_id: str
    qualification_status: str
    supporting_attempts: int
    counterexamples: int
    expected_gain_milli: int
    gain_lower_milli: int
    gain_upper_milli: int
    token_cost: int
    latency_ms: int
    regression_risk_milli: int
    applicability: tuple[Mapping, ...] = ()
    abstain_when: tuple[Mapping, ...] = ()
    known_failure_signatures: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "applicability",
                           tuple(self.applicability or ()))
        object.__setattr__(self, "abstain_when",
                           tuple(self.abstain_when or ()))
        object.__setattr__(self, "known_failure_signatures",
                           tuple(self.known_failure_signatures or ()))
        if not self.candidate_id:
            raise EvidencePolicyError("candidate_id_required")
        if self.qualification_status not in _STATUSES:
            raise EvidencePolicyError("qualification_status_invalid",
                                      self.qualification_status)
        for name, minimum in (("supporting_attempts", 0),
                              ("counterexamples", 0),
                              ("token_cost", 0),
                              ("latency_ms", 0)):
            value = getattr(self, name)
            if type(value) is not int or value < minimum:
                raise EvidencePolicyError(f"{name}_invalid")
        for name in ("expected_gain_milli", "gain_lower_milli",
                     "gain_upper_milli", "regression_risk_milli"):
            value = getattr(self, name)
            if type(value) is not int or not -1000 <= value <= 1000:
                raise EvidencePolicyError(f"{name}_invalid")
        if not self.gain_lower_milli <= self.expected_gain_milli \
                <= self.gain_upper_milli:
            raise EvidencePolicyError("gain_interval_inconsistent")
        if self.regression_risk_milli < 0:
            raise EvidencePolicyError("regression_risk_invalid")

    @property
    def uncertainty_milli(self) -> int:
        return self.gain_upper_milli - self.gain_lower_milli

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "qualification_status": self.qualification_status,
            "supporting_attempts": self.supporting_attempts,
            "counterexamples": self.counterexamples,
            "expected_gain_milli": self.expected_gain_milli,
            "gain_lower_milli": self.gain_lower_milli,
            "gain_upper_milli": self.gain_upper_milli,
            "token_cost": self.token_cost,
            "latency_ms": self.latency_ms,
            "regression_risk_milli": self.regression_risk_milli,
            "applicability": [dict(item) for item in self.applicability],
            "abstain_when": [dict(item) for item in self.abstain_when],
            "known_failure_signatures": list(self.known_failure_signatures),
        }


@dataclass(frozen=True)
class CalibrationPolicy:
    """The explicit trade-off applied to every candidate.

    ``utility_mode`` makes the meaning of ``utility_milli`` explicit:

    - ``ranking`` (default): utility orders candidates; it never rejects
      one. This is the historical behaviour.
    - ``abstention``: a candidate whose net utility is below
      ``min_net_utility_milli`` is refused with
      ``net_utility_below_threshold``. A deployment that serves only when
      the expected gain pays for its cost must opt in to this mode.
    """

    min_supporting_attempts: int = 3
    min_gain_lower_milli: int = 1
    max_regression_risk_milli: int = 100
    max_token_cost: int = 400
    max_latency_ms: int = 2_000
    token_weight_milli: int = 1
    latency_weight_milli: int = 1
    uncertainty_weight_milli: int = 1
    allow_exploratory: bool = False
    utility_mode: str = "ranking"
    min_net_utility_milli: int = 0

    def __post_init__(self) -> None:
        for name, minimum, maximum in (
            ("min_supporting_attempts", 0, 10_000),
            ("min_gain_lower_milli", -1000, 1000),
            ("max_regression_risk_milli", 0, 1000),
            ("max_token_cost", 1, 1_000_000),
            ("max_latency_ms", 0, 86_400_000),
            ("token_weight_milli", 0, 1000),
            ("latency_weight_milli", 0, 1000),
            ("uncertainty_weight_milli", 0, 1000),
            ("min_net_utility_milli", -1000, 1000),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise EvidencePolicyError(f"{name}_invalid", str(value))
        if not isinstance(self.allow_exploratory, bool):
            raise EvidencePolicyError("allow_exploratory_invalid")
        if self.utility_mode not in UTILITY_MODES:
            raise EvidencePolicyError("utility_mode_invalid", self.utility_mode)

    def to_dict(self) -> dict:
        return {
            "min_supporting_attempts": self.min_supporting_attempts,
            "min_gain_lower_milli": self.min_gain_lower_milli,
            "max_regression_risk_milli": self.max_regression_risk_milli,
            "max_token_cost": self.max_token_cost,
            "max_latency_ms": self.max_latency_ms,
            "token_weight_milli": self.token_weight_milli,
            "latency_weight_milli": self.latency_weight_milli,
            "uncertainty_weight_milli": self.uncertainty_weight_milli,
            "allow_exploratory": self.allow_exploratory,
            "utility_mode": self.utility_mode,
            "min_net_utility_milli": self.min_net_utility_milli,
        }

    def digest(self) -> str:
        """Stable digest of the policy, recorded with every decision."""
        return canonical_digest("evidence_policy", 1, self.to_dict())

    def utility(self, evidence: RuleEvidence) -> int:
        return (evidence.expected_gain_milli
                - self.token_weight_milli * evidence.token_cost
                - self.latency_weight_milli * (evidence.latency_ms // 100)
                - self.uncertainty_weight_milli * (
                    evidence.uncertainty_milli // 10)
                - evidence.regression_risk_milli)

    def decide(self, evidence: RuleEvidence,
               context: RetrievalContext) -> "Decision":
        if evidence.qualification_status == REVOKED:
            return Decision(evidence.candidate_id, False, "revoked", 0)
        if evidence.qualification_status != QUALIFIED and \
                not self.allow_exploratory:
            return Decision(evidence.candidate_id, False,
                            "not_qualified", self.utility(evidence))
        for condition in evidence.abstain_when:
            if precondition_holds(condition, context):
                return Decision(evidence.candidate_id, False,
                                "abstention_condition", self.utility(evidence))
        for condition in evidence.applicability:
            if not precondition_holds(condition, context):
                return Decision(evidence.candidate_id, False,
                                "not_applicable", self.utility(evidence))
        if evidence.supporting_attempts < self.min_supporting_attempts:
            return Decision(evidence.candidate_id, False,
                            "insufficient_support", self.utility(evidence))
        if evidence.counterexamples > evidence.supporting_attempts:
            return Decision(evidence.candidate_id, False,
                            "counterexamples_outweigh_support",
                            self.utility(evidence))
        if evidence.gain_lower_milli < self.min_gain_lower_milli:
            # The pessimistic end of the interval is not an improvement.
            return Decision(evidence.candidate_id, False,
                            "gain_interval_not_positive",
                            self.utility(evidence))
        if evidence.regression_risk_milli > self.max_regression_risk_milli:
            return Decision(evidence.candidate_id, False,
                            "regression_risk_too_high",
                            self.utility(evidence))
        if evidence.token_cost > self.max_token_cost:
            return Decision(evidence.candidate_id, False,
                            "token_cost_too_high", self.utility(evidence))
        if evidence.latency_ms > self.max_latency_ms:
            return Decision(evidence.candidate_id, False,
                            "latency_too_high", self.utility(evidence))
        utility = self.utility(evidence)
        if self.utility_mode == "abstention" and \
                utility < self.min_net_utility_milli:
            # The gain does not pay for the cost under this deployment's
            # declared policy. Ranking mode never rejects on utility.
            return Decision(evidence.candidate_id, False,
                            "net_utility_below_threshold", utility)
        return Decision(evidence.candidate_id, True, "served", utility)


@dataclass(frozen=True)
class Decision:
    candidate_id: str
    serve: bool
    reason: str
    utility_milli: int

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "serve": self.serve,
            "reason": self.reason,
            "utility_milli": self.utility_milli,
        }


def select(
    evidence: Iterable[RuleEvidence],
    context: RetrievalContext,
    policy: CalibrationPolicy | None = None,
    *,
    token_budget: int | None = None,
    max_rules: int | None = None,
) -> list[Decision]:
    """Rank candidates by utility and cut at the budget.

    The budget is a hard stop: a rule that would exceed it is rejected
    with ``token_budget_exhausted`` rather than truncated, because a
    half-served procedure is not the procedure that was evaluated.
    """
    policy = policy or CalibrationPolicy()
    budget = policy.max_token_cost if token_budget is None \
        else token_budget
    evidence = list(evidence)
    if len({item.candidate_id for item in evidence}) != len(evidence):
        # Two declarations for one candidate would rank it twice and
        # double-count its token cost; the caller must merge them first.
        raise EvidencePolicyError("duplicate_candidate_id")
    decisions = [policy.decide(item, context) for item in evidence]
    ranked = sorted(
        decisions,
        key=lambda decision: (not decision.serve, -decision.utility_milli,
                              decision.candidate_id))
    out: list[Decision] = []
    spent = 0
    served = 0
    costs = {item.candidate_id: item.token_cost for item in evidence}
    for decision in ranked:
        if not decision.serve:
            out.append(decision)
            continue
        cost = costs[decision.candidate_id]
        if spent + cost > budget:
            out.append(Decision(decision.candidate_id, False,
                                "token_budget_exhausted",
                                decision.utility_milli))
            continue
        if max_rules is not None and served >= max_rules:
            out.append(Decision(decision.candidate_id, False,
                                "rule_limit_reached",
                                decision.utility_milli))
            continue
        spent += cost
        served += 1
        out.append(decision)
    return out


def negative_transfer_guard(
    evidence: RuleEvidence, *, task_signature: str,
    known_failures: Sequence[str],
) -> str | None:
    """Reason to abstain because this rule failed on a resembling task.

    ``known_failures`` are task signatures on which the rule was observed
    to make a correct solution worse. A shared prefix is treated as
    resemblance: the cost of a false positive (corrupting working code) is
    higher than the cost of abstaining.
    """
    for failure in known_failures:
        if not isinstance(failure, str):
            continue
        if failure == task_signature:
            return "prior_negative_transfer"
        common = 0
        for left, right in zip(failure, task_signature):
            if left != right:
                break
            common += 1
        if common >= MIN_RESEMBLANCE_PREFIX:
            return "prior_negative_transfer"
    return None


__all__ = [
    "CalibrationPolicy",
    "Decision",
    "EXPLORATORY",
    "EvidencePolicyError",
    "QUALIFIED",
    "REVOKED",
    "MIN_RESEMBLANCE_PREFIX",
    "RuleEvidence",
    "negative_transfer_guard",
    "select",
]
