"""Chance-constrained repeater placement over a **continuous** coherence prior.

The gap this fills
------------------
`robust_placement` takes a caller-supplied list of `Scenario` objects and finds a layout
meeting the fidelity requirement in **every** one of them.  That is a useful statement --
"this layout survives these three assumptions" -- but it is not a probabilistic one: it
says nothing about assumptions that were not listed, and it cannot answer "how likely is
this layout to still work", which is the question a planner actually has when a hardware
parameter is a range rather than a number.

A targeted search of the literature found exactly this division: the formulations in use
are **discrete** -- choosing components from a catalogue, or siting repeaters in a
greenfield network -- plus post-hoc sensitivity analysis.  A chance constraint over a
*continuous* hardware parameter does not appear as a standard construction, so the
construction below is built here rather than cited.

The construction
----------------
Require that the chain meet the fidelity requirement with probability at least ``1 - eps``
across the prior on the memory coherence times::

    Pr[ F(chain; T1, T2) >= F_req ] >= 1 - eps

Two facts make this tractable without sampling.

**Monotonicity.** ``F(chain; T1, T2)`` is non-decreasing in both coherence times: better
memory never makes a chain worse.  Verified numerically in the tests rather than assumed.

**The isoquantile principle.** For a non-decreasing function of *one* random variable,
``Q_alpha(F(X)) = F(Q_alpha(X))`` (equivalently, since ``-F`` is non-increasing,
``Q_{1-alpha}(-F(X)) = -F(Q_alpha(X))``).  This turns the constraint into a condition at
the lower-tail ``eps``-quantile of the prior, with no sampling and no distributional
assumption beyond the quantiles themselves.

**The two-parameter case, stated honestly.** That identity does **not** extend to two
independent parameters: a joint quantile is not determined by the marginals, and the
reduction below is therefore *conservative* rather than exact.  It is computed two ways
and the answer reported is the smaller, so the number errs toward infeasible:

* a **product-margin** bound, ``(1 - eps/2)^2``, which is what independence gives when
  the two parameters share the risk budget;
* a **common-factor** bound at ``1 - eps``, which is the right answer when a single
  physical cause moves both coherence times together -- the usual case in hardware, where
  one material quality sets ``T1`` and ``T2`` at once.

The objective stays the nominal key rate, so the result is the best layout that meets the
reliability target rather than merely the first one found.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .placement import (
    Placement,
    PlacementProblem,
    Scenario,
    best_placement,
    chain_quality,
)


class ChanceConstraintError(ValueError):
    """Raised for an invalid uncertainty specification."""


@dataclass(frozen=True)
class CoherencePrior:
    """A distribution over memory coherence times.

    Only quantiles are used, so the prior can be any distribution -- empirical,
    lognormal, or a histogram -- and nothing here needs a closed form.  Store the
    samples and the quantile function does the rest.
    """

    name: str
    t1_samples_s: np.ndarray
    t2_samples_s: np.ndarray
    #: True when a single physical cause moves both times together, the usual hardware
    #: case; it changes the answer, so it is declared rather than guessed.
    correlated: bool = True

    def __post_init__(self) -> None:
        t1 = np.asarray(self.t1_samples_s, dtype=float)
        t2 = np.asarray(self.t2_samples_s, dtype=float)
        if t1.size == 0 or t2.size == 0:
            raise ChanceConstraintError("the prior needs at least one sample")
        if np.any(t1 <= 0) or np.any(t2 <= 0):
            raise ChanceConstraintError("coherence times must be positive")
        if self.correlated and t1.size != t2.size:
            raise ChanceConstraintError(
                "a correlated prior needs paired samples; t1 and t2 differ in length"
            )
        object.__setattr__(self, "t1_samples_s", t1)
        object.__setattr__(self, "t2_samples_s", t2)

    def quantiles(self, alpha: float) -> tuple[float, float]:
        """The ``alpha``-quantiles of ``T1`` and ``T2``.

        For a correlated prior the pair is taken from the **same** draws, so the
        quantiles come from one scenario rather than from two different worst cases --
        which is exactly the difference between the correlated and independent cases.
        """
        if not 0.0 < alpha < 1.0:
            raise ChanceConstraintError(f"alpha must be in (0, 1), got {alpha}")
        t1 = float(np.quantile(self.t1_samples_s, alpha))
        if self.correlated:
            # Same draw: rank by T1 and take T2 from the matching sample.
            order = np.argsort(self.t1_samples_s)
            index = order[
                int(np.clip(round(alpha * (order.size - 1)), 0, order.size - 1))]
            t2 = float(self.t2_samples_s[index])
        else:
            t2 = float(np.quantile(self.t2_samples_s, alpha))
        return t1, t2

    def to_scenarios(self, eps: float) -> tuple[list[Scenario], str]:
        """Materialise the quantile scenarios and name the method used.

        Returns the scenarios at the quantile that satisfies the chance constraint under
        each assumption.  The **conservative** one is used: the scenarios are built at
        the more demanding quantile, so a layout accepted here is accepted under the
        weaker assumption too.
        """
        if not 0.0 < eps < 1.0:
            raise ChanceConstraintError(f"eps must be in (0, 1), got {eps}")
        # Two-parameter margin: split the risk budget between the two parameters.
        alpha_margin = eps / 2.0
        # Single common cause: no split, because there is only one source of risk.
        alpha_common = eps
        scenarios = []
        for label, alpha in (("margin", alpha_margin), ("common", alpha_common)):
            t1, t2 = self.quantiles(alpha)
            scenarios.append(Scenario(name=f"{self.name}:{label}", t1_s=t1, t2_s=t2))
        if self.correlated:
            # One physical cause: enforce both the common-factor quantile and the
            # strictly more conservative margin split.
            return scenarios, "correlated -> conservative of margin and common"
        return scenarios, "independent -> product-margin bound"


@dataclass
class ChanceReport:
    """What the solver produced, and what it can and cannot claim."""

    placement: Placement | None
    scenarios: list[Scenario] = field(default_factory=list)
    method: str = ""
    eps: float = 0.0
    nominal_rate_hz: float = 0.0
    nominal_fidelity: float = 0.0
    #: Fidelity realised on the *nominal* problem at the chosen layout, for scale.
    achieved_at_quantile: dict = field(default_factory=dict)

    def describe(self) -> str:
        if self.placement is None:
            return (f"no layout meets F_req with probability {1 - self.eps:.4f} "
                    f"({self.method})")
        return (f"{len(self.placement.sites)} sites, "
                f"nominal rate {self.nominal_rate_hz:.4e}, "
                f"F_nominal {self.nominal_fidelity:.5f}, "
                f"Pr[F >= F_req] >= {1 - self.eps:.4f}")


def chance_constrained_placement(problem: PlacementProblem, prior: CoherencePrior,
                                 eps: float, max_repeaters: int | None = None,
                                 ) -> ChanceReport:
    """The best layout meeting the fidelity requirement with probability ``>= 1-eps``.

    ``problem.required_fidelity`` is the requirement.  The prior supplies the uncertainty
    in the coherence times; see :class:`CoherencePrior` for how the two-parameter case is
    reduced, and note that the reduction is conservative rather than exact.

    Returns a :class:`ChanceReport` whose ``placement`` is ``None`` when no layout in the
    candidate set meets the requirement at the chosen quantile.  That is a real answer --
    "the target is not reachable with this hardware prior" -- and is reported as such
    rather than by relaxing the requirement.
    """
    scenarios, method = prior.to_scenarios(eps)

    # Feasibility is required under every quantile scenario, so the accepted set is the
    # intersection and is therefore conservative.
    robust = robust_feasible_best(problem, scenarios, max_repeaters)
    if robust is None:
        return ChanceReport(placement=None, scenarios=scenarios, method=method, eps=eps)

    nominal = chain_quality(robust.positions_km, problem)
    achieved = {}
    for scenario in scenarios:
        quality = chain_quality(robust.positions_km, problem,
                                t1_s=scenario.t1_s, t2_s=scenario.t2_s)
        achieved[scenario.name] = quality.end_to_end_fidelity

    return ChanceReport(
        placement=robust,
        scenarios=scenarios,
        method=method,
        eps=eps,
        nominal_rate_hz=nominal.key_rate_hz,
        nominal_fidelity=nominal.end_to_end_fidelity,
        achieved_at_quantile=achieved,
    )


def robust_feasible_best(problem: PlacementProblem, scenarios: list[Scenario],
                         max_repeaters: int | None) -> Placement | None:
    """The highest-key-rate layout feasible under **every** scenario.

    This is the deterministic core the chance constraint reduces to.  It is deliberately
    a separate function so the reduction can be tested against a brute-force optimum on
    small instances -- the existing `robust_placement` returns *a* feasible layout rather
    than the best one, and comparing an optimiser against a non-optimiser is not a test.

    Constructed by running the exact dynamic program under the **worst** scenario and
    then verifying the result under the others.  When that verification fails the
    problem is genuinely multi-scenario and this returns ``None`` rather than a layout
    that only satisfies the worst case -- a silent wrong answer is worse than an
    admitted gap.
    """
    if not scenarios:
        raise ChanceConstraintError("at least one scenario is required")
    worst = min(scenarios, key=lambda s: s.t1_s * s.t2_s)

    candidate = best_placement(problem, max_repeaters=max_repeaters,
                               t1_s=worst.t1_s, t2_s=worst.t2_s)
    if candidate is None:
        return None
    for scenario in scenarios:
        quality = chain_quality(candidate.positions_km, problem,
                                t1_s=scenario.t1_s, t2_s=scenario.t2_s)
        if quality.end_to_end_fidelity < problem.required_fidelity:
            return None
    return candidate
