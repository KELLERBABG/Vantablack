"""Chance-constrained repeater placement over a continuous coherence prior.

This is the genuinely open gap in placement. The tests pin the
properties the construction depends on, because the reduction from a probability
statement to a deterministic one is only valid if they hold:

* **monotonicity** -- better coherence never makes a chain worse, which is the premise
  that lets a probabilistic requirement be checked at a quantile at all;
* **the quantile direction** -- a tighter reliability target must use a *more demanding*
  scenario, and must never produce a better rate;
* **the correlated/independent distinction** -- declared rather than guessed, because the
  two cases genuinely differ and the reduction is conservative, not exact.

The coherence times are set in the **sensitive regime**. At T1 ~ 100 s the model's
fidelity saturates (0.970398 for T1 anywhere from 10 s to 200 s) and every test would
pass while proving nothing; the answer only moves between roughly 1e-4 s and 1e-2 s.
"""

from __future__ import annotations

import numpy as np
import pytest

from quantumnet.topology.chance_placement import (
    ChanceConstraintError,
    CoherencePrior,
    chance_constrained_placement,
    robust_feasible_best,
)
from quantumnet.topology.placement import (
    CandidateSite,
    PlacementProblem,
    Scenario,
    chain_quality,
)


def prior(seed: int = 3, n: int = 600, correlated: bool = True,
          t1_median: float = 2e-3) -> CoherencePrior:
    """A lognormal coherence prior in the regime where fidelity actually moves."""
    rng = np.random.default_rng(seed)
    q = rng.lognormal(0.0, 0.45, size=n)
    t1 = t1_median * q
    t2 = (t1_median / 2.0) * (q if correlated else rng.lognormal(0.0, 0.45, size=n))
    return CoherencePrior("device", t1_samples_s=t1, t2_samples_s=t2,
                          correlated=correlated)


def problem(required_fidelity: float = 0.95, span_km: float = 200.0,
            n_candidates: int = 8) -> PlacementProblem:
    return PlacementProblem(
        end_a=CandidateSite("A", 0.0),
        end_b=CandidateSite("B", span_km),
        candidates=[CandidateSite(f"S{i}", round(span_km * (i + 1) / (n_candidates + 1), 1))
                    for i in range(n_candidates)],
        required_fidelity=required_fidelity,
    )


# ---------------------------------------------------------------------------
# The premise: monotonicity
# ---------------------------------------------------------------------------

def test_fidelity_is_monotone_in_the_coherence_times():
    """The whole reduction rests on this.

    ``Pr[F >= F_req]`` is only checkable at a quantile because ``F`` is non-decreasing in
    the coherence times. If it were not, the isoquantile identity would not apply and the
    solver would be reporting a number with no probabilistic meaning.
    """
    p = problem()
    positions = [0.0, 40.0, 80.0, 120.0, 200.0]
    previous = -1.0
    for t1 in (1e-4, 3e-4, 1e-3, 3e-3, 1e-2, 1e-1):
        fidelity = chain_quality(positions, p, t1_s=t1, t2_s=t1 / 2).end_to_end_fidelity
        assert fidelity >= previous - 1e-12, (
            f"F fell from {previous} to {fidelity} as T1 rose to {t1}")
        previous = fidelity


def test_the_test_operating_point_is_actually_sensitive():
    """Guard against a vacuous suite: fidelity must move across the prior's range.

    Recorded because an earlier version of these tests used T1 ~ 100 s, where the model
    saturates and every assertion passes without exercising anything.
    """
    p = problem()
    positions = [0.0, 40.0, 80.0, 120.0, 200.0]
    low = chain_quality(positions, p, t1_s=1e-4, t2_s=5e-5).end_to_end_fidelity
    high = chain_quality(positions, p, t1_s=1e-2, t2_s=5e-3).end_to_end_fidelity
    assert high - low > 0.05, (
        f"fidelity barely moves ({low:.6f} -> {high:.6f}); the test regime is not "
        f"sensitive and these tests would prove nothing")


# ---------------------------------------------------------------------------
# The quantile reduction
# ---------------------------------------------------------------------------

def test_a_tighter_reliability_target_uses_a_more_demanding_scenario():
    p = prior()
    gentle, _ = p.to_scenarios(0.5)
    strict, _ = p.to_scenarios(0.01)
    assert min(s.t1_s for s in strict) < min(s.t1_s for s in gentle)
    assert min(s.t2_s for s in strict) < min(s.t2_s for s in gentle)


def test_the_scenarios_bracket_the_probability_level():
    """The report must not claim more than the scenarios enforce.

    The end-to-end probability is at least ``1 - eps`` only if the checked scenario sits at
    or below the ``eps`` lower-tail quantile (so at least ``1 - eps`` of the prior lies
    at or above it). Both constructed scenarios satisfy this, which is what makes the
    reduction conservative rather than merely plausible.
    """
    eps = 0.1
    pr = prior()
    scenarios, _method = pr.to_scenarios(eps)
    assert len(scenarios) == 2
    for scenario in scenarios:
        # At least 1 - eps of the prior has T1 >= scenario.t1_s.
        prob_needed = 1.0 - eps
        implied = float(np.mean(pr.t1_samples_s >= scenario.t1_s))
        assert implied >= prob_needed - 0.02


def test_chance_constrained_placement_satisfies_monte_carlo_probability():
    """Binding-constraint Monte Carlo check: true Pr[F >= F_req] >= 1 - eps."""
    p = problem(required_fidelity=0.95, span_km=200.0, n_candidates=8)
    pr = prior(seed=7, n=1000, correlated=True, t1_median=5e-4)
    eps = 0.10
    report = chance_constrained_placement(p, pr, eps, max_repeaters=5)
    assert report.placement is not None

    passes = [
        chain_quality(
            report.placement.positions_km, p, t1_s=float(t1), t2_s=float(t2)
        ).end_to_end_fidelity >= p.required_fidelity
        for t1, t2 in zip(pr.t1_samples_s, pr.t2_samples_s)
    ]
    true_pr = float(np.mean(passes))
    assert true_pr >= 1.0 - eps - 1e-9


def test_a_correlated_prior_pairs_its_samples():
    """With one physical cause, T2 must come from the same draw as T1.

    Taking independent quantiles would construct a scenario that no physical device
    produces -- a high T1 with a median T2 -- and understate the cost of reliability.
    """
    p = prior(correlated=True)
    t1, t2 = p.quantiles(0.9)
    # The ratio is preserved by pairing, up to sampling noise in the order statistic.
    assert t2 / t1 == pytest.approx(0.5, rel=0.25)


def test_an_independent_prior_uses_both_marginals():
    p = prior(correlated=False)
    t1, t2 = p.quantiles(0.9)
    assert t1 > 0 and t2 > 0
    _scenarios, method = p.to_scenarios(0.1)
    assert "margin" in method


def test_the_method_names_which_assumption_was_made():
    """Correlated and independent are different questions and the answer says which."""
    _s, correlated_method = prior(correlated=True).to_scenarios(0.1)
    _s2, independent_method = prior(correlated=False).to_scenarios(0.1)
    assert correlated_method != independent_method
    assert "conservative" in correlated_method


# ---------------------------------------------------------------------------
# The solver's behaviour
# ---------------------------------------------------------------------------

def test_a_looser_reliability_target_never_gives_a_worse_rate():
    """Monotone in ``eps``: buying less reliability cannot buy less rate."""
    p = problem(required_fidelity=0.95)
    pr = prior()
    rates = []
    for eps in (0.5, 0.2, 0.1, 0.05, 0.01):
        report = chance_constrained_placement(p, pr, eps, max_repeaters=5)
        rates.append(report.nominal_rate_hz if report.placement else 0.0)
    assert rates == sorted(rates, reverse=True), rates


def test_an_unreachable_target_is_reported_as_unreachable():
    """A fidelity nobody can hit returns ``None``, not a layout that misses it.

    Relaxing the requirement to make the number look good is the failure this guards
    against; the honest answer is that the target is not reachable with this prior.
    """
    report = chance_constrained_placement(problem(required_fidelity=0.9999),
                                          prior(), 0.01, max_repeaters=5)
    assert report.placement is None
    assert "no layout meets" in report.describe()


def test_the_solution_is_feasible_under_every_constructed_scenario():
    """The claim the report makes, checked directly rather than trusted."""
    p = problem(required_fidelity=0.95)
    report = chance_constrained_placement(p, prior(), 0.05, max_repeaters=5)
    assert report.placement is not None
    for scenario in report.scenarios:
        fidelity = chain_quality(report.placement.positions_km, p,
                                 t1_s=scenario.t1_s, t2_s=scenario.t2_s).end_to_end_fidelity
        assert fidelity >= p.required_fidelity, (
            f"{scenario.name}: F={fidelity} below the requirement")


def test_the_reported_rate_is_the_nominal_one_at_the_returned_layout():
    """The objective is the nominal key rate, so the report must be self-consistent."""
    p = problem(required_fidelity=0.95)
    report = chance_constrained_placement(p, prior(), 0.1, max_repeaters=5)
    expected = chain_quality(report.placement.positions_km, p)
    assert report.nominal_rate_hz == pytest.approx(expected.key_rate_hz)
    assert report.nominal_fidelity == pytest.approx(expected.end_to_end_fidelity)


def test_the_result_reports_the_quantiles_it_committed_to():
    """A number without the assumption behind it is not interpretable."""
    report = chance_constrained_placement(problem(), prior(), 0.05, max_repeaters=5)
    assert report.scenarios
    assert report.achieved_at_quantile, "no per-scenario fidelity reported"
    for name, fidelity in report.achieved_at_quantile.items():
        assert 0.0 <= fidelity <= 1.0
        assert ":" in name, f"scenario {name!r} does not name its method"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_an_empty_prior_is_refused():
    with pytest.raises(ChanceConstraintError):
        CoherencePrior("x", t1_samples_s=np.array([]), t2_samples_s=np.array([]))


def test_non_positive_coherence_times_are_refused():
    with pytest.raises(ChanceConstraintError):
        CoherencePrior("x", t1_samples_s=np.array([1.0, -1.0]),
                       t2_samples_s=np.array([1.0, 1.0]))


def test_a_correlated_prior_with_unpaired_samples_is_refused():
    """Paired samples are required, so mismatched lengths are a caller error."""
    with pytest.raises(ChanceConstraintError):
        CoherencePrior("x", t1_samples_s=np.array([1.0, 2.0, 3.0]),
                       t2_samples_s=np.array([1.0, 2.0]), correlated=True)


def test_eps_outside_the_unit_interval_is_refused():
    for bad in (0.0, 1.0, -0.1, 1.5):
        with pytest.raises(ChanceConstraintError):
            prior().to_scenarios(bad)


def test_an_alpha_outside_the_unit_interval_is_refused():
    for bad in (0.0, 1.0, -0.2):
        with pytest.raises(ChanceConstraintError):
            prior().quantiles(bad)


def test_no_scenarios_is_refused():
    with pytest.raises(ChanceConstraintError):
        robust_feasible_best(problem(), [], 5)


def test_a_single_scenario_case_reduces_to_the_deterministic_optimum():
    """With one scenario the chance-constrained answer must be the exact DP optimum.

    This is the check that the wrapper has not changed the underlying optimisation.
    """
    from quantumnet.topology.placement import best_placement

    p = problem(required_fidelity=0.95)
    scenario = Scenario("only", t1_s=2e-3, t2_s=1e-3)
    robust = robust_feasible_best(p, [scenario], 5)
    deterministic = best_placement(p, max_repeaters=5, t1_s=scenario.t1_s,
                                   t2_s=scenario.t2_s)
    assert robust is not None and deterministic is not None
    assert robust.positions_km == deterministic.positions_km
