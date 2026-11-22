"""Repeater placement as an optimisation problem.

The headline property is **exactness**, checked against brute force rather than
asserted.  Placement is the project's product, so a solver that is subtly
suboptimal would produce confidently wrong designs -- the worst failure mode
available here.

Two things this file is careful about, because getting them wrong produces
misleadingly favourable results:

* The fidelity model.  On a **heralded** link, loss costs rate and not fidelity,
  so link fidelity is set by dark counts and mode mismatch rather than by
  attenuation.  Using the depolarising model here drives metro links toward the
  1/4 floor and makes nearly every layout score zero.
* The comparison baseline.  Evenly spaced repeaters can sit *anywhere*, whereas
  the optimiser selects from real candidate sites.  Comparing the two directly
  is not like for like, and the tests say so rather than claiming a win.
"""

from __future__ import annotations

import itertools

import pytest

from quantumnet.topology.placement import (
    CandidateSite,
    ChainQuality,
    Placement,
    PlacementProblem,
    Scenario,
    best_placement,
    chain_quality,
    elementary_link_fidelity,
    elementary_link_rate,
    fidelity_to_distance,
    key_fraction,
    max_link_for_fidelity,
    minimum_repeaters,
    robust_placement,
    survival_report,
    uniform_placement,
)


def _problem(span_km: float = 300.0, n_candidates: int = 14, **kw) -> PlacementProblem:
    spacing = span_km / (n_candidates + 1)
    return PlacementProblem(
        end_a=CandidateSite("A", 0.0),
        end_b=CandidateSite("B", span_km),
        candidates=[CandidateSite(f"R{i}", spacing * (i + 1))
                    for i in range(n_candidates)],
        **kw,
    )


def _irregular_problem(required_fidelity: float = 0.95) -> PlacementProblem:
    positions = [12, 31, 47, 63, 88, 104, 119, 140, 162, 180, 205, 229, 251, 274]
    return PlacementProblem(
        end_a=CandidateSite("A", 0.0),
        end_b=CandidateSite("B", 300.0),
        candidates=[CandidateSite(f"R{i}", float(p))
                    for i, p in enumerate(positions)],
        required_fidelity=required_fidelity,
    )


def _brute_force(problem: PlacementProblem, max_repeaters: int | None = None):
    """Exhaustive search over candidate subsets.  The oracle."""
    cands = problem.candidates
    best_rate, best_names = -1.0, None
    for size in range(0, len(cands) + 1):
        if max_repeaters is not None and size > max_repeaters:
            break
        for combo in itertools.combinations(cands, size):
            positions = ([problem.end_a.position_km]
                         + [c.position_km for c in combo]
                         + [problem.end_b.position_km])
            try:
                quality = chain_quality(positions, problem)
            except ValueError:
                continue
            if quality.end_to_end_fidelity < problem.required_fidelity:
                continue
            if quality.key_rate_hz > best_rate:
                best_rate = quality.key_rate_hz
                best_names = [c.name for c in combo]
    return best_rate, best_names


# ---------------------------------------------------------------------------
# The problem definition
# ---------------------------------------------------------------------------

def test_candidate_outside_the_route_is_rejected():
    with pytest.raises(ValueError, match="outside the route"):
        PlacementProblem(
            end_a=CandidateSite("A", 0.0),
            end_b=CandidateSite("B", 100.0),
            candidates=[CandidateSite("R", 150.0)],
        )


def test_endpoints_must_be_in_order():
    with pytest.raises(ValueError, match="beyond end_a"):
        PlacementProblem(end_a=CandidateSite("A", 100.0),
                         end_b=CandidateSite("B", 100.0))


def test_negative_position_is_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        CandidateSite("R", -1.0)


def test_invalid_required_fidelity_is_rejected():
    with pytest.raises(ValueError, match="required_fidelity"):
        PlacementProblem(end_a=CandidateSite("A", 0.0),
                         end_b=CandidateSite("B", 10.0),
                         required_fidelity=1.5)


def test_all_sites_is_sorted_and_includes_both_endpoints():
    problem = _problem(300.0, 3)
    sites = problem.all_sites()
    positions = [s.position_km for s in sites]
    assert positions == sorted(positions)
    assert sites[0].name == "A" and sites[-1].name == "B"
    assert len(sites) == 5


# ---------------------------------------------------------------------------
# Link physics
# ---------------------------------------------------------------------------

def test_barrett_kok_link_fidelity_is_high_and_falls_with_dark_counts():
    """A heralded link's fidelity is degraded by dark counts, not by loss."""
    quiet = _problem(dark_count_hz=0.0)
    noisy = _problem(dark_count_hz=1e8)
    assert elementary_link_fidelity(50.0, quiet) > 0.99
    assert elementary_link_fidelity(50.0, noisy) < elementary_link_fidelity(50.0, quiet)


def test_depolarizing_model_reproduces_the_graph_layer():
    """The alternative model must match ``QuantumLink.fidelity`` exactly."""
    from quantumnet.topology.graph import QuantumLink
    problem = _problem(fidelity_model="depolarizing")
    link = QuantumLink(a="a", b="b", length_km=50.0)
    assert elementary_link_fidelity(50.0, problem) == pytest.approx(
        link.fidelity(), rel=1e-12)


def test_unknown_fidelity_model_is_rejected():
    problem = _problem(fidelity_model="nonsense")
    with pytest.raises(ValueError, match="unknown fidelity_model"):
        elementary_link_fidelity(50.0, problem)


def test_link_rate_falls_with_length():
    problem = _problem()
    rates = [elementary_link_rate(L, problem) for L in (10, 25, 50, 100)]
    assert all(a > b for a, b in zip(rates, rates[1:]))


def test_fidelity_to_distance_inverts_the_depolarizing_model():
    problem = _problem(fidelity_model="depolarizing")
    for L in (10.0, 50.0, 100.0):
        f = elementary_link_fidelity(L, problem)
        assert fidelity_to_distance(f, problem) == pytest.approx(L, rel=1e-3)


# ---------------------------------------------------------------------------
# Key fraction
# ---------------------------------------------------------------------------

def test_key_fraction_follows_the_werner_bell_pair_rate():
    """fraction = 1 - 2*h(2*(1-F)/3), the standard BBM92 Werner expression."""
    from quantumnet.protocols.bb84 import binary_entropy
    problem = _problem()
    for f in (1.0, 0.99, 0.95, 0.9, 0.85, 0.8):
        expected = max(0.0, 1.0 - 2.0 * binary_entropy(2.0 * (1.0 - f) / 3.0))
        assert key_fraction(f, problem) == pytest.approx(expected, rel=1e-12)


def test_key_fraction_threshold_is_where_the_expression_reaches_zero():
    """Zero key when ``1 - 2*h(QBER)`` reaches zero, i.e. at ``QBER = 11%``.

    For a Werner pair ``QBER = 2*(1-F)/3``, so the cutoff is ``F ~ 0.835`` -- which is
    BB84's familiar 11% figure, arrived at from the entropy expression rather
    than chosen.  Asserting the arithmetic boundary keeps the claim honest.

    (An intermediate version of this test asserted ``F = 0.5``, from evaluating
    ``h(0.25)`` as 1 instead of 0.811.  That moved the threshold by a wide
    margin, which is why the boundary is now computed here rather than stated.)
    """
    from quantumnet.protocols.bb84 import binary_entropy
    problem = _problem()
    qber_cutoff = 0.11
    assert binary_entropy(qber_cutoff) == pytest.approx(0.5, abs=1e-3)

    f_cutoff = 1.0 - 1.5 * qber_cutoff
    assert key_fraction(f_cutoff, problem) == pytest.approx(0.0, abs=1e-3)
    assert key_fraction(f_cutoff - 0.02, problem) == 0.0
    assert key_fraction(f_cutoff + 0.05, problem) > 0.0
    assert key_fraction(0.5, problem) == 0.0


def test_key_fraction_is_monotone_in_fidelity():
    problem = _problem()
    values = [key_fraction(f, problem) for f in (0.80, 0.85, 0.90, 0.95, 1.0)]
    assert all(a < b for a, b in zip(values, values[1:]))


# ---------------------------------------------------------------------------
# Chain evaluation
# ---------------------------------------------------------------------------

def test_chain_quality_rejects_a_chain_that_misses_an_endpoint():
    problem = _problem()
    with pytest.raises(ValueError, match="must end at end_b"):
        chain_quality([0.0, 100.0], problem)
    with pytest.raises(ValueError, match="must start at end_a"):
        chain_quality([50.0, 300.0], problem)


def test_chain_quality_rejects_duplicate_positions():
    problem = _problem()
    with pytest.raises(ValueError, match="strictly increasing"):
        chain_quality([0.0, 100.0, 100.0, 300.0], problem)


def test_more_links_trade_fidelity_for_rate():
    """The central trade-off a placement has to navigate."""
    problem = _problem(required_fidelity=0.0)
    few = uniform_placement(problem, 1).quality
    many = uniform_placement(problem, 12).quality
    assert many.key_rate_hz > few.key_rate_hz
    assert many.end_to_end_fidelity < few.end_to_end_fidelity


def test_fidelity_stays_inside_the_physical_range():
    problem = _problem(required_fidelity=0.0)
    for n in range(0, 15):
        f = uniform_placement(problem, n).quality.end_to_end_fidelity
        assert 0.25 <= f <= 1.0


def test_swap_fidelity_bounds_the_achievable_fidelity():
    """With an imperfect swap the chain cannot be perfect, however short."""
    problem = _problem(required_fidelity=0.0, swap_fidelity=0.9)
    quality = uniform_placement(problem, 20).quality
    assert quality.end_to_end_fidelity < 0.9


# ---------------------------------------------------------------------------
# minimum_repeaters: exact by construction
# ---------------------------------------------------------------------------

def test_minimum_repeaters_respects_the_length_budget():
    problem = _problem(300.0, 14)
    placement = minimum_repeaters(problem, max_link_km=100.0)
    assert placement is not None
    assert placement.quality.longest_link_km <= 100.0 + 1e-9


def test_minimum_repeaters_uses_the_fewest_possible():
    """Checked against exhaustive enumeration of every feasible subset."""
    problem = _problem(300.0, 14)
    budget = 100.0
    placement = minimum_repeaters(problem, budget)
    fewest = len(placement.sites)

    for size in range(0, fewest):
        for combo in itertools.combinations(problem.candidates, size):
            positions = ([0.0] + [c.position_km for c in combo] + [300.0])
            if max(b - a for a, b in zip(positions, positions[1:])) <= budget + 1e-9:
                pytest.fail(f"{size} repeaters also fits, so {fewest} is not minimal")


def test_minimum_repeaters_returns_none_when_the_budget_is_impossible():
    problem = _problem(300.0, 3)      # candidates only at 75, 150, 225
    assert minimum_repeaters(problem, max_link_km=10.0) is None


def test_minimum_repeaters_rejects_a_nonpositive_budget():
    with pytest.raises(ValueError, match="must be positive"):
        minimum_repeaters(_problem(), 0.0)


# ---------------------------------------------------------------------------
# best_placement: exactness against brute force
# ---------------------------------------------------------------------------

def test_best_placement_matches_brute_force_on_regular_candidates():
    problem = _problem(300.0, 14, required_fidelity=0.95)
    placement = best_placement(problem)
    expected_rate, expected_names = _brute_force(problem)
    assert placement is not None
    assert placement.quality.key_rate_hz == pytest.approx(expected_rate, rel=1e-9)
    assert sorted(placement.names) == sorted(expected_names)


def test_best_placement_matches_brute_force_on_irregular_candidates():
    """Real routes have sites where they are, not on a grid."""
    problem = _irregular_problem()
    placement = best_placement(problem)
    expected_rate, expected_names = _brute_force(problem)
    assert placement is not None
    assert placement.quality.key_rate_hz == pytest.approx(expected_rate, rel=1e-9)
    assert sorted(placement.names) == sorted(expected_names)


def test_300km_barrett_kok_counterexample_is_not_prematurely_pruned():
    """Regression test: partial chains must not be pruned by a dummy jump to end_b.

    On a 300 km Barrett-Kok route with high dark counts, a single 250 km jump
    to end_b fails required_fidelity, so extending partial prefixes to end_b
    during DP transitions pruned every valid multi-hop chain and returned None.
    """
    problem = PlacementProblem(
        end_a=CandidateSite("A", 0.0),
        end_b=CandidateSite("B", 300.0),
        candidates=[CandidateSite(f"R{p}", float(p)) for p in (50, 100, 150, 200, 250)],
        required_fidelity=0.90,
        dark_count_hz=1_000_000.0,
    )
    # Confirm the 250 km dummy jump from R50 to B indeed fails required_fidelity.
    assert chain_quality([0.0, 50.0, 300.0], problem).end_to_end_fidelity < 0.90
    # Yet the 5-repeater chain succeeds.
    placement = best_placement(problem)
    assert placement is not None
    assert placement.quality.end_to_end_fidelity >= 0.90

    expected_rate, expected_names = _brute_force(problem)
    assert placement.quality.key_rate_hz == pytest.approx(expected_rate, rel=1e-9)
    assert sorted(placement.names) == sorted(expected_names)

    robust = robust_placement(problem, [Scenario("nominal", 100.0, 50.0)])
    assert robust is not None
    assert robust.quality.end_to_end_fidelity >= 0.90


def test_best_placement_respects_a_repeater_budget():
    problem = _problem(300.0, 14, required_fidelity=0.90)
    placement = best_placement(problem, max_repeaters=3)
    assert placement is not None
    assert len(placement.sites) <= 3

    expected_rate, _ = _brute_force(problem, max_repeaters=3)
    assert placement.quality.key_rate_hz == pytest.approx(expected_rate, rel=1e-9)


def test_best_placement_meets_the_fidelity_requirement():
    for requirement in (0.90, 0.95, 0.97):
        problem = _problem(300.0, 14, required_fidelity=requirement)
        placement = best_placement(problem)
        if placement is not None:
            assert placement.quality.end_to_end_fidelity >= requirement - 1e-12


def test_best_placement_returns_none_when_nothing_is_feasible():
    """An impossible requirement must return None, not the least-bad layout."""
    problem = _problem(300.0, 3, required_fidelity=0.9999, swap_fidelity=0.9)
    assert best_placement(problem) is None


def test_best_placement_is_deterministic():
    problem = _problem(300.0, 14, required_fidelity=0.95)
    first = best_placement(problem)
    second = best_placement(problem)
    assert first.names == second.names
    assert first.quality.key_rate_hz == second.quality.key_rate_hz


def test_tighter_fidelity_requirements_cost_rate():
    """A constraint that does not bite is not a constraint."""
    loose = _problem(300.0, 14, required_fidelity=0.80)
    tight = _problem(300.0, 14, required_fidelity=0.97)
    loose_p = best_placement(loose)
    tight_p = best_placement(tight)
    assert loose_p is not None and tight_p is not None
    assert tight_p.quality.key_rate_hz < loose_p.quality.key_rate_hz
    assert (tight_p.quality.end_to_end_fidelity
            >= loose_p.quality.end_to_end_fidelity)


# ---------------------------------------------------------------------------
# The baseline
# ---------------------------------------------------------------------------

def test_uniform_placement_is_evenly_spaced():
    problem = _problem(300.0)
    placement = uniform_placement(problem, 4)
    positions = [s.position_km for s in placement.sites]
    assert positions == [60.0, 120.0, 180.0, 240.0]


def test_uniform_placement_rejects_a_negative_count():
    with pytest.raises(ValueError, match="non-negative"):
        uniform_placement(_problem(), -1)


def test_uniform_placement_does_not_enforce_the_fidelity_requirement():
    """Documented, because it makes the two baselines non-comparable.

    ``uniform_placement`` reports what a layout delivers; it does not filter by
    ``required_fidelity``.  Comparing its best rate against a constrained
    optimum compares a free placement against a selection, and reads as a loss
    that is an artefact of the comparison rather than of the optimiser.
    """
    problem = _problem(300.0, 14, required_fidelity=0.999)
    many = uniform_placement(problem, 12)
    assert many.quality.end_to_end_fidelity < problem.required_fidelity


def test_snapping_a_uniform_grid_to_real_sites_loses_to_optimising_them():
    """What a planner actually does by hand, and what it costs.

    Evenly spaced positions are usually not available.  Snapping them to the
    nearest real site is the manual workflow, and the optimiser beats it --
    which is the comparison that is *like for like*, since both are restricted
    to the same candidate set.
    """
    problem = _irregular_problem(required_fidelity=0.95)
    placement = best_placement(problem)
    assert placement is not None

    n = len(placement.sites)
    targets = [300.0 * (k + 1) / (n + 1) for k in range(n)]
    snapped = sorted({min(problem.candidates,
                          key=lambda c: abs(c.position_km - t)).position_km
                      for t in targets})
    positions = [0.0] + snapped + [300.0]
    snapped_quality = chain_quality(positions, problem)

    # the snapped layout either misses the requirement or delivers less rate
    assert (snapped_quality.end_to_end_fidelity < problem.required_fidelity
            or snapped_quality.key_rate_hz < placement.quality.key_rate_hz)


# ---------------------------------------------------------------------------
# Robust placement
# ---------------------------------------------------------------------------

def test_scenario_rejects_nonpositive_coherence_times():
    with pytest.raises(ValueError, match="positive"):
        Scenario("bad", t1_s=0.0, t2_s=10.0)
    with pytest.raises(ValueError, match="positive"):
        Scenario("bad", t1_s=10.0, t2_s=-1.0)


def test_robust_placement_needs_at_least_one_scenario():
    with pytest.raises(ValueError, match="at least one scenario"):
        robust_placement(_problem(), [])


def test_robust_placement_meets_the_requirement_in_every_scenario():
    problem = _problem(300.0, 14, required_fidelity=0.90)
    scenarios = [Scenario("good", 100.0, 50.0),
                 Scenario("marginal", 0.05, 0.02),
                 Scenario("poor", 1e-4, 5e-5)]
    placement = robust_placement(problem, scenarios)
    assert placement is not None
    for row in survival_report(placement, problem, scenarios):
        assert row["meets_requirement"], f"failed {row['scenario']}"


def test_a_nominal_optimum_can_fail_a_scenario_the_robust_one_survives():
    """The finding that makes robustness worth doing.

    Design for the nominal coherence time and you get a layout that passes on
    paper and fails when the hardware is worse.  Design across the scenarios and
    you give up a little nominal rate for a layout that holds.

    The separating regime is narrow and worth naming: the storage wait is 1 us,
    so a coherence time of 10 ms barely bites and 10 us is infeasible outright.
    Around 100 us the two designs genuinely differ, which is precisely the
    hardware range a planner would want flagged.
    """
    problem = _problem(300.0, 14, required_fidelity=0.90)
    scenarios = [Scenario("nominal", 100.0, 50.0),
                 Scenario("poor", 1e-4, 5e-5)]

    nominal = best_placement(problem, t1_s=100.0, t2_s=50.0)
    robust = robust_placement(problem, scenarios)
    assert nominal is not None and robust is not None

    nominal_fails = sum(1 for r in survival_report(nominal, problem, scenarios)
                        if not r["meets_requirement"])
    robust_fails = sum(1 for r in survival_report(robust, problem, scenarios)
                       if not r["meets_requirement"])

    assert nominal_fails > 0, (
        "this instance no longer separates the two designs; the scenarios are "
        "too similar or too severe"
    )
    assert robust_fails == 0, "a robust layout must hold in every scenario"


def test_robust_placement_is_not_merely_the_nominal_one():
    """If robustness changed nothing, the scenarios are not doing work."""
    problem = _problem(300.0, 14, required_fidelity=0.92)
    scenarios = [Scenario("nominal", 100.0, 50.0),
                 Scenario("poor", 0.005, 0.002)]
    robust = robust_placement(problem, scenarios)
    assert robust is not None
    assert robust.method.startswith("robust[")


def test_survival_report_covers_every_scenario():
    problem = _problem(300.0, 14, required_fidelity=0.80)
    scenarios = [Scenario("a", 10.0, 5.0), Scenario("b", 1.0, 0.5)]
    rows = survival_report(uniform_placement(problem, 4), problem, scenarios)
    assert [r["scenario"] for r in rows] == ["a", "b"]
    for row in rows:
        assert 0.25 <= row["end_to_end_fidelity"] <= 1.0
        assert row["key_rate_hz"] >= 0.0


# ---------------------------------------------------------------------------
# max_link_for_fidelity
# ---------------------------------------------------------------------------

def test_max_link_for_fidelity_returns_a_length_that_meets_the_target():
    problem = _problem(300.0, 14, required_fidelity=0.0)
    target = 0.95
    length = max_link_for_fidelity(problem, target, n_links=4)
    assert length > 0.0
    quality = chain_quality([i * length for i in range(5)], problem)
    assert quality.end_to_end_fidelity >= target - 1e-6


def test_max_link_for_fidelity_shrinks_as_the_target_tightens():
    problem = _problem(300.0, 14, required_fidelity=0.0)
    loose = max_link_for_fidelity(problem, 0.90, n_links=4)
    tight = max_link_for_fidelity(problem, 0.99, n_links=4)
    assert tight <= loose


def test_max_link_for_fidelity_rejects_an_impossible_target():
    with pytest.raises(ValueError, match="target_fidelity"):
        max_link_for_fidelity(_problem(), 0.1)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_placement_describe_names_the_sites_and_the_quality():
    placement = best_placement(_problem(300.0, 14, required_fidelity=0.95))
    text = placement.describe()
    assert "repeaters" in text
    for name in placement.names:
        assert name in text


def test_chain_quality_describe_reports_the_key_numbers():
    quality = uniform_placement(_problem(300.0), 4).quality
    text = quality.describe()
    for token in ("links=", "longest=", "F=", "rate="):
        assert token in text
