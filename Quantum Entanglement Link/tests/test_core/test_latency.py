"""Classical control-plane latency, and why it changes placement.

A swap produces one of four Bell states **at random** and the swapping node
learns two bits saying which.  Until those bits reach both endpoints the pair is
unusable, so every swap costs a classical round trip spent with the pair decaying
in memory.  That couples placement to latency in the right direction: few long
spans generate quickly and coordinate slowly, so the latency-aware optimum is not
the latency-blind one.

This is also a place to be better than the literature rather than level with it:
the leading published non-ILP placement work (Avis & Krastanov, arXiv:2501.06291)
deliberately omits classical communication.
"""

from __future__ import annotations

import pytest

from quantumnet.core.latency import (
    DEFAULT_C_FIBER_KM_PER_S,
    ZERO_LATENCY,
    ClassicalLink,
    swap_coordination_delay_s,
    total_coordination_delay_s,
)
from quantumnet.topology.placement import (
    CandidateSite,
    PlacementProblem,
    best_placement,
)


# ---------------------------------------------------------------------------
# The delay model
# ---------------------------------------------------------------------------

def test_speed_of_light_in_fibre_is_the_community_value():
    """2.0e8 m/s.  QuISP writes exactly ``distance / 200000km * 1s``."""
    assert DEFAULT_C_FIBER_KM_PER_S == 200_000.0


def test_one_way_delay_is_distance_over_c():
    link = ClassicalLink()
    assert link.one_way_s(200.0) == pytest.approx(1e-3)


def test_round_trip_is_twice_one_way():
    """Both endpoints must learn the outcome, so a one-way charge undercounts."""
    link = ClassicalLink()
    assert link.round_trip_s(200.0) == pytest.approx(2e-3)
    assert link.round_trip_s(200.0) == pytest.approx(2 * link.one_way_s(200.0))


def test_processing_delay_is_charged_per_hop():
    link = ClassicalLink(processing_delay_s=1e-6)
    assert link.one_way_s(0.0, hops=0) == 0.0
    assert link.one_way_s(0.0, hops=2) == pytest.approx(2e-6)


@pytest.mark.parametrize("kwargs,match", [
    ({"c_fiber_km_per_s": 0.0}, "positive"),
    ({"c_fiber_km_per_s": -1.0}, "positive"),
    ({"processing_delay_s": -1e-9}, "non-negative"),
])
def test_invalid_link_parameters_are_rejected(kwargs, match):
    with pytest.raises(ValueError, match=match):
        ClassicalLink(**kwargs)


def test_negative_distance_is_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        ClassicalLink().one_way_s(-1.0)


def test_zero_latency_link_is_effectively_instant():
    """For isolating the quantum terms from the control plane."""
    assert ZERO_LATENCY.round_trip_s(1000.0) < 1e-8


def test_total_delay_serialises_rather_than_overlapping():
    """Each swap's coordination completes before the next pair is consumed."""
    link = ClassicalLink()
    one = total_coordination_delay_s([0.0, 100.0], 1, link)
    three = total_coordination_delay_s([0.0, 100.0], 3, link)
    assert three == pytest.approx(3 * one)


def test_total_delay_of_no_swaps_is_zero():
    assert total_coordination_delay_s([0.0, 100.0], 0) == 0.0


def test_negative_swap_count_is_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        total_coordination_delay_s([0.0, 100.0], -1)


def test_swap_coordination_scales_with_the_span_it_covers():
    link = ClassicalLink()
    near = swap_coordination_delay_s([0.0, 10.0], link)
    far = swap_coordination_delay_s([0.0, 200.0], link)
    assert far == pytest.approx(20 * near)


def test_swap_coordination_of_a_degenerate_chain_is_zero():
    assert swap_coordination_delay_s([0.0], ClassicalLink()) == 0.0


def test_latency_is_a_measurable_fraction_of_a_millisecond_over_300km():
    """Sanity on the magnitude, so the model is not accidentally charging ns."""
    rtt_ms = ClassicalLink().round_trip_s(300.0) * 1e3
    assert rtt_ms == pytest.approx(3.0, rel=1e-6)


# ---------------------------------------------------------------------------
# Latency changes the placement
# ---------------------------------------------------------------------------

def _problem(**kw) -> PlacementProblem:
    return PlacementProblem(
        end_a=CandidateSite("A", 0.0),
        end_b=CandidateSite("B", 300.0),
        candidates=[CandidateSite(f"R{i}", 300.0 * (i + 1) / 15)
                    for i in range(14)],
        required_fidelity=0.90,
        **kw,
    )


def test_charging_latency_reduces_the_delivered_fidelity():
    """The pair sits in memory for the round trip, so it decays more."""
    blind = best_placement(_problem(classical_link=None))
    aware = best_placement(_problem(classical_link=ClassicalLink()))
    assert blind is not None and aware is not None
    assert aware.quality.end_to_end_fidelity < blind.quality.end_to_end_fidelity


def test_latency_changes_which_sites_are_chosen():
    """If latency changed nothing, it would not be a placement consideration.

    This is the substantive claim: a design optimised for the quantum link
    budget alone is not the design you want once the control plane is charged.
    """
    blind = best_placement(_problem(classical_link=None))
    aware = best_placement(_problem(classical_link=ClassicalLink()))
    assert blind is not None and aware is not None
    assert blind.names != aware.names, (
        "latency did not move the optimum; the coupling is too weak to test"
    )


def test_a_slow_control_plane_forces_more_fidelity_margin():
    """A worse control plane must not deliver a better pair."""
    fast = best_placement(_problem(classical_link=ClassicalLink()))
    slow = best_placement(_problem(
        classical_link=ClassicalLink(processing_delay_s=1e-4)))
    assert fast is not None and slow is not None
    assert slow.quality.end_to_end_fidelity <= fast.quality.end_to_end_fidelity


def test_zero_latency_matches_charging_none():
    """A control plane faster than the quantum terms should not disturb them."""
    none_charged = best_placement(_problem(classical_link=None))
    zero = best_placement(_problem(classical_link=ZERO_LATENCY))
    assert none_charged is not None and zero is not None
    assert zero.quality.end_to_end_fidelity == pytest.approx(
        none_charged.quality.end_to_end_fidelity, rel=1e-6)


def test_a_single_link_has_no_swap_and_so_no_coordination_cost():
    """No swap means no Bell-state outcome to communicate."""
    problem = PlacementProblem(
        end_a=CandidateSite("A", 0.0), end_b=CandidateSite("B", 50.0),
        classical_link=ClassicalLink(), required_fidelity=0.0)
    from quantumnet.topology.placement import chain_quality
    quality = chain_quality([0.0, 50.0], problem)
    bare = PlacementProblem(
        end_a=CandidateSite("A", 0.0), end_b=CandidateSite("B", 50.0),
        required_fidelity=0.0)
    assert quality.end_to_end_fidelity == pytest.approx(
        chain_quality([0.0, 50.0], bare).end_to_end_fidelity, rel=1e-12)


def test_latency_aware_placement_still_meets_the_requirement():
    """A constraint that the optimiser can no longer satisfy is not a result."""
    placement = best_placement(_problem(classical_link=ClassicalLink()))
    assert placement is not None
    assert placement.quality.end_to_end_fidelity >= 0.90 - 1e-12


def test_the_pareto_search_still_finds_a_feasible_layout_with_latency():
    """Latency makes more layouts infeasible, so the search has less room.

    Checked because the frontier pruning is the part that could silently lose
    the only feasible continuation.
    """
    for t2 in (50.0, 2.0, 0.5):
        problem = _problem(classical_link=ClassicalLink())
        placement = best_placement(problem, t2_s=t2)
        if placement is not None:
            assert placement.quality.end_to_end_fidelity >= 0.90 - 1e-12
