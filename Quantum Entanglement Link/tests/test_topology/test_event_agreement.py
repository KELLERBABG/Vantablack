"""M1 acceptance: the event path and the closed-form path must agree.

For a contention-free route both paths model the same physics, so they must
return the same fidelity and the same swap times.  The closed-form
:func:`~quantumnet.topology.schedule.distribute` is the oracle; the event-driven
:func:`~quantumnet.topology.events.distribute_events` has to reproduce it.

This is the cheapest useful check in the project, because a disagreement means
one of the two is wrong and there is no third candidate to blame.  It is also
what makes the event path safe to build contention on top of later: an event
kernel whose answers already drift from the equation is not a foundation.
"""

from __future__ import annotations

import pytest

from quantumnet.topology.events import distribute_events
from quantumnet.topology.graph import (
    QuantumLink,
    QuantumNode,
    QuantumTopology,
)
from quantumnet.topology.routing import best_route
from quantumnet.topology.schedule import distribute


def _chain(n_nodes: int, spacing_km: float = 10.0,
           **link_kw) -> QuantumTopology:
    """A linear chain of nodes, one link between neighbours."""
    topo = QuantumTopology()
    for i in range(n_nodes):
        topo.add_node(QuantumNode(node_id=f"N{i}", x_km=i * spacing_km, y_km=0.0))
    for i in range(n_nodes - 1):
        topo.add_link(QuantumLink(
            a=f"N{i}", b=f"N{i+1}", length_km=spacing_km, **link_kw))
    return topo


# ---------------------------------------------------------------------------
# The agreement criterion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n_nodes", [2, 3, 4, 5, 6])
def test_event_and_closed_form_agree_on_fidelity(n_nodes):
    """Same topology, same route: the two paths must agree exactly."""
    topo = _chain(n_nodes)
    route = best_route(topo, "N0", f"N{n_nodes - 1}", max_hops=10)
    assert route is not None

    closed = distribute(topo, route)
    events = distribute_events(topo, route)

    assert events.final_fidelity == pytest.approx(closed.final_fidelity,
                                                  rel=1e-12, abs=1e-15)


@pytest.mark.parametrize("n_nodes", [3, 4, 5, 6])
def test_event_and_closed_form_agree_on_swap_times(n_nodes):
    topo = _chain(n_nodes)
    route = best_route(topo, "N0", f"N{n_nodes - 1}", max_hops=10)

    closed = distribute(topo, route)
    events = distribute_events(topo, route)

    assert len(events.swap_times) == len(closed.events)
    for got, want in zip(events.swap_times, closed.events):
        assert got == pytest.approx(want.time_s, rel=1e-12, abs=1e-18)


@pytest.mark.parametrize("n_nodes", [3, 4, 5, 6])
def test_event_and_closed_form_agree_on_swap_nodes(n_nodes):
    topo = _chain(n_nodes)
    route = best_route(topo, "N0", f"N{n_nodes - 1}", max_hops=10)

    closed = distribute(topo, route)
    events = distribute_events(topo, route)

    assert events.swap_nodes == [ev.node for ev in closed.events]


def test_agreement_holds_for_a_single_link():
    """Degenerate case: no swaps at all."""
    topo = _chain(2)
    route = best_route(topo, "N0", "N1")
    closed = distribute(topo, route)
    events = distribute_events(topo, route)
    assert events.final_fidelity == pytest.approx(closed.final_fidelity,
                                                  rel=1e-12)
    assert events.swap_times == []
    assert closed.events == []


@pytest.mark.parametrize("spacing_km", [1.0, 20.0, 60.0, 120.0])
def test_agreement_holds_across_loss_regimes(spacing_km):
    """Agreement must not depend on the route being short or high-fidelity."""
    topo = _chain(5, spacing_km=spacing_km)
    route = best_route(topo, "N0", "N4", max_hops=10)
    closed = distribute(topo, route)
    events = distribute_events(topo, route)
    assert events.final_fidelity == pytest.approx(closed.final_fidelity,
                                                  rel=1e-12, abs=1e-15)


def test_agreement_holds_with_short_memories():
    """Retune T1/T2 so decay is a large fraction of the answer, not a rounding."""
    topo = _chain(5, spacing_km=30.0)
    for node in topo.nodes.values():
        node.t1_s = 1e-3
        node.t2_s = 1e-3
    route = best_route(topo, "N0", "N4", max_hops=10)
    assert route is not None

    closed = distribute(topo, route)
    events = distribute_events(topo, route)
    # decay must actually be biting, or this test proves nothing
    undecayed = distribute(topo, route).final_fidelity
    assert undecayed < 1.0
    assert events.final_fidelity == pytest.approx(closed.final_fidelity,
                                                  rel=1e-12, abs=1e-15)


def test_models_the_same_decay_so_fidelity_is_below_pure_swap():
    """A guard that the agreement is not vacuous agreement on a broken model."""
    topo = _chain(4, spacing_km=50.0)
    for node in topo.nodes.values():
        node.t1_s = 1.0
        node.t2_s = 1.0
    route = best_route(topo, "N0", "N3", max_hops=10)
    from quantumnet.topology.routing import e2e_fidelity
    pure_swap = e2e_fidelity(route.link_fidelities, route.swap_order)
    events = distribute_events(topo, route)
    assert events.final_fidelity < pure_swap


# ---------------------------------------------------------------------------
# Kernel-driven properties
# ---------------------------------------------------------------------------

def test_swap_events_are_strictly_ordered_in_time():
    topo = _chain(6)
    route = best_route(topo, "N0", "N5", max_hops=10)
    events = distribute_events(topo, route)
    assert all(a < b for a, b in zip(events.swap_times, events.swap_times[1:]))


def test_event_count_matches_links_plus_swaps():
    topo = _chain(5)
    route = best_route(topo, "N0", "N4", max_hops=10)
    events = distribute_events(topo, route)
    n_links = len(route.path) - 1
    n_swaps = len(route.swap_order)
    assert events.events_run == n_links + n_swaps


def test_final_time_is_the_last_swap():
    topo = _chain(5)
    route = best_route(topo, "N0", "N4", max_hops=10)
    events = distribute_events(topo, route)
    assert events.t_end_s == pytest.approx(events.swap_times[-1])


def test_distribution_is_deterministic_across_runs():
    """Same input, same schedule, same answer -- the kernel's tie-break."""
    topo = _chain(5)
    route = best_route(topo, "N0", "N4", max_hops=10)
    first = distribute_events(topo, route)
    second = distribute_events(topo, route)
    assert first.final_fidelity == second.final_fidelity
    assert first.swap_times == second.swap_times
    assert first.swap_nodes == second.swap_nodes


def test_explicit_t_gen_shifts_the_timeline_but_not_the_fidelity():
    """``t_gen`` translates the whole schedule; it does not change decay.

    This is a real property of the model and worth pinning, because it is easy
    to assume the opposite.  Every segment is born at ``t_gen`` and consumed at
    ``t_gen + step*t_swap``, so a segment's age at consumption is
    ``step * t_swap`` -- the absolute offset cancels.  A longer generation wait
    therefore moves every timestamp but leaves the fidelity identical.
    """
    topo = _chain(4)
    route = best_route(topo, "N0", "N3", max_hops=10)

    slow = distribute_events(topo, route, t_gen_s=1.0)
    fast = distribute_events(topo, route, t_gen_s=1e-6)

    assert slow.swap_times[0] > fast.swap_times[0]
    assert slow.final_fidelity == pytest.approx(fast.final_fidelity, rel=1e-12)


def test_longer_swaps_cost_fidelity():
    """Decay is driven by elapsed time, which ``t_swap_s`` controls.

    The complement of the test above: the time that matters is the *interval*
    between a segment's birth and its consumption, so stretching the swap
    cadence must reduce the final fidelity.

    The regime has to be chosen so decay actually bites.  Short links keep the
    link fidelity high, and short memories make milliseconds significant; on a
    lossy 60 km chain the pair fidelity is already near its 1/4 floor and there
    is nothing left for decay to remove, so the effect vanishes.
    """
    topo = _chain(5, spacing_km=2.0)
    for node in topo.nodes.values():
        node.t1_s = 1e-5
        node.t2_s = 1e-5
    route = best_route(topo, "N0", "N4", max_hops=10)

    quick = distribute_events(topo, route, t_swap_s=1e-7)
    slow = distribute_events(topo, route, t_swap_s=1e-3)
    assert slow.final_fidelity < quick.final_fidelity

    # and the closed-form path must agree at both cadences
    for t_swap, events in ((1e-7, quick), (1e-3, slow)):
        closed = distribute(topo, route, t_swap_s=t_swap)
        assert events.final_fidelity == pytest.approx(closed.final_fidelity,
                                                      rel=1e-12)


def test_constrained_route_agrees_when_min_fidelity_bites():
    """Agreement must survive the router choosing a non-obvious path."""
    topo = _chain(6, spacing_km=40.0)
    route = best_route(topo, "N0", "N5", max_hops=10, min_fidelity=0.0)
    assert route is not None
    closed = distribute(topo, route)
    events = distribute_events(topo, route)
    assert events.final_fidelity == pytest.approx(closed.final_fidelity,
                                                  rel=1e-12, abs=1e-15)
    assert events.swap_nodes == [ev.node for ev in closed.events]
