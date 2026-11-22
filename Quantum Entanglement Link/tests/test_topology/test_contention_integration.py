"""Contention on the event timeline: M3 driving M1.

The point of this file is that resource management and the event kernel are not
two features that happen to coexist.  A demand is *decided at its start time*
against the capacity free at that moment, its distribution runs on the same
clock, and its memories come back at its end time.  Contention therefore changes
the timeline, and the timeline decides who was in time to get a memory.

A run that granted every demand would model one user at a time.  That is the
optimistic failure this integration exists to prevent.
"""

from __future__ import annotations

import pytest

from quantumnet.topology.events import simulate_demands
from quantumnet.topology.graph import QuantumNode, QuantumTopology
from quantumnet.topology.resources import (
    NodeEntanglementManager,
    Reservation,
    ReservationState,
    ResourceManager,
)


def _chain(n: int = 4, spacing_km: float = 10.0,
           memories: int = 2, **kw) -> tuple[QuantumTopology,
                                             NodeEntanglementManager]:
    topo = QuantumTopology()
    for i in range(n):
        topo.add_node(QuantumNode(node_id=f"N{i}", x_km=i * spacing_km,
                                  y_km=0.0))
    for i in range(n - 1):
        topo.connect(f"N{i}", f"N{i + 1}")
    managers = {f"N{i}": ResourceManager(f"N{i}", size=memories, **kw)
                for i in range(n)}
    return topo, NodeEntanglementManager(managers)


def _demand(a, b, size, priority=0, seq=1, start=0.0, end=5.0, fidelity=0.5):
    return Reservation(a, b, start, end, size, fidelity,
                       priority=priority, identity=seq, arrival_seq=seq)


# ---------------------------------------------------------------------------
# The M3 acceptance criterion, on the timeline
# ---------------------------------------------------------------------------

def test_competing_demands_on_the_same_link_yield_exactly_one_winner():
    """M3: two requests contend and exactly one is refused -- through the kernel."""
    topo, mgr = _chain(n=2, memories=2)
    demands = [_demand("N0", "N1", 2, seq=1), _demand("N0", "N1", 2, seq=2)]

    result = simulate_demands(topo, demands, mgr)

    assert len(result.granted) == 1
    assert len(result.refused) == 1
    assert result.refused[0].reservation.reason
    assert result.refused[0].rejected_at is not None


def test_without_contention_everything_is_granted():
    """The control: refusal above must be caused by contention, not a defect."""
    topo, mgr = _chain(n=4, memories=4)
    demands = [_demand("N0", "N1", 2, seq=1), _demand("N2", "N3", 2, seq=2)]

    result = simulate_demands(topo, demands, mgr)

    assert len(result.granted) == 2
    assert not result.refused


def test_a_granted_demand_delivers_a_fidelity_and_a_route():
    topo, mgr = _chain(n=4, memories=4)
    result = simulate_demands(topo, [_demand("N0", "N3", 1, seq=1)], mgr)

    assert len(result.granted) == 1
    outcome = result.granted[0]
    assert outcome.route is not None
    assert outcome.route.path == ["N0", "N1", "N2", "N3"]
    assert 0.0 < outcome.delivered_fidelity <= 1.0


def test_a_demand_that_cannot_be_granted_delivers_nothing():
    """A refusal must not report a fidelity, or it would look like a success."""
    topo, mgr = _chain(n=2, memories=2)
    demands = [_demand("N0", "N1", 2, seq=1), _demand("N0", "N1", 2, seq=2)]
    result = simulate_demands(topo, demands, mgr)

    for outcome in result.refused:
        assert outcome.delivered_fidelity == 0.0


# ---------------------------------------------------------------------------
# Arbitration reaches the timeline
# ---------------------------------------------------------------------------

def test_priority_decides_who_wins_the_contested_memory():
    topo, mgr = _chain(n=2, memories=2)
    low = _demand("N0", "N1", 2, priority=0, seq=1)
    high = _demand("N0", "N1", 2, priority=7, seq=2)

    result = simulate_demands(topo, [low, high], mgr)

    assert [o.reservation.identity for o in result.granted] == [2]
    assert [o.reservation.identity for o in result.refused] == [1]


def test_equal_priority_resolves_by_arrival_order():
    topo, mgr = _chain(n=2, memories=2)
    first = _demand("N0", "N1", 2, priority=1, seq=1)
    second = _demand("N0", "N1", 2, priority=1, seq=2)

    # supplied in reverse on purpose
    result = simulate_demands(topo, [second, first], mgr)

    assert [o.reservation.identity for o in result.granted] == [1]


def test_the_run_is_deterministic():
    """Same demands, same capacity, same answer -- twice."""
    def run():
        topo, mgr = _chain(n=3, memories=2)
        demands = [_demand("N0", "N2", 2, seq=1),
                   _demand("N0", "N2", 2, seq=2),
                   _demand("N1", "N2", 2, seq=3)]
        result = simulate_demands(topo, demands, mgr)
        return ([(o.granted, o.reservation.identity) for o in result.outcomes],
                result.t_end_s)

    assert run() == run()


# ---------------------------------------------------------------------------
# Time actually matters: a later demand can win because the earlier one
# released its memories
# ---------------------------------------------------------------------------

def test_a_sequential_demand_succeeds_after_the_first_releases():
    """Capacity is time-dependent, so ordering by time is the whole point.

    The second demand starts after the first ends, so the memories are free
    again even though the pool is far too small for both at once.
    """
    topo, mgr = _chain(n=2, memories=2)
    early = _demand("N0", "N1", 2, seq=1, start=0.0, end=1.0)
    later = _demand("N0", "N1", 2, seq=2, start=2.0, end=3.0)

    result = simulate_demands(topo, [early, later], mgr)

    assert len(result.granted) == 2
    assert not result.refused


def test_overlapping_demands_contend_where_sequential_ones_do_not():
    """The same two demands, overlapped, cannot both be served.

    Paired with the test above this isolates *time* as the cause: identical
    demands, identical capacity, different windows.
    """
    topo, mgr = _chain(n=2, memories=2)
    first = _demand("N0", "N1", 2, seq=1, start=0.0, end=5.0)
    second = _demand("N0", "N1", 2, seq=2, start=1.0, end=6.0)

    result = simulate_demands(topo, [first, second], mgr)

    assert len(result.granted) == 1
    assert len(result.refused) == 1


def test_memories_are_released_by_the_end_of_the_run():
    """A finished run must not leave the pool consumed."""
    topo, mgr = _chain(n=2, memories=2)
    simulate_demands(topo, [_demand("N0", "N1", 2, seq=1)], mgr)
    assert mgr.managers["N0"].memory_array.available_count() == 2
    assert mgr.managers["N1"].memory_array.available_count() == 2


def test_a_short_window_does_not_hold_memory_for_the_whole_run():
    """Capacity returns at the demand's end time, not at the horizon."""
    topo, mgr = _chain(n=2, memories=2)
    short = _demand("N0", "N1", 2, seq=1, start=0.0, end=1.0)
    long = _demand("N0", "N1", 2, seq=2, start=2.0, end=100.0)

    result = simulate_demands(topo, [short, long], mgr)
    assert len(result.granted) == 2


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------

def test_a_demand_between_disconnected_nodes_is_refused_with_a_reason():
    topo = QuantumTopology()
    # Two islands: A-B and C-D.  Positions are spaced so the auto-distance is
    # positive; a zero-length link is rejected by the graph itself.
    for i, name in enumerate(("A", "B", "C", "D")):
        topo.add_node(QuantumNode(node_id=name, x_km=i * 10.0, y_km=0.0))
    topo.connect("A", "B")
    topo.connect("C", "D")
    mgr = NodeEntanglementManager(
        {n: ResourceManager(n, size=2) for n in ("A", "B", "C", "D")})

    result = simulate_demands(topo, [_demand("A", "D", 1)], mgr)

    assert len(result.refused) == 1
    assert "no route" in result.refused[0].reservation.reason


def test_an_impossible_demand_does_not_break_the_run():
    """One bad demand must not prevent the others being served."""
    topo, mgr = _chain(n=4, memories=4)
    demands = [_demand("N0", "N9", 1, seq=1), _demand("N0", "N1", 1, seq=2)]

    result = simulate_demands(topo, demands, mgr)

    assert len(result.refused) == 1
    assert len(result.granted) == 1
    assert result.granted[0].reservation.identity == 2


def test_an_empty_demand_set_is_a_no_op():
    topo, mgr = _chain(n=2, memories=2)
    result = simulate_demands(topo, [], mgr)
    assert result.outcomes == []
    assert result.granted == [] and result.refused == []
    assert mgr.managers["N0"].memory_array.available_count() == 2


def test_more_demand_than_capacity_is_bounded_not_optimistic():
    """Many overlapping demands on a small pool: grants cannot exceed capacity."""
    topo, mgr = _chain(n=2, memories=2)
    demands = [_demand("N0", "N1", 1, seq=i, start=0.0, end=5.0)
               for i in range(1, 8)]

    result = simulate_demands(topo, demands, mgr)

    # each demand needs 1 memory at both ends; only 2 pairs fit
    assert len(result.granted) == 2
    assert len(result.refused) == 5
    assert len(result.granted) + len(result.refused) == len(demands)


def test_outcome_describe_is_readable_for_both_cases():
    topo, mgr = _chain(n=2, memories=2)
    result = simulate_demands(
        topo, [_demand("N0", "N1", 2, seq=1), _demand("N0", "N1", 2, seq=2)],
        mgr)
    text = result.describe()
    assert "GRANTED" in text and "REFUSED" in text
    assert "granted" in text and "refused" in text
