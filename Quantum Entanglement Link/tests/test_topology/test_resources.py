"""Resource management and contention tests.

The headline test is the acceptance criterion for resource management: **two
competing requests contend and exactly one is refused**.  That is a different
question from "does allocation work".  A manager that grants both requests has
no contention at all, and would make every multi-user network result wrong in
the optimistic direction -- which is the failure mode this module exists to
prevent.
"""

from __future__ import annotations

import pytest

from quantumnet.core.memory import MemoryState
from quantumnet.topology.resources import (
    NodeEntanglementManager,
    Reservation,
    ReservationState,
    ResourceError,
    ResourceManager,
    resolve_contention,
)


def _pair(size_a: int = 4, size_b: int = 4, **kw):
    """Two managers that can talk to each other."""
    return {"A": ResourceManager("A", size_a, **kw),
            "B": ResourceManager("B", size_b, **kw)}


def _request(mgr, initiator="A", responder="B", size=1, start=0.0, end=10.0,
             fidelity=0.9, priority=0, seq=1, identity=1):
    return mgr.request(Reservation(
        initiator=initiator, responder=responder, start_time=start,
        end_time=end, memory_size=size, target_fidelity=fidelity,
        priority=priority, arrival_seq=seq, identity=identity))


# ---------------------------------------------------------------------------
# The M3 acceptance criterion
# ---------------------------------------------------------------------------

def test_two_competing_requests_contend_and_exactly_one_is_refused():
    """The M3 acceptance test, stated as the plan states it."""
    managers = _pair(size_a=4, size_b=4)
    mgr = NodeEntanglementManager(managers)

    first = Reservation("A", "B", 0.0, 10.0, 4, 0.9, identity=1, arrival_seq=1)
    second = Reservation("A", "B", 0.0, 10.0, 4, 0.9, identity=2, arrival_seq=2)
    results = mgr.request_many([first, second])

    assert len(mgr.granted) == 1, "exactly one request must be granted"
    assert len(mgr.refused) == 1, "exactly one request must be refused"
    states = sorted(r.state.value for r in results)
    assert states == ["active", "rejected"]
    # the refusal must say why, not just fail
    assert mgr.refused[0].reason
    assert "memories available" in mgr.refused[0].reason


def test_both_requests_succeed_when_capacity_allows():
    """A control: the refusal above must be caused by contention, not a bug."""
    managers = _pair(size_a=4, size_b=4)
    mgr = NodeEntanglementManager(managers)
    a = Reservation("A", "B", 0.0, 10.0, 2, 0.9, identity=1, arrival_seq=1)
    b = Reservation("A", "B", 0.0, 10.0, 2, 0.9, identity=2, arrival_seq=2)
    mgr.request_many([a, b])
    assert len(mgr.granted) == 2 and not mgr.refused
    assert managers["A"].memory_array.available_count() == 0


def test_contention_is_decided_by_priority_not_arrival_order():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    low = Reservation("A", "B", 0.0, 10.0, 4, 0.9, priority=0,
                      identity=1, arrival_seq=1)
    high = Reservation("A", "B", 0.0, 10.0, 4, 0.9, priority=9,
                       identity=2, arrival_seq=2)
    mgr.request_many([low, high])
    assert [r.identity for r in mgr.granted] == [2]
    assert [r.identity for r in mgr.refused] == [1]


def test_equal_priority_falls_back_to_arrival_order():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    first = Reservation("A", "B", 0.0, 10.0, 4, 0.9, priority=1,
                        identity=1, arrival_seq=1)
    second = Reservation("A", "B", 0.0, 10.0, 4, 0.9, priority=1,
                         identity=2, arrival_seq=2)
    # supplied in the wrong order on purpose
    mgr.request_many([second, first])
    assert [r.identity for r in mgr.granted] == [1]


def test_resolve_contention_is_deterministic_regardless_of_input_order():
    """The tie-break must not depend on how the caller built the list."""
    a = Reservation("A", "B", 0.0, 1.0, 1, 0.9, priority=0,
                    identity=1, arrival_seq=1)
    b = Reservation("A", "B", 0.0, 1.0, 1, 0.9, priority=5,
                    identity=2, arrival_seq=2)
    c = Reservation("A", "B", 0.0, 1.0, 1, 0.9, priority=0,
                    identity=3, arrival_seq=3)
    assert [r.identity for r in resolve_contention([a, b, c])] == [2, 1, 3]
    assert [r.identity for r in resolve_contention([c, b, a])] == [2, 1, 3]


# ---------------------------------------------------------------------------
# Both ends must agree
# ---------------------------------------------------------------------------

def test_a_request_needs_memories_at_both_ends():
    managers = _pair(size_a=4, size_b=2)
    mgr = NodeEntanglementManager(managers)
    r = Reservation("A", "B", 0.0, 10.0, 4, 0.9, identity=1, arrival_seq=1)
    assert mgr.request(r) is False
    assert r.state is ReservationState.REJECTED
    assert "B" in r.reason


def test_a_refused_request_leaks_no_memory_at_either_end():
    """Rollback, or a refusal would silently consume capacity."""
    managers = _pair(size_a=4, size_b=2)
    mgr = NodeEntanglementManager(managers)
    r = Reservation("A", "B", 0.0, 10.0, 4, 0.9, identity=1, arrival_seq=1)
    mgr.request(r)
    assert managers["A"].memory_array.available_count() == 4
    assert managers["B"].memory_array.available_count() == 2
    assert managers["A"].memory_array.occupied() == []


def test_commit_failure_rolls_back_the_already_granted_end():
    """If the second node cannot commit, the first must not keep the memory.

    Exercised by making the second node's array smaller *after* the availability
    check, which is the only way the two can disagree.
    """
    managers = _pair(size_a=4, size_b=4)
    mgr = NodeEntanglementManager(managers)
    original = managers["B"].grant

    def failing_grant(reservation):
        raise ResourceError("B hardware faulted")

    managers["B"].grant = failing_grant
    r = Reservation("A", "B", 0.0, 10.0, 2, 0.9, identity=1, arrival_seq=1)
    assert mgr.request(r) is False
    assert r.state is ReservationState.REJECTED
    assert "commit failed" in r.reason
    assert managers["A"].memory_array.available_count() == 4, "A leaked memory"
    managers["B"].grant = original


def test_request_for_an_unknown_node_is_rejected_with_a_reason():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    r = Reservation("A", "Z", 0.0, 10.0, 1, 0.9, identity=1, arrival_seq=1)
    assert mgr.request(r) is False
    assert "no resource manager" in r.reason


# ---------------------------------------------------------------------------
# Expiry: both the timeline and the physics
# ---------------------------------------------------------------------------

def test_sweeping_past_the_end_time_releases_the_memories():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    _request(mgr, size=4, start=0.0, end=5.0)
    assert managers["A"].memory_array.available_count() == 0

    expired = mgr.sweep(6.0)
    assert len(expired) == 2
    assert managers["A"].memory_array.available_count() == 4
    assert managers["A"].active == {}


def test_sweeping_before_the_end_time_changes_nothing():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    _request(mgr, size=2, start=0.0, end=10.0)
    assert mgr.sweep(1.0) == []
    assert managers["A"].memory_array.available_count() == 2


def test_a_pair_that_decays_is_released_early_not_held_to_the_deadline():
    """Early-expiry release: the reservation cannot be met, so free the slot.

    Protocol order matters and is itself enforced: a memory is entangled while
    still claimable, and only then committed to a reservation.  Attempting to
    entangle an already-OCCUPIED memory raises, which is what stops a protocol
    from overwriting a pair another request is relying on.
    """
    managers = _pair(t1_s=1.0, t2_s=1.0, cutoff_fidelity=0.9)
    mgr = NodeEntanglementManager(managers)

    # Entangle first, on both ends, then reserve the pairs.
    for node_id in ("A", "B"):
        managers[node_id].memory_array[0].entangle("peer", 0, 0.95, at=0.0)

    r = Reservation("A", "B", 0.0, 1000.0, 1, 0.9, identity=1, arrival_seq=1)
    assert mgr.request(r) is True
    assert managers["A"].memory_array[0].state is MemoryState.OCCUPIED

    expired = mgr.sweep(100.0)
    assert r in expired
    assert r.state is ReservationState.EXPIRED
    assert "decayed" in r.reason
    assert managers["A"].memory_array.available_count() == 4
    assert managers["A"].memory_array.occupied() == []


def test_release_after_early_completion_returns_memories():
    """A request that finishes early should not hold the slot to its end."""
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    r = Reservation("A", "B", 0.0, 100.0, 3, 0.9, identity=1, arrival_seq=1)
    mgr.request(r)
    # each manager frees only its own end; 3 here, not 6
    freed = managers["A"].release_reservation(r, ReservationState.FULFILLED)
    assert freed == 3
    assert managers["A"].memory_array.available_count() == 4
    assert r.state is ReservationState.FULFILLED
    assert 1 not in managers["A"].active


def test_releasing_at_one_node_leaves_the_other_end_intact():
    """``allocated`` is shared, so a release must not double-count."""
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    r = Reservation("A", "B", 0.0, 100.0, 3, 0.9, identity=1, arrival_seq=1)
    mgr.request(r)

    assert managers["A"].release_reservation(r) == 3
    assert managers["A"].memory_array.available_count() == 4
    # B still holds its end until B is told to release
    assert managers["B"].memory_array.available_count() == 1
    assert managers["B"].release_reservation(r) == 3
    assert managers["B"].memory_array.available_count() == 4
    assert r.allocated == {}


# ---------------------------------------------------------------------------
# Capacity accounting
# ---------------------------------------------------------------------------

def test_can_supply_does_not_count_a_decayed_pair_as_a_pair():
    """A stale pair must not be reported as a usable entangled resource.

    The distinction that matters: *availability* is about slots, so a freed slot
    legitimately counts again; but a decayed pair must never be handed to a
    caller as though it were still usable.
    """
    managers = _pair(size_a=2, t1_s=1.0, t2_s=1.0, cutoff_fidelity=0.9)
    arr = managers["A"].memory_array
    for m in arr:
        m.entangle("B", 0, 0.95, at=0.0)

    # at t=0 the pairs are good and the slots are genuinely usable
    assert managers["A"].can_supply(2, 0.0)
    assert len(arr.expiring(0.0)) == 0

    # much later every pair has decayed
    assert len(arr.expiring(1000.0)) == 2
    managers["A"].can_supply(2, 1000.0)
    # and none is still claiming to hold a usable pair
    assert all(m.entanglement is None for m in arr)
    assert all(m.state is MemoryState.RAW for m in arr)


def test_repeated_grant_and_sweep_conserves_memory():
    """A long run must not leak or invent memories."""
    managers = _pair(size_a=4, size_b=4)
    mgr = NodeEntanglementManager(managers)
    for cycle in range(20):
        start = cycle * 10.0
        r = Reservation("A", "B", start, start + 1.0, 4, 0.9,
                        identity=cycle + 1, arrival_seq=cycle + 1)
        assert mgr.request(r) is True
        mgr.sweep(start + 2.0)
        assert managers["A"].memory_array.available_count() == 4
        assert managers["B"].memory_array.available_count() == 4
        assert managers["A"].memory_array.occupied() == []


def test_summary_reports_the_whole_picture():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    _request(mgr, size=2)
    s = mgr.summary()
    assert s["granted"] == 1 and s["refused"] == 0
    assert s["nodes"]["A"]["occupied"] == 2
    assert s["nodes"]["A"]["available"] == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs,match", [
    ({"memory_size": -1}, "non-negative"),
    ({"start_time": 5.0, "end_time": 1.0}, "before it starts"),
    ({"target_fidelity": 1.5}, "target_fidelity"),
    ({"target_fidelity": -0.1}, "target_fidelity"),
])
def test_invalid_reservations_are_rejected(kwargs, match):
    base = dict(initiator="A", responder="B", start_time=0.0, end_time=10.0,
                memory_size=1, target_fidelity=0.9)
    base.update(kwargs)
    with pytest.raises(ResourceError, match=match):
        Reservation(**base)


def test_reservation_duration_and_nodes():
    r = Reservation("A", "B", 2.0, 7.0, 1, 0.9)
    assert r.duration == pytest.approx(5.0)
    assert r.nodes == ("A", "B")
    assert "A->B" in r.describe()


def test_zero_memory_reservation_is_granted_trivially():
    managers = _pair()
    mgr = NodeEntanglementManager(managers)
    r = Reservation("A", "B", 0.0, 10.0, 0, 0.9, identity=1, arrival_seq=1)
    assert mgr.request(r) is True
    assert managers["A"].memory_array.available_count() == 4
