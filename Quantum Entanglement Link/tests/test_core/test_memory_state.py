"""Quantum memory state machine tests.

The states exist to make contention decidable, so these test the *transitions*
and their legality rather than the data layout.  An illegal transition must
raise: silently corrupting the resource accounting is how a simulator ends up
allocating one memory to two protocols and reporting an impossible throughput.
"""

from __future__ import annotations

import pytest

from quantumnet.core.memory import (
    Entanglement,
    Memory,
    MemoryArray,
    MemoryError,
    MemoryState,
)


# ---------------------------------------------------------------------------
# Single-memory transitions
# ---------------------------------------------------------------------------

def test_a_new_memory_is_raw_and_available():
    m = Memory(0, node_id="A")
    assert m.state is MemoryState.RAW
    assert m.free and m.available
    assert m.entanglement is None
    assert m.current_fidelity(0.0) == 0.0


def test_entangle_moves_raw_to_entangled():
    m = Memory(0, node_id="A")
    held = m.entangle("B", 3, fidelity=0.9, at=1.0)
    assert m.state is MemoryState.ENTANGLED
    assert held.remote_node == "B" and held.remote_memory == 3
    # entangled but still claimable by a protocol
    assert m.available and not m.free


def test_entangling_an_entangled_memory_is_rejected():
    m = Memory(0, node_id="A")
    m.entangle("B", 0, 0.9, 0.0)
    with pytest.raises(MemoryError, match="already holds a pair"):
        m.entangle("B", 1, 0.9, 0.0)


def test_entangling_an_occupied_memory_is_rejected():
    m = Memory(0, node_id="A")
    m.occupy()
    with pytest.raises(MemoryError, match="OCCUPIED"):
        m.entangle("B", 0, 0.9, 0.0)


def test_occupy_preserves_the_entanglement():
    """Info must survive the transition, or committing loses the pair's data."""
    m = Memory(0, node_id="A")
    m.entangle("B", 7, 0.85, 2.0)
    m.occupy(reservation_id=42, until=9.0)
    assert m.state is MemoryState.OCCUPIED
    assert m.entanglement is not None
    assert m.entanglement.remote_memory == 7
    assert m.reservation_id == 42
    assert m.reserved_until == 9.0
    assert not m.available


def test_double_occupy_is_rejected():
    m = Memory(0, node_id="A")
    m.occupy(reservation_id=1)
    with pytest.raises(MemoryError, match="already OCCUPIED"):
        m.occupy(reservation_id=2)


def test_release_returns_to_entangled_when_a_pair_survives():
    m = Memory(0, node_id="A")
    m.entangle("B", 0, 0.9, 0.0)
    m.occupy()
    m.release()
    assert m.state is MemoryState.ENTANGLED
    assert m.entanglement is not None
    assert m.reservation_id is None and m.reserved_until is None


def test_release_returns_to_raw_when_no_pair_is_held():
    m = Memory(0, node_id="A")
    m.occupy()
    m.release()
    assert m.state is MemoryState.RAW
    assert m.entanglement is None


def test_releasing_a_non_occupied_memory_is_rejected():
    m = Memory(0, node_id="A")
    with pytest.raises(MemoryError, match="not OCCUPIED"):
        m.release()


def test_consume_takes_the_pair_and_frees_the_slot():
    """What a successful swap does to its two inputs."""
    m = Memory(0, node_id="A")
    m.entangle("B", 4, 0.8, 1.0)
    held = m.consume()
    assert held is not None and held.remote_memory == 4
    assert m.entanglement is None
    assert m.state is MemoryState.RAW
    assert m.consume() is None


def test_clear_is_always_legal():
    m = Memory(0, node_id="A")
    m.entangle("B", 0, 0.9, 0.0)
    m.occupy()
    m.clear()
    assert m.state is MemoryState.RAW and m.entanglement is None


def test_busy_count_tracks_occupations():
    m = Memory(0, node_id="A")
    assert m.busy_count == 0
    m.occupy()
    m.release()
    m.occupy()
    assert m.busy_count == 2


def test_negative_index_is_rejected():
    with pytest.raises(MemoryError, match="non-negative"):
        Memory(-1, node_id="A")


# ---------------------------------------------------------------------------
# Decay and expiry
# ---------------------------------------------------------------------------

def test_fidelity_decays_with_age_and_floors_at_one_quarter():
    m = Memory(0, node_id="A", t1_s=1.0, t2_s=1.0)
    m.entangle("B", 0, 1.0, 0.0)
    assert m.current_fidelity(0.0) == pytest.approx(1.0)
    mid = m.current_fidelity(1.0)
    assert 0.25 <= mid < 1.0
    assert m.current_fidelity(1e9) == pytest.approx(0.25, abs=1e-9)


def test_fidelity_query_for_negative_age_returns_stored_value():
    m = Memory(0, node_id="A")
    m.entangle("B", 0, 0.9, 5.0)
    assert m.current_fidelity(1.0) == pytest.approx(0.9)


def test_expiry_is_a_predicate_over_time():
    m = Memory(0, node_id="A", t1_s=1.0, t2_s=1.0, cutoff_fidelity=0.5)
    m.entangle("B", 0, 0.9, 0.0)
    assert not m.is_expired(0.0)
    assert m.is_expired(100.0)


def test_a_memory_without_a_pair_never_expires():
    assert not Memory(0, node_id="A").is_expired(1e12)


def test_states_are_comparable_to_their_string_values():
    """``str``-enum so state can be serialised and compared by name."""
    assert MemoryState.RAW == "raw"
    assert MemoryState.OCCUPIED.value == "occupied"


# ---------------------------------------------------------------------------
# MemoryArray
# ---------------------------------------------------------------------------

def test_array_starts_empty_of_pairs_and_fully_available():
    arr = MemoryArray("A", size=5)
    assert len(arr) == 5
    assert arr.capacity() == 5
    assert arr.available_count() == 5
    assert arr.free_count() == 5
    assert arr.occupied() == []


def test_array_iteration_is_index_ordered():
    arr = MemoryArray("A", size=4)
    assert [m.index for m in arr] == [0, 1, 2, 3]
    assert arr[2].index == 2


def test_reserve_takes_available_memories_in_index_order():
    arr = MemoryArray("A", size=4)
    got = arr.reserve(2, reservation_id=1)
    assert [m.index for m in got] == [0, 1]
    assert arr.available_count() == 2
    assert arr.occupied() == got


def test_reserve_is_all_or_nothing():
    """A partial grant would leave the caller holding an unusable half-link."""
    arr = MemoryArray("A", size=4)
    arr.reserve(3, reservation_id=1)
    assert arr.reserve(2, reservation_id=2) == []
    # and the failed attempt must not have consumed anything
    assert arr.available_count() == 1


def test_reserve_negative_count_is_rejected():
    with pytest.raises(MemoryError, match="negative"):
        MemoryArray("A", size=2).reserve(-1)


def test_reserve_of_zero_returns_nothing_and_changes_nothing():
    arr = MemoryArray("A", size=2)
    assert arr.reserve(0) == []
    assert arr.available_count() == 2


def test_release_frees_only_occupied_memories():
    arr = MemoryArray("A", size=3)
    got = arr.reserve(2, reservation_id=1)
    assert arr.release(got) == 2
    assert arr.available_count() == 3
    # releasing again is a no-op, not an error
    assert arr.release(got) == 0


def test_release_expired_clears_decayed_pairs():
    arr = MemoryArray("A", size=3, t1_s=1.0, t2_s=1.0, cutoff_fidelity=0.9)
    for m in arr:
        m.entangle("B", m.index, 0.95, at=0.0)
    assert arr.expiring(0.0) == []
    expired = arr.release_expired(100.0)
    assert len(expired) == 3
    assert all(m.state is MemoryState.RAW for m in arr)


def test_summary_counts_partition_the_capacity():
    arr = MemoryArray("A", size=4)
    arr.reserve(2, reservation_id=1)
    arr[2].entangle("B", 0, 0.9, 0.0)
    s = arr.summary()
    assert s["capacity"] == 4
    assert s["occupied"] == 2
    assert s["entangled"] == 1
    assert s["raw"] == 1
    assert s["raw"] + s["entangled"] + s["occupied"] == s["capacity"]


def test_zero_sized_array_is_legal_and_supplies_nothing():
    arr = MemoryArray("A", size=0)
    assert len(arr) == 0
    assert arr.reserve(1) == []


def test_negative_size_is_rejected():
    with pytest.raises(MemoryError, match="non-negative"):
        MemoryArray("A", size=-1)


def test_entanglement_record_is_a_plain_dataclass():
    e = Entanglement(remote_node="B", remote_memory=2, fidelity=0.9,
                     created_at=1.0)
    assert "B[2]" in e.describe()
