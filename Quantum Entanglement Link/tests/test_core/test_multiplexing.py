"""Explicit time-division multiplexing: slots, exclusivity, and attribution.

P1.2's documented gap was that multiplexing is modelled **statistically** --
``1 - (1-p)^M`` -- which is right for the rate and silent about *when*. Its own docstring
said the tighter treatment "belongs with the scheduling layer". These tests cover that
treatment, and they concentrate on the thing a statistical model structurally cannot do:
say that two demands are competing for the **same slot on the same link**.

The distinction is asserted directly rather than assumed, because "both models agree"
would be the wrong conclusion: they answer different questions.
"""

from __future__ import annotations

import pytest

from quantumnet.core.multiplexing import (
    MultiplexedLink,
    Slot,
    SlotAllocation,
    SlotAllocator,
    SlotError,
    statistical_gain,
)


def link(modes: int = 4, period_s: float = 1e-8) -> MultiplexedLink:
    return MultiplexedLink("A-B", modes=modes, pulse_period_s=period_s)


# ---------------------------------------------------------------------------
# The constraint the statistical model cannot express
# ---------------------------------------------------------------------------

def test_two_demands_cannot_hold_the_same_slot():
    """The core property, and the reason this module exists.

    Under ``1 - (1-p)^M`` both demands look fine, because that model has no notion of a
    specific slot being taken.
    """
    channel = link()
    first = channel.request("demand-1", start_time_s=0.0, count=2)
    second = channel.request("demand-2", start_time_s=0.0, count=2)
    assert first is not None and second is not None
    assert not first.overlaps(second), (
        f"{first.slots} and {second.slots} overlap; the same slot was granted twice")
    assert not (set(s.index for s in first.slots)
                & set(s.index for s in second.slots))


def test_a_second_demand_is_placed_after_the_first_not_refused():
    """Placement, not refusal -- the throughput difference from a yes/no model.

    The statistical model must answer yes or no for a whole request. Slot allocation can
    serve both demands back to back, which is what multiplexing actually buys.
    """
    channel = link(modes=1)
    first = channel.request("demand-1", start_time_s=0.0, count=1)
    second = channel.request("demand-2", start_time_s=0.0, count=1)
    assert second is not None
    assert second.start_index == first.start_index + 1


def test_an_exact_slot_request_is_refused_when_taken_rather_than_moved():
    """``allocate`` is all-or-nothing so a partial grant cannot be reported as delivery.

    Silently relocating an explicit request would hide the contention the caller asked to
    be told about.
    """
    allocator = SlotAllocator()
    assert allocator.allocate("L", 4, 2, "first") is not None
    assert allocator.allocate("L", 5, 2, "second") is None       # slot 5 is taken
    assert allocator.allocate("L", 6, 2, "second") is not None   # clear of it


def test_a_refusal_can_name_the_conflicting_holder():
    """A "no" that cannot be attributed is not actionable."""
    allocator = SlotAllocator()
    allocator.allocate("L", 0, 3, "demand-A")
    assert allocator.blocking_holder("L", 2, 1) == "demand-A"
    assert allocator.blocking_holder("L", 3, 2) is None


def test_slots_on_different_links_never_conflict():
    """Exclusivity is per link, not global. Conflating them would refuse valid work."""
    allocator = SlotAllocator()
    assert allocator.allocate("L1", 0, 4, "a") is not None
    assert allocator.allocate("L2", 0, 4, "b") is not None
    assert allocator.blocking_holder("L2", 0, 4) == "b"


# ---------------------------------------------------------------------------
# Release and occupancy
# ---------------------------------------------------------------------------

def test_released_slots_become_available_again():
    channel = link()
    first = channel.request("a", count=2)
    channel.allocator.release(first)
    assert channel.allocator.is_free(Slot("A-B", 0))
    assert channel.allocator.is_free(Slot("A-B", 1))


def test_releasing_an_unknown_allocation_is_ignored():
    """Idempotent release, so a double-free is not a crash."""
    allocator = SlotAllocator()
    stale = SlotAllocation(link="never-used", start_index=0, count=2, holder="x")
    allocator.release(stale)          # must not raise


def test_occupancy_is_zero_for_an_empty_window():
    """Guarded against a zero denominator: nan would propagate as a plausible number."""
    assert link().busy_fraction(1e-6) == 0.0
    assert link().allocator.occupancy("A-B", upto=0) == 0.0


def test_occupancy_counts_only_slots_inside_the_window():
    channel = link(modes=1, period_s=1e-8)
    channel.request("a", count=2)
    # A one-pulse window of one mode holds one slot, and it is taken.
    assert channel.busy_fraction(1e-8) == pytest.approx(1.0)
    # A wider window sees the same two slots spread thinly.
    assert channel.busy_fraction(4e-8) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Modes as slot supply, not a probability exponent
# ---------------------------------------------------------------------------

def test_more_modes_means_more_slots_per_second():
    assert link(modes=4).slots_per_second == pytest.approx(4 / 1e-8)
    assert link(modes=1).slots_per_second == pytest.approx(1 / 1e-8)
    assert link(modes=8).slots_per_second > link(modes=2).slots_per_second


def test_more_modes_serve_more_concurrent_demands_before_waiting():
    """The concrete meaning of M here: a bigger slot supply, not a bigger probability.

    The comparison must be on **time**, not on raw slot index. A slot index is a pulse
    position and does not depend on how many modes a period holds; what changes is when
    that slot occurs. My first version of this test compared indices and failed, because
    ``modes`` correctly leaves the index alone.
    """
    one = link(modes=1)
    four = link(modes=4)
    assert one.request("a", count=4).count == 4
    assert four.request("a", count=4).count == 4

    one_second = one.request("b", count=4)
    four_second = four.request("b", count=4)
    # Both demands land on the same slot *index*, but four modes reach it four times
    # sooner, so the same wall-clock window holds four times the work.
    assert one_second.start_index == four_second.start_index
    assert four.slot_time_s(four_second.start_index) < \
        one.slot_time_s(one_second.start_index)
    assert four.slots_per_second == pytest.approx(4 * one.slots_per_second)


def test_slot_times_are_monotone_and_scale_with_the_period():
    channel = link(modes=2, period_s=1e-8)
    times = [channel.slot_time_s(i) for i in range(5)]
    assert times == sorted(times)
    assert times[1] - times[0] == pytest.approx(1e-8 / 2)


# ---------------------------------------------------------------------------
# The statistical model, kept for comparison
# ---------------------------------------------------------------------------

def test_the_statistical_gain_is_one_minus_the_all_failed_probability():
    assert statistical_gain(0.5, 1) == pytest.approx(0.5)
    assert statistical_gain(0.5, 2) == pytest.approx(0.75)
    assert statistical_gain(0.5, 4) == pytest.approx(0.9375)
    # Saturating toward one, which is the property the photonic layer relies on.
    assert statistical_gain(0.5, 20) > 0.999
    assert statistical_gain(0.5, 20) < 1.0


def test_the_two_models_answer_different_questions():
    """Pinned so the comparison is not mistaken for agreement.

    ``statistical_gain`` is the probability that *some* mode succeeded. Slot allocation is
    whether a *specific* slot is free. A high statistical gain says nothing about whether
    a slot is available, so a test asserting they agree would be asserting a category
    error.
    """
    high = statistical_gain(0.9, 8)
    assert high > 0.99, "the statistical model reports near-certainty"
    channel = link(modes=1)                 # one slot per period: easily exhausted
    for demand in range(3):
        channel.request(f"d{demand}", count=1)
    assert channel.busy_fraction(1e-8) == pytest.approx(1.0), (
        "the slot model reports the window full while the statistical model reports "
        "near-certainty -- which is the point, not a contradiction")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_a_negative_slot_index_is_refused():
    with pytest.raises(SlotError):
        Slot("L", -1)


def test_a_zero_count_allocation_is_refused():
    with pytest.raises(SlotError):
        SlotAllocation(link="L", start_index=0, count=0, holder="x")


def test_an_allocation_of_zero_slots_is_refused():
    with pytest.raises(SlotError):
        SlotAllocator().allocate("L", 0, 0, "x")


def test_a_negative_start_index_is_refused():
    with pytest.raises(SlotError):
        SlotAllocator().allocate("L", -1, 1, "x")


@pytest.mark.parametrize("modes", [0, -1])
def test_invalid_mode_counts_are_refused(modes):
    with pytest.raises(SlotError):
        link(modes=modes)
    with pytest.raises(SlotError):
        statistical_gain(0.5, modes)


def test_a_non_positive_period_is_refused():
    with pytest.raises(SlotError):
        MultiplexedLink("L", modes=1, pulse_period_s=0.0)


def test_a_negative_start_time_is_refused():
    with pytest.raises(SlotError):
        link().request("a", start_time_s=-1e-9)


def test_a_non_positive_horizon_is_refused():
    with pytest.raises(SlotError):
        link().busy_fraction(0.0)


def test_a_probability_outside_the_unit_interval_is_refused():
    for bad in (-0.1, 1.1):
        with pytest.raises(SlotError):
            statistical_gain(bad, 2)
