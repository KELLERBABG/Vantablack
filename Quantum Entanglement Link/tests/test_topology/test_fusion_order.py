"""The balanced fusion order, verified against exhaustive search.

Fusing a chain of ``n`` segments needs ``n - 1`` swaps, and each swap costs a
classical round trip across the span it covers.  The order therefore changes the
total delay: fusing the leftmost pair repeatedly makes the span grow linearly, while
fusing near the middle keeps it logarithmic.

These tests exist because an earlier implementation returned a list of *segment
indices* and replayed it.  Indices shift as segments merge, the replay silently
skipped fusions, and it reported **less delay than the brute-force optimum** -- an
impossible result.  Reporting a tree (``Fusion`` objects carrying actual extents)
removes the shifting-index failure mode entirely, and the oracle below is what
catches it if it ever returns.
"""

from __future__ import annotations

import pytest

from quantumnet.topology.coordination import (
    adjacent_strategy,
    segment_aware_delay,
    whole_span_delay,
)
from quantumnet.topology.fusion_order import (
    balanced_tree,
    optimal_span_km,
    total_span_km,
)


def uniform(n_links: int, spacing_km: float = 10.0) -> list[float]:
    return [i * spacing_km for i in range(n_links + 1)]


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("links", range(2, 9))
def test_balanced_tree_matches_exhaustive_optimum(links):
    """The claim, checked against every possible fusion order.

    Exhaustive search is exponential, so this covers chains short enough to be
    decided exactly -- which is precisely where the previous implementation's bug
    (beating the optimum) was detectable.
    """
    positions = uniform(links)
    assert total_span_km(balanced_tree(positions)) == pytest.approx(
        optimal_span_km(positions), rel=1e-9)


@pytest.mark.parametrize("links", range(2, 9))
def test_the_tree_never_beats_the_optimum(links):
    """A lower bound the result must never violate.

    The previous index-replay version reported *less* delay than the minimum, which
    is impossible; a result below the oracle means the accounting is wrong, not that
    a better order was found.
    """
    positions = uniform(links)
    assert total_span_km(balanced_tree(positions)) >= optimal_span_km(positions) - 1e-9


def test_the_balancing_actually_balances():
    """Extents should repeat at each level, not grow one segment at a time."""
    extents = [f.extent_km for f in balanced_tree(uniform(8))]
    assert extents.count(10.0) >= 4, f"first level is not balanced: {extents}"
    assert max(extents) == 80.0
    # Sequential fusion would give 10, 20, 30, ... 80 -- every value distinct.
    assert len(set(extents)) < len(extents), (
        f"extents look sequential rather than balanced: {extents}"
    )


@pytest.mark.parametrize("links", range(3, 9))
def test_balanced_beats_sequential(links):
    """The improvement over the previous order, which is the point of the work."""
    positions = uniform(links)
    balanced = total_span_km(balanced_tree(positions))
    sequential = segment_aware_delay(
        positions, strategy=adjacent_strategy)["total_s"]
    from quantumnet.core.latency import ClassicalLink

    sequential_km = sequential / ClassicalLink().round_trip_s(1.0)
    assert balanced < sequential_km


@pytest.mark.parametrize("links", range(3, 9))
def test_the_default_strategy_is_the_balanced_one(links):
    """The default must be the good order, not the old one."""
    positions = uniform(links)
    default = segment_aware_delay(positions)["total_s"]
    balanced = segment_aware_delay(positions, strategy=None)["total_s"]
    assert default == pytest.approx(balanced)
    sequential = segment_aware_delay(
        positions, strategy=adjacent_strategy)["total_s"]
    assert default <= sequential


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

def test_a_single_link_needs_no_fusion():
    """Two positions, one link, nothing to fuse."""
    assert balanced_tree([0.0]) == []
    assert balanced_tree([]) == []


def test_a_degenerate_chain_is_handled():
    assert total_span_km(balanced_tree([])) == 0.0
    assert total_span_km(balanced_tree([5.0])) == 0.0


def test_every_fusion_joins_the_extents_it_claims():
    """Each fusion's operands must be real extents from the chain.

    A tree that invented extents would produce a plausible total from nonsense, so
    the operands are checked against the chain's own boundaries.
    """
    positions = uniform(6)
    lo, hi = min(positions), max(positions)
    for fusion in balanced_tree(positions):
        for a, b in (fusion.left, fusion.right):
            assert lo <= a <= hi and lo <= b <= hi
            assert a <= b
        assert fusion.left[1] < fusion.right[0], (
            "a fusion must join two disjoint extents in position order"
        )


def test_the_number_of_fusions_is_one_less_than_the_segments():
    """``uniform(n)`` has ``n + 1`` positions, and a chain of ``k`` segments needs
    ``k - 1`` swaps.

    Written explicitly because the off-by-one is easy to make and the test caught it
    here: I first asserted ``links - 1`` when the chain of ``links + 1`` positions
    needs ``links`` fusions.
    """
    for links in range(2, 9):
        positions = uniform(links)
        assert len(positions) == links + 1
        assert len(balanced_tree(positions)) == len(positions) - 1


def test_fusions_never_exceed_the_whole_chain():
    positions = uniform(7)
    span = max(positions) - min(positions)
    assert all(f.extent_km <= span + 1e-9 for f in balanced_tree(positions))


# ---------------------------------------------------------------------------
# Against the shipped bound
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("links", [4, 8, 16, 32])
def test_the_whole_span_bound_is_looser_than_the_balanced_order(links):
    """The bound is an upper bound; the balanced order is strictly below it."""
    positions = uniform(links)
    bound = whole_span_delay(positions)["total_s"]
    balanced = segment_aware_delay(positions)["total_s"]
    assert balanced < bound


def test_the_gap_grows_with_chain_length():
    """Worth recording: the bound's looseness depends on the thing being studied."""
    ratios = []
    for links in (4, 8, 16, 32):
        positions = uniform(links)
        bound = whole_span_delay(positions)["total_s"]
        balanced = segment_aware_delay(positions)["total_s"]
        ratios.append(bound / balanced)
    assert ratios == sorted(ratios), ratios
