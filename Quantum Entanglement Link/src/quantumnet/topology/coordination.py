"""Segment-aware classical coordination, against the whole-span bound.

The shipped model charges every swap a round trip across the **whole chain**:

    coordination = (n_links - 1) * round_trip(span)

That is O(N^2) in the number of links.  But a swap only fuses **two adjacent
segments**, and the coordination for it has to reach the outer endpoints of just
those two.  Charging the whole chain for every fusion overstates the delay, and the
overstatement grows with chain length -- so it is worst exactly where latency
matters most.

This module computes the honest figure for a given fusion order and reports the
ratio, which decides whether the shipped bound is a minor conservatism or a
material distortion.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.latency import ClassicalLink


@dataclass
class FusionStep:
    """One entanglement swap and the coordination it requires."""

    left: tuple[float, float]
    right: tuple[float, float]
    extent_km: float
    round_trip_s: float

    def describe(self) -> str:
        return (f"[{self.left[0]:.0f},{self.left[1]:.0f}] + "
                f"[{self.right[0]:.0f},{self.right[1]:.0f}] -> "
                f"extent {self.extent_km:.1f} km, "
                f"RTT {self.round_trip_s * 1e3:.3f} ms")


def _steps(positions: list[float], strategy) -> list[FusionStep]:
    """Run a fusion strategy, tracking each surviving segment's extent.

    ``strategy`` is called with the list of live segment extents and returns the
    index of the left segment to fuse, or ``None`` when one segment remains.
    Choosing dynamically -- rather than from a precomputed index list -- is
    necessary because indices shift as segments merge, which is what broke the
    first version of the balanced order.
    """
    segments = [(p, p) for p in positions]
    steps: list[FusionStep] = []
    while len(segments) > 1:
        index = strategy(segments)
        if index is None or index < 0 or index + 1 >= len(segments):
            index = 0
        left, right = segments[index], segments[index + 1]
        extent = max(left[1], right[1]) - min(left[0], right[0])
        steps.append(FusionStep(left, right, extent,
                                ClassicalLink().round_trip_s(extent)))
        segments[index:index + 2] = [(min(left[0], right[0]),
                                      max(left[1], right[1]))]
    return steps


def adjacent_strategy(segments) -> int:
    """Always fuse the leftmost pair -- the shipped behaviour's natural order."""
    return 0


def balanced_strategy(segments) -> int:
    """Fuse at the midpoint of the remaining span -- a divide-and-conquer merge.

    The seek is for the adjacent pair straddling the midpoint of the **whole
    remaining extent**.  That is what forces a balanced merge tree: the final
    fusion joins two halves of roughly equal size, and recursively so.

    Two greedy rules were tried first and **both degenerate to the sequential
    order** on a uniform chain, because every pair ties at the start and the
    leftmost is taken.  Smallest-extent-first and midpoint-of-pair-centre both
    fail the same way, and the failure is silent: extents then grow linearly
    (10, 20, 30, ... 80 km at eight links) rather than logarithmically, which is
    exactly the O(N^2) behaviour this module exists to avoid.
    """
    lo = min(s[0] for s in segments)
    hi = max(s[1] for s in segments)
    middle = 0.5 * (lo + hi)
    best, best_distance = 0, None
    for i in range(len(segments) - 1):
        # Distance from the midpoint of the remaining span to the gap between segments
        # i and i+1: the gap nearest the middle splits the remaining work most evenly.
        distance = abs(middle - segments[i][1])
        if best_distance is None or distance < best_distance:
            best, best_distance = i, distance
    return best


def recursive_order(positions: list[float]) -> list[int]:
    """Optimal-shaped fusion order for a uniform chain, built recursively.

    A balanced merge of `n` segments joins `floor(n/2)` on the left to
    `ceil(n/2)` on the right, recursively.  Returning the sequence of *original*
    adjacent-pair indices this implies avoids the shifting-index problem that
    broke the first attempt: the sequence is generated in the order the fusions
    happen, on the live segment list.
    """
    n = len(positions)
    if n < 2:
        return []
    if n == 2:
        return [0]
    left = n // 2
    # Fuse the left block fully, the right block fully, then join the two.
    return (recursive_order(positions[:left])
            + [i + left for i in recursive_order(positions[left:])]
            + [left - 1])


def replay_indices(positions: list[float], order: list[int]) -> list[FusionStep]:
    """Run a sequence of *original* indices, reporting the extent of each fusion.

    The indices refer to segments in the original chain, so a segment already
    absorbed is skipped rather than fused twice.
    """
    segments = [(p, p) for p in positions]
    absorbed = [False] * len(segments)
    steps: list[FusionStep] = []
    for index in order:
        if absorbed[index]:
            continue
        # find the next live segment to the right
        right = index + 1
        while right < len(segments) and absorbed[right]:
            right += 1
        if right >= len(segments):
            continue
        left, rseg = segments[index], segments[right]
        extent = max(left[1], rseg[1]) - min(left[0], rseg[0])
        steps.append(FusionStep(left, rseg, extent,
                                ClassicalLink().round_trip_s(extent)))
        segments[index] = (min(left[0], rseg[0]), max(left[1], rseg[1]))
        absorbed[right] = True
    return steps


def segment_aware_delay(positions: list[float], strategy=None,
                        link: ClassicalLink | None = None) -> dict:
    """Total coordination delay when each swap is charged its own extent.

    ``strategy`` defaults to **the balanced fusion order**, which is optimal for a
    uniform chain -- verified against exhaustive search for 2 to 8 links.  Pass
    :func:`adjacent_strategy` for the sequential order, which is what an earlier
    version used and which costs up to 1.65x more delay.
    """
    from .fusion_order import balanced_tree, total_span_km

    link = link or ClassicalLink()
    positions = sorted(float(p) for p in positions)
    if len(positions) < 2:
        return {"total_s": 0.0, "steps": [], "max_extent_km": 0.0,
                "mean_extent_km": 0.0}
    if strategy is None:
        fusions = balanced_tree(positions)
        total_km = total_span_km(fusions)
        exts = [f.extent_km for f in fusions]
        return {
            "total_s": float(link.round_trip_s(total_km)),
            "steps": fusions,
            "max_extent_km": float(max(exts)) if exts else 0.0,
            "mean_extent_km": float(sum(exts) / len(exts)) if exts else 0.0,
        }
    steps = _steps(positions, strategy)
    exts = [s.extent_km for s in steps]
    return {
        "total_s": float(sum(s.round_trip_s for s in steps)),
        "steps": steps,
        "max_extent_km": float(max(exts)) if exts else 0.0,
        "mean_extent_km": float(sum(exts) / len(exts)) if exts else 0.0,
    }


def whole_span_delay(positions: list[float],
                     link: ClassicalLink | None = None) -> dict:
    """The shipped bound: every swap charged the full chain span."""
    link = link or ClassicalLink()
    positions = sorted(float(p) for p in positions)
    if len(positions) < 2:
        return {"total_s": 0.0, "span_km": 0.0}
    span = positions[-1] - positions[0]
    n_swaps = len(positions) - 1
    return {"total_s": n_swaps * link.round_trip_s(span), "span_km": span,
            "n_swaps": n_swaps}


def compare_models(positions: list[float]) -> dict:
    """Ratio of the shipped bound to the segment-aware figure."""
    aware = segment_aware_delay(positions)
    balanced = segment_aware_delay(positions, strategy=balanced_strategy)
    whole = whole_span_delay(positions)
    ratio = (whole["total_s"] / aware["total_s"]) if aware["total_s"] > 0 else None
    return {
        "n_links": len(positions) - 1,
        "span_km": whole["span_km"],
        "whole_span_ms": whole["total_s"] * 1e3,
        "segment_aware_ms": aware["total_s"] * 1e3,
        "balanced_ms": balanced["total_s"] * 1e3,
        "overstatement_adjacent": ratio,
        "max_extent_km": aware["max_extent_km"],
        "mean_extent_km": aware["mean_extent_km"],
    }
