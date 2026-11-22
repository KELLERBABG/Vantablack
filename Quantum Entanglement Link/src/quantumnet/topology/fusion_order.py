"""A divide-and-conquer fusion order for classical coordination.

The problem
-----------
Fusing a chain of ``n`` segments needs ``n - 1`` entanglement swaps.  Each swap
produces one of four Bell states at random, and **both outer endpoints of the two
segments being fused must be told which** before the pair can be used -- so each
swap costs a classical round trip across the span it covers, with the pair sitting
in memory meanwhile.

Which *order* the swaps happen in therefore changes the total delay: fusing the
leftmost pair repeatedly makes the span grow linearly (10, 20, 30, ... km), while
fusing near the middle keeps it logarithmic.

The failure this replaces
-------------------------
An earlier attempt returned a fusion *order* as a list of original segment indices,
then replayed it.  Indices shift as segments merge, so the replay skipped fusions --
and the bug was silent in the worst way: it reported **less delay than the
brute-force optimum**, which is impossible.  A list of indices is the wrong
representation for this problem; what is needed is a *tree*, and this module builds
one.

Brute force over all orders is exponential, which is fine as an oracle for small
chains and useless at scale.  The published optimum for a uniform chain is a
balanced merge, so that is what is constructed here -- explicitly, as a tree, and
checked against the oracle.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.latency import ClassicalLink


@dataclass(frozen=True)
class Fusion:
    """One entanglement swap: which two segment extents it joins."""

    left: tuple[float, float]
    right: tuple[float, float]

    @property
    def extent_km(self) -> float:
        return max(self.left[1], self.right[1]) - min(self.left[0], self.right[0])

    def describe(self) -> str:
        return (f"[{self.left[0]:.0f},{self.left[1]:.0f}] + "
                f"[{self.right[0]:.0f},{self.right[1]:.0f}] -> "
                f"{self.extent_km:.1f} km")


def balanced_tree(positions: list[float]) -> list[Fusion]:
    """Fusions ordered so the span doubles rather than grows linearly.

    Built by **splitting the segment list in half recursively** and emitting each
    merge as it completes.  Returning actual ``Fusion`` objects -- rather than
    indices into a list that shifts underneath -- is what avoids the silent
    index-replay bug described in the module docstring.

    For a uniform chain the result is the balanced-merge optimum: at eight links
    the extents are ten kilometres each at the first level, twenty at the second,
    and so on, instead of 10, 20, 30, ... 80.
    """
    if len(positions) < 2:
        return []

    segments: list[tuple[float, float]] = [(p, p) for p in positions]
    fusions: list[Fusion] = []

    def merge(lo: int, hi: int) -> tuple[float, float]:
        """Merge ``segments[lo:hi]`` and return the resulting extent."""
        if hi - lo == 1:
            return segments[lo]
        mid = lo + (hi - lo) // 2
        left = merge(lo, mid)
        right = merge(mid, hi)
        fusions.append(Fusion(left=left, right=right))
        return (min(left[0], right[0]), max(left[1], right[1]))

    merge(0, len(segments))
    return fusions


def total_span_km(fusions: list[Fusion]) -> float:
    """Sum of the extents covered by each fusion.

    This is the quantity the delay is proportional to: total round-trip time is
    ``sum(extent) / c`` up to the round-trip factor.
    """
    return float(sum(f.extent_km for f in fusions))


def optimal_span_km(positions: list[float]) -> float:
    """Exhaustive minimum over all fusion orders.  An oracle for small chains.

    Exponential, so usable only as a check -- but it is what caught the earlier
    implementation reporting an impossible result, and a number that can be beaten
    is worth having.
    """
    best: list[float] = [float("inf")]

    def walk(segments: list[tuple[float, float]], acc: float) -> None:
        if acc >= best[0]:
            return                                  # prune
        if len(segments) == 1:
            best[0] = acc
            return
        for i in range(len(segments) - 1):
            a, b = segments[i], segments[i + 1]
            extent = max(a[1], b[1]) - min(a[0], b[0])
            merged = (min(a[0], b[0]), max(a[1], b[1]))
            walk(segments[:i] + [merged] + segments[i + 2:], acc + extent)

    if len(positions) < 2:
        return 0.0
    walk([(p, p) for p in positions], 0.0)
    return best[0]


def compare_orders(positions: list[float]) -> dict:
    """Balanced tree against the sequential order and the optimum."""
    from .coordination import segment_aware_delay

    sequential = segment_aware_delay(positions)["total_s"]
    link = ClassicalLink()
    balanced_km = total_span_km(balanced_tree(positions))
    return {
        "links": len(positions) - 1,
        "balanced_km": balanced_km,
        "sequential_km": sequential / link.round_trip_s(1.0),
        "optimal_km": optimal_span_km(positions) if len(positions) <= 8 else None,
    }
