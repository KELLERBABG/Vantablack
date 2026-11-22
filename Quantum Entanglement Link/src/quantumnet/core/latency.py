"""Classical control-plane latency.

Why latency belongs in the model at all
---------------------------------------
Entanglement swapping produces one of four Bell states **at random**, and the
node that performed the swap learns two bits saying which.  Until those two bits
reach both ends, the pair is unusable: the endpoints do not know what state they
share.  So every swap on a path costs a classical round trip before the pair can
be consumed, and that time is spent with the pair sitting in memory, decaying.

This is not a detail.  A design that is optimal for the *quantum* link budget can
be wrong once the classical exchange is charged, and the leading published
non-ILP placement work (Avis & Krastanov, arXiv:2501.06291) **deliberately omits
classical communication entirely**.  Modelling it is therefore a place where a
result can be better than the literature rather than merely comparable to it --
provided the model says plainly what it does and does not include.

What is modelled
----------------
* **Propagation at ``c`` in fibre.**  The community standard is 2.0-2.05e8 m/s;
  QuISP writes ``distance / 200000km * 1s`` in its own network files and
  SeQUeNCe's examples span the same range.  The default here is 2.0e8.
* **A round trip per swap**, because the swap outcome must reach *both*
  endpoints.
* **Processing/serialisation delay**, configurable, defaulting to zero so that
  what is being charged is unambiguous.

What is *not* modelled, stated so nobody assumes otherwise: queueing, bandwidth
limits, retransmission, and asymmetric or routed control planes.  The delay is a
single propagation-plus-processing term, which is the first-order effect and not
the whole story.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Speed of light in fibre, in km/s.  QuISP writes exactly
#: ``distance / 200000km * 1s``; SeQUeNCe's examples range 2.0-2.05e8 m/s.
DEFAULT_C_FIBER_KM_PER_S = 200_000.0


@dataclass(frozen=True)
class ClassicalLink:
    """The classical control path, as a delay model.

    ``processing_delay_s`` is charged **per node** the message passes, so a
    three-node path pays it twice.  Keeping it separate from propagation is what
    lets a caller ask which of the two dominates -- usually a different answer
    inside a data centre than across a backbone.
    """

    c_fiber_km_per_s: float = DEFAULT_C_FIBER_KM_PER_S
    processing_delay_s: float = 0.0

    def __post_init__(self):
        if self.c_fiber_km_per_s <= 0:
            raise ValueError("c_fiber_km_per_s must be positive")
        if self.processing_delay_s < 0:
            raise ValueError("processing_delay_s must be non-negative")

    def one_way_s(self, distance_km: float, hops: int = 0) -> float:
        """Time for one classical message to cross ``distance_km``.

        ``hops`` is the number of intermediate nodes, each adding
        ``processing_delay_s``.
        """
        if distance_km < 0:
            raise ValueError("distance_km must be non-negative")
        return float(distance_km / self.c_fiber_km_per_s
                     + hops * self.processing_delay_s)

    def round_trip_s(self, distance_km: float, hops: int = 0) -> float:
        """Round-trip time: what a swap's two-bit outcome actually costs.

        Both endpoints must learn the outcome, so the message must reach the far
        end and be acknowledged.  Charging one-way here is the common
        under-count.
        """
        return 2.0 * self.one_way_s(distance_km, hops)


#: A control plane with no delay at all -- for isolating the quantum terms.
ZERO_LATENCY = ClassicalLink(c_fiber_km_per_s=1e12, processing_delay_s=0.0)


def swap_coordination_delay_s(positions_km: list[float],
                              link: ClassicalLink | None = None,
                              *,
                              hops_per_span: int = 0) -> float:
    """Classical delay charged to one swap, given the chain geometry.

    A swap fuses two segments whose outer endpoints are the nodes that must be
    told.  The message has to travel the **span covered by the two fused
    segments** and back, so the cost grows with how much fibre the swap spans --
    which is exactly the coupling that makes latency placement-relevant: a
    placement with few, long spans generates quickly but coordinates slowly.
    """
    link = link or ClassicalLink()
    if len(positions_km) < 2:
        return 0.0
    ordered = sorted(float(p) for p in positions_km)
    span = ordered[-1] - ordered[0]
    return link.round_trip_s(span, hops=hops_per_span)


def total_coordination_delay_s(positions_km: list[float],
                               n_swaps: int,
                               link: ClassicalLink | None = None) -> float:
    """Total classical delay for a chain requiring ``n_swaps`` swaps.

    Serialised: each swap's coordination must complete before the next pair can
    be consumed, so the delays add rather than overlap.
    """
    if n_swaps < 0:
        raise ValueError("n_swaps must be non-negative")
    if n_swaps == 0:
        return 0.0
    return n_swaps * swap_coordination_delay_s(positions_km, link)
