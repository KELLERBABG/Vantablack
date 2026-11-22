"""Event-driven entanglement distribution.

This is the M1 path: distribution expressed as timestamped events on
:class:`~quantumnet.core.scheduler.Scheduler`, rather than evaluated in closed
form by :func:`~quantumnet.topology.schedule.distribute`.

Why both exist
--------------
:func:`~quantumnet.topology.schedule.distribute` computes the timeline
algebraically because for a *single* route with no contention the answer is
available in closed form.  That is fast and exact, and it stays.

The event path is not a faster way to get the same number.  It exists because
closed form cannot express the questions that make a network a network:

* Two sources contending for the same link or the same memory.
* A memory that expires before a swap it was reserved for.
* Classical coordination arriving late, after the photon it describes.

Those need a clock and an ordering, not an equation.  Until this path exists,
"what happens when two demands overlap" has no answer in QEL at all.

The agreement test
------------------
For a contention-free route the two paths must agree **exactly** on fidelity and
on swap times, because they model the same physics.  Disagreement means one of
them is wrong, which makes this the cheapest useful check available: the
closed-form path is the oracle and the event path has to reproduce it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..core.physical import bell_pair_fidelity_after_dt
from ..core.scheduler import Scheduler
from .graph import QuantumTopology
from .resources import (
    NodeEntanglementManager,
    Reservation,
    ReservationState,
    resolve_contention,
)
from .routing import Route, best_route, swapped_fidelity


@dataclass
class EventChainResult:
    """Outcome of an event-driven distribution along one route."""

    route: Route
    final_fidelity: float
    t_end_s: float
    swap_times: list[float] = field(default_factory=list)
    swap_nodes: list[str] = field(default_factory=list)
    events_run: int = 0


def distribute_events(
    topology: QuantumTopology,
    route: Route,
    *,
    t_swap_s: float = 1e-3,
    t_gen_s: float | None = None,
) -> EventChainResult:
    """Distribute entanglement along ``route`` using the event kernel.

    Models the same physics as
    :func:`~quantumnet.topology.schedule.distribute`: every link generates in
    parallel and becomes usable at ``t_gen``, each swap costs ``t_swap_s`` and
    occurs at ``t_gen + step * t_swap_s``, and every segment accrues memory
    decay from its birth until it is consumed.

    ``t_gen_s`` defaults to the slowest link's mean wait, ``max(1/rate_i)``,
    matching the closed-form model.

    The swap indices are resolved against the **live** segment list at execution
    time, not pre-resolved when the events are scheduled.  That matters: a swap
    order refers to positions in the array *as it shrinks*, so fusing segments
    ``(0, 1)`` then ``(1, 2)`` means "fuse the first two, then fuse the result
    with what is now the third" -- not the original segments 0, 1 and 2.
    Pre-resolving gives the wrong node and the wrong answer.
    """
    path = route.path
    n_links = len(path) - 1
    if n_links == 0:
        return EventChainResult(route=route, final_fidelity=1.0, t_end_s=0.0)

    links = []
    for a, b in zip(path, path[1:]):
        link = topology.link(a, b)
        if link is None:
            raise KeyError(f"no link {a}-{b}")
        links.append(link)

    rates = [link.generation_rate() for link in links]
    if t_gen_s is None:
        t_gen_s = max(1.0 / max(rate, 1e-12) for rate in rates)
    t_gen_s = float(t_gen_s)

    t1 = topology.nodes[path[0]].t1_s
    t2 = topology.nodes[path[0]].t2_s

    kernel = Scheduler()

    # Segment state: fidelity, birth time, and the path index of the right endpoint
    # (link i spans path[i] -> path[i+1], so i + 1); fusing lo with hi merges there.
    segments: list[dict] = [
        {"fidelity": float(f), "born": t_gen_s, "right": i + 1}
        for i, f in enumerate(route.link_fidelities)
    ]

    swap_times: list[float] = []
    swap_nodes: list[str] = []

    def handle_swap(node_id: str, kind: str, payload: dict, t: float) -> None:
        """Fuse two adjacent live segments and charge memory decay."""
        low = int(payload["lo"])
        high = int(payload["hi"])
        if high >= len(segments) or low >= high:
            raise IndexError(
                f"swap ({low}, {high}) does not address two live segments "
                f"(there are {len(segments)})"
            )

        f_low = bell_pair_fidelity_after_dt(
            segments[low]["fidelity"], t - segments[low]["born"], t1, t2)
        f_high = bell_pair_fidelity_after_dt(
            segments[high]["fidelity"], t - segments[high]["born"], t1, t2)
        merged = swapped_fidelity(f_low, f_high)

        # The fusion node is the shared endpoint, resolved now rather than at scheduling
        # time, because the array has shrunk since.
        node = path[segments[low]["right"]]
        swap_times.append(t)
        swap_nodes.append(node)

        segments[low] = {
            "fidelity": merged,
            "born": t,
            "right": segments[high]["right"],
        }
        segments.pop(high)

    kernel.on("swap", handle_swap)

    # Each link's pair becomes available at t_gen. Modelled as an event so the timeline
    # is explicit and a future resource manager can attach to it.
    for index, _ in enumerate(links):
        kernel.schedule(t_gen_s, "link_ready", path[index], {"link": index})

    for step, (i, j) in enumerate(route.swap_order):
        low, high = sorted((i, j))
        kernel.schedule(
            t_gen_s + step * t_swap_s, "swap", path[0],
            {"lo": low, "hi": high, "step": step},
        )

    events_run = kernel.run()

    return EventChainResult(
        route=route,
        final_fidelity=segments[0]["fidelity"] if segments else 1.0,
        t_end_s=kernel.current_time,
        swap_times=swap_times,
        swap_nodes=swap_nodes,
        events_run=events_run,
    )


# Contention-driven simulation

@dataclass
class ContentionOutcome:
    """What happened to one demand in a contested multi-user run."""

    reservation: Reservation
    route: Route | None
    delivered_fidelity: float
    granted: bool
    rejected_at: float | None = None

    def describe(self) -> str:
        if not self.granted:
            why = f" at t={self.rejected_at:g}" if self.rejected_at is not None else ""
            return (f"REFUSED  {self.reservation.initiator}->"
                    f"{self.reservation.responder}: {self.reservation.reason}{why}")
        route = " -> ".join(self.route.path) if self.route else "?"
        return (f"GRANTED  {self.reservation.initiator}->"
                f"{self.reservation.responder} via {route}, "
                f"F={self.delivered_fidelity:.4f}")


@dataclass
class ContentionResult:
    """The outcome of every demand in one contested run."""

    outcomes: list[ContentionOutcome] = field(default_factory=list)
    t_end_s: float = 0.0
    events_run: int = 0

    @property
    def granted(self) -> list[ContentionOutcome]:
        return [o for o in self.outcomes if o.granted]

    @property
    def refused(self) -> list[ContentionOutcome]:
        return [o for o in self.outcomes if not o.granted]

    def describe(self) -> str:
        lines = [f"Contested run: {len(self.granted)} granted, "
                 f"{len(self.refused)} refused, ended t={self.t_end_s:g}"]
        lines.extend("  " + o.describe() for o in self.outcomes)
        return "\n".join(lines)


def simulate_demands(
    topology: QuantumTopology,
    demands: Iterable,
    manager: NodeEntanglementManager,
    *,
    t_swap_s: float = 1e-3,
    memory_size: int = 1,
) -> ContentionResult:
    """Run competing demands against a finite memory pool on one timeline.

    Each demand is a :class:`~quantumnet.topology.resources.Reservation`.  The
    kernel owns time: a demand is *decided at its start time* against the
    capacity still free at that moment, then its distribution runs and its
    memories are released at its end time.

    This is the M3 payoff -- contention changes the answer.  A run that granted
    everything would model one user at a time and would overstate any
    multi-user network in the optimistic direction.

    Demands are ordered by the arbitration policy, so a batch that overcommits a
    node yields a deterministic winner rather than depending on dict or list
    order.  A demand whose route cannot be found, or whose end time precedes its
    start, is refused for that reason rather than crashing the run.
    """
    kernel = Scheduler()
    outcomes: list[ContentionOutcome] = []

    ordered = resolve_contention(demands)

    def decide(reservation: Reservation) -> None:
        """Grant or refuse a demand at its start time, then deliver it."""
        if reservation.duration < 0:
            reservation.state = ReservationState.REJECTED
            reservation.reason = "negative duration"
            outcomes.append(ContentionOutcome(
                reservation=reservation, route=None, delivered_fidelity=0.0,
                granted=False, rejected_at=reservation.start_time))
            return

        route = best_route(topology, reservation.initiator,
                           reservation.responder, max_hops=16)
        if route is None:
            reservation.state = ReservationState.REJECTED
            reservation.reason = (
                f"no route {reservation.initiator}->{reservation.responder}")
            outcomes.append(ContentionOutcome(
                reservation=reservation, route=None, delivered_fidelity=0.0,
                granted=False, rejected_at=reservation.start_time))
            return

        reservation.path = list(route.path)
        if not manager.request(reservation):
            outcomes.append(ContentionOutcome(
                reservation=reservation, route=route, delivered_fidelity=0.0,
                granted=False, rejected_at=reservation.start_time))
            return

        chain = distribute_events(topology, route, t_swap_s=t_swap_s)
        outcomes.append(ContentionOutcome(
            reservation=reservation, route=route,
            delivered_fidelity=chain.final_fidelity, granted=True))

    def expire(node_id: str, kind: str, payload: dict, t: float) -> None:
        manager.sweep(t)

    kernel.on("decide", lambda n, k, p, t: decide(p["reservation"]))
    kernel.on("expire", expire)

    for reservation in ordered:
        kernel.schedule(reservation.start_time, "decide", reservation.initiator,
                        {"reservation": reservation})
    for reservation in ordered:
        kernel.schedule(max(reservation.end_time, reservation.start_time),
                        "expire", reservation.initiator, {})

    events_run = kernel.run()
    # Any reservation still active at the horizon is released, so a caller inspecting
    # the manager afterwards sees a consistent final state.
    manager.sweep(max((r.end_time for r in ordered), default=0.0))

    return ContentionResult(
        outcomes=outcomes,
        t_end_s=kernel.current_time,
        events_run=events_run,
    )
