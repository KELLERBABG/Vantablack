"""Time-aware entanglement distribution schedule.

Realistic model: every link on the path is generated *in parallel*; the mean
wait for the slowest link is ``max(1/rate_i)``. Swaps then proceed in the
chosen order, each taking ``t_swap`` seconds. Between its creation and its
fusion, every segment sits in quantum memory, so its fidelity decays with
T1/T2 (see :func:`memory_fidelity_after_dt`). Each segment tracks the time it
was created (t_gen for a raw link, the fusion time for a fused segment), so
memory decay is applied exactly once per segment at the moment it is consumed.
The reported end-to-end fidelity accounts for swap noise *and* memory decay.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.physical import memory_fidelity_after_dt
from .graph import QuantumLink, QuantumTopology
from .routing import Route, e2e_fidelity


@dataclass
class SwapEvent:
    """A single Bell-state measurement at a repeater node."""

    step: int
    node: str
    segments: tuple[int, int]
    time_s: float
    fidelity_before: tuple[float, float]
    fidelity_after: float

    def describe(self) -> str:
        return (
            f"  t={self.time_s:9.3f}s  swap at {self.node}: "
            f"F({self.segments[0]},{self.segments[1]}) "
            f"{self.fidelity_before[0]:.4f}x{self.fidelity_before[1]:.4f} "
            f"-> {self.fidelity_after:.4f}"
        )


@dataclass
class DistributionResult:
    """Result of distributing entanglement along a route."""

    route: Route
    link_rates: list[float]
    t_gen_s: float
    events: list[SwapEvent] = field(default_factory=list)
    final_fidelity: float = 0.0

    def describe(self) -> str:
        lines = [
            f"Distribution along: {' -> '.join(self.route.path)}",
            f"  link generation (parallel): {self.t_gen_s:.3f}s "
            f"(rates {['{:.0f}/s'.format(r) for r in self.link_rates]})",
            f"  memory decay (T1/T2) applied until each swap",
        ]
        for ev in self.events:
            lines.append(ev.describe())
        lines.append(f"  END-TO-END FIDELITY: {self.final_fidelity:.4f}")
        return "\n".join(lines)


def distribute(topology: QuantumTopology, route: Route,
               t_swap_s: float = 1e-3) -> DistributionResult:
    """Schedule entanglement distribution along ``route`` with memory decay."""
    path = route.path
    n_links = len(path) - 1
    if n_links == 0:
        return DistributionResult(route=route, link_rates=[], t_gen_s=0.0,
                                  final_fidelity=1.0)

    links: list[QuantumLink] = []
    for a, b in zip(path, path[1:]):
        l = topology.link(a, b)
        if l is None:
            raise KeyError(f"no link {a}-{b}")
        links.append(l)
    rates = [l.generation_rate() for l in links]
    t_gen = max(1.0 / max(r, 1e-12) for r in rates)
    t1 = topology.nodes[path[0]].t1_s
    t2 = topology.nodes[path[0]].t2_s

    # Each segment carries its fidelity, birth time, and the path index of its
    # right endpoint (raw links: i+1). Fusing adjacent segments lo, hi happens
    # at the shared node = the right endpoint of segment lo.
    segments: list[dict] = [
        {"f": float(f), "born": t_gen, "right": i + 1}
        for i, f in enumerate(route.link_fidelities)
    ]
    events: list[SwapEvent] = []
    for step, (i, j) in enumerate(route.swap_order):
        lo, hi = sorted((i, j))
        t = t_gen + step * t_swap_s
        node = path[segments[lo]["right"]]
        fi = memory_fidelity_after_dt(
            segments[lo]["f"], t - segments[lo]["born"], t1, t2)
        fj = memory_fidelity_after_dt(
            segments[hi]["f"], t - segments[hi]["born"], t1, t2)
        merged = (4.0 * fi * fj - fi - fj + 1.0) / 3.0
        events.append(SwapEvent(
            step=step, node=node, segments=(lo, hi), time_s=t,
            fidelity_before=(fi, fj), fidelity_after=merged,
        ))
        segments[lo] = {"f": merged, "born": t, "right": segments[hi]["right"]}
        segments.pop(hi)

    return DistributionResult(route=route, link_rates=rates, t_gen_s=t_gen,
                              events=events, final_fidelity=segments[0]["f"])


def schedule_fidelity_without_decay(route: Route) -> float:
    """Pure swap-noise e2e fidelity (no memory decay), for comparison."""
    return e2e_fidelity(route.link_fidelities, route.swap_order)
