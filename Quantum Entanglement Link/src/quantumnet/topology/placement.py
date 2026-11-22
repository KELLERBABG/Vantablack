"""Repeater placement as an optimisation problem -- the synthesis layer.

What this is
------------
Given a fibre route, candidate repeater sites, and hardware parameters, answer
the question the project exists to answer: **where do the repeaters go, and what
key rate results?**  Every other module in QEL supplies something this needs;
this is the part that produces a design rather than a measurement.

Why not a general MILP
----------------------
The published formulation of this problem (Rabbie, Chakraborty, Avis, Wehner,
[arXiv:2005.14715](https://arxiv.org/abs/2005.14715)) is a binary program.  That is
unnecessary here, and avoiding it is a deliberate choice rather than a shortcut.

Along a *chain* the constraint structure is a longest-segment bound, which makes
the minimum-repeater problem exactly a shortest-path problem and the
maximum-rate problem exactly a dynamic program.  Both are polynomial and both are
exact -- no solver, no tolerance, no possibility of returning a layout that
is quietly suboptimal.  A general-purpose solver would add a heavyweight
dependency to a library whose promise is `numpy` only, in exchange for solving a
problem that does not need one.

The modelling move that makes this work is the published one: **do not put
fidelity in the objective.**  Convert the requirement into a maximum segment
length and a maximum hop count, then solve a purely combinatorial problem over
those derived bounds.  Fidelity is then *reported* for the chosen layout rather
than optimised through.

Robustness
----------
The genuinely open problem.  A targeted search found no published formulation of
repeater placement as a robust or chance-constrained program over *hardware
parameter* uncertainty -- the closest work is discrete component survivability,
or post-hoc sensitivity analysis.  Here a layout can be required to satisfy the
reachability constraint across a **set of scenarios** (memory coherence times,
say), which is a scenario-based robust formulation and is what
:func:`robust_placement` implements.

The honest scope: this is scenario-based robustness over a finite, caller-chosen
scenario set.  It is not a chance constraint and it makes no claim about
probability distributions over hardware parameters -- it says the layout works
for every scenario supplied, which is a statement about those scenarios and
nothing more.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from itertools import combinations

import numpy as np

from ..core.physical import bell_pair_fidelity_after_dt
from ..protocols.bb84 import run_bb84_decoy_preset
from .routing import swapped_fidelity

#: Default key-rate model.  ``practical-1550`` is the modern-SPAD preset.
DEFAULT_RATE_PRESET = "practical-1550"

#: Numeric slack for length comparisons, in km. Two sites 100.0000001 km apart on a
#: 100 km budget count as reachable; exact float comparison hinges on the last bit.
_LENGTH_TOL_KM = 1e-9

#: Default memory coherence times, matching ``graph.DEFAULT_T1_S/T2_S``.
DEFAULT_T1_S = 100.0
DEFAULT_T2_S = 50.0


@dataclass(frozen=True)
class CandidateSite:
    """A place a repeater *could* go.

    ``is_existing`` marks a site that is already built, so a layout can be
    evaluated as an extension of installed plant rather than from nothing.
    """

    name: str
    position_km: float
    is_existing: bool = False

    def __post_init__(self):
        if self.position_km < 0.0:
            raise ValueError("position_km must be non-negative")


@dataclass
class PlacementProblem:
    """A fibre route with candidate repeater sites along it.

    Distances are measured along the fibre, so the chain is one-dimensional: the
    distance between two sites is the difference of their positions.  That is
    what makes an exact combinatorial treatment possible, and it is the right
    model for a single span or a linear backbone.
    """

    end_a: CandidateSite
    end_b: CandidateSite
    candidates: list[CandidateSite] = field(default_factory=list)
    alpha_db_km: float = 0.2
    pulse_rate_hz: float = 1e8
    required_fidelity: float = 0.0
    rate_preset: str = DEFAULT_RATE_PRESET
    detector_efficiency: float | None = None
    dark_count_hz: float | None = None
    error_correction_inefficiency: float = 1.16
    #: Storage time charged per segment before its swap. Microseconds, not milliseconds: a
    #: 1 ms hold destroys the short-coherence scenarios a robustness study is about.
    t_swap_s: float = 1e-6
    #: ``"barrett-kok"`` (default) treats loss as costing rate, not fidelity (true for a
    #: heralded link); ``"depolarizing"`` is the pessimistic single-photon reading.
    fidelity_model: str = "barrett-kok"
    coincidence_window_s: float = 1e-9
    mode_matching: float = 1.0
    #: Fidelity of the entanglement-swap operation itself.  An ideal swap is
    #: 1.0; real BSMs are not, and this is what makes hop count cost fidelity.
    swap_fidelity: float = 0.99
    #: Classical control-plane delay model, or ``None`` to charge none. When set, each
    #: swap costs a round trip spent decaying in memory, so the optimum changes.
    classical_link: object | None = None
    #: Additional processing delay per intermediate node, in seconds.
    classical_processing_s: float = 0.0
    #: ``"whole-span"`` charges each swap the round trip, ``"segment-aware"`` only the
    #: two segments it fuses; it overstates by 1.33x at two links and 2.88x at seven.
    coordination_model: str = "whole-span"
    #: ``"sequential"`` fuses the leftmost pair repeatedly. A better order is known to
    #: exist but no efficient construction was found, so this is a reproducible reference.
    fusion_order: str = "sequential"

    def __post_init__(self):
        if self.end_b.position_km <= self.end_a.position_km:
            raise ValueError("end_b must lie beyond end_a along the fibre")
        if not 0.0 <= self.required_fidelity <= 1.0:
            raise ValueError("required_fidelity must be in [0, 1]")
        for site in self.candidates:
            if not self.end_a.position_km <= site.position_km <= self.end_b.position_km:
                raise ValueError(
                    f"candidate {site.name!r} at {site.position_km} km lies "
                    f"outside the route [{self.end_a.position_km}, "
                    f"{self.end_b.position_km}]"
                )

    @property
    def span_km(self) -> float:
        return self.end_b.position_km - self.end_a.position_km

    def all_sites(self) -> list[CandidateSite]:
        """Owned sites plus candidates, sorted by position."""
        sites = [self.end_a, *self.candidates, self.end_b]
        sites.sort(key=lambda s: s.position_km)
        return sites

    def distance(self, a: CandidateSite, b: CandidateSite) -> float:
        return abs(a.position_km - b.position_km)


# Link and chain physics

def elementary_link_fidelity(length_km: float, problem: PlacementProblem) -> float:
    """Fidelity of one elementary link.

    Uses the **Barrett-Kok** model when ``fidelity_model="barrett-kok"`` (the
    default), because loss on a *heralded* link costs rate, not fidelity: a
    photon that fails to arrive is a failed attempt, not a corrupted pair.  The
    depolarising model conflates the two, and at metro distances it drives link
    fidelity toward the 1/4 floor, which makes every long chain look dead and
    hides the effect of *placement* -- the thing being optimised.

    ``fidelity_model="depolarizing"`` reproduces
    :meth:`~quantumnet.topology.graph.QuantumLink.fidelity` exactly, for callers
    who want the pessimistic single-photon reading.
    """
    from .graph import QuantumLink

    if problem.fidelity_model == "depolarizing":
        link = QuantumLink(
            a="a", b="b", length_km=length_km, alpha_db_km=problem.alpha_db_km,
            pulse_rate_hz=problem.pulse_rate_hz,
            **({"detector_eff": problem.detector_efficiency}
               if problem.detector_efficiency is not None else {}),
            **({"dark_count_hz": problem.dark_count_hz}
               if problem.dark_count_hz is not None else {}),
        )
        return float(link.fidelity())

    if problem.fidelity_model != "barrett-kok":
        raise ValueError(
            f"unknown fidelity_model {problem.fidelity_model!r}; use "
            f"'barrett-kok' or 'depolarizing'"
        )

    from ..core.photonics import elementary_link_from_specs

    link = elementary_link_from_specs(
        length_km,
        alpha_db_km=problem.alpha_db_km,
        detector_efficiency=(problem.detector_efficiency
                             if problem.detector_efficiency is not None else 0.8),
        dark_count_hz=(problem.dark_count_hz
                       if problem.dark_count_hz is not None else 100.0),
        coincidences_window_s=problem.coincidence_window_s,
        mode_matching=problem.mode_matching,
    )
    return float(link.raw_fidelity())


def elementary_link_rate(length_km: float, problem: PlacementProblem) -> float:
    """Successful entanglement attempts per second on one elementary link."""
    from .graph import QuantumLink

    link = QuantumLink(
        a="a", b="b", length_km=length_km, alpha_db_km=problem.alpha_db_km,
        pulse_rate_hz=problem.pulse_rate_hz,
        **({"detector_eff": problem.detector_efficiency}
           if problem.detector_efficiency is not None else {}),
        **({"dark_count_hz": problem.dark_count_hz}
           if problem.dark_count_hz is not None else {}),
    )
    return float(link.barrett_kok_rate())


@dataclass
class ChainQuality:
    """What a completed chain delivers."""

    end_to_end_fidelity: float
    elementary_link_count: int
    longest_link_km: float
    bottleneck_rate_hz: float
    key_rate_hz: float

    def describe(self) -> str:
        return (f"links={self.elementary_link_count} "
                f"longest={self.longest_link_km:.1f}km "
                f"F={self.end_to_end_fidelity:.4f} "
                f"rate={self.key_rate_hz:.3e}/s")


def _chain_from_positions(ordered: list[float], problem: PlacementProblem,
                          t1_s: float, t2_s: float,
                          memory_wait_s: float | None) -> ChainQuality:
    """Evaluate a chain of already-ordered positions.  No endpoint validation.

    The DP builds *partial* chains while searching, so endpoint validation cannot
    live here -- a partial chain legitimately stops short of ``end_b``.  Callers
    that need the whole route checked use :func:`chain_quality`.
    """
    lengths = [b - a for a, b in zip(ordered, ordered[1:])]
    if any(L <= 0 for L in lengths):
        raise ValueError("chain positions must be strictly increasing")

    n_links = len(lengths)
    wait_s = problem.t_swap_s if memory_wait_s is None else float(memory_wait_s)

    # A swap costs a round trip across the whole chain: both endpoints must learn which
    # Bell state resulted. Charging less needs a message-routing model this module lacks.
    coordination_s = 0.0
    if problem.classical_link is not None and n_links > 1:
        from ..core.latency import ClassicalLink

        link_model = problem.classical_link
        if not hasattr(link_model, "round_trip_s"):
            link_model = ClassicalLink(
                processing_delay_s=problem.classical_processing_s)
        span = ordered[-1] - ordered[0]
        model = getattr(problem, "coordination_model", "whole-span")
        if model == "segment-aware":
            # Charge each swap the extent of the two segments it fuses.
            from .coordination import segment_aware_delay

            total = segment_aware_delay(list(ordered))["total_s"]
            # ``segment_aware_delay`` assumes the default fibre speed, so rescale to the
            # caller's link model: the two differ only in what distance is charged.
            default_speed = 200_000.0
            total = total * (default_speed / link_model.c_fiber_km_per_s)
            coordination_s = total + (n_links - 1) * (
                link_model.processing_delay_s - ClassicalLink().processing_delay_s)
        elif model == "whole-span":
            coordination_s = (n_links - 1) * link_model.round_trip_s(span)
        else:
            raise ValueError(
                f"coordination_model must be 'whole-span' or 'segment-aware', "
                f"got {model!r}"
            )
    total_wait_s = wait_s + coordination_s

    # Each factor is a Werner parameter, so the product stays in [0, 1]: per link the
    # heralded fidelity, memory decoherence while waiting, and the swap's fidelity.
    survivor = 1.0
    for length in lengths:
        fidelity = elementary_link_fidelity(length, problem)
        # Written directly rather than via bell_pair_fidelity_after_dt, whose single-qubit
        # asymptote 2*f0 - 1 goes negative and would pin every scenario at the 1/4 floor.
        survival = 1.0
        if t1_s > 0:
            survival *= float(np.exp(-total_wait_s / t1_s))
        if t2_s > 0:
            survival *= float(np.exp(-total_wait_s / t2_s))
        w = (4.0 * fidelity - 1.0) / 3.0
        survivor *= float(np.clip(w, 0.0, 1.0)) * survival

    if problem.swap_fidelity < 1.0:
        w_swap = (4.0 * problem.swap_fidelity - 1.0) / 3.0
        survivor *= float(np.clip(w_swap, 0.0, 1.0)) ** (n_links - 1)

    end_to_end = (1.0 + 3.0 * survivor) / 4.0
    bottleneck = min(elementary_link_rate(L, problem) for L in lengths)
    delivered_rate = bottleneck / n_links

    return ChainQuality(
        end_to_end_fidelity=float(end_to_end),
        elementary_link_count=n_links,
        longest_link_km=float(max(lengths)),
        bottleneck_rate_hz=float(bottleneck),
        key_rate_hz=float(delivered_rate * key_fraction(end_to_end, problem)),
    )


def chain_quality(positions_km: list[float], problem: PlacementProblem,
                  *, t1_s: float = 100.0, t2_s: float = 50.0,
                  memory_wait_s: float | None = None) -> ChainQuality:
    """Evaluate a complete placement: fidelity through the swaps, and the rate.

    **Fidelity** is composed exactly.  Each elementary link has a Werner
    parameter ``W = (4F-1)/3``; storing a pair multiplies ``W`` by the survival
    factor over the wait before its swap; swapping multiplies the survivors.  So
    the whole chain is one product, which is both cheap and exact, and it stays
    inside the physical range ``W in [0, 1]``.

    ``memory_wait_s`` is the storage time charged per segment before its swap.
    It defaults to one swap slot rather than the whole chain's duration, because
    a serial schedule fuses the earliest segments first and so does not hold the
    first pair for the entire run.  Charging every segment the full chain
    duration is a modelling choice rather than a law, and it is the most
    sensitive assumption here -- hence a named parameter, not a buried constant.

    **Rate** takes the bottleneck elementary-link rate and divides by the number
    of links, the standard serial-repeater penalty.  The key *fraction* comes
    from the validated decoy-state model at the end-to-end fidelity's equivalent
    distance, so it is a real calculation and not a fitted constant.
    """
    if len(positions_km) < 2:
        raise ValueError("a chain needs at least two endpoints")
    ordered = sorted(float(p) for p in positions_km)
    if abs(ordered[0] - float(problem.end_a.position_km)) > _LENGTH_TOL_KM:
        raise ValueError("the chain must start at end_a")
    if abs(ordered[-1] - float(problem.end_b.position_km)) > _LENGTH_TOL_KM:
        raise ValueError("the chain must end at end_b")
    return _chain_from_positions(ordered, problem, t1_s, t2_s, memory_wait_s)


def key_fraction(fidelity: float, problem: PlacementProblem) -> float:
    """Secret-key bits per delivered pair, for a pair of fidelity ``fidelity``.

    This is the standard BBM92/entanglement-based rate for a Werner pair, not a
    fitted constant and not a distance inversion:

        QBER = 2 * (1 - F) / 3    (the error rate a Werner pair of fidelity F shows)
        fraction = max(0, 1 - 2*h(QBER))

    The initial version of this function mapped fidelity back to an *equivalent
    fibre distance* and read the decoy-state key rate there.  That was wrong on
    two counts.  First, the decoy-state model's loss mechanism is fibre
    attenuation, whereas a heralded link's fidelity is degraded by dark counts
    and mode mismatch: inverting one against the other relates two unrelated
    axes.  Second, it produced a cliff: any fidelity below about 0.98 mapped to
    an unreachable distance and returned zero, so nearly every realistic layout
    scored 0 and the optimiser had nothing to optimise.

    The threshold falls out at ``QBER = 11%`` (``F ~ 0.835``), which is BB84's
    familiar cutoff -- the number is *derived* from the entropy expression rather
    than chosen, and it lands where the literature puts it.

    (An earlier version of this docstring claimed the cutoff was ``F = 0.5``,
    from evaluating ``h(0.25)`` as 1. It is 0.811, and the difference moved the
    threshold by a large margin. Worth recording because the error was made by
    reasoning about the formula instead of evaluating it.)
    """
    from ..protocols.bb84 import binary_entropy

    f = float(np.clip(fidelity, 0.0, 1.0))
    qber = 2.0 * (1.0 - f) / 3.0
    fraction = 1.0 - 2.0 * binary_entropy(qber)
    return float(max(0.0, min(1.0, fraction)))


def fidelity_to_distance(fidelity: float, problem: PlacementProblem,
                         hi_km: float = 2000.0) -> float:
    """Distance whose elementary-link fidelity equals ``fidelity``, by bisection.

    Only meaningful for ``fidelity_model="depolarizing"``, where attenuation *is*
    the fidelity mechanism.  For the Barrett–Kok model the fidelity is set by
    dark counts and mode mismatch rather than by distance, so this inversion
    relates two different axes and should not be used -- it is retained for the
    depolarising case and for callers probing the attenuation model.
    """
    f = float(np.clip(fidelity, 0.0, 1.0))
    if f >= 1.0:
        return 0.0
    lo = 0.0
    if elementary_link_fidelity(hi_km, problem) > f:
        return hi_km
    for _ in range(80):
        mid = 0.5 * (lo + hi_km)
        if elementary_link_fidelity(mid, problem) > f:
            lo = mid
        else:
            hi_km = mid
    return float(0.5 * (lo + hi_km))


# Placement: exact, by shortest path

@dataclass
class Placement:
    """A chosen set of repeater sites and what it delivers."""

    sites: list[CandidateSite]
    positions_km: list[float]
    quality: ChainQuality
    objective: float
    method: str = ""

    @property
    def names(self) -> list[str]:
        return [s.name for s in self.sites]

    def describe(self) -> str:
        return (f"{len(self.sites)} repeaters [{', '.join(self.names)}]  "
                f"{self.quality.describe()}")


def minimum_repeaters(problem: PlacementProblem,
                      max_link_km: float) -> Placement | None:
    """Fewest repeaters such that no elementary link exceeds ``max_link_km``.

    Exactly a shortest-path problem: build the graph of sites with an edge
    whenever two are within budget, and take the fewest-edge path from ``end_a``
    to ``end_b``.  Unweighted BFS gives the optimum, so this cannot return a
    layout that uses more repeaters than necessary.
    """
    if max_link_km <= 0:
        raise ValueError("max_link_km must be positive")
    sites = problem.all_sites()
    index = {site.name: i for i, site in enumerate(sites)}

    adjacency: dict[int, list[int]] = {i: [] for i in range(len(sites))}
    budget = max_link_km + _LENGTH_TOL_KM
    for i, a in enumerate(sites):
        for j, b in enumerate(sites):
            if i != j and problem.distance(a, b) <= budget:
                adjacency[i].append(j)

    start, goal = index[problem.end_a.name], index[problem.end_b.name]
    # BFS: fewest edges.  Tie-break on total distance for determinism.
    best: dict[int, tuple[int, float]] = {start: (0, 0.0)}
    prev: dict[int, int] = {}
    queue: list[tuple[int, float, int]] = [(0, 0.0, start)]
    while queue:
        hops, travelled, node = heapq.heappop(queue)
        if best.get(node, (10 ** 9, 0.0)) < (hops, travelled):
            continue
        if node == goal:
            break
        for nxt in adjacency[node]:
            cost = (hops + 1, travelled + problem.distance(sites[node], sites[nxt]))
            if cost < best.get(nxt, (10 ** 9, float("inf"))):
                best[nxt] = cost
                prev[nxt] = node
                heapq.heappush(queue, (cost[0], cost[1], nxt))

    if goal not in best:
        return None

    path = [goal]
    while path[-1] != start:
        path.append(prev[path[-1]])
    path.reverse()
    chosen = [sites[i] for i in path]
    return _placement_from_sites(problem, chosen, method="minimum-repeaters")


def _pareto_insert(frontier: list[tuple[float, float, list[int]]],
                   rate: float, fidelity: float, path: list[int],
                   max_size: int = 64) -> None:
    """Insert ``(rate, fidelity, path)`` into a non-dominated frontier in place.

    A state cannot be summarised by its best rate alone.  Two chains reaching the
    same site with the same repeater count are not interchangeable: the higher
    rate may carry lower fidelity, and the lower-rate one may be the only one
    from which the remaining spans are feasible.  Keeping both is what makes the
    search exact rather than greedy -- and the earlier version, which kept only
    the best rate, demonstrably missed a better final layout.

    A point is dominated if another has both rate and fidelity at least as high.
    When the frontier exceeds ``max_size`` it is thinned by dropping points
    nearest to the *middle* of the rate order, keeping both the highest-rate and
    the highest-fidelity ends.  Truncating the low-rate end instead looks
    natural and is wrong: the low-rate end is exactly where the
    highest-fidelity states live, and those are the ones that keep longer spans
    feasible.  That mistake cost the search a reachable layout scoring 1.8x the
    one it returned.
    """
    for existing_rate, existing_fidelity, _ in frontier:
        if existing_rate >= rate and existing_fidelity >= fidelity:
            return
    frontier[:] = [entry for entry in frontier
                   if not (rate >= entry[0] and fidelity >= entry[1])]
    frontier.append((rate, fidelity, path))
    if len(frontier) > max_size:
        frontier.sort(key=lambda e: e[0], reverse=True)
        half = max(1, max_size // 2)
        # keep the fastest `half` and the slowest (highest-fidelity) `half`
        kept = frontier[:half] + frontier[-(max_size - half):]
        frontier[:] = kept


def _placement_from_sites(problem: PlacementProblem,
                          chosen: list[CandidateSite],
                          method: str,
                          **quality_kw) -> Placement:
    positions = [s.position_km for s in chosen]
    quality = chain_quality(positions, problem, **quality_kw)
    repeaters = [s for s in chosen
                 if s.name not in (problem.end_a.name, problem.end_b.name)]
    return Placement(
        sites=repeaters,
        positions_km=positions,
        quality=quality,
        objective=quality.key_rate_hz,
        method=method,
    )


def max_link_for_fidelity(problem: PlacementProblem,
                          target_fidelity: float,
                          n_links: int = 1) -> float:
    """Longest elementary link whose *uniform* chain still meets ``target_fidelity``.

    Derived, not assumed -- the published modelling move: turn the fidelity
    requirement into a length bound once, then solve a purely combinatorial
    problem against it.

    The bisection scales a uniform chain that spans the problem's own
    endpoints, so the returned length is consistent with the route being
    planned.  Constructing a synthetic chain of ``n_links * max_km`` instead
    produces positions that do not reach ``end_b`` and is rejected by the
    evaluator -- a chain must span the route it claims to be a placement for.
    """
    if not 0.25 < target_fidelity <= 1.0:
        raise ValueError("target_fidelity must lie in (1/4, 1]")
    if n_links < 1:
        raise ValueError("n_links must be at least 1")

    span = problem.span_km
    start = problem.end_a.position_km

    def scaled_positions(scale: float) -> list[float]:
        return [start + scale * span * i / n_links for i in range(n_links + 1)]

    def chain_f(scale: float) -> float:
        return _chain_from_positions(scaled_positions(scale), problem,
                                     DEFAULT_T1_S, DEFAULT_T2_S,
                                     None).end_to_end_fidelity

    if chain_f(1e-9) < target_fidelity:
        return 0.0
    if chain_f(1.0) >= target_fidelity:
        return float(span / n_links)
    lo, hi = 1e-9, 1.0
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        if chain_f(mid) >= target_fidelity:
            lo = mid
        else:
            hi = mid
    return float(lo * span / n_links)


# Placement: maximise the delivered key rate

def best_placement(problem: PlacementProblem,
                   max_repeaters: int | None = None,
                   *, t1_s: float = 100.0, t2_s: float = 50.0,
                   frontier_size: int = 64) -> Placement | None:
    """The layout delivering the highest key rate.

    A dynamic program over the sites in ascending position order.  Each state
    carries a **Pareto frontier** of ``(rate, fidelity)`` rather than a single
    best rate, because two chains reaching the same site with the same repeater
    count are not interchangeable: the faster one may carry lower fidelity and
    the slower one may be the only one from which the remaining spans are
    feasible.

    That is not a hypothetical.  A version keeping only the best rate per state
    returned a 7-repeater layout scoring ``5.77e4`` when a 9-repeater layout
    scoring ``8.77e4`` was reachable -- greedy pruning had discarded the
    higher-fidelity state that led to it.  With the frontier the search is exact
    up to the frontier cap, which is a knob rather than a silent approximation.

    Sites are sorted once and the DP is indexed by *that* order.  Indexing by
    position while iterating by index (or the reverse) mixes up which site a
    state refers to, and the symptom is a confusing error from deep inside the
    chain evaluator rather than a wrong-looking number.
    """
    sites = sorted(problem.all_sites(), key=lambda s: s.position_km)
    n = len(sites)
    # ``used`` counts intermediate repeaters (the far endpoint is a terminus, not a
    # repeater), so the budget is compared against it directly.
    limit = n if max_repeaters is None else max_repeaters

    per_link_survival = 1.0
    if t1_s > 0:
        per_link_survival *= float(np.exp(-problem.t_swap_s / t1_s))
    if t2_s > 0:
        per_link_survival *= float(np.exp(-problem.t_swap_s / t2_s))

    edge_rate: dict[tuple[int, int], float] = {}
    edge_werner: dict[tuple[int, int], float] = {}
    for i in range(n):
        for j in range(i + 1, n):
            length = sites[j].position_km - sites[i].position_km
            edge_rate[(i, j)] = elementary_link_rate(length, problem)
            f_link = elementary_link_fidelity(length, problem)
            w_link = float(np.clip((4.0 * f_link - 1.0) / 3.0, 0.0, 1.0))
            edge_werner[(i, j)] = w_link * per_link_survival

    # state[i][k] = frontier of (bottleneck_rate, prefix_werner_product, path) for
    # partial chains reaching site i < n - 1 with k intermediate repeaters.
    # Completed chains reaching end_b (j == n - 1) are evaluated with
    # _chain_from_positions and stored as (key_rate_hz, end_to_end_fidelity, path).
    state: list[dict[int, list[tuple[float, float, list[int]]]]] = [
        {} for _ in range(n)
    ]
    state[0][0] = [(float("inf"), 1.0, [0])]

    for i in range(n - 1):
        if not state[i]:
            continue
        for used, frontier in list(state[i].items()):
            for prefix_rate, prefix_werner, path in list(frontier):
                for j in range(i + 1, n):
                    # The far endpoint is a terminus, not a repeater.
                    new_used = used if j == n - 1 else used + 1
                    if new_used > limit:
                        continue
                    candidate_path = path + [j]
                    if j == n - 1:
                        positions = [sites[p].position_km for p in candidate_path]
                        quality = _chain_from_positions(
                            positions, problem, t1_s, t2_s, None)
                        if quality.end_to_end_fidelity < problem.required_fidelity:
                            continue
                        bucket = state[j].setdefault(new_used, [])
                        _pareto_insert(bucket, quality.key_rate_hz,
                                       quality.end_to_end_fidelity,
                                       candidate_path, frontier_size)
                    else:
                        new_rate = min(prefix_rate, edge_rate[(i, j)])
                        new_werner = prefix_werner * edge_werner[(i, j)]
                        bucket = state[j].setdefault(new_used, [])
                        _pareto_insert(bucket, new_rate, new_werner,
                                       candidate_path, frontier_size)

    if not state[n - 1]:
        return None
    best_rate, best_fidelity, best_path = max(
        (entry for frontier in state[n - 1].values() for entry in frontier),
        key=lambda e: e[0],
    )
    chosen = [sites[i] for i in best_path]
    return _placement_from_sites(problem, chosen, method="max-rate",
                                 t1_s=t1_s, t2_s=t2_s)


def uniform_placement(problem: PlacementProblem,
                      n_repeaters: int) -> Placement | None:
    """``n_repeaters`` evenly spaced along the span -- the naive baseline.

    Present so an optimised layout has something to beat.  "Better" without a
    control is not a result, and evenly-spaced is what a planner does by hand.
    """
    if n_repeaters < 0:
        raise ValueError("n_repeaters must be non-negative")
    span = problem.span_km
    positions = [problem.end_a.position_km + span * i / (n_repeaters + 1)
                 for i in range(n_repeaters + 2)]
    sites = [problem.end_a]
    for i, position in enumerate(positions[1:-1]):
        sites.append(CandidateSite(name=f"U{i}", position_km=position))
    sites.append(problem.end_b)
    return _placement_from_sites(problem, sites, method="uniform")


# Robust placement

@dataclass(frozen=True)
class Scenario:
    """One hardware assumption set the layout must survive.

    Named so a report can say *which* assumption a layout failed under, which is
    the question a planner actually asks.
    """

    name: str
    t1_s: float
    t2_s: float

    def __post_init__(self):
        if self.t1_s <= 0 or self.t2_s <= 0:
            raise ValueError("coherence times must be positive")


def robust_placement(problem: PlacementProblem,
                     scenarios: list[Scenario],
                     max_repeaters: int | None = None) -> Placement | None:
    """A layout that satisfies the fidelity requirement under every scenario.

    Scenario-based robustness over a caller-supplied set.  It is *not* a chance
    constraint and makes no claim about a distribution over hardware parameters:
    it says the layout meets the requirement for each scenario given, and
    nothing about scenarios not given.

    This is the part of placement that is genuinely open -- a targeted search
    found no published robust or chance-constrained formulation over continuous
    hardware uncertainty, only discrete component survivability and post-hoc
    sensitivity analysis.
    """
    if not scenarios:
        raise ValueError("at least one scenario is required")

    # Sorted once, and the DP is indexed by this order -- see best_placement
    # for why mixing position order with index order is a silent bug.
    sites = sorted(problem.all_sites(), key=lambda s: s.position_km)
    n = len(sites)

    def chain_meets(positions: list[float]) -> bool:
        """True when the *whole* chain meets the requirement in every scenario.

        Feasibility is a property of the completed chain, not of individual
        spans.  Each swap has its own fidelity cost, so a path with more hops
        carries more swap penalty than a single span of the same total length --
        which is exactly the trade-off robust placement has to navigate.
        Checking spans in isolation instead marks hop-heavy paths feasible and
        then reports a layout that fails the requirement it was built for.
        """
        for scenario in scenarios:
            quality = _chain_from_positions(positions, problem,
                                            scenario.t1_s, scenario.t2_s, None)
            if quality.end_to_end_fidelity < problem.required_fidelity:
                return False
        return True

    # A cheap prefilter on single spans in the worst scenario: it only rejects an edge
    # that cannot work on its own, so it never drops a span a completed chain needs.
    worst = min(scenarios, key=lambda s: s.t1_s * s.t2_s)
    viable: set[tuple[int, int]] = set()
    for i in range(n):
        for j in range(i + 1, n):
            positions = [sites[i].position_km, sites[j].position_km]
            quality = _chain_from_positions(positions, problem,
                                            worst.t1_s, worst.t2_s, None)
            if quality.end_to_end_fidelity >= problem.required_fidelity:
                viable.add((i, j))

    per_link_survival = 1.0
    if worst.t1_s > 0:
        per_link_survival *= float(np.exp(-problem.t_swap_s / worst.t1_s))
    if worst.t2_s > 0:
        per_link_survival *= float(np.exp(-problem.t_swap_s / worst.t2_s))

    edge_rate: dict[tuple[int, int], float] = {}
    edge_werner: dict[tuple[int, int], float] = {}
    for i, j in viable:
        length = sites[j].position_km - sites[i].position_km
        edge_rate[(i, j)] = elementary_link_rate(length, problem)
        f_link = elementary_link_fidelity(length, problem)
        w_link = float(np.clip((4.0 * f_link - 1.0) / 3.0, 0.0, 1.0))
        edge_werner[(i, j)] = w_link * per_link_survival

    # DP over the viable edges with a Pareto frontier, as in best_placement.
    # Fidelity gates feasibility, so one best rate per state is not enough.
    limit = n if max_repeaters is None else max_repeaters
    state: list[dict[int, list[tuple[float, float, list[int]]]]] = [
        {} for _ in range(n)
    ]
    state[0][0] = [(float("inf"), 1.0, [0])]

    for i in range(n - 1):
        if not state[i]:
            continue
        for used, frontier in list(state[i].items()):
            for prefix_rate, prefix_werner, path in list(frontier):
                for j in range(i + 1, n):
                    if (i, j) not in viable:
                        continue
                    new_used = used if j == n - 1 else used + 1
                    if new_used > limit:
                        continue
                    candidate_path = path + [j]
                    if j == n - 1:
                        positions = [sites[p].position_km for p in candidate_path]
                        if not chain_meets(positions):
                            continue
                        quality = _chain_from_positions(positions, problem,
                                                        worst.t1_s, worst.t2_s, None)
                        state[j].setdefault(new_used, [])
                        _pareto_insert(state[j][new_used], quality.key_rate_hz,
                                       quality.end_to_end_fidelity, candidate_path)
                    else:
                        new_rate = min(prefix_rate, edge_rate[(i, j)])
                        new_werner = prefix_werner * edge_werner[(i, j)]
                        state[j].setdefault(new_used, [])
                        _pareto_insert(state[j][new_used], new_rate, new_werner,
                                       candidate_path)

    if not state[n - 1]:
        return None
    entries = [entry for frontier in state[n - 1].values() for entry in frontier]
    if not entries:
        return None
    _, _, path = max(entries, key=lambda e: e[0])
    chosen = [sites[i] for i in path]
    placement = _placement_from_sites(problem, chosen, method="robust",
                                      t1_s=worst.t1_s, t2_s=worst.t2_s)
    placement.method = "robust[" + ",".join(s.name for s in scenarios) + "]"
    return placement


def survival_report(placement: Placement,
                    problem: PlacementProblem,
                    scenarios: list[Scenario]) -> list[dict]:
    """Evaluate one placement under each scenario.

    The diagnostic that shows whether robustness *bought* anything: a nominal
    layout that fails a scenario it was not optimised for is exactly the failure
    a planner needs to see before committing capital.
    """
    report = []
    for scenario in scenarios:
        quality = chain_quality(placement.positions_km, problem,
                                t1_s=scenario.t1_s, t2_s=scenario.t2_s)
        report.append({
            "scenario": scenario.name,
            "t1_s": scenario.t1_s,
            "t2_s": scenario.t2_s,
            "end_to_end_fidelity": quality.end_to_end_fidelity,
            "key_rate_hz": quality.key_rate_hz,
            "meets_requirement": (quality.end_to_end_fidelity
                                  >= problem.required_fidelity),
        })
    return report
