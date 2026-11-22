"""Multi-commodity routing under contention.

The distinction that makes this a milestone rather than a re-run of M3
-----------------------------------------------------------------------
M3 already models contention: several demands compete for a finite memory pool
and some are refused.  But there the **route is chosen first** and contention only
decides whether the demand is *accepted*.  The path never changes because the
network is busy.

That is the modelling gap this closes.  With several commodities in flight, the
right question is not "is this path free" but "which path should this commodity
take, *given what the others are already using*".  Those give different answers,
and the second is the one a network operator faces.

What is reported, and what it is measured against
-------------------------------------------------
The claim worth testing is that **congestion-aware routing grants strictly more
demand than congestion-blind routing on the same commodity set**.  So both are
run over identical inputs and compared; if they agree, the implementation is not
doing anything and the test says so rather than reporting a number.

Both use the same resource model, the same arbitration and the same kernel as the
rest of QEL.  Congestion-aware differs in exactly one respect: it scores
candidate paths by residual memory capacity along the path -- hops that are
already committed cost more -- instead of by hop count alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .graph import QuantumTopology
from .strategies import make_strategy


class CommodityError(ValueError):
    """Raised for an invalid commodity set."""


@dataclass(frozen=True)
class Commodity:
    """One source-destination pair with a number of units to deliver."""

    name: str
    source: str
    target: str
    units: int = 1

    def __post_init__(self):
        if self.units < 1:
            raise CommodityError(
                f"commodity {self.name!r} must request at least one unit"
            )


@dataclass
class CommodityRoute:
    """One commodity's assigned path and what it consumed."""

    commodity: Commodity
    path: tuple[str, ...]
    hops: int
    congestion_cost: float
    granted: bool = True
    reason: str | None = None

    def describe(self) -> str:
        if not self.granted:
            return f"REFUSED {self.commodity.name}: {self.reason}"
        return (f"{self.commodity.name}: {' -> '.join(self.path)} "
                f"({self.hops} hops, load {self.congestion_cost:.1f})")


@dataclass
class MultiCommodityPlan:
    """The outcome of routing a whole commodity set."""

    routes: list[CommodityRoute] = field(default_factory=list)
    strategy: str = "congestion-aware"

    @property
    def granted(self) -> list[CommodityRoute]:
        return [r for r in self.routes if r.granted]

    @property
    def refused(self) -> list[CommodityRoute]:
        return [r for r in self.routes if not r.granted]

    @property
    def units_granted(self) -> int:
        return sum(r.commodity.units for r in self.granted)

    @property
    def units_requested(self) -> int:
        return sum(r.commodity.units for r in self.routes)

    @property
    def total_hops(self) -> int:
        return sum(r.hops for r in self.granted)

    def node_load(self) -> dict[str, int]:
        """How many commodities use each intermediate node.

        The quantity congestion-aware routing is trying to keep even.  Reported
        so a comparison can be argued about rather than taken on trust.
        """
        load: dict[str, int] = {}
        for route in self.granted:
            for node in route.path[1:-1]:
                load[node] = load.get(node, 0) + route.commodity.units
        return load

    def describe(self) -> str:
        lines = [f"Multi-commodity plan ({self.strategy}): "
                 f"{self.units_granted}/{self.units_requested} units over "
                 f"{len(self.granted)} commodities, {self.total_hops} hops"]
        lines.extend("  " + r.describe() for r in self.routes)
        load = self.node_load()
        if load:
            spread = ", ".join(f"{n}={c}" for n, c in sorted(load.items()))
            lines.append(f"  intermediate load: {spread}")
        return "\n".join(lines)


def _path_congestion(path: tuple[str, ...], load: dict[str, int],
                     capacity: int, units: int = 1) -> float:
    """Cost of a path given current committed load.

    Base cost is hop count, so among equally loaded paths the shorter one still
    wins.  On top of that, each intermediate node contributes a penalty that
    **scales with the load the new commodity would add to it** -- zero when the
    node is empty, rising steeply as it fills.

    Getting that shape right matters.  A penalty that is merely *large* for a
    loaded node does not work if it is equally large for an empty one: it then
    cancels out between alternatives, the comparison falls through to hop count,
    and the router silently behaves like the congestion-blind one while looking
    like it does something.  That was the first version's bug, and it showed up as
    identical plans from both strategies.
    """
    cost = float(len(path) - 1)
    for node in path[1:-1]:
        used = load.get(node, 0) + units
        # 1.0 at half capacity, unbounded as it approaches the limit.
        cost += 4.0 * (used / capacity) ** 2
    return cost


def plan_commodities(
    topology: QuantumTopology,
    commodities: list[Commodity],
    *,
    capacity: int = 1,
    strategy: str = "congestion-aware",
    routing: str = "shortest-distance",
) -> MultiCommodityPlan:
    """Route every commodity, letting congestion influence the path.

    ``strategy``:

    * ``"congestion-aware"`` -- score candidate paths by residual capacity along
      the path, so a commodity is pushed away from hops the others already use.
    * ``"shortest-path"`` -- score by hop count alone, ignoring load.  This is the
      congestion-*blind* baseline the other has to beat.

    ``capacity`` is how many units an intermediate node can hold **at once**.
    This models a node with several parallel memory slots -- a quantum switch
    with a bank of memories -- rather than one memory that gets reused.  At
    ``capacity=1`` every intermediate node is a hard bottleneck and the two
    strategies diverge most; at large capacity they agree, and the tests check
    both so that agreement cannot be mistaken for correctness.

    Both strategies share one thing deliberately: commodity processing order.  If
    the blind strategy also got a worse order the comparison would measure two
    changes at once and neither would be attributable.
    """
    if strategy not in ("congestion-aware", "shortest-path"):
        raise CommodityError(
            f"strategy must be 'congestion-aware' or 'shortest-path', "
            f"got {strategy!r}"
        )
    if capacity < 1:
        raise CommodityError(f"capacity must be at least 1, got {capacity}")

    plan = MultiCommodityPlan(strategy=strategy)
    load: dict[str, int] = {}

    for commodity in commodities:
        if commodity.source not in topology.nodes:
            plan.routes.append(CommodityRoute(
                commodity, (), 0, 0.0, granted=False,
                reason=f"unknown source {commodity.source!r}"))
            continue
        if commodity.target not in topology.nodes:
            plan.routes.append(CommodityRoute(
                commodity, (), 0, 0.0, granted=False,
                reason=f"unknown target {commodity.target!r}"))
            continue

        candidates = _k_shortest_paths(
            topology, commodity.source, commodity.target, k=8)
        if not candidates:
            plan.routes.append(CommodityRoute(
                commodity, (), 0, 0.0, granted=False, reason="no path exists"))
            continue

        if strategy == "shortest-path":
            # The blind baseline takes the same capacity limit as the aware one, it just
            # cannot route around congestion; overcommitting it would be meaningless.
            fitting = [p for p in candidates
                       if all(load.get(n, 0) + commodity.units <= capacity
                              for n in p[1:-1])]
            if not fitting:
                chosen = min(candidates, key=lambda p: (len(p), p))
                plan.routes.append(CommodityRoute(
                    commodity, chosen, len(chosen) - 1,
                    float(len(chosen) - 1), granted=False,
                    reason="shortest path is at capacity"))
                continue
            chosen = min(fitting, key=lambda p: (len(p), p))
            cost = float(len(chosen) - 1)
        else:
            scored = [(p, _path_congestion(p, load, capacity, commodity.units))
                      for p in candidates]
            feasible = [(p, c) for p, c in scored
                        if all(load.get(n, 0) + commodity.units <= capacity
                               for n in p[1:-1])]
            if not feasible:
                # Nothing fits: refuse rather than overcommit, which would look better
                # and be wrong.
                chosen, cost = min(scored, key=lambda item: (item[1], item[0]))
                plan.routes.append(CommodityRoute(
                    commodity, chosen, len(chosen) - 1, cost, granted=False,
                    reason="every path is at capacity"))
                continue
            chosen, cost = min(feasible, key=lambda item: (item[1], item[0]))

        for node in chosen[1:-1]:
            load[node] = load.get(node, 0) + commodity.units
        plan.routes.append(CommodityRoute(
            commodity, chosen, len(chosen) - 1, cost, granted=True))

    return plan


def _k_shortest_paths(topology: QuantumTopology, source: str, target: str,
                      k: int = 6) -> list[tuple[str, ...]]:
    """Up to ``k`` simple paths, shortest first, by breadth-first enumeration.

    Deliberately simple and exhaustive-with-a-cap rather than a Yen
    implementation: the candidate set only has to contain the alternatives a
    congestion-aware router would consider, and enumerating them keeps the
    behaviour inspectable.  Paths are returned as tuples so they are hashable and
    ordering is deterministic.
    """
    if source == target:
        return [(source,)]

    found: list[tuple[str, ...]] = []
    queue: list[tuple[str, ...]] = [(source,)]
    best_length: int | None = None
    limit = len(topology.nodes) + 1

    while queue and len(found) < k * 4:
        path = queue.pop(0)
        if best_length is not None and len(path) > best_length:
            continue
        for neighbour in sorted(topology.neighbors(path[-1])):
            if neighbour in path:
                continue
            extended = path + (neighbour,)
            if neighbour == target:
                if best_length is None:
                    best_length = len(extended)
                if len(extended) <= best_length:
                    found.append(extended)
                continue
            if len(extended) < limit:
                queue.append(extended)

    # Keep only the k shortest, deduplicated, deterministic.
    unique = sorted(set(found), key=lambda p: (len(p), p))
    return unique[:k]


def compare_routing_strategies(
    topology: QuantumTopology,
    commodities: list[Commodity],
    *,
    capacity: int = 1,
) -> dict:
    """Run both strategies on identical input and report the difference.

    The returned dictionary is the evidence for or against the milestone's claim,
    so it carries the raw plans as well as the summary: a summary alone cannot be
    checked.
    """
    aware = plan_commodities(topology, commodities, capacity=capacity,
                             strategy="congestion-aware")
    blind = plan_commodities(topology, commodities, capacity=capacity,
                             strategy="shortest-path")
    return {
        "commodities": len(commodities),
        "units_requested": aware.units_requested,
        "aware": aware,
        "blind": blind,
        "units_aware": aware.units_granted,
        "units_blind": blind.units_granted,
        "advantage_units": aware.units_granted - blind.units_granted,
        "hops_aware": aware.total_hops,
        "hops_blind": blind.total_hops,
        "max_node_load_aware": max(aware.node_load().values(), default=0),
        "max_node_load_blind": max(blind.node_load().values(), default=0),
    }
