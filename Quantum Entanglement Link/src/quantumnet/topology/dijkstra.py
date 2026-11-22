"""Dijkstra routing over fidelity as cost, for graphs where the bounded DFS
in ``routing.all_simple_paths`` exhausts its visit budget before finding the
good paths (dense topologies, 500+ nodes).

Cost model
----------
Werner swap noise multiplies in the Werner parameter
``w = (4F - 1) / 3`` (see ``routing.swapped_fidelity``), so for a path of
links the end-to-end Werner parameter is ``w_path = Π w_i`` and the
end-to-end fidelity is ``F = (1 + 3 w_path) / 4``.

Maximising ``F`` therefore equals maximising ``Σ log w_i`` over the path,
i.e. minimising ``Σ -log w_i``, a *sum* of non-negative edge costs when
``0 < w_i <= 1`` (true for any physical link, F > 0.25).  That is exactly
Dijkstra's requirement, so plain Dijkstra with edge weight ``-log w_i``
returns the fidelity-optimal path.

k-shortest paths uses the standard simple-path exclusion method (Yen's
algorithm without the splicing shortcut): find the best path, temporarily
remove one of its edges, re-run Dijkstra, repeat.  k is small (default 4)
so the total cost is k Dijkstra runs.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass
from typing import Sequence

from .graph import QuantumTopology
from .routing import Route, optimal_swap_order


@dataclass
class DemandPair:
    """One src/dst demand for the multi-commodity rate table."""

    src: str
    dst: str
    min_fidelity: float = 0.0


def _edge_cost(link) -> float:
    """Dijkstra edge weight for a link: ``-log(w)`` where ``w`` is the
    Werner parameter of the link fidelity.  Returns ``inf`` for a link whose
    fidelity is at or below the classical limit (F <= 0.25 ⇒ w <= 0): such a
    link can never carry entanglement, so no path may use it."""
    f = link.fidelity()
    w = (4.0 * f - 1.0) / 3.0
    if w <= 0.0:
        return math.inf
    return -math.log(w)


def dijkstra_best_route(topo: QuantumTopology, src: str, dst: str,
                        min_fidelity: float = 0.0) -> Route | None:
    """Fidelity-optimal route via Dijkstra on ``-log(Werner parameter)``.

    ``O(E log V)``: no hop bound and no enumeration, so it scales to dense
    500-node graphs where the bounded DFS does not.  Returns None when the
    destination is unreachable or the best path's fidelity is below
    ``min_fidelity``.
    """
    if src not in topo.nodes or dst not in topo.nodes:
        return None
    if src == dst:
        return None

    dist: dict[str, float] = {src: 0.0}
    prev: dict[str, str] = {}
    visited: set[str] = set()
    heap = [(0.0, src)]
    while heap:
        d, u = heapq.heappop(heap)
        if u in visited:
            continue
        visited.add(u)
        if u == dst:
            break
        for v in topo.neighbors(u):
            if v in visited:
                continue
            link = topo.link(u, v)
            if link is None:
                continue
            nd = d + _edge_cost(link)
            if nd < dist.get(v, math.inf):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(heap, (nd, v))

    if dst not in visited:
        return None

    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    path.reverse()

    fids: list[float] = []
    for a, b in zip(path, path[1:]):
        fids.append(topo.link_fidelity(a, b))
    order, final = optimal_swap_order(fids)
    if final < min_fidelity - 1e-12:
        return None
    return Route(path=path, link_fidelities=fids, e2e_fidelity=final,
                 swap_order=order)


def k_shortest_routes(topo: QuantumTopology, src: str, dst: str, k: int = 4,
                      min_fidelity: float = 0.0) -> list[Route]:
    """The ``k`` best simple paths by end-to-end fidelity.

    Simple-path exclusion: after each Dijkstra run the best path found is
    banned by removing one of its edges from the working copy, and the next
    run must route around it.  Each route is independent (the bans are not
    cumulative across accepted paths), so the results are k distinct paths
    ranked best-first.
    """
    routes: list[Route] = []
    banned: set[tuple[str, str]] = set()
    while len(routes) < k:
        route = _dijkstra_with_bans(topo, src, dst, banned, min_fidelity)
        if route is None:
            break
        routes.append(route)
        # Ban the last edge of the accepted path: removing any edge breaks
        # this exact path; the last edge forces maximum divergence from it.
        banned.add(_key(route.path[-2], route.path[-1]))
    return routes


def _dijkstra_with_bans(topo: QuantumTopology, src: str, dst: str,
                        banned: set[tuple[str, str]],
                        min_fidelity: float) -> Route | None:
    """One Dijkstra run that refuses to traverse ``banned`` edges."""
    if src not in topo.nodes or dst not in topo.nodes or src == dst:
        return None
    dist: dict[str, float] = {src: 0.0}
    prev: dict[str, str] = {}
    visited: set[str] = set()
    heap = [(0.0, src)]
    while heap:
        d, u = heapq.heappop(heap)
        if u in visited:
            continue
        visited.add(u)
        if u == dst:
            break
        for v in topo.neighbors(u):
            if v in visited or _key(u, v) in banned:
                continue
            link = topo.link(u, v)
            if link is None:
                continue
            nd = d + _edge_cost(link)
            if nd < dist.get(v, math.inf):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(heap, (nd, v))
    if dst not in visited:
        return None
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    path.reverse()
    fids = [topo.link_fidelity(a, b) for a, b in zip(path, path[1:])]
    order, final = optimal_swap_order(fids)
    if final < min_fidelity - 1e-12:
        return None
    return Route(path=path, link_fidelities=fids, e2e_fidelity=final,
                 swap_order=order)


def _key(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a <= b else (b, a)


def multi_demand_routes(topo: QuantumTopology,
                        demands: Sequence[DemandPair],
                        max_hops: int = 6,
                        use_dijkstra: bool | None = None) -> dict[tuple[str, str], Route | None]:
    """Route every (src, dst) in ``demands`` and return ``{(src, dst): route}``.

    Dense-graph fast path: ``use_dijkstra`` defaults to on when the topology
    is large enough that enumerating simple paths would be slow (edges above
    ~2000) or when a demand needs more hops than the bounded DFS allows.
    Sparse topologies keep the exhaustive DFS ranking so ``rank_routes``
    semantics (all paths considered, best chosen) are preserved.
    """
    from .routing import best_route

    out: dict[tuple[str, str], Route | None] = {}
    n_edges = len(topo.links)
    for demand in demands:
        key = (demand.src, demand.dst)
        dijkstra = use_dijkstra
        if dijkstra is None:
            dijkstra = n_edges > 2000 or max_hops > 8
        if dijkstra:
            out[key] = dijkstra_best_route(topo, demand.src, demand.dst,
                                           min_fidelity=demand.min_fidelity)
        else:
            out[key] = best_route(topo, demand.src, demand.dst,
                                  max_hops=max_hops,
                                  min_fidelity=demand.min_fidelity)
    return out
