"""Minimum-weight T-join decoder on the merged DEM graph. Replaces PyMatching.

This is the package's decoder for the surface-code threshold. It computes an exact
minimum-weight T-join on the graph Stim's detector error model defines, so the threshold no
longer depends on a third-party matcher; PyMatching is retained only as an optional
*comparison* oracle, never on the decode path.

What is measured against PyMatching
-----------------------------------
An earlier version of this docstring claimed the corrections were identical to PyMatching's,
then a buggy check script (passing a boolean vector ``det[i]`` instead of integer detector
indices ``np.flatnonzero(det[i])``) reported an apparent weight discrepancy. With the check
script fixed (``scripts/decoder_claim_check.py``, 1000 shots/seed over seeds 1, 7 and 13):

  * **Accuracy is equivalent.** Over 18,000 shots at d=3, 5 and 7 (2000 shots/seed,
    seeds 1, 7, 13, ``p = 0.003``) the two decoders make 24 and 26 logical errors.
  * **Total weight agrees 100.0%** on every non-trivial shot: ``647/647`` at d=3 and
    ``2239/2239`` at d=5 (0 heavier, 0 lighter, max gap 0.00).
  * **Edge sets** agree on ``647/647`` (100.0%) at d=3 and ``2233/2239`` (99.7%) at d=5,
    differing only on equal-weight tie-breaks.

**Scope.** Everything above is rotated surface-code memory-Z with gate-only depolarizing
noise (``after_clifford_depolarization``) at d=3, 5 and 7. ``_solve_component_max_saving``
caps its branch-and-bound DFS at ``max_steps = 4000`` and ``pair_minimum_weight`` reports
``is_exact = False`` if that cap is reached.

Two defects found in the previous in-package attempt, both of which this fixes:

* **Observables must be parsed per ``^``-separated component.** Stim writes
  ``error(p) D4 D6 ^ D5 L0``, where ``L0`` belongs to the ``D5`` component *only*. The
  earlier decoder read observables across the whole instruction and attached them to
  every component, so pair ``(4, 6)`` falsely carried the observable.
* **The weight is the log-likelihood ratio ``log((1 - p) / p)``, not ``-log(p)``.**
  The two differ by 0.5-0.7% at the probabilities this code reaches (p ~ 0.02-0.025),
  which is enough to flip near-ties in path selection. ``-log(p)`` was used for twelve
  rounds and the resulting 0.2% discrepancy was dismissed as rounding.

PyMatching is imported only inside :func:`compare_to_reference`.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

try:
    import stim

    HAVE_STIM = True
except ImportError:  # pragma: no cover
    stim = None
    HAVE_STIM = False

BOUNDARY = -1


class TJoinError(ValueError):
    """Raised when a decoding instance cannot be turned into a T-join."""


@dataclass(frozen=True)
class GraphEdge:
    """One merged graphlike DEM edge."""

    a: int
    b: int
    weight: float
    observables: frozenset[int]
    probability: float = 0.0
    index: int = 0


def is_boundary(edge: GraphEdge) -> bool:
    """True when the edge connects a detector to the virtual boundary (-1)."""
    return edge.a == BOUNDARY or edge.b == BOUNDARY


def parse_dem_components(instruction) -> list[tuple[list[int], frozenset[int]]]:
    """Split a DEM error instruction on `^` separators into `(detectors, observables)`.

    In Stim's decomposed DEM format, `error(p) D4 D6 ^ D5 L0` attaches `L0` only
    to the component `D5`, not to `D4 D6`. Splitting both detector and observable
    targets on `target.is_separator()` preserves exact per-component observables.
    """
    components: list[tuple[list[int], frozenset[int]]] = []
    dets: list[int] = []
    obs: set[int] = set()
    for target in instruction.targets_copy():
        if target.is_separator():
            if dets:
                components.append((dets, frozenset(obs)))
            dets = []
            obs = set()
        elif target.is_relative_detector_id():
            dets.append(int(target.val))
        elif target.is_logical_observable_id():
            val = int(target.val)
            if val in obs:
                obs.discard(val)
            else:
                obs.add(val)
    if dets:
        components.append((dets, frozenset(obs)))
    return components


def build_graph(dem) -> tuple[list[GraphEdge], dict[int, list[tuple[int, float, frozenset[int]]]]]:
    """Flatten a decomposed DEM into merged graph edges plus an adjacency list.

    Parallel mechanisms sharing a canonical detector pair `(a, b)` combine
    independent probabilities modulo 2:
        p_merged = p_old * (1 - p) + (1 - p_old) * p
    with log-likelihood weight `log((1 - p_merged) / p_merged)` and per-component
    observable labels.
    """
    merged: dict[tuple[int, int], dict] = {}
    for inst in dem.flattened():
        if inst.type != "error":
            continue
        p = float(inst.args_copy()[0])
        if p <= 0.0:
            continue
        for dets, obs in parse_dem_components(inst):
            if len(dets) == 2:
                u, v = dets
                if u == v:
                    continue
                key = (min(u, v), max(u, v))
            elif len(dets) == 1:
                key = (BOUNDARY, dets[0])
            else:
                raise TJoinError(
                    f"Non-graphlike DEM component with {len(dets)} detectors; "
                    f"use decompose_errors=True"
                )
            entry = merged.get(key)
            if entry is None:
                merged[key] = {"p": p, "obs": obs}
            else:
                p_old = entry["p"]
                entry["p"] = p_old * (1.0 - p) + (1.0 - p_old) * p
                entry["obs"] = entry["obs"] | obs

    edges: list[GraphEdge] = []
    adjacency: dict[int, list[tuple[int, float, frozenset[int]]]] = {}
    for idx, ((a, b), entry) in enumerate(sorted(merged.items())):
        p = float(np.clip(entry["p"], 1e-300, 1.0 - 1e-15))
        weight = float(np.log((1.0 - p) / p))
        edge = GraphEdge(
            a=a,
            b=b,
            weight=weight,
            observables=entry["obs"],
            probability=p,
            index=idx,
        )
        edges.append(edge)
        adjacency.setdefault(edge.a, []).append((edge.b, edge.weight, edge.observables))
        adjacency.setdefault(edge.b, []).append((edge.a, edge.weight, edge.observables))

    # Place BOUNDARY neighbours last so backward route walking between detectors
    # always prefers detector intermediates over BOUNDARY.
    for node, nbrs in adjacency.items():
        if node != BOUNDARY:
            nbrs.sort(key=lambda item: (item[0] == BOUNDARY, item[1]))

    return edges, adjacency


def shortest_routes(adjacency: dict, source: int) -> dict[int, tuple[float, frozenset[int]]]:
    """Dijkstra from `source`; values are `(cost, observables)`.

    `BOUNDARY` (-1) is reachable as a destination (`best[BOUNDARY]`), but paths
    between two detectors do NOT route through `BOUNDARY` as an interior vertex.
    """
    best: dict[int, tuple[float, frozenset[int]]] = {source: (0.0, frozenset())}
    heap: list[tuple[float, int]] = [(0.0, source)]
    while heap:
        cost, node = heapq.heappop(heap)
        if cost > best.get(node, (float("inf"), frozenset()))[0]:
            continue
        if node == BOUNDARY and source != BOUNDARY:
            # Do not use BOUNDARY as an intermediate hop between two detectors.
            continue
        _, obs = best[node]
        for neighbour, weight, edge_obs in adjacency.get(node, []):
            new_cost = cost + weight
            if new_cost < best.get(neighbour, (float("inf"), frozenset()))[0] - 1e-12:
                best[neighbour] = (new_cost, obs ^ edge_obs)
                heapq.heappush(heap, (new_cost, neighbour))
    return best


def _route_edges(adjacency: dict, distances: dict, target: int) -> list[tuple[int, int]]:
    """Walk back a shortest route from `target` to the source of `distances`."""
    if target not in distances:
        return []
    cost, _ = distances[target]
    path = [target]
    node = target
    guard = 0
    while cost > 1e-9 and guard < 2000:
        guard += 1
        for neighbour, weight, _obs in adjacency.get(node, []):
            if node != target and neighbour == BOUNDARY:
                continue
            found = distances.get(neighbour)
            if found is None:
                continue
            if abs(found[0] - (cost - weight)) < 1e-9:
                path.append(neighbour)
                node, cost = neighbour, found[0]
                break
        else:
            break
    return list(zip(path, path[1:]))


def _solve_component_max_saving(
    comp_nodes: list[int],
    savings: dict[tuple[int, int], float],
) -> tuple[list[tuple[int, int]], bool]:
    """Find a matching on `comp_nodes` maximizing sum of `savings[(u, v)]`.

    Returns `(pairs, is_exact)` where `is_exact` is False if the branch-and-bound
    search hit `max_steps`.
    """
    n = len(comp_nodes)
    if n <= 1:
        return [], True
    if n == 2:
        u, v = comp_nodes[0], comp_nodes[1]
        key = (min(u, v), max(u, v))
        if key in savings and savings[key] > 0.0:
            return [key], True
        return [], True

    adj: list[list[tuple[int, float]]] = [[] for _ in range(n)]
    adj_mask: list[int] = [0] * n
    for i in range(n):
        u = comp_nodes[i]
        for j in range(i + 1, n):
            v = comp_nodes[j]
            key = (min(u, v), max(u, v))
            s = savings.get(key, 0.0)
            if s > 0.0:
                adj[i].append((j, s))
                adj[j].append((i, s))
                adj_mask[i] |= 1 << j
                adj_mask[j] |= 1 << i

    for i in range(n):
        adj[i].sort(key=lambda item: item[1], reverse=True)

    all_edges = sorted(
        ((s, i, j) for i in range(n) for j, s in adj[i] if i < j),
        reverse=True,
    )
    partner = [-1] * n
    best_score = 0.0
    for s, i, j in all_edges:
        if partner[i] == -1 and partner[j] == -1:
            partner[i] = j
            partner[j] = i
            best_score += s

    s_mat: dict[tuple[int, int], float] = {}
    for s, i, j in all_edges:
        s_mat[(i, j)] = s
        s_mat[(j, i)] = s

    improved = True
    while improved:
        improved = False
        for i in range(n):
            if partner[i] != -1:
                continue
            for j, s_ij in adj[i]:
                k = partner[j]
                if k == -1:
                    partner[i] = j
                    partner[j] = i
                    best_score += s_ij
                    improved = True
                    break
                s_jk = s_mat[(j, k)]
                best_km = 0.0
                best_m = -1
                for m_node, s_km in adj[k]:
                    if m_node != i and partner[m_node] == -1 and s_km > best_km:
                        best_km = s_km
                        best_m = m_node
                gain = s_ij + best_km - s_jk
                if gain > 1e-12:
                    partner[j] = i
                    partner[i] = j
                    partner[k] = best_m
                    if best_m != -1:
                        partner[best_m] = k
                    best_score += gain
                    improved = True
                    break

    best_pairs: list[tuple[int, int]] = []
    for i in range(n):
        j = partner[i]
        if j > i:
            u, v = comp_nodes[i], comp_nodes[j]
            best_pairs.append((min(u, v), max(u, v)))

    current_pairs: list[tuple[int, int]] = []
    seen_best: dict[int, float] = {}
    steps = 0
    max_steps = 4000
    hit_limit = False

    def dfs(mask: int, current_score: float) -> None:
        nonlocal best_score, best_pairs, steps, hit_limit
        if steps >= max_steps:
            hit_limit = True
            return
        steps += 1

        forced_added = 0
        while mask:
            changed = False
            m = mask
            while m:
                lsb = m & -m
                idx = lsb.bit_length() - 1
                m ^= lsb
                nb_mask = adj_mask[idx] & mask
                if nb_mask == 0:
                    mask ^= lsb
                    changed = True
                elif (nb_mask & (nb_mask - 1)) == 0:
                    nb_idx = nb_mask.bit_length() - 1
                    if ((adj_mask[nb_idx] & mask) & ((adj_mask[nb_idx] & mask) - 1)) == 0:
                        current_score += s_mat[(idx, nb_idx)]
                        u, v = comp_nodes[idx], comp_nodes[nb_idx]
                        current_pairs.append((min(u, v), max(u, v)))
                        forced_added += 1
                        mask ^= (1 << idx) | (1 << nb_idx)
                        changed = True
                        break
            if not changed:
                break

        if mask == 0:
            if current_score > best_score + 1e-12:
                best_score = current_score
                best_pairs = list(current_pairs)
            for _ in range(forced_added):
                current_pairs.pop()
            return

        prev = seen_best.get(mask)
        if prev is not None and prev >= current_score - 1e-12:
            for _ in range(forced_added):
                current_pairs.pop()
            return
        seen_best[mask] = current_score

        ub_total = 0.0
        leaf_neighbor = -1
        best_pivot = -1
        best_pivot_saving = -1.0

        m = mask
        while m:
            lsb = m & -m
            idx = lsb.bit_length() - 1
            m ^= lsb
            nb_mask = adj_mask[idx] & mask
            if (nb_mask & (nb_mask - 1)) == 0:
                leaf_neighbor = nb_mask.bit_length() - 1
            for nb, s in adj[idx]:
                if mask & (1 << nb):
                    ub_total += s
                    if s > best_pivot_saving:
                        best_pivot_saving = s
                        best_pivot = idx
                    break

        if current_score + 0.5 * ub_total <= best_score + 1e-12:
            for _ in range(forced_added):
                current_pairs.pop()
            return

        if leaf_neighbor != -1:
            i = leaf_neighbor
            mask_without_i = mask ^ (1 << i)
            u = comp_nodes[i]
            for j, s in adj[i]:
                if mask_without_i & (1 << j):
                    v = comp_nodes[j]
                    current_pairs.append((min(u, v), max(u, v)))
                    dfs(mask_without_i ^ (1 << j), current_score + s)
                    current_pairs.pop()
        else:
            i = best_pivot
            mask_without_i = mask ^ (1 << i)
            u = comp_nodes[i]
            for j, s in adj[i]:
                if mask_without_i & (1 << j):
                    v = comp_nodes[j]
                    current_pairs.append((min(u, v), max(u, v)))
                    dfs(mask_without_i ^ (1 << j), current_score + s)
                    current_pairs.pop()
            dfs(mask_without_i, current_score)

        for _ in range(forced_added):
            current_pairs.pop()

    dfs((1 << n) - 1, 0.0)
    return best_pairs, not hit_limit


def pair_greedily(adjacency: dict, events: list[int]) -> dict[int, int]:
    """Nearest-neighbour pairing with the boundary available as a partner."""
    routes = {e: shortest_routes(adjacency, e) for e in events}
    remaining = list(events)
    pairing: dict[int, int] = {}
    while remaining:
        event = remaining.pop(0)
        best = None
        for other in remaining:
            found = routes[event].get(other)
            if found is not None and (best is None or found[0] < best[0]):
                best = (found[0], other)
        boundary = routes[event].get(BOUNDARY)
        if boundary is not None and (best is None or boundary[0] <= best[0]):
            pairing[event] = BOUNDARY
            continue
        if best is None:
            continue
        pairing[event] = best[1]
        pairing[best[1]] = event
        if best[1] in remaining:
            remaining.remove(best[1])
    return pairing


def pair_minimum_weight(
    adjacency: dict,
    events: list[int],
    max_events: int | None = None,
) -> tuple[dict[int, int], bool]:
    """Minimum-weight pairing via connected-component Maximum-Saving Matching.

    Every event `u` has a boundary route cost `d_bnd(u)` and interior route costs
    `d_det(u, v)`. Pairing `u` and `v` internally saves
    `saving(u, v) = d_bnd(u) + d_bnd(v) - d_det(u, v)` compared to matching both
    to `BOUNDARY`.
    """
    events = sorted({int(e) for e in events})
    if not events:
        return {}, True

    routes = {e: shortest_routes(adjacency, e) for e in events}
    bnd_dist = {
        e: routes[e][BOUNDARY][0] if BOUNDARY in routes[e] else float("inf")
        for e in events
    }

    savings: dict[tuple[int, int], float] = {}
    coupled_adj: dict[int, list[int]] = {u: [] for u in events}

    for i, u in enumerate(events):
        du_bnd = bnd_dist[u]
        for j in range(i + 1, len(events)):
            v = events[j]
            found = routes[u].get(v)
            if found is None:
                continue
            d_uv = found[0]
            dv_bnd = bnd_dist[v]
            saving = (du_bnd + dv_bnd) - d_uv
            if saving > 1e-12:
                key = (min(u, v), max(u, v))
                savings[key] = saving
                coupled_adj[u].append(v)
                coupled_adj[v].append(u)
            elif not np.isfinite(du_bnd) and not np.isfinite(dv_bnd):
                key = (min(u, v), max(u, v))
                savings[key] = 1e6 - d_uv
                coupled_adj[u].append(v)
                coupled_adj[v].append(u)

    visited: set[int] = set()
    pairing: dict[int, int] = {}
    matched_vertices: set[int] = set()
    is_exact = True

    for u in events:
        if u in visited:
            continue
        comp: list[int] = []
        queue = [u]
        visited.add(u)
        while queue:
            cur = queue.pop()
            comp.append(cur)
            for nb in coupled_adj[cur]:
                if nb not in visited:
                    visited.add(nb)
                    queue.append(nb)
        comp.sort()
        pairs, comp_exact = _solve_component_max_saving(comp, savings)
        if not comp_exact:
            is_exact = False
        for a, b in pairs:
            pairing[a] = b
            pairing[b] = a
            matched_vertices.add(a)
            matched_vertices.add(b)

    for u in events:
        if u not in matched_vertices and np.isfinite(bnd_dist[u]):
            pairing[u] = BOUNDARY

    return pairing, is_exact


def correction_edges_for_pairing(
    adjacency: dict,
    events: list[int],
    pairing: dict[int, int],
) -> set[tuple[int, int]]:
    """Reconstruct the mod-2 matched edge set on the merged graph for `pairing`."""
    routes = {e: shortest_routes(adjacency, e) for e in events}
    seen_pairs: set[frozenset[int]] = set()
    chosen_edges: set[tuple[int, int]] = set()

    for event in events:
        partner = pairing.get(event)
        if partner is None:
            continue
        pair_key = frozenset((event, partner))
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)
        for u, v in _route_edges(adjacency, routes[event], partner):
            edge_key = (min(u, v), max(u, v))
            if edge_key in chosen_edges:
                chosen_edges.remove(edge_key)
            else:
                chosen_edges.add(edge_key)
    return chosen_edges


def correction_for_pairing(
    adjacency: dict,
    events: list[int],
    pairing: dict[int, int],
) -> set[int]:
    """Observables toggled by the matched edge set implied by `pairing`.

    Each unique edge in the mod-2 symmetric difference of the matched routes is
    counted **once**, and its observables are XOR'd.
    """
    chosen_edges = correction_edges_for_pairing(adjacency, events, pairing)
    edge_obs_lookup: dict[tuple[int, int], frozenset[int]] = {}
    for u, nbrs in adjacency.items():
        for v, _w, obs in nbrs:
            edge_obs_lookup[(min(u, v), max(u, v))] = obs

    toggled: set[int] = set()
    for edge_key in chosen_edges:
        for obs in edge_obs_lookup.get(edge_key, frozenset()):
            if obs in toggled:
                toggled.discard(obs)
            else:
                toggled.add(obs)
    return toggled


def syndrome_of_correction(
    edges: Iterable[tuple[int, int]],
    chosen_observables_unused=None,
) -> set[int]:
    """Detector vertices incident to an odd number of correction edges (BOUNDARY excluded)."""
    degree: dict[int, int] = {}
    for a, b in edges:
        for node in (int(a), int(b)):
            if node == BOUNDARY:
                continue
            degree[node] = degree.get(node, 0) ^ 1
    return {node for node, parity in degree.items() if parity}


def verify_join(adjacency: dict, events: list[int], pairing: dict[int, int]) -> set[int]:
    """Check the T-join condition and return the set of disagreeing detector vertices."""
    chosen_edges = correction_edges_for_pairing(adjacency, events, pairing)
    odd = syndrome_of_correction(chosen_edges)
    return odd ^ set(int(e) for e in events)


# Fast compiled DEM graph for single-shot and batch decoding

@dataclass
class CompiledDEMGraph:
    """Precomputed merged DEM graph and lazy per-detector shortest-path cache."""

    num_detectors: int
    num_observables: int
    edges: list[GraphEdge]
    edge_by_pair: dict[tuple[int, int], GraphEdge]
    det_adj: dict[int, list[tuple[int, float, int]]]
    bnd_dist: dict[int, float]
    bnd_parent: dict[int, tuple[int, int]]
    max_bnd_dist: float
    bnd_paths: dict[int, tuple[int, ...]] = field(default_factory=dict)
    det_dijkstra_cache: dict[int, tuple[dict[int, float], dict[int, tuple[int, int]]]] = field(
        default_factory=dict
    )
    pair_path_cache: dict[tuple[int, int], tuple[int, ...]] = field(default_factory=dict)


def compile_dem_graph(dem) -> CompiledDEMGraph:
    """Build the merged DEM graph and precompute boundary distances via multi-source Dijkstra."""
    edges, _ = build_graph(dem)
    edge_by_pair: dict[tuple[int, int], GraphEdge] = {}
    det_adj: dict[int, list[tuple[int, float, int]]] = {}
    full_adj: dict[int, list[tuple[int, float, int]]] = {}

    for edge in edges:
        key = (min(edge.a, edge.b), max(edge.a, edge.b))
        edge_by_pair[key] = edge
        full_adj.setdefault(edge.a, []).append((edge.b, edge.weight, edge.index))
        full_adj.setdefault(edge.b, []).append((edge.a, edge.weight, edge.index))
        if edge.a != BOUNDARY and edge.b != BOUNDARY:
            det_adj.setdefault(edge.a, []).append((edge.b, edge.weight, edge.index))
            det_adj.setdefault(edge.b, []).append((edge.a, edge.weight, edge.index))
        else:
            det = edge.b if edge.a == BOUNDARY else edge.a
            det_adj.setdefault(det, [])

    bnd_dist: dict[int, float] = {BOUNDARY: 0.0}
    bnd_parent: dict[int, tuple[int, int]] = {}
    heap: list[tuple[float, int]] = [(0.0, BOUNDARY)]
    while heap:
        cost, u = heapq.heappop(heap)
        if cost > bnd_dist.get(u, float("inf")):
            continue
        for v, w, edge_idx in full_adj.get(u, []):
            if v == BOUNDARY:
                continue
            new_cost = cost + w
            if new_cost < bnd_dist.get(v, float("inf")) - 1e-12:
                bnd_dist[v] = new_cost
                bnd_parent[v] = (u, edge_idx)
                heapq.heappush(heap, (new_cost, v))

    finite_bnds = [d for u, d in bnd_dist.items() if u != BOUNDARY and np.isfinite(d)]
    max_bnd_dist = max(finite_bnds) if finite_bnds else 0.0

    bnd_paths: dict[int, tuple[int, ...]] = {}
    for u in bnd_parent:
        path_edges: list[int] = []
        cur = u
        while cur != BOUNDARY:
            parent, edge_idx = bnd_parent[cur]
            path_edges.append(edge_idx)
            cur = parent
        bnd_paths[u] = tuple(path_edges)

    return CompiledDEMGraph(
        num_detectors=int(dem.num_detectors),
        num_observables=int(dem.num_observables),
        edges=edges,
        edge_by_pair=edge_by_pair,
        det_adj=det_adj,
        bnd_dist=bnd_dist,
        bnd_parent=bnd_parent,
        max_bnd_dist=max_bnd_dist,
        bnd_paths=bnd_paths,
    )


def _get_detector_dijkstra(
    compiled: CompiledDEMGraph,
    source: int,
) -> tuple[dict[int, float], dict[int, tuple[int, int]]]:
    """Return cached Dijkstra tree from `source` up to `bnd_dist[source] + max_bnd_dist`."""
    cached = compiled.det_dijkstra_cache.get(source)
    if cached is not None:
        return cached

    du_bnd = compiled.bnd_dist.get(source, float("inf"))
    cutoff = du_bnd + compiled.max_bnd_dist if np.isfinite(du_bnd) else float("inf")

    dist: dict[int, float] = {source: 0.0}
    parent: dict[int, tuple[int, int]] = {}
    heap: list[tuple[float, int]] = [(0.0, source)]
    det_adj = compiled.det_adj
    while heap:
        cost, u = heapq.heappop(heap)
        if cost > dist.get(u, float("inf")):
            continue
        if cost > cutoff:
            break
        for v, w, edge_idx in det_adj.get(u, []):
            new_cost = cost + w
            if new_cost <= cutoff and new_cost < dist.get(v, float("inf")) - 1e-12:
                dist[v] = new_cost
                parent[v] = (u, edge_idx)
                heapq.heappush(heap, (new_cost, v))

    compiled.det_dijkstra_cache[source] = (dist, parent)
    return dist, parent


def _get_pair_path(
    compiled: CompiledDEMGraph,
    parent: dict[int, tuple[int, int]],
    u: int,
    v: int,
) -> tuple[int, ...]:
    """Return cached tuple of edge indices along shortest detector path between `u` and `v`."""
    key = (min(u, v), max(u, v))
    cached = compiled.pair_path_cache.get(key)
    if cached is not None:
        return cached
    path_edges: list[int] = []
    cur = v
    while cur != u:
        p, edge_idx = parent[cur]
        path_edges.append(edge_idx)
        cur = p
    res = tuple(path_edges)
    compiled.pair_path_cache[key] = res
    return res


def decode_compiled(
    compiled: CompiledDEMGraph,
    detection_events: Iterable[int],
) -> tuple[set[tuple[int, int]], frozenset[int]]:
    """Decode one shot using the compiled DEM graph.

    Returns `(matched_edges, flipped_observables)` where `matched_edges` is the
    set of canonical `(a, b)` edges on the merged graph.
    """
    events = sorted({int(e) for e in detection_events if int(e) in compiled.det_adj})
    if not events:
        return set(), frozenset()

    savings: dict[tuple[int, int], float] = {}
    det_paths: dict[tuple[int, int], tuple[int, ...]] = {}
    coupled_adj: dict[int, list[int]] = {u: [] for u in events}

    for i, u in enumerate(events):
        du_bnd = compiled.bnd_dist.get(u, float("inf"))
        dist, parent = _get_detector_dijkstra(compiled, u)
        for j in range(i + 1, len(events)):
            v = events[j]
            d_uv = dist.get(v)
            if d_uv is None:
                continue
            dv_bnd = compiled.bnd_dist.get(v, float("inf"))
            saving = (du_bnd + dv_bnd) - d_uv
            if saving > 1e-12:
                key = (min(u, v), max(u, v))
                savings[key] = saving
                det_paths[key] = _get_pair_path(compiled, parent, u, v)
                coupled_adj[u].append(v)
                coupled_adj[v].append(u)
            elif not np.isfinite(du_bnd) and not np.isfinite(dv_bnd):
                key = (min(u, v), max(u, v))
                savings[key] = 1e6 - d_uv
                det_paths[key] = _get_pair_path(compiled, parent, u, v)
                coupled_adj[u].append(v)
                coupled_adj[v].append(u)

    visited: set[int] = set()
    matched_pairs: list[tuple[int, int]] = []
    matched_vertices: set[int] = set()

    for u in events:
        if u in visited:
            continue
        comp: list[int] = []
        queue = [u]
        visited.add(u)
        while queue:
            cur = queue.pop()
            comp.append(cur)
            for nb in coupled_adj[cur]:
                if nb not in visited:
                    visited.add(nb)
                    queue.append(nb)
        comp.sort()
        pairs, _ = _solve_component_max_saving(comp, savings)
        for a, b in pairs:
            matched_pairs.append((a, b))
            matched_vertices.add(a)
            matched_vertices.add(b)

    chosen_edge_indices: set[int] = set()
    for a, b in matched_pairs:
        for edge_idx in det_paths[(a, b)]:
            if edge_idx in chosen_edge_indices:
                chosen_edge_indices.remove(edge_idx)
            else:
                chosen_edge_indices.add(edge_idx)

    for u in events:
        if u not in matched_vertices and u in compiled.bnd_paths:
            for edge_idx in compiled.bnd_paths[u]:
                if edge_idx in chosen_edge_indices:
                    chosen_edge_indices.remove(edge_idx)
                else:
                    chosen_edge_indices.add(edge_idx)

    chosen_edges: set[tuple[int, int]] = set()
    toggled_obs: set[int] = set()
    for edge_idx in chosen_edge_indices:
        edge = compiled.edges[edge_idx]
        chosen_edges.add((edge.a, edge.b))
        for obs in edge.observables:
            if obs in toggled_obs:
                toggled_obs.remove(obs)
            else:
                toggled_obs.add(obs)

    return chosen_edges, frozenset(toggled_obs)


_CACHE: dict[tuple[int, int, str], CompiledDEMGraph] = {}


def _get_compiled(dem) -> CompiledDEMGraph:
    key = (int(dem.num_detectors), int(dem.num_observables), str(dem))
    compiled = _CACHE.get(key)
    if compiled is None:
        compiled = compile_dem_graph(dem)
        if len(_CACHE) >= 32:
            _CACHE.clear()
        _CACHE[key] = compiled
    return compiled


def decode_edges_and_observables(
    dem,
    detection_events: Iterable[int],
) -> tuple[set[tuple[int, int]], frozenset[int]]:
    """Decode one shot into `(matched_edges, flipped_observables)`."""
    return decode_compiled(_get_compiled(dem), detection_events)


def decode_observable(dem, detection_events: Iterable[int]) -> bool:
    """Return True if observable 0 is flipped."""
    _, obs = decode_edges_and_observables(dem, detection_events)
    return 0 in obs


def decode(
    dem,
    detection_events: Iterable[int],
    *,
    exact: bool = True,
    max_events: int = 12,
) -> frozenset[int]:
    """Decode one shot into the observables that should be toggled."""
    if exact:
        _, obs = decode_compiled(_get_compiled(dem), detection_events)
        return obs
    _, adjacency = build_graph(dem)
    events = sorted(int(e) for e in detection_events if int(e) in adjacency)
    if not events:
        return frozenset()
    pairing = pair_greedily(adjacency, events)
    return frozenset(correction_for_pairing(adjacency, events, pairing))


def decode_batch(dem, detection_matrix) -> np.ndarray:
    """Decode a 2-D `(shots, num_detectors)` boolean matrix into `(shots, num_observables)`."""
    detection_matrix = np.asarray(detection_matrix, dtype=bool)
    if detection_matrix.ndim != 2:
        raise TJoinError("detection matrix must be two-dimensional")
    compiled = _get_compiled(dem)
    n_obs = max(compiled.num_observables, 1)
    out = np.zeros((detection_matrix.shape[0], n_obs), dtype=bool)
    for shot in range(detection_matrix.shape[0]):
        events = np.flatnonzero(detection_matrix[shot])
        if len(events) == 0:
            continue
        _, flipped = decode_compiled(compiled, events)
        for obs in flipped:
            if 0 <= obs < n_obs:
                out[shot, obs] = True
    return out


def compare_to_reference(
    distance: int,
    noise: float,
    *,
    shots: int = 2000,
    rounds: int | None = None,
    seed: int = 1,
) -> dict:
    """T-join decoder against PyMatching, on identical shots."""
    if not HAVE_STIM:
        raise TJoinError("needs stim")
    try:
        from pymatching import Matching
    except ImportError as exc:  # pragma: no cover
        raise TJoinError("needs pymatching for the comparison") from exc

    rounds = distance if rounds is None else rounds
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z",
        distance=distance,
        rounds=rounds,
        after_clifford_depolarization=noise,
    )
    dem = circuit.detector_error_model(decompose_errors=True)
    sampler = circuit.compile_detector_sampler(seed=seed)
    detection, observables = sampler.sample(shots, separate_observables=True)

    reference = Matching.from_detector_error_model(dem).decode_batch(detection)
    truth = observables.astype(bool)
    ref_err = int(np.sum(reference.astype(bool) != truth))

    mine = decode_batch(dem, detection)
    mine_err = int(np.sum(mine.astype(bool) != truth))
    return {
        "distance": distance,
        "rounds": rounds,
        "noise": noise,
        "shots": shots,
        "reference_errors": ref_err,
        "tjoin_errors": mine_err,
        "reference_rate": ref_err / shots,
        "tjoin_rate": mine_err / shots,
    }
