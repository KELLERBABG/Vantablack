"""Fidelity-optimal routing: the additive weight must be ``-log W``, not ``-log F``.

This file pins a correction that matters for the planning layer.

Entanglement swapping on Werner states composes *exactly* as

    F' = F1*F2 + (1-F1)(1-F2)/3

Writing ``W = (4F - 1)/3`` (the Werner parameter), that is ``W' = W1*W2``.
So along a path ``W_path = prod(W_i)`` and therefore

    -log W_path = sum(-log W_i)          <-- exactly additive

whereas ``sum(-log F_i) = -log prod(F_i)``, and ``prod(F_i) != F_path``.

Consequence: Dijkstra on ``-log W`` returns the fidelity-optimal path;
Dijkstra on ``-log F`` does **not**, and can return a strictly worse path.
The gap grows as fidelity drops (the ratio -log W / -log F is 1.34 at
F=0.99 but 2.25 at F=0.30), so the naive weight systematically under-penalises
low-fidelity links.

``quantumnet.topology.dijkstra`` already uses ``-log W``. These tests exist so
that a future "simplification" to ``-log F`` fails loudly rather than silently
degrading route quality.

References
----------
* Kozlowski, Dahlberg, Wehner, "Designing a Quantum Network Protocol",
  CoNEXT '20, arXiv:2010.02575 -- states the composition formula and that it
  is associative.
* Chakraborty, Elkouss, Rijsman, Wehner, arXiv:2005.14304 -- derives the same
  by ``W -> W^2`` and reduces a fidelity requirement to a path-length bound.
"""

from __future__ import annotations

import heapq
import itertools
import math

import numpy as np
import pytest

from quantumnet.topology.dijkstra import _edge_cost, dijkstra_best_route
from quantumnet.topology.graph import QuantumLink, QuantumNode, QuantumTopology
from quantumnet.topology.routing import swapped_fidelity


# ---------------------------------------------------------------------------
# Helpers -- topologies with directly specified link fidelities
# ---------------------------------------------------------------------------

def _link(a: str, b: str, fidelity: float) -> QuantumLink:
    """A link whose fidelity is pinned, bypassing the distance model."""
    lk = QuantumLink(a=a, b=b, length_km=1.0)
    lk.fidelity = lambda _f=fidelity: _f  # type: ignore[method-assign]
    return lk


def _topo(n: int, fidelities: dict[tuple[int, int], float]) -> QuantumTopology:
    topo = QuantumTopology()
    for i in range(n):
        topo.add_node(QuantumNode(node_id=f"N{i}", x_km=float(i), y_km=0.0))
    for (i, j), f in fidelities.items():
        topo.add_link(_link(f"N{i}", f"N{j}", f))
    return topo


def _exact_e2e(fids) -> float:
    """Exact end-to-end fidelity via the Werner product."""
    w = 1.0
    for f in fids:
        w *= (4.0 * f - 1.0) / 3.0
    return (1.0 + 3.0 * w) / 4.0


def _brute_force(topo: QuantumTopology, src: str, dst: str,
                 max_hops: int = 6) -> tuple[float, list[str] | None]:
    """Best achievable fidelity over every simple path, by exhaustive search."""
    best_f, best_path = -1.0, None
    others = [n for n in topo.nodes if n not in (src, dst)]
    for length in range(1, max_hops + 1):
        for mid in itertools.permutations(others, length - 1):
            path = [src, *mid, dst]
            fids, ok = [], True
            for a, b in zip(path, path[1:]):
                lk = topo.link(a, b)
                if lk is None:
                    ok = False
                    break
                fids.append(lk.fidelity())
            if not ok:
                continue
            f = _exact_e2e(fids)
            if f > best_f:
                best_f, best_path = f, path
    return best_f, best_path


def _dijkstra_naive_logF(topo: QuantumTopology, src: str, dst: str):
    """Dijkstra with the WRONG weight (-log F).  Used only to demonstrate
    that it is wrong; the production code must never do this."""
    dist, prev, visited = {src: 0.0}, {}, set()
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
            lk = topo.link(u, v)
            if lk is None:
                continue
            f = lk.fidelity()
            if f <= 0.0:
                continue
            nd = d - math.log(f)
            if nd < dist.get(v, math.inf):
                dist[v], prev[v] = nd, u
                heapq.heappush(heap, (nd, v))
    if dst not in visited:
        return None
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    path.reverse()
    fids = [topo.link_fidelity(a, b) for a, b in zip(path, path[1:])]
    return _exact_e2e(fids), path


# ---------------------------------------------------------------------------
# The composition algebra
# ---------------------------------------------------------------------------

def test_swapped_fidelity_equals_werner_product():
    """F1F2 + (1-F1)(1-F2)/3 must equal (1 + 3*W1*W2)/4."""
    for f1 in (0.5, 0.7, 0.9, 0.99):
        for f2 in (0.6, 0.8, 0.95):
            w1, w2 = (4 * f1 - 1) / 3, (4 * f2 - 1) / 3
            assert swapped_fidelity(f1, f2) == pytest.approx((1 + 3 * w1 * w2) / 4)


def test_werner_parameter_is_multiplicative_along_a_path():
    fids = [0.9, 0.8, 0.95, 0.7]
    w = 1.0
    for f in fids:
        w *= (4 * f - 1) / 3
    # left-to-right composition must land on the same value
    acc = fids[0]
    for f in fids[1:]:
        acc = swapped_fidelity(acc, f)
    assert acc == pytest.approx((1 + 3 * w) / 4)


def test_logW_is_exactly_additive_and_logF_is_not():
    """The whole point: -log W sums; -log F does not."""
    fids = [0.9, 0.7, 0.8]
    sum_log_w = sum(-math.log((4 * f - 1) / 3) for f in fids)
    path_w = 1.0
    for f in fids:
        path_w *= (4 * f - 1) / 3
    assert sum_log_w == pytest.approx(-math.log(path_w))

    # -log F does NOT reconstruct the true path fidelity
    wrong = (1 + 3 * math.exp(-sum(-math.log(f) for f in fids))) / 4
    assert wrong != pytest.approx(_exact_e2e(fids))


# ---------------------------------------------------------------------------
# The production weight
# ---------------------------------------------------------------------------

def test_edge_cost_is_minus_log_werner_parameter():
    for f in (0.99, 0.9, 0.8, 0.6):
        lk = _link("a", "b", f)
        w = (4 * f - 1) / 3
        assert _edge_cost(lk) == pytest.approx(-math.log(w))


def test_edge_cost_is_infinite_at_or_below_classical_limit():
    for f in (0.25, 0.2, 0.0):
        assert _edge_cost(_link("a", "b", f)) == math.inf


def test_edge_cost_non_negative_for_physical_links():
    for f in np.linspace(0.2501, 1.0, 50):
        assert _edge_cost(_link("a", "b", float(f))) >= 0.0


# ---------------------------------------------------------------------------
# Optimality against brute force
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seed", range(12))
def test_dijkstra_matches_brute_force_on_random_graphs(seed):
    """-log W Dijkstra must reproduce the exhaustive optimum exactly."""
    rng = np.random.default_rng(seed)
    n = 6
    fids = {}
    for i in range(n):
        for j in range(i + 1, n):
            if rng.random() < 0.5:
                fids[(i, j)] = float(rng.uniform(0.55, 1.0))
    topo = _topo(n, fids)
    best_f, best_path = _brute_force(topo, "N0", "N5")
    if best_f <= 0:
        pytest.skip("no path in this random graph")
    route = dijkstra_best_route(topo, "N0", "N5")
    assert route is not None
    assert route.e2e_fidelity == pytest.approx(best_f, abs=1e-9)
    # and the reported fidelity must match an independent recomputation
    assert route.e2e_fidelity == pytest.approx(
        _exact_e2e(route.link_fidelities), abs=1e-12)


def test_naive_logF_weight_is_demonstrably_suboptimal():
    """A concrete graph where -log F picks a worse path than -log W.

    True optimum is N0->N1->N2->N5 (F = 0.580467742); the naive -log F weight
    prefers the single hop N0->N5 (F = 0.559719649), losing 0.0207 of
    end-to-end fidelity.  The naive weight is fooled because F(N0,N5) = 0.560
    looks "cheap" under -log F while the three-hop route's individual links
    (0.718, 0.905, 0.856) look worse than they are.

    If someone 'simplifies' the edge cost to -log F, this test and the
    random-graph sweep above will catch it.
    """
    topo = _topo(6, {
        (0, 1): 0.7179387735621440,
        (0, 3): 0.5828321768009815,
        (0, 5): 0.5597196486217589,
        (1, 2): 0.9052389449819160,
        (1, 3): 0.9757737739477019,
        (1, 4): 0.7339443274856253,
        (2, 5): 0.8562655136858579,
        (3, 4): 0.8074042964640864,
        (4, 5): 0.8451876998241034,
    })

    best_f, best_path = _brute_force(topo, "N0", "N5")
    assert best_path == ["N0", "N1", "N2", "N5"]
    assert best_f == pytest.approx(0.580467742, abs=1e-6)

    # production weight gets it right
    route = dijkstra_best_route(topo, "N0", "N5")
    assert route is not None
    assert route.e2e_fidelity == pytest.approx(best_f, abs=1e-12)
    assert route.path == best_path

    # the naive weight gets it wrong -- this is the point of the test
    naive = _dijkstra_naive_logF(topo, "N0", "N5")
    assert naive is not None
    naive_f, naive_path = naive
    assert naive_path == ["N0", "N5"]
    assert naive_f == pytest.approx(0.559719649, abs=1e-6)
    assert naive_f < best_f


def test_fidelity_requirement_makes_dijkstra_detour():
    """With min_fidelity set, a shorter but worse route must be rejected."""
    topo = _topo(4, {
        (0, 1): 0.99, (0, 2): 0.99,
        (1, 3): 0.99, (2, 3): 0.60,
    })
    high = dijkstra_best_route(topo, "N0", "N3", min_fidelity=0.9)
    assert high is not None
    assert high.path == ["N0", "N1", "N3"]
    # demanding more than the graph can deliver must return None, not a lie
    assert dijkstra_best_route(topo, "N0", "N3", min_fidelity=0.999) is None


def test_unreachable_destination_returns_none():
    topo = _topo(3, {(0, 1): 0.9})  # N2 isolated
    assert dijkstra_best_route(topo, "N0", "N2") is None


def test_missing_node_returns_none():
    topo = _topo(2, {(0, 1): 0.9})
    assert dijkstra_best_route(topo, "N0", "nope") is None
    assert dijkstra_best_route(topo, "N0", "N0") is None
