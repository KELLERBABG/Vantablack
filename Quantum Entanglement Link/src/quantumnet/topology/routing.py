"""Fidelity-constrained entanglement routing over a quantum topology.

Bell-state swapping
-------------------
Perfect Bell-state measurement on two Werner states of fidelity ``F1``, ``F2``
yields a Werner state with fidelity

    F' = F1*F2 + (1-F1)(1-F2)/3 = (4*F1*F2 - F1 - F2 + 1)/3

In the Werner parameter ``p = (4F-1)/3`` the operation multiplies
(``p' = p1*p2``), so pure swap noise is independent of the fusion order.
Order still matters for the *scheduled* distribution because segments wait
in memory between generation and fusion (T1/T2 decay) — see ``schedule.py``.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Sequence

from .graph import QuantumTopology


def swapped_fidelity(f1: float, f2: float) -> float:
    """Fidelity after swapping two Werner-state Bell pairs of fidelity f1, f2.

    Derived from the Bell-basis convolution of two Werner states
    (λ = (F, (1-F)/3, (1-F)/3, (1-F)/3)):

        F' = F1*F2 + (1-F1)(1-F2)/3 = (4F1F2 - F1 - F2 + 1)/3
    """
    return (4.0 * f1 * f2 - f1 - f2 + 1.0) / 3.0


def e2e_fidelity(fidelities: Sequence[float],
                 order: Sequence[tuple[int, int]] | None = None) -> float:
    """End-to-end fidelity after fusing ``fidelities`` in ``order``.

    ``order`` is a sequence of (i, j) pairs meaning "fuse segment i with
    segment j". After a fusion the two segments are replaced by one with the
    swapped fidelity. If ``order`` is None the segments are fused left-to-right.
    """
    f = list(float(x) for x in fidelities)
    if not f:
        return 1.0
    if order is None:
        # left-to-right: fuse 0+1, then result with 2, ...
        acc = f[0]
        for x in f[1:]:
            acc = swapped_fidelity(acc, x)
        return acc
    segments: list[float] = list(f)
    for i, j in order:
        lo, hi = sorted((i, j))
        if lo < 0 or hi >= len(segments):
            raise IndexError("swap order references a non-existent segment")
        merged = swapped_fidelity(segments[lo], segments[hi])
        segments[lo] = merged
        segments.pop(hi)
    if len(segments) != 1:
        raise ValueError("swap order must fuse all segments into one")
    return segments[0]


def optimal_swap_order(fidelities: Sequence[float],
                       brute_force_limit: int = 8) -> tuple[list[tuple[int, int]], float]:
    """Return (swap order, final fidelity) for fusing all segments.

    Pure swap noise is order-independent (Werner parameter multiplies), so
    the brute-force search here simply picks the first valid order; it is
    kept because the *scheduled* distribution (with memory decay) can make
    the ordering matter, and callers may inspect/override the order.
    """
    n = len(fidelities)
    if n <= 1:
        return [], float(fidelities[0]) if n == 1 else 1.0

    if n <= brute_force_limit:
        # all valid fusion trees give the same noise-only result; return
        # the first one found by the exact enumeration
        for perm in _fusion_orders(n):
            return perm, e2e_fidelity(fidelities, perm)
        return [], e2e_fidelity(fidelities)  # unreachable

    # Large n: fuse left-to-right (identical noise result).
    order = [(k, k + 1) for k in range(n - 1)]
    return order, e2e_fidelity(fidelities, order)


def _fusion_orders(n: int):
    """Generate fusion orders for ``n`` segments.

    A fusion order is a sequence of n-1 fusions of *adjacent* segments; each
    entry ``(k, k+1)`` refers to the current working array at that step
    (exactly the semantics :func:`e2e_fidelity` applies). All valid fusion
    trees are enumerated by DFS.
    """
    ids = tuple(range(n))

    def dfs(current: tuple) -> list[list[tuple[int, int]]]:
        if len(current) == 1:
            return [[]]
        out: list[list[tuple[int, int]]] = []
        for k in range(len(current) - 1):
            rest = current[:k] + (current[k],) + current[k + 2:]
            for tail in dfs(rest):
                out.append([(k, k + 1)] + tail)
        return out

    yield from dfs(ids)


@dataclass
class Route:
    """A candidate entanglement path."""

    path: list[str]
    link_fidelities: list[float]
    e2e_fidelity: float
    swap_order: list[tuple[int, int]]

    @property
    def hops(self) -> int:
        return len(self.path) - 1

    def describe(self) -> str:
        fids = ", ".join(f"{f:.3f}" for f in self.link_fidelities)
        swaps = " -> ".join(f"{a}+{b}" for a, b in self.swap_order)
        return (
            f"{' -> '.join(self.path)}  (links: [{fids}], "
            f"e2e F={self.e2e_fidelity:.4f}, swaps: {swaps})"
        )


def all_simple_paths(topo: QuantumTopology, src: str, dst: str,
                     max_hops: int = 6, max_paths: int = 10_000,
                     max_visits: int = 200_000) -> list[list[str]]:
    """All simple paths from ``src`` to ``dst`` (bounded search).

    ``max_paths`` caps the result list, but when ``dst`` is unreachable the
    DFS would still enumerate every simple path (exponential in dense
    graphs). ``max_visits`` is a global node-expansion budget that bounds
    the traversal itself — crafted topology files cannot hang the search.
    """
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(src, [src])]
    visits = 0
    while stack and len(paths) < max_paths and visits < max_visits:
        node, trail = stack.pop()
        for nb in topo.neighbors(node):
            visits += 1
            if visits > max_visits:
                return paths
            if nb in trail:
                continue
            new_trail = trail + [nb]
            if nb == dst:
                paths.append(new_trail)
                continue
            if len(new_trail) - 1 < max_hops:
                stack.append((nb, new_trail))
    return paths


def rank_routes(topo: QuantumTopology, src: str, dst: str,
                max_hops: int = 6, max_paths: int = 10_000,
                min_fidelity: float = 0.0) -> list[Route]:
    """Rank all simple paths by achievable end-to-end fidelity.

    Returns routes sorted best-first. Only paths whose best achievable
    fidelity is at least ``min_fidelity`` are returned.
    """
    routes: list[Route] = []
    for path in all_simple_paths(topo, src, dst, max_hops, max_paths):
        fids: list[float] = []
        ok = True
        for a, b in zip(path, path[1:]):
            l = topo.link(a, b)
            if l is None:
                ok = False
                break
            fids.append(l.fidelity())
        if not ok:
            continue
        order, final = optimal_swap_order(fids)
        if final >= min_fidelity - 1e-12:
            routes.append(Route(path=path, link_fidelities=fids,
                                e2e_fidelity=final, swap_order=order))
    routes.sort(key=lambda r: r.e2e_fidelity, reverse=True)
    return routes


def best_route(topo: QuantumTopology, src: str, dst: str,
               max_hops: int = 6, max_paths: int = 10_000,
               min_fidelity: float = 0.0) -> Route | None:
    """The single best route (or None if no route meets the constraint)."""
    routes = rank_routes(topo, src, dst, max_hops, max_paths, min_fidelity)
    return routes[0] if routes else None
