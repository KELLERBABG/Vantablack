"""Standard data-centre topologies as first-class objects.

Why these two
-------------
`ring` and `grid` already existed, which covers metro and mesh geometry.  FatTree
and BCube cover the shapes a *data-centre* quantum network takes, and they matter
for a specific reason: they are deliberately built with **different path
redundancy at different levels**, so they separate routing policies that a grid
cannot.  On a symmetric grid every sensible policy picks nearly the same route;
on a FatTree the distance-minimising and fidelity-minimising routes genuinely
diverge, which is exactly the comparison a routing-policy study needs to make.

Both are defined in their standard form:

* **FatTree(k)** -- *k* pods, each with *k*/2 aggregation and *k*/2 edge
  switches, and (*k*/2)^2 core switches.  Every host connects to one edge switch.
  Hosts in the same pod share a short path; across pods the path goes up to a
  core and back down.
* **BCube(n, k)** -- *n*-port switches at each of *k+1* levels, with *n^(k+1)*
  hosts.  Level *j* connects hosts differing in digit *j* of their base-*n*
  address.  Adding a level adds redundancy rather than length, so BCube
  degrades more gracefully than FatTree.

Both are built in pure Python, keeping the project's no-dependency promise.
NetworkX interop is deliberately *not* added: it would be a heavyweight
dependency for a convenience, and the canonical `QuantumTopology` shape is
already the interface every consumer uses.
"""

from __future__ import annotations

from .graph import QuantumNode, QuantumTopology

#: Link attenuation used for data-centre topologies. Intra-datacentre fibre is short, so
#: the default km spacing barely affects fidelity; the topology decides the answer here.
DEFAULT_DC_ALPHA_DB_KM = 0.2


def fat_tree(k: int = 4, *, link_km: float = 1.0,
             alpha_db_km: float = DEFAULT_DC_ALPHA_DB_KM,
             t1_s: float = 100.0, t2_s: float = 50.0,
             **link_kw) -> QuantumTopology:
    """A standard *k*-ary FatTree.

    Nodes are named ``core<i>``, ``agg<p>_<i>``, ``edge<p>_<i>`` and ``host<p>_<i>``
    so a path's level is readable from its labels -- which is what makes the
    cross-pod / same-pod distinction legible in a routing report.

    ``k`` must be even: the topology is built from ``k/2`` upward and downward
    ports, so an odd arity has no standard form.
    """
    if k < 2 or k % 2 != 0:
        raise ValueError(f"FatTree arity k must be an even integer >= 2, got {k}")

    topo = QuantumTopology()
    half = k // 2
    n_core = half * half

    def add(node_id: str, x: float, y: float, repeater: bool) -> None:
        topo.add_node(QuantumNode(node_id=node_id, x_km=x, y_km=y,
                                  t1_s=t1_s, t2_s=t2_s,
                                  is_repeater=repeater))

    # Core layer, aggregated switch layer, edge layer, hosts. Positions are laid out by
    # layer in y so the visualiser produces something legible.
    for c in range(n_core):
        add(f"core{c}", float(c) * link_km, 0.0, True)
    for p in range(k):
        for a in range(half):
            add(f"agg{p}_{a}", float(p * half + a) * link_km, link_km, True)
        for e in range(half):
            add(f"edge{p}_{e}", float(p * half + e) * link_km, 2 * link_km, True)
        for e in range(half):
            for h in range(half):
                add(f"host{p}_{e}_{h}", float(p * half + e) * link_km,
                    3 * link_km, False)

    def connect(a: str, b: str) -> None:
        topo.connect(a, b, length_km=link_km, alpha_db_km=alpha_db_km,
                     **link_kw)

    # Every aggregation switch reaches every core switch: this full bipartite layer is
    # what gives a FatTree its cross-pod bisection bandwidth.
    for p in range(k):
        for a in range(half):
            for c in range(n_core):
                connect(f"agg{p}_{a}", f"core{c}")

    # Each aggregation switch serves half the edge switches in its pod.
    for p in range(k):
        for a in range(half):
            for e in range(half):
                connect(f"agg{p}_{a}", f"edge{p}_{e}")

    # Each edge switch serves half the hosts in its pod.
    for p in range(k):
        for e in range(half):
            for h in range(half):
                connect(f"edge{p}_{e}", f"host{p}_{e}_{h}")

    return topo


def bcube(n: int = 2, k: int = 1, *, link_km: float = 1.0,
          alpha_db_km: float = DEFAULT_DC_ALPHA_DB_KM,
          t1_s: float = 100.0, t2_s: float = 50.0,
          **link_kw) -> QuantumTopology:
    """A BCube(n, k): ``n**(k+1)`` hosts and ``(k+1) * n**k`` switches.

    Hosts are ``h<digits>`` with exactly ``k+1`` base-``n`` digits.  A host
    connects to one switch per level, and the switch at level *j* is identified
    by the host's *other* ``k`` digits -- so each level needs ``n**k`` switches,
    not ``n``.  Switch ``s<j>_<index>`` therefore connects the ``n`` hosts that
    share those other digits and differ in digit *j*.

    The property that distinguishes BCube from FatTree: every extra level adds a
    *disjoint* path rather than a longer one, so redundancy grows without the
    path length growing.  Host degree is exactly ``k+1``.

    ``n**(k+1)`` hosts of degree ``k+1``, with ``n`` hosts per switch, gives
    ``(k+1) * n**(k+1) / n = (k+1) * n**k`` switches, which is the count
    asserted in the tests.
    """
    if n < 2:
        raise ValueError(f"BCube arity n must be >= 2, got {n}")
    if k < 0:
        raise ValueError(f"BCube level count k must be >= 0, got {k}")

    topo = QuantumTopology()
    n_hosts = n ** (k + 1)

    def digits(index: int) -> list[int]:
        out = []
        value = index
        for _ in range(k + 1):
            out.append(value % n)
            value //= n
        return list(reversed(out))

    def label_for(ds: list[int]) -> str:
        return "h" + "".join(str(d) for d in ds)

    for index in range(n_hosts):
        ds = digits(index)
        topo.add_node(QuantumNode(node_id=label_for(ds),
                                  x_km=float(index) * link_km, y_km=0.0,
                                  t1_s=t1_s, t2_s=t2_s, is_repeater=False))

    for level in range(k + 1):
        # A switch at this level is named by the k digits other than `level`.
        others = [j for j in range(k + 1) if j != level]
        for switch_index in range(n ** k):
            # Decode switch_index into the `others` digit positions.
            other_digits = digits(switch_index)[-(k):] if k > 0 else []
            key = dict(zip(others, other_digits))
            switch_id = f"s{level}_" + ("".join(str(key[j]) for j in others)
                                        if others else "0")
            topo.add_node(QuantumNode(node_id=switch_id,
                                      x_km=float(switch_index) * link_km,
                                      y_km=float(level + 1) * link_km,
                                      t1_s=t1_s, t2_s=t2_s, is_repeater=True))
            # Connect the n hosts that agree on `others` and vary at `level`.
            for value in range(n):
                full = [0] * (k + 1)
                for j in others:
                    full[j] = key[j]
                full[level] = value
                host_id = label_for(full)
                if host_id in topo.nodes:
                    topo.connect(switch_id, host_id, length_km=link_km,
                                 alpha_db_km=alpha_db_km, **link_kw)

    return topo


def ring_wrap(nodes: list[str], radius_km: float = 20.0,
              **kw) -> QuantumTopology:
    """Alias for :meth:`QuantumTopology.ring`, kept for a uniform builder API."""
    return QuantumTopology.ring(nodes, radius_km=radius_km, **kw)


def grid_wrap(rows: int, cols: int, spacing_km: float = 5.0,
              **kw) -> QuantumTopology:
    """Alias for :meth:`QuantumTopology.grid`, kept for a uniform builder API."""
    return QuantumTopology.grid(rows, cols, spacing_km=spacing_km, **kw)


#: Builders by name, so a topology can be produced from a config string.
TOPOLOGY_BUILDERS = {
    "ring": ring_wrap,
    "grid": grid_wrap,
    "fattree": fat_tree,
    "fat-tree": fat_tree,
    "bcube": bcube,
}


def build_topology(shape: str, **kwargs) -> QuantumTopology:
    """Instantiate a named topology builder."""
    if shape not in TOPOLOGY_BUILDERS:
        raise ValueError(
            f"unknown topology shape {shape!r}; available: "
            f"{sorted(TOPOLOGY_BUILDERS)}"
        )
    return TOPOLOGY_BUILDERS[shape](**kwargs)


def topology_report(topo: QuantumTopology) -> dict:
    """Summary statistics, including whether the graph is connected.

    Connectivity is reported because an unreachable pair looks identical to a
    routing failure in most outputs, and those are different problems.
    """
    n = len(topo.nodes)
    degrees = {node: len(topo.neighbors(node)) for node in topo.nodes}
    seen: set[str] = set()
    if n:
        stack = [next(iter(topo.nodes))]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(nb for nb in topo.neighbors(node) if nb not in seen)
    degrees_sorted = sorted(degrees.values())
    return {
        "nodes": n,
        "links": len(topo.links),
        "connected": len(seen) == n,
        "is_repeater_count": sum(1 for nd in topo.nodes.values() if nd.is_repeater),
        "min_degree": degrees_sorted[0] if degrees_sorted else 0,
        "max_degree": degrees_sorted[-1] if degrees_sorted else 0,
        "mean_degree": (sum(degrees_sorted) / n) if n else 0.0,
    }
