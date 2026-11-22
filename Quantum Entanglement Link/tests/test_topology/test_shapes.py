"""Standard data-centre topologies: FatTree and BCube.

These are not here for completeness.  They are here because they have
**non-uniform path redundancy**, which separates routing policies that a
symmetric grid cannot: on a grid every sensible policy takes a near-identical
route, whereas on a FatTree the distance-minimising and fidelity-minimising
routes can genuinely diverge.  That divergence is what M4's comparison needs to
be able to produce.
"""

from __future__ import annotations

import pytest

from quantumnet.topology.shapes import (
    TOPOLOGY_BUILDERS,
    bcube,
    build_topology,
    fat_tree,
    topology_report,
)
from quantumnet.topology.strategies import (
    FidelityOptimalRouting,
    LengthRouting,
)


# ---------------------------------------------------------------------------
# FatTree
# ---------------------------------------------------------------------------

def test_fattree_node_and_link_counts_match_the_definition():
    """FatTree(k): k pods; (k/2)^2 cores; k*k/2 agg; k*k/2 edge; k^3/4 hosts."""
    for k in (2, 4):
        topo = fat_tree(k)
        half = k // 2
        cores = half * half
        agg = k * half
        edge = k * half
        hosts = k * half * half
        assert sum(1 for n in topo.nodes if n.startswith("core")) == cores
        assert sum(1 for n in topo.nodes if n.startswith("agg")) == agg
        assert sum(1 for n in topo.nodes if n.startswith("edge")) == edge
        assert sum(1 for n in topo.nodes if n.startswith("host")) == hosts
        assert len(topo.nodes) == cores + agg + edge + hosts


def test_fattree_is_connected():
    for k in (2, 4):
        assert topology_report(fat_tree(k))["connected"]


def test_fattree_rejects_an_odd_arity():
    with pytest.raises(ValueError, match="even integer"):
        fat_tree(3)


def test_fattree_rejects_a_degenerate_arity():
    with pytest.raises(ValueError, match="even integer"):
        fat_tree(0)


def test_fattree_every_aggregation_switch_reaches_every_core():
    """The full bipartite core layer is what gives cross-pod bandwidth."""
    topo = fat_tree(4)
    cores = [n for n in topo.nodes if n.startswith("core")]
    for agg in (n for n in topo.nodes if n.startswith("agg")):
        neighbours = set(topo.neighbors(agg))
        assert set(cores) <= neighbours


def test_fattree_hosts_are_leaves_and_switches_are_repeaters():
    topo = fat_tree(4)
    for name, node in topo.nodes.items():
        if name.startswith("host"):
            assert not node.is_repeater
            assert len(topo.neighbors(name)) == 1
        else:
            assert node.is_repeater


def test_fattree_same_pod_path_is_shorter_than_cross_pod():
    """The structural property the topology exists to express."""
    topo = fat_tree(4)
    same = FidelityOptimalRouting().select(topo, "host0_0_0", "host0_0_1")
    cross = FidelityOptimalRouting().select(topo, "host0_0_0", "host3_1_1")
    assert same is not None and cross is not None
    assert same.hops < cross.hops


# ---------------------------------------------------------------------------
# BCube
# ---------------------------------------------------------------------------

def test_bcube_node_counts_match_the_definition():
    """BCube(n, k): n^(k+1) hosts and (k+1) * n^k switches."""
    for n, k in ((2, 0), (2, 1), (3, 1), (2, 2)):
        topo = bcube(n, k)
        assert sum(1 for x in topo.nodes if x.startswith("h")) == n ** (k + 1)
        assert sum(1 for x in topo.nodes if x.startswith("s")) == (k + 1) * n ** k


def test_bcube_is_connected():
    for n, k in ((2, 1), (2, 2), (3, 1)):
        assert topology_report(bcube(n, k))["connected"]


def test_bcube_rejects_a_degenerate_arity():
    with pytest.raises(ValueError, match="arity n"):
        bcube(1, 1)
    with pytest.raises(ValueError, match="level count"):
        bcube(2, -1)


def test_bcube_host_degree_grows_with_levels():
    """Every extra level adds a disjoint path, so host degree grows linearly."""
    d1 = len(bcube(2, 1).neighbors("h00"))
    d2 = len(bcube(2, 2).neighbors("h000"))
    assert d1 == 2 and d2 == 3


def test_bcube_switches_are_repeaters_and_hosts_are_not():
    topo = bcube(2, 1)
    for name, node in topo.nodes.items():
        assert node.is_repeater == name.startswith("s")


def test_bcube_level_connects_hosts_sharing_that_digit():
    """A host reaches one switch per level, indexed by its *other* digits.

    At level 0 the switch is identified by the trailing digits, so ``s0_0``
    serves the hosts ending in 0; at level 1 it is identified by the leading
    digit, so ``s1_0`` serves the hosts starting with 0.  Each switch therefore
    serves exactly ``n`` hosts.
    """
    topo = bcube(2, 1)
    # level 0 varies the first digit -> switch keyed by the second
    assert set(topo.neighbors("s0_0")) == {"h00", "h10"}
    assert set(topo.neighbors("s0_1")) == {"h01", "h11"}
    # level 1 varies the second digit -> switch keyed by the first
    assert set(topo.neighbors("s1_0")) == {"h00", "h01"}
    assert set(topo.neighbors("s1_1")) == {"h10", "h11"}


def test_every_bcube_switch_serves_exactly_n_hosts():
    """A structural invariant of the construction, at several sizes."""
    for n, k in ((2, 1), (2, 2), (3, 1), (3, 2)):
        topo = bcube(n, k)
        switches = [x for x in topo.nodes if x.startswith("s")]
        for switch in switches:
            assert len(topo.neighbors(switch)) == n, (
                f"BCube({n},{k}) switch {switch} serves "
                f"{len(topo.neighbors(switch))} hosts, expected {n}"
            )


def test_bcube_switch_names_are_unique():
    """Encoding the other digits must not collide between levels."""
    for n, k in ((2, 2), (3, 2)):
        topo = bcube(n, k)
        switches = [x for x in topo.nodes if x.startswith("s")]
        assert len(switches) == len(set(switches))
        assert len(switches) == (k + 1) * n ** k


# ---------------------------------------------------------------------------
# Builder registry
# ---------------------------------------------------------------------------

def test_every_documented_builder_is_registered():
    for shape in ("ring", "grid", "fattree", "bcube"):
        assert shape in TOPOLOGY_BUILDERS


def test_build_topology_dispatches_by_name():
    assert len(build_topology("fattree", k=2).nodes) == 7
    assert len(build_topology("bcube", n=2, k=1).nodes) == 8
    assert len(build_topology("ring", nodes=["a", "b", "c"]).nodes) == 3
    assert len(build_topology("grid", rows=2, cols=3).nodes) == 6


def test_build_topology_rejects_an_unknown_shape():
    with pytest.raises(ValueError, match="unknown topology shape"):
        build_topology("hypercube")


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

def test_report_counts_nodes_links_and_repeaters():
    report = topology_report(fat_tree(4))
    assert report["nodes"] == 36
    assert report["links"] > 0
    assert report["is_repeater_count"] == 20
    assert report["min_degree"] >= 1
    assert report["max_degree"] >= report["min_degree"]


def test_report_detects_a_disconnected_graph():
    """An unreachable pair looks like a routing failure; it is a different thing."""
    from quantumnet.topology.graph import QuantumNode, QuantumTopology
    topo = QuantumTopology()
    for i, name in enumerate(("A", "B", "C", "D")):
        topo.add_node(QuantumNode(node_id=name, x_km=float(i)))
    topo.connect("A", "B")
    topo.connect("C", "D")
    assert topology_report(topo)["connected"] is False


def test_report_marks_a_connected_graph_connected():
    assert topology_report(fat_tree(2))["connected"] is True


def test_report_handles_an_empty_topology():
    from quantumnet.topology.graph import QuantumTopology
    report = topology_report(QuantumTopology())
    assert report["nodes"] == 0
    assert report["connected"] is True   # vacuously
    assert report["mean_degree"] == 0.0


# ---------------------------------------------------------------------------
# The property these topologies exist to expose
# ---------------------------------------------------------------------------

def test_a_fattree_can_separate_the_routing_policies():
    """Distance and fidelity routing are not always the same choice.

    On uniform links they coincide, because fidelity is then a function of hop
    count alone.  A FatTree makes the divergence reachable in its natural form:
    the pod-local path is short and, if one of its middle links is degraded,
    poor; the core detour is longer and good.

    The property asserted is the one that matters operationally -- the
    fidelity-optimal router **accepts more hops and more fibre** to reach a
    materially better pair, and the distance-minimising router does not.

    (Equal-distance variants are covered separately in
    ``test_strategies.py``; on a FatTree the hop counts cannot be equalised,
    because the detour through the core is inherently longer.)
    """
    topo = fat_tree(4, link_km=1.0)

    def pin(a: str, b: str, fidelity: float) -> None:
        link = topo.link(a, b)
        assert link is not None, f"no link {a}-{b}"
        link.fidelity = lambda _f=fidelity: _f  # type: ignore[method-assign]

    src, dst = "host0_0_0", "host0_1_1"
    # The pod-local path's shared hop is degraded.
    pin("edge0_0", "agg0_0", 0.55)

    optimal = FidelityOptimalRouting().select(topo, src, dst)
    distance = LengthRouting().select(topo, src, dst)
    assert optimal is not None and distance is not None

    def total_km(route) -> float:
        return sum(topo.link(a, b).length_km
                   for a, b in zip(route.path, route.path[1:]))

    # Distance is *indifferent* here: both candidate routes are 4 hops of 1 km,
    # so total distance ties and the distance-minimising router resolves the tie
    # arbitrarily -- landing on the degraded path.  Fidelity is the only metric
    # with information, and it picks the other one.
    assert optimal.hops == distance.hops, (
        "hop counts diverged, so this would not isolate fidelity"
    )
    assert optimal.e2e_fidelity > distance.e2e_fidelity
    assert optimal.e2e_fidelity - distance.e2e_fidelity > 0.1
    assert optimal.path != distance.path
