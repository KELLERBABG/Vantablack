"""M5 acceptance: export a QEL topology, load it in SeQUeNCe, compare.

This is the "same topology in both tools" test.  It requires SeQUeNCe to be
installed; when it is absent the cross-check is skipped rather than faked.

What it checks: SeQUeNCe's own loader accepts QEL's emitted document, and the
network it builds has the nodes and links QEL intended -- in particular that the
**distance halving** is understood (a qconnection declares the FULL link, and
SeQUeNCe splits it into two half-length arms) and that the mandatory classical
companions are present, since ``_add_qconnections`` asserts without them.
"""
import json

import pytest

from quantumnet.topology.graph import QuantumLink, QuantumNode, QuantumTopology
from quantumnet.topology.importers.sequencer import export_document

sequence = pytest.importorskip("sequence", reason="SeQUeNCe is not installed")

from sequence.topology.router_net_topo import RouterNetTopo  # noqa: E402


def _chain(n=3, spacing=50.0):
    topo = QuantumTopology()
    for i in range(n):
        topo.add_node(QuantumNode(node_id=f"router_{i}", x_km=i * spacing,
                                  y_km=0.0))
    for i in range(n - 1):
        topo.add_link(QuantumLink(a=f"router_{i}", b=f"router_{i+1}",
                                  length_km=spacing))
    return topo


def test_qel_export_loads_in_sequence():
    """SeQUeNCe's own loader must accept QEL's document."""
    topo = _chain(3, 50.0)
    config = export_document(topo, stop_time_ps=1_000_000_000)
    # RouterNetTopo accepts a path or a dict; a dict skips the file round-trip.
    try:
        net = RouterNetTopo(config)
    except Exception as exc:  # noqa: BLE001 - report the reason, do not mask it
        pytest.fail(f"SeQUeNCe rejected QEL's config: {type(exc).__name__}: {exc}")
    assert net is not None


def test_the_node_set_survives_the_round_trip():
    """Same router names on both sides."""
    topo = _chain(3, 50.0)
    config = export_document(topo)
    net = RouterNetTopo(config)

    routers = net.get_nodes_by_type(RouterNetTopo.QUANTUM_ROUTER)
    names = {r.name for r in routers}
    assert names == set(topo.nodes), f"node sets differ: {names}"


def test_the_link_count_survives_the_round_trip():
    """One qconnection becomes one BSM node plus two half arms.

    So the network gains nodes that are *not* routers -- which is why the importer
    has to treat them as scaffolding rather than as placeable sites.
    """
    topo = _chain(3, 50.0)
    config = export_document(topo)
    net = RouterNetTopo(config)

    routers = net.get_nodes_by_type(RouterNetTopo.QUANTUM_ROUTER)
    bsms = net.get_nodes_by_type(RouterNetTopo.BSM_NODE)
    assert len(routers) == 3
    # two qconnections -> two midpoint BSM nodes
    assert len(bsms) == 2, f"expected one BSM per qconnection, got {len(bsms)}"


def test_the_declared_distance_is_the_full_link():
    """Trap #2: SeQUeNCe halves the declared distance into two arms.

    QEL records the full link, so the arms must each be half of it.  If the
    exporter wrote the half-length, SeQUeNCe would build arms of a quarter and
    the link budget would be wrong by 2x -- silently.
    """
    topo = _chain(2, 80.0)
    config = export_document(topo)
    net = RouterNetTopo(config)

    channels = net.get_qchannels()
    assert channels, "no quantum channels were built"
    for channel in channels:
        # each arm carries half the declared length
        assert channel.distance == pytest.approx(40.0, rel=1e-9), (
            f"arm distance {channel.distance} km, expected half of 80 km"
        )


def test_the_classical_companions_are_present_and_used():
    """Trap #5: ``_add_qconnections`` asserts without a classical channel."""
    topo = _chain(3, 50.0)
    config = export_document(topo)
    # every qconnection has a matching cconnection between its router pair
    q_pairs = {frozenset((q["node1"], q["node2"]))
               for q in config["qconnections"]}
    c_pairs = {frozenset((c["node1"], c["node2"]))
               for c in config["cconnections"]}
    assert q_pairs <= c_pairs

    net = RouterNetTopo(config)
    classical = net.get_cchannels()
    assert classical, "no classical channels built"


def test_a_qel_exported_file_round_trips_through_disk(tmp_path):
    """The file path, not just the dict path."""
    from quantumnet.topology.importers.sequencer import write_config
    topo = _chain(3, 40.0)
    path = write_config(topo, tmp_path / "net.sequence.json")
    net = RouterNetTopo(str(path))
    routers = {r.name for r in net.get_nodes_by_type(RouterNetTopo.QUANTUM_ROUTER)}
    assert routers == set(topo.nodes)


def test_qel_can_read_back_what_it_wrote_for_sequencer(tmp_path):
    """Round trip within QEL: export, re-import, same links."""
    from quantumnet.topology.importers import parse as parse_topology
    from quantumnet.topology.importers.sequencer import write_config
    topo = _chain(4, 30.0)
    path = write_config(topo, tmp_path / "rt.sequence.json")
    doc = parse_topology(str(path))
    assert set(doc["nodes"]) == set(topo.nodes)
    assert len(doc["links"]) == len(topo.links)
