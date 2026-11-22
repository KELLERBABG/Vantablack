"""SeQUeNCe topology interop tests.

These pin the five traps documented in ``topology/importers/sequencer.py``.
Each one is a silent corruption rather than a crash, which is why they are
tested by explicit numeric assertion rather than by "it did not raise".

The fixtures are modelled on the real shapes from SeQUeNCe's own examples
(``example/demo_for_beginners/star_network.json`` and ``teleport_2node.json``),
including the ``0.0002`` attenuation value (dB/m = 0.2 dB/km) and the
``BSM_alice_bob``/``BSM.node1.node2`` midpoint naming.
"""

from __future__ import annotations

import json

import pytest

from quantumnet.topology.graph import (
    QuantumLink,
    QuantumNode,
    QuantumTopology,
)
from quantumnet.topology.importers import parse as parse_topology
from quantumnet.topology.importers.base import TopologyParseException
from quantumnet.topology.importers.sequencer import (
    C_FIBER_KM_PER_S,
    SequencerImporter,
    export_document,
    import_document,
    write_config,
)


def _star_config() -> dict:
    """SeQUeNCe's star-network demo shape, verbatim in structure."""
    return {
        "nodes": [
            {"name": "center", "type": "QuantumRouter", "seed": 0, "memo_size": 50},
            {"name": "router1", "type": "QuantumRouter", "seed": 1, "memo_size": 50},
            {"name": "router2", "type": "QuantumRouter", "seed": 2, "memo_size": 50},
            {"name": "router3", "type": "QuantumRouter", "seed": 3, "memo_size": 50},
            {"name": "router4", "type": "QuantumRouter", "seed": 4, "memo_size": 50},
        ],
        "qconnections": [
            {"node1": "center", "node2": "router1", "attenuation": 0.0002,
             "distance": 500, "type": "meet_in_the_middle"},
            {"node1": "center", "node2": "router2", "attenuation": 0.0002,
             "distance": 500, "type": "meet_in_the_middle"},
            {"node1": "center", "node2": "router3", "attenuation": 0.0002,
             "distance": 500, "type": "meet_in_the_middle"},
            {"node1": "center", "node2": "router4", "attenuation": 0.0002,
             "distance": 500, "type": "meet_in_the_middle"},
        ],
        "stop_time": 2000000000000,
        "cconnections": [
            {"node1": "center", "node2": "router1", "delay": 500000000},
            {"node1": "center", "node2": "router2", "delay": 500000000},
            {"node1": "center", "node2": "router3", "delay": 500000000},
            {"node1": "center", "node2": "router4", "delay": 500000000},
        ],
    }


def _teleport_config() -> dict:
    """SeQUeNCe's 2-node teleportation shape: explicit qchannels via a BSM."""
    return {
        "templates": {"teleportation": {"MemoryArray": {"fidelity": 1, "efficiency": 0.7}}},
        "nodes": [
            {"name": "alice", "type": "DQCNode", "seed": 0, "memo_size": 1,
             "data_memo_size": 1, "group": 0, "template": "teleportation"},
            {"name": "bob", "type": "DQCNode", "seed": 1, "memo_size": 1,
             "data_memo_size": 1, "group": 0, "template": "teleportation"},
            {"name": "BSM_alice_bob", "type": "BSMNode", "seed": 0, "group": 0,
             "template": "teleportation"},
        ],
        "qchannels": [
            {"source": "alice", "destination": "BSM_alice_bob",
             "distance": 500.0, "attenuation": 0.0002},
            {"source": "bob", "destination": "BSM_alice_bob",
             "distance": 500.0, "attenuation": 0.0002},
        ],
        "cchannels": [
            {"source": "alice", "destination": "BSM_alice_bob", "delay": 500000000},
            {"source": "bob", "destination": "BSM_alice_bob", "delay": 500000000},
        ],
        "stop_time": 10000000000000,
    }


# ---------------------------------------------------------------------------
# Trap 1: attenuation is dB/m, not dB/km
# ---------------------------------------------------------------------------

def test_attenuation_is_converted_from_db_per_metre():
    """0.0002 dB/m must become 0.2 dB/km -- not 0.0002 dB/km (1000x too lossy)."""
    doc = import_document(_star_config())
    for link in doc["links"]:
        assert link.alpha_db_km == pytest.approx(0.2, rel=1e-12)


def test_reading_attenuation_as_db_per_km_would_be_wrong():
    """Guard the direction of the conversion with an explicit inverse check."""
    doc = import_document(_star_config())
    link = doc["links"][0]
    assert link.alpha_db_km != pytest.approx(0.0002, rel=1e-3)
    # and it round-trips back to the written dB/m value
    out = export_document(doc)
    for qc in out["qconnections"]:
        assert qc["attenuation"] == pytest.approx(0.0002, rel=1e-12)


# ---------------------------------------------------------------------------
# Trap 2: a qconnection's declared distance is the full link
# ---------------------------------------------------------------------------

def test_qconnection_distance_is_the_full_link_length():
    """SeQUeNCe halves it internally; the canonical topology must keep 500 km."""
    doc = import_document(_star_config())
    lengths = sorted(l.length_km for l in doc["links"])
    assert lengths == [500.0] * 4


def test_exported_distance_is_the_full_length_not_the_half():
    """Export must write the full length so SeQUeNCe's halving reconstructs it."""
    doc = import_document(_star_config())
    out = export_document(doc)
    for qc in out["qconnections"]:
        assert qc["distance"] == pytest.approx(500.0, rel=1e-12)


# ---------------------------------------------------------------------------
# Trap 3: explicit qchannel halves collapse into one whole link
# ---------------------------------------------------------------------------

def test_explicit_half_channels_collapse_into_one_link():
    """alice->BSM (500 km) + bob->BSM (500 km) is ONE 1000 km link."""
    doc = import_document(_teleport_config())
    assert len(doc["links"]) == 1
    link = doc["links"][0]
    assert {link.a, link.b} == {"alice", "bob"}
    assert link.length_km == pytest.approx(1000.0, rel=1e-12)


def test_unpaired_half_link_is_dropped_not_invented():
    """A lone router->BSM arm is not a link; fabricating an endpoint is wrong."""
    config = _teleport_config()
    config["qchannels"] = config["qchannels"][:1]  # keep only alice's arm
    doc = import_document(config)
    assert doc["links"] == []


# ---------------------------------------------------------------------------
# Trap 4: BSM / scaffolding nodes are not network sites
# ---------------------------------------------------------------------------

def test_bsm_nodes_are_excluded_from_the_node_set():
    doc = import_document(_teleport_config())
    assert set(doc["nodes"]) == {"alice", "bob"}
    assert not any(name.startswith("BSM") for name in doc["nodes"])


def test_dotted_bsm_names_are_also_excluded():
    """SeQUeNCe auto-generates names like ``BSM.center.router1``."""
    config = _star_config()
    config["nodes"].append({
        "name": "BSM.center.router1", "type": "BSMNode", "seed": 0,
    })
    config["qchannels"] = [
        {"source": "center", "destination": "BSM.center.router1",
         "distance": 250, "attenuation": 0.0002},
        {"source": "router1", "destination": "BSM.center.router1",
         "distance": 250, "attenuation": 0.0002},
    ]
    doc = import_document(config)
    assert "BSM.center.router1" not in doc["nodes"]
    # the two 250 km halves become one 500 km link
    assert any(l.length_km == pytest.approx(500.0) for l in doc["links"])


# ---------------------------------------------------------------------------
# Trap 5: exported configs must carry the classical companions
# ---------------------------------------------------------------------------

def test_export_includes_cconnections_for_every_qconnection():
    """SeQUeNCe asserts if a qconnection lacks a classical companion."""
    doc = import_document(_star_config())
    out = export_document(doc)
    q_pairs = {frozenset((q["node1"], q["node2"])) for q in out["qconnections"]}
    c_pairs = {frozenset((c["node1"], c["node2"])) for c in out["cconnections"]}
    assert q_pairs <= c_pairs


def test_export_classical_delay_matches_fibre_flight_time():
    doc = import_document(_star_config())
    out = export_document(doc)
    qc = out["qconnections"][0]
    cc = next(c for c in out["cconnections"]
              if {c["node1"], c["node2"]} == {qc["node1"], qc["node2"]})
    expected_ps = int(qc["distance"] / C_FIBER_KM_PER_S * 1e12)
    assert cc["delay"] == expected_ps


def test_export_stop_time_is_integer_picoseconds():
    out = export_document(import_document(_star_config()))
    assert isinstance(out["stop_time"], int)
    assert out["stop_time"] > 0


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------

def test_round_trip_import_export_import_preserves_links():
    original = import_document(_star_config())
    again = import_document(export_document(original))
    key = lambda d: sorted(
        (frozenset((l.a, l.b)), round(l.length_km, 6),
         round(l.alpha_db_km, 9)) for l in d["links"]
    )
    assert key(original) == key(again)
    assert set(original["nodes"]) == set(again["nodes"])


def test_round_trip_a_quantum_topology_object():
    topo = QuantumTopology()
    for name, x in (("A", 0.0), ("R0", 50.0), ("B", 100.0)):
        topo.add_node(QuantumNode(node_id=name, x_km=x, y_km=0.0))
    topo.add_link(QuantumLink(a="A", b="R0", length_km=50.0))
    topo.add_link(QuantumLink(a="R0", b="B", length_km=50.0))

    out = export_document(topo)
    back = import_document(out)
    assert set(back["nodes"]) == {"A", "R0", "B"}
    lengths = sorted(l.length_km for l in back["links"])
    assert lengths == [50.0, 50.0]
    for link in back["links"]:
        assert link.alpha_db_km == pytest.approx(0.2, rel=1e-12)


def test_write_config_produces_a_loadable_file(tmp_path):
    topo = QuantumTopology()
    topo.add_node(QuantumNode(node_id="A", x_km=0.0))
    topo.add_node(QuantumNode(node_id="B", x_km=80.0))
    topo.add_link(QuantumLink(a="A", b="B", length_km=80.0))

    path = write_config(topo, tmp_path / "net.sequence.json")
    assert path.exists()
    doc = parse_topology(str(path))
    assert set(doc["nodes"]) == {"A", "B"}
    assert doc["links"][0].length_km == pytest.approx(80.0)


def test_extension_registry_selects_the_sequencer_importer(tmp_path):
    p = tmp_path / "net.sequence.json"
    p.write_text(json.dumps(_star_config()), encoding="utf-8")
    doc = parse_topology(str(p))
    assert set(doc["nodes"]) == {"center", "router1", "router2", "router3",
                                 "router4"}
    assert all(l.alpha_db_km == pytest.approx(0.2) for l in doc["links"])


def test_explicit_schema_id_works_without_a_matching_extension(tmp_path):
    p = tmp_path / "mystery.json"
    p.write_text(json.dumps(_star_config()), encoding="utf-8")
    doc = parse_topology(str(p), schema_id="sequencer")
    assert len(doc["links"]) == 4


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_missing_file_raises_a_parse_exception():
    with pytest.raises(TopologyParseException, match="no such file"):
        parse_topology("does-not-exist.sequence.json")


def test_invalid_json_raises_a_parse_exception(tmp_path):
    p = tmp_path / "broken.sequence.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(TopologyParseException, match="invalid JSON"):
        parse_topology(str(p))


def test_non_object_top_level_is_rejected():
    with pytest.raises(TopologyParseException, match="must be an object"):
        import_document([1, 2, 3])  # type: ignore[arg-type]


def test_missing_nodes_key_is_rejected():
    with pytest.raises(TopologyParseException, match="'nodes' must be an array"):
        import_document({"qconnections": []})


def test_scaffolding_only_config_is_rejected():
    with pytest.raises(TopologyParseException, match="no network nodes"):
        import_document({"nodes": [{"name": "BSM_a_b", "type": "BSMNode"}]})


def test_duplicate_node_name_is_rejected():
    config = _star_config()
    config["nodes"].append({"name": "center", "type": "QuantumRouter"})
    with pytest.raises(TopologyParseException, match="duplicate node name"):
        import_document(config)


def test_qconnection_on_a_scaffolding_node_is_rejected():
    config = _star_config()
    config["nodes"].append({"name": "BSM.x.y", "type": "BSMNode"})
    config["qconnections"].append(
        {"node1": "center", "node2": "BSM.x.y", "distance": 10,
         "attenuation": 0.0002})
    with pytest.raises(TopologyParseException, match="scaffolding"):
        import_document(config)


def test_nan_distance_is_rejected():
    config = _star_config()
    config["qconnections"][0]["distance"] = float("nan")
    with pytest.raises(TopologyParseException, match="must be finite"):
        import_document(config)


def test_export_rejects_a_link_to_an_unknown_node():
    with pytest.raises(TopologyParseException, match="not in the topology"):
        export_document({"nodes": {"A": None},
                         "links": [{"a": "A", "b": "Z", "length_km": 1.0}]})


def test_public_import_document_helper_matches_the_class():
    a = import_document(_star_config())
    b = SequencerImporter("<dict>").parse_document(_star_config())
    assert set(a["nodes"]) == set(b["nodes"])
    assert len(a["links"]) == len(b["links"])
