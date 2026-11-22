"""The SeQUeNCe `RouterNetTopo` export, which existed untested.

`export_sequencer_document` and `write_sequencer_config` were implemented but had no
coverage at all, while the *import* side was tested. An untested exporter is the same
hazard the `qel-json` gap turned out to be: a format with one working direction.

Its docstring names a specific trap -- SeQUeNCe asserts if a quantum connection has no
matching classical channel -- so that is asserted directly here rather than left to
whoever next regenerates a config.
"""

from __future__ import annotations

import json

import pytest

from quantumnet.topology.importers import (
    export_sequencer_document,
    parse,
    write_sequencer_config,
)
from quantumnet.topology.shapes import build_topology


def small_topology():
    """A chain, which is what a repeater config should look like."""
    return build_topology("ring", nodes=["A", "R0", "R1", "B"],
                          radius_km=10.0)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

def test_the_document_has_the_routernettopo_shape():
    document = export_sequencer_document(small_topology(), topology_name="chain")
    assert "nodes" in document and "qconnections" in document
    assert document["nodes"], "no nodes emitted"


def test_every_quantum_connection_has_a_classical_companion():
    """The trap its own docstring names.

    SeQUeNCe asserts when a ``qconnection`` has no matching ``cconnection``, so a config
    that omits them looks correct and fails at load time in the other tool.
    """
    document = export_sequencer_document(small_topology())
    quantum = {json.dumps(q, sort_keys=True) for q in document["qconnections"]}
    assert quantum, "no quantum connections emitted"
    classical = document.get("cconnections") or []
    assert classical, (
        "no classical channels emitted; SeQUeNCe asserts on a qconnection without one")

    def endpoint_pair(connection):
        return tuple(sorted((connection["node1"], connection["node2"])))

    quantum_pairs = {endpoint_pair(q) for q in document["qconnections"]}
    classical_pairs = {endpoint_pair(c) for c in classical}
    assert quantum_pairs <= classical_pairs, (
        f"quantum links without a classical companion: "
        f"{sorted(quantum_pairs - classical_pairs)}")


def test_the_document_is_json_serialisable():
    document = export_sequencer_document(small_topology())
    assert json.loads(json.dumps(document))


def test_the_document_records_its_stop_time():
    """`topology_name` is not part of the format; `stop_time` is.

    My first version of this test asserted the name appeared in the document. It does
    not -- `topology_name` is only used for logging -- so the test was asserting a field
    that does not exist rather than the one that does.
    """
    document = export_sequencer_document(small_topology())
    assert "stop_time" in document
    assert document["stop_time"] > 0


# ---------------------------------------------------------------------------
# Writing, and the round trip
# ---------------------------------------------------------------------------

def test_writing_produces_a_utf8_file(tmp_path):
    path = write_sequencer_config(small_topology(), tmp_path / "seq.json")
    raw = path.read_bytes()
    raw.decode("utf-8")
    assert json.loads(raw.decode("utf-8"))


def test_the_written_file_imports_back(tmp_path):
    """The round trip, which is the only check that both directions agree.

    Imported through `parse`, which resolves the importer from the suffix -- the
    lower-level `import_sequencer_document` takes an already-loaded dict.
    """
    topology = small_topology()
    path = write_sequencer_config(topology, tmp_path / "seq.sequence.json")
    restored = parse(str(path))
    assert restored["nodes"], "importer produced nothing from our own export"


def test_both_directions_agree_on_the_same_topology(tmp_path):
    """The acceptance criterion in the plan: one topology, both tools.

    Written through the native schema and through the SeQUeNCe exporter, then read back
    through each importer, and the node sets compared.
    """
    from quantumnet.topology.qel_json_export import write_qel_json

    topology = small_topology()
    native = write_qel_json(topology, tmp_path / "t.qel.json",
                            generated_at="2026-10-07T00:00:00Z")
    sequencer = write_sequencer_config(topology, tmp_path / "t.sequence.json")

    from_native = parse(str(native))
    from_sequencer = parse(str(sequencer))

    assert set(from_native["nodes"]) == set(from_sequencer["nodes"])
