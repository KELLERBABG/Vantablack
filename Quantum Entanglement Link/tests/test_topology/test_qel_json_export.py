"""QEL JSON export, and the shape coverage the CLI was missing.

The native `qel-json` schema had an importer but **no exporter**, so a topology built in
Python could not be written out and `topology build` could only print one. The importer's
own tests hand-write their fixtures because nothing could produce them, which is the
symptom that this gap was real rather than cosmetic.

These tests assert the **round trip** rather than the field names. A schema drift should
show up as a failed round trip, not as a file that looks plausible -- the same principle
the validation instruments use.
"""

from __future__ import annotations

import json

import pytest

from quantumnet.topology.importers import importer_for, parse
from quantumnet.topology.importers.qel_json import VERSION as QEL_JSON_VERSION
from quantumnet.topology.qel_json_export import (
    topology_to_document,
    write_qel_json,
)
from quantumnet.topology.shapes import build_topology


def nodes_of(topo):
    return list(topo.nodes.values()) if isinstance(topo.nodes, dict) else list(topo.nodes)


def links_of(topo):
    raw = list(topo.links.values()) if isinstance(topo.links, dict) else list(topo.links)
    out = []
    for link in raw:
        a, b = getattr(link, "a", None), getattr(link, "b", None)
        if a is None and isinstance(link, (tuple, list)):
            a, b = link[0], link[1]
        out.append((a, b))
    return out


def pair_set(pairs):
    return {(min(a, b), max(a, b)) for a, b in pairs}


# ---------------------------------------------------------------------------
# The round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shape,kwargs", [
    ("fattree", {"k": 2}),
    ("bcube", {"n": 2, "k": 2}),
])
def test_a_built_topology_survives_a_write_read_round_trip(tmp_path, shape, kwargs):
    """The property the schema exists for, checked end to end."""
    topo = build_topology(shape, **kwargs)
    path = write_qel_json(topo, tmp_path / f"{shape}.qel.json",
                          generated_at="2026-10-07T00:00:00Z")
    document = parse(str(path), "qel-json")

    assert set(document["nodes"]) == {n.node_id for n in nodes_of(topo)}
    assert pair_set((l.a, l.b) for l in document["links"]) == \
        pair_set(links_of(topo))


def test_the_extension_alone_resolves_the_importer(tmp_path):
    """A written file must be readable without naming the schema explicitly."""
    topo = build_topology("fattree", k=2)
    path = write_qel_json(topo, tmp_path / "topology.qel.json",
                          generated_at="2026-10-07T00:00:00Z")
    document = parse(str(path))          # no schema_id
    assert document["nodes"]


def test_the_document_declares_its_schema_version():
    """Self-describing, so the suffix cannot be the only thing that identifies it."""
    document = topology_to_document(build_topology("fattree", k=2),
                                    generated_at="2026-10-07T00:00:00Z")
    assert document["schema_version"] == QEL_JSON_VERSION
    assert set(document) == {"schema_version", "generated_at", "nodes", "links"}


def test_geometry_and_coherence_times_are_preserved(tmp_path):
    """The load-bearing fields: without these the file is not a topology."""
    topo = build_topology("fattree", k=2)
    path = write_qel_json(topo, tmp_path / "t.qel.json",
                          generated_at="2026-10-07T00:00:00Z")
    document = parse(str(path), "qel-json")

    original = {n.node_id: n for n in nodes_of(topo)}
    for node_id, restored in document["nodes"].items():
        source = original[node_id]
        assert restored.x_km == pytest.approx(source.x_km)
        assert restored.y_km == pytest.approx(source.y_km)
        assert restored.t1_s == pytest.approx(source.t1_s)
        assert restored.t2_s == pytest.approx(source.t2_s)


def test_link_lengths_and_attenuation_are_preserved(tmp_path):
    topo = build_topology("fattree", k=2)
    path = write_qel_json(topo, tmp_path / "t.qel.json",
                          generated_at="2026-10-07T00:00:00Z")
    document = parse(str(path), "qel-json")

    original = {}
    for link in (list(topo.links.values()) if isinstance(topo.links, dict)
                 else list(topo.links)):
        original[(min(link.a, link.b), max(link.a, link.b))] = link
    for restored in document["links"]:
        key = (min(restored.a, restored.b), max(restored.a, restored.b))
        assert key in original
        assert restored.length_km == pytest.approx(original[key].length_km)
        assert restored.alpha_db_km == pytest.approx(original[key].alpha_db_km)


def test_the_written_file_is_utf8_with_lf_newlines(tmp_path):
    """A data format must not be able to corrupt itself through a code page.

    Appending to a document from PowerShell's legacy default corrupted a file in this
    repository twice. Writing with an explicit encoding is the guard.
    """
    topo = build_topology("fattree", k=2)
    path = write_qel_json(topo, tmp_path / "t.qel.json",
                          generated_at="2026-10-07T00:00:00Z")
    raw = path.read_bytes()
    raw.decode("utf-8")                       # must not raise
    assert b"\r\n" not in raw


def test_the_output_is_deterministic_for_a_fixed_timestamp(tmp_path):
    """Byte-identical output makes the file usable as a test fixture."""
    topo = build_topology("bcube", n=2, k=2)
    first = write_qel_json(topo, tmp_path / "a.qel.json",
                           generated_at="2026-10-07T00:00:00Z").read_bytes()
    second = write_qel_json(topo, tmp_path / "b.qel.json",
                            generated_at="2026-10-07T00:00:00Z").read_bytes()
    assert first == second


def test_the_document_is_valid_json_with_the_expected_shape():
    document = topology_to_document(build_topology("fattree", k=2),
                                    generated_at="2026-10-07T00:00:00Z")
    text = json.dumps(document)
    reloaded = json.loads(text)
    assert set(reloaded["nodes"][0]) == {"id", "x_km", "y_km", "t1_s", "t2_s",
                                         "is_repeater"}
    assert {"a", "b", "length_km", "alpha_db_km"} <= set(reloaded["links"][0])


# ---------------------------------------------------------------------------
# Suffix resolution
# ---------------------------------------------------------------------------

def test_a_plain_json_file_is_read_as_qel_json():
    """Otherwise `topology build --out x.json` writes a file `import` cannot read."""
    assert importer_for("topology.json").__name__ == "QelJsonImporter"


def test_more_specific_suffixes_still_win():
    """The regression this guards: a bare `.json` must not shadow a longer suffix.

    Iterating the extension map in insertion order would resolve `a.sequence.json` to
    the QEL JSON importer and silently mis-read a SeQUeNCe document.
    """
    assert importer_for("a.sequence.json").__name__ == "SequencerImporter"
    assert importer_for("a.seq.json").__name__ == "SequencerImporter"
    assert importer_for("a.qel.json").__name__ == "QelJsonImporter"
    assert importer_for("a.qeljs").__name__ == "QelJsonImporter"


def test_unrelated_suffixes_are_still_rejected():
    from quantumnet.topology.importers.base import TopologyParseException

    with pytest.raises(TopologyParseException):
        importer_for("topology.yaml")


# ---------------------------------------------------------------------------
# The CLI surface
# ---------------------------------------------------------------------------

def run_cli(*args):
    """Invoke the CLI the way a user does.

    `cli.main()` takes no arguments and reads `sys.argv`, so this goes through a
    subprocess rather than monkeypatching argv -- which also means the test covers real
    argument parsing and the `__main__` entry point, not just the dispatch function.
    """
    import subprocess
    import sys

    return subprocess.run([sys.executable, "-m", "quantumnet", *args],
                          capture_output=True, text=True)


def test_the_cli_can_build_every_registered_shape(tmp_path):
    """The missing piece: `topology build` only handled ring and grid."""
    for shape, extra in (("fattree", ["--k", "2"]),
                         ("bcube", ["--bcube-n", "2", "--k", "2"])):
        out = tmp_path / f"{shape}.qel.json"
        proc = run_cli("topology", "build", "--shape", shape, *extra,
                       "--out", str(out))
        assert proc.returncode == 0, proc.stderr
        assert out.exists()
        document = parse(str(out))
        assert document["nodes"], f"{shape} wrote no nodes"


def test_the_cli_written_file_is_consumable_by_import(tmp_path):
    """The round trip the plan asks for: `bench`/`plan` consume a generated file."""
    out = tmp_path / "fattree.qel.json"
    assert run_cli("topology", "build", "--shape", "fattree", "--k", "2",
                   "--out", str(out)).returncode == 0
    # `import` resolves the schema from the suffix and routes over the file.
    proc = run_cli("import", "--topology", str(out),
                   "--from", "edge0_0", "--to", "core0")
    assert proc.returncode == 0, proc.stderr
    assert "QuantumTopology" in proc.stdout


def test_build_without_out_still_prints():
    """Writing a file must not replace the existing behaviour."""
    proc = run_cli("topology", "build", "--shape", "grid")
    assert proc.returncode == 0, proc.stderr
    assert "QuantumTopology" in proc.stdout or "nodes" in proc.stdout
