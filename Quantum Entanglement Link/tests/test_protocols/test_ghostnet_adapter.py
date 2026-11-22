"""Adapter tests for the legacy Ghost-Net exporter importer.

These cover exactly the format knowledge that used to live in the old
``topology/ghostnet.py``: ``generator`` gating, ``fingerprint``/``addr``
node records, and the ``positions`` object.  Everything else in QEL keeps
the generic-schema contract defined in ``test_bridge_json.py``.

Each test goes through :func:`topology.importers.parse` with
``schema_id="vantablack"`` so the adapter -- not the test -- carries the
legacy format knowledge.
"""

import json

import pytest

from quantumnet.topology.importers import importer_for, parse


def _write_export(tmp_path, nodes, links, positions=None):
    doc = {
        "schema_version": 1,
        "generator": "vantablack",
        "exported_at": 0,
        "nodes": [{"fingerprint": fp, "addr": addr} for fp, addr in nodes],
        "links": [{"a": a, "b": b} for a, b in links],
    }
    if positions:
        doc["positions"] = positions
    path = tmp_path / "topology.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


class TestGhostNetExporterImporter:
    def test_parse_positions(self):
        from quantumnet.topology.importers.ghostnet import parse_positions
        assert parse_positions("aa=0,0 bb=10,20") == {"aa": (0.0, 0.0), "bb": (10.0, 20.0)}
        assert parse_positions(None) == {}

    def test_load_rejects_non_vantablack(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"generator": "other"}), encoding="utf-8")
        with pytest.raises(ValueError):
            parse(str(p), schema_id="vantablack")

    def test_import_two_nodes(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(
            tmp_path, [(fp_a, "1.2.3.4:1000"), (fp_b, "5.6.7.8:2000")],
            [(fp_a, fp_b)], positions="aa11=0,0 bb22=500,300",
        )
        importer = importer_for(path, "vantablack")
        doc = importer(path).parse()
        assert set(doc["nodes"]) == {fp_a, fp_b}
        assert doc["nodes"][fp_a].x_km == 0.0 and doc["nodes"][fp_a].y_km == 0.0
        assert doc["nodes"][fp_b].x_km == 500.0 and doc["nodes"][fp_b].y_km == 300.0
        assert len(doc["links"]) == 1

    def test_embedded_positions(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(
            tmp_path, [(fp_a, "a"), (fp_b, "b")],
            [(fp_a, fp_b)], positions="aa11=0,0 bb22=200,0",
        )
        doc = parse(path, schema_id="vantablack")
        assert ((doc["nodes"][fp_a].x_km-doc["nodes"][fp_b].x_km)**2+(doc["nodes"][fp_a].y_km-doc["nodes"][fp_b].y_km)**2)**0.5 == ((doc["nodes"][fp_a].x_km-doc["nodes"][fp_b].x_km)**2+(doc["nodes"][fp_a].y_km-doc["nodes"][fp_b].y_km)**2)**0.5

    def test_unknown_node_raises(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(
            tmp_path, [(fp_a, "a"), (fp_b, "b")], [(fp_a, fp_b)],
        )
        doc = parse(path, schema_id="vantablack")
        with pytest.raises(KeyError):
            _ = doc["nodes"]["nope"]


class TestImporterSelection:
    def test_prefer_schema_over_extension(self, tmp_path):
        p = tmp_path / "mesh.dot"
        p.write_text("digraph QEL { A; B; A -> B [len=100]; }", encoding="utf-8")
        with pytest.raises(ValueError):
            parse(str(p), schema_id="vantablack")

    def test_no_importer_for_unknown_extension(self, tmp_path):
        p = tmp_path / "unknown.xyz"
        p.write_text("not a topology", encoding="utf-8")
        with pytest.raises(ValueError):
            parse(str(p))
