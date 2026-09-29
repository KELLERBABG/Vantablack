import json

import pytest

from quantumnet.topology import (
    load_ghost_topology, parse_positions, route_ghost,
)


def _write_export(tmp_path, nodes, links, positions=None):
    doc = {
        "schema_version": 1,
        "generator": "vantablack",
        "exported_at": 0,
        "nodes": [{"fingerprint": fp, "addr": addr} for fp, addr in nodes],
        "links": [{"a": a, "b": b} for a, b in links],
    }
    if positions:
        doc["positions"] = {fp: list(xy) for fp, xy in positions.items()}
    p = tmp_path / "topology.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


class TestGhostNetBridge:
    def test_parse_positions(self):
        spec = "aa=0,0 bb=10,20"
        assert parse_positions(spec) == {"aa": (0.0, 0.0), "bb": (10.0, 20.0)}
        assert parse_positions(None) == {}

    def test_load_rejects_non_vantablack(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"generator": "other"}), encoding="utf-8")
        with pytest.raises(ValueError):
            load_ghost_topology(str(p))

    def test_route_two_nodes(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(tmp_path, [(fp_a, "1.2.3.4:1000"),
                                        (fp_b, "5.6.7.8:2000")],
                             [(fp_a, fp_b)],
                             positions={fp_a: (0.0, 0.0), fp_b: (500.0, 300.0)})
        topo, route, dist = route_ghost(path, fp_a, fp_b)
        assert route is not None
        assert route.path == [fp_a, fp_b]
        assert dist is not None
        assert 0.25 < dist.final_fidelity <= 1.0

    def test_embedded_positions(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(tmp_path,
                             [(fp_a, "a"), (fp_b, "b")],
                             [(fp_a, fp_b)],
                             positions={fp_a: (0.0, 0.0), fp_b: (200.0, 0.0)})
        topo, _, _ = route_ghost(path, fp_a, fp_b, positions=None)
        assert topo.nodes[fp_a].distance_to(topo.nodes[fp_b]) == pytest.approx(200.0)

    def test_unknown_node_raises(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(tmp_path, [(fp_a, "a"), (fp_b, "b")], [(fp_a, fp_b)])
        with pytest.raises(KeyError):
            route_ghost(path, fp_a, "nope")

    def test_min_fidelity_no_route(self, tmp_path):
        fp_a, fp_b = "aa11", "bb22"
        path = _write_export(tmp_path, [(fp_a, "a"), (fp_b, "b")], [(fp_a, fp_b)],
                             positions={fp_a: (0.0, 0.0), fp_b: (100000.0, 0.0)})
        topo, route, dist = route_ghost(path, fp_a, fp_b, min_fidelity=0.99)
        assert route is None and dist is None
