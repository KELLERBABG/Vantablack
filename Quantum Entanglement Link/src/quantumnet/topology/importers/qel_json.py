"""Versioned native QEL JSON topology importer.

QEL owns its own schema.  This importer is the reference implementation of
that schema: it is *also* the bridge format the Rust daemon consumes, but
the fields below are defined by QEL, not by the daemon.  Callers that need
a ``generator`` field should use :class:`GhostNetImporter` instead.
"""

from __future__ import annotations

import json
from math import isfinite
from pathlib import Path

from .base import (
    Topology,
    TopologyImporter,
    TopologyLink,
    TopologyNode,
    TopologyParseException,
)

VERSION = "1.0"


def _finite_float(value, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise TopologyParseException(f"{what}: expected a number, got {value!r}") from exc
    if not isfinite(number):
        raise TopologyParseException(f"{what}: must be finite, got {value!r}")
    return number


class QelJsonImporter(TopologyImporter):
    """Read a QEL JSON topology file into the canonical :class:`Topology`.

    Expected document::

        {
          "schema_version": "1.0",
          "generated_at": "2026-10-07T00:00:00Z",
          "nodes": [
            {"id": "A", "x_km": 0, "y_km": 0, "t1_s": 100, "t2_s": 50, "is_repeater": false},
            {"id": "R0", "x_km": 50, "y_km": 0, "t1_s": 200, "t2_s": 100, "is_repeater": true}
          ],
          "links": [
            {"a": "A", "b": "R0", "length_km": 50, "alpha_db_km": 0.2}
          ]
        }
    """

    def parse(self) -> dict:
        data = json.loads(Path(self.path).read_text(encoding="utf-8"), parse_constant=self._reject_constant)
        return self._build(data)

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise TopologyParseException(f"non-finite constant {value!r} in topology JSON")

    def _build(self, data: dict) -> dict:
        if not isinstance(data, dict):
            raise TopologyParseException(f"{self.path}: top level must be an object")

        if data.get("schema_version") != VERSION:
            raise TopologyParseException(
                f"{self.path}: unsupported schema_version "
                f"{data.get('schema_version')!r} (want {VERSION})"
            )

        nodes = data.get("nodes")
        links = data.get("links")
        if not isinstance(nodes, list) or not isinstance(links, list):
            raise TopologyParseException(f"{self.path}: 'nodes' and 'links' must be arrays")

        out_nodes: dict[str, TopologyNode] = {}
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise TopologyParseException(f"{self.path}: nodes[{index}] must be an object")
            node_id = node.get("id")
            if not isinstance(node_id, str) or not node_id:
                raise TopologyParseException(f"{self.path}: nodes[{index}].id must be a non-empty string")
            x = _finite_float(node.get("x_km", 0.0), f"{self.path}: nodes[{index}].x_km")
            y = _finite_float(node.get("y_km", 0.0), f"{self.path}: nodes[{index}].y_km")
            t1 = _finite_float(node.get("t1_s", 100.0), f"{self.path}: nodes[{index}].t1_s")
            t2 = _finite_float(node.get("t2_s", 50.0), f"{self.path}: nodes[{index}].t2_s")
            is_repeater = bool(node.get("is_repeater", False))
            if node_id in out_nodes:
                raise TopologyParseException(f"{self.path}: duplicate node id {node_id!r}")
            out_nodes[node_id] = TopologyNode(
                id=node_id, x_km=x, y_km=y, t1_s=t1, t2_s=t2, is_repeater=is_repeater
            )

        out_links: list[TopologyLink] = []
        for index, link in enumerate(links):
            if not isinstance(link, dict):
                raise TopologyParseException(f"{self.path}: links[{index}] must be an object")
            a = link.get("a")
            b = link.get("b")
            if not isinstance(a, str) or not isinstance(b, str):
                raise TopologyParseException(f"{self.path}: links[{index}] endpoints must be strings")
            if not a or not b:
                raise TopologyParseException(f"{self.path}: links[{index}] endpoints must be non-empty")
            if a not in out_nodes or b not in out_nodes:
                raise TopologyParseException(
                    f"{self.path}: links[{index}] references unknown node "
                    f"({a!r} or {b!r}); known ids: {sorted(out_nodes)}"
                )
            length = _finite_float(link.get("length_km"), f"{self.path}: links[{index}].length_km")
            alpha = _finite_float(link.get("alpha_db_km", 0.2), f"{self.path}: links[{index}].alpha_db_km")
            out_links.append(TopologyLink(a=a, b=b, length_km=length, alpha_db_km=alpha))

        return {"nodes": out_nodes, "links": out_links}
