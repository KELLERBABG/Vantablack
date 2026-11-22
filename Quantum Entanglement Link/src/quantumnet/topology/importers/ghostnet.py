"""Thin adapter over the legacy Ghost-Net exporter format.

Ghost-Net is a live mesh daemon whose ``EXPORTTOPOLOGY <file.json>`` output
this module understands.  It keeps all the format knowledge (which keys it
expects, which values it accepts) inside this single file so nothing else in
QEL has to read the export.

For the record, a Ghost-Net export looks like::

    {
      "generator": "vantablack",
      "exported_at": "...",
      "nodes": [{"fingerprint": "...", "addr": "127.0.0.1:15252"}],
      "links":  [{"a": "<fp>", "b": "<fp>"}]
    }
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
import json
import math
from pathlib import Path

GHOST_TOPOLOGY_SCHEMA_VERSION = 1


def parse_positions(spec: str | None) -> dict[str, tuple[float, float]]:
    """Parse a ``"fp=x,y fp2=x,y"`` positions string."""
    out: dict[str, tuple[float, float]] = {}
    if not spec:
        return out
    for token in spec.split():
        if "=" not in token:
            continue
        nid, xy = token.split("=", 1)
        x, y = xy.split(",")
        out[nid.strip()] = (float(x), float(y))
    return out


class GhostNetImporter(TopologyImporter):
    """Import a live Ghost-Net topology export into the canonical :class:`Topology`.

    The legacy format is hard-coded here so nothing else in QEL knows about
    ``generator``, node fingerprints, or the ``positions`` map.  When a file
    is not a Ghost-Net export the importer raises :class:`TopologyParseException`
    (it does not silently fall back to an empty topology).
    """

    def parse(self) -> dict:
        data = json.loads(
            Path(self.path).read_text(encoding="utf-8"), parse_constant=self._reject_constant
        )
        return self._build(data)

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise TopologyParseException(f"non-finite constant {value!r} in topology JSON")

    def _build(self, data: dict) -> dict:
        if not isinstance(data, dict):
            raise TopologyParseException(f"{self.path}: top level must be an object")

        if data.get("generator") != "vantablack":
            raise TopologyParseException(
                f"{self.path}: not a Ghost-Net topology export "
                f"(generator={data.get('generator')!r})"
            )

        nodes = data.get("nodes")
        links = data.get("links")
        if not isinstance(nodes, list) or not isinstance(links, list):
            raise TopologyParseException(
                f"{self.path}: topology JSON must contain 'nodes' and 'links' arrays"
            )

        raw_positions = data.get("positions")
        if isinstance(raw_positions, str):
            # legacy exporter stored positions as a "fp=x,y fp2=x,y" string
            positions = parse_positions(raw_positions)
        elif isinstance(raw_positions, dict):
            positions = dict(raw_positions)
        else:
            positions = {}
        embedded = data.get("positions") or {}
        if isinstance(embedded, str):
            embedded = parse_positions(embedded)
        elif isinstance(embedded, dict):
            embedded = dict(embedded)
        elif embedded is None:
            embedded = {}

        for node in nodes:
            if not isinstance(node, dict):
                raise TopologyParseException(f"{self.path}: node entry is not an object")
            fp = node.get("fingerprint") or node.get("id")
            if not fp:
                continue
            if "x_km" in node and "y_km" in node:
                embedded.setdefault(
                    fp,
                    (
                        _finite_float(node["x_km"], f"node {fp} x_km"),
                        _finite_float(node["y_km"], f"node {fp} y_km"),
                    ),
                )
        for fp, xy in embedded.items():
            if not (isinstance(xy, (list, tuple)) and len(xy) == 2):
                raise TopologyParseException(
                    f"{self.path}: positions[{fp!r}]: expected [x, y], got {xy!r}"
                )
            positions.setdefault(fp, (float(xy[0]), float(xy[1])))

        out_nodes: dict[str, TopologyNode] = {}
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise TopologyParseException(f"{self.path}: nodes[{index}] must be an object")
            fp = node.get("fingerprint") or node.get("id")
            if not fp:
                continue
            x, y = positions.get(fp, (0.0, 0.0))
            out_nodes[fp] = TopologyNode(
                id=fp, x_km=float(x), y_km=float(y),
                t1_s=100.0, t2_s=50.0, is_repeater=False,
            )

        out_links: list[TopologyLink] = []
        for index, link in enumerate(links):
            if not isinstance(link, dict):
                raise TopologyParseException(f"{self.path}: links[{index}] must be an object")
            a, b = link.get("a"), link.get("b")
            if not isinstance(a, str) or not isinstance(b, str):
                raise TopologyParseException(f"{self.path}: links[{index}] endpoints must be strings")
            if not a or not b or a not in out_nodes or b not in out_nodes:
                continue
            length = link.get("length_km")
            if length is None:
                dx = out_nodes[a].x_km - out_nodes[b].x_km
                dy = out_nodes[a].y_km - out_nodes[b].y_km
                length = (dx * dx + dy * dy) ** 0.5
            length = _finite_float(length, f"link {a}->{b} length_km")
            if length <= 0:
                continue
            out_links.append(TopologyLink(a=a, b=b, length_km=length, alpha_db_km=0.2))

        return {"nodes": out_nodes, "links": out_links}


def _finite_float(value, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise TopologyParseException(f"{what}: expected a number, got {value!r}") from exc
    if not isfinite(number):
        raise TopologyParseException(f"{what}: must be finite, got {value!r}")
    return number
