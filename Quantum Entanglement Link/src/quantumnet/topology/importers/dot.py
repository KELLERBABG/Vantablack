"""Graphviz .dot importer.

Graphviz diagrams are trivial to write by hand, so QEL accepts a small
strict subset of the dot language: a list of ``node`` statements with
optional ``x=``/``y=`` coordinates and a list of ``edge`` statements with
an optional ``len=`` attribute.

::

    digraph QEL {
        A; B; R0; R1;
        A -> B [len=100];
        B -> R0 [len=200];
        ...
    }

Only ``digraph``, ``node`` and ``edge`` statements are accepted; anything
else raises :class:`TopologyParseException`.
"""

from __future__ import annotations

import re
from math import isfinite
from pathlib import Path

from .base import (
    Topology,
    TopologyImporter,
    TopologyLink,
    TopologyNode,
    TopologyParseException,
)

_TOKEN = re.compile(r"[A-Za-z0-9_\-\.]+")
_ATTR = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([-+0-9.eE]+)")


def _finite_float(value, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise TopologyParseException(f"{what}: expected a number, got {value!r}") from exc
    if not isfinite(number):
        raise TopologyParseException(f"{what}: must be finite, got {value!r}")
    return number


class DotImporter(TopologyImporter):
    """Import a hand-written Graphviz subset into the canonical :class:`Topology`.
    """

    def parse(self) -> dict:
        text = Path(self.path).read_text(encoding="utf-8")
        return self._build(text)

    def _build(self, text: str) -> dict:
        if not text.lstrip().startswith("digraph"):
            raise TopologyParseException(
                f"{self.path}: only 'digraph' files are accepted"
            )
        nodes: dict[str, TopologyNode] = {}
        links: list[TopologyLink] = []
        seen_nodes: set[str] = set()

        for line_no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue
            if line.startswith("/*") and line.endswith("*/"):
                continue
            if line.startswith("digraph"):
                if not line.endswith("{"):
                    raise TopologyParseException(f"{self.path}:{line_no}: expecting '{{'")
                continue
            if line == "}":
                continue

            if "->" in line:
                edge = line[:-1].strip() if line.endswith(";") else line
                body, _, attr_text = edge.partition("[")
                if attr_text:
                    if not attr_text.endswith("]"):
                        raise TopologyParseException(f"{self.path}:{line_no}: unterminated '['")
                    attr_text = attr_text[:-1]  # drop the closing ']'
                pair = body.split("->")
                if len(pair) != 2:
                    raise TopologyParseException(f"{self.path}:{line_no}: expected 'A -> B'")
                a = pair[0].strip()
                b = pair[1].strip()
                for nid in (a, b):
                    if nid not in seen_nodes:
                        nodes[nid] = TopologyNode(id=nid, x_km=0.0, y_km=0.0)
                        seen_nodes.add(nid)
                length = 0.0
                for attr in attr_text.split(","):
                    attr = attr.strip()
                    if not attr:
                        continue
                    match = _ATTR.match(attr)
                    if match and match.group(1) == "len":
                        length = _finite_float(match.group(2), f"{self.path}:{line_no}: len")
                if length <= 0:
                    raise TopologyParseException(
                        f"{self.path}:{line_no}: edge {a}->{b} needs a positive 'len=' attribute"
                    )
                links.append(TopologyLink(a=a, b=b, length_km=length, alpha_db_km=0.2))
                continue

            if line.endswith(";"):
                nid = line[:-1].strip()
                if nid not in seen_nodes:
                    nodes[nid] = TopologyNode(id=nid, x_km=0.0, y_km=0.0)
                    seen_nodes.add(nid)
                continue

            if line.startswith("node") or line.startswith("edge") or line.startswith("digraph"):
                raise TopologyParseException(
                    f"{self.path}:{line_no}: unsupported statement {line.split()[0]!r}"
                )

        out_nodes: dict[str, TopologyNode] = {}
        for nid, node in nodes.items():
            x = _finite_float(node.x_km, f"{self.path}: node {nid} x_km")
            y = _finite_float(node.y_km, f"{self.path}: node {nid} y_km")
            out_nodes[nid] = TopologyNode(id=nid, x_km=x, y_km=y, t1_s=100.0, t2_s=50.0, is_repeater=False)

        out_links: list[TopologyLink] = []
        for link in links:
            if link.a not in out_nodes or link.b not in out_nodes:
                raise TopologyParseException(
                    f"{self.path}: edge {link.a}->{link.b} references unknown node"
                )
            if link.length_km <= 0:
                raise TopologyParseException(
                    f"{self.path}: edge {link.a}->{link.b} needs 'len=' attribute"
                )
            out_links.append(link)

        return {"nodes": out_nodes, "links": out_links}
