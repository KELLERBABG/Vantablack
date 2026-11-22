"""Topology importer registry and data model.

Every topology source in QEL shares this shape, produced by ``parse`` and
consumed by the routing, scheduling and visualisation layers.  Nothing in
routing/schedule/visualise may know *where* a topology came from, only what
it looks like.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


class TopologyParseException(ValueError):
    """Raised by an importer when a topology file cannot be parsed."""


@dataclass
class TopologyImporter:
    """Protocol for anything that turns a file into a topology.

    ``path`` is the caller-supplied file path (used for error messages only).
    ``parse`` returns the canonical shape and must not raise on empty files --
    that is the caller's decision to make.
    """

    path: str

    def parse(self) -> dict:
        raise NotImplementedError


@dataclass
class TopologyNode:
    """Canonical node record produced by every importer."""

    id: str
    x_km: float = 0.0
    y_km: float = 0.0
    t1_s: float = 100.0
    t2_s: float = 50.0
    is_repeater: bool = False


@dataclass
class TopologyLink:
    """Canonical link record produced by every importer."""

    a: str
    b: str
    length_km: float
    alpha_db_km: float = 0.2


@dataclass
class Topology:
    """Canonical topology record produced by every importer."""

    nodes: dict[str, TopologyNode] = field(default_factory=dict)
    links: list[TopologyLink] = field(default_factory=list)

    def add_node(self, node: TopologyNode) -> "Topology":
        self.nodes[node.id] = node
        return self

    def add_link(self, link: TopologyLink) -> "Topology":
        if link.length_km <= 0:
            raise TopologyParseException(
                f"link {link.a}-{link.b} must have positive length"
            )
        self.links.append(link)
        return self

    def neighbors(self, node_id: str) -> list[str]:
        out = []
        for link in self.links:
            if link.a == node_id:
                out.append(link.b)
            elif link.b == node_id:
                out.append(link.a)
        return out

    def link_length(self, a: str, b: str) -> float | None:
        for link in self.links:
            if (link.a == a and link.b == b) or (link.a == b and link.b == a):
                return link.length_km
        return None

    def summary(self) -> str:
        worst = 1.0
        best = 0.0
        return (
            f"Topology: {len(self.nodes)} nodes, {len(self.links)} links "
            f"(range {worst:.3f}-{best:.3f})"
        )
