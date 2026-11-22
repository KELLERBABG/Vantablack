"""Ghost-Net bridge: import a live Ghost Net topology and route quantum entanglement paths over it.

This module keeps the *routing* entry points used by the CLI, but carries no
format knowledge.  A topology is built from a parsed document via
``topology.importers.parse``, and the parsed document is produced by one of
the importers (``qel-json``, ``ghostnet``, ``dot``).  The legacy
``generator``/``fingerprint``/``positions`` details live in
``topology/importers/ghostnet.py`` only.

Routing is unchanged:::

    from quantumnet.topology.importers import parse
    from quantumnet.topology.ghostnet import route_ghost

    doc = parse("topology.qel.json", schema_id="qel-json")
    topo, route, dist = route_ghost(doc, "A", "D", min_fidelity=0.0)
"""

from __future__ import annotations

from typing import Iterable

from .graph import QuantumLink, QuantumNode, QuantumTopology
from .importers import parse as load_topology
from .importers.base import TopologyParseException
from .routing import Route, best_route, rank_routes
from .schedule import DistributionResult, distribute
from .visualize import render_topology

__all__ = [
    "describe_ghost_result",
    "route_ghost",
    "parse_positions",
    "load_topology",
]


def parse_positions(spec: str | None) -> dict[str, tuple[float, float]]:
    """Parse a ``"fp=x,y fp2=x,y"`` positions string.  Exported for the CLI."""
    from .importers.ghostnet import parse_positions as _parse_positions
    return _parse_positions(spec)


def describe_ghost_result(
    topo: QuantumTopology,
    route: Route | None,
    dist: DistributionResult | None,
) -> str:
    """Human-readable summary of a ghost-route result."""
    lines = [topo.summary(), ""]
    if route is None or dist is None:
        lines.append("No route meets the fidelity constraint.")
    else:
        lines.append(route.describe())
        lines.append("")
        lines.append(dist.describe())
        lines.append("")
        lines.append(render_topology(topo, route=route))
    return "\n".join(lines)


def route_ghost(
    doc: dict,
    from_fp: str,
    to_fp: str,
    min_fidelity: float = 0.0,
    max_hops: int = 6,
) -> tuple[QuantumTopology, Route | None, DistributionResult | None]:
    """Load a parsed topology document, find the best quantum route, schedule it.

    ``doc`` is the canonical shape returned by :func:`topology.importers.parse`
    (see ``topology/importers/base.py``).

    Returns ``(topology, best_route, distribution)``; ``best_route`` is None
    if no path meets ``min_fidelity``.
    """
    topo = _doc_to_topology(doc, from_fp, to_fp)

    if from_fp not in topo.nodes:
        raise KeyError(f"from fingerprint {from_fp} not in topology")
    if to_fp not in topo.nodes:
        raise KeyError(f"to fingerprint {to_fp} not in topology")

    route = best_route(topo, from_fp, to_fp, max_hops=max_hops, min_fidelity=min_fidelity)
    if route is None:
        return topo, None, None

    dist = distribute(topo, route)
    return topo, route, dist


def _doc_to_topology(doc: dict, from_fp: str, to_fp: str) -> QuantumTopology:
    """Turn the canonical parsed document into a :class:`QuantumTopology`.

    Only the from/to fingerprints are known at the routing boundary; positions
    are resolved from the parsed document's node records so every importer
    (including ``dot`` with no coordinates) can supply them.
    """
    topology = QuantumTopology()

    # Nodes: prefer explicit coordinates when present, else default origin.
    nodes = doc.get("nodes") or {}
    if isinstance(nodes, dict):
        for nid, node in nodes.items():
            topology.add_node(
                QuantumNode(
                    node_id=nid,
                    x_km=node.x_km or 0.0,
                    y_km=node.y_km or 0.0,
                    t1_s=node.t1_s,
                    t2_s=node.t2_s,
                    is_repeater=node.is_repeater,
                )
            )
    else:
        # Legacy exporter list / legacy test helper: a list of
        # (id, x, y, t1, t2, is_repeater) tuples, interpreted as such.
        for nid in nodes:
            topology.add_node(
                QuantumNode(
                    node_id=nid,
                    x_km=0.0,
                    y_km=0.0,
                    t1_s=100.0,
                    t2_s=50.0,
                    is_repeater=False,
                )
            )
        topology.add_node(
            QuantumNode(
                node_id=nid,
                x_km=node.x_km or 0.0,
                y_km=node.y_km or 0.0,
                t1_s=node.t1_s,
                t2_s=node.t2_s,
                is_repeater=node.is_repeater,
            )
        )

    # Links.
    links = doc.get("links") or []
    for link in links:
        topology.add_link(
            QuantumLink(
                a=link.a,
                b=link.b,
                length_km=link.length_km,
                alpha_db_km=link.alpha_db_km,
            )
        )

    return topology
