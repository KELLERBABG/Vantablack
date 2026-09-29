"""Ghost-Net bridge: import a live Global Ghost Net topology and route
quantum entanglement paths over it.

The Rust ``vantablack`` daemon exports its real mesh state with the CLI
command ``EXPORTTOPOLOGY <file.json>``::

    {
      "generator": "vantablack",
      "exported_at": "...",
      "nodes": [{"fingerprint": "...", "addr": "127.0.0.1:15252"}],
      "links":  [{"a": "<fp>", "b": "<fp>"}]
    }

This module turns that export into a :class:`QuantumTopology`. Node positions
may be embedded in the export ("x_km"/"y_km" per node, or a "positions"
object) or supplied via ``--positions "fp=x,y ..."``.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from .graph import DEFAULT_ALPHA_DB_KM, QuantumLink, QuantumNode, QuantumTopology
from .routing import Route, best_route, rank_routes
from .schedule import DistributionResult, distribute
from .visualize import render_topology

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


def _reject_constants(s: str):
    """Reject NaN/Infinity in untrusted JSON (they silently poison math)."""
    raise ValueError(f"non-finite constant {s!r} in topology JSON")


def _finite_float(v, what: str) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{what}: expected a number, got {v!r}") from e
    if not math.isfinite(f):
        raise ValueError(f"{what}: must be finite, got {v!r}")
    return f


def load_ghost_topology(path: str | Path,
                        positions: dict[str, tuple[float, float]] | None = None,
                        alpha_db_km: float = DEFAULT_ALPHA_DB_KM,
                        ) -> QuantumTopology:
    """Build a :class:`QuantumTopology` from a vantablack export file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"),
                      parse_constant=_reject_constants)
    if data.get("generator") != "vantablack":
        raise ValueError(
            f"{path}: not a vantablack topology export "
            f"(generator={data.get('generator')!r})"
        )
    if not isinstance(data.get("nodes"), list) or not isinstance(data.get("links"), list):
        raise ValueError(f"{path}: topology JSON must contain 'nodes' and 'links' arrays")
    positions = dict(positions or {})
    # embedded positions (per-node x_km/y_km, or a top-level "positions" map)
    embedded = data.get("positions") or {}
    for node in data.get("nodes", []):
        if not isinstance(node, dict):
            raise ValueError(f"{path}: node entry is not an object: {node!r}")
        fp = node.get("fingerprint") or node.get("id")
        if not fp:
            continue
        if "x_km" in node and "y_km" in node:
            embedded.setdefault(fp, (_finite_float(node["x_km"], f"node {fp} x_km"),
                                     _finite_float(node["y_km"], f"node {fp} y_km")))
    for fp, xy in embedded.items():
        if not (isinstance(xy, (list, tuple)) and len(xy) == 2):
            raise ValueError(f"positions[{fp!r}]: expected [x, y], got {xy!r}")
        positions.setdefault(fp, (_finite_float(xy[0], f"positions[{fp}] x"),
                                  _finite_float(xy[1], f"positions[{fp}] y")))

    topo = QuantumTopology()
    for node in data.get("nodes", []):
        fp = node.get("fingerprint") or node.get("id")
        if not fp:
            continue
        x, y = positions.get(fp, (0.0, 0.0))
        topo.add_node(QuantumNode(node_id=fp, x_km=x, y_km=y))
    for link in data.get("links", []):
        if not isinstance(link, dict):
            raise ValueError(f"{path}: link entry is not an object: {link!r}")
        a, b = link.get("a"), link.get("b")
        if not isinstance(a, str) or not isinstance(b, str):
            raise ValueError(f"{path}: link endpoints must be strings, got {link!r}")
        if not a or not b or a not in topo.nodes or b not in topo.nodes:
            continue
        na, nb = topo.nodes[a], topo.nodes[b]
        length = link.get("length_km")
        if length is None:
            length = na.distance_to(nb)
        length = _finite_float(length, f"link {a}->{b} length_km")
        if length <= 0:
            continue  # co-located nodes: no optical link
        topo.add_link(QuantumLink(a=a, b=b, length_km=length,
                                  alpha_db_km=alpha_db_km))
    return topo


def route_ghost(path: str | Path,
                from_fp: str, to_fp: str,
                positions: dict[str, tuple[float, float]] | None = None,
                min_fidelity: float = 0.0,
                max_hops: int = 6) -> tuple[QuantumTopology, Route | None,
                                            DistributionResult | None]:
    """Load a Ghost-Net export, find the best quantum route, schedule it.

    Returns ``(topology, best_route, distribution)``; ``best_route`` is None
    if no path meets ``min_fidelity``.
    """
    topo = load_ghost_topology(path, positions=positions)
    if from_fp not in topo.nodes:
        raise KeyError(f"from fingerprint {from_fp} not in topology "
                       f"(have {sorted(topo.nodes)[:8]}{'...' if len(topo.nodes) > 8 else ''})")
    if to_fp not in topo.nodes:
        raise KeyError(f"to fingerprint {to_fp} not in topology")
    route = best_route(topo, from_fp, to_fp,
                       max_hops=max_hops, min_fidelity=min_fidelity)
    if route is None:
        return topo, None, None
    dist = distribute(topo, route)
    return topo, route, dist


def describe_ghost_result(topo: QuantumTopology,
                          route: Route | None,
                          dist: DistributionResult | None) -> str:
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


__all__ = [
    "load_ghost_topology", "route_ghost", "describe_ghost_result",
    "parse_positions", "GHOST_TOPOLOGY_SCHEMA_VERSION",
]
