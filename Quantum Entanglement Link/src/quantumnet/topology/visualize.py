"""Visualisation of quantum topologies and routes.

Default output is a dependency-free ASCII map (fidelity heat legend). If
``matplotlib`` happens to be installed it is used for a nicer spatial plot;
this module never requires it.
"""

from __future__ import annotations

import math

from .graph import QuantumTopology
from .routing import Route


def _fidelity_char(f: float) -> str:
    """Map a fidelity to a heat character (0.0 -> dim, 1.0 -> bright)."""
    if f >= 0.95:
        return "#"
    if f >= 0.90:
        return "8"
    if f >= 0.80:
        return "O"
    if f >= 0.65:
        return "o"
    if f >= 0.50:
        return "."
    return " "


def render_topology(topo: QuantumTopology, route: Route | None = None,
                    width: int = 72, height: int = 22) -> str:
    """Render the topology as an ASCII map with a fidelity heat legend.

    ``route`` (optional) highlights the chosen path with ``*`` links.
    """
    if not topo.nodes:
        return "(empty topology)"

    xs = [n.x_km for n in topo.nodes.values()]
    ys = [n.y_km for n in topo.nodes.values()]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(ys), max(ys)
    span_x = max(x1 - x0, 1e-9)
    span_y = max(y1 - y0, 1e-9)

    grid = [[" " for _ in range(width)] for _ in range(height)]
    pos: dict[str, tuple[int, int]] = {}

    for nid, node in topo.nodes.items():
        col = int(round((node.x_km - x0) / span_x * (width - 1)))
        row = int(round((y1 - node.y_km) / span_y * (height - 1)))
        pos[nid] = (col, row)

    # draw links first (under nodes)
    for (a, b), link in topo.links.items():
        if a not in pos or b not in pos:
            continue
        (c1, r1), (c2, r2) = pos[a], pos[b]
        ch = _fidelity_char(link.fidelity())
        route_chars = set()
        if route is not None:
            for u, v in zip(route.path, route.path[1:]):
                route_chars |= {(u, v), (v, u)}
        for t in range(0, 21):
            col = int(round(c1 + (c2 - c1) * t / 20.0))
            row = int(round(r1 + (r2 - r1) * t / 20.0))
            if 0 <= col < width and 0 <= row < height and grid[row][col] == " ":
                if route is not None and (a, b) in route_chars:
                    grid[row][col] = "*"
                else:
                    grid[row][col] = ch

    for nid, (col, row) in pos.items():
        if 0 <= col < width and 0 <= row < height:
            grid[row][col] = "@"

    lines = ["Quantum topology map (x/y in km, @ = node):"]
    lines += ["".join(row) for row in grid]
    lines.append("Legend:  ' ' <0.50   '.' 0.50-0.65   'o' 0.65-0.80   "
                 "'O' 0.80-0.90   '8' 0.90-0.95   '#' >0.95   '*' route")
    if route is not None:
        lines.append("Route:  " + " -> ".join(route.path))
    return "\n".join(lines)


def plot_matplotlib(topo: QuantumTopology, route: Route | None = None,
                    path: str = "topology.png") -> bool:
    """Render with matplotlib if available. Returns False if not installed."""
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except ImportError:
        return False

    fig, ax = plt.subplots(figsize=(8, 6))
    for (a, b), link in topo.links.items():
        na, nb = topo.nodes[a], topo.nodes[b]
        ax.plot([na.x_km, nb.x_km], [na.y_km, nb.y_km],
                color=(1 - link.fidelity(), 0.1, 0.6),
                linewidth=2.5 * max(link.fidelity(), 0.05), zorder=1)
    if route is not None:
        for u, v in zip(route.path, route.path[1:]):
            na, nb = topo.nodes[u], topo.nodes[v]
            ax.plot([na.x_km, nb.x_km], [na.y_km, nb.y_km],
                    color="black", linewidth=3, zorder=2, linestyle="--")
    for nid, node in topo.nodes.items():
        ax.scatter([node.x_km], [node.y_km], s=120, zorder=3,
                   color="darkred" if node.is_repeater else "navy")
        ax.annotate(nid, (node.x_km, node.y_km), textcoords="offset points",
                    xytext=(6, 6), fontsize=8)
    ax.set_title("Quantum Entanglement Topology (fidelity heat)")
    ax.set_xlabel("x [km]")
    ax.set_ylabel("y [km]")
    ax.set_aspect("equal", adjustable="box")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return True


__all__ = ["render_topology", "plot_matplotlib"]
