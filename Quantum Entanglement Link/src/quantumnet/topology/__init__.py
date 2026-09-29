"""Ghost-Net topology layer (Phase 3): quantum network graphs, fidelity
routing, swap scheduling, and visualisation. Pure numpy + physics from
``core.physical`` — no fabricated data.
"""

from .graph import (
    QuantumLink,
    QuantumNode,
    QuantumTopology,
    bell_fidelity_from_depolarizing,
)
from .routing import (
    Route,
    all_simple_paths,
    best_route,
    e2e_fidelity,
    optimal_swap_order,
    rank_routes,
    swapped_fidelity,
)
from .schedule import (
    DistributionResult,
    SwapEvent,
    distribute,
    schedule_fidelity_without_decay,
)
from .visualize import plot_matplotlib, render_topology
from .ghostnet import (
    describe_ghost_result,
    load_ghost_topology,
    parse_positions,
    route_ghost,
)

__all__ = [
    "QuantumLink", "QuantumNode", "QuantumTopology",
    "bell_fidelity_from_depolarizing",
    "Route", "all_simple_paths", "best_route", "e2e_fidelity",
    "optimal_swap_order", "rank_routes", "swapped_fidelity",
    "DistributionResult", "SwapEvent", "distribute",
    "schedule_fidelity_without_decay",
    "plot_matplotlib", "render_topology",
    "describe_ghost_result", "load_ghost_topology", "parse_positions",
    "route_ghost",
]
