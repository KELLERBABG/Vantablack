"""Ghost-Net topology layer (Phase 3): quantum network graphs, fidelity
routing, swap scheduling, and visualisation. Pure numpy + physics from
``core.physical``: no fabricated data.
"""

from .graph import (
    QuantumLink,
    QuantumNode,
    QuantumTopology,
    bell_fidelity_from_depolarizing,
)
from .importers import parse as load_topology
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
from .events import EventChainResult, distribute_events
from .resources import (
    NodeEntanglementManager,
    Reservation,
    ReservationState,
    ResourceError,
    ResourceManager,
    resolve_contention,
)
from .visualize import plot_matplotlib, render_topology
from .strategies import (
    FidelityOptimalRouting,
    HopCountRouting,
    LengthRouting,
    RoutingError,
    RoutingStrategy,
    StaticRouting,
    StrategyComparison,
    available_strategies,
    compare_instances,
    compare_strategies,
    fidelity_weight,
    make_strategy,
    register_routing,
    route_from_path,
    route_with,
    werner_parameter,
)
from .shapes import (
    TOPOLOGY_BUILDERS,
    bcube,
    build_topology,
    fat_tree,
    topology_report,
)
from .ghostnet import (
    describe_ghost_result,
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
    "EventChainResult", "distribute_events",
    "NodeEntanglementManager", "Reservation", "ReservationState",
    "ResourceError", "ResourceManager", "resolve_contention",
    "FidelityOptimalRouting", "HopCountRouting", "LengthRouting",
    "RoutingError", "RoutingStrategy", "StaticRouting",
    "StrategyComparison", "available_strategies", "compare_instances",
    "compare_strategies", "fidelity_weight", "make_strategy",
    "register_routing", "route_from_path", "route_with", "werner_parameter",
    "TOPOLOGY_BUILDERS", "bcube", "build_topology", "fat_tree",
    "topology_report",
    "plot_matplotlib", "render_topology",
    "describe_ghost_result", "parse_positions", "route_ghost",
]
