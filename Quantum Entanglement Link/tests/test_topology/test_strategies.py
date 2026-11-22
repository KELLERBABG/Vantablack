"""Pluggable routing: the interface, the registry, and the measured comparison.

The comparison is the point of this file.  The claim under test is that QEL
routes *better* than a general-purpose simulator, and the incumbent's stock
static routing is Dijkstra on **physical distance**.  That policy is implemented
here as :class:`~quantumnet.topology.strategies.LengthRouting` purely so the
claim can be measured rather than asserted -- and these tests measure it.

A strategy that returns "a route" is not enough.  What has to hold is that the
fidelity-optimal policy is *optimally* optimal (matching brute force), that it
*beats* the control where the control is wrong, and that swapping the policy
requires no change to the caller.
"""

from __future__ import annotations

import itertools

import pytest

from quantumnet.topology.graph import (
    QuantumLink,
    QuantumNode,
    QuantumTopology,
)
from quantumnet.topology.routing import swapped_fidelity
from quantumnet.topology.strategies import (
    FidelityOptimalRouting,
    HopCountRouting,
    LengthRouting,
    RoutingError,
    RoutingStrategy,
    StaticRouting,
    available_strategies,
    compare_instances,
    compare_strategies,
    fidelity_weight,
    hop_weight,
    length_weight,
    make_strategy,
    register_routing,
    route_from_path,
    werner_parameter,
)


def _pinned(a: str, b: str, fidelity: float, length_km: float = 1.0):
    """A link whose fidelity is set directly, bypassing the distance model."""
    link = QuantumLink(a=a, b=b, length_km=length_km)
    link.fidelity = lambda _f=fidelity: _f  # type: ignore[method-assign]
    return link


def _topo(spec: dict, positions: dict | None = None) -> QuantumTopology:
    topo = QuantumTopology()
    names = positions or {n: (float(i), 0.0) for i, n in enumerate(
        sorted({x for pair in spec for x in pair}))}
    for name, (x, y) in names.items():
        topo.add_node(QuantumNode(node_id=name, x_km=x, y_km=y))
    for (a, b), fidelity in spec.items():
        length = abs(names[a][0] - names[b][0])
        topo.add_link(_pinned(a, b, fidelity, length_km=length or 1.0))
    return topo


# ---------------------------------------------------------------------------
# Edge weights
# ---------------------------------------------------------------------------

def test_werner_parameter_matches_the_composition_algebra():
    for f in (0.25, 0.5, 0.75, 1.0):
        assert werner_parameter(f) == pytest.approx((4 * f - 1) / 3)


def test_fidelity_weight_is_minus_log_werner_parameter():
    import math
    for f in (0.9, 0.7, 0.5):
        assert fidelity_weight(_pinned("a", "b", f)) == pytest.approx(
            -math.log((4 * f - 1) / 3))


def test_fidelity_weight_is_infinite_at_or_below_the_classical_limit():
    import math
    for f in (0.25, 0.1, 0.0):
        assert fidelity_weight(_pinned("a", "b", f)) == math.inf


def test_fidelity_weights_are_additive_where_fidelities_are_not():
    """The property the optimal strategy depends on.

    ``-log W`` sums along a path; ``-log F`` does not.  If this ever fails, the
    optimality guarantee is void.
    """
    import math
    fids = [0.9, 0.8, 0.7]
    weights = [_pinned("a", "b", f) for f in fids]
    total = sum(fidelity_weight(link) for link in weights)

    w = 1.0
    for f in fids:
        w *= (4 * f - 1) / 3
    assert total == pytest.approx(-math.log(w))

    acc = fids[0]
    for f in fids[1:]:
        acc = swapped_fidelity(acc, f)
    assert (1 + 3 * math.exp(-total)) / 4 == pytest.approx(acc)


def test_length_and_hop_weights_are_what_they_say():
    link = _pinned("a", "b", 0.9, length_km=42.0)
    assert length_weight(link) == 42.0
    assert hop_weight(link) == 1.0


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

def test_the_expected_strategies_are_registered():
    names = available_strategies()
    for expected in ("fidelity-optimal", "shortest-distance", "fewest-hops",
                     "static"):
        assert expected in names


def test_unknown_strategy_raises_with_the_available_list():
    with pytest.raises(RoutingError, match="unknown routing strategy"):
        make_strategy("no-such-policy")


def test_make_strategy_returns_the_right_class():
    assert isinstance(make_strategy("fidelity-optimal"), FidelityOptimalRouting)
    assert isinstance(make_strategy("shortest-distance"), LengthRouting)
    assert isinstance(make_strategy("fewest-hops"), HopCountRouting)
    assert isinstance(make_strategy("static"), StaticRouting)


def test_a_third_party_can_register_a_strategy_without_editing_the_module():
    """The substitutability requirement, tested by actually substituting."""
    @register_routing("test-always-longest")
    class _LongestPath(RoutingStrategy):
        name = "test-always-longest"

        def _select(self, topology, src, dst):
            best = None
            for length in range(1, len(topology.nodes)):
                for mid in itertools.permutations(
                        [n for n in topology.nodes if n not in (src, dst)],
                        length - 1):
                    path = [src, *mid, dst]
                    if all(topology.link(a, b) is not None
                           for a, b in zip(path, path[1:])):
                        if best is None or len(path) > len(best):
                            best = path
            return best

    try:
        assert "test-always-longest" in available_strategies()
        topo = _topo({("A", "B"): 0.99, ("B", "C"): 0.99, ("A", "C"): 0.99})
        route = make_strategy("test-always-longest").select(topo, "A", "C")
        assert route.path == ["A", "B", "C"]
    finally:
        # leave the registry as we found it
        from quantumnet.topology import strategies as mod
        mod._REGISTRY.pop("test-always-longest", None)


# ---------------------------------------------------------------------------
# The strategies return usable routes
# ---------------------------------------------------------------------------

def _chain_topology(n: int = 5) -> QuantumTopology:
    topo = QuantumTopology()
    for i in range(n):
        topo.add_node(QuantumNode(node_id=f"N{i}", x_km=i * 10.0, y_km=0.0))
    for i in range(n - 1):
        topo.add_link(_pinned(f"N{i}", f"N{i+1}", 0.9, length_km=10.0))
    return topo


@pytest.mark.parametrize("name", ["fidelity-optimal", "shortest-distance",
                                  "fewest-hops"])
def test_every_strategy_returns_a_route_with_consistent_fidelity(name):
    topo = _chain_topology()
    route = make_strategy(name).select(topo, "N0", "N4")
    assert route is not None
    assert route.path[0] == "N0" and route.path[-1] == "N4"
    # the reported fidelity must match an independent recomputation
    expected = route_from_path(topo, route.path).e2e_fidelity
    assert route.e2e_fidelity == pytest.approx(expected, rel=1e-12)


def test_unreachable_destination_returns_none_not_a_guess():
    topo = QuantumTopology()
    for name in ("A", "B", "C"):
        topo.add_node(QuantumNode(node_id=name, x_km=0.0))
    topo.add_link(_pinned("A", "B", 0.9))
    route = FidelityOptimalRouting().select(topo, "A", "C")
    assert route is None


def test_missing_node_returns_none():
    topo = _chain_topology(2)
    assert FidelityOptimalRouting().select(topo, "N0", "nope") is None
    assert FidelityOptimalRouting().select(topo, "N0", "N0") is None


def test_a_link_below_the_classical_limit_is_never_used():
    """F <= 1/4 cannot carry entanglement, so it must be excluded entirely."""
    topo = QuantumTopology()
    for i, name in enumerate(("A", "B", "C")):
        topo.add_node(QuantumNode(node_id=name, x_km=float(i) * 10))
    topo.add_link(_pinned("A", "B", 0.20, length_km=10.0))   # unusable
    topo.add_link(_pinned("B", "C", 0.99, length_km=10.0))
    topo.add_link(_pinned("A", "C", 0.95, length_km=20.0))
    route = FidelityOptimalRouting().select(topo, "A", "C")
    assert route.path == ["A", "C"], "routed through a link that cannot work"


def test_hop_count_strategy_really_minimises_hops():
    topo = _topo({("A", "B"): 0.99, ("B", "C"): 0.99, ("A", "C"): 0.60})
    route = HopCountRouting().select(topo, "A", "C")
    assert route.hops == 1


# ---------------------------------------------------------------------------
# Optimality: measured against brute force
# ---------------------------------------------------------------------------

def _brute_force_best(topo, src, dst, max_hops=6):
    best_f, best_path = -1.0, None
    others = [n for n in topo.nodes if n not in (src, dst)]
    for length in range(1, max_hops + 1):
        for mid in itertools.permutations(others, length - 1):
            path = [src, *mid, dst]
            fids, ok = [], True
            for a, b in zip(path, path[1:]):
                link = topo.link(a, b)
                if link is None:
                    ok = False
                    break
                fids.append(link.fidelity())
            if not ok:
                continue
            w = 1.0
            for f in fids:
                w *= (4 * f - 1) / 3
            f = (1 + 3 * w) / 4
            if f > best_f:
                best_f, best_path = f, path
    return best_f, best_path


@pytest.mark.parametrize("seed", range(8))
def test_fidelity_optimal_matches_brute_force_on_random_graphs(seed):
    import numpy as np
    rng = np.random.default_rng(seed)
    names = [f"N{i}" for i in range(6)]
    spec = {}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if rng.random() < 0.5:
                spec[(a, b)] = float(rng.uniform(0.55, 1.0))
    topo = _topo(spec, {n: (float(i) * 10, 0.0) for i, n in enumerate(names)})
    if not topo.links:
        pytest.skip("no links drawn")

    best_f, _ = _brute_force_best(topo, "N0", "N5")
    if best_f <= 0:
        pytest.skip("no path in this random graph")
    route = FidelityOptimalRouting().select(topo, "N0", "N5")
    assert route is not None
    assert route.e2e_fidelity == pytest.approx(best_f, abs=1e-9)


# ---------------------------------------------------------------------------
# The measured comparison: optimal against the incumbent's policy
# ---------------------------------------------------------------------------

def test_fidelity_optimal_beats_shortest_distance_where_they_diverge():
    """The claim under test, measured.

    A short mediocre span competes with three short good ones.  Distance
    minimisation takes the single hop; fidelity minimisation takes the detour,
    and delivers materially more fidelity.
    """
    topo = _topo(
        {("A", "D"): 0.70,
         ("A", "B"): 0.99, ("B", "C"): 0.99, ("C", "D"): 0.99},
        {"A": (0.0, 0.0), "B": (10.0, 0.0), "C": (20.0, 0.0), "D": (30.0, 0.0)},
    )
    comparison = compare_strategies(topo, "A", "D")

    best = comparison.fidelity("fidelity-optimal")
    control = comparison.fidelity("shortest-distance")
    assert best > control
    assert control == pytest.approx(0.70, rel=1e-9)
    assert comparison.best_name == "fidelity-optimal"
    # the control took the direct hop; the optimal policy did not
    assert comparison.results["shortest-distance"].hops == 1
    assert comparison.results["fidelity-optimal"].hops > 1


def test_shortest_distance_can_be_wrong_by_a_large_margin():
    """Quantify it, because "better" without a number is not a claim."""
    topo = _topo(
        {("A", "D"): 0.60,
         ("A", "B"): 0.999, ("B", "C"): 0.999, ("C", "D"): 0.999},
        {"A": (0.0, 0.0), "B": (5.0, 0.0), "C": (10.0, 0.0), "D": (100.0, 0.0)},
    )
    comparison = compare_strategies(topo, "A", "D")
    best = comparison.fidelity("fidelity-optimal")
    control = comparison.fidelity("shortest-distance")
    assert best - control > 0.3, f"gap only {best - control}"


def test_fewest_hops_agrees_with_shortest_distance_on_unit_lengths():
    """A sanity check on the control: on equal-length links they coincide."""
    topo = _chain_topology(5)
    hops = HopCountRouting().select(topo, "N0", "N4")
    length = LengthRouting().select(topo, "N0", "N4")
    assert hops.path == length.path


def test_the_comparison_reports_every_strategy_it_was_asked_for():
    topo = _chain_topology(4)
    comparison = compare_strategies(topo, "N0", "N3")
    assert set(comparison.results) == {"fidelity-optimal", "shortest-distance",
                                       "fewest-hops"}
    assert "best:" in comparison.describe()


def test_compare_instances_accepts_arbitrary_strategies():
    """Needed because a configured static table cannot be named."""
    topo = _topo({("A", "B"): 0.9, ("B", "C"): 0.9, ("A", "C"): 0.8},
                 {"A": (0.0, 0.0), "B": (10.0, 0.0), "C": (20.0, 0.0)})
    static = StaticRouting(table={"A->C": "B", "B->C": "C"})
    comparison = compare_instances(topo, "A", "C", [
        ("optimal", FidelityOptimalRouting()),
        ("hand-planned", static),
    ])
    assert comparison.results["hand-planned"].path == ["A", "B", "C"]
    assert comparison.best_name in ("optimal", "hand-planned")


# ---------------------------------------------------------------------------
# Static routing
# ---------------------------------------------------------------------------

def test_static_routing_follows_its_table():
    topo = _topo({("A", "B"): 0.9, ("B", "C"): 0.9, ("A", "C"): 0.9},
                 {"A": (0.0, 0.0), "B": (10.0, 0.0), "C": (20.0, 0.0)})
    strategy = StaticRouting(table={"A->C": "B", "B->C": "C"})
    assert strategy.select(topo, "A", "C").path == ["A", "B", "C"]


def test_static_routing_returns_none_when_its_table_is_silent():
    topo = _chain_topology(3)
    assert StaticRouting(table={}).select(topo, "N0", "N2") is None


def test_static_routing_detects_a_loop_rather_than_hanging():
    """A misconfigured table must fail, not spin."""
    topo = _chain_topology(3)
    strategy = StaticRouting(table={"N0->N2": "N1", "N1->N2": "N0"})
    assert strategy.select(topo, "N0", "N2") is None


def test_static_routing_rejects_a_hop_to_an_unknown_node():
    topo = _chain_topology(3)
    strategy = StaticRouting(table={"N0->N2": "ghost"})
    assert strategy.select(topo, "N0", "N2") is None


# ---------------------------------------------------------------------------
# Forwarding tables
# ---------------------------------------------------------------------------

def test_forwarding_table_covers_every_reachable_pair():
    topo = _chain_topology(4)
    table = FidelityOptimalRouting().forwarding_table(topo)
    for src in topo.nodes:
        for dst in topo.nodes:
            if src == dst:
                continue
            assert f"{src}->{dst}" in table


def test_forwarding_table_next_hop_is_on_the_chosen_path():
    topo = _chain_topology(4)
    strategy = FidelityOptimalRouting()
    table = strategy.forwarding_table(topo)
    route = strategy.select(topo, "N0", "N3")
    assert table["N0->N3"] == route.path[1]


def test_forwarding_table_omits_unreachable_destinations():
    """A missing key says "no route"; a placeholder would look like a route."""
    topo = QuantumTopology()
    for name in ("A", "B", "C", "D"):
        topo.add_node(QuantumNode(node_id=name, x_km=0.0))
    topo.add_link(_pinned("A", "B", 0.9))
    topo.add_link(_pinned("C", "D", 0.9))
    table = FidelityOptimalRouting().forwarding_table(topo)
    assert "A->B" in table
    assert "A->D" not in table


# ---------------------------------------------------------------------------
# route_from_path
# ---------------------------------------------------------------------------

def test_route_from_path_rejects_a_nonexistent_link():
    topo = _chain_topology(3)
    with pytest.raises(RoutingError, match="non-existent link"):
        route_from_path(topo, ["N0", "N2"])


def test_route_from_path_computes_the_swap_order():
    topo = _chain_topology(4)
    route = route_from_path(topo, ["N0", "N1", "N2", "N3"])
    assert route.link_fidelities == [pytest.approx(0.9)] * 3
    assert route.swap_order  # a non-empty fusion order


def test_single_hop_path_has_no_swaps():
    topo = _chain_topology(2)
    route = route_from_path(topo, ["N0", "N1"])
    assert route.hops == 1
    assert route.swap_order == []
    assert route.e2e_fidelity == pytest.approx(0.9)
