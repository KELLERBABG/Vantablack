"""Multi-commodity routing under contention.

M3 already models contention, but there the route is chosen *before* contention
is considered and the only question is whether the demand is accepted.  These
tests cover the case that matters operationally: several commodities in flight,
where the path a commodity should take depends on what the others are already
using.

The claim under test is narrow and falsifiable: **congestion-aware routing grants
at least as much demand as congestion-blind routing on identical input, and
strictly more when the topology forces a choice.** Both strategies share the same
capacity model and the same commodity order, so the difference is attributable to
the routing score alone.
"""

from __future__ import annotations

import pytest

from quantumnet.topology.commodities import (
    Commodity,
    CommodityError,
    MultiCommodityPlan,
    _k_shortest_paths,
    _path_congestion,
    compare_routing_strategies,
    plan_commodities,
)
from quantumnet.topology.graph import QuantumLink, QuantumNode, QuantumTopology


def hub_topology(alternatives: int = 3, commodities: int = 5) -> QuantumTopology:
    """Sources share one hub; ``alternatives`` of them have a longer bypass.

    Built so congestion is forced to matter: the hub is on everybody's shortest
    path, and only some commodities can avoid it.
    """
    topology = QuantumTopology()
    names = [f"S{i}" for i in range(1, commodities + 1)]
    names += [f"T{i}" for i in range(1, commodities + 1)]
    names += ["HUB"] + [f"M{i}" for i in range(1, alternatives + 1)]
    for name in names:
        topology.add_node(QuantumNode(node_id=name))

    edges = []
    for i in range(1, commodities + 1):
        edges.append((f"S{i}", "HUB"))
        edges.append(("HUB", f"T{i}"))
    for i in range(1, alternatives + 1):
        edges.append((f"S{i}", f"M{i}"))
        edges.append((f"M{i}", f"T{i}"))
    for a, b in edges:
        topology.add_link(QuantumLink(a=a, b=b, length_km=10.0))
    return topology


def commodities(n: int = 5) -> list[Commodity]:
    return [Commodity(f"c{i}", f"S{i}", f"T{i}") for i in range(1, n + 1)]


# ---------------------------------------------------------------------------
# Commodity validation
# ---------------------------------------------------------------------------

def test_a_commodity_needs_at_least_one_unit():
    with pytest.raises(CommodityError, match="at least one unit"):
        Commodity("c", "A", "B", units=0)


def test_an_unknown_strategy_is_rejected():
    with pytest.raises(CommodityError, match="strategy must be"):
        plan_commodities(hub_topology(), commodities(), strategy="magic")


def test_a_bad_capacity_is_rejected():
    with pytest.raises(CommodityError, match="capacity must be at least 1"):
        plan_commodities(hub_topology(), commodities(), capacity=0)


# ---------------------------------------------------------------------------
# Path enumeration
# ---------------------------------------------------------------------------

def test_paths_are_returned_shortest_first():
    topology = hub_topology()
    paths = _k_shortest_paths(topology, "S1", "T1")
    assert paths
    lengths = [len(p) for p in paths]
    assert lengths == sorted(lengths)


def test_paths_are_simple():
    """No repeated nodes: a route that revisits a node is not a route."""
    topology = hub_topology()
    for path in _k_shortest_paths(topology, "S1", "T1"):
        assert len(set(path)) == len(path)


def test_a_node_is_its_own_trivial_path():
    assert _k_shortest_paths(hub_topology(), "S1", "S1") == [("S1",)]


def test_no_path_between_disconnected_nodes():
    topology = QuantumTopology()
    topology.add_node(QuantumNode(node_id="A"))
    topology.add_node(QuantumNode(node_id="B"))
    assert _k_shortest_paths(topology, "A", "B") == []


# ---------------------------------------------------------------------------
# The congestion cost
# ---------------------------------------------------------------------------

def test_an_empty_path_costs_hop_count_plus_its_own_load():
    """No *pre-existing* load, but the commodity itself still occupies a slot.

    At capacity 1 a single unit fills the intermediate node, so the penalty is
    legitimately nonzero -- the cost is about the load the path would *carry*, not
    about what was already there.  An earlier version added a constant penalty to
    every node including empty ones, which cancelled between alternatives and made
    the router behave exactly like the congestion-blind one.
    """
    # one intermediate node, full at capacity 1 -> hop cost 2 + 4.0
    assert _path_congestion(("A", "B", "C"), {}, 1) == pytest.approx(6.0)
    # room to spare -> much smaller penalty
    assert _path_congestion(("A", "B", "C"), {}, 10) == pytest.approx(2.04)
    # a direct edge has no intermediate node at all
    assert _path_congestion(("A", "B"), {}, 1) == pytest.approx(1.0)


def test_cost_rises_with_the_load_it_would_add():
    empty = _path_congestion(("A", "B", "C"), {}, 2)
    loaded = _path_congestion(("A", "B", "C"), {"B": 1}, 2)
    assert loaded > empty


def test_cost_is_independent_of_load_on_the_endpoints():
    """Only intermediate nodes hold a pair; the endpoints are the users."""
    with_load = _path_congestion(("A", "B", "C"), {"A": 5, "C": 5}, 10)
    without = _path_congestion(("A", "B", "C"), {}, 10)
    assert with_load == pytest.approx(without)


def test_a_loaded_longer_path_can_cost_more_than_a_clean_shorter_one():
    short_jammed = _path_congestion(("A", "X", "B"), {"X": 10}, 10)
    long_clean = _path_congestion(("A", "Y", "Z", "B"), {}, 10)
    assert short_jammed > long_clean


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------

def test_capacity_is_never_exceeded():
    """The invariant that a cheating baseline violated first time round.

    An earlier version of the blind strategy granted past capacity, which made it
    look *better* than the aware one; the whole advantage was an accounting
    artifact.  This asserts the limit directly for both strategies.
    """
    topology = hub_topology()
    for capacity in (1, 2, 3):
        for strategy in ("congestion-aware", "shortest-path"):
            plan = plan_commodities(topology, commodities(), capacity=capacity,
                                    strategy=strategy)
            for node, load in plan.node_load().items():
                assert load <= capacity, (
                    f"{strategy} put {load} units on {node} with capacity "
                    f"{capacity}"
                )


def test_an_unknown_endpoint_is_refused_with_a_reason():
    topology = hub_topology()
    plan = plan_commodities(topology, [Commodity("c", "S1", "NOPE")])
    assert len(plan.refused) == 1
    assert "NOPE" in (plan.refused[0].reason or "")


def test_every_commodity_appears_exactly_once():
    """A commodity silently dropped is a plan that looks better than it is."""
    plan = plan_commodities(hub_topology(), commodities())
    assert len(plan.routes) == 5
    assert {r.commodity.name for r in plan.routes} == {f"c{i}"
                                                       for i in range(1, 6)}


def test_units_granted_plus_refused_equals_requested():
    plan = plan_commodities(hub_topology(), commodities())
    refused_units = sum(r.commodity.units for r in plan.refused)
    assert plan.units_granted + refused_units == plan.units_requested


def test_a_plan_is_deterministic():
    topology = hub_topology()
    first = plan_commodities(topology, commodities())
    second = plan_commodities(topology, commodities())
    assert [(r.commodity.name, r.path, r.granted) for r in first.routes] == \
           [(r.commodity.name, r.path, r.granted) for r in second.routes]


# ---------------------------------------------------------------------------
# The milestone claim
# ---------------------------------------------------------------------------

def test_congestion_aware_never_grants_less_than_blind():
    """The core claim, checked across capacities rather than at one point."""
    topology = hub_topology()
    for capacity in (1, 2, 3, 4, 5):
        result = compare_routing_strategies(topology, commodities(),
                                            capacity=capacity)
        assert result["advantage_units"] >= 0, (
            f"capacity {capacity}: aware granted {result['units_aware']} but "
            f"blind granted {result['units_blind']}"
        )


def test_congestion_aware_grants_strictly_more_where_it_must():
    """At capacity 3 the aware strategy fits all five and blind fits three.

    This is the regime the milestone is about: the hub cannot hold everything,
    the bypasses can, and only a router that looks at load will use them.
    """
    result = compare_routing_strategies(hub_topology(), commodities(),
                                        capacity=3)
    assert result["units_aware"] == 5
    assert result["units_blind"] == 3
    assert result["advantage_units"] == 2


def test_congestion_aware_spreads_load_where_blind_concentrates_it():
    """The mechanism, not just the outcome.

    With capacity large enough that nothing is refused, the two strategies grant
    the same units -- and the difference is where the load went.  Asserting the
    outcome alone would miss this, so the load is asserted directly.
    """
    result = compare_routing_strategies(hub_topology(), commodities(),
                                        capacity=10)
    assert result["units_aware"] == result["units_blind"]
    assert result["max_node_load_aware"] < result["max_node_load_blind"]


def test_the_strategies_agree_when_capacity_is_effectively_unlimited():
    """A difference that persists with no constraint would be a bug."""
    result = compare_routing_strategies(hub_topology(), commodities(),
                                        capacity=1000)
    assert result["units_aware"] == result["units_blind"] == 5
    assert result["hops_aware"] == result["hops_blind"]


def test_comparison_reports_both_raw_plans():
    """A summary alone cannot be checked; the plans must come back too."""
    result = compare_routing_strategies(hub_topology(), commodities(),
                                        capacity=2)
    assert isinstance(result["aware"], MultiCommodityPlan)
    assert isinstance(result["blind"], MultiCommodityPlan)
    assert result["units_aware"] == result["aware"].units_granted
    assert result["units_blind"] == result["blind"].units_granted


def test_plan_describe_names_the_strategy_and_the_load():
    text = plan_commodities(hub_topology(), commodities()).describe()
    assert "congestion-aware" in text
    assert "intermediate load" in text


def test_route_describe_covers_refusals():
    topology = hub_topology()
    plan = plan_commodities(topology, [Commodity("c", "S1", "NOPE")])
    assert "REFUSED" in plan.refused[0].describe()
