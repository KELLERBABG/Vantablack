"""Space-time decoder correctness, by single-error injection.

A single X error on a data qubit flips exactly the Z-checks containing it, and the
decoder must repair it for the minimum cost: **one** correction, plus a logical
flip **if and only if** the qubit lies on the logical operator.

Both halves matter, and the second is easy to get backwards.  An earlier version
of this test counted *every* logical flip as a failure and so reported the decoder
broken while it was in fact correct: a single X error on a qubit belonging to
`logical_z()` is repaired by an X on that same qubit, which anticommutes with the
logical Z operator and therefore legitimately flips it.  The expected number of
flips is exactly the weight of the logical operator, `d`.

This is the test that localises a defect: if it passes for every qubit in every
layer, then neither the graph nor the matcher is responsible for any
anti-scaling seen in aggregate statistics.
"""

from __future__ import annotations

import pytest

from quantumnet.core.surface_code import (
    RotatedSurfaceCode,
    decode_space_time_greedy,
    matching_graph,
)


@pytest.mark.parametrize("distance", [3, 5])
def test_a_single_data_error_costs_exactly_one_correction(distance):
    """The minimum possible repair, in every layer.

    One correction per error is the signature of a correct space-time graph: the
    error is diagnosed as a data error rather than as an isolated event matched
    across the code, which would cost many edges.
    """
    code = RotatedSurfaceCode(distance)
    single = matching_graph(code, "Z")
    for data in sorted(set(single["edges"].values())):
        fired = {n for (a, b), d in single["edges"].items() if d == data
                 for n in (a, b) if n > 0}
        assert fired, f"data qubit {data} flips no check"
        for rnd in range(distance):
            result = decode_space_time_greedy(code, {rnd: set(fired)}, "Z",
                                              distance)
            assert len(result.corrections) == 1, (
                f"d={distance} data={data} round={rnd}: expected 1 correction, "
                f"got {len(result.corrections)}"
            )
            assert result.residual == []


@pytest.mark.parametrize("distance", [3, 5])
def test_the_logical_flips_are_exactly_the_logical_operator(distance):
    """The correctness statement that the earlier harness got backwards.

    A single error flips the logical **iff** its qubit is on the logical
    operator, so the count of flipping qubits equals `d` and the *set* equals
    `logical_z()`.  Asserting the set rather than a count is what makes this
    diagnostic: a decoder that flipped the logical for the wrong qubits would
    still pass on the count.
    """
    code = RotatedSurfaceCode(distance)
    logical = set(code.logical_z())
    single = matching_graph(code, "Z")

    flippers = set()
    for data in sorted(set(single["edges"].values())):
        fired = {n for (a, b), d in single["edges"].items() if d == data
                 for n in (a, b) if n > 0}
        result = decode_space_time_greedy(code, {0: set(fired)}, "Z", distance)
        if result.logical_flip:
            flippers.add(data)

    assert flippers == logical, (
        f"d={distance}: flipping qubits {sorted(flippers)} but the logical "
        f"operator is {sorted(logical)}"
    )
    assert len(flippers) == distance


@pytest.mark.parametrize("distance", [3, 5])
def test_an_empty_syndrome_is_never_a_logical_flip(distance):
    code = RotatedSurfaceCode(distance)
    result = decode_space_time_greedy(code, {}, "Z", distance)
    assert result.corrections == []
    assert result.logical_flip is False


def test_every_ancilla_can_reach_a_boundary():
    """A detection event with no route to the edge cannot be decoded.

    Checked from round 0, which is the layer whose boundary wiring is easiest to
    omit.
    """
    from quantumnet.core.surface_code import SpaceTimeMatchingGraph

    code = RotatedSurfaceCode(3)
    graph = SpaceTimeMatchingGraph(code, "Z", 3)
    edges = graph.edges()
    adjacency: dict = {}
    for (a, b), data in edges.items():
        adjacency.setdefault(a, []).append((b, data))
        adjacency.setdefault(b, []).append((a, data))

    boundaries = [b for b in graph.boundary_nodes() if b in adjacency]
    assert boundaries, "no boundary is connected to the graph"
    from quantumnet.core.surface_code import shortest_paths

    for ancilla in graph.ancillas:
        reachable = shortest_paths(adjacency, (0, ancilla))
        assert any(b in reachable for b in boundaries), (
            f"ancilla {ancilla} in round 0 cannot reach any boundary"
        )


def test_a_measurement_error_costs_one_edge():
    """The property that a time dimension buys, and the reason for having one."""
    from quantumnet.core.surface_code import (
        SpaceTimeMatchingGraph,
        shortest_paths,
    )

    graph = SpaceTimeMatchingGraph(RotatedSurfaceCode(3), "Z", 3)
    edges = graph.edges()
    adjacency: dict = {}
    for (a, b), data in edges.items():
        adjacency.setdefault(a, []).append((b, data))
        adjacency.setdefault(b, []).append((a, data))

    ancilla = graph.ancillas[0]
    found = shortest_paths(adjacency, (0, ancilla)).get((1, ancilla))
    assert found is not None, "no vertical edge between consecutive rounds"
    assert found[0] == 1, f"a measurement error should cost 1, got {found[0]}"
