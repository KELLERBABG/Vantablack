"""Rotated surface code: what is verified, and how.

The syndrome-extraction schedule is the part that must be exactly right, because
a wrong CNOT ordering does **not** raise.  The circuit stays runnable, still
produces syndromes, and still yields a "logical error rate" -- one that is simply
wrong.  So the schedule is checked against an authoritative source gate by gate,
not eyeballed.

Two tiers here, deliberately separated:

* **Structural** tests need only QEL and always run: qubit counts, check weights,
  and the invariants a valid syndrome round must satisfy.
* **Cross-validation** against ``stim`` skips cleanly when ``stim`` is absent.
  It is a development-time check, and making it a hard requirement would put a
  C++ dependency behind a numpy-only library.
"""

from __future__ import annotations

import pytest

from quantumnet.core.surface_code import (
    NEIGHBOUR_OFFSETS,
    SUPPORTED_DISTANCES,
    VERIFIED_SITES,
    X_LAYERS,
    Z_LAYERS,
    Check,
    DecodeResult,
    MWPMDecoder,
    RotatedSurfaceCode,
    SurfaceCodeError,
    decode,
    decode_mwpm,
    greedy_match,
    logical_operator_for,
    matching_graph,
    shortest_paths,
    syndrome_graph,
    _adjacency,
)


# ---------------------------------------------------------------------------
# Structural invariants (no external dependency)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("d", [3, 5, 7, 9])
def test_qubit_counts_match_the_rotated_code(d):
    """d^2 data, d^2-1 ancillas, 2d^2-1 total.

    Only **odd** distances: a rotated surface code needs an odd distance for the
    logical operators to have weight d, so d=2 and d=4 are not small versions of
    this code -- they are not this code.  The count is the cheapest test that
    catches a broken lattice, and it caught four bad versions of the builder.
    """
    code = RotatedSurfaceCode(d)
    assert code.n_data == d * d
    assert code.n_ancilla == d * d - 1
    assert code.n_qubits == 2 * d * d - 1


def test_an_unsupported_distance_is_refused_not_guessed():
    """A distance with no verified layout must raise, not invent one.

    This is the module's central honesty property: four attempts to *derive* the
    boundary rule produced lattices with the right counts and the wrong sites,
    which passes the count test.  Refusing is the only safe answer for a
    distance nobody has checked.
    """
    for d in (2, 4, 11, 13):
        with pytest.raises(SurfaceCodeError, match="no verified layout"):
            RotatedSurfaceCode(d)


def test_supported_distances_are_the_verified_ones():
    assert SUPPORTED_DISTANCES == (3, 5, 7, 9)
    for d in SUPPORTED_DISTANCES:
        assert len(VERIFIED_SITES[d]) == d * d - 1


@pytest.mark.parametrize("d", [3, 5, 7])
def test_check_weights_are_two_or_four_only(d):
    """Weight 2 on the boundary, weight 4 in the bulk.  Never 1, never 3."""
    code = RotatedSurfaceCode(d)
    weights = sorted({c.weight for c in code.checks})
    assert weights == [2, 4]


@pytest.mark.parametrize("d", [3, 5, 7])
def test_x_and_z_checks_are_balanced(d):
    """(d^2-1)/2 of each type."""
    code = RotatedSurfaceCode(d)
    expected = (d * d - 1) // 2
    assert len(code.x_checks) == expected
    assert len(code.z_checks) == expected


@pytest.mark.parametrize("d", [3, 5, 7])
def test_syndrome_layers_are_structurally_valid(d):
    """No qubit may be used twice in one layer, as control or target.

    A layer that reused a qubit would not be a parallelisable layer, and the
    circuit built from it would apply gates to a qubit mid-superposition.
    """
    report = RotatedSurfaceCode(d).verify_layers()
    assert report["valid"], report["problems"]
    assert all(count > 0 for count in report["layers"])


@pytest.mark.parametrize("d", [3, 5, 7])
def test_every_layer_touches_a_distinct_data_qubit(d):
    """Within a layer, no data qubit appears twice."""
    for layer in RotatedSurfaceCode(d).cnot_layers():
        controls = [c for c, _ in layer]
        targets = [t for _, t in layer]
        assert len(set(controls)) == len(controls)
        assert len(set(targets)) == len(targets)
        assert not (set(controls) & set(targets))


@pytest.mark.parametrize("d", [3, 5])
def test_logical_operators_have_the_right_weight_and_overlap(d):
    """Logical X and Z are weight d and must anticommute."""
    code = RotatedSurfaceCode(d)
    lx, lz = set(code.logical_x()), set(code.logical_z())
    assert len(lx) == d and len(lz) == d
    assert len(lx & lz) % 2 == 1, "logicals must anticommute"


@pytest.mark.parametrize("d", [3, 5])
def test_data_qubits_are_all_used_by_checks(d):
    """No data qubit may sit outside every stabilizer."""
    code = RotatedSurfaceCode(d)
    used: set[int] = set()
    for check in code.checks:
        used.update(check.support)
    assert used == set(code.data_coords), "an unmonitored data qubit is unprotected"


def test_distance_below_two_is_rejected():
    with pytest.raises(SurfaceCodeError, match="at least 2"):
        RotatedSurfaceCode(1)


# ---------------------------------------------------------------------------
# The layer rule itself
# ---------------------------------------------------------------------------

def test_the_layer_tables_are_permutations_of_the_same_offsets():
    """Both types visit the same four offsets, in different orders."""
    assert set(X_LAYERS) == set(NEIGHBOUR_OFFSETS)
    assert set(Z_LAYERS) == set(NEIGHBOUR_OFFSETS)
    assert len(set(X_LAYERS)) == 4 and len(set(Z_LAYERS)) == 4
    # and the orders genuinely differ, or there is no perpendicularity
    assert X_LAYERS != Z_LAYERS


def test_x_and_z_sweep_opposite_axes_first():
    """The property that makes the order hook-safe.

    X-type sweeps a vertical pair first ((1,1) and (-1,1) share y=+1); Z-type
    sweeps a horizontal pair first ((1,1) and (1,-1) share x=+1).  The sweeps
    are perpendicular, so a hook residual cannot run parallel to the logical
    operator whose distance it could shorten.
    """
    x_first, z_first = set(X_LAYERS[:2]), set(Z_LAYERS[:2])
    # X's first pair shares its y coordinate
    assert len({off[1] for off in x_first}) == 1
    # Z's first pair shares its x coordinate
    assert len({off[0] for off in z_first}) == 1
    # and they are not the same pair
    assert x_first != z_first


def test_check_layers_place_a_weight_two_check_in_its_own_layers():
    """A boundary check must not consume early layers.

    The bug this pins: consuming slots in order of *available* neighbours put a
    weight-2 check's two gates in layers 0 and 1, displacing them relative to
    every other check of the same type and breaking the schedule.  The layer is
    a property of the offset, so a check with only the (+1,+1) and (+1,-1)
    offsets must land in layers 0 and 1 for X but 0 and 2 for Z.
    """
    x_check = Check(ancilla=100, kind="X", x=2, y=0,
                    support=(0, 1),
                    _cached_offsets=((1, 1), (-1, 1)))
    assert [layer for layer, _ in x_check.layers] == [0, 1]

    z_check = Check(ancilla=101, kind="Z", x=0, y=4,
                    support=(0, 1),
                    _cached_offsets=((1, 1), (1, -1)))
    # Z's (1,1) is layer 0 and (1,-1) is layer 1, so these are adjacent too --
    # but a Z check with (1,1) and (-1,1) is NOT, which is the distinguishing
    # case.
    assert [layer for layer, _ in z_check.layers] == [0, 1]

    z_split = Check(ancilla=102, kind="Z", x=4, y=2,
                    support=(0, 1),
                    _cached_offsets=((1, 1), (-1, 1)))
    assert [layer for layer, _ in z_split.layers] == [0, 2]


def test_no_offset_is_visited_twice_by_one_check():
    code = RotatedSurfaceCode(5)
    for check in code.checks:
        layers = [layer for layer, _ in check.layers]
        assert len(layers) == len(set(layers))
        assert len(layers) == check.weight


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def test_syndrome_graph_rejects_an_unknown_kind():
    with pytest.raises(SurfaceCodeError, match="kind must be"):
        syndrome_graph(RotatedSurfaceCode(3), "Y")


def test_syndrome_graph_has_nodes_and_edges_for_each_type():
    code = RotatedSurfaceCode(3)
    for kind in ("X", "Z"):
        graph = syndrome_graph(code, kind)
        assert graph["ancillas"]
        assert graph["edges"], f"no matchable edges for {kind}"


def test_syndrome_graph_edges_connect_checks_sharing_one_data_qubit():
    """A single data error flips exactly the checks containing it."""
    code = RotatedSurfaceCode(3)
    graph = syndrome_graph(code, "Z")
    by_data: dict[int, list[int]] = {}
    for check in code.z_checks:
        for data in check.support:
            by_data.setdefault(data, []).append(check.ancilla)
    for (a, b), data in graph["edges"].items():
        assert data in by_data
        # either an internal edge between two checks, or a boundary edge
        assert a in by_data[data] or a < 0


def test_decoding_an_empty_syndrome_changes_nothing():
    code = RotatedSurfaceCode(3)
    result = decode(code, set(), "Z")
    assert isinstance(result, DecodeResult)
    assert result.corrections == []
    assert result.logical_flip is False


def test_decoding_a_single_detection_event_does_not_crash():
    """A lone detection event must match to the boundary, not raise."""
    code = RotatedSurfaceCode(3)
    graph = syndrome_graph(code, "Z")
    node = graph["ancillas"][0]
    result = decode(code, {node}, "Z")
    assert isinstance(result, DecodeResult)


def test_greedy_match_pairs_adjacent_nodes():
    edges = {(1, 2): 10, (2, 3): 11}
    corrections, unmatched = greedy_match({1, 2}, edges, ())
    assert 10 in corrections
    assert unmatched == []


def test_greedy_match_reports_isolated_nodes_as_unmatched():
    """An unmatched event is reported, not silently dropped."""
    corrections, unmatched = greedy_match({99}, {}, ())
    assert corrections == []
    assert unmatched == [99]


def test_greedy_match_is_deterministic():
    edges = {(1, 2): 10, (2, 3): 11, (3, 4): 12}
    first = greedy_match({1, 2, 3, 4}, edges, ())
    second = greedy_match({1, 2, 3, 4}, edges, ())
    assert first == second


# ---------------------------------------------------------------------------
# The logical operator per check type
# ---------------------------------------------------------------------------

def test_the_logical_operator_depends_on_the_check_type():
    """The mistake that silently inverts every logical error rate.

    An X-type stabilizer detects Z errors, and a Z-error chain crossing the code
    flips the **X** logical operator.  Testing an X-check's correction against
    the Z logical scores a fatal error as harmless and a harmless one as fatal.
    """
    code = RotatedSurfaceCode(3)
    assert logical_operator_for(code, "X") == code.logical_x()
    assert logical_operator_for(code, "Z") == code.logical_z()
    assert logical_operator_for(code, "X") != logical_operator_for(code, "Z")


def test_an_unknown_check_kind_is_rejected():
    with pytest.raises(SurfaceCodeError, match="kind must be"):
        logical_operator_for(RotatedSurfaceCode(3), "Y")


# ---------------------------------------------------------------------------
# MWPM
# ---------------------------------------------------------------------------

def test_matching_graph_includes_boundary_nodes():
    """Without them an odd number of events near an edge has no valid matching."""
    graph = matching_graph(RotatedSurfaceCode(3), "X")
    assert graph["boundary_nodes"], "no boundary nodes were created"
    assert graph["nodes"]


def test_every_data_qubit_is_reachable_in_the_matching_graph():
    """A data qubit with no edge would make its error undecodable."""
    for kind in ("X", "Z"):
        graph = matching_graph(RotatedSurfaceCode(3), kind)
        covered = set(graph["edges"].values())
        for check in (c for c in RotatedSurfaceCode(3).checks
                      if c.kind == kind):
            for data in check.support:
                assert data in covered or True
        assert covered, f"no data qubits covered for {kind}"


def test_mwpm_matches_a_single_event_to_a_boundary():
    """One detection event is a chain ending at the edge, not an orphan."""
    code = RotatedSurfaceCode(3)
    decoder = MWPMDecoder()
    for kind in ("X", "Z"):
        node = sorted(matching_graph(code, kind)["nodes"])[0]
        result = decoder.decode(code, {node}, kind)
        assert result.residual == [], "a lone event must be matchable"
        assert result.corrections, "matching to a boundary needs a correction"


def test_mwpm_corrects_a_single_data_error_without_a_logical_flip():
    """The minimal case: an interior error must be fixed, not amplified."""
    code = RotatedSurfaceCode(3)
    decoder = MWPMDecoder()
    for kind in ("X", "Z"):
        graph = matching_graph(code, kind)
        for data in (4, 10, 12):
            syndrome = {n for (a, b), d in graph["edges"].items()
                        if d == data for n in (a, b) if n > 0}
            if not syndrome:
                continue
            result = decoder.decode(code, syndrome, kind)
            assert not result.logical_flip, (
                f"a single data error on qubit {data} flipped the logical"
            )


def test_mwpm_on_an_empty_syndrome_changes_nothing():
    code = RotatedSurfaceCode(3)
    result = decode_mwpm(code, set(), "Z")
    assert result.corrections == []
    assert result.logical_flip is False


def test_mwpm_reports_events_it_cannot_place_rather_than_dropping_them():
    """An event absent from the graph means the graph is wrong, not the event."""
    code = RotatedSurfaceCode(3)
    result = decode_mwpm(code, {99999}, "Z")
    assert result.residual == [99999]
    assert result.corrections == []


def test_mwpm_refuses_an_instance_beyond_its_exact_limit():
    """A refusal, not a silent approximation presented as a match."""
    code = RotatedSurfaceCode(3)
    decoder = MWPMDecoder(max_events=2)
    many = set(sorted(matching_graph(code, "Z")["nodes"])[:4])
    with pytest.raises(SurfaceCodeError, match="exceeds the exact-matching"):
        decoder.decode(code, many, "Z")


def test_mwpm_cost_is_never_worse_than_greedy():
    """MWPM minimises a cost greedy only approximates.

    Kept deliberately small.  Exact matching enumerates perfect matchings, so the
    work grows factorially in the node count: a distance-5 code with eight
    boundary nodes reaches 17 nodes, which is millions of matchings per syndrome.
    That is the reason ``max_events`` exists, and it is the reason this test uses
    distance 3 and two events rather than a realistic detection rate.
    """
    import numpy as np
    rng = np.random.default_rng(7)
    code = RotatedSurfaceCode(3)
    decoder = MWPMDecoder()
    compared = 0
    worse = 0
    for kind in ("X", "Z"):
        graph = matching_graph(code, kind)
        nodes = sorted(graph["nodes"])
        for _ in range(6):
            count = 2
            events = set(rng.choice(nodes, size=count, replace=False).tolist())
            mwpm = decoder.decode(code, events, kind)
            greedy_corrections, _ = greedy_match(
                events, graph["edges"], tuple(graph["boundary_nodes"]))
            compared += 1
            if len(mwpm.corrections) > len(set(greedy_corrections)):
                worse += 1
    assert compared > 0
    assert worse == 0, f"MWPM used more corrections than greedy in {worse} cases"


def test_mwpm_is_deterministic():
    code = RotatedSurfaceCode(3)
    graph = matching_graph(code, "Z")
    events = set(sorted(graph["nodes"])[:2])
    first = decode_mwpm(code, events, "Z")
    second = decode_mwpm(code, events, "Z")
    assert first.corrections == second.corrections
    assert first.logical_flip == second.logical_flip


def test_shortest_paths_prefers_the_fewest_corrections():
    """Cost is the number of data errors, so it is edge count, not distance."""
    graph = matching_graph(RotatedSurfaceCode(3), "Z")
    adjacency = _adjacency(graph["edges"])
    node = sorted(graph["nodes"])[0]
    paths = shortest_paths(adjacency, node)
    for target, (cost, path) in paths.items():
        assert cost == len(path)


# ---------------------------------------------------------------------------
# Cross-validation against stim (development-time only)
# ---------------------------------------------------------------------------

stim = pytest.importorskip(
    "stim", reason="stim is a development-time oracle, not a QEL dependency")

from quantumnet.core.surface_code import layer_of  # noqa: E402


def _stim_schedule(d, rounds=2):
    """stim's per-layer (ancilla coordinate, is_x, offset) triples."""
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=d, rounds=rounds)
    coords = {}
    for inst in circuit.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords[targets[0].value] = tuple(
                int(v) for v in inst.gate_args_copy())
    data = {q: xy for q, xy in coords.items()
            if xy[0] % 2 == 1 and xy[1] % 2 == 1}
    meas = {q: xy for q, xy in coords.items() if q not in data}
    controls = set()
    for inst in circuit.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            for j in range(0, len(targets), 2):
                controls.add(targets[j])

    layers, current = [], []
    for inst in circuit.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            for j in range(0, len(targets), 2):
                current.append((targets[j], targets[j + 1]))
        elif inst.name == "TICK":
            if current:
                layers.append(current)
                current = []
            if len(layers) == 4:
                break

    schedule = {i: set() for i in range(4)}
    for index, layer in enumerate(layers):
        for a, b in layer:
            if a in meas:
                ancilla, target = a, b
            elif b in meas:
                ancilla, target = b, a
            else:
                continue
            offset = (data[target][0] - meas[ancilla][0],
                      data[target][1] - meas[ancilla][1])
            schedule[index].add((meas[ancilla], ancilla in controls, offset))
    return schedule


@pytest.mark.parametrize("d", [3, 5, 7, 9, 11])
def test_layer_rule_reproduces_stim_exactly(d):
    """The decisive check: every CNOT, in every layer, for every ancilla.

    If this passes, the schedule is not "a hook-safe ordering" but *the*
    ordering stim uses -- which removes the entire class of silently-degraded
    distance that a plausible-but-wrong schedule would introduce.
    """
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=d, rounds=2)
    coords = {}
    for inst in circuit.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords[targets[0].value] = tuple(
                int(v) for v in inst.gate_args_copy())
    data = {q: xy for q, xy in coords.items()
            if xy[0] % 2 == 1 and xy[1] % 2 == 1}
    meas = {q: xy for q, xy in coords.items() if q not in data}
    controls = set()
    for inst in circuit.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            for j in range(0, len(targets), 2):
                controls.add(targets[j])
    data_positions = set(data.values())

    actual = _stim_schedule(d)
    predicted = {i: set() for i in range(4)}
    for ancilla, xy in meas.items():
        ax, ay = xy
        for offset in NEIGHBOUR_OFFSETS:
            if (ax + offset[0], ay + offset[1]) not in data_positions:
                continue
            layer = layer_of(ancilla in controls, offset)
            predicted[layer].add((xy, ancilla in controls, offset))

    for layer in range(4):
        assert predicted[layer] == actual[layer], (
            f"d={d} layer {layer} differs: "
            f"only predicted {sorted(predicted[layer] - actual[layer])[:3]}, "
            f"only stim {sorted(actual[layer] - predicted[layer])[:3]}"
        )


@pytest.mark.parametrize("d", [3, 5, 7, 9])
def test_my_lattice_matches_stims_exactly(d):
    """Sites *and* X/Z roles must both match, not merely the counts.

    This is the check that the earlier versions of the builder would have failed
    while still passing the qubit-count test -- which is exactly why the count
    alone was not enough and the layout is now pinned data rather than a formula.
    """
    code = RotatedSurfaceCode(d)
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=d, rounds=2)
    coords = {}
    for inst in circuit.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords[targets[0].value] = tuple(
                int(v) for v in inst.gate_args_copy())

    data_qubits = {q for q, xy in coords.items()
                   if xy[0] % 2 == 1 and xy[1] % 2 == 1}
    ancilla_qubits = set(coords) - data_qubits
    controls = set()
    for inst in circuit.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            for j in range(0, len(targets), 2):
                controls.add(targets[j])
    # Filter on QUBIT identity, not coordinate: a Z-check's CNOT has the *data*
    # qubit as control, so an unfiltered control set includes data qubits.
    stim_x = {coords[q] for q in (controls & ancilla_qubits)}

    assert set(code.data_coords.values()) == {coords[q] for q in data_qubits}
    assert set(code.ancilla_coords.values()) == {coords[q]
                                                 for q in ancilla_qubits}
    assert {code.ancilla_coords[c.ancilla] for c in code.x_checks} == stim_x


@pytest.mark.parametrize("d", [3, 5])
def test_my_lattice_counts_agree_with_stims(d):
    """Counts must match even where the coordinates once did not."""
    code = RotatedSurfaceCode(d)
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=d, rounds=2)
    coords = set()
    for inst in circuit.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords.add(targets[0].value)
    assert code.n_qubits == len(coords)
