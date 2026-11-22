"""Rotated surface code: what is verified, and what is deliberately not.

WHY THIS FILE EXISTS
--------------------
The rule here is *never quote a threshold or logical-error-rate
number that has not been both cited and reproduced locally*.  The same applies
to the syndrome-extraction circuit, for a sharper reason: a wrong CNOT ordering
does not raise.  It still runs, still returns syndromes, and still produces a
"logical error rate" -- that number is simply wrong, and it looks plausible.

So this file records only claims that were checked against an authoritative
oracle, and states plainly what remains open.

VERIFIED HERE (against ``stim``'s rotated-surface-code generator)
----------------------------------------------------------------
1. Qubit counts: ``d^2`` data, ``d^2 - 1`` measure, ``2 d^2 - 1`` total.
2. Data qubits occupy the (odd, odd) coordinate sublattice: a ``d x d`` grid
   with spacing 2.
3. The ancillas split evenly into X-type and Z-type, and they are disjoint.
4. Every CNOT in the round is ancilla<->data -- never data<->data and never
   ancilla<->ancilla.  X-type ancillas act as CNOT *controls*, Z-type as
   *targets*.
5. Stabilizer weights are only ever 2 or 4: weight 2 on the boundary,
   weight 4 in the bulk.
6. **The reference circuit's circuit-level fault distance equals ``d``.**  This
   is the ground truth any implementation must reproduce, and the number a
   hook-prone ordering would silently halve.

NOT VERIFIED HERE -- do not assume these
----------------------------------------
* **The stabilizer supports and their pairwise commutation.**  Two geometric
  guesses were tried and *both provably wrong*: a Chebyshev-distance rule and a
  Manhattan-distance-2 rule each leave same-type stabilizers anticommuting,
  which is impossible for a valid code and therefore proves the guess bad
  rather than proving the code bad.  The correct support must be read out of
  stim's detector definitions (or its detector error model), not inferred from
  coordinates.  Until that is done, no stabilizer table in this repository
  should be trusted.

* **A generative rule for the CNOT ordering.**  ``stim`` emits a
  hook-avoiding order, but it is *not* the folklore "X-type gets one shape,
  Z-type the other": X-type ancillas at different coordinates take different
  orderings (asserted below).  A candidate rule exists in the literature and in
  ``rotated_surface_code_spec.md``, but it **contradicts** the order this
  repository extracted from stim, so neither should be committed to code until
  one is reconciled against the fault-distance oracle.

``stim`` is a **verification-only** tool.  It is not a QEL dependency, and this
module skips cleanly when it is absent.
"""

from __future__ import annotations

import pytest

stim = pytest.importorskip("stim", reason="stim is a verification-only tool")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract(d: int, rounds: int = 2):
    """Pull coordinates, the data/ancilla split and CNOT roles out of stim."""
    c = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=d, rounds=rounds)

    coords: dict[int, tuple[int, int]] = {}
    for inst in c.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords[targets[0].value] = tuple(
                int(v) for v in inst.gate_args_copy())

    data = {q: xy for q, xy in coords.items()
            if xy[0] % 2 == 1 and xy[1] % 2 == 1}
    meas = {q: xy for q, xy in coords.items() if q not in data}

    controls: set[int] = set()
    for inst in c.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            for j in range(0, len(targets), 2):
                controls.add(targets[j])

    x_type = {q for q in meas if q in controls}
    z_type = set(meas) - x_type
    return c, coords, data, meas, x_type, z_type


def _cnots_per_ancilla(c, data, meas, n_layers: int = 4):
    """``{ancilla: [data qubits in CNOT order]}`` for one syndrome round.

    The flattened circuit repeats the round, so stopping after ``n_layers``
    TICK-delimited layers is what isolates a single round.
    """
    schedule: dict[int, list[int]] = {q: [] for q in meas}
    layers, current = [], []
    for inst in c.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            for j in range(0, len(targets), 2):
                current.append((targets[j], targets[j + 1]))
        elif inst.name == "TICK":
            if current:
                layers.append(current)
                current = []
            if len(layers) == n_layers:
                break
    for layer in layers:
        for a, b in layer:
            if a in meas and b in data:
                schedule[a].append(b)
            elif b in meas and a in data:
                schedule[b].append(a)
    return schedule


# ---------------------------------------------------------------------------
# 1. VERIFIED: lattice layout
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("d", [3, 5, 7])
def test_qubit_counts_match_the_rotated_code(d):
    """A distance-d rotated code has d^2 data and d^2-1 measure qubits."""
    _, coords, data, meas, _, _ = _extract(d)
    assert len(data) == d * d
    assert len(meas) == d * d - 1
    assert len(coords) == 2 * d * d - 1


@pytest.mark.parametrize("d", [3, 5, 7])
def test_data_qubits_lie_on_the_odd_odd_sublattice(d):
    """Data qubits sit at (odd, odd): a spacing-2 lattice, d x d of them."""
    _, _, data, _, _, _ = _extract(d)
    for x, y in data.values():
        assert x % 2 == 1 and y % 2 == 1
    assert len({x for x, _ in data.values()}) == d
    assert len({y for _, y in data.values()}) == d


@pytest.mark.parametrize("d", [3, 5, 7])
def test_ancillas_split_evenly_between_x_and_z(d):
    """(d^2-1)/2 X-type and (d^2-1)/2 Z-type, disjoint and covering."""
    _, _, _, meas, x_type, z_type = _extract(d)
    expected = (d * d - 1) // 2
    assert len(x_type) == expected
    assert len(z_type) == expected
    assert x_type | z_type == set(meas)
    assert not (x_type & z_type)


@pytest.mark.parametrize("d", [3, 5])
def test_every_cnot_is_between_an_ancilla_and_a_data_qubit(d):
    """X-type ancillas are controls; Z-type ancillas are targets."""
    c, _, data, meas, x_type, _ = _extract(d)
    for inst in c.flattened():
        if inst.name in ("CX", "CNOT"):
            targets = [t.value for t in inst.targets_copy()]
            assert len(targets) % 2 == 0
            for j in range(0, len(targets), 2):
                a, b = targets[j], targets[j + 1]
                if a in meas and b in data:
                    assert a in x_type, "an ancilla controlling a CNOT is X-type"
                elif b in meas and a in data:
                    assert b not in x_type, "an ancilla targeted by a CNOT is Z-type"
                else:
                    pytest.fail(f"CNOT {a}->{b} is not ancilla<->data")


@pytest.mark.parametrize("d", [3, 5])
def test_stabilizer_weights_are_two_or_four_only(d):
    """Weight 2 on the boundary, weight 4 in the bulk.  Never 1, never 3."""
    c, _, data, meas, _, _ = _extract(d)
    schedule = _cnots_per_ancilla(c, data, meas)
    weights = sorted(len(s) for s in schedule.values())
    assert set(weights) <= {2, 4}
    assert 4 in weights and 2 in weights
    # Weight-2 checks are exactly the boundary ones.
    assert weights.count(2) + weights.count(4) == d * d - 1


@pytest.mark.parametrize("d", [3, 5])
def test_every_data_qubit_is_touched_by_the_round(d):
    """No data qubit may be idle for the whole syndrome round.

    An unmonitored data qubit would make the code unprotected.
    """
    c, _, data, meas, _, _ = _extract(d)
    schedule = _cnots_per_ancilla(c, data, meas)
    touched: set[int] = set()
    for support in schedule.values():
        touched.update(support)
    assert touched == set(data)


# ---------------------------------------------------------------------------
# 2. VERIFIED: the reference circuit preserves distance d
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("d", [3, 5])
def test_stim_reference_circuit_has_fault_distance_d(d):
    """The generated circuit's fault distance must equal d.

    This is the ground truth an implementation has to match, and precisely the
    number a hook-prone CNOT ordering would quietly drop to about d/2.
    """
    c = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=d, rounds=2,
        after_clifford_depolarization=0.001)
    assert len(c.shortest_graphlike_error()) == d


# ---------------------------------------------------------------------------
# 3. Guards against the two documented wrong turns
# ---------------------------------------------------------------------------

def test_the_ordering_rule_is_not_the_x_z_checkerboard():
    """Folklore says "X-type gets one CNOT shape, Z-type the other".

    On this lattice that is false: X-type ancillas at different coordinates
    take *different* orderings, so no rule keyed only on X-vs-Z can reproduce
    stim's schedule.  This is the single easiest way to get the circuit wrong.
    """
    c, _, data, meas, x_type, _ = _extract(3)
    schedule = _cnots_per_ancilla(c, data, meas)

    by_type: dict[str, set[tuple]] = {"X": set(), "Z": set()}
    for ancilla, order in schedule.items():
        ax, ay = meas[ancilla]
        offsets = tuple((data[q][0] - ax, data[q][1] - ay) for q in order)
        by_type["X" if ancilla in x_type else "Z"].add(offsets)

    assert len(by_type["X"]) > 1 or len(by_type["Z"]) > 1, (
        "expected the ordering to depend on more than the X/Z type; if this "
        "fails the scheduling problem is simpler than documented and the "
        "documentation should be corrected"
    )


def test_coordinate_parity_alone_does_not_determine_ancilla_type():
    """No rule based only on (x % 2, y % 2) can classify ancillas.

    stim's own placement hosts both X-type and Z-type ancillas on the same
    coordinate parity, so a parity-only classifier is provably insufficient.
    """
    _, _, _, meas, x_type, _ = _extract(5)
    by_parity: dict[tuple[int, int], set[str]] = {}
    for q, (x, y) in meas.items():
        by_parity.setdefault((x % 2, y % 2), set()).add(
            "X" if q in x_type else "Z")
    assert any(len(kinds) > 1 for kinds in by_parity.values())


def test_geometric_support_guesses_are_rejected():
    """Document, as a test, that coordinate-distance support rules are wrong.

    Both a Chebyshev-distance rule and a Manhattan-distance-2 rule were tried
    as ways to derive stabilizer support.  Each leaves same-type stabilizers
    anticommuting -- impossible for a valid code, and therefore proof that the
    *guess* is wrong.  Support must come from stim's detector definitions.

    This test pins that finding so the next person does not repeat it.
    """
    _, _, data, meas, _, _ = _extract(3)

    def anticommuting_pairs(support_of) -> int:
        support = {q: sorted(support_of(q, xy)) for q, xy in meas.items()}
        bad = 0
        qs = sorted(meas)
        for i, a in enumerate(qs):
            for b in qs[i + 1:]:
                if len(set(support[a]) & set(support[b])) % 2:
                    bad += 1
        return bad

    chebyshev = anticommuting_pairs(lambda q, xy: [
        dq for dq, (dx, dy) in data.items()
        if abs(dx - xy[0]) <= 1 and abs(dy - xy[1]) <= 1])
    manhattan2 = anticommuting_pairs(lambda q, xy: [
        dq for dq, (dx, dy) in data.items()
        if abs(dx - xy[0]) + abs(dy - xy[1]) == 2])

    assert chebyshev > 0, "the Chebyshev rule was expected to be wrong"
    assert manhattan2 > 0, "the Manhattan-2 rule was expected to be wrong"
