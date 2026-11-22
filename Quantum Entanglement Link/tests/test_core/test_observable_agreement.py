"""Reconcile the logical operators against stim's own observable.

An earlier note in the plan claimed a mismatch: that `RotatedSurfaceCode.logical_z`
uses the **top** data row while `stim`'s observable uses the **bottom** row. That
claim was **wrong**, and this file is what disproves it.

`stim` reports the observable as measurement-record indices, which for
`rotated_memory_z` are the final data-qubit measurements. Resolving those indices
to qubits gives data qubits `[5, 3, 1]` at coordinates `(5,1), (3,1), (1,1)` for
d=3 -- the **same support** as `logical_z()`, `[0, 1, 2]` at
`(1,1), (3,1), (5,1)`. Only the listing order differs, and the support is what a
logical operator is.

The misreading came from treating the negative record indices as a geometric
statement. `-7` is "the seventh-from-last measurement", not "a qubit at some
row" -- and the data measurements are emitted in *sorted qubit order*, so a
descending record index is an ascending coordinate.

These tests pin the agreement so the claim cannot be resurrected, and pin the
reason it looked wrong so the same misreading is not made twice.
"""

from __future__ import annotations

import pytest

try:
    import stim

    HAVE_STIM = True
except ImportError:  # pragma: no cover - exercised by the skip path
    stim = None
    HAVE_STIM = False

from quantumnet.core.surface_code import RotatedSurfaceCode

pytestmark = pytest.mark.skipif(not HAVE_STIM, reason="needs stim")


def stim_observable_qubits(distance: int, rounds: int | None = None) -> set[int]:
    """The **lattice-local** data indices stim's memory-Z observable covers.

    Resolved in two steps, and both are needed:

    1. the observable's targets are measurement-record indices, and the final
       block of measurements is the data qubits -- so a negative index counts
       backwards from the *end of the measurement list*, not from the end of some
       qubit ordering;
    2. stim numbers qubits globally and its data qubits are not contiguous, so the
       resolved stim qubit ids must be mapped to lattice-local indices by position
       in the sorted data list.

    Skipping step 2 -- comparing stim qubit ids against local indices -- is what
    produced the original "mismatch": stim's ids ``[1, 3, 5]`` are local indices
    ``[0, 1, 2]``.
    """
    rounds = distance if rounds is None else rounds
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=distance, rounds=rounds)
    coords = {}
    for inst in circuit.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords[targets[0].value] = tuple(
                int(v) for v in inst.gate_args_copy())
    data = sorted(q for q, xy in coords.items()
                  if xy[0] % 2 == 1 and xy[1] % 2 == 1)

    measurements: list[int] = []
    for inst in circuit.flattened():
        if inst.name in ("M", "MR"):
            measurements.extend(t.value for t in inst.targets_copy())

    records: list[int] = []
    for inst in circuit.flattened():
        if inst.name == "OBSERVABLE_INCLUDE":
            records = [t.value for t in inst.targets_copy()]
    assert records, "the circuit declares no observable"

    final_data = measurements[-len(data):]
    assert sorted(final_data) == data, (
        "the last measurements are not the data qubits; the resolution below "
        "assumes they are"
    )
    local_of = {q: i for i, q in enumerate(data)}
    return {local_of[final_data[len(data) + r]] for r in records}


@pytest.mark.parametrize("distance", [3, 5, 7])
def test_logical_z_matches_stims_observable_support(distance):
    """The claim of a mismatch is disproved here.

    Support equality, not set ordering: a logical operator is a set of qubits, and
    stim happens to emit the record indices in descending qubit order.
    """
    code = RotatedSurfaceCode(distance)
    assert set(code.logical_z()) == stim_observable_qubits(distance)


@pytest.mark.parametrize("distance", [3, 5])
def test_the_two_are_the_same_row(distance):
    """Both sit on the low-y data row, which is why only order differs."""
    code = RotatedSurfaceCode(distance)
    stim_coords = {code.data_coords[q] for q in stim_observable_qubits(distance)}
    my_coords = {code.data_coords[q] for q in code.logical_z()}
    assert stim_coords == my_coords
    assert len({y for _, y in my_coords}) == 1, "the logical row is not constant"
    assert min(y for _, y in my_coords) == 1


def stim_observable_sequence(distance: int, rounds: int | None = None) -> list[int]:
    """As :func:`stim_observable_qubits`, but preserving the declared order.

    The order is the point of the test below: the descending record indices are
    what made a same-row observable look like a different row.
    """
    rounds = distance if rounds is None else rounds
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=distance, rounds=rounds)
    coords = {}
    for inst in circuit.flattened():
        if inst.name == "QUBIT_COORDS":
            targets = inst.targets_copy()
            coords[targets[0].value] = tuple(
                int(v) for v in inst.gate_args_copy())
    data = sorted(q for q, xy in coords.items()
                  if xy[0] % 2 == 1 and xy[1] % 2 == 1)
    measurements: list[int] = []
    for inst in circuit.flattened():
        if inst.name in ("M", "MR"):
            measurements.extend(t.value for t in inst.targets_copy())
    records: list[int] = []
    for inst in circuit.flattened():
        if inst.name == "OBSERVABLE_INCLUDE":
            records = [t.value for t in inst.targets_copy()]
    final_data = measurements[-len(data):]
    local_of = {q: i for i, q in enumerate(data)}
    return [local_of[final_data[len(data) + r]] for r in records]


def test_the_record_order_is_why_it_looked_like_the_other_row():
    """The misreading, pinned so it is not repeated.

    stim's observable records come out in descending index, so resolving them in
    declared order gives *descending* x coordinates. Reading that as a geometric
    statement -- "the observable is on the other row" -- is the mistake.
    """
    distance = 3
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=distance, rounds=distance)
    records: list[int] = []
    for inst in circuit.flattened():
        if inst.name == "OBSERVABLE_INCLUDE":
            records = [t.value for t in inst.targets_copy()]
    assert records == sorted(records, reverse=True), (
        "the record indices are no longer descending; the note explaining the "
        "original misreading needs revisiting"
    )

    code = RotatedSurfaceCode(distance)
    ordered = stim_observable_sequence(distance)
    xs = [code.data_coords[q][0] for q in ordered]
    assert xs == sorted(xs, reverse=True), (
        f"declared order should give descending x, got {xs}"
    )
    # And as a set it is the top row, not the bottom.
    assert set(ordered) == set(code.logical_z())
    assert {code.data_coords[q][1] for q in ordered} == {1}


@pytest.mark.parametrize("distance", [3, 5])
def test_logical_x_is_a_column(distance):
    """The complementary operator, checked for the property that matters:
    it anticommutes with logical Z and has weight d."""
    code = RotatedSurfaceCode(distance)
    lx, lz = set(code.logical_x()), set(code.logical_z())
    assert len(lx) == distance
    assert len(lx & lz) % 2 == 1
    xs = {code.data_coords[q][0] for q in lx}
    assert len(xs) == 1, "logical X should lie on a constant column"


@pytest.mark.parametrize("distance", [3, 5])
def test_the_observable_is_what_the_code_protects(distance):
    """A decoder's logical-flip decision is only meaningful if the operator it
    tests against is the one stim measures. This asserts that directly."""
    from quantumnet.core.surface_code import logical_operator_for

    code = RotatedSurfaceCode(distance)
    # `logical_operator_for` maps X-type checks to the X logical, and the
    # memory-Z experiment's Z-type checks to the Z logical -- which is stim's
    # observable.
    assert set(logical_operator_for(code, "Z")) == stim_observable_qubits(distance)
