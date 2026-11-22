"""Logical entanglement between surface-code patches.

Verifies logical teleportation against the identities it must satisfy, and the
two-patch layout against the algebra a logical qubit requires.  **No lattice
surgery is implemented or claimed** -- no patch merging or splitting, no seam
defect decoder, no logical Pauli product measurement.

The reason teleportation can be verified without simulating amplitudes: it is the
**identity on the logical Pauli frame**, and that is a finite algebraic statement.
Every Pauli the Bell measurement appears to introduce must be cancelled by the
correction its outcome dictates, for all four outcomes; and an incoming logical
error must arrive intact rather than be absorbed.
"""

from __future__ import annotations

import pytest

from quantumnet.core.logical_entanglement import (
    BELL_OUTCOME_CORRECTIONS,
    PAULI_I,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    LogicalPauliFrame,
    TwoPatchLayout,
    logical_cnot_action,
    pauli_commutes,
    pauli_multiply,
    pauli_name,
    prepare_logical_bell_pair,
    teleportation_frame,
    transversal_cnot_pairs,
    verify_bell_pair_operators,
    verify_error_propagation,
    verify_teleportation_identity,
    verify_transversal_cnot_action,
)
from quantumnet.core.surface_code import SurfaceCodeError


# ---------------------------------------------------------------------------
# Pauli algebra
# ---------------------------------------------------------------------------

def test_pauli_names_are_self_inverse():
    for p in (PAULI_X, PAULI_Y, PAULI_Z):
        assert pauli_multiply(p, p) == PAULI_I


def test_x_and_z_anticommute_while_x_commutes_with_itself():
    assert not pauli_commutes(PAULI_X, PAULI_Z)
    assert pauli_commutes(PAULI_X, PAULI_X)
    assert pauli_commutes(PAULI_X, PAULI_I)


def test_y_is_x_times_z():
    assert pauli_multiply(PAULI_X, PAULI_Z) == PAULI_Y


# ---------------------------------------------------------------------------
# Two-patch layout
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distance", [3, 5, 7])
def test_the_layout_is_structurally_valid(distance):
    """Disjoint patches, correct logical weights, anticommuting logicals."""
    report = TwoPatchLayout(distance).verify()
    assert report["valid"], report["problems"]
    assert report["total_data"] == 2 * distance * distance


def test_the_two_patches_do_not_share_a_qubit():
    """The offset bug this exists to catch."""
    layout = TwoPatchLayout(3)
    a = {layout.global_index("A", q) for q in range(layout.n_data)}
    b = {layout.global_index("B", q) for q in range(layout.n_data)}
    assert not (a & b)
    assert a | b == set(range(layout.total_data))


def test_index_round_trips():
    layout = TwoPatchLayout(3)
    for patch in ("A", "B"):
        for local in range(layout.n_data):
            g = layout.global_index(patch, local)
            assert layout.local_index(g) == (patch, local)


def test_an_out_of_range_index_is_rejected():
    layout = TwoPatchLayout(3)
    with pytest.raises(SurfaceCodeError, match="outside"):
        layout.local_index(layout.total_data)


def test_an_unknown_patch_is_rejected():
    with pytest.raises(SurfaceCodeError, match="patch must be"):
        TwoPatchLayout(3).global_index("C", 0)


def test_patches_are_offset_not_overlapping():
    """A concrete check that B is shifted by exactly one patch."""
    layout = TwoPatchLayout(3)
    assert layout.logical_x("A") == [0, 3, 6]
    assert layout.logical_x("B") == [9, 12, 15]


# ---------------------------------------------------------------------------
# Transversal CNOT: the property that makes the Bell pair legitimate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distance", [3, 5, 7])
def test_a_transversal_cnot_acts_as_a_logical_cnot(distance):
    """`X_A -> X_A X_B`, `Z_B -> Z_A Z_B`, `Z_A` and `X_B` unchanged.

    Verified on the real layout, not asserted.  A scrambled pairing would still
    look transversal while implementing something that is not a logical CNOT.
    """
    report = verify_transversal_cnot_action(TwoPatchLayout(distance))
    assert report["valid"], report["problems"]


def test_the_cnot_rule_matches_the_expected_algebra():
    assert logical_cnot_action(1, 0, 0, 0) == (1, 0, 1, 0)   # X_A -> X_A X_B
    assert logical_cnot_action(0, 1, 0, 0) == (0, 1, 0, 0)   # Z_A unchanged
    assert logical_cnot_action(0, 0, 0, 1) == (0, 1, 0, 1)   # Z_B -> Z_A Z_B
    assert logical_cnot_action(0, 0, 1, 0) == (0, 0, 1, 0)   # X_B unchanged


def test_the_pairing_is_a_bijection():
    """An unpaired or doubled data qubit is not a transversal operation."""
    pairs = transversal_cnot_pairs(3)
    assert len(pairs) == 9
    assert len({a for a, _ in pairs}) == 9
    assert len({b for _, b in pairs}) == 9


def test_the_pairing_uses_matching_local_indices():
    """Both patches share an orientation, which is what makes the identity map
    correct.  If one were reflected, this pairing would be wrong."""
    assert transversal_cnot_pairs(3) == [(i, i) for i in range(9)]


# ---------------------------------------------------------------------------
# Bell pair
# ---------------------------------------------------------------------------

def test_the_bell_pair_carries_no_pauli_frame():
    """Preparation is deterministic, so nothing is owed."""
    pair = prepare_logical_bell_pair()
    assert pair["frames"]["A"].is_identity
    assert pair["frames"]["B"].is_identity


def test_the_bell_pair_stabilisers_are_the_two_patch_products():
    pair = prepare_logical_bell_pair()
    assert pair["stabilisers"] == (("X", "A", "X", "B"), ("Z", "A", "Z", "B"))


@pytest.mark.parametrize("distance", [3, 5, 7])
def test_the_bell_operator_algebra_is_valid(distance):
    report = verify_bell_pair_operators(TwoPatchLayout(distance))
    assert report["valid"], report["problems"]


# ---------------------------------------------------------------------------
# Teleportation: the identities
# ---------------------------------------------------------------------------

def test_teleportation_is_the_identity_for_every_outcome():
    """The central identity, checked exhaustively rather than argued."""
    report = verify_teleportation_identity()
    assert report["identity_holds"], report["failures"]
    assert report["outcomes_checked"] == len(BELL_OUTCOME_CORRECTIONS) == 4


def test_an_incoming_error_arrives_intact():
    """Teleportation is the identity, so the error must pass through unchanged.

    Checked for every Pauli against every outcome.  A frame that absorbed errors
    would be worse than useless: it would report a clean state.
    """
    report = verify_error_propagation()
    assert report["propagation_exact"], report["failures"]
    assert report["cases_checked"] == 12


@pytest.mark.parametrize("outcome", sorted(BELL_OUTCOME_CORRECTIONS))
@pytest.mark.parametrize("error", [PAULI_I, PAULI_X, PAULI_Y, PAULI_Z])
def test_every_error_outcome_pair_propagates(outcome, error):
    frame, _ = teleportation_frame(outcome, error)
    assert frame.pauli == error


def test_the_trace_records_each_step():
    """The trace is what makes a wrong correction table visible as wrong."""
    _, info = teleportation_frame((1, 0), PAULI_Z)
    assert len(info["trace"]) == 3
    assert "input" in info["trace"][0]
    assert "outcome" in info["trace"][1]
    assert "correction" in info["trace"][2]


def test_an_invalid_outcome_is_rejected():
    with pytest.raises(SurfaceCodeError, match="outcome must be"):
        teleportation_frame((2, 0), PAULI_I)


def test_the_correction_table_covers_all_four_outcomes():
    assert set(BELL_OUTCOME_CORRECTIONS) == {(0, 0), (0, 1), (1, 0), (1, 1)}
    assert all(len(v) == 2 for v in BELL_OUTCOME_CORRECTIONS.values())


# ---------------------------------------------------------------------------
# Frame bookkeeping
# ---------------------------------------------------------------------------

def test_a_frame_accumulates_and_remembers_why():
    frame = LogicalPauliFrame(PAULI_I, [])
    frame.apply(PAULI_X, "first")
    frame.apply(PAULI_Z, "second")
    assert frame.pauli == PAULI_Y
    assert len(frame.history) == 2
    assert not frame.is_identity


def test_a_pauli_applied_twice_cancels_in_the_frame():
    frame = LogicalPauliFrame(PAULI_I, [])
    frame.apply(PAULI_Y, "error")
    frame.apply(PAULI_Y, "correction")
    assert frame.is_identity


def test_frame_describe_names_the_pauli():
    assert "X" in LogicalPauliFrame(PAULI_X, []).describe()
    assert pauli_name(PAULI_I) == "I"


def test_a_distance_below_two_is_rejected():
    with pytest.raises(SurfaceCodeError, match="at least 2"):
        TwoPatchLayout(1)
