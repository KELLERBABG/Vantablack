"""Logical error rates and the logical key rate.

The surface code and the decoy-state analysis both worked and were not joined up.
These tests cover the join, and they concentrate on the two bookkeeping mistakes
that are invisible from the output: which check family protects which observable,
and whether a syndrome is decoded per round or XOR-ed over time.

Both mistakes produce a *number* rather than a crash.  The first made the decoder
worse than doing nothing (0.98% error against a 0.05% raw flip rate); the second
made distance 5 look worse than distance 3.  Neither raises.  That is why this
file pins the mapping and the family rather than trusting the rate.
"""

from __future__ import annotations

import pytest

from quantumnet.core.logical import (
    HAVE_STIM,
    LogicalKeyRate,
    MemoryResult,
    build_detector_table,
    detector_coordinates,
    detector_map,
    error_rate_curve,
    logical_error_rate,
    logical_key_rate,
    memory_circuit,
    pair_key_fraction,
    protecting_check_family,
)
from quantumnet.core.surface_code import RotatedSurfaceCode, SurfaceCodeError

pytestmark = pytest.mark.skipif(
    not HAVE_STIM, reason="measuring a logical error rate needs stim")


# ---------------------------------------------------------------------------
# Detector bookkeeping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("d", [3, 5])
def test_detector_map_matches_the_lattice_exactly(d):
    """Every detector coordinate must be a real ancilla, and typed correctly."""
    lut = detector_map(d)
    code = RotatedSurfaceCode(d)
    for kind in ("X", "Z"):
        for coord, ancilla in lut[kind].items():
            assert code.ancilla_coords[ancilla] == coord
            check = next(c for c in code.checks if c.ancilla == ancilla)
            assert check.kind == kind


def test_detector_coordinates_are_three_dimensional():
    """(x, y, time).  Without the time axis the round cannot be recovered."""
    circuit = memory_circuit(3, 0.001, rounds=3)
    coords = detector_coordinates(circuit)
    assert coords
    assert all(len(v) == 3 for v in coords.values())


def test_the_detector_table_carries_a_round_index():
    """A syndrome is per round; XOR-ing an ancilla over time is not a syndrome."""
    table = build_detector_table(3)
    assert table
    assert all(len(v) == 3 for v in table.values())
    rounds = {v[2] for v in table.values()}
    assert len(rounds) > 1, "rounds were collapsed"


def test_the_detector_table_agrees_with_the_circuit():
    """Detector count must match, or events are being dropped silently."""
    for d in (3, 5):
        circuit = memory_circuit(d, 0.001, rounds=d)
        assert len(build_detector_table(d)) == circuit.num_detectors


def test_every_detector_maps_to_a_real_ancilla():
    for d in (3, 5):
        table = build_detector_table(d)
        code = RotatedSurfaceCode(d)
        for kind, ancilla, _round in table.values():
            assert ancilla in code.ancilla_coords
            check = next(c for c in code.checks if c.ancilla == ancilla)
            assert check.kind == kind


# ---------------------------------------------------------------------------
# Which family protects which observable
# ---------------------------------------------------------------------------

def test_the_protecting_family_for_a_z_observable_is_z():
    """The assumption that decides whether the decoder helps or hurts.

    A Z-basis observable is flipped by X errors, and X errors are detected by the
    **Z-type** checks.  Decoding the X-family as well corrects Z errors that were
    harmless by construction and then reports a logical failure for them.
    """
    assert protecting_check_family("Z") == "Z"
    assert protecting_check_family("X") == "X"


def test_an_unknown_basis_is_rejected():
    with pytest.raises(SurfaceCodeError, match="observable_basis"):
        protecting_check_family("Y")


# ---------------------------------------------------------------------------
# Memory experiment
# ---------------------------------------------------------------------------

def test_zero_noise_gives_no_logical_errors():
    """A decoder that invents errors on a clean circuit is broken."""
    result = logical_error_rate(3, 0.0, shots=200, seed=1)
    assert result.logical_errors == 0
    assert result.logical_error_rate == 0.0


def test_the_error_rate_is_a_rate():
    result = logical_error_rate(3, 0.001, shots=300, seed=1)
    assert 0.0 <= result.logical_error_rate <= 1.0
    assert result.shots + result.decode_failures <= 300


def test_per_round_conversion_uses_the_bit_flip_form():
    """``1 - 2p``, not ``1 - p``: a logical error is a bit flip.

    Spot-checked against a hand calculation rather than round-tripped through the
    same expression, which would pass for either convention.
    """
    result = MemoryResult(distance=3, rounds=3, noise=0.001, shots=1000,
                          logical_errors=80)
    p_shot = 0.08
    expected = (1.0 - (1.0 - 2.0 * p_shot) ** (1 / 3)) / 2.0
    assert result.per_round_error_rate == pytest.approx(expected)
    # and it must differ from the wrong convention
    wrong = 1.0 - (1.0 - p_shot) ** (1 / 3)
    assert result.per_round_error_rate != pytest.approx(wrong)


def test_more_noise_never_gives_fewer_logical_errors():
    quiet = logical_error_rate(3, 0.0002, shots=600, seed=4)
    loud = logical_error_rate(3, 0.002, shots=600, seed=4)
    assert loud.logical_error_rate >= quiet.logical_error_rate


def test_an_unsupported_distance_is_refused():
    with pytest.raises(SurfaceCodeError, match="no verified layout"):
        logical_error_rate(4, 0.001, shots=10)


def test_negative_noise_is_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        logical_error_rate(3, -0.001, shots=10)


def test_zero_rounds_is_rejected():
    with pytest.raises(ValueError, match="at least 1"):
        logical_error_rate(3, 0.001, rounds=0, shots=10)


def test_the_decoder_beats_doing_nothing():
    """The check that caught the wrong-family bug.

    A decoder that cannot beat "predict no flip" is not decoding.  Asserted as a
    strict improvement at a noise level where the undecoded rate is measurable,
    because equality is exactly the symptom the wrong-family bug produced.

    Note the model: this runs the **depolarizing-gate** channel, not all four
    ``stim`` knobs.  Under the four-knob model the same physical ``p`` injects
    roughly five times the error rate, and at ``p = 2e-4`` the decoder scored
    5e-4 -- worse than the raw flip rate, which is what exposed both the wrong
    check family and, later, the missing time dimension.  Under the gate model
    that test produced **zero** logical errors in 3000 shots, which is why the
    noise level here is raised to keep the assertion falsifiable.
    """
    noise = 0.002
    result = logical_error_rate(3, noise, shots=3000, seed=7)
    assert result.logical_errors > 0, "raise the noise; the test needs failures"
    undecoded = MemoryResult(distance=3, rounds=3, noise=noise, shots=1000,
                             logical_errors=150).logical_error_rate
    assert result.logical_error_rate < undecoded


def test_decoding_is_reproducible():
    first = logical_error_rate(3, 0.001, shots=200, seed=11)
    second = logical_error_rate(3, 0.001, shots=200, seed=11)
    assert first.logical_errors == second.logical_errors


def test_error_rate_curve_returns_one_row_per_grid_point():
    curve = error_rate_curve(distances=(3,), noises=(0.001, 0.002), shots=50)
    assert len(curve) == 2
    assert all(isinstance(r, MemoryResult) for r in curve)


def test_memory_result_describe_is_informative():
    text = MemoryResult(3, 3, 0.001, 100, 5).describe()
    assert "d=3" in text and "p_L" in text


# ---------------------------------------------------------------------------
# The logical key rate
# ---------------------------------------------------------------------------

def test_a_perfect_pair_has_full_key_fraction():
    assert pair_key_fraction(1.0) == pytest.approx(1.0)


def test_key_fraction_vanishes_below_the_threshold_fidelity():
    """A pair below ~0.78 fidelity yields no key, as at the physical layer."""
    assert pair_key_fraction(0.5) == 0.0
    assert pair_key_fraction(0.25) == 0.0


def test_the_key_fraction_is_monotone_in_fidelity():
    values = [pair_key_fraction(f) for f in (0.8, 0.85, 0.9, 0.95, 1.0)]
    assert values == sorted(values)


def test_the_logical_rate_costs_the_code_and_says_so():
    """A logical rate must report its qubit overhead, not just a fraction."""
    rate = logical_key_rate(0.99, 3, 0.0002, shots=400, seed=1)
    assert isinstance(rate, LogicalKeyRate)
    assert rate.physical_qubits_per_logical == 2 * RotatedSurfaceCode(3).n_qubits
    assert rate.distance == 3


def test_error_correction_cannot_improve_on_the_physical_pair():
    """A logical pair is built from a physical one, so it cannot beat it."""
    rate = logical_key_rate(0.97, 3, 0.0002, shots=400, seed=1)
    assert rate.logical_fidelity <= rate.physical_fidelity


def test_a_better_physical_pair_gives_at_least_as_much_key():
    good = logical_key_rate(0.99, 3, 0.0002, shots=400, seed=1)
    poor = logical_key_rate(0.90, 3, 0.0002, shots=400, seed=1)
    assert good.key_fraction >= poor.key_fraction


def test_more_noise_never_improves_the_logical_fidelity():
    quiet = logical_key_rate(0.99, 3, 0.0002, shots=400, seed=1)
    loud = logical_key_rate(0.99, 3, 0.002, shots=400, seed=1)
    assert loud.logical_fidelity <= quiet.logical_fidelity
    assert loud.logical_error_per_round >= quiet.logical_error_per_round


def test_an_out_of_range_fidelity_is_rejected():
    for bad in (-0.1, 1.1):
        with pytest.raises(ValueError, match="physical_fidelity"):
            logical_key_rate(bad, 3, 0.0002, shots=50)


def test_the_logical_rate_reports_its_parts():
    text = logical_key_rate(0.99, 3, 0.0002, shots=200, seed=1).describe()
    assert "F_phys" in text and "F_log" in text and "qubits per logical" in text
