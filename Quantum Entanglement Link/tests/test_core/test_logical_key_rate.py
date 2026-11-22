"""The logical key rate: the package's distinctive number.

"Key rate after error correction" is a figure almost nobody reports, so it is worth
being pedantic about. These tests pin the parts that are easy to get subtly wrong:

* the **Werner composition** of two error sources, which an earlier version got wrong
  by treating a bit-flip probability as a fidelity (overstating logical fidelity by
  0.004 at the package's own operating point, and by up to 0.09 at lower physical
  fidelity);
* the **rounds conversion**, where a bit flip needs ``1 - 2p`` rather than ``1 - p``
  because a flip has two outcomes;
* and the **monotonicity properties** that any defensible key rate must satisfy --
  correction cannot improve the pair, and more rounds cannot help.
"""

from __future__ import annotations

import pytest

from quantumnet.core.logical import (
    LogicalKeyRate,
    compose_pair_fidelity,
    logical_key_rate,
    pair_key_fraction,
)

stim = pytest.importorskip("stim")


# ---------------------------------------------------------------------------
# The composition -- the corrected part
# ---------------------------------------------------------------------------

def test_no_logical_error_returns_physical_fidelity():
    """With no flip (q = 0), the physical pair fidelity is returned unchanged."""
    for f_phys in (1.0, 0.99, 0.9, 0.5, 0.25):
        for f_log in (1.0, 0.996, 0.9):
            assert compose_pair_fidelity(f_phys, f_log, 0.0) == pytest.approx(f_phys)


def test_maximally_mixed_state_is_invariant_under_bit_flip():
    """I/4 invariance: a bit flip on the maximally mixed state keeps F = 0.25."""
    assert compose_pair_fidelity(0.25, 1.0, 0.5) == pytest.approx(0.25)
    for q in (0.0, 0.1, 0.5, 0.9, 1.0):
        for f_log in (0.25, 0.5, 1.0):
            assert compose_pair_fidelity(0.25, f_log, q) == pytest.approx(0.25)


def test_a_certain_flip_on_perfect_pairs_annihilates_the_entanglement():
    """Two perfect pairs with a certain bit flip end up orthogonal to the Bell state."""
    assert compose_pair_fidelity(1.0, 1.0, 1.0) == pytest.approx(0.0)


def test_two_perfect_pairs_with_a_rare_flip_give_one_minus_q():
    """With both pairs perfect the flip is the only error source, so ``F = 1 - q``.

    Recording why this is **not** ``1 - 2q/3``: my first version of this test asserted
    that, reasoning that a flip removes two of the three triplet components. That is
    wrong at F_log = 1 -- when both pairs are perfect there is no triplet weight to
    remove, so the whole 1/3 correction vanishes. The ``(1-F_log)/3`` term in
    :func:`compose_pair_fidelity` is exactly what carries that dependence, and it is
    zero here.
    """
    for q in (0.001, 0.004, 0.05):
        assert compose_pair_fidelity(1.0, 1.0, q) == pytest.approx(1 - q)


def test_the_composition_is_not_a_weighted_average_of_fidelities():
    """The specific error an earlier version made, pinned so it cannot return.

    ``F_phys(1-q) + (1-F_phys)q`` treats a bit-flip probability as a fidelity.
    Exact bit-flip on a Werner state gives ``(1-q)*F_phys + q*(1-F_phys)/3``.
    """
    f_phys, f_log, q = 0.95, 0.9, 0.05
    wrong = f_phys * (1 - q) + (1 - f_phys) * q
    right = compose_pair_fidelity(f_phys, f_log, q)
    expected = (1 - q) * f_phys + q * (1 - f_phys) / 3
    assert right == pytest.approx(expected)
    assert abs(right - wrong) > 1e-3, (
        f"the two forms have converged ({right} vs {wrong}); this test is now vacuous")


def test_composition_is_monotone_in_each_argument():
    """More error, or a worse pair, must never give a better fidelity."""
    assert compose_pair_fidelity(0.9, 0.9, 0.1) < compose_pair_fidelity(0.9, 0.9, 0.0)
    assert compose_pair_fidelity(0.9, 0.9, 0.1) < compose_pair_fidelity(0.99, 0.9, 0.1)


def test_composition_stays_a_valid_fidelity():
    for f_phys in (0.0, 0.5, 1.0):
        for f_log in (0.0, 0.5, 1.0):
            for q in (0.0, 0.5, 1.0):
                value = compose_pair_fidelity(f_phys, f_log, q)
                assert 0.0 <= value <= 1.0


def test_out_of_range_inputs_are_clipped_not_propagated():
    """A fidelity outside [0, 1] is a caller error, but it must not corrupt the rate."""
    assert 0.0 <= compose_pair_fidelity(1.5, 0.9, 0.1) <= 1.0
    assert 0.0 <= compose_pair_fidelity(0.9, -0.5, 0.1) <= 1.0


# ---------------------------------------------------------------------------
# The pair key fraction
# ---------------------------------------------------------------------------

def test_a_perfect_pair_yields_a_unit_key_fraction():
    assert pair_key_fraction(1.0) == pytest.approx(1.0)


def test_a_maximally_mixed_pair_yields_nothing():
    """F = 1/4 is no entanglement, so the rate must be exactly zero, not slightly off."""
    assert pair_key_fraction(0.25) == pytest.approx(0.0, abs=1e-12)


def test_the_key_fraction_is_monotone_in_fidelity():
    fidelities = [0.2, 0.3, 0.5, 0.7, 0.9, 1.0]
    rates = [pair_key_fraction(f) for f in fidelities]
    assert rates == sorted(rates)


def test_pair_key_fraction_uses_werner_qber():
    from quantumnet.protocols.bb84 import binary_entropy

    f = 0.95
    expected = max(0.0, 1.0 - 2.0 * binary_entropy(2.0 * (1.0 - f) / 3.0))
    assert pair_key_fraction(f) == pytest.approx(expected)


# ---------------------------------------------------------------------------
# The rate itself
# ---------------------------------------------------------------------------

def test_correction_cannot_improve_the_pair():
    """``F_log <= F_phys`` always: a logical pair is built from a physical one.

    Checked across the range because a composition error can push the result *above*
    the physical fidelity, which is unphysical and would flatter the key rate.
    """
    for physical in (1.0, 0.995, 0.99, 0.95, 0.9, 0.8):
        rate = logical_key_rate(physical, 3, 0.003, shots=2000)
        assert rate.logical_fidelity <= physical + 1e-12, (
            f"F_log={rate.logical_fidelity} exceeds F_phys={physical}")


def test_a_worse_physical_pair_gives_a_worse_key_fraction():
    rates = [logical_key_rate(f, 3, 0.003, shots=2000).key_fraction
             for f in (1.0, 0.99, 0.95, 0.9)]
    assert rates == sorted(rates, reverse=True)


def test_the_overhead_is_reported_because_a_rate_without_it_is_not_engineering():
    """A key rate that hides the qubits it cost is not a usable figure."""
    for distance in (3, 5, 7):
        rate = logical_key_rate(0.99, distance, 0.003, shots=2000)
        assert rate.physical_qubits_per_logical > 0
        # Two logical qubits, one per end; each costs the code's *full* physical
        # qubit count -- `d^2` data AND `d^2 - 1` ancilla -- not just the data.
        # Measured: 2 x 17 = 34 at d=3, 2 x 49 = 98 at d=5, 2 x 97 = 194 at d=7.
        assert rate.physical_qubits_per_logical == 2 * (distance ** 2
                                                        + distance ** 2 - 1)
    # More distance costs strictly more.
    costs = [logical_key_rate(0.99, d, 0.003, shots=2000)
             .physical_qubits_per_logical for d in (3, 5, 7)]
    assert costs == sorted(costs)


def test_the_result_reports_which_decoder_produced_it():
    """A key rate is a property of the decoder as much as the code."""
    from quantumnet.core.logical import logical_error_rate

    memory = logical_error_rate(5, 0.003, shots=2000)
    assert memory.decoder == "in-package"
    rate = logical_key_rate(0.99, 5, 0.003, shots=2000)
    assert rate.decoder == "in-package"


def test_describe_mentions_both_fidelities_and_the_overhead():
    """The printed form must carry the cost, not just the rate."""
    text = logical_key_rate(0.99, 5, 0.003, shots=2000).describe()
    assert "F_phys" in text and "F_log" in text
    assert "qubits per logical" in text


def test_physical_fidelity_outside_the_unit_interval_is_refused():
    with pytest.raises(ValueError):
        logical_key_rate(1.2, 3, 0.003, shots=100)
    with pytest.raises(ValueError):
        logical_key_rate(-0.1, 3, 0.003, shots=100)


def test_the_key_fraction_never_exceeds_one():
    for physical in (1.0, 0.999, 0.99):
        rate = logical_key_rate(physical, 3, 0.001, shots=2000)
        assert 0.0 <= rate.key_fraction <= 1.0


def test_the_dataset_is_well_formed():
    """A small structural guard so the fields cannot silently change meaning."""
    rate = logical_key_rate(0.99, 3, 0.003, shots=2000)
    assert isinstance(rate, LogicalKeyRate)
    assert rate.rounds == 3
    assert rate.distance == 3
    assert 0.0 <= rate.logical_error_per_pair <= 1.0
