"""Memory-decay models: single qubit versus entangled pair.

These two cases have different fidelity floors, and conflating them produces a
model with unphysical behaviour.

* A single qubit relaxing to ``I/2`` has fidelity asymptoting to **0**.
* A Bell pair relaxing to ``I/4`` has fidelity asymptoting to **1/4**, because
  ``<Φ+|I/4|Φ+> = 1/4`` for every Bell state.

The measured facts about the old single-qubit function, which is what makes the
distinction matter:

* Its asymptote is ``2*f0 - 1``, not 0.  At ``f0 = 1`` it returns 1 forever, and
  at ``f0 = 0.3`` it runs to ``-0.4``.
* It therefore produces **negative fidelities** for any ``f0 < 0.5``, which is
  not a state.

Applying that function to a stored *entangled pair* -- as the distribution paths
did -- gives decay that is wrong in both directions: it destroys fidelity that
the pair should keep down to a floor of 1/4, and (below f0 = 0.5) it reports
fidelities no density matrix can have.
"""

from __future__ import annotations

import numpy as np
import pytest

from quantumnet.core.physical import (
    bell_pair_fidelity_after_dt,
    memory_fidelity_after_dt,
)


# ---------------------------------------------------------------------------
# The single-qubit model: its real behaviour, documented
# ---------------------------------------------------------------------------

def test_single_qubit_model_is_monotone_decreasing():
    for f0 in (0.3, 0.5, 0.9, 1.0):
        values = [memory_fidelity_after_dt(f0, t, 1.0, 1.0)
                  for t in (0.0, 0.1, 0.5, 1.0, 2.0, 5.0)]
        assert all(a >= b for a, b in zip(values, values[1:]))


def test_single_qubit_model_asymptote_is_two_f0_minus_one():
    """The documented asymptote, measured rather than assumed.

    This is *not* zero unless ``f0 = 0.5``.  Called out explicitly because the
    natural assumption -- "fidelity decays to zero" -- is wrong here, and the
    consequence is that this function cannot be borrowed for other objects.
    """
    for f0 in (0.3, 0.5, 0.9, 1.0):
        far = memory_fidelity_after_dt(f0, 1e9, 1.0, 1.0)
        assert far == pytest.approx(2.0 * f0 - 1.0, abs=1e-6)


def test_single_qubit_model_goes_negative_below_half():
    """It is not a valid fidelity for f0 < 0.5. Do not use it there."""
    got = memory_fidelity_after_dt(0.3, 10.0, 1.0, 1.0)
    assert got < 0.0


def test_single_qubit_identity_without_noise():
    assert memory_fidelity_after_dt(0.8, 1e6, 0.0, 0.0) == pytest.approx(0.8)
    assert memory_fidelity_after_dt(0.8, 0.0, 5.0, 5.0) == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# The pair model
# ---------------------------------------------------------------------------

def test_pair_fidelity_floor_is_one_quarter():
    """No amount of memory noise can push a Bell pair's fidelity below 1/4."""
    for f0 in (1.0, 0.9, 0.5, 0.3):
        f = bell_pair_fidelity_after_dt(f0, 1e9, t1=1.0, t2=1.0)
        assert f == pytest.approx(0.25, abs=1e-9)


def test_pair_fidelity_is_monotone_decreasing_for_every_valid_f0():
    for f0 in (0.9, 0.6, 0.5, 0.4, 0.3, 0.26):
        values = [bell_pair_fidelity_after_dt(f0, t, t1=1.0, t2=1.0)
                  for t in (0.0, 0.5, 1.0, 3.0, 10.0, 100.0)]
        assert all(a >= b - 1e-15 for a, b in zip(values, values[1:])), (
            f"f0={f0} gained fidelity with age: {values}"
        )
        assert all(v >= 0.25 - 1e-12 for v in values), (
            f"f0={f0} fell below the 1/4 floor: {values}"
        )


def test_pair_model_never_reports_a_negative_fidelity():
    for f0 in (0.26, 0.3, 0.5, 0.9):
        for t in (0.0, 1.0, 1e3, 1e9):
            assert bell_pair_fidelity_after_dt(f0, t, 1.0, 1.0) >= 0.25 - 1e-12


def test_the_old_model_was_unphysical_where_the_new_one_is_not():
    """Document the specific defect so the fix cannot be silently reverted.

    At ``f0 = 0.3`` the single-qubit model reports a negative fidelity while the
    pair model stays inside ``[1/4, f0]``.
    """
    f0, dt = 0.3, 10.0
    assert memory_fidelity_after_dt(f0, dt, 1.0, 1.0) < 0.0
    pair = bell_pair_fidelity_after_dt(f0, dt, 1.0, 1.0)
    assert 0.25 <= pair <= f0


def test_pair_fidelity_preserved_at_zero_time():
    for f0 in (0.25, 0.3, 0.5, 0.75, 1.0):
        assert bell_pair_fidelity_after_dt(f0, 0.0, 1.0, 1.0) == pytest.approx(f0)


def test_pair_model_agrees_with_werner_parameter_decay():
    """F = (1 + 3*W0*exp(-t/T1)*exp(-t/T2)) / 4, checked directly."""
    f0, dt, t1, t2 = 0.8, 2.0, 3.0, 5.0
    w0 = (4 * f0 - 1) / 3
    expected = (1 + 3 * w0 * np.exp(-dt / t1) * np.exp(-dt / t2)) / 4
    assert bell_pair_fidelity_after_dt(f0, dt, t1, t2) == pytest.approx(expected)


def test_decay_composes_with_entanglement_swapping():
    """The same W must be what swapping multiplies, or the models disagree.

    This is the property that makes the pair model the right one for a network:
    memory decay and entanglement swapping are expressed in one parameter.
    """
    from quantumnet.topology.routing import swapped_fidelity

    f_a = bell_pair_fidelity_after_dt(0.9, 1.0, t1=2.0, t2=2.0)
    f_b = bell_pair_fidelity_after_dt(0.9, 1.0, t1=2.0, t2=2.0)
    swapped = swapped_fidelity(f_a, f_b)

    w = ((4 * 0.9 - 1) / 3) * np.exp(-1.0 / 2.0) * np.exp(-1.0 / 2.0)
    assert swapped == pytest.approx((1 + 3 * w * w) / 4)


def test_pair_model_clamps_out_of_range_input():
    """A fidelity above 1 or below 1/4 is not a state; do not propagate it."""
    assert bell_pair_fidelity_after_dt(1.5, 0.0, 1.0, 1.0) == pytest.approx(1.0)
    assert bell_pair_fidelity_after_dt(0.1, 0.0, 1.0, 1.0) == pytest.approx(0.25)
    assert bell_pair_fidelity_after_dt(-1.0, 1.0, 1.0, 1.0) == pytest.approx(0.25)
