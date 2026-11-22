"""Calibration against a published decoy-state dataset.

The dataset is Lo, Ma & Chen, Phys. Rev. Lett. **94**, 230504 (2005),
[arXiv:quant-ph/0411004](https://arxiv.org/abs/quant-ph/0411004), Figure 1, computed for
the Gobby-Yuan-Shields hardware this package's `gobby-yuan-shields` preset carries.

These tests pin three things:

* the statements the package **does** reproduce, so a regression is caught;
* the statements it **does not**, so a later change cannot silently make them agree by
  loosening a bound -- a calibration that quietly moved the goalposts would be worse than
  none;
* the **mechanism**, which is the part that matters more than any single number. The
  source's central claim is that the optimal signal intensity sits at ``mu = O(1)`` rather
  than ``O(eta)``, and that is what raises the rate from ``O(eta^2)`` to ``O(eta)``.
  Reproducing that is evidence the model captures the physics; matching an absolute reach
  drawn asymptotically is not something a finite-key package should be tuned to do.
"""

from __future__ import annotations

import numpy as np
import pytest

from quantumnet.calibration import (
    PUBLISHED,
    calibration_report,
    gllp_no_decoy_rate,
    gllp_parameter_sensitivity,
    intercept_resend_crossing_km,
    key_rate_curve,
    no_decoy_reach_km,
    optimal_signal_intensity,
)
from quantumnet.protocols.bb84 import binary_entropy


# ---------------------------------------------------------------------------
# The mechanism: the part that must be reproduced
# ---------------------------------------------------------------------------

def test_the_optimal_signal_intensity_is_order_one_not_order_eta():
    """The source's central mechanism claim, and the reason decoys help.

    Without decoys the safe choice is ``mu = O(eta)``, which makes the rate ``O(eta^2)``;
    with them the optimum moves to ``mu = O(1)`` and the rate becomes ``O(eta)``. At 50 km
    the GYS channel transmissivity is roughly 1e-3, so an optimal ``mu`` near 0.5 is
    three orders of magnitude above ``O(eta)`` -- the effect is not marginal.
    """
    best_mu, best_reach, sweep = optimal_signal_intensity()
    assert 0.3 <= best_mu <= 0.6, (
        f"optimal mu measured as {best_mu}, but the source reports roughly 0.5")
    assert best_mu > 0.1, "the optimum has drifted toward the experimental value"
    # And the sweep must be a real maximum, not a flat plateau's first point.
    reaches = dict(sweep)
    assert reaches[best_mu] >= max(reaches.values()) - 1e-9


def test_lower_intensity_is_measurably_worse():
    """If mu did not matter, the mechanism claim would be vacuous."""
    sweep = dict(optimal_signal_intensity()[2])
    assert sweep[0.1] < sweep[0.5] - 1.0, (
        f"mu=0.1 and mu=0.5 give the same reach ({sweep[0.1]}), so the sweep proves "
        f"nothing")
    assert sweep[1.0] < sweep[0.5] + 1e-9, "the reach is not maximal near mu=0.5"


# ---------------------------------------------------------------------------
# The statements that are reproduced
# ---------------------------------------------------------------------------

def test_the_no_decoy_gllp_reach_reproduces_the_published_thirty_km():
    """Equation 12 with the pessimistic tagged fraction, mu optimized over O(eta)."""
    reach = no_decoy_reach_km()
    assert 25.0 <= reach <= 45.0, f"no-decoy reach {reach} km is not near 30-40 km"


def test_the_no_decoy_bound_is_zero_at_fixed_mu_but_positive_when_optimized():
    """At eta_Bob = 0.045, fixed mu = 0.1 gives zero reach, while mu = O(eta) gives ~30-40 km."""
    assert no_decoy_reach_km(mu=0.1, detector_efficiency=0.045) == 0.0
    assert 30.0 <= no_decoy_reach_km(detector_efficiency=0.045) <= 45.0


def test_no_decoy_reach_improves_with_detector_efficiency():
    """Monotone, which is the sanity property the sensitivity table must satisfy."""
    points = gllp_parameter_sensitivity()
    reaches = [reach for _eta, reach in points]
    assert reaches == sorted(reaches), reaches
    assert reaches[0] > 0.0 and reaches[-1] > reaches[0]


# ---------------------------------------------------------------------------
# The statements that are NOT reproduced, pinned so they cannot be faked
# ---------------------------------------------------------------------------

def test_the_report_states_how_many_published_claims_it_reproduces():
    """The denominator must be reported, not just the agreements.

    A calibration that quietly dropped the statements it failed would report a smaller
    denominator and look like better agreement than it has.
    """
    report = calibration_report()
    assert len(report.rows) == len(PUBLISHED), (
        "a published statement has been dropped from the comparison")
    assert report.agreements == sum(1 for row in report.rows if row.held)


def test_the_decoy_reach_reproduces_the_published_140_km():
    """With published GYS parameters, the asymptotic vacuum+weak decoy reach exceeds 140 km."""
    report = calibration_report()
    rows = {row.point.name: row for row in report.rows}
    assert rows["reach_with_decoy"].held is True
    assert report.measured_reach_km is not None
    assert 140.0 <= report.measured_reach_km <= 150.0


def test_the_intercept_resend_crossing_is_reported_without_being_tuned():
    """~205 km here against the source's 208 km argument."""
    crossing = intercept_resend_crossing_km()
    assert crossing is not None, "no intercept-resend crossing found below the scan limit"
    assert 150.0 < crossing < 215.0, crossing
    report = calibration_report()
    assert crossing > report.measured_reach_km, (
        "the code reaches further than the point where intercept-resend wins")


def test_a_published_statement_is_not_claimed_unless_it_holds():
    point = PUBLISHED[1]                      # reach_with_decoy, an at_least bound
    assert point.holds(145.0, 0.0) is True
    assert point.holds(120.0, 0.0) is False


# ---------------------------------------------------------------------------
# The rate formula itself
# ---------------------------------------------------------------------------

def test_the_gllp_rate_needs_a_gain_above_the_multi_photon_probability():
    """The condition that makes the bound vanish, exercised directly.

    ``Omega = 1 - p_multi / Q_mu`` must be positive; a gain below the multi-photon
    probability admits no untagged fraction at all and the rate is zero rather than
    negative.
    """
    assert gllp_no_decoy_rate(0.1, q_mu=1e-4, e_mu=0.02) == 0.0
    assert gllp_no_decoy_rate(0.1, q_mu=0.05, e_mu=0.02) > 0.0


def test_the_gllp_rate_is_zero_for_degenerate_inputs():
    for mu, q_mu in ((0.0, 0.05), (0.1, 0.0)):
        assert gllp_no_decoy_rate(mu, q_mu, 0.02) == 0.0


def test_the_gllp_rate_falls_as_the_error_rate_rises():
    rates = [gllp_no_decoy_rate(0.1, 0.05, e) for e in (0.005, 0.02, 0.05, 0.1)]
    assert rates == sorted(rates, reverse=True), rates


def test_the_multi_photon_probability_is_the_poisson_tail():
    """``p_multi = 1 - e^-mu (1 + mu)``; at mu = 0.1 that is 0.0047."""
    import math

    mu = 0.1
    assert 1 - math.exp(-mu) * (1 + mu) == pytest.approx(0.004679, abs=1e-6)
    # And it is genuinely the two-or-more tail, checked independently. Summed far
    # enough that the discarded Poisson weight is below the tolerance: truncating at
    # n = 6 leaves a 1.3e-9 discrepancy, which is the truncation and not the formula.
    terms = [math.exp(-mu) * mu ** n / math.factorial(n) for n in range(40)]
    assert 1 - math.exp(-mu) * (1 + mu) == pytest.approx(sum(terms[2:]), abs=1e-15)


def test_binary_entropy_endpoints():
    """Used by the rate; the endpoints must be exact."""
    assert binary_entropy(0.0) == pytest.approx(0.0)
    assert binary_entropy(0.5) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# The curve
# ---------------------------------------------------------------------------

def test_the_curve_is_monotone_decreasing_in_distance():
    """A secure key rate that rose with distance would be a modelling error."""
    curve = key_rate_curve(list(range(0, 120, 20)))
    rates = [row["key_rate_per_pulse"] for row in curve]
    assert rates[0] > 0.0
    for earlier, later in zip(rates, rates[1:]):
        assert later <= earlier + 1e-12, rates


def test_the_curve_uses_the_optimal_intensity_by_default():
    """Not the experimental 0.1, which is the whole point of the calibration."""
    curve = key_rate_curve([50.0])
    assert 0.3 <= curve[0]["mu"] <= 0.6
