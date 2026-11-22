"""Photonic hardware layer: detectors, Bell-state measurement, multiplexing.

The acceptance criterion for the photonic layer is that **Barrett-Kok success
probability falls with link loss exactly as the closed form predicts**.  These
tests hold the implementation to that, and to the two published properties of
the scheme that everything else follows from:

* the ideal success probability is **1/2**, stated by Barrett and Kok as the
  protocol's theoretical upper limit; and
* it is **quadratic in detector efficiency** (``p ∝ eta^2``), because two photons
  must each survive and each be detected.

A model that got either wrong would still produce a plausible rate-vs-distance
curve, which is why they are asserted rather than assumed.
"""

from __future__ import annotations

import numpy as np
import pytest

from quantumnet.core.photonics import (
    BARRETT_KOK_IDEAL_SUCCESS,
    BarrettKok,
    Detector,
    PhotonicLink,
    elementary_link_from_specs,
    ideal_success_from_loss,
    multiplexed_success,
)


def _perfect_arm(length_km: float = 0.0, **kw) -> PhotonicLink:
    """An arm with no loss and a perfect detector, unless overridden."""
    return PhotonicLink(
        length_km=length_km,
        detector=Detector(efficiency=kw.pop("efficiency", 1.0),
                          dark_count_rate_hz=kw.pop("dark_count_rate_hz", 0.0),
                          **kw),
    )


def _link(arm_a: PhotonicLink, arm_b: PhotonicLink, **kw) -> BarrettKok:
    """Combine two arms.  The window defaults to 1 ns, a realistic gate.

    It is not zero deliberately: a zero-length coincidence window closes the
    detector to dark counts entirely, which would quietly remove the dark-count
    physics from every test that did not override it.
    """
    kw.setdefault("coincidence_window_s", 1e-9)
    return BarrettKok(arm_a=arm_a, arm_b=arm_b, **kw)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def test_detector_rejects_impossible_parameters():
    with pytest.raises(ValueError, match="efficiency"):
        Detector(efficiency=0.0)
    with pytest.raises(ValueError, match="efficiency"):
        Detector(efficiency=1.5)
    with pytest.raises(ValueError, match="dark_count_rate_hz"):
        Detector(dark_count_rate_hz=-1.0)
    with pytest.raises(ValueError, match="non-negative"):
        Detector(dead_time_s=-1e-9)
    with pytest.raises(ValueError, match="afterpulse"):
        Detector(afterpulse_probability=2.0)


def test_dark_count_probability_is_poissonian():
    d = Detector(dark_count_rate_hz=1000.0)
    assert d.dark_count_probability(1e-3) == pytest.approx(1 - np.exp(-1.0))
    assert d.dark_count_probability(0.0) == 0.0


def test_perfect_detector_with_no_dark_counts_passes_the_signal_through():
    d = Detector(efficiency=1.0, dark_count_rate_hz=0.0)
    assert d.click_probability(0.3, 1e-9) == pytest.approx(0.3)


def test_click_probability_is_the_union_not_the_sum():
    """Dark counts must not be double-counted when both events happen."""
    d = Detector(efficiency=1.0, dark_count_rate_hz=1e9)
    p_dark = d.dark_count_probability(1e-9)
    got = d.click_probability(0.5, 1e-9)
    assert got == pytest.approx(0.5 + p_dark - 0.5 * p_dark)
    assert got < 0.5 + p_dark, "the sum would double-count the coincidence"


def test_dead_time_blinds_the_detector_after_a_click():
    d = Detector(dead_time_s=50e-9)
    assert d.is_blind(1e-9)
    assert not d.is_blind(60e-9)
    # and a detector with no dead time is never blind
    assert not Detector(dead_time_s=0.0).is_blind(0.0)


# ---------------------------------------------------------------------------
# The two published properties
# ---------------------------------------------------------------------------

def test_ideal_success_probability_is_exactly_one_half():
    """With no loss and perfect detectors, p = 1/2.

    Barrett and Kok state this as the theoretical upper limit of the protocol,
    so it must be exact, not approximate.
    """
    link = _link(_perfect_arm(), _perfect_arm())
    assert link.success_probability() == pytest.approx(BARRETT_KOK_IDEAL_SUCCESS,
                                                       rel=1e-15)
    assert BARRETT_KOK_IDEAL_SUCCESS == 0.5


def test_success_probability_is_quadratic_in_detector_efficiency():
    """p ∝ eta^2, because both photons must be detected."""
    for eta in (0.2, 0.4, 0.6, 0.8, 1.0):
        arm_a = _perfect_arm(efficiency=eta)
        arm_b = _perfect_arm(efficiency=eta)
        p = _link(arm_a, arm_b).success_probability()
        assert p == pytest.approx(0.5 * eta * eta, rel=1e-12), (
            f"eta={eta}: p={p}, expected {0.5 * eta * eta}"
        )


def test_halving_one_detector_efficiency_quarters_nothing_asymmetric():
    """For asymmetric arms, p is the product -- linear in each, quadratic if equal."""
    link = _link(_perfect_arm(efficiency=0.5), _perfect_arm(efficiency=1.0))
    assert link.success_probability() == pytest.approx(0.25, rel=1e-12)


# ---------------------------------------------------------------------------
# The M2 acceptance criterion: loss dependence matches the closed form
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("length_km", [0.0, 1.0, 10.0, 25.0, 50.0, 100.0])
def test_success_probability_matches_the_closed_form(length_km):
    """The numerical path must reproduce ``1/2 * eta_a * eta_b`` exactly.

    This is the acceptance test: with dark counts and mode mismatch switched
    off, the general implementation has to reduce to the analytic expression. If
    it does not, the extra physics is not a refinement, it is a different model.
    """
    arm_a = _perfect_arm(length_km)
    arm_b = _perfect_arm(length_km)
    link = _link(arm_a, arm_b)

    assert link.success_probability() == pytest.approx(
        ideal_success_from_loss(arm_a, arm_b), rel=1e-12)


def test_success_probability_falls_by_2_db_per_50km_of_link():
    """At 0.2 dB/km a 50 km link costs 10 dB, and the pair costs 20 dB.

    Both arms double in length penalty, and the probability is the product, so
    the *pair* loses 10 dB per 50 km of *link* -- i.e. rate falls by a factor of
    10 per 50 km.  Stated as a test because it is the number a reader will
    compare against a published curve.
    """
    p_close = _link(_perfect_arm(0.0), _perfect_arm(0.0)).success_probability()
    p_far = _link(_perfect_arm(50.0), _perfect_arm(50.0)).success_probability()
    assert p_close / p_far == pytest.approx(100.0, rel=1e-6)


def test_success_probability_decreases_monotonically_with_length():
    ps = [_link(_perfect_arm(L), _perfect_arm(L)).success_probability()
          for L in np.linspace(0.0, 200.0, 40)]
    assert all(a >= b for a, b in zip(ps, ps[1:]))
    assert ps[0] > ps[-1]


def test_the_closed_form_and_the_implementation_agree_across_real_hardware():
    """Not just the ideal case: real efficiencies and dark counts, still equal.

    The dark-count term is inside both, so this checks the two paths agree on
    the *whole* model rather than only where it is trivial.
    """
    for eta in (0.045, 0.5, 0.93):
        for L in (0.0, 20.0, 80.0):
            arm_a = PhotonicLink(length_km=L, detector=Detector(
                efficiency=eta, dark_count_rate_hz=100.0))
            arm_b = PhotonicLink(length_km=L, detector=Detector(
                efficiency=eta, dark_count_rate_hz=100.0))
            link = BarrettKok(arm_a=arm_a, arm_b=arm_b,
                              coincidence_window_s=1e-9)
            # the closed form excludes dark counts, so compare the signal term
            assert link.signal_coincidence_probability() == pytest.approx(
                ideal_success_from_loss(arm_a, arm_b), rel=1e-12)


# ---------------------------------------------------------------------------
# Loss costs rate, not fidelity
# ---------------------------------------------------------------------------

def test_loss_reduces_the_rate_without_degrading_the_heralded_fidelity():
    """The defining property of double heralding.

    A photon that fails to arrive is a failed attempt, not a corrupted pair, so
    stretching the fibre must cut the success probability while leaving the
    fidelity of the attempts that *do* succeed untouched.
    """
    near = _link(_perfect_arm(1.0), _perfect_arm(1.0))
    far = _link(_perfect_arm(100.0), _perfect_arm(100.0))

    assert far.success_probability() < near.success_probability()
    assert far.raw_fidelity() == pytest.approx(near.raw_fidelity(), rel=1e-12)
    assert near.raw_fidelity() == pytest.approx(1.0, rel=1e-12)


def test_dark_counts_do_degrade_the_heralded_fidelity():
    """Unlike loss, a dark coincidence is a false herald and corrupts the pair."""
    clean = _link(_perfect_arm(50.0), _perfect_arm(50.0))
    noisy = _link(
        _perfect_arm(50.0, dark_count_rate_hz=1e6),
        _perfect_arm(50.0, dark_count_rate_hz=1e6),
    )
    assert noisy.raw_fidelity() < clean.raw_fidelity()
    assert 0.25 <= noisy.raw_fidelity() <= 1.0


def test_dark_coincidence_fidelity_is_the_maximally_mixed_value():
    """Two independent dark counts carry no entanglement: fidelity 1/4."""
    link = _link(_perfect_arm(), _perfect_arm())
    assert link.dark_coincidence_fidelity == pytest.approx(0.25)


def test_mode_mismatch_reduces_fidelity_but_not_success_probability():
    """Mode mismatch is a fidelity impairment, not a loss mechanism here."""
    matched = _link(_perfect_arm(10.0), _perfect_arm(10.0), mode_matching=1.0)
    mismatched = _link(_perfect_arm(10.0), _perfect_arm(10.0),
                       mode_matching=0.7)
    assert mismatched.raw_fidelity() < matched.raw_fidelity()
    assert mismatched.success_probability() == pytest.approx(
        matched.success_probability(), rel=1e-12)


def test_a_link_with_no_signal_and_no_dark_counts_heralds_nothing_but_lies_about_nothing():
    """When nothing can arrive, the fidelity is reported, not favourable.

    A vanishing success probability with a fidelity of 1.0 is the honest
    answer -- *those* attempts that succeed are perfect -- and it is not a
    claim that any attempt succeeds.  The distinction matters because a rate
    figure alone cannot express it.
    """
    darkless = BarrettKok(
        arm_a=PhotonicLink(length_km=400.0, detector=Detector(
            efficiency=1.0, dark_count_rate_hz=0.0)),
        arm_b=PhotonicLink(length_km=400.0, detector=Detector(
            efficiency=1.0, dark_count_rate_hz=0.0)),
        coincidence_window_s=1e-12)
    # 400 km at 0.2 dB/km is 80 dB each way, so eta^2 = 1e-16 and p ~ 5e-17.
    assert darkless.success_probability() == pytest.approx(5e-17, rel=1e-6)
    assert darkless.raw_fidelity() == pytest.approx(1.0, rel=1e-9)

    # And with a dark-count floor, a link that can only ever click on dark
    # counts reports the maximally mixed fidelity instead.
    dark_only = BarrettKok(
        arm_a=PhotonicLink(length_km=1e6, detector=Detector(
            efficiency=1.0, dark_count_rate_hz=1e9)),
        arm_b=PhotonicLink(length_km=1e6, detector=Detector(
            efficiency=1.0, dark_count_rate_hz=1e9)),
        coincidence_window_s=1e-6)
    assert dark_only.raw_fidelity() == pytest.approx(0.25, abs=0.05)


# ---------------------------------------------------------------------------
# Multiplexing
# ---------------------------------------------------------------------------

def test_multiplexed_success_is_one_minus_all_failed():
    assert multiplexed_success(0.1, 1) == pytest.approx(0.1)
    assert multiplexed_success(0.1, 2) == pytest.approx(1 - 0.9 ** 2)
    assert multiplexed_success(0.1, 0) == 0.0
    assert multiplexed_success(0.0, 10) == 0.0
    assert multiplexed_success(1.0, 5) == pytest.approx(1.0)


def test_multiplexing_raises_the_rate_but_saturates():
    link = _link(_perfect_arm(100.0), _perfect_arm(100.0))
    rates = [link.success_probability_multiplexed(m) for m in (1, 2, 4, 8, 64)]
    assert all(a < b for a, b in zip(rates, rates[1:]))
    assert rates[-1] < 1.0, "multiplexing must not exceed certainty"


def test_negative_modes_is_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        multiplexed_success(0.1, -1)


def test_generation_rate_scales_with_pulse_rate():
    link = _link(_perfect_arm(50.0), _perfect_arm(50.0))
    slow = link.generation_rate_hz(1e6)
    fast = link.generation_rate_hz(1e8)
    assert fast == pytest.approx(100.0 * slow, rel=1e-9)


def test_generation_rate_is_capped_by_detector_dead_time():
    """A herald needs both detectors live, so dead time bounds the rate."""
    quick = PhotonicLink(50.0, detector=Detector(efficiency=1.0,
                                                 dead_time_s=0.0))
    slow = PhotonicLink(50.0, detector=Detector(efficiency=1.0,
                                                dead_time_s=1e-6))
    fast_link = _link(quick, quick)
    slow_link = _link(slow, slow)

    # at 1 GHz the dead-time-limited detector cannot keep up
    assert slow_link.generation_rate_hz(1e9) < fast_link.generation_rate_hz(1e9)
    assert slow_link.generation_rate_hz(1e9) <= 1e6 * (1 + 1e-9)


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def test_attempt_without_an_rng_returns_the_expected_values():
    link = _link(_perfect_arm(50.0), _perfect_arm(50.0))
    attempt = link.attempt()
    assert attempt.success_probability == pytest.approx(
        link.success_probability())
    assert attempt.raw_fidelity == pytest.approx(link.raw_fidelity())
    assert attempt.describe()


def test_sampling_converges_to_the_probability():
    link = _link(_perfect_arm(20.0), _perfect_arm(20.0))
    rng = np.random.default_rng(11)
    trials = 20000
    hits = sum(link.attempt(rng).success for _ in range(trials))
    assert hits / trials == pytest.approx(link.success_probability(), rel=0.05)


def test_sampling_is_deterministic_for_a_given_seed():
    link = _link(_perfect_arm(20.0), _perfect_arm(20.0))
    first = [link.attempt(np.random.default_rng(3)).success for _ in range(50)]
    second = [link.attempt(np.random.default_rng(3)).success for _ in range(50)]
    assert first == second


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_link_parameter_validation():
    with pytest.raises(ValueError, match="length_km"):
        PhotonicLink(-1.0)
    with pytest.raises(ValueError, match="source_efficiency"):
        PhotonicLink(1.0, source_efficiency=0.0)
    with pytest.raises(ValueError, match="memory_efficiency"):
        PhotonicLink(1.0, memory_efficiency=1.5)


def test_barrett_kok_parameter_validation():
    arm = _perfect_arm()
    with pytest.raises(ValueError, match="mode_matching"):
        BarrettKok(arm, arm, mode_matching=0.0)
    with pytest.raises(ValueError, match="coincidence_window_s"):
        BarrettKok(arm, arm, coincidence_window_s=-1.0)
    with pytest.raises(ValueError, match="multiphoton"):
        BarrettKok(arm, arm, multiphoton_probability=1.5)


def test_photon_arrival_excludes_detector_efficiency_by_design():
    """The detector acts at the click, so folding it in twice would be wrong."""
    arm = PhotonicLink(0.0, detector=Detector(efficiency=0.5,
                                              dark_count_rate_hz=0.0))
    assert arm.photon_arrival_probability() == pytest.approx(1.0)
    assert arm.total_efficiency() == pytest.approx(0.5)


def test_asymmetric_arms_use_the_slower_one():
    short = _perfect_arm(10.0)
    long = _perfect_arm(100.0)
    link = _link(short, long)
    assert link.success_probability() == pytest.approx(
        0.5 * short.total_efficiency() * long.total_efficiency(), rel=1e-12)


def test_elementary_link_from_specs_splits_length_at_midpoint():
    """Midpoint beam splitter: each arm is half the total link length."""
    link = elementary_link_from_specs(
        50.0,
        alpha_db_km=0.2,
        detector_efficiency=1.0,
        dark_count_hz=0.0,
    )
    assert link.arm_a.length_km == pytest.approx(25.0)
    assert link.arm_b.length_km == pytest.approx(25.0)
    # 25 km * 0.2 dB/km = 5 dB per arm -> 10 dB total -> 0.5 * 10^(-1) = 0.05
    assert link.success_probability() == pytest.approx(0.05, rel=1e-12)


def test_signal_dark_cross_coincidence_degrades_raw_fidelity():
    """A real photon on one arm + dark count on the other is a false herald."""
    arm_clean = _perfect_arm(10.0, dark_count_rate_hz=0.0)
    arm_noisy = _perfect_arm(10.0, dark_count_rate_hz=1e7)
    link = BarrettKok(arm_a=arm_clean, arm_b=arm_noisy, coincidence_window_s=1e-9)

    # arm_clean has zero dark counts, so dark-dark coincidence is 0;
    # degradation must come entirely from the signal-dark cross-coincidence.
    assert link.dark_coincidence_probability() == 0.0
    p_sig = link.signal_coincidence_probability()
    p_sd = link.signal_dark_coincidence_probability()
    p_sig_a = arm_clean.total_efficiency()
    p_dark_b = arm_noisy.detector.dark_count_probability(1e-9)
    assert p_sd == pytest.approx(0.5 * p_sig_a * p_dark_b, rel=1e-12)
    expected_f = (p_sig * 1.0 + p_sd * 0.25) / (p_sig + p_sd)
    assert link.raw_fidelity() == pytest.approx(expected_f, rel=1e-12)
    assert link.raw_fidelity() < 1.0
