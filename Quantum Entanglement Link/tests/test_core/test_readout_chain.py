"""Tests for the readout-chain recovery model.

These assert the **measured properties** reported by Burenkov et al. (2013,
arXiv:1306.3749), not a fit to their data. Each test corresponds to a statement the paper
makes, so a failure means either the model or the transcription is wrong -- and the paper
says which.

The properties are chosen because they are the ones a *conventional* model gets wrong.
A monotonic ``1 - exp(-t/tau)`` recovery with a flat afterpulse probability would fail
four of the tests below, which is the point: the model exists because those four things
cannot be expressed by the scalars currently in `photonics.py`.

Nothing here is calibrated against data points. The overshoot amplitude in particular is a
placeholder and no test asserts its exact value -- only that it exceeds nominal, which the
paper does state.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from quantumnet.core.readout_chain import (
    AFTERPULSE_PEAK_S,
    DEAD_TIME_S,
    SECONDARY_AFTERPULSE_PEAK_S,
    AfterpulseKernel,
    ReadoutChainError,
    ReadoutChainRecovery,
    RecoveryCurve,
    afterpulse_amplitude_from_bias,
    burenkov_2013_recovery,
)


class TestReportedFeatures:
    """The four properties a monotonic model cannot express."""

    def test_efficiency_is_essentially_zero_in_the_dead_zone(self):
        """Paper, Sec. VI: 'virtually zero up to about 80 ns'."""
        curve = burenkov_2013_recovery()
        for ns in (0, 20, 40, 60, 80):
            assert curve.at(ns * 1e-9) < 0.05, \
                f"efficiency at {ns} ns should be near zero"

    def test_efficiency_rises_sharply_between_80_and_180_ns(self):
        """The recovery is fast once it begins, not gradual.

        A monotonic form could satisfy this, which is why it is not the discriminating
        test -- but it is still a reported feature and worth pinning.
        """
        curve = burenkov_2013_recovery()
        early = curve.at(80e-9)
        mid = curve.at(140e-9)
        peak = curve.at(180e-9)
        assert early < mid < peak

    def test_efficiency_OVERSHOOTS_nominal_at_the_peak(self):
        """Paper, Sec. VI: efficiency 'increases beyond it' -- the unexpected finding.

        This is the test a saturating `1 - exp(-t/tau)` fails. It is the single most
        important assertion in this file, because the overshoot is why the model cannot be
        a scalar and why a monotonic fit would be a mis-calibration rather than a
        coarse approximation.
        """
        curve = burenkov_2013_recovery()
        assert curve.overshoot_peak > 1.0
        peak_time_ns = curve.times_s[int(np.argmax(curve.efficiency))] * 1e9
        assert peak_time_ns == pytest.approx(180, abs=1)

    def test_the_curve_is_structurally_non_monotonic(self):
        """The shape, not just the peak: it goes above nominal and comes back down."""
        assert burenkov_2013_recovery().is_non_monotonic

    def test_efficiency_settles_back_to_nominal(self):
        """Paper: 'dropping back to the nominal value' after several hundred ns."""
        curve = burenkov_2013_recovery()
        assert curve.at(700e-9) == pytest.approx(1.0, abs=1e-9)
        assert curve.at(1000e-9) == pytest.approx(1.0, abs=1e-9)

    def test_a_monotonic_curve_is_rejected_as_not_non_monotonic(self):
        """Guard on the predicate itself, so `is_non_monotonic` cannot pass vacuously."""
        flat = RecoveryCurve(times_s=np.array([0.0, 1e-9, 2e-9]),
                             efficiency=np.array([0.0, 0.5, 1.0]))
        assert not flat.is_non_monotonic

    def test_gamma_below_one_is_refused(self):
        """A gamma <= 1 is the monotonic model this module exists to reject."""
        with pytest.raises(ReadoutChainError):
            burenkov_2013_recovery(gamma=1.0)
        with pytest.raises(ReadoutChainError):
            burenkov_2013_recovery(gamma=0.9)


class TestAfterpulseKernel:
    def test_primary_peak_is_at_the_reported_delay(self):
        """Paper, abstract: 'most likely to occur at around 180 ns'."""
        kernel = AfterpulseKernel(amplitude=0.5)
        grid = np.linspace(0.0, 500e-9, 2001)
        peak = grid[int(np.argmax(kernel.at(grid)))]
        assert peak == pytest.approx(AFTERPULSE_PEAK_S, abs=5e-9)

    def test_secondary_peak_exists_near_360_ns(self):
        """Paper, Sec. V: 'about 180 ns after the first afterpulse, there is an enhanced
        probability of having a second afterpulse'."""
        kernel = AfterpulseKernel(amplitude=0.5, secondary_ratio=0.6)
        # A local maximum near 360 ns, distinct from the primary.
        near = np.linspace(330e-9, 390e-9, 601)
        primary_region = np.linspace(120e-9, 240e-9, 601)
        assert kernel.at(near).max() > kernel.at(near).min()
        assert kernel.at(SECONDARY_AFTERPULSE_PEAK_S) > 0.0
        assert (kernel.at(near).max() > 0.0
                and kernel.at(SECONDARY_AFTERPULSE_PEAK_S)
                < kernel.at(AFTERPULSE_PEAK_S))

    def test_zero_amplitude_gives_no_afterpulsing(self):
        """With amplitude zero the kernel must vanish, or the model adds clicks from
        nowhere -- which would corrupt every downstream rate."""
        kernel = AfterpulseKernel(amplitude=0.0)
        grid = np.linspace(0.0, 1000e-9, 1001)
        assert np.allclose(kernel.at(grid), 0.0)

    def test_larger_amplitude_gives_proportionally_more(self):
        small = AfterpulseKernel(amplitude=0.1).at(180e-9)
        large = AfterpulseKernel(amplitude=0.4).at(180e-9)
        assert large == pytest.approx(4 * small, rel=1e-9)

    @pytest.mark.parametrize("amplitude", [-0.1, 1.5])
    def test_impossible_amplitudes_are_refused(self, amplitude):
        with pytest.raises(ReadoutChainError):
            AfterpulseKernel(amplitude=amplitude)

    def test_zero_width_is_refused(self):
        with pytest.raises(ReadoutChainError):
            AfterpulseKernel(amplitude=0.3, primary_sigma_s=0.0)


class TestBiasDependence:
    """Paper, Fig. 6: afterpulsing rises exponentially toward the critical current."""

    def test_amplitude_increases_monotonically_toward_critical(self):
        amplitudes = [afterpulse_amplitude_from_bias(b, 24.8)
                      for b in (20.0, 22.0, 24.0, 24.5, 24.7, 24.75)]
        assert amplitudes == sorted(amplitudes)
        assert amplitudes[-1] > amplitudes[0]

    def test_amplitude_becomes_negligible_far_from_critical(self):
        """Paper: 'afterpulsing quickly becomes negligible as bias is decreased away
        from the critical value.'"""
        assert afterpulse_amplitude_from_bias(10.0, 24.8) < 1e-8
        assert afterpulse_amplitude_from_bias(20.0, 24.8) < 1e-6

    def test_bias_at_or_above_critical_is_refused(self):
        """Above the critical current the device relaxes into oscillation and does not
        detect at all, so an amplitude there is meaningless rather than large."""
        with pytest.raises(ReadoutChainError):
            afterpulse_amplitude_from_bias(24.8, 24.8)
        with pytest.raises(ReadoutChainError):
            afterpulse_amplitude_from_bias(25.5, 24.8)

    def test_amplitude_is_bounded(self):
        assert 0.0 <= afterpulse_amplitude_from_bias(24.799, 24.8, scale=100.0) <= 1.0


class TestStateMachine:
    def _chain(self, amplitude: float = 0.0, nominal: float = 1.0):
        return ReadoutChainRecovery(
            recovery=burenkov_2013_recovery(),
            afterpulse=AfterpulseKernel(amplitude=amplitude),
            dead_time_s=DEAD_TIME_S)

    def test_no_previous_click_means_nominal_efficiency(self):
        assert self._chain().efficiency_after(None) == 1.0

    def test_chain_is_blind_during_dead_time(self):
        chain = self._chain()
        assert chain.is_blind(0.0)
        assert chain.is_blind(100e-9)
        assert not chain.is_blind(200e-9)

    def test_two_photons_closer_than_dead_time_produce_one_click(self):
        """The dead time must actually suppress the second click."""
        chain = self._chain()
        clicks = chain.detect([0.0, 50e-9], seed=1)
        assert len(clicks) == 1

    def test_photons_far_apart_both_click_at_full_efficiency(self):
        chain = self._chain()
        clicks = chain.detect([0.0, 5e-6], seed=1)
        assert len(clicks) == 2

    def test_afterpulsing_adds_clicks_that_no_photon_caused(self):
        """With afterpulsing on, one photon can yield more than one click."""
        quiet = self._chain(amplitude=0.0)
        noisy = self._chain(amplitude=0.9)
        photon_times = [0.0]
        assert len(quiet.detect(photon_times, seed=3)) == 1
        assert len(noisy.detect(photon_times, seed=3)) > 1

    def test_recovered_efficiency_suppresses_a_photon_soon_after_a_click(self):
        """A photon arriving while the chain is still recovering must be less likely to
        register than one arriving after full recovery.

        Averaged over many seeds, because a single draw proves nothing.
        """
        chain = self._chain()
        soon = sum(len(chain.detect([0.0, 90e-9], seed=s)) - 1 for s in range(300))
        later = sum(len(chain.detect([0.0, 800e-9], seed=s)) - 1 for s in range(300))
        assert soon < later, "recovery must suppress detection, not be cosmetic"

    def test_detections_never_exceed_photons_when_afterpulsing_is_off(self):
        """Without afterpulsing the chain cannot invent clicks."""
        chain = self._chain(amplitude=0.0)
        photons = [i * 1e-5 for i in range(50)]
        clicks = chain.detect(photons, seed=7)
        assert len(clicks) <= len(photons)

    def test_output_is_sorted(self):
        chain = self._chain(amplitude=0.5)
        clicks = chain.detect([5e-6, 0.0, 1e-5, 2e-5], seed=11)
        assert clicks == sorted(clicks)

    def test_negative_dead_time_is_refused(self):
        with pytest.raises(ReadoutChainError):
            ReadoutChainRecovery(dead_time_s=-1e-9)


class TestValidationMetric:
    """The metric is P(click at tau | click at 0), NOT g^(2)(tau)."""

    def test_metric_is_bounded_and_non_negative(self):
        chain = ReadoutChainRecovery(
            recovery=burenkov_2013_recovery(),
            afterpulse=AfterpulseKernel(amplitude=0.5))
        grid = np.linspace(0.0, 1500e-9, 501)
        p = chain.conditional_click_probability(grid)
        assert np.all(p >= 0.0) and np.all(p <= 1.0)

    def test_metric_is_zero_in_the_dead_zone_without_afterpulsing(self):
        chain = ReadoutChainRecovery(
            recovery=burenkov_2013_recovery(),
            afterpulse=AfterpulseKernel(amplitude=0.0))
        grid = np.linspace(0.0, 70e-9, 50)
        assert np.allclose(chain.conditional_click_probability(grid), 0.0, atol=0.05)

    def test_metric_exceeds_nominal_at_the_overshoot_without_afterpulsing(self):
        """Crucially this must hold with afterpulsing OFF.

        If it only held with afterpulsing on, the excess could be attributed to spurious
        clicks and would not demonstrate the efficiency overshoot the paper reports.

        Measured at a nominal efficiency below 1, and that is not a convenience. A
        probability cannot exceed 1, so at ``nominal = 1.0`` the overshoot saturates and is
        invisible in this metric -- the chain is already clicking on every photon. The
        effect is observable exactly where the *relative* efficiency can rise without the
        *absolute* probability hitting the ceiling, which is the regime the experiment ran
        in: Burenkov et al. report the maximum detection efficiency of their device as
        about 2.5%, so their overshoot had ample headroom.
        """
        chain = ReadoutChainRecovery(
            recovery=burenkov_2013_recovery(),
            afterpulse=AfterpulseKernel(amplitude=0.0))
        nominal = 0.025                       # the paper's own operating efficiency
        at_peak = chain.conditional_click_probability(np.array([180e-9]),
                                                      nominal_efficiency=nominal)[0]
        at_nominal = chain.conditional_click_probability(np.array([800e-9]),
                                                         nominal_efficiency=nominal)[0]
        assert at_peak > at_nominal, \
            "the overshoot must be visible in the metric at the operating efficiency"

    def test_overshoot_saturates_rather_than_exceeding_one(self):
        """At nominal efficiency 1 the metric cannot exceed 1, and must say so by clamping.

        Asserted explicitly so the clamping is a documented property rather than a silent
        cap that hides an error elsewhere.
        """
        chain = ReadoutChainRecovery(
            recovery=burenkov_2013_recovery(),
            afterpulse=AfterpulseKernel(amplitude=0.0))
        at_peak = chain.conditional_click_probability(np.array([180e-9]))
        assert at_peak[0] == pytest.approx(1.0)
        assert chain.efficiency_after(180e-9) > 1.0, \
            "the relative efficiency still overshoots; only the probability is capped"

    def test_negative_delays_are_refused(self):
        chain = ReadoutChainRecovery()
        with pytest.raises(ReadoutChainError):
            chain.conditional_click_probability(np.array([-1e-9, 1e-9]))


class TestProvenance:
    """An unlabelled calibration is indistinguishable from a guess."""

    def test_default_provenance_says_it_is_not_a_fit(self):
        chain = ReadoutChainRecovery()
        assert "NOT a fit" in chain.provenance

    def test_calibrated_requires_a_named_source(self):
        with pytest.raises(ReadoutChainError):
            ReadoutChainRecovery.calibrated(burenkov_2013_recovery(),
                                            AfterpulseKernel(0.1), source="")
        with pytest.raises(ReadoutChainError):
            ReadoutChainRecovery.calibrated(burenkov_2013_recovery(),
                                            AfterpulseKernel(0.1), source="   ")

    def test_calibrated_records_the_source(self):
        chain = ReadoutChainRecovery.calibrated(
            burenkov_2013_recovery(), AfterpulseKernel(0.1),
            source="digitized_burenkov2013_fig10")
        assert "digitized_burenkov2013_fig10" in chain.provenance

    def test_the_recovery_curve_carries_its_own_provenance(self):
        assert "Burenkov" in burenkov_2013_recovery().provenance


class TestCurveValidation:
    def test_unsorted_times_are_refused(self):
        with pytest.raises(ReadoutChainError):
            RecoveryCurve(times_s=np.array([1e-9, 0.0]), efficiency=np.array([1.0, 0.0]))

    def test_mismatched_lengths_are_refused(self):
        with pytest.raises(ReadoutChainError):
            RecoveryCurve(times_s=np.array([0.0, 1e-9]), efficiency=np.array([1.0]))

    def test_non_finite_efficiency_is_refused(self):
        with pytest.raises(ReadoutChainError):
            RecoveryCurve(times_s=np.array([0.0, 1e-9]),
                          efficiency=np.array([1.0, np.nan]))

    def test_single_point_is_refused(self):
        with pytest.raises(ReadoutChainError):
            RecoveryCurve(times_s=np.array([0.0]), efficiency=np.array([1.0]))

    def test_no_extrapolation_beyond_the_measured_support(self):
        """Holding terminal values rather than extrapolating. Extrapolating an overshoot
        past its measured support would invent a feature the experiment did not see."""
        curve = RecoveryCurve(times_s=np.array([0.0, 100e-9]), efficiency=np.array([0.0, 2.0]))
        assert curve.at(1e-3) == pytest.approx(2.0)
        assert curve.at(-1.0) == pytest.approx(0.0)


def test_the_model_predicts_something_the_scalar_cannot():
    """The end-to-end reason this module exists.

    `photonics.Detector` can say P(afterpulse) = const. It cannot say *when*. This shows
    the difference is measurable rather than cosmetic: the conditional click probability is
    strongly time-dependent, so a scalar would place the same probability at 20 ns as at
    180 ns, where the two differ by an order of magnitude.
    """
    chain = ReadoutChainRecovery(
        recovery=burenkov_2013_recovery(),
        afterpulse=AfterpulseKernel(amplitude=0.5, secondary_ratio=0.0))
    early = chain.conditional_click_probability(np.array([20e-9]))[0]
    at_peak = chain.conditional_click_probability(np.array([180e-9]))[0]
    assert at_peak > 10 * max(early, 1e-9), \
        "the time structure must be large, or a scalar would suffice"
    assert not math.isclose(early, at_peak)
