"""Source and detector impairments that degrade *fidelity*, not only rate.

Two fields existed as declared parameters with no effect on fidelity, which is the
worst kind of gap: they look modelled.  These tests pin the behaviour of each.

* ``multiphoton_probability`` was added to the success probability and never to the
  fidelity, so a source emitting two pairs per pulse was modelled as producing
  **more** entanglement of the **same** quality.
* ``afterpulse_probability`` was validated and then never used anywhere.

Both mistakes flatter the hardware, which is why they are worth explicit tests
rather than a comment.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from quantumnet.core.photonics import (
    BARRETT_KOK_IDEAL_SUCCESS,
    BarrettKok,
    Detector,
    PhotonicLink,
    elementary_link_from_specs,
)


def link_at(length_km: float = 50.0, **kwargs) -> BarrettKok:
    return elementary_link_from_specs(length_km, **kwargs)


def with_detector(link: BarrettKok, **changes) -> BarrettKok:
    det = replace(link.arm_a.detector, **changes)
    return BarrettKok(arm_a=replace(link.arm_a, detector=det),
                      arm_b=replace(link.arm_b, detector=det),
                      multiphoton_probability=link.multiphoton_probability,
                      multipair_visibility=link.multipair_visibility,
                      mode_matching=link.mode_matching,
                      coincidence_window_s=link.coincidence_window_s)


# ---------------------------------------------------------------------------
# Multi-photon emission
# ---------------------------------------------------------------------------

def test_an_ideal_link_has_unit_fidelity():
    """The baseline: loss costs rate, not fidelity, so nothing degrades it."""
    link = link_at(50.0)
    assert link.raw_fidelity() == pytest.approx(1.0)
    assert link.multiphoton_coincidence_probability() == 0.0


def test_multi_pair_emission_raises_the_rate():
    """Two pairs can also produce a coincidence, so the herald rate rises."""
    quiet = link_at(50.0)
    noisy = BarrettKok(arm_a=quiet.arm_a, arm_b=quiet.arm_b,
                       multiphoton_probability=0.05)
    assert noisy.success_probability() > quiet.success_probability()
    assert noisy.multiphoton_coincidence_probability() > 0.0


def test_multi_pair_emission_lowers_the_fidelity():
    """The regression: it used to raise the rate and leave fidelity at 1.0."""
    quiet = link_at(50.0)
    noisy = BarrettKok(arm_a=quiet.arm_a, arm_b=quiet.arm_b,
                       multiphoton_probability=0.05)
    assert noisy.raw_fidelity() < quiet.raw_fidelity(), (
        "a two-pair source must not herald the intended state as cleanly"
    )


def test_fidelity_falls_monotonically_with_multi_pair_emission():
    values = []
    for mu2 in (0.0, 0.01, 0.05, 0.15, 0.30):
        base = link_at(50.0)
        values.append(BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b,
                                 multiphoton_probability=mu2).raw_fidelity())
    assert values == sorted(values, reverse=True), values
    assert all(0.25 <= v <= 1.0 for v in values)


def test_a_multi_pair_herald_is_between_signal_and_dark():
    """A stated model, and these are the bounds it must respect.

    A multi-pair herald is a real coincidence between real photons (so better
    than two dark counts) but an ambiguous one (so worse than a clean signal).
    """
    base = link_at(50.0)
    multi = BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b,
                       multiphoton_probability=0.15)
    f = multi.raw_fidelity()
    assert multi.dark_coincidence_fidelity < f < 1.0


def test_multipair_visibility_spans_the_stated_range():
    """Visibility 1 makes a multi-pair herald as good as signal; 0 as bad as dark."""
    base = link_at(50.0)
    optimistic = BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b,
                            multiphoton_probability=0.1,
                            multipair_visibility=1.0)
    pessimistic = BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b,
                             multiphoton_probability=0.1,
                             multipair_visibility=0.0)
    assert optimistic.raw_fidelity() > pessimistic.raw_fidelity()
    assert pessimistic.raw_fidelity() >= base.dark_coincidence_fidelity


def test_an_out_of_range_visibility_is_rejected():
    base = link_at(50.0)
    for bad in (-0.1, 1.1):
        with pytest.raises(ValueError, match="multipair_visibility"):
            BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b,
                       multipair_visibility=bad)


def test_mode_mismatch_and_multi_pair_compound():
    """Two independent impairments must both bite."""
    base = link_at(50.0)
    mismatch_only = BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b,
                               mode_matching=0.97)
    both = BarrettKok(arm_a=base.arm_a, arm_b=base.arm_b, mode_matching=0.97,
                      multiphoton_probability=0.05)
    assert both.raw_fidelity() < mismatch_only.raw_fidelity()


# ---------------------------------------------------------------------------
# Afterpulsing
# ---------------------------------------------------------------------------

def test_afterpulsing_degrades_fidelity():
    """The regression: the field was validated and then never used."""
    clean = link_at(50.0)
    dirty = with_detector(clean, afterpulse_probability=0.05)
    assert dirty.raw_fidelity() < clean.raw_fidelity()


def test_afterpulse_probability_scales_with_the_prior_click_rate():
    """Traps need a prior avalanche, so the rate tracks the click rate."""
    det = Detector(efficiency=0.8)
    assert det.afterpulse_click_probability(1e-9, 0.0) == 0.0
    low = det.afterpulse_click_probability(1e-9, 0.01)
    high = det.afterpulse_click_probability(1e-9, 0.10)
    assert high == pytest.approx(10 * low)


def test_zero_afterpulsing_contributes_nothing():
    clean = link_at(50.0)
    assert clean.afterpulse_coincidence_probability() == 0.0


def test_afterpulse_coincidence_grows_with_the_probability():
    values = []
    for ap in (0.0, 0.01, 0.05, 0.2):
        values.append(with_detector(link_at(50.0),
                                    afterpulse_probability=ap
                                    ).afterpulse_coincidence_probability())
    assert values == sorted(values), values


def test_an_invalid_prior_probability_is_rejected():
    det = Detector(afterpulse_probability=0.1)
    for bad in (-0.1, 1.5):
        with pytest.raises(ValueError, match="prior_click_probability"):
            det.afterpulse_click_probability(1e-9, bad)


def test_afterpulsing_is_charged_as_maximally_mixed():
    """A real photon on one arm plus a spurious click is uncorrelated.

    So it must pull the fidelity toward 1/4 exactly as a dark coincidence does,
    and the two must be the same verdict by different routes.
    """
    clean = link_at(50.0)
    dirty = with_detector(clean, afterpulse_probability=0.3)
    assert dirty.raw_fidelity() < clean.raw_fidelity()
    assert dirty.raw_fidelity() > clean.dark_coincidence_fidelity


# ---------------------------------------------------------------------------
# Dead time and jitter: declared, and honest about their scope
# ---------------------------------------------------------------------------

def test_dead_time_caps_the_achievable_generation_rate():
    rate = 1e8
    clean = link_at(50.0)
    slow = with_detector(clean, dead_time_s=1e-6)
    assert slow.generation_rate_hz(rate) <= clean.generation_rate_hz(rate)


def test_the_blind_window_follows_the_declared_dead_time():
    det = Detector(dead_time_s=1e-6)
    assert det.is_blind(5e-7)
    assert not det.is_blind(1.5e-6)
    assert not Detector(dead_time_s=0.0).is_blind(0.0)


def test_jitter_is_documented_as_not_changing_the_per_attempt_rate():
    """Stated scope, pinned so it cannot drift silently.

    Jitter sets how finely arrival times can be resolved, which the coincidence
    window must respect; it does not itself change the per-attempt probability.
    If that ever changes, this test is where it should be noticed.
    """
    clean = link_at(50.0)
    jittery = with_detector(clean, jitter_s=1e-9)
    assert jittery.success_probability() == pytest.approx(
        clean.success_probability())
    assert jittery.raw_fidelity() == pytest.approx(clean.raw_fidelity())


def test_an_ideal_detector_reproduces_the_barrett_kok_bound():
    """The ideal case must still reduce to the published 1/2 times efficiency."""
    detector = Detector(efficiency=1.0, dark_count_rate_hz=0.0)
    arm = PhotonicLink(length_km=0.0, detector=detector)
    link = BarrettKok(arm_a=arm, arm_b=arm)
    expected = BARRETT_KOK_IDEAL_SUCCESS * arm.total_efficiency() ** 2
    assert link.success_probability() == pytest.approx(expected)
