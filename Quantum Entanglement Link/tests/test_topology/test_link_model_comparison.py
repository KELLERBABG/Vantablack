"""The Barrett-Kok model against the pre-existing heuristic rate.

``topology.graph.QuantumLink`` computes its generation rate as
``pulse_rate * (detector_eff * transmissivity)^2``.  That is a *single-photon*
scheme: one photon per arm, both detected.  Barrett-Kok is a *double-heralded*
scheme whose ideal probability is 1/2, so the two differ by that factor and by
the dark-count treatment.

The tests here exist so the difference is **visible and attributable** rather
than a silent inconsistency between two parts of the same codebase.  Neither
number is wrong; they describe different hardware.  What would be wrong is
quoting one while the other is what the simulator actually uses.
"""

from __future__ import annotations

import pytest

from quantumnet.core.photonics import (
    BARRETT_KOK_IDEAL_SUCCESS,
    Detector,
    PhotonicLink,
    BarrettKok,
    compare_link_models,
    elementary_link_from_specs,
    single_photon_attempt_probability,
)
from quantumnet.topology.graph import QuantumLink


def test_the_two_models_differ_by_the_beamsplitter_factor_at_low_dark_counts():
    """At zero distance (T=1), legacy omits the 1/2 so it is ~2x Barrett-Kok.

    At finite distance L, the midpoint beam splitter gives Barrett-Kok T(L)
    total attenuation whereas the legacy heuristic squares T(L), so the ratio
    is ``2.0 * T(L)``.
    """
    link = QuantumLink(a="A", b="B", length_km=50.0,
                       dark_count_hz=1e-9, detector_eff=0.8)
    comparison = compare_link_models(link)
    expected_ratio = 2.0 * 10.0 ** (-0.2 * 50.0 / 10.0)
    assert comparison["ratio"] == pytest.approx(expected_ratio, rel=0.05), (
        f"ratio {comparison['ratio']} -- expected ~{expected_ratio} from midpoint 1/2 * T(L)"
    )


def test_barrett_kok_rate_is_strictly_below_the_single_photon_heuristic():
    """At zero distance (T=1), Barrett-Kok is 0.5x legacy; at long spans T(L) > T(L)^2."""
    zero_link = QuantumLink(a="A", b="B", length_km=0.0,
                            dark_count_hz=1e-9, detector_eff=0.8)
    assert compare_link_models(zero_link)["barrett_kok_rate_hz"] < compare_link_models(zero_link)["legacy_rate_hz"]
    for length in (20.0, 50.0, 100.0):
        link = QuantumLink(a="A", b="B", length_km=length,
                           dark_count_hz=1e-9, detector_eff=0.8)
        comparison = compare_link_models(link)
        assert comparison["barrett_kok_rate_hz"] > comparison["legacy_rate_hz"]


def test_both_models_agree_on_the_distance_scaling():
    """Legacy scales as T(L)^2 while midpoint Barrett-Kok scales as T(L), so ratio / T(L) is constant."""
    normalized = []
    for length in (20.0, 40.0, 80.0):
        link = QuantumLink(a="A", b="B", length_km=length,
                           dark_count_hz=1e-9, detector_eff=0.8)
        t = 10.0 ** (-0.2 * length / 10.0)
        normalized.append(compare_link_models(link)["ratio"] / t)
    assert max(normalized) - min(normalized) < 0.05, f"slopes differ: {normalized}"


def test_the_ratio_is_exactly_two_in_the_no_dark_count_limit():
    """Stated analytically: legacy = 2 * T(L) * Barrett-Kok when dark counts vanish."""
    link_zero = QuantumLink(a="A", b="B", length_km=0.0,
                            dark_count_hz=0.0, detector_eff=0.8)
    assert compare_link_models(link_zero)["ratio"] == pytest.approx(2.0, rel=1e-6)
    link_50 = QuantumLink(a="A", b="B", length_km=50.0,
                          dark_count_hz=0.0, detector_eff=0.8)
    assert compare_link_models(link_50)["ratio"] == pytest.approx(0.2, rel=1e-6)


def test_single_photon_probability_matches_the_legacy_squared_form():
    """The legacy rate is ``pulse_rate * eta^2``; confirm that reading of it."""
    for length in (0.0, 25.0, 50.0):
        eta = single_photon_attempt_probability(length, detector_efficiency=0.8)
        link = QuantumLink(a="A", b="B", length_km=length,
                           dark_count_hz=0.0, detector_eff=0.8)
        assert link.generation_rate() == pytest.approx(
            link.pulse_rate_hz * eta ** 2, rel=1e-9)


def test_high_dark_counts_close_the_gap_between_the_models():
    """Dark counts add to the Barrett-Kok rate, so the ratio falls below 2."""
    quiet = QuantumLink(a="A", b="B", length_km=100.0,
                        dark_count_hz=0.0, detector_eff=0.8)
    noisy = QuantumLink(a="A", b="B", length_km=100.0,
                        dark_count_hz=1e7, detector_eff=0.8)
    assert compare_link_models(noisy)["ratio"] < compare_link_models(quiet)["ratio"]


def test_elementary_link_helper_builds_a_symmetric_link():
    link = elementary_link_from_specs(30.0, detector_efficiency=0.9)
    assert link.arm_a.length_km == link.arm_b.length_km == 15.0
    assert link.arm_a.detector.efficiency == 0.9
    assert link.success_probability() > 0.0


def test_elementary_link_fidelity_is_high_when_mode_matching_is_perfect():
    link = elementary_link_from_specs(10.0, coincidences_window_s=1e-12)
    assert link.raw_fidelity() > 0.99


def test_comparison_reports_every_field_a_caller_needs():
    link = QuantumLink(a="A", b="B", length_km=50.0)
    comparison = compare_link_models(link)
    for key in ("legacy_rate_hz", "barrett_kok_rate_hz", "success_probability",
                "raw_fidelity", "ratio", "length_km"):
        assert key in comparison
    assert comparison["length_km"] == 50.0


def test_a_span_too_long_to_be_useful_reports_underflow_not_a_false_ratio():
    """Past extreme distances both rates underflow to zero and ratio reports 1.0."""
    link = QuantumLink(a="A", b="B", length_km=20000.0,
                       dark_count_hz=0.0, detector_eff=0.8)
    comparison = compare_link_models(link)
    assert comparison["barrett_kok_rate_hz"] == 0.0
    assert comparison["legacy_rate_hz"] == 0.0
    assert comparison["ratio"] == 1.0
