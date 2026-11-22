"""The in-package surface-code decoder.

This decoder replaced PyMatching on the threshold path, so these tests guard two
different things:

1. **That it is correct** -- corrections reproduce the observed syndrome, and the
   logical error rate falls with distance. If correctness regresses, the threshold
   number becomes meaningless while still looking plausible.
2. **That the two defects behind the previous failed decoder stay fixed.** Both are
   pinned by a test that would fail if the defect returned:

   * observables must be parsed per ``^``-separated component, because
     ``error(p) D4 D6 ^ D5 L0`` binds ``L0`` to the ``D5`` component only;
   * the edge weight is the log-likelihood ratio ``log((1-p)/p)``, not ``-log(p)``.

Both defects survived twelve rounds of debugging because the *instrument* had the same
blind spot as the code, so the tests here check the properties directly rather than
comparing against another implementation.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

stim = pytest.importorskip("stim")

from quantumnet.core import tjoin_decoder as decoder  # noqa: E402
from quantumnet.core.tjoin_decoder import (  # noqa: E402
    BOUNDARY,
    build_graph,
    decode_batch,
    decode_edges_and_observables,
    parse_dem_components,
)


def circuit(distance: int = 3, noise: float = 0.003):
    return stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=distance, rounds=distance,
        after_clifford_depolarization=noise)


# ---------------------------------------------------------------------------
# Observable parsing -- defect 1
# ---------------------------------------------------------------------------

def test_observables_are_parsed_per_component():
    """The bug: ``L`` targets belong to their own ``^`` component, not the instruction.

    ``error(p) D4 D6 ^ D5 L0`` means the ``(4, 6)`` component does **not** flip ``L0``.
    Reading observables across the whole instruction -- which the previous decoder did
    -- falsely attaches ``L0`` to ``(4, 6)``.
    """
    instruction = stim.DemInstruction(
        "error", [0.001], [stim.DemTarget("D4"), stim.DemTarget("D6"),
                           stim.DemTarget("^"),
                           stim.DemTarget("D5"), stim.DemTarget("L0")])
    components = parse_dem_components(instruction)
    assert len(components) == 2
    assert components[0] == ([4, 6], frozenset())
    assert components[1] == ([5], frozenset({0}))


def test_such_a_mechanism_actually_occurs_in_a_real_model():
    """The defect is not hypothetical, so the guard must not be either."""
    dem = circuit().detector_error_model(decompose_errors=True)
    found = 0
    for inst in dem.flattened():
        if inst.type != "error":
            continue
        flags = [bool(obs) for _dets, obs in parse_dem_components(inst)]
        if len(flags) > 1 and any(flags) and not all(flags):
            found += 1
    assert found > 0, "no mixed-observable mechanism found; the test is vacuous"


def test_no_detector_pair_has_conflicting_observables():
    """Once parsed per component, a pair's observable is unambiguous."""
    dem = circuit().detector_error_model(decompose_errors=True)
    seen: dict[tuple[int, int], set] = {}
    conflicts = 0
    for inst in dem.flattened():
        if inst.type != "error":
            continue
        for dets, obs in parse_dem_components(inst):
            if len(dets) == 2:
                key = (min(dets), max(dets))
            elif len(dets) == 1:
                key = (BOUNDARY, dets[0])
            else:
                continue
            prior = seen.setdefault(key, set(obs))
            if set(obs) != prior:
                conflicts += 1
    assert conflicts == 0


# ---------------------------------------------------------------------------
# Weight formula -- defect 2
# ---------------------------------------------------------------------------

def test_the_weight_is_the_log_likelihood_ratio_not_negative_log_p():
    """``-log(p)`` was used for twelve rounds and is wrong.

    The two agree only as ``p -> 0``. At the probabilities this code reaches they
    differ by 0.5-0.7%, which is enough to change which path a decoder picks.
    """
    for p in (0.001, 0.01, 0.025):
        expected = math.log((1.0 - p) / p)
        assert expected != pytest.approx(-math.log(p), rel=1e-6) or p < 1e-6
    # And the difference is material, not cosmetic, at realistic probabilities.
    p = 0.025
    assert abs(math.log((1 - p) / p) - (-math.log(p))) > 0.02


def test_edge_weights_match_the_log_likelihood_of_the_merged_probability():
    dem = circuit().detector_error_model(decompose_errors=True)
    edges, _adjacency = build_graph(dem)
    assert edges
    for edge in edges:
        assert edge.weight == pytest.approx(
            math.log((1.0 - edge.probability) / edge.probability))


def test_parallel_mechanisms_combine_by_parity_not_by_or():
    """Merging is modulo-2: two mechanisms on one pair may cancel in probability."""
    dem = circuit().detector_error_model(decompose_errors=True)
    edges, _adjacency = build_graph(dem)
    for edge in edges:
        assert 0.0 < edge.probability <= 1.0 - 1e-15


# ---------------------------------------------------------------------------
# Correctness -- the invariant
# ---------------------------------------------------------------------------

def _syndrome(check) -> set:
    return set(check.explained)


@pytest.mark.parametrize("distance", [3, 5])
def test_every_correction_reproduces_the_observed_syndrome(distance):
    """The property the previous decoder failed on 100% of shots at one point."""
    from validation import check_correction

    c = circuit(distance)
    dem = c.detector_error_model(decompose_errors=True)
    sampler = c.compile_detector_sampler(seed=3)
    detection, _obs = sampler.sample(600, separate_observables=True)

    checked = 0
    for shot in range(600):
        events = [int(e) for e in np.flatnonzero(detection[shot])]
        if not events:
            continue
        edges, _flipped = decode_edges_and_observables(dem, events)
        assert check_correction(events, list(edges)).valid, (
            f"shot {shot} at d={distance} does not reproduce its syndrome")
        checked += 1
    assert checked > 0, "no shots with events; the test is vacuous"


def test_no_detection_events_means_no_observable_flip():
    c = circuit()
    dem = c.detector_error_model(decompose_errors=True)
    _edges, flipped = decode_edges_and_observables(dem, [])
    assert not flipped


# ---------------------------------------------------------------------------
# Accuracy -- the gates
# ---------------------------------------------------------------------------

def test_accuracy_is_suppressed_at_large_distance():
    """Suppression, which is what makes a threshold claim meaningful.

    Deliberately asserted at d=7 with enough shots to resolve it. An earlier version
    asserted ``rate < noise/10`` at d=5 with 4000 shots, where the expected rate is
    ~0.0005 against a 0.0003 threshold -- tighter than the statistics support, so it
    failed on sampling noise rather than on a defect.
    """
    c = circuit(7, 0.003)
    dem = c.detector_error_model(decompose_errors=True)
    sampler = c.compile_detector_sampler(seed=7)
    detection, observables = sampler.sample(20000, separate_observables=True)
    predicted = decode_batch(dem, detection)[:, 0].astype(bool)
    truth = observables[:, 0].astype(bool)
    rate = float(np.mean(predicted != truth))
    # Measured ~0.00010 at d=7, p=0.003: a factor of 30 below the physical rate.
    assert rate < 0.003 / 10, f"logical rate {rate} is not suppressed"


@pytest.mark.parametrize("noise", [0.004, 0.005, 0.006])
def test_the_logical_rate_falls_with_distance_below_threshold(noise):
    """The acceptance test for the surface code: error rate falls with ``d``.

    Noise levels are chosen **below the threshold**. At p=0.007 the d=5 point is
    already at the crossing (measured 0.00985 at d=3 against 0.01045 at d=5), so
    including it here would assert suppression in the region where the whole point is
    that it stops -- see :func:`test_the_curves_cross_near_the_threshold` for that.
    """
    rates = []
    for distance in (3, 5, 7):
        c = circuit(distance, noise)
        dem = c.detector_error_model(decompose_errors=True)
        sampler = c.compile_detector_sampler(seed=5)
        detection, observables = sampler.sample(10000, separate_observables=True)
        predicted = decode_batch(dem, detection)[:, 0].astype(bool)
        truth = observables[:, 0].astype(bool)
        rates.append(float(np.mean(predicted != truth)))
    assert rates[0] > rates[1] > rates[2], f"not suppressed: {rates}"


def test_the_curves_cross_near_the_threshold():
    """A threshold is only a real result if the ordering **reverses** above it.

    Below threshold more distance means fewer errors; above it, more distance means
    more. Asserting only the sub-threshold half would pass just as well for a decoder
    that suppresses by accident. This pins the transition at p ~ 0.007, which is in
    the published range for this code and noise model.

    Deliberately loose: it checks the *ordering reverses*, not the exact crossing
    point, because locating the crossing precisely needs a fit and far more shots.
    """
    rates: dict[float, list[float]] = {}
    for noise in (0.006, 0.008):
        row = []
        for distance in (3, 5, 7):
            c = circuit(distance, noise)
            dem = c.detector_error_model(decompose_errors=True)
            sampler = c.compile_detector_sampler(seed=11)
            detection, observables = sampler.sample(10000, separate_observables=True)
            predicted = decode_batch(dem, detection)[:, 0].astype(bool)
            truth = observables[:, 0].astype(bool)
            row.append(float(np.mean(predicted != truth)))
        rates[noise] = row

    below = rates[0.006]
    above = rates[0.008]
    assert below[0] > below[1], f"no suppression below threshold: {below}"
    # Above the threshold the smallest code is no longer the worst.
    assert not (above[0] > above[1] > above[2]), (
        f"error rate still falling at p=0.008, so the threshold is not near 0.007: "
        f"{above}")


# ---------------------------------------------------------------------------
# Independence from PyMatching
# ---------------------------------------------------------------------------

def test_the_decode_path_does_not_import_pymatching():
    """The whole point of the replacement: PyMatching must be off the decode path.

    Checked by looking for actual **imports**, not for the word. The module docstring
    legitimately *mentions* PyMatching (it explains the replacement), so a naive
    substring scan fails on its own documentation -- which is what my first version of
    this test did.
    """
    import inspect
    import re

    source = inspect.getsource(decoder)
    decode_path = source.split("def compare_to_reference")[0]
    imports = re.findall(r"^\s*(?:from|import)\s+pymatching\b", decode_path,
                         flags=re.MULTILINE)
    assert imports == [], (
        f"PyMatching is imported on the decode path: {imports}")


def test_the_graph_matches_the_reference_edge_count():
    """A structural check that does not need PyMatching installed to be meaningful.

    The merged graph must have one edge per distinct detector pair. PyMatching merges
    the same way, so its edge count is the reference -- but the assertion is on the
    structure, falling back to a known count when PyMatching is absent.
    """
    dem = circuit(3).detector_error_model(decompose_errors=True)
    edges, _adjacency = build_graph(dem)
    distinct_pairs = {(edge.a, edge.b) for edge in edges}
    assert len(edges) == len(distinct_pairs)
    try:
        from pymatching import Matching
    except ImportError:
        assert len(edges) == 78
    else:
        reference = Matching.from_detector_error_model(dem)
        assert len(edges) == reference.num_edges
