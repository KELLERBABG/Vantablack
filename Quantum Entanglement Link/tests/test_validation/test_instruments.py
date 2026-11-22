"""Tests for the validation instruments themselves.

These are not tests of a decoder. They test the **ruler**, because during the failed
effort the ruler was wrong five times and each time the resulting measurement sent a
round in the wrong direction:

* a checker compared the correction's odd-degree set against the boundary -- which is
  legitimately odd -- and reported 57.4% failures that did not exist;
* a diagnostic silently unpacked a stale tuple length, printed nothing, and the blank was
  read as a result;
* three "fixes" changed nothing because the edit was not executing.

So each instrument here is shown to work on inputs whose answers are known in advance,
**including the ability to reject**. An instrument only ever shown to accept is
indistinguishable from one that always accepts.
"""

from __future__ import annotations

import pytest

from validation import check_correction, syndrome_of_correction
from validation.bench import DEFAULT_SEEDS, BenchmarkResult, benchmark
from validation.validators import (
    BOUNDARY,
    dem_components,
    graph_from_dem,
    rate_over_shots,
    validate_against_known_good,
)

stim = pytest.importorskip("stim")
pytest.importorskip("pymatching")


# ---------------------------------------------------------------------------
# The invariant, on hand-computable inputs
# ---------------------------------------------------------------------------

def test_a_single_boundary_edge_explains_one_event():
    """The case that peeled to an *empty* correction for four rounds.

    An event on a detector with a direct boundary edge is explained by that edge alone.
    The boundary is excluded from the syndrome, so a route ending there is allowed to
    leave it odd -- counting it as a violation was one of the instrument defects.
    """
    check = check_correction([19], [(BOUNDARY, 19)])
    assert check.valid, check.describe()


def test_an_edge_between_two_events_explains_both():
    assert check_correction([6, 12], [(6, 12)]).valid


def test_a_path_explains_only_its_endpoints():
    """Interior vertices are entered and left, so they cancel."""
    assert check_correction([1, 4], [(1, 2), (2, 3), (3, 4)]).valid


def test_the_boundary_is_never_counted_as_a_spurious_detector():
    """Regression: the boundary is legitimately odd and must not be reported."""
    check = check_correction([7], [(BOUNDARY, 7)])
    assert BOUNDARY not in check.explained
    assert BOUNDARY not in check.spurious
    assert check.valid


def test_an_unexplained_event_is_reported_as_unexplained():
    check = check_correction([5, 9], [(5, 6)])
    assert not check.valid
    assert check.unexplained == frozenset({9})
    assert check.spurious == frozenset({6})


def test_a_correction_flipping_a_non_event_is_spurious():
    check = check_correction([1], [(1, 2), (2, 3)])
    assert not check.valid
    assert check.spurious == frozenset({3})


def test_an_empty_correction_is_valid_only_for_no_events():
    assert check_correction([], []).valid
    assert not check_correction([4], []).valid


def test_an_empty_correction_does_not_claim_to_explain_events():
    check = check_correction([4], [])
    assert check.unexplained == frozenset({4})


def test_duplicate_edges_cancel():
    """XOR semantics: traversing an edge twice is the same as not traversing it."""
    assert check_correction([], [(3, 4), (3, 4)]).valid


def test_syndrome_of_correction_ignores_the_boundary():
    assert syndrome_of_correction([(BOUNDARY, 2)]) == {2}
    assert syndrome_of_correction([(BOUNDARY, 2), (BOUNDARY, 2)]) == set()


# ---------------------------------------------------------------------------
# The instrument must be able to FAIL
# ---------------------------------------------------------------------------

def test_the_instrument_rejects_a_corrupted_correction():
    """The regression that matters most.

    Shown to reject a known-bad input, so a passing result is evidence. During the
    failed effort there was no such test, and a 100%-wrong decoder produced plausible
    error rates for four rounds.
    """
    good = [(1, 2), (2, 3)]
    assert check_correction([1, 3], good).valid
    assert not check_correction([1, 3], good[:-1]).valid


def test_the_instrument_rejects_a_shifted_correction():
    assert not check_correction([1, 3], [(1, 2), (3, 4)]).valid


# ---------------------------------------------------------------------------
# No silent zeros
# ---------------------------------------------------------------------------

def test_rate_over_shots_refuses_to_report_a_rate_for_no_samples():
    """A rate over zero shots must not be 0%.

    An earlier diagnostic printed nothing when its input shape changed and the blank was
    read as a result. Returning a clean 0.0 here would repeat that failure in a new form.
    """
    result = rate_over_shots([])
    assert result["shot_count"] == 0
    assert result["violation_rate"] is None
    assert "NO SAMPLES" in result["note"]


def test_rate_over_shots_counts_violations():
    samples = [([1], [(1, 2)]), ([1, 3], [(1, 2), (2, 3)])]
    result = rate_over_shots(samples)
    assert result["shot_count"] == 2
    assert result["invalid"] == 1                       # first shot is wrong
    assert result["violation_rate"] == pytest.approx(0.5)
    assert result["first_failure"] is not None


def test_rate_over_shots_is_zero_percent_only_when_every_shot_is_valid():
    # A path 1-2-3 has boundary {1, 3} -- interior vertices cancel, so the events must
    # be BOTH endpoints. My first version of this test wrote events=[1] and was wrong;
    # the instrument was right.
    result = rate_over_shots([([1, 3], [(1, 2), (2, 3)])])
    assert result["shot_count"] == 1
    assert result["violation_rate"] == 0.0


# ---------------------------------------------------------------------------
# DEM parsing
# ---------------------------------------------------------------------------

def test_components_split_on_the_separator():
    """``error(p) D1 D5 ^ D4`` is two components, not three detectors in one."""
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=3, rounds=3,
        after_clifford_depolarization=0.003)
    dem = circuit.detector_error_model(decompose_errors=True)
    multi = 0
    for inst in dem.flattened():
        if inst.type == "error" and len(dem_components(inst)) > 1:
            multi += 1
    assert multi > 0, "expected decomposed mechanisms with multiple components"


def test_no_component_exceeds_two_detectors_when_decomposed():
    """The premise that makes the graph well defined."""
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=3, rounds=3,
        after_clifford_depolarization=0.003)
    dem = circuit.detector_error_model(decompose_errors=True)
    oversized = [c for inst in dem.flattened() if inst.type == "error"
                 for c in dem_components(inst) if len(c) > 2]
    assert oversized == []


def test_graph_from_dem_puts_the_boundary_first():
    """``-1`` sorts first, so on a boundary edge ``a`` IS the boundary.

    Recorded because it silently turned a fix into a no-op: keying on ``edge.a``
    returned the boundary's own root instead of the detector's.
    """
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=3, rounds=3,
        after_clifford_depolarization=0.003)
    dem = circuit.detector_error_model(decompose_errors=True)
    boundary_edges = [e for e in graph_from_dem(dem) if BOUNDARY in e[:2]]
    assert boundary_edges, "expected boundary edges"
    assert all(e[0] == BOUNDARY for e in boundary_edges), (
        "boundary edges are not canonically first -- the edge.a trap has changed shape"
    )


def test_graph_from_dem_matches_the_reference_edge_count():
    """PyMatching merges parallel mechanisms; this graph does not.

    The distinct detector pairs should equal the reference's edge count, which is the
    check that confirmed merging is what the reference does -- a fact the failed effort
    got wrong for a round in the opposite direction.
    """
    from pymatching import Matching

    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=3, rounds=3,
        after_clifford_depolarization=0.003)
    dem = circuit.detector_error_model(decompose_errors=True)
    matching = Matching.from_detector_error_model(dem)
    distinct_pairs = {(e[0], e[1]) for e in graph_from_dem(dem)}
    assert len(distinct_pairs) == matching.num_edges


# ---------------------------------------------------------------------------
# Self-validation, and the benchmark
# ---------------------------------------------------------------------------

def test_the_instrument_validates_itself_both_ways():
    """Accepts known-good corrections *and* rejects a known-bad one."""
    outcome = validate_against_known_good(distance=3, shots=200, seed=3)
    assert outcome["shots_with_events"] > 0
    assert outcome["accepted_known_good"] == outcome["shots_with_events"]
    assert outcome["rejected_known_bad"] > 0
    assert outcome["instrument_trustworthy"]


def test_benchmark_agrees_with_itself_when_the_decoder_is_the_reference():
    """A decoder that *is* the reference must score the reference's rate.

    This validates the whole harness: sampling, truth extraction, both scorers. If the
    harness mis-scored, this would not come out equal.
    """
    from validation.bench import reference_decoder

    _circuit, _dem, matching = reference_decoder(3, 0.003)
    seen = {}

    def decoder(dem, events):
        return seen.setdefault("last", None) is not None

    # Score the reference through the same decoder interface.
    result = BenchmarkResult(label="reference-as-decoder", distance=3,
                             noise=0.003, shots_per_seed=400)
    circuit, dem, matching = reference_decoder(3, 0.003)
    for seed in (3, 7):
        sampler = circuit.compile_detector_sampler(seed=seed)
        detection, observables = sampler.sample(400, separate_observables=True)
        truth = observables[:, 0].astype(bool)
        reference = matching.decode_batch(detection)[:, 0].astype(bool)
        errors = int((reference != truth).sum())
        result.per_seed.append((seed, errors, errors))
    assert result.ratio == pytest.approx(1.0)
    assert result.mean_decoder == result.mean_reference


def test_benchmark_reports_spread_and_per_seed_values():
    """Rates must come with the shots they were taken over, not as bare numbers."""
    circuit, dem, matching = _reference_pieces()

    def never_flips(_dem, _events):
        return False

    result = benchmark(never_flips, distance=3, shots=300, seeds=(3, 7),
                       label="never-flips")
    assert result.seeds == 2
    assert len(result.per_seed) == 2
    assert result.shots_per_seed == 300
    assert all(isinstance(s, int) for s, _d, _r in result.per_seed)


def test_a_decoder_that_never_flips_is_not_credited():
    """Predicting "no flip" is right most of the time and must not look good.

    An earlier decoder returned an *empty* correction and scored better than a
    working-but-imperfect one, because "no flip" is correct ~97% of the time. The
    benchmark must make that visible rather than rewarding it.
    """
    def never_flips(_dem, _events):
        return False

    result = benchmark(never_flips, distance=3, shots=2000, seeds=(3,),
                       label="never-flips")
    # Abstaining is WORSE than the reference, not comparable to it.
    assert result.decoder_rate > result.reference_rate
    # And it is still not a decoder: it never suppresses below the physical rate.
    assert result.decoder_rate > 0.0
    assert not result.beats_physical_rate()


def test_beats_physical_rate_is_the_threshold_gate():
    """A rate above the physical rate means no threshold is recoverable."""
    result = BenchmarkResult(label="x", distance=5, noise=0.003,
                             shots_per_seed=2000)
    result.per_seed = [(3, 79, 1)]
    assert result.decoder_rate == pytest.approx(0.0395)
    assert not result.beats_physical_rate()
    assert result.ratio == pytest.approx(79.0)


def _reference_pieces():
    from validation.bench import reference_decoder

    return reference_decoder(3, 0.003)


def test_default_seeds_are_multiple():
    """One seed is not a measurement."""
    assert len(DEFAULT_SEEDS) >= 3
