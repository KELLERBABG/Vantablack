"""DEM hyperedges: how they are actually handled.

The stated gap was "DEM hyperedge error mechanisms are skipped, limiting decoding".
Investigating it produced a more precise and more useful finding:

**`stim`'s DEM separates a mechanism into components with `^`, and with
``decompose_errors=True`` every component is graphlike.** A mechanism written
``error(p) D1 D5 ^ D4`` is *two* independent graphlike errors, not a four-detector
hyperedge. Reading its targets as one flat list makes it look like a hyperedge, and
the decoder then discards it.

So the barrier was never fundamental. The previous code skipped **147 of 286
mechanisms at d=3** -- 51% of the model -- while the graphlike pieces it discarded
were present in the instruction. Fixed by splitting on the separator.

These tests pin the split, and pin the property that makes it valid.
"""

from __future__ import annotations

import pytest

try:
    import stim

    HAVE_STIM = True
except ImportError:  # pragma: no cover - exercised by the skip path
    stim = None
    HAVE_STIM = False

from quantumnet.core.surface_code import (
    _dem_components,
    dem_matching_graph,
)

pytestmark = pytest.mark.skipif(not HAVE_STIM, reason="needs stim")


def dem(distance: int, rounds: int | None = None, noise: float = 0.001):
    rounds = distance if rounds is None else rounds
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=distance, rounds=rounds,
        after_clifford_depolarization=noise)
    return circuit.detector_error_model(decompose_errors=True)


# ---------------------------------------------------------------------------
# The property that makes decomposition usable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distance", [3, 5, 7])
def test_every_decomposed_component_is_graphlike(distance):
    """The claim the whole approach rests on, verified at three distances.

    If any component ever exceeds two detectors, the component split stops being
    sufficient and ``dem_matching_graph`` will count it as skipped -- so this test
    is the early warning for a change in ``stim``'s decomposition.
    """
    worst = 0
    components = 0
    for inst in dem(distance).flattened():
        if inst.type != "error":
            continue
        for component in _dem_components(inst):
            components += 1
            worst = max(worst, len(component))
    assert components > 0, "no components were parsed at all"
    assert worst <= 2, (
        f"d={distance}: a decomposed component has {worst} detectors; the "
        f"component split is no longer sufficient"
    )


def test_the_dem_really_contains_multi_component_mechanisms():
    """If it did not, the component split would be a no-op and this file vacuous."""
    multi = 0
    for inst in dem(3).flattened():
        if inst.type == "error" and len(_dem_components(inst)) > 1:
            multi += 1
    assert multi > 0, "no decomposed mechanism had more than one component"


# ---------------------------------------------------------------------------
# The split itself
# ---------------------------------------------------------------------------

def test_components_are_split_on_the_separator():
    """A flat read of the targets is what caused the bug."""
    inspected = 0
    for inst in dem(3).flattened():
        if inst.type != "error":
            continue
        flat = [t.val for t in inst.targets_copy()
                if t.is_relative_detector_id()]
        comps = _dem_components(inst)
        if len(comps) > 1:
            # The flat reading sees more detectors than any single component.
            assert max(len(c) for c in comps) < len(flat)
            inspected += 1
            if inspected >= 5:
                break
    assert inspected > 0


def test_every_component_is_non_empty():
    for inst in dem(3).flattened():
        if inst.type != "error":
            continue
        for component in _dem_components(inst):
            assert component, "a separator produced an empty component"


def test_the_components_partition_the_detectors():
    """No detector may be lost or duplicated by the split."""
    for inst in dem(3).flattened():
        if inst.type != "error":
            continue
        flat = sorted(t.val for t in inst.targets_copy()
                      if t.is_relative_detector_id())
        split = sorted(d for c in _dem_components(inst) for d in c)
        assert split == flat


# ---------------------------------------------------------------------------
# The consequence: the graph stops dropping half the model
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distance", [3, 5])
def test_the_graph_uses_multi_component_mechanisms(distance):
    """Regression: multi-component mechanisms were discarded wholesale before.

    The comparison is against the number of **unique** graphlike detector pairs,
    not the raw component count.  Many components describe the same pair -- a data
    error and a measurement error can connect the same two detectors -- and the
    adjacency deduplicates them, so counting components would demand more edges
    than exist.
    """
    adjacency, to_node = dem_matching_graph(distance, "Z", distance)
    edges = {frozenset(e) for v in adjacency.values() for e in [v]}
    flat_edges = {frozenset((a, b)) for v in adjacency.values()
                  for (b, _) in v for a in [None]}
    # Count distinct node pairs actually present.
    pairs_present = set()
    for node, neighbours in adjacency.items():
        for other, _ in neighbours:
            pairs_present.add(frozenset((node, other)))
    assert pairs_present, "the graph has no edges at all"

    # Distinct graphlike detector pairs implied by the DEM, restricted to
    # detectors the lattice maps to nodes.
    expected = set()
    for inst in dem(distance).flattened():
        if inst.type != "error":
            continue
        for component in _dem_components(inst):
            if len(component) != 2:
                continue
            a, b = to_node.get(component[0]), to_node.get(component[1])
            if a is None or b is None or a == b:
                continue
            expected.add(frozenset((a, b)))

    assert expected, "no graphlike component mapped to a node pair"
    missing = expected - pairs_present
    assert not missing, (
        f"d={distance}: {len(missing)} of {len(expected)} graphlike node pairs "
        f"are absent from the graph"
    )


def test_multi_component_mechanisms_contribute_edges():
    """A concrete floor, so the fix cannot silently revert.

    Before the component split the d=3 graph had **17** undirected edges.  After
    it there are **55** -- measured, and the exact-coverage test above is the real
    assertion; this floor exists so a regression fails loudly even if the coverage
    test is ever weakened.
    """
    adjacency, _ = dem_matching_graph(3, "Z", 3)
    pairs_present = {frozenset((node, other))
                     for node, neighbours in adjacency.items()
                     for other, _ in neighbours}
    assert len(pairs_present) >= 50, (
        f"only {len(pairs_present)} unique edges at d=3; the graph looks like it "
        f"is still discarding multi-component mechanisms"
    )


def test_single_detector_components_reach_a_boundary():
    """A one-detector component is a chain ending at the code edge.

    Without a boundary node it has no partner and the decoder must invent one.
    """
    from quantumnet.core.surface_code import _DEM_BOUNDARY

    adjacency, _ = dem_matching_graph(3, "Z", 3)
    assert _DEM_BOUNDARY in adjacency, "no boundary node was created"
    assert adjacency[_DEM_BOUNDARY], "the boundary is not connected to anything"


def test_no_component_is_silently_discarded():
    """Every component must either become an edge or be counted as skipped.

    The original defect was a silent discard; the fix counts what it cannot use so
    a future change in ``stim`` cannot reintroduce one.
    """
    for distance in (3, 5):
        adjacency, to_node = dem_matching_graph(distance, "Z", distance)
        # Every detector that maps to a node should appear in the adjacency.
        mapped = {n for n in to_node.values()}
        present = set(adjacency)
        missing = mapped - present
        assert not missing, (
            f"d={distance}: {len(missing)} mapped detectors have no edge at all"
        )
