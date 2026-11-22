"""Load and the classical control plane.

The acceptance test for this milestone is deliberately negative: **throughput is
undefined with no load, and becomes defined with a request stream.** That is worth
asserting rather than assuming, because "throughput = 0" is a number that looks like a
result and means nothing.

The arrival process is checked against its own statistics. A mis-specified arrival
process silently changes every throughput number downstream, so an exponential
inter-arrival mean and a Poisson window count are tested rather than trusted.
"""

from __future__ import annotations

import numpy as np
import pytest

from quantumnet.core.latency import ClassicalLink
from quantumnet.topology.load import (
    ClassicalControlPlane,
    LoadError,
    Request,
    RequestGenerator,
    throughput,
)
from quantumnet.topology.resources import ResourceManager


def generator(rate: float = 5.0, seed: int = 7) -> RequestGenerator:
    return RequestGenerator(rate_per_s=rate, pairs=[("A", "B")], seed=seed)


# ---------------------------------------------------------------------------
# The acceptance test: undefined, then defined
# ---------------------------------------------------------------------------

def test_throughput_is_undefined_with_no_load():
    """The milestone's own acceptance criterion.

    Returning ``0.0`` here would be a number that looks like a measurement. There is
    nothing to divide by, so the answer is ``None`` and it says why.
    """
    result = throughput([], 0, horizon_s=100.0)
    assert result["throughput_per_s"] is None
    assert result["offered_load_per_s"] is None
    assert result["grant_ratio"] is None
    assert result["consistent"] is None
    assert "UNDEFINED" in result["note"]


def test_throughput_becomes_defined_with_load():
    requests = generator().generate_until(50.0)
    assert requests
    result = throughput(requests, granted=len(requests), horizon_s=50.0)
    assert result["throughput_per_s"] is not None
    assert result["requests"] == len(requests)
    assert result["grant_ratio"] == pytest.approx(1.0)


def test_throughput_cannot_exceed_the_arrival_rate():
    """A delivered rate above the offered rate is an accounting bug, not a fast network.

    Surfaced as ``consistent=False`` rather than reported as a success.
    """
    requests = generator().generate_until(20.0)
    impossible = throughput(requests, granted=len(requests) * 10, horizon_s=20.0)
    assert impossible["consistent"] is False
    assert "EXCEEDS" in impossible["note"]


def test_a_zero_horizon_is_refused():
    with pytest.raises(LoadError):
        throughput([], 0, horizon_s=0.0)


# ---------------------------------------------------------------------------
# The arrival process, against its own statistics
# ---------------------------------------------------------------------------

def test_inter_arrival_times_are_exponential_with_the_right_mean():
    """Poisson arrivals: mean gap is ``1/rate`` and the spread matches the mean."""
    gaps = np.diff([0.0] + [r.arrival_time_s for r in generator(rate=5.0).generate(4000)])
    assert gaps.mean() == pytest.approx(0.2, abs=0.01)
    # For an exponential, standard deviation equals the mean.
    assert gaps.std() == pytest.approx(0.2, abs=0.02)


def test_the_arrival_count_in_a_window_is_poisson():
    """Mean count in a window of length T is ``rate * T``."""
    counts = []
    for seed in range(40):
        stream = RequestGenerator(rate_per_s=5.0, pairs=[("A", "B")], seed=seed)
        counts.append(len(stream.generate_until(100.0)))
    assert np.mean(counts) == pytest.approx(500, rel=0.05)


def test_the_same_seed_gives_the_same_stream():
    """Reproducibility, without which no throughput number is comparable."""
    a = [r.arrival_time_s for r in generator(seed=11).generate(50)]
    b = [r.arrival_time_s for r in generator(seed=11).generate(50)]
    assert a == b


def test_different_seeds_give_different_streams():
    a = [r.arrival_time_s for r in generator(seed=1).generate(50)]
    b = [r.arrival_time_s for r in generator(seed=2).generate(50)]
    assert a != b


def test_arrivals_are_monotone():
    times = [r.arrival_time_s for r in generator().generate(200)]
    assert times == sorted(times)
    assert all(t > 0 for t in times)


def test_generate_until_does_not_lose_the_next_arrival():
    """A request past the horizon must not be silently dropped.

    The generator steps its clock back when it overshoots, so the first arrival after
    one window is the same arrival a longer window would see. Without that, extending a
    simulation would silently discard demand.
    """
    stream = generator(seed=5)
    short = stream.generate_until(10.0)
    following = len(short) + 1
    rest = stream.generate(following - len(short))
    fresh = generator(seed=5).generate(following)
    assert [r.arrival_time_s for r in short + rest] == [r.arrival_time_s for r in fresh]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_a_non_positive_rate_is_refused():
    with pytest.raises(LoadError):
        RequestGenerator(rate_per_s=0.0, pairs=[("A", "B")])


def test_a_negative_rate_is_refused():
    with pytest.raises(LoadError):
        RequestGenerator(rate_per_s=-1.0, pairs=[("A", "B")])


def test_an_empty_pair_list_is_refused():
    """A stream with nowhere to go is not a load."""
    with pytest.raises(LoadError):
        RequestGenerator(rate_per_s=1.0, pairs=[])


def test_a_negative_generate_count_is_refused():
    with pytest.raises(LoadError):
        generator().generate(-1)


def test_requests_spread_across_the_supplied_pairs():
    stream = RequestGenerator(rate_per_s=5.0,
                              pairs=[("A", "B"), ("C", "D")], seed=3)
    requests = stream.generate(10)
    assert {r.source for r in requests} == {"A", "C"}


# ---------------------------------------------------------------------------
# The classical control plane
# ---------------------------------------------------------------------------

def test_messages_are_counted():
    """An uncounted classical cost is invisible in the results."""
    plane = ClassicalControlPlane()
    assert plane.message_count == 0
    for t in (0.0, 1.0, 2.0):
        plane.send("A", "B", distance_km=100.0, time_s=t)
    assert plane.message_count == 3
    assert plane.total_delay_s() > 0


def test_delay_is_a_round_trip_not_one_way():
    """Coordination needs the acknowledgement, so charging one way halves the cost."""
    link = ClassicalLink()
    one_way = link.one_way_s(100.0)
    plane = ClassicalControlPlane(link=link)
    message = plane.send("A", "B", distance_km=100.0, time_s=0.0)
    assert message.delay_s == pytest.approx(2 * one_way)


def test_delay_scales_with_distance():
    plane = ClassicalControlPlane()
    near = plane.send("A", "B", distance_km=10.0, time_s=0.0).delay_s
    far = plane.send("A", "B", distance_km=100.0, time_s=0.0).delay_s
    assert far == pytest.approx(10 * near)


def test_a_message_is_in_flight_only_within_its_window():
    plane = ClassicalControlPlane()
    message = plane.send("A", "B", distance_km=100.0, time_s=5.0)
    assert not message.in_flight_at(4.9)
    assert message.in_flight_at(5.0)
    assert message.in_flight_at(5.0 + message.delay_s / 2)
    assert not message.in_flight_at(5.0 + message.delay_s)


def test_delivery_time_is_send_plus_delay():
    plane = ClassicalControlPlane()
    message = plane.send("A", "B", distance_km=50.0, time_s=3.0)
    assert message.deliver() == pytest.approx(3.0 + message.delay_s)


def test_a_negative_distance_is_refused():
    with pytest.raises(LoadError):
        ClassicalControlPlane().send("A", "B", distance_km=-1.0, time_s=0.0)


def test_the_summary_reports_what_was_paid():
    plane = ClassicalControlPlane()
    plane.send("A", "B", distance_km=100.0, time_s=0.0)
    plane.send("A", "B", distance_km=100.0, time_s=1.0)
    summary = plane.summary()
    assert summary["messages"] == 2
    assert summary["total_delay_s"] == pytest.approx(2 * summary["mean_delay_s"])


# ---------------------------------------------------------------------------
# Handing off to the existing arbiter
# ---------------------------------------------------------------------------

def test_a_request_becomes_a_reservation_for_the_existing_arbiter():
    """The load layer must not re-implement contention."""
    request = Request(source="A", target="B", arrival_time_s=2.5,
                      memory_size=2, target_fidelity=0.8, identity=4)
    reservation = generator().to_reservation(request, duration_s=1.5,
                                             nodes=["A", "M", "B"])
    assert reservation.initiator == "A"
    assert reservation.responder == "B"
    assert reservation.start_time == pytest.approx(2.5)
    assert reservation.end_time == pytest.approx(4.0)
    assert reservation.path == ["A", "M", "B"]


def test_the_arbiter_sees_the_stream():
    """End to end through ResourceManager: a load produces decisions."""
    from quantumnet.topology.load import run_load

    managers = {"A": ResourceManager(node_id="A", size=4),
                "B": ResourceManager(node_id="B", size=4)}
    stream = RequestGenerator(rate_per_s=2.0, pairs=[("A", "B")], seed=3)
    plane = ClassicalControlPlane()
    result = run_load(stream, managers, horizon_s=20.0, duration_s=0.5,
                      control=plane)
    assert result["requests"] > 0
    assert result["throughput_per_s"] is not None
    assert result["control_plane"]["messages"] == result["requests"]
    assert {outcome for _request, outcome in result["outcomes"]}
