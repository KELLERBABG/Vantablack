"""Discrete-event kernel tests.

The kernel's value is its *guarantees*, so these test the contract rather than
the implementation: monotone time, deterministic tie-breaking, and refusal to
schedule into the past.  Rule 3 is the one a step-based simulation cannot express
at all, and the one an unchecked event kernel will silently violate by producing
a timeline in which an effect precedes its cause.
"""

from __future__ import annotations

import pytest

from quantumnet.core.scheduler import Event, MoveToPastError, Scheduler


def _recorder():
    """A handler that appends ``(node_id, kind, t)`` to a shared list."""
    log: list[tuple[str, str, float]] = []

    def handler(node_id: str, kind: str, payload: dict, t: float) -> None:
        log.append((node_id, kind, t))

    return log, handler


# ---------------------------------------------------------------------------
# Ordering and monotone time
# ---------------------------------------------------------------------------

def test_events_execute_in_time_order_not_insertion_order():
    sch = Scheduler()
    log, handler = _recorder()
    sch.on("x", handler)
    # inserted out of order on purpose
    sch.schedule(3.0, "x", "c")
    sch.schedule(1.0, "x", "a")
    sch.schedule(2.0, "x", "b")
    sch.run()
    assert [node for node, _, _ in log] == ["a", "b", "c"]
    assert [t for _, _, t in log] == [1.0, 2.0, 3.0]


def test_current_time_is_monotone_across_a_long_run():
    sch = Scheduler()
    seen: list[float] = []
    sch.on("tick", lambda n, k, p, t: seen.append(t))
    for i in range(200):
        # deliberately jumbled scheduling order
        sch.schedule(float((i * 37) % 200), "tick", f"n{i}")
    sch.run()
    assert seen == sorted(seen), "clock went backwards"
    assert sch.current_time == max(seen)


def test_equal_time_events_run_in_insertion_order():
    """Deterministic ties are what make a run reproducible."""
    sch = Scheduler()
    order: list[str] = []
    sch.on("x", lambda n, k, p, t: order.append(n))
    for name in ("first", "second", "third", "fourth"):
        sch.schedule(5.0, "x", name)
    sch.run()
    assert order == ["first", "second", "third", "fourth"]


def test_same_schedule_replays_identically():
    """Two schedulers fed the same schedule produce the same trace."""
    def trace() -> list[tuple[str, float]]:
        sch = Scheduler()
        out: list[tuple[str, float]] = []
        sch.on("x", lambda n, k, p, t: out.append((n, t)))
        for i in range(50):
            sch.schedule(float((i * 13) % 50), "x", f"n{i}")
        sch.run()
        return out

    assert trace() == trace()


def test_event_ordering_key_is_time_then_sequence():
    a = Event(time=1.0, seq=1, kind="k", node_id="a")
    b = Event(time=1.0, seq=2, kind="k", node_id="b")
    c = Event(time=2.0, seq=0, kind="k", node_id="c")
    assert a < b < c
    # seq breaks the tie regardless of the other payload fields
    assert min(b, a) is a


# ---------------------------------------------------------------------------
# Causality: no scheduling into the past
# ---------------------------------------------------------------------------

def test_scheduling_into_the_past_raises_once_started():
    sch = Scheduler()
    sch.on("x", lambda n, k, p, t: None)
    sch.schedule(10.0, "x", "a")
    sch.step()
    assert sch.current_time == 10.0
    with pytest.raises(MoveToPastError):
        sch.schedule(9.999, "x", "b")


def test_scheduling_into_the_past_is_allowed_after_start_by_opt_in():
    sch = Scheduler(allow_move_to_past=True)
    log, handler = _recorder()
    sch.on("x", handler)
    sch.schedule(10.0, "x", "a")
    sch.step()
    sch.schedule(5.0, "x", "early")   # explicit opt-in
    sch.run()
    assert [n for n, _, _ in log] == ["a", "early"]


def test_scheduling_at_the_current_time_is_allowed():
    sch = Scheduler()
    log, handler = _recorder()
    sch.on("x", handler)
    sch.schedule(4.0, "x", "a")
    sch.step()
    sch.schedule_now("x", "same_time")
    sch.run()
    assert [n for n, _, _ in log] == ["a", "same_time"]


def test_scheduling_in_the_past_before_execution_is_allowed():
    """Negative offsets express "already in flight" initial conditions.

    Enforcement only applies once the clock has been advanced by a real event,
    because before that there is no established "now" to contradict.
    """
    sch = Scheduler()
    log, handler = _recorder()
    sch.on("x", handler)
    sch.schedule(-1.0, "x", "already_in_flight")
    sch.schedule(2.0, "x", "later")
    sch.run()
    assert [n for n, _, _ in log] == ["already_in_flight", "later"]


def test_a_handler_cannot_schedule_its_own_cause():
    """The mistake this rule exists to catch, stated as a test.

    A swap handler that tries to schedule the creation of its input pair *after*
    the swap has run would be describing an effect preceding its cause.
    """
    sch = Scheduler()
    results: list[str] = []

    def swap_handler(node_id, kind, payload, t):
        results.append(f"swap at {t}")
        with pytest.raises(MoveToPastError):
            sch.schedule_relative(-1.0, "generate", node_id)

    sch.on("swap", swap_handler)
    sch.schedule(1.0, "generate", "R0")
    sch.schedule(2.0, "swap", "R0")
    sch.run()
    assert results == ["swap at 2.0"]


# ---------------------------------------------------------------------------
# Driven execution
# ---------------------------------------------------------------------------

def test_run_until_leaves_later_events_queued():
    sch = Scheduler()
    log, handler = _recorder()
    sch.on("x", handler)
    for t in (1.0, 2.0, 3.0, 4.0):
        sch.schedule(t, "x", f"n{t}")
    assert sch.run_until(2.5) == 2
    assert [t for _, _, t in log] == [1.0, 2.0]
    assert sch.pending_count == 2
    assert sch.peek_time() == 3.0
    assert sch.run_until(4.0) == 2
    assert sch.pending_count == 0


def test_run_until_is_inclusive_of_the_horizon():
    sch = Scheduler()
    sch.on("x", lambda n, k, p, t: None)
    sch.schedule(2.0, "x", "a")
    assert sch.run_until(2.0) == 1


def test_run_respects_max_steps():
    sch = Scheduler()
    sch.on("x", lambda n, k, p, t: None)
    for i in range(10):
        sch.schedule(float(i), "x", f"n{i}")
    assert sch.run(max_steps=4) == 4
    assert sch.pending_count == 6


def test_step_returns_false_when_drained():
    sch = Scheduler()
    sch.on("x", lambda n, k, p, t: None)
    assert sch.step() is False
    sch.schedule(1.0, "x", "a")
    assert sch.step() is True
    assert sch.step() is False


def test_run_count_tracks_dispatches():
    sch = Scheduler()
    sch.on("x", lambda n, k, p, t: None)
    for i in range(7):
        sch.schedule(float(i), "x", f"n{i}")
    sch.run()
    assert sch.run_count == 7


def test_payload_and_node_reach_the_handler():
    sch = Scheduler()
    seen = []
    sch.on("x", lambda n, k, p, t: seen.append((n, k, p)))
    sch.schedule(1.0, "x", "node7", {"fidelity": 0.9})
    sch.run()
    assert seen == [("node7", "x", {"fidelity": 0.9})]


def test_multiple_handlers_for_one_kind_all_fire():
    sch = Scheduler()
    seen: list[str] = []
    sch.on("x", lambda n, k, p, t: seen.append("a"))
    sch.on("x", lambda n, k, p, t: seen.append("b"))
    sch.schedule(1.0, "x", "n")
    sch.run()
    assert seen == ["a", "b"]


def test_off_unregisters_a_handler_and_is_idempotent():
    sch = Scheduler()
    seen: list[str] = []

    def handler(node_id, kind, payload, t):
        seen.append(node_id)

    sch.on("x", handler)
    sch.off("x", handler)
    sch.off("x", handler)          # second removal must not raise
    sch.schedule(1.0, "x", "n")
    sch.run()
    assert seen == []


def test_unhandled_event_kinds_are_harmless():
    sch = Scheduler()
    log, handler = _recorder()
    sch.on("known", handler)
    sch.schedule(1.0, "known", "a")
    sch.schedule(2.0, "unknown", "b")
    assert sch.run() == 2
    assert [n for n, _, _ in log] == ["a"]


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_clear_resets_clock_queue_handlers_and_counters():
    sch = Scheduler()
    log, handler = _recorder()
    sch.on("x", handler)
    sch.schedule(5.0, "x", "a")
    sch.step()
    assert sch.current_time == 5.0
    sch.clear()
    assert sch.current_time == 0.0
    assert sch.pending_count == 0
    assert sch.run_count == 0
    # handlers are gone too, and scheduling in the past is legal again
    sch.schedule(-1.0, "x", "a")
    sch.run()
    assert log == [("a", "x", 5.0)]


def test_peek_time_is_none_when_empty():
    assert Scheduler().peek_time() is None


def test_now_is_an_alias_for_current_time():
    sch = Scheduler()
    sch.on("x", lambda n, k, p, t: None)
    sch.schedule(3.5, "x", "a")
    sch.step()
    assert sch.now == sch.current_time == 3.5


def test_microsecond_resolution_is_preserved():
    """The kernel imposes no resolution, so microsecond work stays exact."""
    sch = Scheduler()
    seen: list[float] = []
    sch.on("x", lambda n, k, p, t: seen.append(t))
    for us in (1e-6, 2e-6, 1.5e-6):
        sch.schedule(us, "x", "n")
    sch.run()
    assert seen == [1e-6, 1.5e-6, 2e-6]
    assert sch.current_time == 2e-6
