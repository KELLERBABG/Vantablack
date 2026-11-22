"""Asynchronous discrete-event simulation kernel.

This is the simulation **kernel**, not a helper.  Everything that changes state
over time should go through it, so that ordering questions -- "did the photon
arrive before the memory expired?" -- have a defined answer at the resolution
where they are asked.

Time unit and precision
-----------------------
Time is a float in **seconds** and the kernel imposes no resolution of its own,
so a caller working in microseconds can simply pass microseconds.  That is
deliberate: microsecond causality with a correct ordering guarantee is a step
change over step-based propagation, and it is testable.  Picosecond precision is
not attempted, because sub-nanosecond ordering without a hardware clock to
justify it is precision theatre.

Causality contract
------------------
The kernel guarantees the following, and the test suite enforces each one:

1. **Monotone time.** ``current_time`` never decreases.  Events execute in
   non-decreasing order of their scheduled time.
2. **Deterministic ties.** Events at equal time execute in insertion order, so
   a simulation is reproducible from the same schedule.  (Handlers that consume
   randomness are reproducible only if their RNG is seeded -- the kernel does
   not manage randomness.)
3. **No scheduling into the past.** Once execution has begun, scheduling an
   event before ``current_time`` would make cause and effect observably
   inconsistent, so it raises :class:`MoveToPastError`.  Before the first event
   runs, any time is allowed, because negative offsets are the natural way to
   express "already in flight" initial conditions.

The third rule is the one that earns its keep.  A step-based simulation cannot
express it at all, and an event kernel that does not enforce it will happily
produce a plausible-looking timeline in which a swap completes before its input
pair was created.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable


class MoveToPastError(ValueError):
    """Raised when an event is scheduled before the current simulation time."""


@dataclass
class Event:
    """A timestamped state change.

    Ordering is **strictly** ``(time, seq)``.  ``seq`` is a monotonic insertion
    counter and is what makes equal-time ordering deterministic.

    Note the explicit :meth:`__lt__` and the absence of ``order=True``.  A
    ``@dataclass(order=True)`` with ``compare=False`` on the payload fields
    looks right but is not: the generated comparison still falls through to
    tuple comparison of the *remaining* fields, so ``heapq`` will order
    equal-time events by ``kind`` and ``node_id`` (i.e. alphabetically by node
    name) instead of by insertion.  That is a silent reproducibility bug, and
    it is why the tie-break is implemented by hand here.
    """

    time: float
    seq: int
    kind: str
    node_id: str
    payload: dict = field(default_factory=dict)

    def __lt__(self, other: "Event") -> bool:
        return (self.time, self.seq) < (other.time, other.seq)


EventHandler = Callable[[str, str, dict, float], None]
"""(node_id, kind, payload, current_time) -> None"""


class Scheduler:
    """Priority-queue discrete-event kernel.

    Events are processed in time order.  Handlers are registered per event
    *kind*.  :meth:`step` runs one event, :meth:`run` drains the queue, and
    :meth:`run_until` drains up to a time horizon while leaving later events
    queued -- which is what lets a caller drive a simulation in windows.
    """

    def __init__(self, *, allow_move_to_past: bool = False):
        self._queue: list[Event] = []
        self._seq = 0
        self._time = 0.0
        self._started = False
        self._allow_past = bool(allow_move_to_past)
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self.run_count = 0

    # Scheduling
    def schedule(self, time: float, kind: str, node_id: str,
                 payload: dict | None = None) -> None:
        """Insert an event into the queue.

        Raises :class:`MoveToPastError` if ``time`` precedes the current
        simulation time and execution has already begun.  Pass
        ``allow_move_to_past=True`` to the constructor to override that, for a
        deliberately retroactive correction.
        """
        time = float(time)
        if self._started and not self._allow_past and time < self._time:
            raise MoveToPastError(
                f"cannot schedule {kind!r} at t={time} while the clock reads "
                f"t={self._time}; that would make cause and effect observably "
                f"inconsistent"
            )
        self._seq += 1
        ev = Event(time=time, seq=self._seq, kind=kind,
                   node_id=node_id, payload=payload or {})
        heapq.heappush(self._queue, ev)

    def schedule_now(self, kind: str, node_id: str,
                     payload: dict | None = None) -> None:
        """Schedule an event at the current simulation time."""
        self.schedule(self._time, kind, node_id, payload)

    def schedule_relative(self, delta: float, kind: str, node_id: str,
                          payload: dict | None = None) -> None:
        """Schedule an event at current_time + delta."""
        self.schedule(self._time + float(delta), kind, node_id, payload)

    # Registration
    def on(self, kind: str, handler: EventHandler):
        self._handlers[kind].append(handler)

    def off(self, kind: str, handler: EventHandler):
        try:
            self._handlers[kind].remove(handler)
        except ValueError:
            pass

    # Execution
    @property
    def current_time(self) -> float:
        return self._time

    @property
    def now(self) -> float:
        """Alias for :attr:`current_time`; reads better inside handlers."""
        return self._time

    def _dispatch(self, ev: Event) -> None:
        """Advance the clock and run every handler registered for the kind."""
        self._time = ev.time
        self._started = True
        for handler in self._handlers.get(ev.kind, []):
            handler(ev.node_id, ev.kind, ev.payload, self._time)

    def step(self) -> bool:
        """Execute the next pending event.  Returns False if the queue is empty."""
        if not self._queue:
            return False
        self._dispatch(heapq.heappop(self._queue))
        self.run_count += 1
        return True

    def run(self, max_steps: int = 0) -> int:
        """Run all events, or at most ``max_steps``.  Returns the count run."""
        count = 0
        while self._queue:
            if max_steps and count >= max_steps:
                break
            self._dispatch(heapq.heappop(self._queue))
            self.run_count += 1
            count += 1
        return count

    def run_until(self, horizon: float) -> int:
        """Run every event with ``time <= horizon``.

        Events strictly after the horizon stay queued, so a caller can drive a
        simulation in windows without draining it.  Returns the count run.
        """
        horizon = float(horizon)
        count = 0
        while self._queue and self._queue[0].time <= horizon:
            self._dispatch(heapq.heappop(self._queue))
            self.run_count += 1
            count += 1
        return count

    def peek_time(self) -> float | None:
        """Time of the next pending event, or None."""
        return self._queue[0].time if self._queue else None

    def clear(self):
        """Discard every pending event, handler and reset the clock."""
        self._queue.clear()
        self._handlers.clear()
        self._time = 0.0
        self._started = False
        self.run_count = 0

    @property
    def pending_count(self) -> int:
        return len(self._queue)
