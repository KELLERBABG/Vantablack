"""Asynchronous discrete-event simulation core."""

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(order=True)
class Event:
    time: float
    seq: int = field(compare=False)
    kind: str = field(compare=False)
    node_id: str = field(compare=False)
    payload: dict = field(default_factory=dict, compare=False)


EventHandler = Callable[[str, str, dict, float], None]
"""(node_id, kind, payload, current_time) -> None"""


class Scheduler:
    """Priority-queue-based discrete-event scheduler.

    Events are processed in time order.  Handlers are registered by
    event *kind* string.  *Advance* runs the next event; *run* drains
    the queue.
    """

    def __init__(self):
        self._queue: list[Event] = []
        self._seq = 0
        self._time = 0.0
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------
    def schedule(self, time: float, kind: str, node_id: str,
                 payload: dict | None = None) -> None:
        """Insert an event into the queue."""
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
        self.schedule(self._time + delta, kind, node_id, payload)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def on(self, kind: str, handler: EventHandler):
        self._handlers[kind].append(handler)

    def off(self, kind: str, handler: EventHandler):
        try:
            self._handlers[kind].remove(handler)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    @property
    def current_time(self) -> float:
        return self._time

    def step(self) -> bool:
        """Execute the next pending event.  Returns False if queue empty."""
        if not self._queue:
            return False
        ev = heapq.heappop(self._queue)
        self._time = ev.time
        for h in self._handlers.get(ev.kind, []):
            h(ev.node_id, ev.kind, ev.payload, self._time)
        return True

    def run(self, max_steps: int = 0) -> int:
        """Run all events (or up to *max_steps*).  Returns count executed."""
        count = 0
        while self._queue:
            if max_steps and count >= max_steps:
                break
            ev = heapq.heappop(self._queue)
            self._time = ev.time
            for h in self._handlers.get(ev.kind, []):
                h(ev.node_id, ev.kind, ev.payload, self._time)
            count += 1
        return count

    def peek_time(self) -> float | None:
        """Time of the next pending event, or None."""
        return self._queue[0].time if self._queue else None

    def clear(self):
        self._queue.clear()
        self._handlers.clear()
        self._time = 0.0

    @property
    def pending_count(self) -> int:
        return len(self._queue)
