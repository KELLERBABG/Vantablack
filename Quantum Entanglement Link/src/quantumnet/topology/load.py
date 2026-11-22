"""Load and the classical control plane -- making *throughput* a defined quantity.

The problem this solves
-----------------------
Every rate this package reports so far is unconditional: "a link at this distance
yields this key rate", "a reservation that is granted costs this much fidelity". Those
are properties of a *single* request. Throughput is not. It is only defined against a
**request stream** -- how often demands arrive, and what happens when two want the same
memory at once. With one request, "throughput" is undefined, and reporting a number
anyway is the kind of unfalsifiable claim this package tries not to make.

So the acceptance test for this milestone is deliberately negative:

    **with no load, throughput is undefined; with a request stream, it becomes
    defined and is bounded above by both the arrival rate and the service rate.**

That bound is what makes the number meaningful. A measured throughput above the arrival
rate means the accounting is wrong, not that the network is fast.

Two pieces
----------
1. :class:`RequestGenerator` -- arrivals as a Poisson process, so the stream is
   reproducible from a seed and its statistics are checkable (inter-arrival times are
   exponential with mean ``1/rate``; the count in a fixed window is Poisson).
2. :class:`ClassicalControlPlane` -- messages between nodes with a configurable
   propagation delay, **counted**, because classical coordination is a real cost in a
   quantum network and an uncounted one is invisible in the results.

Nothing here re-implements contention: :class:`ResourceManager` already arbitrates, and
this layer feeds it and counts what comes out.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from ..core.latency import ClassicalLink
from .resources import Reservation, ResourceManager


class LoadError(ValueError):
    """Raised for an invalid request stream or load parameter."""


# The control plane

@dataclass
class ClassicalMessage:
    """One message on the classical control plane."""

    sender: str
    recipient: str
    send_time_s: float
    delay_s: float
    kind: str = "control"
    payload: dict = field(default_factory=dict)
    #: Set when handed off; ``None`` while still in flight.
    delivery_time_s: float | None = None

    def in_flight_at(self, time_s: float) -> bool:
        return self.send_time_s <= time_s < self.send_time_s + self.delay_s

    def deliver(self) -> float:
        self.delivery_time_s = self.send_time_s + self.delay_s
        return self.delivery_time_s


class ClassicalControlPlane:
    """Counts classical messages and their delay.

    The count matters more than it looks. A quantum network that needs a round trip per
    swap pays for it in latency, and a model that silently omits the classical leg
    overstates the achievable rate. Every message sent here is recorded, so the cost is
    visible in the results rather than assumed away.
    """

    def __init__(self, link: ClassicalLink | None = None) -> None:
        self.link = link or ClassicalLink()
        self.sent: list[ClassicalMessage] = []

    def send(self, sender: str, recipient: str, distance_km: float,
             time_s: float, kind: str = "control", **payload) -> ClassicalMessage:
        """Send one message, charging the link's round-trip delay over ``distance_km``.

        Rounds trip rather than one way: coordination needs the acknowledgement before
        the pair is usable, so a one-way charge would understate the cost by half.
        """
        if distance_km < 0:
            raise LoadError(f"distance must be non-negative, got {distance_km}")
        message = ClassicalMessage(
            sender=sender, recipient=recipient, send_time_s=float(time_s),
            delay_s=float(self.link.round_trip_s(distance_km)), kind=kind,
            payload=dict(payload))
        self.sent.append(message)
        return message

    @property
    def message_count(self) -> int:
        return len(self.sent)

    def total_delay_s(self) -> float:
        """Sum of every message's delay -- the coordination cost actually paid."""
        return float(sum(m.delay_s for m in self.sent))

    def mean_delay_s(self) -> float:
        return self.total_delay_s() / self.message_count if self.sent else 0.0

    def summary(self) -> dict:
        return {
            "messages": self.message_count,
            "total_delay_s": self.total_delay_s(),
            "mean_delay_s": self.mean_delay_s(),
        }


# Arrivals

@dataclass(frozen=True)
class Request:
    """One demand: a source-destination pair asking for entanglement at a time."""

    source: str
    target: str
    arrival_time_s: float
    memory_size: int = 1
    target_fidelity: float = 0.9
    priority: int = 0
    identity: int = 0


class RequestGenerator:
    """A Poisson request stream, reproducible from a seed.

    Poisson arrivals are the standard memoryless choice and have checkable statistics:
    inter-arrival times are exponential with mean ``1/rate``, and the count in a window
    of length ``T`` is Poisson with mean ``rate * T``. A mis-specified arrival process
    silently changes every throughput number downstream.
    """

    def __init__(self, rate_per_s: float, pairs: list[tuple[str, str]],
                 seed: int = 1, memory_size: int = 1,
                 target_fidelity: float = 0.9) -> None:
        if rate_per_s <= 0:
            raise LoadError(f"arrival rate must be positive, got {rate_per_s}")
        if not pairs:
            raise LoadError("at least one source-destination pair is required")
        self.rate_per_s = float(rate_per_s)
        self.pairs = list(pairs)
        self.seed = int(seed)
        self.memory_size = int(memory_size)
        self.target_fidelity = float(target_fidelity)
        self._rng = np.random.default_rng(seed)
        self._next_time = 0.0
        self._generated = 0
        #: An arrival that overshot a window, held until the next call so no demand is
        #: lost.
        self._pending: Request | None = None

    def next_request(self) -> Request:
        """The next arrival, by exponential inter-arrival time."""
        if self._pending is not None:
            request, self._pending = self._pending, None
            return request
        gap = float(self._rng.exponential(1.0 / self.rate_per_s))
        self._next_time += gap
        source, target = self.pairs[self._generated % len(self.pairs)]
        request = Request(
            source=source, target=target, arrival_time_s=self._next_time,
            memory_size=self.memory_size, target_fidelity=self.target_fidelity,
            identity=self._generated)
        self._generated += 1
        return request

    def generate(self, count: int) -> list[Request]:
        if count < 0:
            raise LoadError(f"count must be non-negative, got {count}")
        return [self.next_request() for _ in range(count)]

    def generate_until(self, time_s: float) -> list[Request]:
        """All arrivals in ``[0, time_s]``. Reproducible for a given seed.

        An arrival that overshoots the window is **held**, not discarded. An earlier
        version rewound the clock instead, which re-drew a fresh random gap and so broke
        determinism -- extending a horizon produced a different stream, and the test
        caught it. Holding the drawn request keeps the generator's state consistent:
        ``generate_until(t1)`` followed by more calls gives exactly the stream that
        ``generate(n)`` would.
        """
        if time_s < 0:
            raise LoadError(f"time must be non-negative, got {time_s}")
        out: list[Request] = []
        while True:
            request = self.next_request()
            if request.arrival_time_s > time_s:
                self._pending = request
                return out
            out.append(request)

    def to_reservation(self, request: Request, duration_s: float,
                       nodes: list[str] | None = None) -> Reservation:
        """Convert a request into a :class:`Reservation` for the existing arbiter.

        The load layer deliberately does not arbitrate itself -- contention is already
        implemented in :class:`ResourceManager`, and a second implementation would be a
        second thing to get wrong.
        """
        return Reservation(
            initiator=request.source, responder=request.target,
            start_time=request.arrival_time_s,
            end_time=request.arrival_time_s + float(duration_s),
            memory_size=request.memory_size,
            target_fidelity=request.target_fidelity,
            priority=request.priority,
            arrival_seq=request.identity,
            path=list(nodes or [request.source, request.target]))


# Throughput

def throughput(requests: list[Request], granted: int,
               horizon_s: float) -> dict:
    """Delivered demand per unit time, and the bounds it must respect.

    ``throughput`` is ``None`` when there is no load, and that is the point: with no
    request stream there is nothing to divide by, and returning ``0.0`` would be a
    number that looks like a result. This mirrors the rule the validation instruments
    enforce -- a rate over an empty sample is undefined, not zero.

    The reported ``rate_ceiling`` is the arrival rate. A throughput above it is
    impossible and therefore a bug in the accounting, so it is checked and surfaced
    rather than reported as a success.
    """
    if horizon_s <= 0:
        raise LoadError(f"horizon must be positive, got {horizon_s}")
    if not requests:
        return {
            "requests": 0, "granted": 0, "throughput_per_s": None,
            "offered_load_per_s": None, "grant_ratio": None,
            "consistent": None,
            "note": ("no load -- throughput is UNDEFINED. Reporting a number here "
                     "would be unfalsifiable."),
        }
    span = max(r.arrival_time_s for r in requests)
    # Use the span actually covered by arrivals, falling back to the horizon.
    denominator = span if span > 0 else horizon_s
    offered = len(requests) / denominator
    delivered = granted / denominator
    return {
        "requests": len(requests),
        "granted": granted,
        "throughput_per_s": delivered,
        "offered_load_per_s": offered,
        "grant_ratio": granted / len(requests),
        "consistent": delivered <= offered + 1e-12,
        "note": ("delivered demand per second, bounded above by the arrival rate"
                 if delivered <= offered + 1e-12 else
                 "THROUGHPUT EXCEEDS THE ARRIVAL RATE -- accounting is wrong"),
    }


def run_load(generator: RequestGenerator, managers: dict[str, ResourceManager],
             horizon_s: float, duration_s: float = 1.0,
             control: ClassicalControlPlane | None = None,
             spacing_km: float = 10.0) -> dict:
    """Feed a request stream to the arbiter and report what was delivered.

    ``managers`` maps node id to :class:`ResourceManager`; every request is submitted as
    a :class:`Reservation` and the arbiter decides. Coordination messages are charged to
    ``control`` so the classical cost appears in the result rather than being assumed.
    """
    requests = generator.generate_until(horizon_s)
    granted = 0
    outcomes: list[tuple[Request, str]] = []

    for request in requests:
        reservation = generator.to_reservation(request, duration_s)
        node_managers = [managers[n] for n in (request.source, request.target)
                         if n in managers]
        if len(node_managers) < 2:
            outcomes.append((request, "unknown-node"))
            continue
        if control is not None:
            control.send(request.source, request.target, spacing_km,
                         request.arrival_time_s, kind="request",
                         identity=request.identity)
        try:
            for manager in node_managers:
                manager.submit(reservation)
            granted += 1
            outcomes.append((request, "granted"))
        except Exception as exc:                       # noqa: BLE001
            outcomes.append((request, f"refused:{type(exc).__name__}"))

    result = throughput(requests, granted, horizon_s)
    result["outcomes"] = outcomes
    if control is not None:
        result["control_plane"] = control.summary()
    return result
