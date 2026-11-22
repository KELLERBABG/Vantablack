"""Resource management: reservations, contention, and the rules that arbitrate.

Why this exists
---------------
A memory array with states is necessary but not sufficient.  The question that
makes a network a network is *who gets the memory when two demands want it*,
and that question has no answer without an allocator and a policy.  This module
is that answer, and it is the largest conceptual gap between a link simulator
and a network one.

The shape, following SeQUeNCe's design
--------------------------------------
``Reservation``
    A request: initiator, responder, a start and end time, how many memory
    pairs, and a target fidelity.  It has a lifecycle and ends in exactly one
    of: rejected, expired, fulfilled, released.
``ResourceManager``
    Owns a node's memory array.  Accepts or refuses reservations, allocates
    memories, releases them on expiry or completion, and refuses to
    double-allocate.
``resolve_contention``
    The arbitration policy when the array cannot satisfy every pending
    reservation.  Higher priority first; FIFO within a priority band.  The
    tie-break is explicit because an implicit one (dict order, allocation order)
    makes results irreproducible -- the same failure the event kernel had.
``NodeEntanglementManager``
    Two nodes negotiating: a request is only granted if **both** ends can supply
    memories, which is what produces genuine contention rather than two
    independent per-node decisions.

The acceptance test this is built for
-------------------------------------
Two competing requests contend and exactly one is refused.  That is a
*different* question from "does
allocation work" -- a manager that grants both requests has no contention at
all, and would make every multi-user network result wrong in the optimistic
direction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from ..core.memory import Memory, MemoryArray


class ReservationState(str, Enum):
    """Lifecycle of a reservation."""

    PENDING = "pending"
    ACTIVE = "active"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FULFILLED = "fulfilled"
    RELEASED = "released"


class ResourceError(RuntimeError):
    """Raised on an illegal resource operation."""


@dataclass
class Reservation:
    """A request for entangled memory pairs between two nodes.

    ``priority`` is an integer where **higher wins**; ties are broken by
    ``arrival_seq``, the order in which requests reached the manager.  Without
    that second key the arbitration would depend on iteration order and two
    runs of the same scenario could disagree.
    """

    initiator: str
    responder: str
    start_time: float
    end_time: float
    memory_size: int
    target_fidelity: float
    priority: int = 0
    entitlement: int = 1
    identity: int = 0
    arrival_seq: int = 0
    state: ReservationState = ReservationState.PENDING
    #: The path this reservation was routed over, once decided.
    path: list[str] = field(default_factory=list)
    #: Memories granted per node, keyed by node id.
    allocated: dict[str, list[Memory]] = field(default_factory=dict)
    reason: str = ""

    def __post_init__(self):
        if self.memory_size < 0:
            raise ResourceError("memory_size must be non-negative")
        if self.end_time < self.start_time:
            raise ResourceError(
                f"reservation ends ({self.end_time}) before it starts "
                f"({self.start_time})"
            )
        if not 0.0 <= self.target_fidelity <= 1.0:
            raise ResourceError("target_fidelity must be in [0, 1]")

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def nodes(self) -> tuple[str, str]:
        return (self.initiator, self.responder)

    def describe(self) -> str:
        return (f"{self.initiator}->{self.responder} "
                f"[{self.start_time:g},{self.end_time:g}) "
                f"{self.memory_size} pairs, F>={self.target_fidelity:.3f}, "
                f"prio={self.priority}, {self.state.value}"
                + (f" ({self.reason})" if self.reason else ""))


class ResourceManager:
    """Owns one node's memories and decides who gets them.

    The manager is the only thing permitted to change allocation state, so the
    accounting invariant -- a memory is never in two reservations at once --
    is enforced in one place.
    """

    def __init__(self, node_id: str, size: int,
                 t1_s: float = 100.0, t2_s: float = 50.0,
                 cutoff_fidelity: float = 0.5):
        self.node_id = node_id
        self.memory_array = MemoryArray(
            node_id=node_id, size=size, t1_s=t1_s, t2_s=t2_s,
            cutoff_fidelity=cutoff_fidelity)
        self._ids = _sequence_counter()
        self.active: dict[int, Reservation] = {}
        self.history: list[Reservation] = []

    def next_identity(self) -> int:
        """Allocate a unique reservation identity from this node."""
        return self._ids()

    # -- negotiation -------------------------------------------------------

    def can_supply(self, count: int, at: float) -> bool:
        """Can this node provide ``count`` memories usable at time ``at``?

        A memory whose held pair has decayed below the cutoff is not a usable
        resource, so it is freed first rather than counted -- counting it would
        overstate capacity, which is exactly the optimistic error this module
        exists to prevent.  Once freed the *slot* becomes available for a fresh
        entanglement attempt, which is why it then counts: availability is about
        slots, and a stale pair is not a claim on one.
        """
        self.memory_array.release_expired(at)
        return self.memory_array.available_count() >= count

    def grant(self, reservation: Reservation) -> list[Memory]:
        """Allocate memories for an accepted reservation.

        Raises if the node cannot supply them, so a caller cannot end up with a
        reservation marked active but holding nothing.  A zero-memory
        reservation is granted trivially -- it holds nothing and blocks nothing.
        """
        if reservation.memory_size == 0:
            reservation.allocated[self.node_id] = []
            return []
        memories = self.memory_array.reserve(
            reservation.memory_size,
            reservation_id=reservation.identity,
            until=reservation.end_time,
        )
        if not memories:
            raise ResourceError(
                f"{self.node_id} cannot supply {reservation.memory_size} "
                f"memories for reservation {reservation.identity}"
            )
        reservation.allocated[self.node_id] = memories
        return memories

    def release_reservation(self, reservation: Reservation,
                            state: ReservationState = ReservationState.RELEASED
                            ) -> int:
        """Return the memories **this node** holds for ``reservation``.

        Only this node's own entry is released.  ``reservation.allocated`` is
        shared across the nodes party to the request, so clearing all of it here
        would double-count: every manager would release both ends' memories and
        report twice the freed count.
        """
        freed = 0
        own = reservation.allocated.pop(self.node_id, [])
        freed += self.memory_array.release(own)
        if reservation.state in (ReservationState.ACTIVE,
                                 ReservationState.PENDING):
            reservation.state = state
        self.active.pop(reservation.identity, None)
        if reservation not in self.history:
            self.history.append(reservation)
        return freed

    def sweep(self, at: float) -> list[Reservation]:
        """Expire reservations and memories whose time has passed.

        Two distinct expiries, both needed:

        * A reservation past its ``end_time`` is over; holding its memories
          would starve later requests.
        * A reservation still inside its window whose *pairs* have decayed
          cannot be met, so it is expired early rather than left to fail at
          delivery time.  This is the early-expiry release path.

        The decay check runs **before** releasing decayed memories, because the
        early-expiry decision has to see the pair that decayed.  Clearing first
        would erase the evidence and leave the reservation holding a slot with
        nothing in it.
        """
        expired: list[Reservation] = []

        for reservation in list(self.active.values()):
            if at >= reservation.end_time:
                reservation.reason = "end time reached"
                self.release_reservation(reservation,
                                         ReservationState.EXPIRED)
                expired.append(reservation)
                continue
            for memories in reservation.allocated.values():
                if any(m.is_expired(at) for m in memories
                       if m.entanglement is not None):
                    reservation.reason = "held pair decayed below cutoff"
                    self.release_reservation(reservation,
                                             ReservationState.EXPIRED)
                    expired.append(reservation)
                    break

        # Anything else that decayed and is not covered by a reservation is freed here,
        # so capacity is never overstated by an unusable pair.
        self.memory_array.release_expired(at)
        return expired

    def summary(self) -> dict:
        return {
            "node_id": self.node_id,
            "active_reservations": len(self.active),
            "history": len(self.history),
            **self.memory_array.summary(),
        }


def _sequence_counter():
    """A monotonic integer counter, used for deterministic arrival order.

    A closure rather than an ``itertools.count`` so the counter cannot be
    iterated or reset from outside, which would let a caller reorder
    arbitration by accident.
    """
    counter = {"n": 0}

    def _next() -> int:
        counter["n"] += 1
        return counter["n"]

    return _next


# Arbitration

def resolve_contention(candidates: Iterable[Reservation]) -> list[Reservation]:
    """Order competing reservations by the arbitration policy.

    **Higher priority first; FIFO within a priority band.**  The tie-break is
    explicit rather than incidental: relying on input order makes arbitration
    depend on how the caller happened to build the list, and the same scenario
    then produces different allocations on different runs.
    """
    return sorted(candidates, key=lambda r: (-r.priority, r.arrival_seq))


class NodeEntanglementManager:
    """Coordinates reservations across nodes, where contention actually bites.

    A request needs memories at *both* ends.  Deciding per node independently
    would grant two requests that each fit on one node but together overcommit
    the other -- which is the whole reason a distributed manager is needed
    rather than two local ones.
    """

    def __init__(self, managers: dict[str, ResourceManager]):
        self.managers = managers
        self._arrival = _sequence_counter()
        self.granted: list[Reservation] = []
        self.refused: list[Reservation] = []

    def request(self, reservation: Reservation) -> bool:
        """Try to satisfy one reservation.  Returns True if granted.

        Refusal reasons are recorded, because "why was I refused" is the
        question a network operator actually asks and a bare False does not
        answer it.
        """
        if reservation.arrival_seq == 0:
            reservation.arrival_seq = self._arrival()
        if reservation.identity == 0:
            reservation.identity = self._arrival()

        missing = [n for n in reservation.nodes if n not in self.managers]
        if missing:
            reservation.state = ReservationState.REJECTED
            reservation.reason = f"no resource manager for {sorted(missing)}"
            self.refused.append(reservation)
            return False

        for node_id in reservation.nodes:
            manager = self.managers[node_id]
            if not manager.can_supply(reservation.memory_size,
                                      reservation.start_time):
                reservation.state = ReservationState.REJECTED
                reservation.reason = (
                    f"{node_id} has "
                    f"{manager.memory_array.available_count()} of "
                    f"{reservation.memory_size} memories available"
                )
                self.refused.append(reservation)
                return False

        # Both ends can supply: commit.  Grant both or neither.
        granted: dict[str, list[Memory]] = {}
        try:
            for node_id in reservation.nodes:
                granted[node_id] = self.managers[node_id].grant(reservation)
        except ResourceError as exc:
            # Roll back, so no node is left holding memories for a dead request.
            for node_id, memories in granted.items():
                self.managers[node_id].memory_array.release(memories)
            reservation.allocated.clear()
            reservation.state = ReservationState.REJECTED
            reservation.reason = f"commit failed: {exc}"
            self.refused.append(reservation)
            return False

        reservation.state = ReservationState.ACTIVE
        reservation.reason = ""
        for node_id in reservation.nodes:
            self.managers[node_id].active[reservation.identity] = reservation
        self.granted.append(reservation)
        return True

    def request_many(self, reservations: Iterable[Reservation]
                     ) -> list[Reservation]:
        """Process a batch of competing reservations, arbitrating between them.

        Ordering is by :func:`resolve_contention`, so a batch containing more
        demand than capacity yields a deterministic winner -- the scenario the
        M3 acceptance test describes.
        """
        results = []
        for reservation in resolve_contention(reservations):
            self.request(reservation)
            results.append(reservation)
        return results

    def sweep(self, at: float) -> list[Reservation]:
        """Advance every manager's clock to ``at``, expiring what has lapsed."""
        expired: list[Reservation] = []
        for manager in self.managers.values():
            expired.extend(manager.sweep(at))
        return expired

    def summary(self) -> dict:
        return {
            "nodes": {nid: m.summary() for nid, m in self.managers.items()},
            "granted": len(self.granted),
            "refused": len(self.refused),
        }
