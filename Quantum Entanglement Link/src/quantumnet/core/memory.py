"""Quantum memory: state machines, arrays, and time-aware decay.

What this is for
----------------
Until a memory can be *in use*, a network simulator measures a single-user link.
Contention -- two demands wanting the same memory at the same time -- is what
makes a network a network.  This module supplies the state that contention
is decided over.

Memory states
-------------
Following the shape used by SeQUeNCe, a memory is in exactly one of three
states:

``RAW``
    Not entangled and not reserved.  The only state from which a new
    entanglement can be attempted.
``ENTANGLED``
    Holds one half of a pair with a remote memory.  Available to a protocol,
    but not yet committed.
``OCCUPIED``
    Committed to a protocol instance or a reservation.  Cannot be handed to a
    second caller -- this is the state that makes contention possible.

``ENTANGLED`` and ``OCCUPIED`` are orthogonal in SeQUeNCe's design and
conflated here into a single enum, which is a deliberate simplification: a
memory cannot be both reserved and free, and the reservation is the stronger
claim.  :attr:`Memory.entanglement` survives a transition into ``OCCUPIED``, so
no information is lost -- and the tests assert that.

Decay
-----
Fidelity decays while a memory holds a pair, and the decay is charged against
the *pair* model (:func:`~quantumnet.core.physical.bell_pair_fidelity_after_dt`),
whose floor is 1/4.  Expiry is not a timer that fires on a wall clock; it is a
predicate over the current simulation time, so it composes with the event kernel
without the kernel needing to know about memories.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from enum import Enum

from ..core.physical import bell_pair_fidelity_after_dt


class MemoryState(str, Enum):
    """The three states a memory can be in."""

    RAW = "raw"
    ENTANGLED = "entangled"
    OCCUPIED = "occupied"


class MemoryError(RuntimeError):
    """Raised on an illegal memory operation."""


@dataclass
class Entanglement:
    """The remote half of a pair held by a memory."""

    remote_node: str
    remote_memory: int
    fidelity: float
    created_at: float

    def describe(self) -> str:
        return (f"{self.remote_node}[{self.remote_memory}] "
                f"F={self.fidelity:.4f} at t={self.created_at:g}")


class Memory:
    """A single quantum memory slot.

    A memory is *not* a container that is filled and emptied; it is a slot whose
    state is one of :class:`MemoryState`, plus an optional
    :class:`Entanglement` when it holds half of a pair.  Every transition is
    validated, so an invalid protocol sequence raises rather than silently
    corrupting the resource accounting.
    """

    def __init__(self, index: int, node_id: str = "",
                 t1_s: float = 100.0, t2_s: float = 50.0,
                 cutoff_fidelity: float = 0.5):
        if index < 0:
            raise MemoryError("memory index must be non-negative")
        self.index = int(index)
        self.node_id = node_id
        self.t1_s = float(t1_s)
        self.t2_s = float(t2_s)
        self.cutoff_fidelity = float(cutoff_fidelity)

        self.state = MemoryState.RAW
        self.entanglement: Entanglement | None = None
        #: Simulation time at which the current reservation lapses, if any.
        self.reserved_until: float | None = None
        #: Identifies the reservation holding this memory, for release checks.
        self.reservation_id: int | None = None
        self.busy_count = 0

    # -- state transitions -------------------------------------------------

    @property
    def free(self) -> bool:
        return self.state is MemoryState.RAW

    @property
    def available(self) -> bool:
        """True when a new caller may take this memory.

        ``ENTANGLED`` counts as available: the pair exists but nothing has
        committed to it yet, so a protocol may still claim it.
        """
        return self.state in (MemoryState.RAW, MemoryState.ENTANGLED)

    def entangle(self, remote_node: str, remote_memory: int,
                 fidelity: float, at: float) -> Entanglement:
        """Record a newly generated pair on this memory."""
        if self.state is MemoryState.OCCUPIED:
            raise MemoryError(
                f"memory {self.node_id}[{self.index}] is OCCUPIED and cannot "
                f"be re-entangled"
            )
        if self.state is MemoryState.ENTANGLED:
            raise MemoryError(
                f"memory {self.node_id}[{self.index}] already holds a pair "
                f"with {self.entanglement.describe() if self.entanglement else '?'}"
            )
        self.entanglement = Entanglement(
            remote_node=remote_node,
            remote_memory=int(remote_memory),
            fidelity=float(fidelity),
            created_at=float(at),
        )
        self.state = MemoryState.ENTANGLED
        return self.entanglement

    def occupy(self, reservation_id: int | None = None,
               until: float | None = None) -> None:
        """Commit this memory to a protocol or reservation.

        Legal from ``RAW`` (a reservation against a memory not yet entangled)
        or ``ENTANGLED`` (committing an existing pair).  Any existing
        entanglement is preserved, not discarded.
        """
        if self.state is MemoryState.OCCUPIED:
            raise MemoryError(
                f"memory {self.node_id}[{self.index}] is already OCCUPIED by "
                f"reservation {self.reservation_id}"
            )
        self.state = MemoryState.OCCUPIED
        self.busy_count += 1
        if reservation_id is not None:
            self.reservation_id = int(reservation_id)
        if until is not None:
            self.reserved_until = float(until)

    def release(self) -> None:
        """Give the memory back.

        Returns to ``ENTANGLED`` if it still holds a pair (the pair was not
        consumed) and to ``RAW`` otherwise.
        """
        if self.state is not MemoryState.OCCUPIED:
            raise MemoryError(
                f"memory {self.node_id}[{self.index}] is {self.state.value}, "
                f"not OCCUPIED; nothing to release"
            )
        self.reservation_id = None
        self.reserved_until = None
        self.state = (MemoryState.ENTANGLED if self.entanglement is not None
                      else MemoryState.RAW)

    def clear(self) -> None:
        """Discard the pair and return to ``RAW``.  Always legal."""
        self.entanglement = None
        self.state = MemoryState.RAW
        self.reservation_id = None
        self.reserved_until = None

    def consume(self) -> Entanglement | None:
        """Take the pair out of this memory, freeing the slot for reuse.

        This is what a successful swap does to its two inputs: the pairs are
        destroyed, so the memories return to ``RAW`` rather than staying
        entangled with a pair that no longer exists.
        """
        held = self.entanglement
        self.entanglement = None
        self.state = MemoryState.RAW
        self.reservation_id = None
        self.reserved_until = None
        return held

    # -- time-dependent queries -------------------------------------------

    def current_fidelity(self, at: float) -> float:
        """Fidelity of the held pair at time ``at``, after memory decay.

        Returns 0.0 when no pair is held.  Decay uses the pair model, so the
        result never drops below 1/4 while a pair exists.
        """
        if self.entanglement is None:
            return 0.0
        age = float(at) - self.entanglement.created_at
        if age <= 0.0:
            return self.entanglement.fidelity
        return bell_pair_fidelity_after_dt(
            self.entanglement.fidelity, age, self.t1_s, self.t2_s)

    def is_expired(self, at: float) -> bool:
        """True when the held pair has decayed below the usable threshold."""
        if self.entanglement is None:
            return False
        return self.current_fidelity(at) < self.cutoff_fidelity

    def __repr__(self) -> str:
        held = f", {self.entanglement.describe()}" if self.entanglement else ""
        return (f"Memory({self.node_id}[{self.index}], "
                f"{self.state.value}{held})")


class MemoryArray:
    """A fixed pool of memories at one node.

    Iteration yields the memories in index order, so any policy built on top is
    deterministic.
    """

    def __init__(self, node_id: str, size: int,
                 t1_s: float = 100.0, t2_s: float = 50.0,
                 cutoff_fidelity: float = 0.5):
        if size < 0:
            raise MemoryError("memory array size must be non-negative")
        self.node_id = node_id
        self.memories: list[Memory] = [
            Memory(index=i, node_id=node_id, t1_s=t1_s, t2_s=t2_s,
                   cutoff_fidelity=cutoff_fidelity)
            for i in range(size)
        ]

    def __len__(self) -> int:
        return len(self.memories)

    def __iter__(self):
        return iter(self.memories)

    def __getitem__(self, index: int) -> Memory:
        return self.memories[index]

    # -- queries -----------------------------------------------------------

    def in_state(self, state: MemoryState) -> list[Memory]:
        return [m for m in self.memories if m.state is state]

    def available(self) -> list[Memory]:
        return [m for m in self.memories if m.available]

    def entangled(self) -> list[Memory]:
        return self.in_state(MemoryState.ENTANGLED)

    def occupied(self) -> list[Memory]:
        return self.in_state(MemoryState.OCCUPIED)

    def free_count(self) -> int:
        return sum(1 for m in self.memories if m.free)

    def available_count(self) -> int:
        return sum(1 for m in self.memories if m.available)

    def capacity(self) -> int:
        return len(self.memories)

    # -- allocation --------------------------------------------------------

    def reserve(self, count: int, reservation_id: int | None = None,
                until: float | None = None) -> list[Memory]:
        """Occupy ``count`` available memories, or nothing at all.

        **All-or-nothing deliberately.**  A partial allocation would leave the
        caller holding half an entangled link -- a resource it cannot use and
        will not release promptly.  Failing cleanly means the caller is refused
        and the memories stay available for a request that can be satisfied,
        which is the behaviour contention tests depend on.
        """
        if count < 0:
            raise MemoryError("cannot reserve a negative count")
        chosen = self.available()[:count]
        if len(chosen) < count:
            return []
        for memory in chosen:
            memory.occupy(reservation_id=reservation_id, until=until)
        return chosen

    def release(self, memories: list[Memory]) -> int:
        """Release a specific set of memories.  Returns how many were freed."""
        freed = 0
        for memory in memories:
            if memory.state is MemoryState.OCCUPIED:
                memory.release()
                freed += 1
        return freed

    def expiring(self, at: float) -> list[Memory]:
        """Memories whose held pair has decayed below the usable threshold."""
        return [m for m in self.memories if m.is_expired(at)]

    def release_expired(self, at: float) -> list[Memory]:
        """Clear every memory whose held pair has decayed, freeing the slot.

        This is the *early-expiry release* path.  A pair below the cutoff is not
        a resource: the memory cannot be used for the entanglement it holds, and
        it cannot be handed to a new request either.  Leaving it in that state
        would both overstate capacity and strand the slot, so a decayed pair is
        discarded and the memory returns to ``RAW``.

        A memory that has decayed while ``OCCUPIED`` is released too, so the
        reservation holding it no longer blocks reuse.
        """
        expired = self.expiring(at)
        for memory in expired:
            if memory.state is MemoryState.OCCUPIED:
                memory.release()
            memory.clear()
        return expired

    def summary(self) -> dict:
        return {
            "node_id": self.node_id,
            "capacity": self.capacity(),
            "raw": len(self.in_state(MemoryState.RAW)),
            "entangled": len(self.in_state(MemoryState.ENTANGLED)),
            "occupied": len(self.in_state(MemoryState.OCCUPIED)),
            "available": self.available_count(),
        }
