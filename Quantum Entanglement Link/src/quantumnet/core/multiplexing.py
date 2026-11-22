"""Explicit time-division multiplexing: time slots, and who holds them.

The gap this fills
------------------
`core/photonics.py` models multiplexing **statistically**: ``M`` parallel modes give a
success probability ``1 - (1-p)^M``. That is correct for the *rate* and says nothing about
*when* anything happens, so it cannot express the constraint that actually bites in a
network: **two demands cannot occupy the same slot on the same link.** Its own docstring
names the omission -- "a tighter treatment would track each detector's recovery, which
belongs with the scheduling layer rather than here."

This is that treatment. A link is divided into discrete slots of one pulse period; a
demand reserves specific slots; and a second demand wanting the same slot on the same link
is refused *for that slot* rather than being refused outright. The difference matters for
throughput: the statistical model has to answer yes-or-no for a whole request, while slot
allocation can grant part of one.

What is modelled, and what is not
---------------------------------
* **Modelled:** per-link slot occupancy, exclusivity, slot release, and contention for a
  named slot. The failure mode this prevents is reporting two overlapping demands as both
  delivered on one link.
* **Not modelled:** detector recovery as a *per-detector* state machine. Dead time enters
  as a minimum slot spacing, which is the part that affects scheduling. A full recovery
  trace would need the detector's internal recovery curve, which this package does not
  have.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class SlotError(ValueError):
    """Raised for an invalid slot request."""


@dataclass(frozen=True)
class Slot:
    """One time slot on one link.

    ``index`` is the pulse number from the start of the simulation, so a slot is
    identified by ``(link, index)`` and nothing else. Keeping the link inside the slot
    rather than alongside it makes a cross-link mix-up impossible rather than merely
    unlikely.
    """

    link: str
    index: int

    def __post_init__(self) -> None:
        if self.index < 0:
            raise SlotError(f"slot index must be non-negative, got {self.index}")


@dataclass
class SlotAllocation:
    """A granted reservation of consecutive slots on one link."""

    link: str
    start_index: int
    count: int
    holder: str

    def __post_init__(self) -> None:
        if self.count < 1:
            raise SlotError(f"an allocation needs at least one slot, got {self.count}")

    @property
    def slots(self) -> tuple[Slot, ...]:
        return tuple(Slot(self.link, self.start_index + offset)
                     for offset in range(self.count))

    def overlaps(self, other: "SlotAllocation") -> bool:
        if self.link != other.link:
            return False
        return not (self.start_index + self.count <= other.start_index
                    or other.start_index + other.count <= self.start_index)


@dataclass
class SlotAllocator:
    """Tracks slot occupancy per link and grants non-overlapping allocations.

    Deterministic and first-come: a refused request is refused because the slots are
    **taken**, not because of an ordering artefact. The tests check that a refusal is
    accompanied by naming the holder, so "no" is always attributable.
    """

    #: Slots already spoken for, per link.
    occupied: dict[str, set[int]] = field(default_factory=dict)
    #: Who holds each slot, per link, so a refusal can name the conflicting demand.
    holder: dict[str, dict[int, str]] = field(default_factory=dict)

    def is_free(self, slot: Slot) -> bool:
        return slot.index not in self.occupied.get(slot.link, set())

    def blocking_holder(self, link: str, start_index: int, count: int) -> str | None:
        """The holder of the first conflicting slot, or ``None`` if all are free."""
        for index in range(start_index, start_index + count):
            who = self.holder.get(link, {}).get(index)
            if who is not None:
                return who
        return None

    def allocate(self, link: str, start_index: int, count: int,
                 holder: str) -> SlotAllocation | None:
        """Grant ``count`` consecutive slots, or ``None`` if any is taken.

        All-or-nothing deliberately: a correction that consumed half a demand and
        reported it as delivered would overstate throughput in exactly the direction this
        module exists to prevent. Partial service is available through
        :meth:`allocate_next_free`, which says how much it could grant.
        """
        if start_index < 0:
            raise SlotError(f"start index must be non-negative, got {start_index}")
        if count < 1:
            raise SlotError(f"count must be at least one, got {count}")
        if self.blocking_holder(link, start_index, count) is not None:
            return None
        taken = self.occupied.setdefault(link, set())
        owners = self.holder.setdefault(link, {})
        for index in range(start_index, start_index + count):
            taken.add(index)
            owners[index] = holder
        return SlotAllocation(link=link, start_index=start_index, count=count,
                              holder=holder)

    def allocate_next_free(self, link: str, count: int, holder: str,
                           first_index: int = 0) -> SlotAllocation | None:
        """The earliest run of ``count`` free slots at or after ``first_index``.

        This is the part the statistical model cannot do: it places a demand **after**
        whatever is already scheduled instead of refusing it, so two non-overlapping
        demands on one link are both served.
        """
        index = max(0, first_index)
        taken = self.occupied.get(link, set())
        while True:
            if all((index + offset) not in taken for offset in range(count)):
                return self.allocate(link, index, count, holder)
            index += 1

    def release(self, allocation: SlotAllocation) -> None:
        """Free an allocation's slots. Unknown slots are ignored, not an error."""
        taken = self.occupied.get(allocation.link, set())
        owners = self.holder.get(allocation.link, {})
        for index in range(allocation.start_index,
                           allocation.start_index + allocation.count):
            taken.discard(index)
            owners.pop(index, None)

    def occupancy(self, link: str, upto: int | None = None) -> float:
        """Fraction of slots in use, up to ``upto``. 0.0 when ``upto`` is 0.

        Guarded against a zero denominator rather than returning ``nan``: an empty window
        has no occupancy, and a nan would propagate into a throughput figure as a
        plausible-looking number.
        """
        if upto is None:
            upto = max(self.occupied.get(link, {0})) + 1 if self.occupied.get(link) else 0
        if upto <= 0:
            return 0.0
        used = sum(1 for index in self.occupied.get(link, set()) if index < upto)
        return used / upto


@dataclass
class MultiplexedLink:
    """A link offering ``modes`` slots per pulse period, with explicit allocation.

    The point of ``modes`` here is concrete rather than statistical: it is how many
    attempts fit in one pulse period, so it multiplies the slot supply. ``M = 4`` means a
    demand can be placed in four times as many slots per period, not that a probability
    is raised to a power.
    """

    name: str
    modes: int = 1
    pulse_period_s: float = 1e-8
    allocator: SlotAllocator = field(default_factory=SlotAllocator)

    def __post_init__(self) -> None:
        if self.modes < 1:
            raise SlotError(f"modes must be at least one, got {self.modes}")
        if self.pulse_period_s <= 0:
            raise SlotError(
                f"pulse period must be positive, got {self.pulse_period_s}")

    @property
    def slots_per_second(self) -> float:
        return self.modes / self.pulse_period_s

    def slot_time_s(self, index: int) -> float:
        """When a slot begins, in seconds."""
        return index * self.pulse_period_s / self.modes

    def request(self, holder: str, *, start_time_s: float = 0.0,
                count: int = 1) -> SlotAllocation | None:
        """Reserve ``count`` slots, placed after whatever is already scheduled.

        Watermark placement rather than exact-index: a caller asks for ``count`` attempts
        from a start time, not for a specific pulse number, because that is what a
        network layer knows.
        """
        if start_time_s < 0:
            raise SlotError(f"start time must be non-negative, got {start_time_s}")
        first = int(start_time_s / self.pulse_period_s * self.modes)
        return self.allocator.allocate_next_free(self.name, count, holder,
                                                 first_index=first)

    def busy_fraction(self, horizon_s: float) -> float:
        """Occupancy over a window, for comparison with a statistical model."""
        if horizon_s <= 0:
            raise SlotError(f"horizon must be positive, got {horizon_s}")
        total = int(horizon_s / self.pulse_period_s * self.modes)
        return self.allocator.occupancy(self.name, upto=total)


def statistical_gain(success_per_mode: float, modes: int) -> float:
    """``1 - (1-p)^M``: what the photonic layer reports, for cross-checking.

    Kept here so the two models can be compared directly instead of the statistical one
    being taken on faith. They answer different questions -- this is a probability that
    *some* mode succeeded, while slot allocation is about whether a *specific* slot is
    available -- and the tests assert that distinction rather than assuming it.
    """
    if not 0.0 <= success_per_mode <= 1.0:
        raise SlotError(
            f"success probability must be in [0, 1], got {success_per_mode}")
    if modes < 1:
        raise SlotError(f"modes must be at least one, got {modes}")
    return 1.0 - (1.0 - success_per_mode) ** modes
