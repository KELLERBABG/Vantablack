"""Quantum network topology: nodes, optical links, and physical fidelity models.

Everything is derived from the physical-layer models in ``core.physical``
(fibre attenuation, dark counts, detector efficiency, pulse rates) — no
hand-tuned "plausible" numbers.

Link fidelity model
-------------------
A photonic Bell-pair generation attempt over a link of length ``L`` succeeds
with probability proportional to the end-to-end transmissivity; loss and dark
counts are modelled as a two-qubit depolarising channel with parameter
``p`` (from :func:`depolarizing_from_distance`). A Bell pair that survives the
channel has fidelity

    F = 1 - 3p/4    (Werner state)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

from ..core.physical import (
    depolarizing_from_distance,
    entanglement_generation_rate,
    fiber_transmissivity,
)

# Default physical hardware assumptions (documented, tunable per link)
DEFAULT_ALPHA_DB_KM = 0.2        # 1550 nm fibre
DEFAULT_DARK_COUNT_HZ = 100.0    # dark-count rate per detector
DEFAULT_PULSE_RATE_HZ = 1e8      # laser pulse repetition rate
DEFAULT_DETECTOR_EFF = 0.8       # detector quantum efficiency
DEFAULT_T1_S = 100.0             # qubit memory T1 (seconds)
DEFAULT_T2_S = 50.0              # qubit memory T2 (seconds)


def bell_fidelity_from_depolarizing(p: float) -> float:
    """Fidelity of a Bell pair after a two-qubit depolarising channel."""
    p = float(np.clip(p, 0.0, 1.0))
    return 1.0 - 3.0 * p / 4.0


@dataclass
class QuantumNode:
    """A quantum network node (ground station or repeater)."""

    node_id: str
    x_km: float = 0.0
    y_km: float = 0.0
    t1_s: float = DEFAULT_T1_S
    t2_s: float = DEFAULT_T2_S
    is_repeater: bool = False

    def distance_to(self, other: "QuantumNode") -> float:
        return float(np.hypot(self.x_km - other.x_km, self.y_km - other.y_km))


@dataclass
class QuantumLink:
    """An optical link between two nodes with physical hardware parameters."""

    a: str
    b: str
    length_km: float
    alpha_db_km: float = DEFAULT_ALPHA_DB_KM
    dark_count_hz: float = DEFAULT_DARK_COUNT_HZ
    pulse_rate_hz: float = DEFAULT_PULSE_RATE_HZ
    detector_eff: float = DEFAULT_DETECTOR_EFF

    def transmissivity(self) -> float:
        return fiber_transmissivity(self.length_km, self.alpha_db_km)

    def depolarizing_probability(self) -> float:
        return depolarizing_from_distance(
            self.length_km,
            alpha_db_km=self.alpha_db_km,
            dark_count_rate_hz=self.dark_count_hz,
            pulse_rate_hz=self.pulse_rate_hz,
            detector_efficiency=self.detector_eff,
        )

    def fidelity(self) -> float:
        """Expected fidelity of a generated Bell pair on this link."""
        return bell_fidelity_from_depolarizing(self.depolarizing_probability())

    def generation_rate(self) -> float:
        """Mean successful entanglement attempts per second on this link."""
        return entanglement_generation_rate(
            self.pulse_rate_hz,
            self.length_km,
            alpha_db_km=self.alpha_db_km,
            detector_efficiency=self.detector_eff,
        )


@dataclass
class QuantumTopology:
    """A graph of quantum nodes connected by optical links."""

    nodes: dict[str, QuantumNode] = field(default_factory=dict)
    links: dict[tuple[str, str], QuantumLink] = field(default_factory=dict)

    # -- construction ------------------------------------------------------

    def add_node(self, node: QuantumNode) -> "QuantumTopology":
        self.nodes[node.node_id] = node
        return self

    def add_link(self, link: QuantumLink) -> "QuantumTopology":
        key = self._key(link.a, link.b)
        if link.length_km <= 0:
            raise ValueError(f"link {link.a}-{link.b} must have positive length")
        self.links[key] = link
        return self

    def connect(self, a: str, b: str, length_km: float | None = None,
                **kw) -> "QuantumTopology":
        """Add a link between two existing nodes (auto distance if omitted)."""
        if a not in self.nodes or b not in self.nodes:
            raise KeyError(f"unknown node: {a if a not in self.nodes else b}")
        if length_km is None:
            length_km = self.nodes[a].distance_to(self.nodes[b])
        return self.add_link(QuantumLink(a=a, b=b, length_km=length_km, **kw))

    # -- queries -----------------------------------------------------------

    @staticmethod
    def _key(a: str, b: str) -> tuple[str, str]:
        return (a, b) if a <= b else (b, a)

    def neighbors(self, node_id: str) -> list[str]:
        out = []
        for (a, b) in self.links:
            if a == node_id:
                out.append(b)
            elif b == node_id:
                out.append(a)
        return out

    def link(self, a: str, b: str) -> QuantumLink | None:
        return self.links.get(self._key(a, b))

    def link_fidelity(self, a: str, b: str) -> float:
        l = self.link(a, b)
        if l is None:
            raise KeyError(f"no link between {a} and {b}")
        return l.fidelity()

    # -- topology builders -------------------------------------------------

    @staticmethod
    def ring(nodes: Iterable[str],
             radius_km: float = 20.0,
             t1_s: float = DEFAULT_T1_S,
             t2_s: float = DEFAULT_T2_S,
             **link_kw) -> "QuantumTopology":
        """A ring of nodes on a circle (satellite/basin geometry).

        Deterministic: node ``i`` sits at angle ``2πi/N`` on a circle of the
        given radius. Adjacent nodes are connected with the chord distance.
        """
        node_ids = list(nodes)
        n = len(node_ids)
        topo = QuantumTopology()
        for i, nid in enumerate(node_ids):
            theta = 2.0 * np.pi * i / n
            topo.add_node(QuantumNode(
                node_id=nid,
                x_km=radius_km * np.cos(theta),
                y_km=radius_km * np.sin(theta),
                t1_s=t1_s,
                t2_s=t2_s,
                is_repeater=(nid.startswith("R")),
            ))
        for i in range(n):
            topo.connect(node_ids[i], node_ids[(i + 1) % n], **link_kw)
        return topo

    @staticmethod
    def grid(rows: int, cols: int, spacing_km: float = 5.0,
             t1_s: float = DEFAULT_T1_S,
             t2_s: float = DEFAULT_T2_S,
             **link_kw) -> "QuantumTopology":
        """A rectangular grid of ``rows x cols`` nodes connected to neighbours."""
        topo = QuantumTopology()
        nid = lambda r, c: f"{chr(ord('A') + r)}{c}"
        for r in range(rows):
            for c in range(cols):
                topo.add_node(QuantumNode(
                    node_id=nid(r, c),
                    x_km=c * spacing_km,
                    y_km=r * spacing_km,
                    t1_s=t1_s,
                    t2_s=t2_s,
                ))
        for r in range(rows):
            for c in range(cols):
                if c + 1 < cols:
                    topo.connect(nid(r, c), nid(r, c + 1), **link_kw)
                if r + 1 < rows:
                    topo.connect(nid(r, c), nid(r + 1, c), **link_kw)
        return topo

    def summary(self) -> str:
        lines = [f"QuantumTopology: {len(self.nodes)} nodes, {len(self.links)} links"]
        worst = min((l.fidelity() for l in self.links.values()), default=1.0)
        best = max((l.fidelity() for l in self.links.values()), default=1.0)
        lines.append(f"  link fidelity range: {worst:.3f} - {best:.3f}")
        return "\n".join(lines)
