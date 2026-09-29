import numpy as np
import pytest

from quantumnet.topology import (
    QuantumNode, QuantumLink, QuantumTopology,
    bell_fidelity_from_depolarizing,
)


class TestLinkFidelityPhysics:
    def test_longer_link_is_worse(self):
        t = QuantumTopology()
        t.add_node(QuantumNode("A")).add_node(QuantumNode("B", x_km=100))
        t.add_node(QuantumNode("C", x_km=1000))
        t.connect("A", "B")  # 100 km
        t.connect("A", "C")  # 1000 km
        assert t.link_fidelity("A", "B") > t.link_fidelity("A", "C")
        assert t.link_fidelity("A", "C") >= 0.25  # never below fully-mixed
        assert t.link_fidelity("A", "B") <= 1.0

    def test_transmissivity_monotonic(self):
        q = QuantumLink("A", "B", length_km=10)
        q2 = QuantumLink("A", "B", length_km=100)
        assert q.transmissivity() > q2.transmissivity()

    def test_bell_fidelity_werner(self):
        assert bell_fidelity_from_depolarizing(0.0) == pytest.approx(1.0)
        assert bell_fidelity_from_depolarizing(1.0) == pytest.approx(0.25)
        assert bell_fidelity_from_depolarizing(0.5) == pytest.approx(0.625)

    def test_generation_rate_positive(self):
        q = QuantumLink("A", "B", length_km=50)
        assert q.generation_rate() > 0.0

    def test_negative_length_rejected(self):
        t = QuantumTopology()
        t.add_node(QuantumNode("A")).add_node(QuantumNode("B"))
        with pytest.raises(ValueError):
            t.connect("A", "B", length_km=-1)

    def test_ring_is_deterministic(self):
        t1 = QuantumTopology.ring(["A", "R0", "R1", "B"], radius_km=500)
        t2 = QuantumTopology.ring(["A", "R0", "R1", "B"], radius_km=500)
        for k in t1.links:
            assert t1.links[k].length_km == pytest.approx(t2.links[k].length_km)

    def test_grid_neighbors(self):
        t = QuantumTopology.grid(2, 2, spacing_km=100)
        assert sorted(t.neighbors("A0")) == ["A1", "B0"]
