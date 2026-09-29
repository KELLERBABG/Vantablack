import numpy as np
import pytest

from quantumnet.topology import (
    QuantumNode, QuantumTopology, best_route, distribute,
    schedule_fidelity_without_decay,
)


class TestDistribution:
    @pytest.fixture
    def chain(self):
        # Linear chain A—R0—R1—B: exactly 3 links, no shortcut
        t = QuantumTopology()
        t.add_node(QuantumNode("A", 0, 0))
        t.add_node(QuantumNode("R0", 10, 0, t1_s=1.0, t2_s=0.5))
        t.add_node(QuantumNode("R1", 20, 0, t1_s=1.0, t2_s=0.5))
        t.add_node(QuantumNode("B", 30, 0))
        t.connect("A", "R0")
        t.connect("R0", "R1")
        t.connect("R1", "B")
        return t

    def test_fuses_all_links(self, chain):
        r = best_route(chain, "A", "B")
        assert r is not None and r.hops == 3
        res = distribute(chain, r)
        assert len(res.events) == 2  # 3 links → 2 swaps

    def test_no_decay_matches_pure_swap(self, chain):
        r = best_route(chain, "A", "B")
        res = distribute(chain, r)
        pure = schedule_fidelity_without_decay(r)
        # with these short memory lifetimes decay must reduce the fidelity
        assert res.final_fidelity < pure

    def test_long_memory_no_decay(self):
        t = QuantumTopology()
        t.add_node(QuantumNode("A", 0, 0, t1_s=1e9, t2_s=1e9))
        t.add_node(QuantumNode("R0", 10, 0, t1_s=1e9, t2_s=1e9))
        t.add_node(QuantumNode("R1", 20, 0, t1_s=1e9, t2_s=1e9))
        t.add_node(QuantumNode("B", 30, 0, t1_s=1e9, t2_s=1e9))
        t.connect("A", "R0")
        t.connect("R0", "R1")
        t.connect("R1", "B")
        r = best_route(t, "A", "B")
        res = distribute(t, r)
        assert res.final_fidelity == pytest.approx(
            schedule_fidelity_without_decay(r), abs=1e-6)

    def test_timeline_positive(self, chain):
        r = best_route(chain, "A", "B")
        res = distribute(chain, r)
        assert res.t_gen_s > 0
        times = [e.time_s for e in res.events]
        assert times == sorted(times)
        # generation waits for the slowest link
        assert res.t_gen_s == pytest.approx(
            max(1.0 / max(rate, 1e-12) for rate in res.link_rates))

    def test_single_link_no_events(self):
        t = QuantumTopology()
        t.add_node(QuantumNode("A")).add_node(QuantumNode("B", x_km=10))
        t.connect("A", "B")
        r = best_route(t, "A", "B")
        res = distribute(t, r)
        assert res.events == []
        assert res.final_fidelity == pytest.approx(r.e2e_fidelity, abs=1e-9)
