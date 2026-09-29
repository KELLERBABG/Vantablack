import numpy as np
import pytest

from quantumnet.topology import (
    QuantumNode, QuantumTopology,
    all_simple_paths, best_route, e2e_fidelity, optimal_swap_order,
    rank_routes, swapped_fidelity,
)


class TestSwapFidelity:
    def test_perfect_swap_is_perfect(self):
        assert swapped_fidelity(1.0, 1.0) == pytest.approx(1.0)

    def test_mixed_swap_stays_mixed(self):
        assert swapped_fidelity(0.25, 0.25) == pytest.approx(0.25)

    def test_monotone(self):
        assert swapped_fidelity(0.9, 0.9) > swapped_fidelity(0.8, 0.8)

    def test_symmetric(self):
        assert swapped_fidelity(0.7, 0.6) == pytest.approx(swapped_fidelity(0.6, 0.7))


class TestSwapOrdering:
    def test_order_does_not_matter_noise_only(self):
        # With the correct Werner formula the pure swap-noise operation is
        # associative (p' = p1·p2 in Werner parameter), so the fusion order
        # does not change the noise-only result.
        f = [0.9, 0.5, 0.6]
        left = e2e_fidelity(f, [(0, 1), (0, 1)])
        right = e2e_fidelity(f, [(1, 2), (0, 1)])
        assert left == pytest.approx(right)
        # ... and matches the closed form: p_e2e = Π(4Fi-1)/3
        p = 1.0
        for x in f:
            p *= (4.0 * x - 1.0) / 3.0
        assert left == pytest.approx((1.0 + 3.0 * p) / 4.0)

    def test_greedy_matches_bruteforce_small(self):
        rng = np.random.default_rng(7)
        for n in range(2, 7):
            f = list(0.55 + 0.4 * rng.random(n))
            exact = optimal_swap_order(f, brute_force_limit=8)
            # greedy worst-first
            greedy_order = []
            segs = list(f)
            while len(segs) > 1:
                idx = sorted(range(len(segs)), key=lambda i: segs[i])[:2]
                i, j = sorted(idx)
                greedy_order.append((i, j))
                segs[i] = swapped_fidelity(segs[i], segs[j])
                segs.pop(j)
            greedy_f = e2e_fidelity(f, greedy_order)
            assert exact[1] == pytest.approx(greedy_f, abs=1e-12), \
                f"n={n}: brute={exact[1]:.6f} greedy={greedy_f:.6f}"

    def test_single_link(self):
        order, f = optimal_swap_order([0.8])
        assert order == []
        assert f == pytest.approx(0.8)


class TestRouting:
    @pytest.fixture
    def grid(self):
        return QuantumTopology.grid(3, 3, spacing_km=100)

    def test_paths_exist(self, grid):
        paths = all_simple_paths(grid, "A0", "C2", max_hops=6)
        assert paths, "expected at least one path"
        for p in paths:
            assert p[0] == "A0" and p[-1] == "C2"

    def test_best_route_short(self, grid):
        r = best_route(grid, "A0", "A2")
        assert r is not None
        assert r.hops == 2  # straight line beats detours

    def test_ranked_descending(self, grid):
        routes = rank_routes(grid, "A0", "C2", max_hops=6)
        fids = [r.e2e_fidelity for r in routes]
        assert fids == sorted(fids, reverse=True)

    def test_min_fidelity_filters(self, grid):
        routes = rank_routes(grid, "A0", "C2", min_fidelity=0.9999)
        assert all(r.e2e_fidelity >= 0.9999 for r in routes)

    def test_no_route(self):
        t = QuantumTopology()
        t.add_node(QuantumNode("A")).add_node(QuantumNode("B"))
        assert best_route(t, "A", "B") is None

    def test_route_has_valid_swap_order(self, grid):
        r = best_route(grid, "A0", "C2", max_hops=6)
        f = e2e_fidelity(r.link_fidelities, r.swap_order)
        assert f == pytest.approx(r.e2e_fidelity, abs=1e-9)
