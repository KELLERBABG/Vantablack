import numpy as np
from quantumnet.protocols import run_swapping


def test_swapping_no_noise():
    r = run_swapping(noise=0.0, rng=np.random.default_rng(42))
    assert r["swapped_fidelity"] > 0.9
    assert r["success"]


def test_swapping_bell_outcome():
    r = run_swapping(noise=0.0, rng=np.random.default_rng(42))
    assert len(r["bell_outcome"]) == 2
    assert all(b in (0, 1) for b in r["bell_outcome"])


def test_swapping_noise_reduces_fidelity():
    r1 = run_swapping(noise=0.0, rng=np.random.default_rng(42))
    r2 = run_swapping(noise=0.3, rng=np.random.default_rng(42))
    assert r2["swapped_fidelity"] <= r1["swapped_fidelity"] + 0.1
