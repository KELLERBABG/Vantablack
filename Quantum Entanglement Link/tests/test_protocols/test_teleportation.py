import numpy as np
from quantumnet.protocols import run_teleportation


def test_teleportation_no_noise():
    r = run_teleportation(rng=np.random.default_rng(42))
    assert r["teleported_fidelity"] > 0.9
    assert r["success"]


def test_teleportation_reproducible():
    r1 = run_teleportation(rng=np.random.default_rng(42))
    r2 = run_teleportation(rng=np.random.default_rng(42))
    assert r1["bell_outcome"] == r2["bell_outcome"]


def test_teleportation_bell_outcome_range():
    r = run_teleportation(rng=np.random.default_rng(42))
    b0, b1 = r["bell_outcome"]
    assert b0 in (0, 1) and b1 in (0, 1)
