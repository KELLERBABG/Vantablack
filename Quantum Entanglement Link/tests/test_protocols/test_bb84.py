import numpy as np
from quantumnet.protocols import run_bb84


def test_bb84_no_noise():
    r = run_bb84(1000, noise=0.0, rng=np.random.default_rng(42))
    assert len(r["key"]) > 0
    assert r["qber"] >= 0.0


def test_bb84_key_length():
    r = run_bb84(100, noise=0.0, rng=np.random.default_rng(42))
    assert len(r["key"]) <= 100


def test_bb84_qber_increases_with_noise():
    r1 = run_bb84(2000, noise=0.0, rng=np.random.default_rng(42))
    r2 = run_bb84(2000, noise=0.2, rng=np.random.default_rng(42))
    assert r2["qber"] >= r1["qber"]


def test_bb84_key_string():
    r = run_bb84(100, noise=0.0, rng=np.random.default_rng(42))
    assert all(c in "01" for c in r["key"])
