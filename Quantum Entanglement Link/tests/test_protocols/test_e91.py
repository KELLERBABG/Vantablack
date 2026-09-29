import numpy as np
from quantumnet.protocols import run_e91


def test_e91_no_noise():
    r = run_e91(500, noise=0.0, rng=np.random.default_rng(42))
    assert len(r["key"]) > 0
    assert r["qber"] >= 0.0


def test_e91_qber_increases_with_noise():
    r1 = run_e91(1000, noise=0.0, rng=np.random.default_rng(42))
    r2 = run_e91(1000, noise=0.2, rng=np.random.default_rng(42))
    assert r2["qber"] >= r1["qber"]


def test_e91_key_string():
    r = run_e91(200, noise=0.0, rng=np.random.default_rng(42))
    assert all(c in "01" for c in r["key"])
