import numpy as np
from quantumnet.protocols import run_superdense


def test_superdense_all_bits():
    for bits in range(4):
        r = run_superdense(bits, rng=np.random.default_rng(42))
        assert r["success"], f"Failed for bits={bits}"


def test_superdense_roundtrip():
    for bits in range(4):
        r = run_superdense(bits, rng=np.random.default_rng(42))
        assert r["encoded_bits"] == r["decoded_bits"]
