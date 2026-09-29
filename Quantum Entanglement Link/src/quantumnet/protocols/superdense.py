import numpy as np
from ..core import QubitState, I, X, Z, apply, measure_bell


ENCODE_MAP = {
    0: I,     # 00
    1: X,     # 01
    2: Z,     # 10
    3: X @ Z, # 11
}
DECODE_MAP = {0: 0, 1: 1, 2: 2, 3: 3}


def run_superdense(bits: int | None = None, rng: np.random.Generator | None = None) -> dict:
    if rng is None:
        rng = np.random.default_rng()
    if bits is None:
        bits = int(rng.integers(0, 4))
    bell = QubitState.bell_phi_plus()
    gate = ENCODE_MAP[bits]
    encoded = apply(gate, bell, targets=[0])
    outcome, _ = measure_bell(encoded, rng=rng)
    decoded = DECODE_MAP.get(outcome, outcome)
    return {
        "encoded_bits": format(bits, "02b"),
        "decoded_bits": format(decoded, "02b"),
        "bell_outcome": int(outcome),
        "success": bool(decoded == bits),
    }
