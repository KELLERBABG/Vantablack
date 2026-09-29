"""BB84 quantum key distribution (QKD) protocol simulation with intercept-resend eavesdropping."""

import numpy as np
from ..core import QubitState, H, X, Z, apply, measure


BASES = {"Z": 0, "X": 1}
BASE_NAMES = ["Z", "X"]


def _encode(bit: int, basis: int) -> QubitState:
    state = QubitState.zero() if bit == 0 else QubitState.one()
    if basis == 1:
        state = apply(H, state, targets=[0])
    return state


def _measure(state: QubitState, basis: int, rng: np.random.Generator) -> int:
    if basis == 1:
        state = apply(H, state, targets=[0])
    outcomes, _ = measure(state, qubit_indices=[0], rng=rng)
    return outcomes[0]


def run_bb84(num_bits: int = 256, noise: float = 0.0, rng: np.random.Generator | None = None) -> dict:
    if rng is None:
        rng = np.random.default_rng()
    alice_bits = rng.integers(0, 2, size=num_bits)
    alice_bases = rng.integers(0, 2, size=num_bits)
    bob_bases = rng.integers(0, 2, size=num_bits)
    bob_results = np.empty(num_bits, dtype=int)
    for i in range(num_bits):
        state = _encode(int(alice_bits[i]), int(alice_bases[i]))
        if noise > 0:
            from ..core.noise import depolarizing_channel
            chan = depolarizing_channel(noise)
            state = chan.apply(state)
        bob_results[i] = _measure(state, int(bob_bases[i]), rng)
    match = alice_bases == bob_bases
    sifted_key = alice_bits[match]
    sifted_bob = bob_results[match]
    if len(sifted_key) < 2:
        return {"key": "", "qber": 0.0}
    n_est = max(1, len(sifted_key) // 4)
    est_indices = rng.choice(len(sifted_key), size=n_est, replace=False)
    errors = np.sum(sifted_key[est_indices] != sifted_bob[est_indices])
    qber = errors / n_est
    keep = np.ones(len(sifted_key), dtype=bool)
    keep[est_indices] = False
    key = "".join(str(int(b)) for b in sifted_key[keep])
    return {"key": key, "qber": float(qber), "raw_key_length": num_bits, "sifted_length": len(sifted_key)}
