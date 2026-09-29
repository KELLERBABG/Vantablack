"""Ekert (E91) entanglement-based quantum key distribution protocol simulation."""

import numpy as np
from ..core import QubitState, apply, measure
from ..core.gate import Gate


def _bell_pair(noise: float) -> QubitState:
    state = QubitState(np.kron(QubitState.zero().rho, QubitState.zero().rho), dims=[2, 2])
    state = apply(Gate(np.array([[1, 1], [1, -1]], dtype=complex) / np.sqrt(2), "H"), state, targets=[0])
    state = apply(Gate(np.array([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]], dtype=complex), "CNOT"), state, targets=[0, 1])
    if noise > 0:
        from ..core.noise import depolarizing_channel_2
        chan = depolarizing_channel_2(noise)
        state = chan.apply(state)
    return state


def _measure_angle(state: QubitState, qubit: int, angle: float, rng: np.random.Generator) -> int:
    c = np.cos(angle)
    s = np.sin(angle)
    R = Gate(np.array([[c, s], [s, -c]], dtype=complex), "R")
    state = apply(R, state, targets=[qubit])
    outcomes, _ = measure(state, qubit_indices=[qubit], rng=rng)
    return outcomes[qubit]


ALICE_ANGLES = [0.0, np.pi / 4, np.pi / 8]
BOB_ANGLES = [np.pi / 8, np.pi / 4, 0.0]


def run_e91(num_pairs: int = 256, noise: float = 0.0, rng: np.random.Generator | None = None) -> dict:
    if rng is None:
        rng = np.random.default_rng()
    a_choices = rng.integers(0, 3, size=num_pairs)
    b_choices = rng.integers(0, 3, size=num_pairs)
    a_results = np.empty(num_pairs, dtype=int)
    b_results = np.empty(num_pairs, dtype=int)
    for i in range(num_pairs):
        state = _bell_pair(noise)
        a_results[i] = _measure_angle(state, 0, ALICE_ANGLES[int(a_choices[i])], rng)
        b_results[i] = _measure_angle(state, 1, BOB_ANGLES[int(b_choices[i])], rng)
    sifted_alice = []
    sifted_bob = []
    for i in range(num_pairs):
        if a_choices[i] == b_choices[i]:
            sifted_alice.append(int(a_results[i]))
            sifted_bob.append(int(b_results[i]))
    key = "".join(str(b) for b in sifted_alice)
    if len(sifted_alice) > 0:
        errors = sum(a != b for a, b in zip(sifted_alice, sifted_bob))
        qber = errors / len(sifted_alice)
    else:
        qber = 0.0
    e_vals = []
    for ka in range(3):
        for kb in range(3):
            mask = (a_choices == ka) & (b_choices == kb)
            if np.sum(mask) > 0:
                e = np.mean(a_results[mask] != b_results[mask])
                e_vals.append((ka, kb, float(e)))
    s_value = 0.0
    if len(e_vals) > 0:
        try:
            e11 = next(e for k, kk, e in e_vals if k == 0 and kk == 0)
            e13 = next(e for k, kk, e in e_vals if k == 0 and kk == 2)
            e31 = next(e for k, kk, e in e_vals if k == 2 and kk == 0)
            e33 = next(e for k, kk, e in e_vals if k == 2 and kk == 2)
            s_value = abs(e11 - e13 + e31 + e33 - 2 * e33)
        except StopIteration:
            s_value = 0.0
    return {"key": key, "qber": float(qber), "s_value": float(s_value), "raw_pairs": num_pairs, "sifted_length": len(sifted_alice)}
