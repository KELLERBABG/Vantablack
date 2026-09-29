"""Quantum state teleportation protocol via shared EPR pairs and classical communication."""

import numpy as np
from ..core import QubitState, H, CNOT, X, Z, apply, measure


def _random_qubit_state(rng: np.random.Generator) -> QubitState:
    alpha = rng.random() + 1j * rng.random()
    beta = rng.random() + 1j * rng.random()
    norm = np.sqrt(abs(alpha) ** 2 + abs(beta) ** 2)
    alpha /= norm
    beta /= norm
    v = np.array([alpha, beta])
    return QubitState(np.outer(v, v.conj()))


def _reduce_to_last(state: QubitState) -> QubitState:
    dims = state.dims
    r = state.rho.reshape(*dims, *dims)
    for _ in range(len(dims) - 1):
        mid = len(r.shape) // 2
        r = np.trace(r, axis1=0, axis2=mid)
    d = dims[-1]
    return QubitState(r.reshape(d, d), dims=[d])


def run_teleportation(rng: np.random.Generator | None = None) -> dict:
    if rng is None:
        rng = np.random.default_rng()
    psi = _random_qubit_state(rng)
    rho_bell = QubitState.bell_phi_plus().rho
    full_rho = np.kron(psi.rho, rho_bell)
    state = QubitState(full_rho, dims=[2, 2, 2])
    state = apply(CNOT, state, targets=[0, 1])
    state = apply(H, state, targets=[0])
    outcomes, state = measure(state, qubit_indices=[0, 1], rng=rng)
    b0, b1 = outcomes[0], outcomes[1]
    if b1 == 1:
        state = apply(X, state, targets=[2])
    if b0 == 1:
        state = apply(Z, state, targets=[2])
    bob_rho = _reduce_to_last(state)
    teleported_fidelity = psi.fidelity(bob_rho)
    return {
        "input_fidelity": float(psi.fidelity(psi)),
        "teleported_fidelity": float(teleported_fidelity),
        "bell_outcome": (int(b0), int(b1)),
        "success": bool(teleported_fidelity > 0.99),
    }
