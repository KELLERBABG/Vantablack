"""Bell state preparation, CHSH inequality tests, and entanglement verification."""

import numpy as np
from ..core import QubitState, H, CNOT, apply, measure_bell


BELL_MAP = {
    0: ("|Φ+⟩", QubitState.bell_phi_plus),
    1: ("|Φ-⟩", QubitState.bell_phi_minus),
    2: ("|Ψ+⟩", QubitState.bell_psi_plus),
    3: ("|Ψ-⟩", QubitState.bell_psi_minus),
}


def bell_state(index: int) -> QubitState:
    return BELL_MAP[index][1]()


def prepare_bell_state() -> QubitState:
    state = QubitState(np.kron(QubitState.zero().rho, QubitState.zero().rho), dims=[2, 2])
    state = apply(H, state, targets=[0])
    state = apply(CNOT, state, targets=[0, 1])
    return state


def bell_measurement(state: QubitState, rng: np.random.Generator | None = None) -> tuple[int, QubitState]:
    if rng is None:
        rng = np.random.default_rng()
    return measure_bell(state, rng)


def bell_fidelity(state: QubitState, target: int) -> float:
    return state.fidelity(bell_state(target))
