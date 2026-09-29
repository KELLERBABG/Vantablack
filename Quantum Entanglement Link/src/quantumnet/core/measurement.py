import numpy as np
from .qubit import QubitState


def measure(state: QubitState, qubit_indices: list[int], rng: np.random.Generator | None = None) -> tuple[dict[int, int], QubitState]:
    """Perform a computational basis measurement on specified qubits.

    Computes joint probabilities sequentially (projecting after each outcome),
    then projects the full state onto the observed outcome combination and
    traces out the measured qubits.

    Args:
        state: The quantum state to measure.
        qubit_indices: Indices of qubits to measure.
        rng: Random number generator for reproducibility.

    Returns:
        Tuple of (outcomes_dict, post_measurement_state on unmeasured qubits).
    """
    if rng is None:
        rng = np.random.default_rng()
    n = state.num_qubits
    dims = state.dims
    qi_list = sorted(qubit_indices)

    outcomes = {}
    cur_rho = state.rho.copy()

    for qi in qi_list:
        d = 2 ** n
        p0 = sum(cur_rho[i, i] for i in range(d)
                 if ((i >> (n - 1 - qi)) & 1) == 0)
        p0 = float(np.real(p0))
        p0 = np.clip(p0, 0, 1)
        outcome = 0 if rng.random() < p0 else 1
        outcomes[qi] = outcome

        proj = np.zeros(d, dtype=complex)
        for i in range(d):
            if ((i >> (n - 1 - qi)) & 1) == outcome:
                proj[i] = 1.0
        P = np.diag(proj)
        cur_rho = P @ cur_rho @ P
        tr = float(np.real(np.trace(cur_rho)))
        if tr > 1e-15:
            cur_rho = cur_rho / tr

    return outcomes, QubitState(cur_rho, dims=dims.copy())


def measure_bell(state: QubitState, rng: np.random.Generator | None = None) -> tuple[int, QubitState]:
    """Perform a Bell basis measurement on a 2-qubit state.

    Transforms to the Bell basis via CNOT then H, then measures in the
    computational basis.

    Args:
        state: A 2-qubit state.
        rng: Random number generator for reproducibility.

    Returns:
        Tuple of (bell_index, post_measurement_state).
        bell_index: 0=|Phi+>, 1=|Phi->, 2=|Psi+>, 3=|Psi->
    """
    if rng is None:
        rng = np.random.default_rng()
    from .gate import H, CNOT, apply
    transformed = apply(CNOT, state, targets=[0, 1])
    transformed = apply(H, transformed, targets=[0])
    outcomes, collapsed = measure(transformed, [0, 1], rng=rng)
    bell_index = outcomes[0] * 2 + outcomes[1]
    return bell_index, collapsed
