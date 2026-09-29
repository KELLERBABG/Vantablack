import numpy as np
from ..core import QubitState, H, CNOT, X, Z, apply, measure


def _bell_pair() -> QubitState:
    state = QubitState(np.kron(QubitState.zero().rho, QubitState.zero().rho), dims=[2, 2])
    state = apply(H, state, targets=[0])
    state = apply(CNOT, state, targets=[0, 1])
    return state


def _reduce_to_first_last(state: QubitState) -> QubitState:
    dims = state.dims
    r = state.rho.reshape(*dims, *dims)
    for _ in range(1, len(dims) - 1):
        mid = len(r.shape) // 2
        r = np.trace(r, axis1=1, axis2=mid + 1)
    keep = [dims[0], dims[-1]]
    d = int(np.prod(keep))
    return QubitState(r.reshape(d, d), dims=keep)


def run_swapping(noise: float = 0.0, rng: np.random.Generator | None = None) -> dict:
    if rng is None:
        rng = np.random.default_rng()
    pair_ac = _bell_pair()
    pair_cb = _bell_pair()
    all_rho = np.kron(pair_ac.rho, pair_cb.rho)
    state = QubitState(all_rho, dims=[2, 2, 2, 2])
    if noise > 0:
        from ..core.noise import depolarizing_channel_2
        chan = depolarizing_channel_2(noise)
        state = chan.apply(state, targets=[0, 1])
        state = chan.apply(state, targets=[2, 3])
    state = apply(CNOT, state, targets=[1, 2])
    state = apply(H, state, targets=[1])
    outcomes, state = measure(state, qubit_indices=[1, 2], rng=rng)
    m1, m2 = outcomes[1], outcomes[2]
    if (m1, m2) == (0, 1):
        state = apply(X, state, targets=[0])
    elif (m1, m2) == (1, 0):
        state = apply(Z, state, targets=[0])
    elif (m1, m2) == (1, 1):
        state = apply(X, state, targets=[0])
        state = apply(Z, state, targets=[0])
    ab_state = _reduce_to_first_last(state)
    expected = QubitState.bell_phi_plus()
    swapped_fidelity = expected.fidelity(ab_state)
    return {
        "bell_outcome": (int(m1), int(m2)),
        "swapped_fidelity": float(swapped_fidelity),
        "success": bool(swapped_fidelity > 0.9),
    }
