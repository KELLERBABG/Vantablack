import numpy as np
from ..core import QubitState, apply, X, Z


_ENCODED_ZERO = None
_ENCODED_ONE = None


def _compute_logical_states():
    global _ENCODED_ZERO, _ENCODED_ONE
    ghz3 = np.zeros(8, dtype=complex)
    ghz3[0] = 1.0
    ghz3[7] = 1.0
    ghz3 /= np.sqrt(2)
    zero = np.kron(np.kron(ghz3, ghz3), ghz3)
    zero /= np.linalg.norm(zero)
    ghz3_m = np.zeros(8, dtype=complex)
    ghz3_m[0] = 1.0
    ghz3_m[7] = -1.0
    ghz3_m /= np.sqrt(2)
    one = np.kron(np.kron(ghz3_m, ghz3_m), ghz3_m)
    one /= np.linalg.norm(one)
    _ENCODED_ZERO = zero
    _ENCODED_ONE = one


def _get_encoding_matrix():
    if _ENCODED_ZERO is None:
        _compute_logical_states()
    return np.column_stack([_ENCODED_ZERO, _ENCODED_ONE])


def shor_encode(state: QubitState) -> QubitState:
    alpha = np.sqrt(max(0, state.rho[0, 0]))
    beta = np.sqrt(max(0, state.rho[1, 1]))
    phase = np.angle(state.rho[0, 1]) if abs(state.rho[0, 1]) > 1e-10 else 0.0
    vec = np.array([alpha, beta * np.exp(1j * phase)], dtype=complex)
    U = _get_encoding_matrix()
    enc = U @ vec
    return QubitState(np.outer(enc, enc.conj()), dims=[2] * 9)


def shor_stabilizers():
    return [
        [(0, 'Z'), (1, 'Z')],
        [(1, 'Z'), (2, 'Z')],
        [(3, 'Z'), (4, 'Z')],
        [(4, 'Z'), (5, 'Z')],
        [(6, 'Z'), (7, 'Z')],
        [(7, 'Z'), (8, 'Z')],
        [(0, 'X'), (1, 'X'), (2, 'X'), (3, 'X'), (4, 'X'), (5, 'X')],
        [(3, 'X'), (4, 'X'), (5, 'X'), (6, 'X'), (7, 'X'), (8, 'X')],
    ]


_PAULIS = {
    'I': np.eye(2, dtype=complex),
    'X': np.array([[0, 1], [1, 0]], dtype=complex),
    'Z': np.array([[1, 0], [0, -1]], dtype=complex),
}


def _pauli_string_op(ops, n):
    full = np.array([1.0], dtype=complex)
    for i in range(n):
        p = 'I'
        for qi, pauli in ops:
            if qi == i:
                p = pauli
                break
        full = np.kron(full, _PAULIS[p])
    return full


def shor_syndrome(state):
    n = state.num_qubits
    return [0 if np.real(np.trace(_pauli_string_op(stab, n) @ state.rho)) > 0 else 1
            for stab in shor_stabilizers()]


def shor_correct(state):
    s = shor_syndrome(state)
    for block_idx in range(3):
        z1, z2 = s[block_idx * 2], s[block_idx * 2 + 1]
        if z1 == 1 and z2 == 0:
            state = apply(X, state, targets=[block_idx * 3])
        elif z1 == 0 and z2 == 1:
            state = apply(X, state, targets=[block_idx * 3 + 2])
        elif z1 == 1 and z2 == 1:
            state = apply(X, state, targets=[block_idx * 3 + 1])
    p1, p2 = s[6], s[7]
    if p1 and not p2:
        state = apply(Z, state, targets=[0])
    elif not p1 and p2:
        state = apply(Z, state, targets=[6])
    elif p1 and p2:
        state = apply(Z, state, targets=[3])
    return state


def shor_decode(state):
    U = _get_encoding_matrix()
    decoded = U.conj().T @ state.rho @ U
    return QubitState(decoded, dims=[2])
