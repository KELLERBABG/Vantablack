import numpy as np
from ..core import QubitState, apply, I, X, Z, H


_PAULIS = {
    'I': np.eye(2, dtype=complex),
    'X': np.array([[0, 1], [1, 0]], dtype=complex),
    'Z': np.array([[1, 0], [0, -1]], dtype=complex),
}

STEANE_STABS = [
    [(0, 'X'), (1, 'X'), (2, 'X'), (4, 'X')],
    [(0, 'Z'), (1, 'Z'), (2, 'Z'), (4, 'Z')],
    [(0, 'X'), (1, 'X'), (3, 'X'), (5, 'X')],
    [(0, 'Z'), (1, 'Z'), (3, 'Z'), (5, 'Z')],
    [(0, 'X'), (2, 'X'), (3, 'X'), (6, 'X')],
    [(0, 'Z'), (2, 'Z'), (3, 'Z'), (6, 'Z')],
]


def _build_steane_states():
    H_mat = np.array([
        [1, 1, 1, 0, 1, 0, 0],
        [1, 1, 0, 1, 0, 1, 0],
        [1, 0, 1, 1, 0, 0, 1],
    ])
    dual_codewords = []
    for x in range(8):
        bits = [(x >> i) & 1 for i in range(3)]
        c = (np.array(bits) @ H_mat) % 2
        idx = sum(int(c[i]) << (6 - i) for i in range(7))
        dual_codewords.append(idx)
    zero = np.zeros(128, dtype=complex)
    one = np.zeros(128, dtype=complex)
    flip = int('1111111', 2)
    for idx in dual_codewords:
        zero[idx] = 1.0
        one[idx ^ flip] = 1.0
    zero /= np.sqrt(len(dual_codewords))
    one /= np.sqrt(len(dual_codewords))
    return zero, one


_LOGICAL_ZERO, _LOGICAL_ONE = _build_steane_states()
ENCODING_MATRIX = np.column_stack([_LOGICAL_ZERO, _LOGICAL_ONE])


def steane_encode(state: QubitState) -> QubitState:
    alpha = np.sqrt(max(0, state.rho[0, 0]))
    beta = np.sqrt(max(0, state.rho[1, 1]))
    phase = np.angle(state.rho[0, 1]) if abs(state.rho[0, 1]) > 1e-10 else 0.0
    vec = np.array([alpha, beta * np.exp(1j * phase)], dtype=complex)
    enc = ENCODING_MATRIX @ vec
    return QubitState(np.outer(enc, enc.conj()), dims=[2] * 7)


def steane_syndrome(state):
    n = 7
    syndrome = []
    for stab in STEANE_STABS:
        op = np.array([1.0], dtype=complex)
        for i in range(n):
            p = 'I'
            for qi, pauli in stab:
                if qi == i:
                    p = pauli
                    break
            op = np.kron(op, _PAULIS[p])
        exp_val = np.real(np.trace(op @ state.rho))
        syndrome.append(0 if exp_val > 0 else 1)
    return syndrome


def steane_correct(state):
    s = steane_syndrome(state)
    x_syn = (s[0], s[2], s[4])
    z_syn = (s[1], s[3], s[5])
    col_lookup = {
        (1, 1, 1): 0, (1, 1, 0): 1, (1, 0, 1): 2, (0, 1, 1): 3,
        (1, 0, 0): 4, (0, 1, 0): 5, (0, 0, 1): 6, (0, 0, 0): None,
    }
    z_err = col_lookup.get(x_syn)
    x_err = col_lookup.get(z_syn)
    if x_err is not None:
        state = apply(X, state, targets=[x_err])
    if z_err is not None:
        state = apply(Z, state, targets=[z_err])
    return state


def steane_decode(state):
    projected = ENCODING_MATRIX @ ENCODING_MATRIX.conj().T @ state.rho @ ENCODING_MATRIX @ ENCODING_MATRIX.conj().T
    decoded = ENCODING_MATRIX.conj().T @ projected @ ENCODING_MATRIX
    return QubitState(decoded, dims=[2])
