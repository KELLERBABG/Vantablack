import numpy as np
from quantumnet.core import QubitState, Gate, I, X, Y, Z, H, S, T, CNOT, SWAP, apply


def test_hadamard_on_zero():
    q = apply(H, QubitState.zero(), targets=[0])
    expected = QubitState.plus()
    assert np.isclose(q.fidelity(expected), 1.0)


def test_x_on_zero():
    q = apply(X, QubitState.zero(), targets=[0])
    assert q.fidelity(QubitState.one()) > 0.999


def test_xx_is_i():
    q = apply(X, apply(X, QubitState.zero(), targets=[0]), targets=[0])
    assert q.fidelity(QubitState.zero()) > 0.999


def test_cnot():
    state = QubitState(np.kron(QubitState.plus().rho, QubitState.zero().rho), dims=[2, 2])
    state = apply(CNOT, state, targets=[0, 1])
    bell = QubitState.bell_phi_plus()
    assert state.fidelity(bell) > 0.999


def test_swap():
    state = QubitState(np.kron(QubitState.zero().rho, QubitState.one().rho), dims=[2, 2])
    state = apply(SWAP, state, targets=[0, 1])
    expected = QubitState(np.kron(QubitState.one().rho, QubitState.zero().rho), dims=[2, 2])
    assert state.fidelity(expected) > 0.999


def test_dagger():
    assert np.allclose((H @ H.dag).matrix, I.matrix)


def test_tensor_product():
    h2 = H.tensor(H)
    assert h2.matrix.shape == (4, 4)
