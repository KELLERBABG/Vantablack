import numpy as np
from quantumnet.core import QubitState, measure


def test_measure_zero():
    q = QubitState.zero()
    outcomes, _ = measure(q, qubit_indices=[0], rng=np.random.default_rng(42))
    assert outcomes[0] == 0


def test_measure_one():
    q = QubitState.one()
    outcomes, _ = measure(q, qubit_indices=[0], rng=np.random.default_rng(42))
    assert outcomes[0] == 1


def test_measure_plus_random():
    q = QubitState.plus()
    rng = np.random.default_rng(42)
    outcomes, _ = measure(q, qubit_indices=[0], rng=rng)
    assert outcomes[0] in (0, 1)


def test_measure_preserves_state():
    q = QubitState.zero()
    _, post = measure(q, qubit_indices=[0], rng=np.random.default_rng(42))
    assert post.fidelity(QubitState.zero()) > 0.999
