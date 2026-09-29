import numpy as np
from quantumnet.core import QubitState, measure_bell
from quantumnet.protocols.bell import prepare_bell_state, bell_measurement, bell_fidelity, BELL_MAP


def test_prepare_bell():
    bell = prepare_bell_state()
    expected = QubitState.bell_phi_plus()
    assert bell.fidelity(expected) > 0.999


def test_bell_measurement():
    bell = prepare_bell_state()
    outcome, post = bell_measurement(bell, rng=np.random.default_rng(42))
    assert 0 <= outcome <= 3
    assert post.is_pure


def test_bell_fidelity_perfect():
    bell = prepare_bell_state()
    f = bell_fidelity(bell, 0)
    assert f > 0.999


def test_all_bell_states():
    for idx in range(4):
        state = BELL_MAP[idx][1]()
        assert state.is_pure
        assert np.isclose(state.fidelity(state), 1.0)


def test_bell_states_orthogonal():
    for i in range(4):
        for j in range(4):
            if i != j:
                si = BELL_MAP[i][1]()
                sj = BELL_MAP[j][1]()
                assert si.fidelity(sj) < 0.01
