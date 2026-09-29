import numpy as np
from quantumnet.core import QubitState, apply, I, H, CNOT, CZ
from quantumnet.core.noise import (
    depolarizing_channel,
    amplitude_damping_channel,
    dephasing_channel,
    depolarizing_channel_2,
)


def test_depolarizing_no_noise():
    chan = depolarizing_channel(0.0)
    q = chan.apply(QubitState.zero())
    assert q.fidelity(QubitState.zero()) > 0.999


def test_depolarizing_full_noise():
    chan = depolarizing_channel(1.0)
    q = chan.apply(QubitState.zero())
    assert not q.is_pure


def test_depolarizing_reduces_fidelity():
    q_clean = QubitState.zero()
    chan = depolarizing_channel(0.5)
    q_noisy = chan.apply(q_clean)
    assert q_noisy.fidelity(q_clean) < 1.0


def test_amplitude_damping():
    chan = amplitude_damping_channel(0.5)
    q = chan.apply(QubitState.one())
    assert q.fidelity(QubitState.zero()) > 0
    assert q.fidelity(QubitState.zero()) < 1


def test_dephasing():
    chan = dephasing_channel(0.5)
    q = chan.apply(QubitState.plus())
    assert q.fidelity(QubitState.plus()) < 1


def test_depolarizing_2_reduces_concurrence():
    chan = depolarizing_channel_2(0.3)
    bell = QubitState.bell_phi_plus()
    q = chan.apply(bell)
    assert q.concurrence() < 1.0
