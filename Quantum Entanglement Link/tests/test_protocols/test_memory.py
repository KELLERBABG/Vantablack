import numpy as np
from quantumnet.core import QubitState
from quantumnet.protocols import apply_t1_t2_noise, memory_fidelity_over_time, memory_cutoff_time, QuantumMemoryBuffer


def test_t1_decay():
    excited = QubitState.one()
    decayed = apply_t1_t2_noise(excited, t=1.0, t1=1.0, t2=1000.0)
    assert decayed.purity() < 1.0
    assert decayed.rho[0, 0] > 0 and decayed.rho[0, 0] < 1


def test_no_noise():
    zero = QubitState.zero()
    same = apply_t1_t2_noise(zero, t=100.0, t1=1e6, t2=1e6)
    assert same.fidelity(zero) > 0.99


def test_fidelity_decays():
    one = QubitState.one()
    fids = memory_fidelity_over_time(one, [0, 1, 10], t1=5.0, t2=5.0)
    assert fids[0] > fids[1] > fids[2]


def test_memory_cutoff():
    t_cut = memory_cutoff_time(QubitState.one(), t1=10.0, t2=10.0, threshold=0.5)
    assert t_cut > 0


def test_buffer_store_retrieve():
    buf = QuantumMemoryBuffer(t1=100.0, t2=100.0, cutoff_fidelity=0.5)
    buf.store("q1", QubitState.zero(), current_time=0.0)
    retrieved = buf.retrieve("q1", current_time=1.0)
    assert retrieved is not None
    assert retrieved.fidelity(QubitState.zero()) > 0.99


def test_buffer_cutoff():
    buf = QuantumMemoryBuffer(t1=1.0, t2=1.0, cutoff_fidelity=0.5)
    buf.store("q1", QubitState.one(), current_time=0.0)
    retrieved = buf.retrieve("q1", current_time=100.0)
    assert retrieved is None
