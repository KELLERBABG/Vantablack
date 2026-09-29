import numpy as np
from quantumnet.core import QubitState, apply, X, Z
from quantumnet.protocols import shor_encode, shor_syndrome, shor_correct, shor_decode


def test_shor_encode_zero():
    logical = shor_encode(QubitState.zero())
    assert logical.num_qubits == 9
    assert np.isclose(logical.purity(), 1.0)


def test_shor_decode_identity():
    logical = shor_encode(QubitState.zero())
    decoded = shor_decode(logical)
    assert decoded.fidelity(QubitState.zero()) > 0.99


def test_shor_corrects_single_x():
    logical = shor_encode(QubitState.zero())
    logical = apply(X, logical, targets=[2])
    corrected = shor_correct(logical)
    decoded = shor_decode(corrected)
    assert decoded.fidelity(QubitState.zero()) > 0.99


def test_shor_corrects_single_z():
    logical = shor_encode(QubitState.plus())
    logical = apply(Z, logical, targets=[5])
    corrected = shor_correct(logical)
    decoded = shor_decode(corrected)
    assert decoded.fidelity(QubitState.plus()) > 0.99


def test_shor_syndrome_no_error():
    logical = shor_encode(QubitState.zero())
    syn = shor_syndrome(logical)
    assert syn == [0] * 8
