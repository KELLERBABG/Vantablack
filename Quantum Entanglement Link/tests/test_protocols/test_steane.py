import numpy as np
from quantumnet.core import QubitState, apply, X, Z
from quantumnet.protocols import steane_encode, steane_syndrome, steane_correct, steane_decode


def test_steane_encode_zero():
    logical = steane_encode(QubitState.zero())
    assert logical.num_qubits == 7
    assert np.isclose(logical.purity(), 1.0)


def test_steane_decode_identity():
    logical = steane_encode(QubitState.zero())
    decoded = steane_decode(logical)
    assert decoded.fidelity(QubitState.zero()) > 0.99


def test_steane_corrects_single_x():
    logical = steane_encode(QubitState.zero())
    logical = apply(X, logical, targets=[3])
    corrected = steane_correct(logical)
    decoded = steane_decode(corrected)
    assert decoded.fidelity(QubitState.zero()) > 0.99


def test_steane_corrects_single_z():
    logical = steane_encode(QubitState.plus())
    logical = apply(Z, logical, targets=[1])
    corrected = steane_correct(logical)
    decoded = steane_decode(corrected)
    assert decoded.fidelity(QubitState.plus()) > 0.99


def test_steane_syndrome_no_error():
    logical = steane_encode(QubitState.zero())
    syn = steane_syndrome(logical)
    assert syn == [0] * 6
