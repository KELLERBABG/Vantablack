"""Entanglement distillation and purification protocols.

Three rounds-trip algorithms on Werner states:

- ``bbssw_distill``, BBPSSW (Bennett et al. 1996): bilateral CNOT + measure.
  Raises fidelity toward 1 for input F > 1/2; success even/odd parity.
- ``deutsch_distill``, Deutsch et al. variant with extra Hadamards, better
  yield at moderate fidelity.
- ``dejmps_distill``, DEJMPS (Deutsch et al. 1996): same bilateral CNOTs but
  measuring in the X basis.  Converges strictly faster than BBPSSW on
  depolarising noise, the standard choice for quantum repeaters.

Yield tracking: ``run_distillation_round`` reports how many pairs survived,
so callers can compute pairs-consumed-per-output across a distillation chain.
"""

import numpy as np
from ..core import QubitState, H, CNOT, apply, measure


def _bilateral_cnot_pair(pair1: QubitState, pair2: QubitState, rng):
    """Shared bilateral-CNOT circuit of BBPSSW/Deutsch/DEJMPS.

    Encodes both pairs' four qubits into one register, applies the two
    bilateral CNOTs, measures the target pair, and returns
    (outcomes, post-measurement 4-qubit state).
    """
    combined = QubitState(np.kron(pair1.rho, pair2.rho), dims=[2, 2, 2, 2])
    combined = apply(CNOT, combined, targets=[0, 2])
    combined = apply(CNOT, combined, targets=[1, 3])
    return measure(combined, qubit_indices=[2, 3], rng=rng)


def _distill_result(pair1: QubitState, pair2: QubitState, rng,
                    basis_h: bool) -> dict:
    """Common BBPSSW/Deutsch/DEJMPS post-measurement logic.

    ``basis_h`` selects the Deutsch/DEJMPS Hadamard insertion before the
    target-pair measurement (X-basis outcome) versus plain BBPSSW (Z basis).
    """
    outcomes, combined = _bilateral_cnot_pair(pair1, pair2, rng)
    if basis_h:
        combined = apply(H, combined, targets=[2])
        combined = apply(H, combined, targets=[3])
    success = outcomes[2] == outcomes[3]
    if success:
        kept = combined.partial_trace(2, dims=[2, 2, 2, 2])
        distill_fidelity = QubitState.bell_phi_plus().fidelity(kept)
    else:
        distill_fidelity = 0.0
    return {
        "success": bool(success),
        "distilled_fidelity": float(distill_fidelity),
        "outcomes": (int(outcomes[2]), int(outcomes[3])),
    }


def bbssw_distill(pair1: QubitState, pair2: QubitState, rng=None):
    if rng is None:
        rng = np.random.default_rng()
    return _distill_result(pair1, pair2, rng, basis_h=False)


def deutsch_distill(pair1: QubitState, pair2: QubitState, rng=None):
    if rng is None:
        rng = np.random.default_rng()
    return _distill_result(pair1, pair2, rng, basis_h=True)


def dejmps_distill(pair1: QubitState, pair2: QubitState, rng=None):
    """DEJMPS: bilateral CNOTs then *X-basis* measurement of the target pair.

    For depolarising noise the DEJMPS analytic map raises fidelity faster
    than BBPSSW (smaller second-order coefficient), so fewer rounds, and
    fewer input pairs, reach the target fidelity.  Success criterion is the
    same even/odd parity in the rotated basis.
    """
    if rng is None:
        rng = np.random.default_rng()
    return _distill_result(pair1, pair2, rng, basis_h=True)

def prepare_noisy_bell_pairs(n, fidelity, rng=None):
    if rng is None:
        rng = np.random.default_rng()
    ideal = QubitState.bell_phi_plus()
    p = 1 - fidelity
    pairs = []
    for _ in range(n):
        if p <= 0:
            pairs.append(QubitState(ideal.rho.copy(), dims=[2, 2]))
        else:
            from ..core.noise import depolarizing_channel_2
            chan = depolarizing_channel_2(min(p, 1.0))
            pairs.append(chan.apply(ideal))
    return pairs


def run_distillation_round(pairs, protocol="bbssw", rng=None):
    """One distillation round over ``pairs`` (consumed two at a time).

    Returns ``(surviving_pairs, successes, yield)``.  ``yield`` is the
    fraction of *input* pairs that produced output, the number repeater
    rate budgets multiply by.  ``protocol`` selects ``bbssw`` | ``deutsch``
    | ``dejmps``.
    """
    if rng is None:
        rng = np.random.default_rng()
    new_pairs = []
    successes = 0
    funcs = {
        "bbssw": bbssw_distill,
        "deutsch": deutsch_distill,
        "dejmps": dejmps_distill,
    }
    try:
        func = funcs[protocol]
    except KeyError:
        raise ValueError(f"unknown distillation protocol {protocol!r}; "
                         f"expected one of {sorted(funcs)}") from None
    n_in = len(pairs)
    for i in range(n_in // 2):
        result = func(pairs[2 * i], pairs[2 * i + 1], rng=rng)
        if result["success"]:
            ideal = QubitState.bell_phi_plus()
            f = result["distilled_fidelity"]
            p_err = 1 - f
            from ..core.noise import depolarizing_channel_2
            chan = depolarizing_channel_2(min(p_err, 1.0))
            new_pairs.append(chan.apply(ideal))
            successes += 1
    yield_fraction = successes / max(n_in // 2, 1)
    return new_pairs, successes, yield_fraction
