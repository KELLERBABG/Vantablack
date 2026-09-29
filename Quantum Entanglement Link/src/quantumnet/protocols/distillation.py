import numpy as np
from ..core import QubitState, H, CNOT, apply, measure


def bbssw_distill(pair1: QubitState, pair2: QubitState, rng=None):
    if rng is None:
        rng = np.random.default_rng()
    combined = QubitState(np.kron(pair1.rho, pair2.rho), dims=[2, 2, 2, 2])
    combined = apply(CNOT, combined, targets=[0, 2])
    combined = apply(CNOT, combined, targets=[1, 3])
    outcomes, combined = measure(combined, qubit_indices=[2, 3], rng=rng)
    success = outcomes[2] == outcomes[3]
    if success:
        kept = combined.partial_trace(2, dims=[2, 2, 2, 2])
        distill_fidelity = QubitState.bell_phi_plus().fidelity(kept)
    else:
        distill_fidelity = 0.0
    return {"success": bool(success), "distilled_fidelity": float(distill_fidelity), "outcomes": (int(outcomes[2]), int(outcomes[3]))}


def deutsch_distill(pair1: QubitState, pair2: QubitState, rng=None):
    if rng is None:
        rng = np.random.default_rng()
    combined = QubitState(np.kron(pair1.rho, pair2.rho), dims=[2, 2, 2, 2])
    combined = apply(CNOT, combined, targets=[0, 2])
    combined = apply(CNOT, combined, targets=[1, 3])
    combined = apply(H, combined, targets=[2])
    combined = apply(H, combined, targets=[3])
    outcomes, combined = measure(combined, qubit_indices=[2, 3], rng=rng)
    success = outcomes[2] == outcomes[3]
    if success:
        kept = combined.partial_trace(2, dims=[2, 2, 2, 2])
        distill_fidelity = QubitState.bell_phi_plus().fidelity(kept)
    else:
        distill_fidelity = 0.0
    return {"success": bool(success), "distilled_fidelity": float(distill_fidelity), "outcomes": (int(outcomes[2]), int(outcomes[3]))}


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
    if rng is None:
        rng = np.random.default_rng()
    new_pairs = []
    successes = 0
    func = bbssw_distill if protocol == "bbssw" else deutsch_distill
    for i in range(len(pairs) // 2):
        result = func(pairs[2 * i], pairs[2 * i + 1], rng=rng)
        if result["success"]:
            ideal = QubitState.bell_phi_plus()
            f = result["distilled_fidelity"]
            p_err = 1 - f
            from ..core.noise import depolarizing_channel_2
            chan = depolarizing_channel_2(min(p_err, 1.0))
            new_pairs.append(chan.apply(ideal))
            successes += 1
    return new_pairs, successes
