"""Interactive demonstration runner for quantum network protocols and QEL bridges."""

import numpy as np
from .core import QubitState, apply, X, Z
from .protocols import (
    run_bb84, run_e91, run_teleportation, run_superdense, run_swapping,
    shor_encode, shor_correct, shor_decode,
    steane_encode, steane_correct, steane_decode,
    bbssw_distill, deutsch_distill, prepare_noisy_bell_pairs,
    memory_fidelity_over_time, memory_cutoff_time, QuantumMemoryBuffer,
)


def run_all_demos():
    rng = np.random.default_rng(42)
    sep = "-" * 60
    print(sep)
    print("  Quantum Entanglement Link -- Protocol Demos")
    print(sep)

    print("\n[1/8] BB84 QKD -- 256 bits, 1% noise")
    r = run_bb84(256, noise=0.01, rng=rng)
    print(f"  | Sifted key: {len(r['key'])} bits")
    print(f"  | QBER:       {r['qber']:.4f}")
    print(f"  | Key prefix: {r['key'][:24]}")

    print("\n[2/8] E91 QKD -- 256 Bell pairs, 1% noise")
    r = run_e91(256, noise=0.01, rng=rng)
    print(f"  | Sifted key: {len(r['key'])} bits")
    print(f"  | QBER:       {r['qber']:.4f}")
    print(f"  | CHSH S:     {r['s_value']:.4f}")
    print(f"  | Key prefix: {r['key'][:24]}")

    print("\n[3/8] Quantum Teleportation")
    r = run_teleportation(rng=rng)
    print(f"  | Input fidelity:   {r['input_fidelity']:.6f}")
    print(f"  | Teleported fid:   {r['teleported_fidelity']:.6f}")
    print(f"  | Success:          {r['success']}")

    print("\n[4/8] Superdense Coding")
    for bits in range(4):
        r = run_superdense(bits, rng=rng)
        ok = "OK" if r["success"] else "FAIL"
        print(f"  | {bits:02b} -> {r['decoded_bits']}  {ok}")

    print("\n[5/8] Entanglement Swapping")
    r = run_swapping(noise=0.0, rng=rng)
    print(f"  | Bell outcome: {r['bell_outcome']}")
    print(f"  | Swapped fid:  {r['swapped_fidelity']:.6f}")
    print(f"  | Success:      {r['success']}")
    r2 = run_swapping(noise=0.1, rng=rng)
    print(f"  | (10% noise:   fid={r2['swapped_fidelity']:.6f})")

    print("\n[6/8] Shor 9-qubit Error Correction")
    for label, state in [("zero", QubitState.zero()), ("plus", QubitState.plus())]:
        enc = shor_encode(state)
        noisy = apply(X, enc, targets=[3])
        corrected = shor_correct(noisy)
        dec = shor_decode(corrected)
        fid = state.fidelity(dec)
        print(f"  | {label}: X error on q3 -> corrected, fid={fid:.6f}")
        noisy = apply(Z, enc, targets=[7])
        corrected = shor_correct(noisy)
        dec = shor_decode(corrected)
        fid = state.fidelity(dec)
        print(f"  | {label}: Z error on q7 -> corrected, fid={fid:.6f}")

    print("\n[7/8] Steane 7-qubit Error Correction")
    for label, state in [("zero", QubitState.zero()), ("plus", QubitState.plus())]:
        enc = steane_encode(state)
        noisy = apply(X, enc, targets=[3])
        corrected = steane_correct(noisy)
        dec = steane_decode(corrected)
        fid = state.fidelity(dec)
        print(f"  | {label}: X error on q3 -> corrected, fid={fid:.6f}")
        noisy = apply(Z, enc, targets=[1])
        corrected = steane_correct(noisy)
        dec = steane_decode(corrected)
        fid = state.fidelity(dec)
        print(f"  | {label}: Z error on q1 -> corrected, fid={fid:.6f}")

    print("\n[8/8] Distillation & Memory")
    for proto_name, func in [("BBPSSW", bbssw_distill), ("Deutsch", deutsch_distill)]:
        pairs = prepare_noisy_bell_pairs(2, fidelity=0.75, rng=rng)
        result = func(pairs[0], pairs[1], rng=rng)
        print(f"  | {proto_name}: success={result['success']}, fid={result['distilled_fidelity']:.4f}")
    state = QubitState.one()
    fids = memory_fidelity_over_time(state, [0, 5, 10], t1=10.0, t2=10.0)
    print(f"  | Memory (|1>, T1=T2=10): fids={[f'{f:.4f}' for f in fids]}")
    t_cut = memory_cutoff_time(state, t1=10.0, t2=10.0, threshold=0.5)
    print(f"  | Cutoff time (threshold=0.5): {t_cut:.4f}")

    print(f"\n{sep}")
    print("  All demos complete.")
    print(sep)


if __name__ == "__main__":
    run_all_demos()
