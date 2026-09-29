"""Command-line interface and CLI command dispatcher for Quantum Entanglement Link (QEL)."""

import argparse
import numpy as np
from .core import (
    QubitState, apply, X, Z,
    StabilizerState,
    Scheduler,
    fiber_transmissivity, fiber_loss_db,
    dark_count_probability,
    t1_decay_probability, t2_dephase_probability,
    depolarizing_from_distance,
)
from .protocols import (
    run_bb84, run_e91, run_teleportation, run_superdense, run_swapping,
    shor_encode, shor_correct, shor_decode, shor_syndrome,
    steane_encode, steane_correct, steane_decode, steane_syndrome,
    bbssw_distill, deutsch_distill, prepare_noisy_bell_pairs,
    memory_fidelity_over_time, memory_cutoff_time, QuantumMemoryBuffer,
    apply_t1_t2_noise,
)


def _do_shor(args):
    rng = np.random.default_rng(args.seed)
    if args.state == "zero":
        orig = QubitState.zero()
    elif args.state == "one":
        orig = QubitState.one()
    else:
        orig = QubitState.plus()
    enc = shor_encode(orig)
    print(f"Shor code -- {args.state} state, {args.error} error on qubit {args.qubit}")
    print(f"  Encoded qubits: {enc.num_qubits}")
    print(f"  Encoded purity: {enc.purity():.6f}")
    if args.error != "none":
        gate = X if args.error == "X" else Z
        enc = apply(gate, enc, targets=[args.qubit])
        syn_before = shor_syndrome(enc)
        print(f"  Syndrome (before): {syn_before}")
        enc = shor_correct(enc)
        syn_after = shor_syndrome(enc)
        print(f"  Syndrome (after):  {syn_after}")
    dec = shor_decode(enc)
    fid = orig.fidelity(dec)
    print(f"  Decoded fidelity:  {fid:.6f}")
    return fid > 0.99


def _do_steane(args):
    rng = np.random.default_rng(args.seed)
    if args.state == "zero":
        orig = QubitState.zero()
    elif args.state == "one":
        orig = QubitState.one()
    else:
        orig = QubitState.plus()
    enc = steane_encode(orig)
    print(f"Steane code -- {args.state} state, {args.error} error on qubit {args.qubit}")
    print(f"  Encoded qubits: {enc.num_qubits}")
    print(f"  Encoded purity: {enc.purity():.6f}")
    if args.error != "none":
        gate = X if args.error == "X" else Z
        enc = apply(gate, enc, targets=[args.qubit])
        syn_before = steane_syndrome(enc)
        print(f"  Syndrome (before): {syn_before}")
        enc = steane_correct(enc)
        syn_after = steane_syndrome(enc)
        print(f"  Syndrome (after):  {syn_after}")
    dec = steane_decode(enc)
    fid = orig.fidelity(dec)
    print(f"  Decoded fidelity:  {fid:.6f}")
    return fid > 0.99


def _do_distill(args):
    rng = np.random.default_rng(args.seed)
    pairs = prepare_noisy_bell_pairs(2, fidelity=args.fidelity, rng=rng)
    func = bbssw_distill if args.protocol == "bbssw" else deutsch_distill
    result = func(pairs[0], pairs[1], rng=rng)
    print(f"Distillation ({args.protocol}) -- input fidelity={args.fidelity}")
    print(f"  Success:           {result['success']}")
    print(f"  Distilled fidelity: {result['distilled_fidelity']:.6f}")
    print(f"  Outcomes:          {result['outcomes']}")
    return result


def _do_memory(args):
    if args.state == "zero":
        state = QubitState.zero()
    elif args.state == "one":
        state = QubitState.one()
    else:
        state = QubitState.plus()
    print(f"Memory buffer -- {args.state} state, T1={args.t1}, T2={args.t2}")
    fids = memory_fidelity_over_time(state, [0, args.t, args.t * 2], t1=args.t1, t2=args.t2)
    print(f"  Fidelity at t=0:   {fids[0]:.6f}")
    print(f"  Fidelity at t={args.t}:    {fids[1]:.6f}")
    print(f"  Fidelity at t={args.t*2}:  {fids[2]:.6f}")
    t_cut = memory_cutoff_time(state, t1=args.t1, t2=args.t2, threshold=args.threshold)
    print(f"  Cutoff time (threshold={args.threshold}): {t_cut:.4f}")
    buf = QuantumMemoryBuffer(t1=args.t1, t2=args.t2, cutoff_fidelity=args.threshold)
    buf.store("q1", state, current_time=0.0)
    retrieved = buf.retrieve("q1", current_time=t_cut * 2)
    print(f"  Retrieve after 2x cutoff: {'None (dropped)' if retrieved is None else f'fidelity={state.fidelity(retrieved):.6f}'}")
    return fids


def _do_stabilizer(args):
    rng = np.random.default_rng(args.seed)
    if args.state == "bell":
        s = StabilizerState.bell_phi_plus()
        print("Stabilizer Bell state (|Phi+>)")
        print(f"  Tableau ({s.n} qubits):")
        for i in range(2 * s.n):
            label = f"  {'D' if i < s.n else 'S'}{i % s.n}: "
            bits = "".join(str(int(b)) for b in s.tab[i, :2 * s.n])
            phase = " -" if s.tab[i, 2 * s.n] else " +"
            print(f"    {label}{bits[:s.n]}|{bits[s.n:]}{phase}")
        dm = s.to_density()
        print(f"  Purity:           {dm.purity():.6f}")
        print(f"  Concurrence:      {dm.concurrence():.6f}")
        return True
    elif args.state == "ghz":
        n = args.nqubits
        s = StabilizerState.zero(n)
        for q in range(1, n):
            s.cnot(0, q)
        print(f"Stabilizer GHZ state ({n} qubits)")
        print(f"  Tableau size: {2 * s.n} x {2 * s.n + 1} = "
              f"{(2 * s.n) * (2 * s.n + 1)} bits")
        dm = s.to_density()
        print(f"  Purity: {dm.purity():.6f}")
        labels = [f"|{i:0{n}b}⟩" for i in range(1 << n) if abs(s.to_statevector()[i]) > 0.01]
        print(f"  Basis states: {', '.join(labels)}")
        return True
    elif args.state == "random":
        s = StabilizerState(args.nqubits)
        for _ in range(args.nqubits * 3):
            q = rng.integers(0, args.nqubits)
            g = rng.integers(0, 3)
            if g == 0:
                s.h(q)
            elif g == 1:
                s.s(q)
            else:
                s.cnot(q, rng.integers(0, args.nqubits))
        print(f"Stabilizer random state ({args.nqubits} qubits, {args.nqubits * 3} random gates)")
        print(f"  Tableau memory: ~{(2 * s.n) * (2 * s.n + 1) / 8:.0f} bytes")
        if args.nqubits <= 6:
            dm = s.to_density()
            print(f"  Purity: {dm.purity():.6f}")
        print(f"  Qubit count: {s.n}")
        return True
    parser.print_help()
    return False


def _do_physical(args):
    if args.compute == "transmissivity":
        eta = fiber_transmissivity(args.length, args.alpha)
        loss_db = fiber_loss_db(args.length, args.alpha)
        print(f"Fibre transmissivity at {args.length} km (α={args.alpha} dB/km)")
        print(f"  η = {eta:.6e}")
        print(f"  Loss = {loss_db:.2f} dB")
    elif args.compute == "dark_count":
        p = dark_count_probability(args.rate, args.window)
        print(f"Dark count probability (rate={args.rate} Hz, window={args.window} s)")
        print(f"  p_dc = {p:.6e}")
    elif args.compute == "depolarizing":
        p = depolarizing_from_distance(args.length, args.alpha, args.dark_rate)
        print(f"Effective depolarizing probability at {args.length} km")
        print(f"  p = {p:.6f}")
    elif args.compute == "t1":
        p = t1_decay_probability(args.dt, args.t1)
        print(f"T1 decay probability (Δt={args.dt}, T1={args.t1})")
        print(f"  p = {p:.6f}")
    elif args.compute == "t2":
        p = t2_dephase_probability(args.dt, args.t2)
        print(f"T2 dephasing probability (Δt={args.dt}, T2={args.t2})")
        print(f"  p = {p:.6f}")
    return True


def _bounded_hops(value: str) -> int:
    """argparse type: bound max-hops to [1, 8] so crafted invocations cannot
    drive the path search into exponential territory."""
    return min(max(int(value), 1), 8)


def _do_topology(args):
    """Phase 3: build a topology and (optionally) route entanglement over it."""
    from .topology import (
        QuantumTopology,
        best_route,
        distribute,
        render_topology,
        rank_routes,
    )

    if args.topology_command == "build":
        if args.shape == "ring":
            n = max(4, args.nodes)
            node_ids = (["A", "B"] +
                        [f"R{i}" for i in range(min(args.repeaters, max(0, n - 2)))] +
                        [chr(ord("C") + i) for i in range(max(0, n - 2 - args.repeaters))])
            node_ids = node_ids[:n]
            topo = QuantumTopology.ring(node_ids, radius_km=args.radius)
        else:
            topo = QuantumTopology.grid(args.rows, args.cols,
                                        spacing_km=args.spacing)
        print(topo.summary())
        print()
        print(render_topology(topo))
        return True

    if args.topology_command == "route":
        if args.shape == "ring":
            n = max(4, args.nodes)
            node_ids = (["A", "B"] +
                        [f"R{i}" for i in range(min(args.repeaters, max(0, n - 2)))] +
                        [chr(ord("C") + i) for i in range(max(0, n - 2 - args.repeaters))])
            node_ids = node_ids[:n]
            topo = QuantumTopology.ring(node_ids, radius_km=args.radius)
        else:
            topo = QuantumTopology.grid(args.rows, args.cols,
                                        spacing_km=args.spacing)
        routes = rank_routes(topo, args.src, args.dst,
                             max_hops=args.max_hops,
                             min_fidelity=args.min_fidelity)
        if not routes:
            print(f"No route from {args.src} to {args.dst} meets "
                  f"min-fidelity {args.min_fidelity}.")
            return False
        best = routes[0]
        print(topo.summary())
        print()
        print(best.describe())
        print()
        print(distribute(topo, best).describe())
        if args.ascii:
            print()
            print(render_topology(topo, route=best))
        return True

    print("usage: quantumnet topology {build,route} ...")
    return False


def _route_fidelity(route, dist):
    """End-to-end fidelity: the scheduled value (swaps + memory decay) when a
    distribution was computed, else the pure swap formula."""
    if dist is not None:
        return float(dist.final_fidelity)
    return float(route.fidelity()) if route is not None else 0.0


#: The seed pinned for the session quantum mix's key label. It is a constant so
#: both peers ask for the same key from the same `(fidelity, seed)` pair; the
#: secret is the quantum channel's contribution, not the seed. A production
#: deployment replaces the label with the QKD appliance's key ID.
QKD_LABEL_SEED = 0x51EE

#: The fidelity a route must reach before BB84 privacy amplification still
#: extracts key material.
#:
#: Deliberately *above* the observed boundary, which sits just past 0.87 for the
#: pinned seed (0.870 yields no key, 0.872 does). Distillation aims at this
#: number rather than the exact boundary so a key is never marginal, and the
#: Rust quantum-mix step uses the same figure to decide whether a session has
#: anything to mix.
KEY_FIDELITY_CUTOFF = 0.88


def _distil_to_key_fidelity(fidelity, seed, max_rounds=6, pairs=256):
    """Raise a route's fidelity far enough for BB84 to still extract a key.

    A route's end-to-end fidelity cannot clear the cutoff on its own: the
    detector dark-count floor caps it at ~0.85 even for a link a few metres
    long, and attenuation takes it down from there. Routing alone therefore
    *never* produces key material, at any distance.

    Entanglement distillation is what closes the gap, and this runs the stack's
    own protocol over a seeded ensemble rather than a fitted curve: `n` noisy
    Bell pairs at the route's fidelity, then BBSSW rounds until the surviving
    pairs are good enough. The ensemble is identical for every pair and the rng
    is seeded, so the result is reproducible for a given `(fidelity, seed)` —
    which is what lets the label identify one key on both peers.

    Returns ``(key_fidelity, rounds, pairs_kept)``. ``rounds == 0`` means the
    route's own fidelity already suffices (it cannot, today — the code is kept
    honest for the case where the physical model improves).
    """
    from .core.qubit import QubitState
    from .protocols.distillation import prepare_noisy_bell_pairs, run_distillation_round

    f = max(0.0, min(1.0, float(fidelity)))
    if f >= KEY_FIDELITY_CUTOFF:
        return f, 0, pairs
    rng = np.random.default_rng(seed)
    live = prepare_noisy_bell_pairs(pairs, f, rng=rng)
    for round_index in range(1, max_rounds + 1):
        live, _successes = run_distillation_round(live, protocol="bbssw", rng=rng)
        if not live:
            # Every pair failed the round: the channel was too noisy to
            # distil. Report the best fidelity reached, which is the honest
            # answer -- the caller sees it is still below the cutoff.
            return f, round_index - 1, 0
        ideal = QubitState.bell_phi_plus()
        f = float(np.mean([ideal.fidelity(p) for p in live]))
        if f >= KEY_FIDELITY_CUTOFF:
            return f, round_index, len(live)
    return f, max_rounds, len(live)


def _qkd_key_for_route(fidelity, seed=QKD_LABEL_SEED):
    """Run a real BB84 key exchange at the route's noise level.

    Maps the route fidelity back to the depolarizing probability that would
    produce it (Werner: F = 1 - 3p/4) and simulates BB84 at that QBER. Returns
    32 bytes (256 bits) of sifted key material, or None when the run cannot
    produce enough sifted bits (too much channel loss / too few bits survive).
    """
    from .protocols import run_bb84

    f = max(0.0, min(1.0, fidelity))
    p = max(0.0, min(1.0, 4.0 * (1.0 - f) / 3.0))
    rng = np.random.default_rng(seed)
    result = run_bb84(4096, noise=p, rng=rng)
    key = result.get("key")
    qber = float(result.get("qber", 1.0))
    # run_bb84 returns the sifted key as a string of '0'/'1' characters.
    # A QBER at/above the 11% security threshold means privacy amplification
    # would extract nothing -- the honest answer is "no key", not garbage.
    if not key or len(key) < 256 or qber >= 0.11:
        return None
    bits = np.array([1 if c == "1" else 0 for c in key[:256]], dtype=np.uint8)
    packed = np.packbits(bits)
    return bytes(packed)


def _emit_ghost_net_json(topo_unused, route, dist, args):
    """Emit exactly one JSON document on stdout; everything else on stderr.

    The Rust l10_qel bridge parses stdout with a strict JSON parser, so this
    stream must never carry diagnostics -- they go to stderr, and even a fatal
    error emits a JSON object (success=false) rather than a bare traceback.
    """
    import json
    import sys

    payload = {
        "success": route is not None,
        "path": list(route.path) if route is not None else [],
        "end_to_end_fidelity": _route_fidelity(route, dist) if route is not None else 0.0,
        "swap_nodes": list(route.path[1:-1]) if route is not None and len(route.path) > 2 else [],
        "qkd_key_hex": None,
        # The fidelity the key is actually derived at, after distillation, and
        # how many rounds it took. This -- not `end_to_end_fidelity` -- is the
        # label the two peers agree a key on, because it is the number that
        # identifies which key material the channel produced.
        "key_fidelity": None,
        "distillation_rounds": 0,
    }
    if route is not None:
        try:
            kf, rounds, _kept = _distil_to_key_fidelity(
                payload["end_to_end_fidelity"], QKD_LABEL_SEED)
            payload["key_fidelity"] = kf
            payload["distillation_rounds"] = rounds
            key = _qkd_key_for_route(kf, QKD_LABEL_SEED)
            payload["qkd_key_hex"] = key.hex() if key else None
            if key is None:
                print(
                    f"ghost-net: route fidelity {payload['end_to_end_fidelity']:.4f} "
                    f"distilled to {kf:.4f} over {rounds} round(s), still below the "
                    f"{KEY_FIDELITY_CUTOFF} key cutoff -- no key material",
                    file=sys.stderr,
                )
        except Exception as e:  # noqa: BLE001 - never emit a traceback on stdout
            print(f"ghost-net: qkd key generation failed: {e}", file=sys.stderr)
    print(json.dumps(payload))


def _do_ghost_net(args):
    """Phase 3 integration: route entanglement over a live Ghost Net export."""
    import sys

    from .topology import (
        describe_ghost_result,
        parse_positions,
        route_ghost,
        plot_matplotlib,
    )

    positions = parse_positions(args.positions)
    try:
        topo, route, dist = route_ghost(
            args.topology, args.src, args.dst,
            positions=positions,
            min_fidelity=args.min_fidelity,
            max_hops=args.max_hops,
        )
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
        if args.json_output:
            import json
            print(json.dumps({"success": False, "path": [], "end_to_end_fidelity": 0.0,
                              "swap_nodes": [], "qkd_key_hex": None}))
        else:
            print(f"ghost-net: {e}")
        return False
    if args.json_output:
        _emit_ghost_net_json(topo, route, dist, args)
        return route is not None
    print(describe_ghost_result(topo, route, dist))
    if route is not None and args.png:
        if not plot_matplotlib(topo, route=route, path=args.png):
            print(f"(matplotlib not installed — skipping PNG {args.png})")
    return route is not None


def _derive_key_document(fidelity, seed):
    """One JSON document for a key derived at an explicit fidelity and seed.

    The Rust daemon's quantum-mix step needs both peers to land on the *same*
    32 bytes without either of them putting the key on the wire. They manage
    that by running this same derivation at the same ``(fidelity, seed)``: the
    simulated channel is reproducible, so both sides compute identical key
    material and only the parameters travel between them. A real deployment
    replaces this call with a fetch from a local QKD appliance (ETSI GS QKD
    014), where the two sides agree because the *quantum channel* did.
    """
    key = _qkd_key_for_route(fidelity, seed)
    return {
        "success": key is not None,
        "path": [],
        "end_to_end_fidelity": float(fidelity),
        "swap_nodes": [],
        "qkd_key_hex": key.hex() if key else None,
        # This side is *handed* the label, so it distils nothing: the fidelity it
        # was given already is the key fidelity. Same field set as `ghost-net`
        # so the Rust bridge parses one document shape, not two.
        "key_fidelity": float(fidelity),
        "distillation_rounds": 0,
    }


def _do_qkd_derive(args):
    """Derive 32 bytes of key material at an explicit fidelity and seed."""
    doc = _derive_key_document(args.fidelity, args.seed)
    if args.json_output:
        import json
        print(json.dumps(doc))
        return doc["success"]
    if doc["qkd_key_hex"] is None:
        print(
            f"qkd-derive: no key at fidelity {args.fidelity} "
            "(QBER at or above the 11% security cutoff)"
        )
        return False
    print(f"qkd-derive: fidelity={args.fidelity} seed={args.seed}")
    print(f"  key: {doc['qkd_key_hex']}")
    return True


def main():
    parser = argparse.ArgumentParser(prog="quantumnet", description="Quantum network simulation toolkit")
    sub = parser.add_subparsers(dest="command")

    bb84_p = sub.add_parser("bb84", help="Run BB84 QKD simulation")
    bb84_p.add_argument("--bits", type=int, default=256)
    bb84_p.add_argument("--noise", type=float, default=0.01)
    bb84_p.add_argument("--seed", type=int, default=None)

    e91_p = sub.add_parser("e91", help="Run E91 QKD simulation")
    e91_p.add_argument("--pairs", type=int, default=256)
    e91_p.add_argument("--noise", type=float, default=0.01)
    e91_p.add_argument("--seed", type=int, default=None)

    sub.add_parser("teleport", help="Run quantum teleportation")

    sub.add_parser("superdense", help="Run superdense coding")

    swap_p = sub.add_parser("swap", help="Run entanglement swapping")
    swap_p.add_argument("--noise", type=float, default=0.0)
    swap_p.add_argument("--seed", type=int, default=None)

    shor_p = sub.add_parser("shor", help="Shor 9-qubit error correction demo")
    shor_p.add_argument("--state", choices=["zero", "one", "plus"], default="zero")
    shor_p.add_argument("--error", choices=["none", "X", "Z"], default="none")
    shor_p.add_argument("--qubit", type=int, default=0)
    shor_p.add_argument("--seed", type=int, default=None)

    steane_p = sub.add_parser("steane", help="Steane 7-qubit error correction demo")
    steane_p.add_argument("--state", choices=["zero", "one", "plus"], default="zero")
    steane_p.add_argument("--error", choices=["none", "X", "Z"], default="none")
    steane_p.add_argument("--qubit", type=int, default=0)
    steane_p.add_argument("--seed", type=int, default=None)

    distill_p = sub.add_parser("distill", help="Entanglement distillation")
    distill_p.add_argument("--protocol", choices=["bbssw", "deutsch"], default="bbssw")
    distill_p.add_argument("--fidelity", type=float, default=0.8)
    distill_p.add_argument("--seed", type=int, default=None)

    mem_p = sub.add_parser("memory", help="Quantum memory buffer demo")
    mem_p.add_argument("--state", choices=["zero", "one", "plus"], default="one")
    mem_p.add_argument("--t1", type=float, default=10.0)
    mem_p.add_argument("--t2", type=float, default=10.0)
    mem_p.add_argument("--t", type=float, default=5.0)
    mem_p.add_argument("--threshold", type=float, default=0.5)

    sub.add_parser("all", help="Run all protocol demos")

    # --- stabilizer ---
    stab_p = sub.add_parser("stabilizer", help="Stabilizer state simulator (Gottesman-Knill)")
    stab_p.add_argument("--state", choices=["bell", "ghz", "random"], default="bell")
    stab_p.add_argument("--nqubits", type=int, default=4)
    stab_p.add_argument("--seed", type=int, default=None)

    # --- physical ---
    phys_p = sub.add_parser("physical", help="Physical-layer impairment calculator")
    phys_p.add_argument("--compute", choices=["transmissivity", "dark_count",
                                              "depolarizing", "t1", "t2"],
                        default="transmissivity")
    phys_p.add_argument("--length", type=float, default=10.0, help="Fibre length (km)")
    phys_p.add_argument("--alpha", type=float, default=0.2, help="Fibre attenuation (dB/km)")
    phys_p.add_argument("--rate", type=float, default=10.0, help="Dark count rate (Hz)")
    phys_p.add_argument("--window", type=float, default=1e-8, help="Detection window (s)")
    phys_p.add_argument("--dark-rate", type=float, default=10.0, help="Dark count rate (Hz)")
    phys_p.add_argument("--dt", type=float, default=1.0, help="Time delta")
    phys_p.add_argument("--t1", type=float, default=100.0, help="T1 coherence time")
    phys_p.add_argument("--t2", type=float, default=50.0, help="T2 coherence time")

    # --- ghost-net / topology (Phase 3) ---
    topo_p = sub.add_parser("topology", help="Quantum topology build / route / visualize")
    topo_sub = topo_p.add_subparsers(dest="topology_command")
    tb = topo_sub.add_parser("build", help="Build a deterministic ring or grid topology")
    tb.add_argument("--shape", choices=["ring", "grid"], default="ring")
    tb.add_argument("--nodes", type=int, default=8)
    tb.add_argument("--repeaters", type=int, default=3,
                    help="number of nodes named R0..Rk-1 (repeaters)")
    tb.add_argument("--radius", type=float, default=20.0, help="ring radius (km)")
    tb.add_argument("--rows", type=int, default=3)
    tb.add_argument("--cols", type=int, default=4)
    tb.add_argument("--spacing", type=float, default=5.0, help="grid spacing (km)")
    tr = topo_sub.add_parser("route", help="Best fidelity route + swap schedule")
    tr.add_argument("--shape", choices=["ring", "grid"], default="ring")
    tr.add_argument("--nodes", type=int, default=8)
    tr.add_argument("--radius", type=float, default=20.0)
    tr.add_argument("--rows", type=int, default=3)
    tr.add_argument("--cols", type=int, default=4)
    tr.add_argument("--spacing", type=float, default=5.0)
    tr.add_argument("--from", dest="src", default="A")
    tr.add_argument("--to", dest="dst", default="D")
    tr.add_argument("--min-fidelity", type=float, default=0.0)
    tr.add_argument("--max-hops", type=_bounded_hops, default=6)
    tr.add_argument("--ascii", action="store_true", default=False,
                    help="also print the ASCII topology map")

    gn = sub.add_parser("ghost-net", help="Route quantum entanglement over a live "
                                          "Global Ghost Net topology export")
    gn.add_argument("--topology", required=True,
                    help="JSON export from the vantablack daemon (EXPORTTOPOLOGY)")
    gn.add_argument("--from", dest="src", required=True, help="source fingerprint")
    gn.add_argument("--to", dest="dst", required=True, help="destination fingerprint")
    gn.add_argument("--positions", default=None,
                    help="optional 'fp=x,y fp2=x,y' coordinates (km)")
    gn.add_argument("--min-fidelity", type=float, default=0.0)
    gn.add_argument("--max-hops", type=_bounded_hops, default=6)
    gn.add_argument("--png", default=None, help="write a matplotlib PNG here if available")
    gn.add_argument("--json-output", action="store_true", default=False,
                    help="machine-readable mode: exactly one JSON document on "
                         "stdout, all diagnostics on stderr (for the Rust bridge)")

    # --- qkd-derive ---
    qd = sub.add_parser("qkd-derive", help="Derive QKD key material at an explicit "
                                            "fidelity and seed (no routing)")
    qd.add_argument("--fidelity", type=float, required=True,
                    help="end-to-end fidelity the route achieved (0..1)")
    qd.add_argument("--seed", type=int, default=QKD_LABEL_SEED,
                    help="deterministic RNG seed; both peers must pass the same value")
    qd.add_argument("--json-output", action="store_true", default=False,
                    help="machine-readable mode: exactly one JSON document on "
                         "stdout, all diagnostics on stderr (for the Rust bridge)")

    # --- ghost-net ---
    args = parser.parse_args()

    ok = True
    if args.command == "bb84":
        rng = np.random.default_rng(args.seed)
        result = run_bb84(args.bits, noise=args.noise, rng=rng)
        print(f"BB84 QKD -- {args.bits} raw bits, noise={args.noise}")
        print(f"  Sifted key length: {len(result['key'])} bits")
        print(f"  QBER: {result['qber']:.4f}")
        print(f"  Key (first 16 bits): {result['key'][:16]}")

    elif args.command == "e91":
        rng = np.random.default_rng(args.seed)
        result = run_e91(args.pairs, noise=args.noise, rng=rng)
        print(f"E91 QKD -- {args.pairs} Bell pairs, noise={args.noise}")
        print(f"  Sifted key length: {len(result['key'])} bits")
        print(f"  QBER: {result['qber']:.4f}")
        print(f"  S value: {result['s_value']:.4f} (CHSH)")

    elif args.command == "teleport":
        rng = np.random.default_rng()
        result = run_teleportation(rng=rng)
        print(f"Quantum Teleportation")
        print(f"  Input fidelity:   {result['input_fidelity']:.6f}")
        print(f"  Teleported fid:   {result['teleported_fidelity']:.6f}")
        print(f"  Success:          {result['success']}")

    elif args.command == "superdense":
        rng = np.random.default_rng()
        result = run_superdense(rng=rng)
        print(f"Superdense Coding")
        print(f"  Encoded bits: {result['encoded_bits']}")
        print(f"  Decoded bits: {result['decoded_bits']}")
        print(f"  Success:      {result['success']}")

    elif args.command == "swap":
        rng = np.random.default_rng(args.seed)
        result = run_swapping(noise=args.noise, rng=rng)
        print(f"Entanglement Swapping -- noise={args.noise}")
        print(f"  Bell outcome: {result['bell_outcome']}")
        print(f"  Swapped fid:  {result['swapped_fidelity']:.6f}")
        print(f"  Success:      {result['success']}")

    elif args.command == "shor":
        ok = _do_shor(args)

    elif args.command == "steane":
        ok = _do_steane(args)

    elif args.command == "distill":
        ok = _do_distill(args)

    elif args.command == "memory":
        ok = _do_memory(args)

    elif args.command == "all":
        rng = np.random.default_rng(42)
        print("=== Quantum Network Protocol Demos ===\n")

        r = run_bb84(128, noise=0.01, rng=rng)
        print(f"BB84:        {len(r['key'])}-bit key, QBER={r['qber']:.4f}")

        r = run_e91(128, noise=0.01, rng=rng)
        print(f"E91:         {len(r['key'])}-bit key, QBER={r['qber']:.4f}, S={r['s_value']:.4f}")

        r = run_teleportation(rng=rng)
        print(f"Teleport:    fidelity={r['teleported_fidelity']:.6f}")

        r = run_superdense(rng=rng)
        print(f"Superdense:  {r['encoded_bits']} -> {r['decoded_bits']}")

        r = run_swapping(noise=0.0, rng=rng)
        print(f"Swap:        swapped fidelity={r['swapped_fidelity']:.6f}")

        enc = shor_encode(QubitState.zero())
        noisy = apply(X, enc, targets=[3])
        corrected = shor_correct(noisy)
        dec = shor_decode(corrected)
        print(f"Shor:        X error corrected, fid={QubitState.zero().fidelity(dec):.6f}")

        enc = steane_encode(QubitState.plus())
        noisy = apply(Z, enc, targets=[1])
        corrected = steane_correct(noisy)
        dec = steane_decode(corrected)
        print(f"Steane:      Z error corrected, fid={QubitState.plus().fidelity(dec):.6f}")

        pairs = prepare_noisy_bell_pairs(2, fidelity=0.8, rng=rng)
        r = bbssw_distill(pairs[0], pairs[1], rng=rng)
        print(f"Distill:     success={r['success']}, fid={r['distilled_fidelity']:.4f}")

        fids = memory_fidelity_over_time(QubitState.one(), [0, 5, 10], t1=10.0, t2=10.0)
        print(f"Memory:      fids={[f'{f:.4f}' for f in fids]}")

    elif args.command == "stabilizer":
        _do_stabilizer(args)

    elif args.command == "physical":
        _do_physical(args)

    elif args.command == "topology":
        _do_topology(args)

    elif args.command == "ghost-net":
        ok = _do_ghost_net(args)

    elif args.command == "qkd-derive":
        ok = _do_qkd_derive(args)

    else:
        parser.print_help()

    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
