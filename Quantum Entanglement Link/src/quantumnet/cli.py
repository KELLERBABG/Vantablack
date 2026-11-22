"""Command-line interface and CLI command dispatcher for Quantum Entanglement Link (QEL)."""

import argparse
import json
import sys
from pathlib import Path

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
from .topology.importers import parse as load_topology
from .topology import (
    QuantumTopology,
    best_route,
    build_topology,
    distribute,
    render_topology,
    rank_routes,
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
        labels = [f"|{i:0{n}b}>" for i in range(1 << n) if abs(s.to_statevector()[i]) > 0.01]
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
        print(f"Fibre transmissivity at {args.length} km (alpha={args.alpha} dB/km)")
        print(f"  eta = {eta:.6e}")
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
        print(f"T1 decay probability (dt={args.dt}, T1={args.t1})")
        print(f"  p = {p:.6f}")
    elif args.compute == "t2":
        p = t2_dephase_probability(args.dt, args.t2)
        print(f"T2 dephasing probability (dt={args.dt}, T2={args.t2})")
        print(f"  p = {p:.6f}")
    return True


def _bounded_hops(value: str) -> int:
    """argparse type: bound max-hops to [1, 8] so crafted invocations cannot
    drive the path search into exponential territory."""
    return min(max(int(value), 1), 8)


def _hex_int(value: str) -> int:
    """argparse type: accept decimal *or* 0x-prefixed hex seeds.

    The pinned QKD label is documented as ``0x51EE`` and the Rust bridge
    passes it in that form, so plain ``type=int`` (decimal only) would reject
    the canonical spelling."""
    try:
        return int(value, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected an integer (decimal or 0x-prefixed hex), got {value!r}"
        ) from None


def _do_topology(args):
    """Build a topology and (optionally) route entanglement over it."""
    if args.topology_command == "build":
        # All four builders go through the registry, so a shape added to
        # `topology/shapes.py` is reachable here without touching the CLI.
        if args.shape == "ring":
            n = max(4, args.nodes)
            node_ids = (["A", "B"] +
                        [f"R{i}" for i in range(min(args.repeaters, max(0, n - 2)))] +
                        [chr(ord("C") + i) for i in range(max(0, n - 2 - args.repeaters))])
            topo = build_topology("ring", nodes=node_ids[:n], radius_km=args.radius)
        elif args.shape == "grid":
            topo = build_topology("grid", rows=args.rows, cols=args.cols,
                                  spacing_km=args.spacing)
        elif args.shape == "fattree":
            topo = build_topology("fattree", k=args.k, link_km=args.link_km)
        else:
            topo = build_topology("bcube", n=args.bcube_n, k=args.k,
                                  link_km=args.link_km)

        if args.out:
            from .topology.qel_json_export import write_qel_json

            written = write_qel_json(topo, args.out)
            print(f"wrote {written} "
                  f"({len(topo.nodes)} nodes, {len(topo.links)} links, qel-json)")
            return True

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
            topo = QuantumTopology.grid(args.rows, args.cols, spacing_km=args.spacing)
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


#: The seed pinned for the session quantum mix's key label, so both peers ask for the
#: same key from the same `(fidelity, seed)` pair; production uses the QKD key ID.
QKD_LABEL_SEED = 0x51EE

#: The fidelity a route must reach for BB84 privacy amplification to still extract key
#: material. Deliberately above the observed 0.87 boundary for the pinned seed (0.870
#: yields no key, 0.872 does), so a key is never marginal; the Rust quantum-mix agrees.
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
    is seeded, so the result is reproducible for a given `(fidelity, seed)` --
    which is what lets the label identify one key on both peers.

    Returns ``(key_fidelity, rounds, pairs_kept)``. ``rounds == 0`` means the
    route's own fidelity already suffices (it cannot, today -- the code is kept
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
        live, _successes, _yield = run_distillation_round(live, protocol="bbssw", rng=rng)
        if not live:
            # Every pair failed the round: the channel was too noisy to distil. Report
            # the best fidelity reached, so the caller sees it is below the cutoff.
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
    # run_bb84 returns the sifted key as '0'/'1' characters. A QBER at or above the 11%
    # security threshold means privacy amplification would extract nothing, so no key.
    if not key or len(key) < 256 or qber >= 0.11:
        return None
    bits = np.array([1 if c == "1" else 0 for c in key[:256]], dtype=np.uint8)
    packed = np.packbits(bits)
    return bytes(packed)


def _emit_import_json(route, dist):
    """Emit exactly one JSON document on stdout; everything else on stderr.

    The Rust bridge parses stdout with a strict JSON parser, so this stream
    must never carry diagnostics -- they go to stderr, and even a fatal error
    emits a JSON object (success=false) rather than a bare traceback.
    """
    payload = {
        "success": route is not None,
        "path": list(route.path) if route is not None else [],
        "end_to_end_fidelity": _route_fidelity(route, dist) if route is not None else 0.0,
        "swap_nodes": list(route.path[1:-1]) if route is not None and len(route.path) > 2 else [],
        "qkd_key_hex": None,
        # The fidelity the key is derived at after distillation, and how many rounds it
        # took. This, not `end_to_end_fidelity`, is the label the peers agree a key on.
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
                    f"import: route fidelity {payload['end_to_end_fidelity']:.4f} "
                    f"distilled to {kf:.4f} over {rounds} round(s), still below the "
                    f"{KEY_FIDELITY_CUTOFF} key cutoff -- no key material",
                    file=sys.stderr,
                )
        except Exception as e:  # noqa: BLE001 - never emit a traceback on stdout
            print(f"import: qkd key generation failed: {e}", file=sys.stderr)
    print(json.dumps(payload))


def _do_import(args):
    """Phase 3 integration: route quantum entanglement over a parsed topology export."""
    from .topology.importers import importer_for, parse as load_topology
    from .topology import describe_ghost_result, parse_positions, route_ghost, plot_matplotlib

    positions = parse_positions(args.positions)
    # The CLI surface is the legacy file path: resolve the schema, parse the file
    # through the importer, and hand the canonical document to route_ghost.
    try:
        schema_id = getattr(args, "schema_id", None)
        importer = importer_for(args.topology, schema_id=schema_id)
        doc = importer(args.topology).parse()
        try:
            topo, route, dist = route_ghost(
                doc, args.src, args.dst,
                min_fidelity=args.min_fidelity,
                max_hops=args.max_hops,
            )
        finally:
            args.topology = doc
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError) as e:
        if args.json_output:
            print(json.dumps({"success": False, "path": [], "end_to_end_fidelity": 0.0,
                              "swap_nodes": [], "qkd_key_hex": None}))
        else:
            print(f"import: {e}")
        return False
    if args.json_output:
        _emit_import_json(route, dist)
        return route is not None
    print(describe_ghost_result(topo, route, dist))
    if route is not None and args.png:
        if not plot_matplotlib(topo, route=route, path=args.png):
            print(f"(matplotlib not installed -- skipping PNG {args.png})")
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
        # This side is handed the label, so it distils nothing: the fidelity it was
        # given already is the key fidelity. Same field set as `import`, one shape.
        "key_fidelity": float(fidelity),
        "distillation_rounds": 0,
    }


def _do_qkd_derive(args):
    """Derive 32 bytes of key material at an explicit fidelity and seed."""
    doc = _derive_key_document(args.fidelity, args.seed)
    if args.json_output:
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


def _do_validate(args) -> bool:
    """Recompute published figures and report the differences.

    This is the credibility surface: a comparison against numbers other people
    measured and published, including the comparisons that do not apply, which
    are listed rather than quietly dropped.
    """
    from .validation import PUBLISHED_DATASETS, validate_boaron_loss_budget, validate_all

    if args.json_output:
        json.dump({
            "comparisons": validate_all(),
            "not_scored": [
                {"name": d.name, "kind": d.kind, "citation": d.citation,
                 "url": d.url, "note": d.note}
                for d in PUBLISHED_DATASETS if d.target_km is None
            ],
            "loss_budget": validate_boaron_loss_budget(),
        }, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return True

    from .validation import validation_report
    print(validation_report())
    rows = validate_all()
    failed = [r for r in rows if r["passes"] is False]
    return not failed


def _do_link(args) -> bool:
    """Physical-layer budget for one fibre span.

    Reports both entanglement-generation models side by side, because they
    describe different hardware and the difference is exactly the 1/2 a
    double-heralded scheme carries.  Quoting one while the simulator uses the
    other is the kind of inconsistency this command exists to make visible.
    """
    from .core.photonics import Detector, PhotonicLink, BarrettKok
    from .topology.graph import QuantumLink

    link = QuantumLink(a="A", b="B", length_km=args.distance,
                       alpha_db_km=args.alpha,
                       detector_eff=args.detector_efficiency,
                       dark_count_hz=args.dark_count,
                       pulse_rate_hz=args.pulse_rate)

    arm = PhotonicLink(
        length_km=args.distance, alpha_db_km=args.alpha,
        detector=Detector(efficiency=args.detector_efficiency,
                          dark_count_rate_hz=args.dark_count,
                          dead_time_s=args.dead_time),
    )
    bk = BarrettKok(arm, arm, coincidence_window_s=args.window,
                    mode_matching=args.mode_matching)

    payload = {
        "distance_km": args.distance,
        "loss_db": arm.loss_db,
        "transmissivity": arm.transmissivity,
        "detector_efficiency": args.detector_efficiency,
        "dark_count_hz": args.dark_count,
        "coincidence_window_s": args.window,
        "single_photon_rate_hz": link.generation_rate(),
        "barrett_kok_rate_hz": link.barrett_kok_rate(
            coincidences_window_s=args.window),
        "barrett_kok_success_probability": bk.success_probability(),
        "barrett_kok_raw_fidelity": bk.raw_fidelity(),
        "per_photon_arrival_probability": arm.photon_arrival_probability(),
    }

    if args.json_output:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return True

    print(f"Physical-layer budget -- {args.distance:g} km span")
    print(f"  fibre loss:            {arm.loss_db:.2f} dB "
          f"(transmissivity {arm.transmissivity:.4e})")
    print(f"  detector:              eta={args.detector_efficiency:g}, "
          f"dark={args.dark_count:g}/s, dead={args.dead_time:g}s")
    print(f"  coincidence window:    {args.window:g}s")
    print(f"  photon arrival (arm):  {arm.photon_arrival_probability():.6e}")
    print()
    print(f"  Barrett-Kok (double-heralded, ideal p <= 1/2):")
    print(f"    success probability: {bk.success_probability():.6e}")
    print(f"    raw fidelity:        {bk.raw_fidelity():.4f}  "
          f"(loss costs rate, not fidelity)")
    print(f"    generation rate:     {link.barrett_kok_rate(coincidences_window_s=args.window):.6e} /s")
    print()
    print(f"  single-photon scheme (legacy heuristic, no 1/2 factor):")
    print(f"    generation rate:     {link.generation_rate():.6e} /s")
    print()
    print("  These differ by a factor of ~2 by construction; they model "
          "different hardware.")
    return True


def _do_contend(args) -> bool:
    """Run competing demands against a finite memory pool on one timeline.

    This is the resource-contention surface: demands are decided at their start
    times against the capacity free at that moment, so a pool too small for the
    overlapping demand set produces refusals rather than an optimistic answer.
    """
    from .topology.graph import QuantumTopology, QuantumNode
    from .topology.resources import (
        NodeEntanglementManager, Reservation, ResourceManager,
    )
    from .topology.events import simulate_demands

    if args.nodes < 2:
        print("contend: need at least 2 nodes", file=sys.stderr)
        return False
    if args.memory < 1:
        print("contend: --memory must be at least 1", file=sys.stderr)
        return False

    topo = QuantumTopology()
    for i in range(args.nodes):
        topo.add_node(QuantumNode(node_id=f"N{i}", x_km=i * args.spacing,
                                  y_km=0.0))
    for i in range(args.nodes - 1):
        topo.connect(f"N{i}", f"N{i + 1}")
    managers = {f"N{i}": ResourceManager(f"N{i}", size=args.memory,
                                         t1_s=args.t1, t2_s=args.t2)
                for i in range(args.nodes)}
    manager = NodeEntanglementManager(managers)

    # Demand set: pairs (0,1), (1,2), ... starting together, each asking for a share of
    # the pool. Deliberately overlapping so contention is exercised.
    demands = []
    for k in range(args.demands):
        a = k % (args.nodes - 1)
        demands.append(Reservation(
            initiator=f"N{a}", responder=f"N{a + 1}",
            start_time=0.0, end_time=args.window,
            memory_size=max(1, args.memory // max(1, args.demands)),
            target_fidelity=0.5,
            priority=0, identity=k + 1, arrival_seq=k + 1,
        ))

    result = simulate_demands(topo, demands, manager,
                              t_swap_s=args.t_swap)

    if args.json_output:
        json.dump({
            "nodes": args.nodes,
            "memory_per_node": args.memory,
            "demands": len(demands),
            "granted": len(result.granted),
            "refused": len(result.refused),
            "t_end_s": result.t_end_s,
            "outcomes": [
                {
                    "identity": o.reservation.identity,
                    "initiator": o.reservation.initiator,
                    "responder": o.reservation.responder,
                    "granted": o.granted,
                    "reason": o.reservation.reason,
                    "path": list(o.route.path) if o.route else [],
                    "delivered_fidelity": o.delivered_fidelity,
                    "rejected_at_s": o.rejected_at,
                }
                for o in result.outcomes
            ],
        }, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return True

    print(f"Memory contention -- {args.nodes} nodes, "
          f"{args.memory} memories each, {len(demands)} competing demands")
    print(f"  {len(result.granted)} granted, {len(result.refused)} refused, "
          f"ended t={result.t_end_s:g}s")
    for outcome in result.outcomes:
        print("  " + outcome.describe())
    if result.refused:
        print("\n  Contention changed the answer: a pool of "
              f"{args.memory} per node cannot serve all {len(demands)} "
              f"overlapping demands.")
    return True


def _do_qkd(args) -> bool:
    """Decoy-state BB84 key rate at one distance, from the analytic analysis."""
    from .protocols.bb84 import DECOY_PRESETS, run_bb84_decoy_preset

    if args.preset not in DECOY_PRESETS:
        print(f"unknown preset {args.preset!r}; available: "
              f"{', '.join(sorted(DECOY_PRESETS))}", file=sys.stderr)
        return False

    overrides = {}
    if args.mu is not None:
        overrides["mu"] = args.mu
    if args.nu is not None:
        overrides["nu"] = args.nu
    if args.detector_efficiency is not None:
        overrides["detector_efficiency"] = args.detector_efficiency
    if args.dark_count is not None:
        overrides["dark_count_hz"] = args.dark_count
    if args.pulses is not None:
        overrides["n_pulses"] = args.pulses

    r = run_bb84_decoy_preset(args.preset, args.distance, **overrides)

    if args.json_output:
        json.dump(r, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return True

    print(f"Decoy-state BB84 -- {args.preset} at {r['distance_km']:.1f} km")
    print(f"  preset:            {r['preset_description']}")
    print(f"  fibre loss:        {r['loss_db']:.2f} dB "
          f"(channel transmissivity {r['channel_transmissivity']:.3e})")
    print(f"  signal/decoy mu/nu:{r['mu']:.3f} / {r['nu']:.3f}"
          f"  ({r['num_decoy_intensities']} intensities)")
    print(f"  gain Q_mu:         {r['q_mu']:.6e}")
    print(f"  QBER E_mu:         {r['e_mu']:.6f}")
    print(f"  bound Y1 lower:    {r['y1_lower']:.6e}")
    print(f"  bound e1 upper:    {r['e1_upper']:.6f}")
    print(f"  single-photon term:{r['single_photon_term']:+.6e} bits/pulse")
    print(f"  error-correction:  {r['error_correction_term']:+.6e} bits/pulse")
    if not r["asymptotic"]:
        print(f"  finite-key penalty:{r['finite_key_penalty_per_pulse']:.6e} bits/pulse"
              f"  (n={r['n_pulses']:.3g}, eps={r['epsilon']:.0e})")
    if r["secure"]:
        print(f"  SECURE KEY RATE:   {r['key_rate_per_pulse']:.6e} bits/pulse "
              f"= {r['key_rate_hz']:.6e} bits/s")
    else:
        # A rate at or below zero is not a key rate.  Say so.
        print(f"  SECURE KEY RATE:   none -- no key is extractable at this distance")
    return True


def _do_bench(args) -> bool:
    """Sweep the decoy-state key rate against distance (rate-vs-distance)."""
    from .protocols.bb84 import (
        DECOY_PRESETS, decoy_key_rate_curve, max_secure_distance_km,
    )

    presets = args.preset if isinstance(args.preset, list) else [args.preset]
    for p in presets:
        if p not in DECOY_PRESETS:
            print(f"unknown preset {p!r}; available: "
                  f"{', '.join(sorted(DECOY_PRESETS))}", file=sys.stderr)
            return False

    step = max(1e-6, float(args.step))
    distances = np.arange(float(args.start), float(args.stop) + step / 2, step)

    documents = []
    for p in presets:
        curve = decoy_key_rate_curve(distances, preset=p, n_pulses=args.pulses)
        documents.append({
            "preset": p,
            "description": DECOY_PRESETS[p]["description"],
            "max_secure_distance_km": max_secure_distance_km(
                p, hi=float(args.stop) + step, dark_count_hz=(
                    DECOY_PRESETS[p]["dark_count_hz"])),
            "points": [
                {
                    "distance_km": c["distance_km"],
                    "key_rate_per_pulse": c["key_rate_per_pulse"],
                    "key_rate_hz": c["key_rate_hz"],
                    "q_mu": c["q_mu"],
                    "e_mu": c["e_mu"],
                    "y1_lower": c["y1_lower"],
                    "e1_upper": c["e1_upper"],
                    "secure": c["secure"],
                }
                for c in curve
            ],
        })

    if args.json_output:
        json.dump(documents if len(documents) > 1 else documents[0],
                  sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return True

    for doc in documents:
        print(f"=== decoy-state BB84 key rate vs distance ===")
        print(f"  preset {doc['preset']}: {doc['description']}")
        print(f"  max secure distance: {doc['max_secure_distance_km']:.1f} km"
              f"  ({'asymptotic' if args.pulses is None else f'n={args.pulses:.3g} pulses'})")
        pts = doc["points"]
        # Subsample the table so a fine sweep stays readable on a terminal.
        stride = max(1, len(pts) // 14)
        print(f"  {'km':>7} {'Y1^L':>10} {'e1^U':>7} {'E_mu':>8} {'bits/pulse':>12} {'bits/s':>12}")
        for pt in pts[::stride]:
            rate = f"{pt['key_rate_per_pulse']:.4e}" if pt["secure"] else "none"
            print(f"  {pt['distance_km']:>7.1f} {pt['y1_lower']:>10.3e} "
                  f"{pt['e1_upper']:>7.4f} {pt['e_mu']:>8.5f} {rate:>12} "
                  f"{pt['key_rate_hz']:>12.4e}")
        print()
    return True


#: Subparser collection the next ``_layout_help`` call registers into; ``main`` points
#: it at the top-level or a nested parser, so every command stays a flat one-liner.
_active_sub = None

def _layout_help(subcommand: str, description: str, *pairs):
    """Register ``subcommand`` on the active subparser.

    Flags alternate with their ``add_argument`` keyword dicts::

        _layout_help("bb84", "Run BB84 QKD simulation",
                     "--bits", {"type": int, "default": 256},
                     "--seed", {"type": int, "default": None})
    """
    if _active_sub is None:
        raise RuntimeError("_layout_help called outside main()")
    parser = _active_sub.add_parser(subcommand, help=description)
    flag_iter = iter(pairs)
    for flag, value in zip(flag_iter, flag_iter):
        parser.add_argument(flag, **value)
    return parser


def main():
    global _active_sub
    parser = argparse.ArgumentParser(prog="quantumnet", description="Quantum network simulation toolkit")
    sub = parser.add_subparsers(dest="command")
    _active_sub = sub

    _layout_help("bb84", "Run BB84 QKD simulation",
                 "--bits", {"type": int, "default": 256},
                 "--noise", {"type": float, "default": 0.01},
                 "--seed", {"type": int, "default": None})

    _layout_help("e91", "Run E91 QKD simulation",
                 "--pairs", {"type": int, "default": 256},
                 "--noise", {"type": float, "default": 0.01},
                 "--seed", {"type": int, "default": None})

    sub.add_parser("teleport", help="Run quantum teleportation")
    sub.add_parser("superdense", help="Run superdense coding")

    _layout_help("swap", "Run entanglement swapping",
                 "--noise", {"type": float, "default": 0.0},
                 "--seed", {"type": int, "default": None})

    _layout_help("shor", "Shor 9-qubit error correction demo",
                 "--state", {"type": str, "choices": ["zero", "one", "plus"], "default": "zero"},
                 "--error", {"type": str, "choices": ["none", "X", "Z"], "default": "none"},
                 "--qubit", {"type": int, "default": 0},
                 "--seed", {"type": int, "default": None})

    _layout_help("steane", "Steane 7-qubit error correction demo",
                 "--state", {"type": str, "choices": ["zero", "one", "plus"], "default": "zero"},
                 "--error", {"type": str, "choices": ["none", "X", "Z"], "default": "none"},
                 "--qubit", {"type": int, "default": 0},
                 "--seed", {"type": int, "default": None})

    _layout_help("distill", "Entanglement distillation",
                 "--protocol", {"type": str, "choices": ["bbssw", "deutsch"], "default": "bbssw"},
                 "--fidelity", {"type": float, "default": 0.8},
                 "--seed", {"type": int, "default": None})

    _layout_help("memory", "Quantum memory buffer demo",
                 "--state", {"type": str, "choices": ["zero", "one", "plus"], "default": "one"},
                 "--t1", {"type": float, "default": 10.0},
                 "--t2", {"type": float, "default": 10.0},
                 "--t", {"type": float, "default": 5.0},
                 "--threshold", {"type": float, "default": 0.5})

    sub.add_parser("all", help="Run all protocol demos")

    # --- stabilizer ---
    _layout_help("stabilizer", "Stabilizer state simulator (Gottesman-Knill)",
                 "--state", {"type": str, "choices": ["bell", "ghz", "random"], "default": "bell"},
                 "--nqubits", {"type": int, "default": 4},
                 "--seed", {"type": int, "default": None})

    # --- physical ---
    _layout_help("physical", "Physical-layer impairment calculator",
                 "--compute", {"type": str, "choices": ["transmissivity", "dark_count",
                                                       "depolarizing", "t1", "t2"],
                               "default": "transmissivity"},
                 "--length", {"type": float, "default": 10.0, "help": "Fibre length (km)"},
                 "--alpha", {"type": float, "default": 0.2, "help": "Fibre attenuation (dB/km)"},
                 "--rate", {"type": float, "default": 10.0, "help": "Dark count rate (Hz)"},
                 "--window", {"type": float, "default": 1e-8, "help": "Detection window (s)"},
                 "--dark-rate", {"type": float, "default": 10.0, "help": "Dark count rate (Hz)"},
                 "--dt", {"type": float, "default": 1.0, "help": "Time delta"},
                 "--t1", {"type": float, "default": 100.0, "help": "T1 coherence time"},
                 "--t2", {"type": float, "default": 50.0, "help": "T2 coherence time"})

    # --- topology (build / route) ---
    topo_p = sub.add_parser("topology", help="Quantum topology build / route / visualize")
    topo_sub = topo_p.add_subparsers(dest="topology_command")
    _active_sub = topo_sub  # build/route belong to `topology`, not the root

    _layout_help("build", "Build a deterministic topology, optionally writing it out",
                 "--shape", {"type": str,
                             "choices": ["ring", "grid", "fattree", "bcube"],
                             "default": "ring",
                             "help": "ring/grid take --nodes/--rows; "
                                     "fattree takes --k; bcube takes --bcube-n/--k"},
                 "--nodes", {"type": int, "default": 8},
                 "--repeaters", {"type": int, "default": 3,
                                 "help": "number of nodes named R0..Rk-1 (repeaters)"},
                 "--radius", {"type": float, "default": 20.0, "help": "ring radius (km)"},
                 "--rows", {"type": int, "default": 3},
                 "--cols", {"type": int, "default": 4},
                 "--spacing", {"type": float, "default": 5.0, "help": "grid spacing (km)"},
                 "--k", {"type": int, "default": 2, "help": "fattree radix / bcube radix"},
                 "--bcube-n", {"dest": "bcube_n", "type": int, "default": 2,
                               "help": "bcube ports per level"},
                 "--link-km", {"dest": "link_km", "type": float, "default": 1.0},
                 "--out", {"type": str, "default": None,
                           "help": "write the topology to this file in QEL JSON; "
                                   "`import`/`route`/`bench` can consume it"})

    _layout_help("route", "Best fidelity route + swap schedule",
                 "--shape", {"type": str, "choices": ["ring", "grid"], "default": "ring"},
                 "--nodes", {"type": int, "default": 8},
                 "--radius", {"type": float, "default": 20.0},
                 "--rows", {"type": int, "default": 3},
                 "--cols", {"type": int, "default": 4},
                 "--spacing", {"type": float, "default": 5.0},
                 "--from", {"dest": "src", "default": "A"},
                 "--to", {"dest": "dst", "default": "D"},
                 "--min-fidelity", {"type": float, "default": 0.0},
                 "--max-hops", {"type": _bounded_hops, "default": 6},
                 "--ascii", {"action": "store_true", "default": False,
                             "help": "also print the ASCII topology map"})
    _active_sub = sub  # back to the root for import / qkd-derive

    # --- import (the sole topology import surface; ``ghost-net`` alias kept
    #     for the existing Rust daemon contract; hidden so help stays clean) ---
    import_p = sub.add_parser("import", aliases=["ghost-net"],
                              help="Route quantum entanglement over a parsed topology export")
    import_p.add_argument("--topology", required=True,
                          help="topology export (QEL json, ghostnet, dot)")
    import_p.add_argument("--from", dest="src", required=True, help="source fingerprint")
    import_p.add_argument("--to", dest="dst", required=True, help="destination fingerprint")
    import_p.add_argument("--positions", default=None,
                          help="optional 'fp=x,y fp2=x,y' coordinates (km)")
    import_p.add_argument("--min-fidelity", type=float, default=0.0)
    import_p.add_argument("--max-hops", type=_bounded_hops, default=6)
    import_p.add_argument("--png", default=None, help="write a matplotlib PNG here if available")
    import_p.add_argument("--json-output", action="store_true", default=False,
                          help="machine-readable mode: exactly one JSON document on "
                               "stdout, all diagnostics on stderr (for the Rust bridge)")

    # --- qkd-derive ---
    _layout_help("qkd-derive", "Derive QKD key material at an explicit "
                                "fidelity and seed (no routing)",
                 "--fidelity", {"type": float, "required": True,
                                "help": "end-to-end fidelity the route achieved (0..1)"},
                 "--seed", {"type": _hex_int, "default": QKD_LABEL_SEED,
                            "help": "deterministic RNG seed; both peers must pass the same value "
                                    "(decimal or 0x-prefixed hex)"},
                 "--json-output", {"action": "store_true", "default": False,
                                   "help": "machine-readable mode: exactly one JSON document on "
                                            "stdout, all diagnostics on stderr (for the Rust bridge)"})

    # --- qkd (analytic decoy-state key rate over a fibre link) ---
    qkd_p = sub.add_parser("qkd", help="Decoy-state BB84 key rate over a fibre link "
                                       "(analytic, finite-key aware)")
    qkd_p.add_argument("--distance", type=float, default=50.0,
                       help="fibre length in km")
    qkd_p.add_argument("--preset", default="practical-1550",
                       help="hardware preset (see `bench --help`); "
                            "practical-1550, snspd-1550, gobby-yuan-shields, "
                            "sequencer_erlang, ideal")
    qkd_p.add_argument("--mu", type=float, default=None,
                       help="signal mean photon number (default: from preset)")
    qkd_p.add_argument("--nu", type=float, default=None,
                       help="decoy mean photon number (default: from preset)")
    qkd_p.add_argument("--detector-efficiency", type=float, default=None)
    qkd_p.add_argument("--dark-count", type=float, default=None,
                       help="dark counts per second per detector")
    qkd_p.add_argument("--pulses", type=float, default=None,
                       help="number of pulses sent; enables the finite-key penalty")
    qkd_p.add_argument("--json-output", action="store_true", default=False,
                       help="machine-readable mode: exactly one JSON document on stdout")

    # --- bench (key rate vs distance) ---
    bench_p = sub.add_parser("bench", help="Sweep the decoy-state key rate against distance")
    bench_p.add_argument("--preset", action="append", default=None,
                         help="hardware preset; repeat the flag to compare several")
    bench_p.add_argument("--start", type=float, default=0.0, help="first distance (km)")
    bench_p.add_argument("--stop", type=float, default=300.0, help="last distance (km)")
    bench_p.add_argument("--step", type=float, default=10.0, help="distance step (km)")
    bench_p.add_argument("--pulses", type=float, default=None,
                         help="pulses per run; enables the finite-key penalty")
    bench_p.add_argument("--json-output", action="store_true", default=False,
                         help="machine-readable mode: exactly one JSON document on stdout")

    # --- contend (multi-user resource contention) ---
    contend_p = sub.add_parser(
        "contend",
        help="Run competing entanglement demands against a finite memory pool")
    contend_p.add_argument("--nodes", type=int, default=4,
                           help="nodes in a linear chain")
    contend_p.add_argument("--memory", type=int, default=2,
                           help="memories per node (the contended resource)")
    contend_p.add_argument("--demands", type=int, default=4,
                           help="competing demands, all starting at t=0")
    contend_p.add_argument("--spacing", type=float, default=10.0,
                           help="link spacing in km")
    contend_p.add_argument("--window", type=float, default=5.0,
                           help="demand end time in seconds")
    contend_p.add_argument("--t-swap", dest="t_swap", type=float, default=1e-3,
                           help="swap duration in seconds")
    contend_p.add_argument("--t1", type=float, default=100.0,
                           help="memory T1 in seconds")
    contend_p.add_argument("--t2", type=float, default=50.0,
                           help="memory T2 in seconds")
    contend_p.add_argument("--json-output", action="store_true", default=False,
                           help="machine-readable mode: exactly one JSON document")

    # --- link (physical-layer budget for one span) ---
    link_p = sub.add_parser(
        "link", help="Physical-layer budget for a fibre span "
                     "(detectors, Barrett-Kok, loss)")
    link_p.add_argument("--distance", type=float, default=50.0,
                        help="span length in km")
    link_p.add_argument("--alpha", type=float, default=0.2,
                        help="fibre attenuation in dB/km")
    link_p.add_argument("--detector-efficiency", type=float, default=0.8)
    link_p.add_argument("--dark-count", type=float, default=100.0,
                        help="dark counts per second")
    link_p.add_argument("--dead-time", type=float, default=0.0,
                        help="detector dead time in seconds")
    link_p.add_argument("--window", type=float, default=1e-9,
                        help="coincidence window in seconds")
    link_p.add_argument("--mode-matching", type=float, default=1.0,
                        help="mode-matching factor in (0, 1]")
    link_p.add_argument("--pulse-rate", type=float, default=1e8,
                        help="laser pulse rate in Hz")
    link_p.add_argument("--json-output", action="store_true", default=False,
                        help="machine-readable mode: exactly one JSON document")

    # --- validate (comparison against published results) ---
    validate_p = sub.add_parser(
        "validate",
        help="Recompute published key-rate figures and report the differences")
    validate_p.add_argument("--json-output", action="store_true", default=False,
                            help="machine-readable mode: exactly one JSON document")

    # argparse stores the name as invoked, so the ghost-net alias surfaces here
    # verbatim; normalize it so one code path handles both spellings.
    args = parser.parse_args()
    if args.command == "ghost-net":
        args.command = "import"
        args.schema_id = "ghostnet"
    if getattr(args, "preset", None) is None and args.command == "bench":
        args.preset = ["practical-1550"]

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

    elif args.command == "import":
        ok = _do_import(args)

    elif args.command == "qkd-derive":
        ok = _do_qkd_derive(args)

    elif args.command == "qkd":
        ok = _do_qkd(args)

    elif args.command == "bench":
        ok = _do_bench(args)

    elif args.command == "contend":
        ok = _do_contend(args)

    elif args.command == "link":
        ok = _do_link(args)

    elif args.command == "validate":
        ok = _do_validate(args)

    else:
        parser.print_help()

    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
