# Quantum Entanglement Link

A modular, simulation-first quantum communication network stack in Python. Implements QKD, teleportation, superdense coding, entanglement swapping, quantum error correction, entanglement distillation, and memory buffers with realistic noise models.

> **Where this code lives:** the package source is the `Quantum Entanglement Link/`
> directory of the Vantablack repository; this document is a copy kept in the
> repository `docs/` directory. Install it from the package directory
> (`cd "Quantum Entanglement Link" && pip install -e .`) before running any of
> the commands below, and run the test suite from that same directory.

## Architecture

```
src/quantumnet/
  core/             -- Foundation layer
    qubit.py        --   Density matrix formalism (QubitState)
    gate.py         --   Gate operations, embedding, tensor products
    measurement.py  --   Computational & Bell basis measurement
    channel.py      --   Quantum channel interface
    noise.py        --   Depolarizing, amplitude damping, dephasing
    stabilizer.py   --   Stabilizer tableau (O(n²) Clifford simulation)
    scheduler.py    --   Discrete-event simulation engine
    physical.py     --   Fibre loss, T1/T2, dark count models
    ipc_node.py     --   Multi-process node architecture
  protocols/        -- Protocol layer
    bb84.py         --   BB84 QKD (prepare-and-measure)
    e91.py          --   E91 QKD (entanglement-based)
    teleportation.py --  Quantum teleportation
    superdense.py   --   Superdense coding (2 bits per qubit)
    swapping.py     --   Entanglement swapping
    shor.py         --   Shor 9-qubit error correction
    steane.py       --   Steane [[7,1,3]] error correction
    distillation.py --   BBPSSW & Deutsch entanglement distillation
    memory.py       --   T1/T2 decoherence buffer with cutoff
    bell.py         --   Bell state helpers
  topology/         -- Phase 3: Ghost-Net topology layer
    graph.py        --   QuantumTopology, nodes, optical links (physical fidelity)
    routing.py      --   Fidelity-constrained path finding + swap fidelity
    schedule.py     --   Time-aware swap scheduling with memory decay
    visualize.py    --   ASCII map / matplotlib heat rendering
    ghostnet.py     --   Bridge to the live Rust Global Ghost Net export
  cli.py            -- Command-line interface
  demo.py           -- Full protocol demo runner
```

## Quick Start

```bash
# Run all protocol demos
python -m quantumnet all

# Individual protocols
python -m quantumnet bb84 --bits 512 --noise 0.02
python -m quantumnet e91 --pairs 512 --noise 0.01
python -m quantumnet teleport
python -m quantumnet superdense
python -m quantumnet swap --noise 0.05

# Error correction
python -m quantumnet shor --state zero --error X --qubit 3
python -m quantumnet steane --state plus --error Z --qubit 1

# Distillation
python -m quantumnet distill --protocol bbssw --fidelity 0.8
python -m quantumnet distill --protocol deutsch --fidelity 0.75

# Memory buffer
python -m quantumnet memory --state one --t1 10.0 --t2 10.0 --t 5.0

# Phase 3: Stabilizer simulation
python -m quantumnet stabilizer --state bell
python -m quantumnet stabilizer --state ghz --nqubits 10
python -m quantumnet stabilizer --state random --nqubits 100

# Phase 3: Physical-layer calculator
python -m quantumnet physical --compute transmissivity --length 50
python -m quantumnet physical --compute depolarizing --length 20

# Phase 3: Quantum topology (build, route, schedule, visualize)
python -m quantumnet topology build --shape ring --nodes 8 --repeaters 3
python -m quantumnet topology route --shape grid --rows 3 --cols 4 \
    --from A0 --to C3 --ascii
python -m quantumnet ghost-net --topology ghost-topology.json \
    --from <fpA> --to <fpB> --positions "<fpA>=0,0 <fpB>=500,300"
```

The Rust daemon's L10 quantum anchor shells out to that last command and parses
its result, so it has a stricter contract:

```bash
# Exactly one JSON document on stdout; every diagnostic on stderr.
python -m quantumnet ghost-net --topology ghost-topology.json \
    --from <fpA> --to <fpB> --json-output
```

```json
{
  "success": true,
  "path": ["<fpA>", "<repeater>", "<fpB>"],
  "end_to_end_fidelity": 0.6286,
  "swap_nodes": ["<repeater>"],
  "key_fidelity": 0.8920,
  "distillation_rounds": 2,
  "qkd_key_hex": "00ff11ee…"
}
```

**Two fidelities, and the difference matters.** `end_to_end_fidelity` is the route
as distributed, and the dark-count floor caps it at ≈0.85 — below the BB84
security cutoff this library enforces (QBER < 11%, i.e. F ≳ 0.87). No route
clears that on its own, at any distance. `key_fidelity` is the fidelity *after*
BBSSW distillation (`_distil_to_key_fidelity`), and it is the figure
`qkd_key_hex` is derived at, so it is the value that identifies the key.
`qkd_key_hex` is `null` only when even distillation cannot reach the cutoff. That
is a real result, not an error: the route exists, but no key may be derived from
it.

Or via the demo module:

```bash
python -m quantumnet.demo
```

## Features

### Core
- **Density matrix formalism** -- mixed states native, no silent idealisations
- **Gate operations** -- single and multi-qubit gates with automatic embedding
- **Measurement** -- computational basis and Bell basis measurement
- **Noise models** -- depolarizing, amplitude damping (T1), dephasing (T2)
- **Stabilizer formalism** -- O(n²) Gottesman-Knill tableau (Phase 3)
- **Discrete-event scheduler** -- priority-queue timed event engine (Phase 3)
- **Physical-layer impairments** -- fibre loss, T1/T2, dark counts (Phase 3)
- **Multi-process IPC** -- isolated node workers over local queues (Phase 3)

### Phase 1: Protocols
- **BB84 QKD** -- prepare-and-measure with sifting, QBER estimation
- **E91 QKD** -- entanglement-based with CHSH Bell inequality check
- **Quantum Teleportation** -- Bell measurement + classical feed-forward
- **Superdense Coding** -- encode 2 bits per transmitted qubit
- **Entanglement Swapping** -- intermediate Bell measurement creates remote entanglement

### Phase 2: Reliability
- **Shor 9-qubit code** -- corrects any single-qubit error (X, Z, or Y)
- **Steane [[7,1,3]] code** -- CSS code, corrects single-qubit errors
- **BBPSSW Distillation** -- purify noisy Bell pairs via CNOT + measurement
- **Deutsch Distillation** -- higher-yield purification protocol
- **Quantum Memory Buffer** -- T1/T2 decoherence with configurable cutoff

### Phase 3: Ghost-Net Topology
- **QuantumTopology graph** -- nodes/repeaters with positions; link fidelity and
  generation rates derived from real fibre loss + dark-count physics
- **Fidelity-constrained routing** -- all simple paths ranked by achievable
  end-to-end fidelity (Werner swap formula `F' = F1F2 + (1-F1)(1-F2)/3`)
- **Time-aware swap scheduling** -- parallel link generation, per-segment T1/T2
  memory decay, ordered Bell-state measurement events per repeater
- **Visualisation** -- dependency-free ASCII heat map (+ optional matplotlib PNG)
- **Ghost-Net bridge** -- loads the live mesh export from the Rust
  `vantablack` daemon (`EXPORTTOPOLOGY`) and routes quantum entanglement over it

## Testing

```bash
pytest tests/ -v
```

116 tests covering:
- Core: gate operations, measurement, noise models, qubit state
- Protocols: BB84, E91, teleportation, superdense, swapping
- Error correction: Shor code, Steane code (all single-error combinations)
- Distillation: BBPSSW, Deutsch
- Memory: T1 decay, fidelity over time, cutoff
- Integration: encode-correct-decode chains, full protocol round-trips
- Topology (Phase 3): link physics, swap formula/ordering, routing, schedules,
  ghost-net bridge (real export format)

## Documentation

- `QUANTUM_ENTANGLEMENT_LINK_ARCHITECTURE.md` -- detailed architecture and protocol documentation
- `QUANTUM_ENTANGLEMENT_LINK_WHITEPAPER.md` -- technical whitepaper with validation results
- `notebooks/demo.ipynb` -- interactive Jupyter notebook with all protocols

## Demo

```bash
# Run every protocol end-to-end
python -m quantumnet all

# Interactive Jupyter notebook
jupyter notebook notebooks/demo.ipynb
```

## Design

- **Simulation-first** -- pure Python + NumPy/SciPy, no external quantum framework dependencies
- **Reproducible** -- all simulations accept `numpy.random.Generator` for deterministic seeds
- **Modular** -- each protocol is independent with a consistent `run()` interface
- **No silent idealisations** -- every channel takes explicit noise parameters

## License

MIT
