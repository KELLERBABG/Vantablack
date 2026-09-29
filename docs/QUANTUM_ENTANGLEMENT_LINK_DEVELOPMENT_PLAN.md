# Quantum Entanglement Link — Development Plan

## Core Idea
A modular, simulation-first quantum communication network stack in Python — implementing BSA, QKD, entanglement swapping, teleportation, superdense coding, error correction, distillation, memory buffering, and Ghost-Net topology. Everything runs in simulation using existing quantum frameworks (Qiskit / Cirq), with a layered architecture that could eventually target real hardware.

## Architecture

```
Ghost-Net Topology (network graph layer)
    │
├── Entanglement Distribution (swapping, repeaters, distillation)
│   ├── Bell State Analysis
│   ├── Entanglement Swapping
│   └── Entanglement Distillation
│
├── Protocol Layer (QKD, Teleportation, Superdense Coding)
│   ├── BB84 / E91
│   ├── Quantum Teleportation
│   └── Superdense Coding
│
├── Reliability Layer
│   ├── Quantum Error Correction (Shor/Steane)
│   ├── Quantum Memory Buffering
│   └── No-Cloning Compliance Checks
│
└── Physical Simulation (noise models, decoherence, detectors)
```

## Development Phases

### Phase 0: Scaffold & Foundation (Week 1)
- Python project with `pyproject.toml`, `src/` layout, `pytest`
- Abstract base classes: `Qubit`, `Channel`, `Gate`, `Measurement`
- Bell state generation and measurement (the primitive everything builds on)
- Noise model interface (depolarizing, amplitude damping, dephasing)

### Phase 1: Core Protocols (Weeks 2–4)
- **BB84 QKD** — full simulation with sifting, error estimation, privacy amplification
- **E91 QKD** — entanglement-based variant with Bell inequality check
- **Quantum Teleportation** — Alice prepares → Bell measurement → classical bits → Bob reconstructs
- **Superdense Coding** — 2 classical bits → 1 qubit → Bell measurement → decode
- **Entanglement Swapping** — intermediate node Bell measurement → remote entanglement
- Validate: QBER curves vs noise, fidelity vs distance

### Phase 2: Reliability (Weeks 5–6)
- **Shor Code** — 9-qubit encoding, syndrome extraction, correction
- **Steane Code** — 7-qubit encoding, transversal gates, fault-tolerant thresholds
- **BBPSSW Distillation** — purify noisy Bell pairs
- **Deutsch Distillation** — purification with higher yield
- **Memory Buffer** — time-dependent decoherence model, cutoff policy

### Phase 3: Ghost-Net Topology (Weeks 7–8) ✓ COMPLETE

**Foundations implemented:**
- Stabilizer formalism (core.stabilizer) — O(n²) Gottesman-Knill tableau
- Discrete-event scheduler (core.scheduler) — priority-queue event engine
- Physical-layer impairments (core.physical) — fibre loss, T1/T2, dark counts
- Multi-process IPC node architecture (core.ipc_node)

**Phase 3 deliverables (all implemented + tested):**
- Graph-based topology optimizer (`topology/graph.py`): nodes, repeaters, lossy edges, `QuantumTopology.ring/grid`, distance model
- Path finding with fidelity constraints (`topology/routing.py`): `all_simple_paths` (bounded), `rank_routes`, `best_route`, `e2e_fidelity`, `optimal_swap_order` (brute force ≤8, left-to-right above)
- Multi-hop swapping schedule optimization (`topology/schedule.py`): time-aware distribution with per-segment T1/T2 memory decay
- Visualisation (`topology/visualize.py`): ASCII render + matplotlib fidelity heatmap
- Ghost-Net bridge (`topology/ghostnet.py`): loads the Rust daemon's live `EXPORTTOPOLOGY` JSON; `quantumnet ghost-net --topology <file> --src --dst`
- CLI: `quantumnet topology build|route`, `quantumnet ghost-net`
- Hardened against hostile inputs: JSON NaN/Infinity rejection, finite-value/type validation, path-visit budget, `--max-hops` clamp (see pentest session log EX-003)
- Tests: 112 green (81 prior + 31 new topology/bridge)

### Phase 4: Stack Integration & Polish (Week 9–10) ✓ COMPLETE
- Unified network stack: app → key mgmt → entanglement distribution → physical
- End-to-end integration tests across all layers
- CLI tool for running experiments
- Jupyter notebooks for interactive demos
- `README.md` with architecture docs and examples
- `WHITEPAPER.md` technical whitepaper
- `docs/architecture.md` detailed protocol documentation

> All four of these documents now live in the repository root `docs/` directory
> as `QUANTUM_ENTANGLEMENT_LINK_{README,WHITEPAPER,ARCHITECTURE}.md` plus this
> development plan.

## Tech Stack
- **Python** 3.11+ — only real choice for quantum simulation ecosystems
- **NumPy / SciPy** — density matrix ops, fidelity calculations, linear algebra
- **NetworkX** — Ghost-Net graph topology
- **Matplotlib / Plotly** — visualisation
- **pytest** — test suite (no surprises)
- **Poetry / uv** — dependency management

## Key Design Decisions
- **Simulation-first, hardware-ready** — abstract backend interface so real hardware can swap in
- **Density matrix formalism** — tracks mixed states and decoherence natively (not just pure state vectors)
- **Explicit noise everywhere** — every channel takes a noise parameter; no silent idealisations
- **Modular components** — each protocol is a standalone class with `run()` returning a result object
- **Deterministic seeds** — all simulations reproducible via `numpy.random.seed`

## Quick Start (target)
```bash
pip install quantumnet
quantumnet simulate bb84 --distance 50 --noise 0.01
quantumnet visualize ghost-net --nodes 8 --repeaters 3
```

## Estimation

| Phase | Time | Lines of Code | Dependencies |
|-------|------|---------------|--------------|
| 0: Scaffold | 1 week | ~500 | Python, Qiskit, pytest |
| 1: Core Protocols | 3 weeks | ~2000 | + NumPy, SciPy |
| 2: Reliability | 2 weeks | ~1500 | + none |
| 3: Ghost-Net | 2 weeks | ~1000 | + NetworkX, Matplotlib |
| 4: Integration | 2 weeks | ~1000 | + optional: Click, Jupyter |
| **Total** | **~10 weeks** | **~6000** | |

No $289k budget. No 4.7 years. No hardware purchase. Just a laptop, Python, and focused execution.
