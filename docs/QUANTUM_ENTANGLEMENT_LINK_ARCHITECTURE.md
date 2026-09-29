# Architecture

## Overview

Quantum Entanglement Link is a layered quantum communication network simulator
built on a density matrix formalism. Every operation preserves the full quantum
state information, enabling native simulation of mixed states, decoherence, and
noise.

## Layer Diagram

```
Ghost-Net Topology       (future -- graph-based network layer)
     |
Protocol Layer           (QKD, teleportation, superdense, swapping)
     |
Reliability Layer        (error correction, distillation, memory)
     |
Physical Simulation      (gates, measurement, noise models)
     |
Core Formalism          (density matrices, stabilizer tableau, channels)
```

## Phase 3 Foundation Modules

The following modules were added in Phase 3 to support the Ghost-Net
topology integration. Each is independent and documented below.

### Stabilizer Formalism (`stabilizer.py`)

The `StabilizerState` class implements the Aaronson-Gottesman tableau
algorithm for efficient Clifford simulation:

- **Memory:** O(n²) boolean tableau — 52 bytes for 10 qubits vs 16 MB
  for the equivalent density matrix; 205 bytes vs 16 TB at 20 qubits
- **Operations:** H, S, S†, X, Y, Z, CNOT, CZ, SWAP — all update the
  tableau in O(n) per gate
- **Measurement:** Standard CHP algorithm with deterministic and random
  outcome paths
- **Fallback:** `to_statevector()` / `to_density()` for conversion to
  full state vectors when non-Clifford operations are needed

```python
# Bell state via stabilizer
s = StabilizerState.zero(2)
s.h(0)
s.cnot(0, 1)
dm = s.to_density()  # convert to density matrix for non-Clifford ops
```

### Discrete-Event Scheduler (`scheduler.py`)

A priority-queue based event engine for asynchronous protocol execution:

```python
sched = Scheduler()

def handler(node_id, kind, payload, time):
    print(f"[t={time}] {node_id}: {kind} {payload}")

sched.on("emit_photon", handler)
sched.on("photon_arrival", handler)

sched.schedule(1.0, "emit_photon", "alice", {"qubit": 0})
sched.schedule_relative(0.5, "photon_arrival", "bob", {"qubit": 0})

sched.run()  # process all events in time order
```

Supports `schedule`, `schedule_relative`, `schedule_now`, handler
registration via `on`/`off`, and single-step execution via `step`.

### Physical-Layer Impairments (`physical.py`)

Parameterises noise channels from real hardware metrics:

- `fiber_transmissivity(L, α)` — η = 10^{-α·L/10}
- `dark_count_probability(R, τ)` — p_dc = 1 - exp(-R·τ)
- `t1_decay_probability(Δt, T1)` — p = 1 - exp(-Δt/T1)
- `t2_dephase_probability(Δt, T2)` — p = 1 - exp(-Δt/T2)
- `depolarizing_from_distance(L, ...)` — effective p from fibre and
  detector parameters
- `memory_fidelity_after_dt(f0, Δt, T1, T2)` — composite fidelity
  estimate

### Multi-Process IPC Node Architecture (`ipc_node.py`)

Enables each network node to execute as an isolated process:

```python
node = IPCNode("alice", t1=100.0, t2=50.0)
node.start()
node.send(MessageType.SCHEDULE_EVENT, payload={...})
result = node.recv()
node.stop()

# Or use the TopologyRunner to coordinate multiple nodes
runner = TopologyRunner()
runner.add_node("alice", t1=100.0, t2=50.0)
runner.add_node("bob", t1=100.0, t2=50.0)
runner.start_all()
runner.send("alice", MessageType.STATE_SYNC)
runner.stop_all()
```

## Core Layer (`src/quantumnet/core/`)

### QubitState (`qubit.py`)

The fundamental state container. Stores a density matrix `rho` and dimension
metadata `dims`.

```python
state = QubitState(rho, dims=[2, 2])  # 2-qubit state
```

Factory methods for common states:
- `QubitState.zero()` -- |0>
- `QubitState.one()` -- |1>
- `QubitState.plus()` -- |+>
- `QubitState.minus()` -- |->
- `QubitState.bell_phi_plus()` -- |Phi+>
- `QubitState.bell_phi_minus()` -- |Phi->
- `QubitState.bell_psi_plus()` -- |Psi+>
- `QubitState.bell_psi_minus()` -- |Psi->
- `QubitState.maximally_mixed(n)` -- I / d

Key methods:
- `fidelity(other)` -- Uhlmann fidelity using matrix square root
- `purity()` -- Tr(rho^2)
- `concurrence()` -- Wootters concurrence for 2-qubit states
- `partial_trace(keep, dims)` -- trace out last n-keep qubits

### Gate (`gate.py`)

Gate operations are represented as matrices with automatic embedding into
multi-qubit systems.

```python
# Apply Hadamard to qubit 0 of a 3-qubit state
state = apply(H, state, targets=[0])

# Apply CNOT with control=0, target=2
state = apply(CNOT, state, targets=[0, 2])
```

Built-in gates: `I`, `X`, `Y`, `Z`, `H`, `S`, `T`, `CNOT`, `SWAP`, `CZ`.

The `_embed` function expands a gate matrix to the full Hilbert space by
tensor-product structure, ensuring all non-target qubits pass through as
identity.

### Measurement (`measurement.py`)

Two measurement primitives:

- `measure(state, qubit_indices, rng)` -- computational basis measurement
  on specified qubits. Returns (outcomes_dict, post_measurement_state).
  The outcomes dict maps qubit index -> 0/1.
  Uses sequential projective collapse: after each qubit is measured, the
  state is projected onto the observed outcome subspace via a diagonal
  projection matrix (not a rank-1 outer product), and subsequent qubit
  probabilities are computed from the collapsed state. This ensures the
  correct conditional joint distribution P(q_1,...,q_m).

- `measure_bell(state, rng)` -- Bell basis measurement on a 2-qubit state.
  Returns (bell_index, post_measurement_state), where bell_index in {0,1,2,3}
  corresponds to |00> -> |Phi+>, |01> -> |Psi+>, |10> -> |Phi->,
  |11> -> |Psi->.

The returned state preserves all qubit dimensions (measured qubits remain in
the Hilbert space but are collapsed). The calling protocol is responsible for
tracing out measured qubits via `partial_trace` if needed.

### Noise Models (`noise.py`)

Four channel implementations, all as Kraus operator decompositions:

**Depolarizing Channel:**
```python
chan = depolarizing_channel(p)  # single qubit
chan = depolarizing_channel_2(p)  # two qubit
```

Kraus operators:
- E0 = sqrt(1-p) * I
- E1 = sqrt(p/3) * X
- E2 = sqrt(p/3) * Y
- E3 = sqrt(p/3) * Z

With probability p, the state is replaced by the maximally mixed state.

**Amplitude Damping (T1):**
```python
chan = amplitude_damping_channel(gamma)  # gamma = 1 - exp(-t/T1)
```

Models energy relaxation |1> -> |0> with rate gamma.

**Dephasing (T2):**
```python
chan = dephasing_channel(gamma)  # gamma = 1 - exp(-t/T2)
```

Models phase randomization without energy exchange.

### Channel (`channel.py`)

The `Channel` class wraps Kraus operators and provides:
- `apply(state, targets=None)` -- applies the channel to a QubitState.
  When `targets` is provided, each Kraus operator is embedded into the full
  Hilbert space (via `_embed` from `gate.py`) and applied to the specified
  qubit subset. When `targets` is None, the channel acts on the full state
  (Kraus operators must match state dimensions).
- Composition via successive application

## Protocols Layer (`src/quantumnet/protocols/`)

Each protocol is an independent module with a consistent interface.
Protocols that involve randomness accept an optional `rng` parameter
for reproducibility.

### BB84 QKD (`bb84.py`)

```python
result = run_bb84(num_bits=256, noise=0.01, rng=rng)
```

Simulates the prepare-and-measure BB84 protocol:
1. Alice generates random bits and random bases
2. Alice encodes each bit in Z-basis (|0>, |1>) or X-basis (|+>, |->)
3. Noisy channel transmits the qubits
4. Bob measures in random bases
5. Alice and Bob sift by comparing bases over classical channel
6. They estimate QBER from a sample subset

Returns: `{"key": str, "qber": float, "raw_bits": int, "sifted_bits": int}`

### E91 QKD (`e91.py`)

```python
result = run_e91(num_pairs=256, noise=0.01, rng=rng)
```

Entanglement-based QKD using Bell pairs:
1. Generate |Phi+> Bell pairs
2. Distribute one qubit to Alice, one to Bob through noisy channels
3. Alice and Bob measure in random bases (Z, X, or diagonal)
4. Compare bases over classical channel, keep matching results as key
5. Use a subset to compute CHSH S-value for security check

Returns: `{"key": str, "qber": float, "s_value": float, "pairs_used": int}`

### Quantum Teleportation (`teleportation.py`)

```python
result = run_teleportation(rng=rng)
```

Transfers an arbitrary qubit state from Alice to Bob:
1. Create a Bell pair shared between Alice and Bob
2. Alice performs Bell measurement on her qubit + the input qubit
3. Alice sends the 2-bit outcome to Bob
4. Bob applies the correction gate (I, X, Z, or X*Z)

Returns: `{"input_fidelity": float, "teleported_fidelity": float,
          "bell_outcome": tuple, "success": bool}`

Works for any input state -- tested with |0>, |1>, |+>.

### Superdense Coding (`superdense.py`)

```python
result = run_superdense(bits=0b10, rng=rng)
```

Encodes 2 classical bits into 1 transmitted qubit:
1. Alice and Bob share a Bell pair
2. Alice applies I, X, Z, or X*Z to encode 00, 01, 10, or 11
3. Alice sends her qubit to Bob
4. Bob performs Bell measurement to decode

Returns: `{"encoded_bits": str, "decoded_bits": str, "success": bool}`

### Entanglement Swapping (`swapping.py`)

```python
result = run_swapping(noise=0.0, rng=rng)
```

Creates remote entanglement between two nodes via an intermediate node:
1. Nodes A-B share a Bell pair, nodes B-C share a Bell pair
2. Node B performs a Bell measurement on its two qubits
3. Nodes A and C now share an entangled state
4. Corrections are applied based on the Bell outcome

Returns: `{"bell_outcome": tuple, "swapped_fidelity": float, "success": bool}`

### Shor 9-Qubit Code (`shor.py`)

```python
encoded = shor_encode(state)           # 1 qubit -> 9 qubits
syndrome = shor_syndrome(state)        # 8-bit error syndrome
corrected = shor_correct(state)        # apply correction based on syndrome
decoded = shor_decode(state)           # 9 qubits -> 1 qubit
```

Corrects any single-qubit error (X, Z, or Y = X*Z).

Encoding: |0>_L = (|000> + |111>)^(x)3 / sqrt(8), same for |1>_L with sign flips.

Stabilizers:
- Z1*Z2, Z2*Z3 (phase-flip detection within block 1)
- Z4*Z5, Z5*Z6 (block 2)
- Z7*Z8, Z8*Z9 (block 3)
- X1X2X3X4X5X6 (bit-flip between blocks 1-2)
- X4X5X6X7X8X9 (bit-flip between blocks 2-3)

Syndrome decoding: Z-type syndromes identify which qubit in a block had a
bit-flip; X-type syndromes identify which block had a phase-flip.

### Steane [[7,1,3]] Code (`steane.py`)

```python
encoded = steane_encode(state)          # 1 qubit -> 7 qubits
syndrome = steane_syndrome(state)       # 6-bit error syndrome
corrected = steane_correct(state)       # apply correction
decoded = steane_decode(state)          # 7 qubits -> 1 qubit
```

CSS code built from the [7,4,3] Hamming code.

Constructed as:
- |0>_L = sum_{y in C_perp} |y> where C_perp is the dual Hamming code (8 vectors)
- |1>_L = X_L |0>_L where X_L = X^{x7} (bitwise Pauli X)

Stabilizers (3 X-type, 3 Z-type) correspond to rows of the Hamming parity
check matrix. Encoding projects onto the simultaneous +1 eigenspace of all 6.

### Entanglement Distillation (`distillation.py`)

**BBPSSW Protocol:**
```python
result = bbssw_distill(pair1, pair2, rng=rng)
```

1. Apply CNOT from pair1 to pair2 (on both Alice and Bob sides)
2. Measure pair2 qubits in Z basis
3. If outcomes match, keep pair1 (now purified)

**Deutsch Protocol:**
```python
result = deutsch_distill(pair1, pair2, rng=rng)
```

1. Apply CNOT from pair1 to pair2
2. Apply Hadamard on pair2 qubits (X-basis measurement)
3. Measure pair2 qubits in Z basis
4. If outcomes match, keep pair1 (now purified)

Both return: `{"success": bool, "distilled_fidelity": float, "outcomes": tuple}`

### Quantum Memory Buffer (`memory.py`)

```python
fids = memory_fidelity_over_time(state, times, t1, t2)
t_cut = memory_cutoff_time(state, t1, t2, threshold)
buf = QuantumMemoryBuffer(t1, t2, cutoff_fidelity)
buf.store(key, state, current_time)
retrieved = buf.retrieve(key, current_time)
```

T1/T2 decoherence model:
- T1 (amplitude damping): |1> relaxes to |0> with rate 1/T1
- T2 (dephasing): off-diagonal coherences decay with rate 1/T2
- Combined: both effects applied sequentially

The buffer implements a cutoff policy: states whose fidelity falls below
threshold are dropped and return None on retrieval.

## CLI (`cli.py`)

```bash
python -m quantumnet <command> [options]
```

Commands: `bb84`, `e91`, `teleport`, `superdense`, `swap`, `shor`,
`steane`, `distill`, `memory`, `stabilizer`, `physical`, `all`

Phase 3 commands:
- `stabilizer` -- explore stabilizer states (bell, ghz, random)
- `physical` -- compute physical-layer parameters (transmissivity,
  dark count, depolarising probability, T1/T2 decay)

Each command accepts protocol-specific flags (--noise, --seed, --state, etc.)
and prints formatted results.

## Reproducibility

All random protocols accept a `numpy.random.Generator` via the `rng` parameter.
The same seed guarantees identical output across runs:

```python
rng = np.random.default_rng(42)
r1 = run_bb84(256, noise=0.01, rng=rng)
rng = np.random.default_rng(42)
r2 = run_bb84(256, noise=0.01, rng=rng)
assert r1["key"] == r2["key"]
```
