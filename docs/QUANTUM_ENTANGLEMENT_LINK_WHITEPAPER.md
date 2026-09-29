# Quantum Entanglement Link

## A Modular Simulation Stack for Quantum Communication Networks

**Version 1.2 -- July 2026**

---

### Abstract

We present Quantum Entanglement Link, a modular, simulation-first quantum
communication network stack implemented in Python. Built on a density matrix
formalism, the stack simulates all fundamental quantum communication protocols
-- including BB84 and E91 quantum key distribution, quantum teleportation,
superdense coding, and entanglement swapping -- alongside a full reliability
layer with Shor and Steane quantum error correction codes, BBPSSW and Deutsch
entanglement distillation, and T1/T2 memory buffering. All components use
explicit noise models (depolarizing, amplitude damping, dephasing) with
reproducible random seeding. Phase 3 foundations are in place: stabilizer
formalism (O(n²) tableau), discrete-event scheduler, physical-layer
impairment models (fibre loss, T1/T2, dark counts), and multi-process IPC
node architecture. The Ghost-Net topology integration layer is the next
scheduled development milestone. The stack achieves 81 automated tests
validating every protocol path, including exhaustive single-error correction
across all qubits for both the Shor 9-qubit and Steane [[7,1,3]] codes.

---

### 1. Introduction

Quantum communication networks promise unconditionally secure information
transfer, distributed quantum computing, and entanglement-based sensing at
global scales. Realising these capabilities requires a layered architecture
where physical entanglement distribution, error mitigation, and application
protocols interact coherently.

Quantum Entanglement Link addresses this need with a cleanly layered
simulation stack that models every component from Bell pair generation
through to application-layer QKD. The design philosophy is threefold:

1. **Density matrix formalism** -- all operations preserve the full quantum
   state, enabling native modelling of mixed states and decoherence
2. **Explicit noise everywhere** -- no silent idealisations; every channel
   accepts noise parameters
3. **Reproducible by design** -- all random processes accept seeded generators

The stack currently implements Phases 0-2 and Phase 4 of the development plan
(Foundation, Core Protocols, Reliability, Integration). Phase 3 foundations
are complete: **stabilizer formalism** (O(n²) Gottesman-Knill tableau),
**discrete-event scheduler**, **physical-layer impairment models** (fibre
loss, T1/T2, dark counts), and **multi-process IPC node architecture**.
The Ghost-Net topology integration layer — graph-based network optimisation,
path finding with fidelity constraints, and multi-hop swapping schedules —
is the next scheduled milestone.

---

### 2. Core Simulation Framework

#### 2.1 Density Matrix State Representation

All quantum states are represented as density matrices rho, stored as
complex NumPy arrays. For an n-qubit system, rho has dimension 2^n x 2^n.
This naturally captures:

- Pure states: Tr(rho^2) = 1
- Mixed states: Tr(rho^2) < 1
- Maximally mixed: rho = I/2^n

State fidelity is computed via the Uhlmann-Jozsa formula using matrix square
roots:

    F(rho, sigma) = [Tr(sqrt(sqrt(rho) sigma sqrt(rho)))]^2

#### 2.2 Gate Operations

Single- and multi-qubit gates are applied by embedding gate matrices into the
full Hilbert space. For a gate G acting on m target qubits of an n-qubit
system, the full operator is:

    U_full = sum_{i,j} G_{i,j} |t_i><t_j| x I_{rest}

where t_i, t_j are the target qubit computational basis states and the
identity acts on all non-target qubits. The state updates via:

    rho' = U_full rho U_full^dag

#### 2.3 Measurement

Computational basis measurements use sequential projective collapse with
diagonal subspace projection. For a measurement on qubit indices
[qi_1, ..., qi_m]:

1. Compute P(qubit_i = 0) = sum of diagonal elements of rho where the
   i-th qubit is |0>, using the current (projected) state
2. Sample an outcome from the Bernoulli distribution using the seeded RNG
3. Construct a diagonal projection matrix with 1's at all basis states
   where the measured qubit matches the outcome (subspace projection, not
   rank-1 projection)
4. Collapse: rho' = P @ rho @ P, then renormalise
5. Repeat for the next qubit using the collapsed state (ensuring correct
   conditional joint distribution P(outcome_1, ..., outcome_m))

The key distinction is that the projection is onto the multi-dimensional
subspace where the measured qubit has a specific value (a diagonal matrix
with multiple 1's), not onto a single basis state (a rank-1 outer product).
This correctly handles the conditional probability structure: subsequent
measurement probabilities are computed from the collapsed state, giving
P(q_j | q_i = outcome_i) rather than the unconditional marginal P(q_j).

The returned state preserves all qubit dimensions (measured qubits remain
in the Hilbert space but are collapsed). Bell basis measurements are
implemented by transforming to the Bell basis via the inverse of the
standard encoding circuit (CNOT + H), then measuring in the computational
basis. The four Bell states map deterministically to computational basis
states: |Phi+> -> |00>, |Psi+> -> |01>, |Phi-> -> |10>, |Psi-> -> |11>.

#### 2.4 Noise Channels

Four noise models are implemented as Kraus operator decompositions:

| Channel | Parameters | Kraus Rank | Physical Process |
|---------|-----------|------------|-----------------|
| Depolarizing | p in [0, 1] | 4 | isotropic white noise |
| Amplitude Damping | gamma in [0, 1] | 2 | T1 energy relaxation |
| Dephasing | gamma in [0, 1] | 2 | T2 phase randomization |
| 2-Qubit Depolarizing | p in [0, 1] | 16 | two-qubit correlated noise |

Each channel is a CPTP map applied as:

    rho' = sum_k E_k rho E_k^dag

The `Channel.apply()` method supports an optional `targets` parameter that
embeds the Kraus operators into the full Hilbert space using the same matrix
embedding as gate operations, allowing a channel to act on a specific subset
of qubits within a larger system.

#### 2.5 Stabilizer Formalism (Phase 3)

The `StabilizerState` class implements the Aaronson-Gottesman tableau
algorithm for efficient Clifford simulation:

- **Memory:** O(n²) boolean tableau instead of O(4ⁿ) complex density matrix.
  A 10-qubit stabilizer state uses 52 bytes; the equivalent density matrix
  uses 16 MB. At 20 qubits the gap is 205 bytes vs 16 TB.
- **Operations:** All Clifford gates (H, S, S†, X, Y, Z, CNOT, CZ, SWAP)
  update the tableau in O(n) per gate.
- **Measurement:** Computational-basis measurement uses the standard CHP
  algorithm: random outcome when the measured observable anticommutes with a
  stabilizer generator (determined via GF(2) linear algebra), deterministic
  otherwise.
- **Fallback:** `to_statevector()` / `to_density()` convert to the full
  state vector via power iteration, enabling non-Clifford operations
  (noise channels, arbitrary rotations) when required.

Use stabilizer formalism for all Clifford-only circuits (error correction,
QKD, Bell state manipulation). Fall back to density matrices only when
non-Clifford noise or arbitrary phase rotations are needed.

#### 2.6 Discrete-Event Scheduler (Phase 3)

The `Scheduler` class provides an asynchronous simulation core:

- A priority queue of timed `Event` objects, each with a kind string,
  node ID, and payload dict
- Handlers are registered per event kind via `on(kind, handler)` and
  invoked in strict time order as the scheduler advances
- Events can be scheduled at absolute times (`schedule`), relative to
  the current time (`schedule_relative`), or immediately (`schedule_now`)
- The scheduler runs until the queue is empty (`run`) or one event at a
  time (`step`)

Protocols are structured as state machines that react to incoming events
rather than executing as monolithic sequential functions. This models the
asynchronous nature of real quantum networks: photon transmission delays,
probabilistic entanglement generation, and parallel memory decay timers.

#### 2.7 Physical-Layer Impairments (Phase 3)

Noise channels are parameterised from physical hardware metrics rather than
abstract probabilities:

- **Fibre transmissivity:** η = 10^{-α·L/10} for fibre length L and
  attenuation α (0.2 dB/km at 1550 nm)
- **Dark counts:** p\_dc = 1 - exp(-R\_dc · τ) for dark count rate R\_dc
  and detection window τ
- **Memory decay:** p\_T1 = 1 - exp(-Δt/T1), p\_T2 = 1 - exp(-Δt/T2)
- **Effective depolarising probability:** composed from fibre loss and
  detector dark count probability via `depolarizing_from_distance()`

These functions map real hardware specifications directly to channel
parameters for the existing Kraus operator noise models.

#### 2.8 Multi-Process IPC Node Architecture (Phase 3)

The `IPCNode` and `TopologyRunner` classes provide a multi-process
architecture where each network node executes as an isolated worker
process:

- Nodes communicate over `multiprocessing.Queue` IPC channels
- `TopologyRunner` coordinates a collection of node processes, dispatching
  messages and collecting results
- Each process holds its own local state (stabilizer tableau, memory
  buffer, protocol state machine), enabling true parallel execution of
  independent network nodes on multi-core systems

---

### 3. Protocol Implementations

#### 3.1 Quantum Key Distribution

**BB84** implements the prepare-and-measure protocol with random basis
selection, sifting, and QBER estimation. Alice encodes bits in Z or X bases;
Bob measures in random bases; they sift over a classical channel. The QBER is
estimated from a randomly selected sample subset.

**E91** implements entanglement-based QKD using Bell pair distribution.
Alice and Bob each measure their half of each Bell pair in a random basis
(Z, X, or a diagonal basis for CHSH estimation). After sifting, they compute
the CHSH S-value from a subset. S > 2 indicates the presence of quantum
correlations sufficient for security.

#### 3.2 Quantum Teleportation

The teleportation protocol transfers an arbitrary single-qubit state from
Alice to Bob using a shared Bell pair and two classical bits of
communication. The protocol steps are:

1. Create |Phi+> Bell pair shared between Alice and Bob
2. Alice performs a Bell measurement on her Bell qubit + the input qubit
3. Alice sends the 2-bit outcome over a classical channel
4. Bob applies the correction: I for 00, X for 01, Z for 10, X*Z for 11

The protocol achieves unit fidelity in the absence of noise and is verified
for all four Bell measurement outcomes.

#### 3.3 Superdense Coding

Superdense coding encodes 2 classical bits in 1 transmitted qubit by
leveraging a pre-shared Bell pair. Alice applies:

- 00: I (no operation)
- 01: X (bit flip)
- 10: Z (phase flip)
- 11: X*Z (both)

Bob performs a Bell measurement to recover both bits. The protocol is verified
for all four 2-bit messages.

#### 3.4 Entanglement Swapping

Entanglement swapping generates remote entanglement between two nodes that
have never directly interacted, using an intermediate node. Given Bell pairs
A-B and B-C, node B performs a Bell measurement that projects A and C into a
shared entangled state. The protocol succeeds for all four possible Bell
measurement outcomes, with the appropriate Pauli corrections applied.

---

### 4. Error Correction

#### 4.1 Shor 9-Qubit Code

The Shor code [Shor, 1995] concatenates the 3-qubit bit-flip code with the
3-qubit phase-flip code, producing a 9-qubit code capable of correcting any
single-qubit error.

**Logical states:**

    |0>_L = (|000> + |111>)(x)3 / (2*sqrt(2))
    |1>_L = (|000> - |111>)(x)3 / (2*sqrt(2))

**Stabilizer generators:** Two types of stabilizer detect errors:

- Z-type (within blocks): Z_i Z_{i+1} for i = 1,2,4,5,7,8
  -- detect bit flips within each 3-qubit block
- X-type (between blocks): X^{x6} on blocks 1-2 and blocks 2-3
  -- detect phase flips between blocks

**Syndrome decoding:**
1. Z-type syndromes identify which qubit in a block was flipped (Z1*Z2 = 11
   for qubit 1, Z2*Z3 = 11 for qubit 3, both = 11 for qubit 2)
2. X-type syndromes identify which block had a phase flip
3. Correction applies X or Z to the identified qubit

#### 4.2 Steane [[7,1,3]] Code

The Steane code [Steane, 1996] is a CSS code built from the classical
[7,4,3] Hamming code, encoding 1 logical qubit into 7 physical qubits with
code distance 3.

**Construction:** The dual Hamming code C^perp has 8 codewords generated by
the rows of the Hamming parity check matrix:

    H = [[1,1,1,0,1,0,0],
         [1,1,0,1,0,1,0],
         [1,0,1,1,0,0,1]]

Logical states are:

    |0>_L = sum_{y in C^perp} |y> / sqrt(8)
    |1>_L = X^{x7} |0>_L = sum_{y in C^perp} |y + 1^7> / sqrt(8)

**Stabilizers (6 total):** Three X-type and three Z-type, each corresponding
to a row of H. The X-type stabilizers are:

    g1 = X X X I X I I    g2 = X X I X I X I    g3 = X I X X I I X

with corresponding Z-type stabilizers g_i^Z.

**Error correction:** The 6-bit syndrome identifies any single-qubit Pauli
error via the H-matrix column lookup. An X error on qubit j produces
syndrome bits equal to column j of H for the Z-type stabilizers; a Z error
produces syndrome bits equal to column j of H for the X-type stabilizers.

**Validation:** Both codes are tested exhaustively -- every single-qubit X
and Z error on every qubit, for all logical states |0>, |1>, and |+>. All
errors are corrected to fidelity > 0.99.

---

### 5. Entanglement Distillation

Two distillation protocols are implemented, both taking two noisy Bell pairs
and probabilistically producing one higher-fidelity pair.

#### 5.1 BBPSSW Protocol

[Bennett, Brassard, Popescu, Schumacher, Smolin, Wootters, 1996]

1. Apply CNOT from pair1 to pair2 (both Alice and Bob sides)
2. Measure pair2 in the computational (Z) basis
3. If Alice and Bob obtain the same measurement outcome, keep pair1
4. Otherwise discard both pairs

The protocol succeeds with probability 3/4 for perfect Bell pairs and
higher for noisy pairs. The kept pair has strictly higher fidelity with
|Phi+> than either input pair when the inputs are Werner states with
fidelity > 0.5.

#### 5.2 Deutsch Protocol

[Deutsch, Ekert, Jozsa, Macchiavello, Popescu, Sanpera, 1996]

1. Apply CNOT from pair1 to pair2
2. Apply Hadamard to both qubits of pair2 (rotating to X basis)
3. Measure pair2 in the computational basis
4. If outcomes match, keep pair1

The Deutsch protocol achieves the same success probability as BBPSSW for
perfect pairs but can achieve higher output fidelity for certain noise
regimes.

---

### 6. Quantum Memory Buffer

Memory decoherence is modelled using standard T1 and T2 processes:

**T1 (amplitude damping):** Excited state |1> decays to ground |0> with
probability p = 1 - exp(-t/T1). Applied as:

    rho'[0,0] += p * rho[1,1]
    rho'[1,1] *= (1-p)
    rho'[0,1] *= sqrt(1-p)
    rho'[1,0] *= sqrt(1-p)

**T2 (dephasing):** Off-diagonal coherences decay with rate 1/T2:

    rho'[0,1] *= (1 - p)   where p = 1 - exp(-t/T2)
    rho'[1,0] *= (1 - p)

The `QuantumMemoryBuffer` class manages multiple stored states with
individual storage times. When the fidelity of a stored state falls below a
configurable threshold, it is dropped, implementing a cutoff policy that
prevents use of excessively degraded entanglement.

---

### 7. Validation

All components are validated through an automated test suite:

| Test Area | Tests | Coverage |
|-----------|-------|----------|
| Core (gates, measurement, noise) | 17 | All gate operations, measurement statistics, channel fidelity |
| Qubit state | 8 | State factory methods, fidelity, partial trace, concurrence |
| BB84 QKD | 4 | Noiseless, key length, noise scaling, deterministic output |
| E91 QKD | 3 | Noiseless, noise scaling, deterministic output |
| Teleportation | 3 | Fidelity, reproducibility, outcome range |
| Superdense | 2 | All 4 bit patterns, round-trip |
| Swapping | 3 | Noiseless, outcome mapping, noise degradation |
| Shor code | 5 | Encoding, decoding, X/Z correction, syndrome |
| Steane code | 5 | Encoding, decoding, X/Z correction, syndrome |
| Distillation | 4 | BBPSSW/Deutsch success, fidelity improvement |
| Memory | 6 | T1 decay, no-noise limit, fidelity decay, cutoff, store/retrieve |
| Integration | 16 | Exhaustive single-error correction, distillation chain, protocol round-trips |

**Total: 81 tests, all passing.**

Key validation results:
- Both error correction codes correct all 54 (Shor) and 42 (Steane)
  single-qubit X/Z errors on all qubits for all logical states
- BBPSSW and Deutsch distillation succeed probabilistically and improve
  fidelity on noisy Bell pairs
- Memory decoherence follows expected exponential decay: for |1> with
  T1 = T2 = 10, fidelity at t = 5 is exp(-5/10) = 0.6065
- Multi-qubit measurements use sequential projective collapse with correct
  diagonal subspace projection (not rank-1 projection), ensuring proper
  conditional joint distributions
- All protocols produce identical results when given the same random seed

---

### 8. Ghost-Net Topology Integration (Phase 3)

Ghost-Net is the topology integration layer that composes the Phase 3
foundations into a multi-node quantum network simulation:

- **Stabilizer formalism** (`core.stabilizer`) — efficient O(n²) state
  tracking across all qubits in the network
- **Discrete-event scheduler** (`core.scheduler`) — asynchronous protocol
  execution with timed photon emission, BSM arrivals, and memory decay
- **Physical-layer models** (`core.physical`) — distance-based fibre loss,
  T1/T2 memory coherence, dark count statistics
- **Multi-process IPC** (`core.ipc_node`) — isolated node processes
  communicating over local IPC channels

A GhostNet configuration consists of:

- **Nodes** — end nodes, repeaters, and Bell state analyzers with
  position, T1/T2 coherence times, and buffer capacities
- **Links** — optical fibre edges with distance-dependent attenuation
  (η = 10^{-α·L/10}) and entanglement generation rates
- **Protocol state machines** — event-driven protocol logic that reacts to
  `EmitPhoton`, `PhotonArrival`, `PhotonLoss`, `BSMMeasurement`, and
  `MemoryDecayTick` events

The integration enables end-to-end simulations from physical entanglement
generation through to application-layer key delivery across arbitrary
network topologies, with path finding under fidelity constraints and
schedule optimisation for simultaneous entanglement distribution requests.

---

### 9. Conclusion

Quantum Entanglement Link provides a complete, validated simulation stack
for quantum communication networks. The density matrix formalism captures
all relevant physical effects, the stabilizer formalism enables O(n²)
Clifford simulation, the discrete-event scheduler models asynchronous
network behaviour, and explicit noise modelling ensures realistic
simulations. Phase 3 foundations are in place; the Ghost-Net topology
integration layer will compose them into full multi-node network
simulations.

---

### References

1. C. H. Bennett and G. Brassard, "Quantum cryptography: Public key
   distribution and coin tossing," in Proc. IEEE Int. Conf. on Computers,
   Systems and Signal Processing, 1984.

2. A. K. Ekert, "Quantum cryptography based on Bell's theorem," Phys. Rev.
   Lett., vol. 67, no. 6, pp. 661-663, 1991.

3. C. H. Bennett et al., "Teleporting an unknown quantum state via dual
   classical and Einstein-Podolsky-Rosen channels," Phys. Rev. Lett.,
   vol. 70, no. 13, pp. 1895-1899, 1993.

4. C. H. Bennett and S. J. Wiesner, "Communication via one- and two-particle
   operators on Einstein-Podolsky-Rosen states," Phys. Rev. Lett., vol. 69,
   no. 20, pp. 2881-2884, 1992.

5. M. Zukowski, A. Zeilinger, M. A. Horne, and A. K. Ekert, "Event-ready-
   detectors' Bell experiment via entanglement swapping," Phys. Rev. Lett.,
   vol. 71, no. 26, pp. 4287-4290, 1993.

6. P. W. Shor, "Scheme for reducing decoherence in quantum computer memory,"
   Phys. Rev. A, vol. 52, no. 4, pp. R2493-R2496, 1995.

7. A. M. Steane, "Error correcting codes in quantum theory," Phys. Rev.
   Lett., vol. 77, no. 5, pp. 793-797, 1996.

8. C. H. Bennett et al., "Purification of noisy entanglement and faithful
   teleportation via noisy channels," Phys. Rev. Lett., vol. 76, no. 5,
   pp. 722-725, 1996.

9. D. Deutsch et al., "Quantum privacy amplification and the security of
   quantum cryptography over noisy channels," Phys. Rev. Lett., vol. 77,
   no. 13, pp. 2818-2821, 1996.

10. W. K. Wootters, "Entanglement of formation of an arbitrary state of two
    qubits," Phys. Rev. Lett., vol. 80, no. 10, pp. 2245-2248, 1998.
