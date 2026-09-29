"""Standard quantum unitary gates, Pauli operators, and multi-qubit tensor products."""

import numpy as np
from .qubit import QubitState


class Gate:
    """A quantum gate represented by its matrix.

    Gates can be composed via @ (matrix multiplication) and tensor(kron).
    The conjugate transpose is available via .dag.

    Args:
        matrix: The gate matrix (complex).
        name: Optional label for display.
    """
    def __init__(self, matrix: np.ndarray, name: str = ""):
        self.matrix = np.asarray(matrix, dtype=complex)
        self.name = name

    def __repr__(self):
        return f"Gate({self.name or 'custom'})"

    @property
    def dag(self):
        """Conjugate transpose (adjoint) of this gate."""
        return Gate(self.matrix.conj().T, f"{self.name}*")

    def __matmul__(self, other: "Gate") -> "Gate":
        """Matrix multiplication: self @ other."""
        return Gate(self.matrix @ other.matrix, f"{self.name}@{other.name}")

    def tensor(self, other: "Gate"):
        """Tensor product: self (x) other."""
        return Gate(np.kron(self.matrix, other.matrix), f"{self.name}(x){other.name}")


# Single-qubit Pauli gates
I = Gate(np.eye(2, dtype=complex), "I")
X = Gate(np.array([[0, 1], [1, 0]], dtype=complex), "X")
Y = Gate(np.array([[0, -1j], [1j, 0]], dtype=complex), "Y")
Z = Gate(np.array([[1, 0], [0, -1]], dtype=complex), "Z")

# Hadamard, phase, and T gates
H = Gate(np.array([[1, 1], [1, -1]], dtype=complex) / np.sqrt(2), "H")
S = Gate(np.array([[1, 0], [0, 1j]], dtype=complex), "S")
T = Gate(np.array([[1, 0], [0, np.exp(1j * np.pi / 4)]], dtype=complex), "T")

# Two-qubit gates
CNOT = Gate(np.array([[1, 0, 0, 0],
                       [0, 1, 0, 0],
                       [0, 0, 0, 1],
                       [0, 0, 1, 0]], dtype=complex), "CNOT")
SWAP = Gate(np.array([[1, 0, 0, 0],
                       [0, 0, 1, 0],
                       [0, 1, 0, 0],
                       [0, 0, 0, 1]], dtype=complex), "SWAP")
CZ = Gate(np.array([[1, 0, 0, 0],
                     [0, 1, 0, 0],
                     [0, 0, 1, 0],
                     [0, 0, 0, -1]], dtype=complex), "CZ")


def _bits_to_int(bits: list[int]) -> int:
    """Convert a list of bits (MSB first) to an integer."""
    return sum(b << (len(bits) - 1 - i) for i, b in enumerate(bits))


def _int_to_bits(val: int, n: int) -> list[int]:
    """Convert an integer to a list of n bits (MSB first)."""
    return [(val >> (n - 1 - i)) & 1 for i in range(n)]


def _embed(gate_mat: np.ndarray, n_qubits: int, targets: list[int]) -> np.ndarray:
    """Embed a gate matrix into the full n-qubit Hilbert space.

    Constructs the operator that applies `gate_mat` to the specified target
    qubits and identity to all others.

    Args:
        gate_mat: The gate matrix (2^m x 2^m for m target qubits).
        n_qubits: Total number of qubits in the system.
        targets: List of target qubit indices.

    Returns:
        2^n x 2^n matrix acting on the full space.
    """
    d = 2 ** n_qubits
    m = len(targets)
    full = np.zeros((d, d), dtype=complex)
    for i in range(d):
        i_bits = _int_to_bits(i, n_qubits)
        for j in range(d):
            j_bits = _int_to_bits(j, n_qubits)
            ok = True
            for k in range(n_qubits):
                if k not in targets and i_bits[k] != j_bits[k]:
                    ok = False
                    break
            if not ok:
                continue
            ti_bits = [i_bits[t] for t in targets]
            tj_bits = [j_bits[t] for t in targets]
            ti_idx = _bits_to_int(ti_bits)
            tj_idx = _bits_to_int(tj_bits)
            full[i, j] = gate_mat[ti_idx, tj_idx]
    return full


def apply(gate: Gate, state: QubitState, targets: list[int]) -> QubitState:
    """Apply a gate to a quantum state on specified target qubits.

    Embeds the gate into the full Hilbert space and updates the density matrix:
    rho' = U rho U^dag.

    Args:
        gate: The gate to apply.
        state: The quantum state.
        targets: Qubit indices the gate acts on.

    Returns:
        New QubitState after applying the gate.
    """
    full = _embed(gate.matrix, state.num_qubits, targets)
    new_rho = full @ state.rho @ full.conj().T
    return QubitState(new_rho, dims=state.dims)


def tensor_product(gates: list[Gate]) -> Gate:
    """Compute the tensor product of a list of gates."""
    mat = gates[0].matrix
    for g in gates[1:]:
        mat = np.kron(mat, g.matrix)
    return Gate(mat)
