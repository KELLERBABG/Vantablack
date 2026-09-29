import numpy as np


class QubitState:
    """Quantum state represented as a density matrix.

    Stores an n-qubit density matrix rho (2^n x 2^n complex) with dimension
    metadata for subsystem tracking. Supports fidelity, purity, concurrence,
    and partial trace operations.

    Args:
        rho: Density matrix (2^n x 2^n complex array).
        dims: List of subsystem dimensions, e.g. [2, 2] for 2 qubits.
              Defaults to [2] for single-qubit or [2, 2] for 4x4 matrices.
    """
    def __init__(self, rho: np.ndarray, dims: list[int] | None = None):
        rho = np.asarray(rho, dtype=complex)
        n = rho.shape[0]
        if dims is None:
            dims = [int(n ** 0.5)] * 2 if n == 4 else [2]
        self._rho = rho
        self.dims = dims

    @property
    def rho(self) -> np.ndarray:
        """The density matrix."""
        return self._rho

    @property
    def num_qubits(self) -> int:
        """Number of qubits in this system."""
        return len(self.dims)

    @property
    def is_pure(self) -> bool:
        """True if Tr(rho^2) is approximately 1."""
        return np.isclose(np.trace(self._rho @ self._rho), 1.0)

    @staticmethod
    def zero() -> "QubitState":
        """|0><0| -- ground state."""
        return QubitState(np.array([[1, 0], [0, 0]], dtype=complex))

    @staticmethod
    def one() -> "QubitState":
        """|1><1| -- excited state."""
        return QubitState(np.array([[0, 0], [0, 1]], dtype=complex))

    @staticmethod
    def plus() -> "QubitState":
        """|+><+| = (|0> + |1>)(<0| + <1|)/2."""
        v = np.array([1, 1], dtype=complex) / np.sqrt(2)
        return QubitState(np.outer(v, v.conj()))

    @staticmethod
    def minus() -> "QubitState":
        """|-><-| = (|0> - |1>)(<0| - <1|)/2."""
        v = np.array([1, -1], dtype=complex) / np.sqrt(2)
        return QubitState(np.outer(v, v.conj()))

    @staticmethod
    def bell_phi_plus() -> "QubitState":
        """|Phi+><Phi+| = (|00> + |11>)(<00| + <11|)/2."""
        v = np.array([1, 0, 0, 1], dtype=complex) / np.sqrt(2)
        return QubitState(np.outer(v, v.conj()), dims=[2, 2])

    @staticmethod
    def bell_phi_minus() -> "QubitState":
        """|Phi-><Phi-| = (|00> - |11>)(<00| - <11|)/2."""
        v = np.array([1, 0, 0, -1], dtype=complex) / np.sqrt(2)
        return QubitState(np.outer(v, v.conj()), dims=[2, 2])

    @staticmethod
    def bell_psi_plus() -> "QubitState":
        """|Psi+><Psi+| = (|01> + |10>)(<01| + <10|)/2."""
        v = np.array([0, 1, 1, 0], dtype=complex) / np.sqrt(2)
        return QubitState(np.outer(v, v.conj()), dims=[2, 2])

    @staticmethod
    def bell_psi_minus() -> "QubitState":
        """|Psi-><Psi-| = (|01> - |10>)(<01| - <10|)/2."""
        v = np.array([0, 1, -1, 0], dtype=complex) / np.sqrt(2)
        return QubitState(np.outer(v, v.conj()), dims=[2, 2])

    @staticmethod
    def maximally_mixed(n_qubits: int = 1) -> "QubitState":
        """I/2^n -- maximally mixed state on n qubits."""
        d = 2 ** n_qubits
        return QubitState(np.eye(d, dtype=complex) / d, dims=[2] * n_qubits)

    def fidelity(self, other: "QubitState") -> float:
        """Uhlmann-Jozsa fidelity F(rho, sigma) = [Tr(sqrt(sqrt(rho) sigma sqrt(rho)))]^2.

        Uses eigenvalue decomposition for matrix square roots. Returns a value
        in [0, 1] where 1 indicates identical states.

        Args:
            other: The target state to compare against.

        Returns:
            Fidelity in [0, 1].
        """
        evals, evecs = np.linalg.eigh(self._rho)
        sqrt_rho = evecs @ np.diag(np.sqrt(np.maximum(evals, 0))) @ evecs.conj().T
        mid = sqrt_rho @ other._rho @ sqrt_rho
        evals_mid, evecs_mid = np.linalg.eigh(mid)
        sqrt_mid = evecs_mid @ np.diag(np.sqrt(np.maximum(evals_mid, 0))) @ evecs_mid.conj().T
        return float(np.real(np.trace(sqrt_mid) ** 2))

    def partial_trace(self, keep: int, dims: list[int] | None = None) -> "QubitState":
        """Trace out the last n-keep subsystems.

        Reshapes the density matrix into (d_0...d_{k-1}) x (d_k...d_{n-1}) block
        form and traces over the second axis.

        Args:
            keep: Number of subsystems to keep (traces out the rest).
            dims: Subsystem dimensions. Defaults to self.dims.

        Returns:
            QubitState on the first `keep` subsystems.
        """
        dims = dims or self.dims
        k = np.prod([dims[i] for i in range(keep)])
        l = np.prod([dims[i] for i in range(keep, len(dims))])
        rho = self._rho.reshape(k, l, k, l)
        traced = np.trace(rho, axis1=1, axis2=3)
        return QubitState(traced, dims=dims[:keep])

    def purity(self) -> float:
        """Tr(rho^2). Equals 1 for pure states, < 1 for mixed states."""
        return float(np.real(np.trace(self._rho @ self._rho)))

    def concurrence(self) -> float:
        """Wootters concurrence for 2-qubit states.

        Measures entanglement: C = 0 for separable, C = 1 for maximally entangled.
        Defined only for 2-qubit states.

        Raises:
            ValueError: If the state is not a 2-qubit state.
        """
        if self.num_qubits != 2:
            raise ValueError("Concurrence is only defined for 2-qubit states")
        pauli = np.array([[0, 0, 0, -1j],
                          [0, 0, 1j, 0],
                          [0, 1j, 0, 0],
                          [-1j, 0, 0, 0]])
        rho_tilde = pauli @ self._rho.conj() @ pauli
        lam = np.sort(np.abs(np.linalg.eigvals(self._rho @ rho_tilde)))
        return max(0.0, float(np.real(lam[-1] - lam[-2] - lam[-3] - lam[-4])))
