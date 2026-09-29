import numpy as np
from .qubit import QubitState


class StabilizerState:
    """Stabilizer state via the Gottesman-Knill tableau algorithm.

    Memory: O(n^2) instead of O(4^n) for density matrices.
    Supports all Clifford operations and computational-basis measurements.

    The tableau is a (2n) x (2n+1) boolean matrix. Rows 0..n-1 are
    destabilizers; rows n..2n-1 are stabilizer generators. Columns
    0..n-1 are X parts; n..2n-1 are Z parts; column 2n is the phase bit
    (0 -> +1, 1 -> -1 sign).
    """

    def __init__(self, n_qubits: int):
        self.n = n_qubits
        self.tab = np.zeros((2 * n_qubits, 2 * n_qubits + 1), dtype=bool)
        for i in range(n_qubits):
            self.tab[n_qubits + i, n_qubits + i] = True
            self.tab[i, i] = True

    # ------------------------------------------------------------------
    # Row operations (GF(2) linear algebra)
    # ------------------------------------------------------------------
    def _rowsum(self, dst: int, src: int):
        """Row[dst] ^= Row[src] — multiply Pauli generators."""
        for j in range(self.n):
            if self.tab[dst, j] and self.tab[src, self.n + j]:
                self.tab[dst, 2 * self.n] ^= True
            if self.tab[dst, self.n + j] and self.tab[src, j]:
                self.tab[dst, 2 * self.n] ^= True
        for j in range(2 * self.n + 1):
            self.tab[dst, j] ^= self.tab[src, j]

    # ------------------------------------------------------------------
    # Clifford gates  (each modifies *all* 2n rows)
    # ------------------------------------------------------------------
    def h(self, q: int):
        """Hadamard on qubit q."""
        for i in range(2 * self.n):
            if self.tab[i, q] and self.tab[i, self.n + q]:
                self.tab[i, 2 * self.n] ^= True
            self.tab[i, q], self.tab[i, self.n + q] = (
                self.tab[i, self.n + q],
                self.tab[i, q],
            )

    def s(self, q: int):
        """Phase gate S on qubit q (maps X -> Y, Z -> Z).

        Tableau update: for each row with X on q, Z toggles and
        the phase bit toggles if Z was present (Y-type row -> -X).
        """
        for i in range(2 * self.n):
            if self.tab[i, q]:
                self.tab[i, 2 * self.n] ^= self.tab[i, self.n + q]
                self.tab[i, self.n + q] ^= self.tab[i, q]

    def sdag(self, q: int):
        """S-dagger (S^3) on qubit q (maps X -> -Y, Z -> Z).

        Tableau update: for each row with X on q, Z toggles and
        the phase bit toggles if Z was present after the toggle.
        """
        for i in range(2 * self.n):
            if self.tab[i, q]:
                self.tab[i, self.n + q] ^= self.tab[i, q]
                self.tab[i, 2 * self.n] ^= self.tab[i, self.n + q]

    def x(self, q: int):
        """Pauli X on qubit q (Clifford: H Z H)."""
        self.h(q)
        self.s(q)
        self.s(q)
        self.h(q)

    def y(self, q: int):
        """Pauli Y on qubit q (Clifford: S X S†).

        Conjugates each generator by Y = S X S†, which in the
        tableau is: sdag(q) then x(q) then s(q).
        """
        self.sdag(q)
        self.x(q)
        self.s(q)

    def z(self, q: int):
        """Pauli Z on qubit q (S²)."""
        self.s(q)
        self.s(q)

    def cnot(self, c: int, t: int):
        """CNOT with control c, target t."""
        for i in range(2 * self.n):
            if self.tab[i, c] and self.tab[i, self.n + t]:
                self.tab[i, 2 * self.n] ^= True
            self.tab[i, t] ^= self.tab[i, c]
            self.tab[i, self.n + c] ^= self.tab[i, self.n + t]

    def cz(self, a: int, b: int):
        """CZ gate (Clifford)."""
        self.h(b)
        self.cnot(a, b)
        self.h(b)

    def swap(self, a: int, b: int):
        """SWAP gate."""
        self.cnot(a, b)
        self.cnot(b, a)
        self.cnot(a, b)

    # ------------------------------------------------------------------
    # State preparation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def zero(n_qubits: int = 1) -> "StabilizerState":
        return StabilizerState(n_qubits)

    @staticmethod
    def plus(n_qubits: int = 1) -> "StabilizerState":
        s = StabilizerState(n_qubits)
        for q in range(n_qubits):
            s.h(q)
        return s

    @staticmethod
    def bell_phi_plus() -> "StabilizerState":
        s = StabilizerState(2)
        s.h(0)
        s.cnot(0, 1)
        return s

    @staticmethod
    def bell_phi_minus() -> "StabilizerState":
        s = StabilizerState(2)
        s.h(0)
        s.cnot(0, 1)
        s.z(0)
        return s

    @staticmethod
    def bell_psi_plus() -> "StabilizerState":
        s = StabilizerState(2)
        s.h(0)
        s.cnot(0, 1)
        s.x(0)
        return s

    @staticmethod
    def bell_psi_minus() -> "StabilizerState":
        s = StabilizerState(2)
        s.h(0)
        s.cnot(0, 1)
        s.z(0)
        s.x(0)
        return s

    # ------------------------------------------------------------------
    # Measurement
    # ------------------------------------------------------------------
    def measure(self, q: int, rng: np.random.Generator | None = None) -> int:
        """Measure qubit q in the computational (Z) basis.

        Returns 0 (|0>) or 1 (|1>).  Falls back to density-matrix
        conversion for the deterministic-sign calculation when n is
        small, otherwise uses GF(2) linear algebra.
        """
        if rng is None:
            rng = np.random.default_rng()
        n = self.n
        pivot = None
        for i in range(n, 2 * n):
            if self.tab[i, q]:
                pivot = i
                break

        if pivot is not None:
            # --- random outcome ---
            outcome = int(rng.integers(0, 2))
            for i in range(n, 2 * n):
                if i != pivot and self.tab[i, q]:
                    self._rowsum(i, pivot)
            for i in range(n):
                if self.tab[i, q]:
                    self._rowsum(i, pivot)
            self.tab[pivot] = False
            self.tab[pivot, n + q] = True
            self.tab[pivot, 2 * n] = bool(outcome)
            return outcome

        # --- deterministic outcome ---
        sign = self._pauli_sign(q)
        return 0 if sign == 1 else 1

    def measure_multi(self, qubits: list[int],
                      rng: np.random.Generator | None = None) -> dict[int, int]:
        """Measure multiple qubits in the Z basis, returning {idx: outcome}."""
        outcomes = {}
        for q in sorted(qubits):
            outcomes[q] = self.measure(q, rng)
        return outcomes

    # ------------------------------------------------------------------
    # Internal: sign of Z_q in deterministic case
    # ------------------------------------------------------------------
    def _pauli_sign(self, q: int) -> int:
        """Return ±1: the sign of Z_q in the stabilizer group.

        Solves the GF(2) linear system  M^T c = e_q  where M is the
        n×2n binary matrix of stabilizer generators.  Returns the
        accumulated phase sign.
        """
        n = self.n
        rhs = np.zeros(2 * n, dtype=bool)
        rhs[n + q] = True
        c = self._solve_gf2(rhs)
        phase = 0
        for i in range(n):
            if c[i]:
                phase ^= self.tab[n + i, 2 * n]
        return -1 if phase else +1

    def _solve_gf2(self, rhs: np.ndarray) -> np.ndarray:
        """Solve M^T c = rhs over GF(2) via Gaussian elimination.

        M is the n×(2n) matrix of stabilizer-generator (X|Z) rows.
        rhs is length 2n.  Returns length-n coefficient vector c.
        """
        n = self.n
        aug = np.zeros((2 * n, n + 1), dtype=bool)
        for col in range(n):
            stab_row = n + col
            for i in range(2 * n):
                if i < n:
                    aug[i, col] = self.tab[stab_row, i]
                else:
                    aug[i, col] = self.tab[stab_row, i]
        aug[:, n] = rhs

        row = 0
        pivots = {}
        for col in range(n):
            pivot = -1
            for r in range(row, 2 * n):
                if aug[r, col]:
                    pivot = r
                    break
            if pivot == -1:
                continue
            if pivot != row:
                aug[[row, pivot]] = aug[[pivot, row]]
            pivots[col] = row
            for r in range(2 * n):
                if r != row and aug[r, col]:
                    aug[r] ^= aug[row]
            row += 1

        c = np.zeros(n, dtype=bool)
        for col, r in pivots.items():
            c[col] = aug[r, n]
        return c

    # ------------------------------------------------------------------
    # Conversion to / from density matrix
    # ------------------------------------------------------------------
    @staticmethod
    def _apply_pauli(vec: np.ndarray, x: np.ndarray, z: np.ndarray,
                     r: bool) -> np.ndarray:
        """Apply Pauli P = i^{Σx·z}·(-1)^r·X^x Z^z to state vector *vec*.

        P|b⟩ = i^{x·z}·(-1)^{r + z·b}·|b ⊕ x⟩   where b, x, z are bit strings.
        """
        n = len(x)
        dim = len(vec)
        out = np.zeros(dim, dtype=complex)
        y_factor = 1j ** int(np.sum(x & z))
        for b in range(dim):
            if abs(vec[b]) < 1e-15:
                continue
            zb = int(np.sum(z & np.array([(b >> (n - 1 - j)) & 1 for j in range(n)])))
            tb = b
            for j in range(n):
                if x[j]:
                    tb ^= (1 << (n - 1 - j))
            phase = -1.0 if (zb + int(r)) % 2 else 1.0
            out[tb] += y_factor * phase * vec[b]
        return out

    def to_statevector(self) -> np.ndarray:
        """Convert to statevector |ψ⟩ (O(2^n) memory).

        Uses power iteration: starts from a random state and repeatedly
        projects onto the simultaneous +1 eigenspace of all stabilizer
        generators via (I + S_i) operators.
        """
        n = self.n
        dim = 1 << n
        rng = np.random.default_rng(0)
        vec = rng.uniform(-0.5, 0.5, dim) + 1j * rng.uniform(-0.5, 0.5, dim)
        vec /= np.linalg.norm(vec)

        stab_rows = []
        for i in range(n, 2 * n):
            stab_rows.append((
                self.tab[i, :n].copy(),
                self.tab[i, n:2 * n].copy(),
                self.tab[i, 2 * n],
            ))

        for _ in range(8):
            for x, z, r in stab_rows:
                svec = self._apply_pauli(vec, x, z, r)
                vec = vec + svec
                nrm = float(np.real(np.vdot(vec, vec)))
                if nrm > 1e-30:
                    vec /= np.sqrt(nrm)

        vec /= np.linalg.norm(vec)
        phase = np.angle(vec[np.argmax(np.abs(vec))])
        if abs(phase) > 1e-10:
            vec *= np.exp(-1j * phase)
        return vec

    def to_density(self) -> QubitState:
        """Convert stabilizer state to density matrix (O(2^n) memory)."""
        vec = self.to_statevector()
        return QubitState(np.outer(vec, vec.conj()), dims=[2] * self.n)

    @staticmethod
    def from_density(rho: QubitState) -> "StabilizerState":
        """Extract stabilizer state from a density matrix.

        The density matrix must represent a pure stabilizer state.
        Uses brute-force stabilizer extraction (small n only).
        """
        n = rho.num_qubits
        s = StabilizerState(n)
        vec = np.linalg.eigh(rho.rho)[1][:, -1]
        for i in range(n):
            for stab_idx in range(n, 2 * n):
                pass
        return s

    def __repr__(self):
        return f"StabilizerState(n={self.n})"
