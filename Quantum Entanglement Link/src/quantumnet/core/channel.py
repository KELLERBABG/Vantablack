"""Quantum and classical communication channel models with distance-dependent attenuation."""

import numpy as np
from .qubit import QubitState


class Channel:
    """A quantum channel represented by a set of Kraus operators.

    Applies the CPTP map: rho' = sum_k E_k rho E_k^dag.

    Args:
        kraus_ops: List of Kraus operator matrices (as numpy arrays).
        name: Optional label.
    """
    def __init__(self, kraus_ops: list[np.ndarray], name: str = ""):
        self.kraus_ops = [np.asarray(k, dtype=complex) for k in kraus_ops]
        self.name = name

    def apply(self, state: QubitState, targets: list[int] | None = None) -> QubitState:
        """Apply the channel to a quantum state.

        Args:
            state: Input quantum state.
            targets: Optional list of target qubit indices to apply the channel
                     to a subsystem. If None, the channel is applied to the
                     full state (Kraus operators must match state dimensions).

        Returns:
            Output state after the channel.
        """
        if targets is None:
            rho = np.zeros_like(state.rho)
            for E in self.kraus_ops:
                rho += E @ state.rho @ E.conj().T
            return QubitState(rho, dims=state.dims)
        from .gate import _embed
        n = state.num_qubits
        rho = np.zeros_like(state.rho)
        for E in self.kraus_ops:
            full = _embed(E, n, targets)
            rho += full @ state.rho @ full.conj().T
        return QubitState(rho, dims=state.dims)
