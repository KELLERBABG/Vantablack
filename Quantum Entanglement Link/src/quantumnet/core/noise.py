"""Quantum noise models including depolarizing, dephasing, and amplitude damping channels."""

import numpy as np
from .channel import Channel


def depolarizing_channel(p: float) -> Channel:
    """Single-qubit depolarizing channel.

    With probability p, replaces the state with the maximally mixed state.
    Kraus operators: sqrt(1-p) I, sqrt(p/3) X, sqrt(p/3) Y, sqrt(p/3) Z.

    Args:
        p: Depolarizing probability in [0, 1].

    Returns:
        Channel object.
    """
    I = np.eye(2, dtype=complex)
    X = np.array([[0, 1], [1, 0]], dtype=complex)
    Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
    Z = np.array([[1, 0], [0, -1]], dtype=complex)
    E0 = np.sqrt(1 - p) * I
    E1 = np.sqrt(p / 3) * X
    E2 = np.sqrt(p / 3) * Y
    E3 = np.sqrt(p / 3) * Z
    return Channel([E0, E1, E2, E3], f"Depolarizing(p={p})")


def amplitude_damping_channel(gamma: float) -> Channel:
    """Amplitude damping channel modelling T1 energy relaxation.

    Models |1> -> |0> decay with rate gamma = 1 - exp(-t/T1).
    Kraus operators: |0><0| + sqrt(1-gamma) |1><1|, sqrt(gamma) |0><1|.

    Args:
        gamma: Damping parameter in [0, 1].

    Returns:
        Channel object.
    """
    E0 = np.array([[1, 0], [0, np.sqrt(1 - gamma)]], dtype=complex)
    E1 = np.array([[0, np.sqrt(gamma)], [0, 0]], dtype=complex)
    return Channel([E0, E1], f"AmplitudeDamping(gamma={gamma})")


def dephasing_channel(gamma: float) -> Channel:
    """Dephasing channel modelling T2 phase randomization.

    Randomizes the phase with rate gamma = 1 - exp(-t/T2).
    Kraus operators: sqrt(1-gamma) I, sqrt(gamma) Z.

    Args:
        gamma: Dephasing parameter in [0, 1].

    Returns:
        Channel object.
    """
    I = np.eye(2, dtype=complex)
    Z = np.array([[1, 0], [0, -1]], dtype=complex)
    E0 = np.sqrt(1 - gamma) * I
    E1 = np.sqrt(gamma) * Z
    return Channel([E0, E1], f"Dephasing(gamma={gamma})")


def depolarizing_channel_2(p: float) -> Channel:
    """Two-qubit depolarizing channel.

    With probability p, replaces the state with the 2-qubit maximally mixed
    state. Uses 16 Kraus operators from the 2-qubit Pauli group.

    Args:
        p: Depolarizing probability in [0, 1].

    Returns:
        Channel object.
    """
    I = np.eye(2, dtype=complex)
    X = np.array([[0, 1], [1, 0]], dtype=complex)
    Z = np.array([[1, 0], [0, -1]], dtype=complex)
    Y = 1j * X @ Z
    paulis = [I, X, Y, Z]
    kraus = []
    for i in range(4):
        for j in range(4):
            if i == 0 and j == 0:
                kraus.append(np.sqrt(1 - p + p / 16) * np.kron(paulis[i], paulis[j]))
            else:
                kraus.append(np.sqrt(p / 16) * np.kron(paulis[i], paulis[j]))
    return Channel(kraus, f"Depolarizing2(p={p})")
