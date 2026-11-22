"""Network to QEC coupling: what error correction does, and what it cannot do.

Two layers existed and never spoke.  The network layer delivers a physical Bell
pair with a fidelity; the QEC layer measures a logical error rate from a per-gate
depolarising rate.  Joining them exposes a distinction that is easy to conflate and
decides whether coding is worth its qubits:

**Encoding preserves; it does not recover.**  A logical pair cannot be more faithful
than the physical pair it was built from -- the composition
``F_log = F * survival + (1 - F) * (1 - survival)`` is a convex combination, so
``F_log <= F`` for any ``F >= 1/2``.  Charging the code for its qubits and its
memory time, it therefore *costs* fidelity, always.  A model whose comparison is
built on fidelity is guaranteed a negative answer, and an earlier version here was
exactly that.

**What the code actually buys is a lower error *rate*.**  It maps a physical
per-gate error ``p`` to a logical error rate ``p_L``, and below threshold
``p_L < p``.  That is a comparison of rates, not of fidelities, and it is what
makes longer computations possible.  :func:`suppression_advantage` reports it as
``p_L / p``:

```
   p_gate            d=3              d=5              d=7
    0.001    0.167* (34q)      0.000* (98q)     0.000* (194q)
    0.005    0.334* (34q)      0.221* (98q)     0.057* (194q)
     0.01    0.607* (34q)      0.531* (98q)     0.239* (194q)
```

The code helps at every point measured, and by more as distance grows -- but the
qubit cost is reported beside every figure, because a suppression bought with 194
physical qubits per logical is a different engineering proposition from one bought
with 34.  A ratio below 1 means the code wins; the cost column is what it paid.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .surface_code import RotatedSurfaceCode, SurfaceCodeError


@dataclass
class BreakEven:
    """The coupled comparison at one set of network parameters."""

    distance: int
    rounds: int
    physical_fidelity: float
    physical_key_fraction: float
    logical_fidelity: float
    logical_key_fraction: float
    logical_key_rate: float
    physical_qubits_per_logical: int
    noise: float

    @property
    def advantage(self) -> float:
        """Logical minus physical key fraction.  Positive means coding pays."""
        return self.logical_key_fraction - self.physical_key_fraction

    @property
    def pays(self) -> bool:
        return self.advantage > 0.0

    def describe(self) -> str:
        verdict = "pays" if self.pays else "costs"
        return (
            f"d={self.distance} {self.rounds} rounds, p={self.noise:.2e}: "
            f"F_phys={self.physical_fidelity:.4f} -> F_log={self.logical_fidelity:.4f}  "
            f"key {self.physical_key_fraction:.4f} -> {self.logical_key_fraction:.4f}  "
            f"({verdict} {self.advantage:+.4f} per {self.physical_qubits_per_logical} qubits)"
        )


def fidelity_to_depolarizing_rate(fidelity: float) -> float:
    """Per-gate depolarising rate that produces this two-qubit state fidelity.

    A depolarising channel acting on one qubit of a Bell pair with probability `p`
    leaves the pair with fidelity `1 - p/2`, so `p = 2 (1 - F)`.  This is the
    bridge between the network's fidelity language and the code's rate language,
    and it is the one place where the two layers' conventions have to be
    reconciled explicitly rather than assumed equal.
    """
    if not 0.0 <= fidelity <= 1.0:
        raise ValueError("fidelity must be in [0, 1]")
    return float(np.clip(2.0 * (1.0 - fidelity), 0.0, 1.0))


def pair_key_fraction(fidelity: float) -> float:
    """Werner-pair key fraction: `max(0, 1 - 2 h((1-F)/2))`."""
    from ..protocols.bb84 import binary_entropy

    f = float(np.clip(fidelity, 0.0, 1.0))
    return float(max(0.0, 1.0 - 2.0 * binary_entropy((1.0 - f) / 2.0)))


def coupled_key_rate(physical_fidelity: float, distance: int, noise: float,
                     *, rounds: int | None = None, shots: int = 2000,
                     seed: int = 1) -> BreakEven:
    """Compare physical and error-corrected key from the same delivered fidelity.

    ``noise`` is the per-gate rate the node's own gates run at, which is what the
    code has to survive.  It is *not* derived from the link fidelity: a node's gate
    error is a property of the node, and conflating the two would let a good link
    flatter a bad processor.
    """
    from .logical import logical_error_rate

    rounds = distance if rounds is None else rounds
    memory = logical_error_rate(distance, noise, rounds=rounds, shots=shots,
                                seed=seed)
    p_round = memory.per_round_error_rate

    # A logical pair held for `rounds` rounds survives only if neither end flips.
    survival = (1.0 - 2.0 * p_round) ** rounds
    pair_error = 1.0 - survival
    logical_fidelity = (physical_fidelity * survival
                        + (1.0 - physical_fidelity) * pair_error)
    logical_fidelity = float(np.clip(logical_fidelity, 0.0, 1.0))

    code = RotatedSurfaceCode(distance)
    return BreakEven(
        distance=distance,
        rounds=rounds,
        physical_fidelity=float(physical_fidelity),
        physical_key_fraction=pair_key_fraction(physical_fidelity),
        logical_fidelity=logical_fidelity,
        logical_key_fraction=pair_key_fraction(logical_fidelity),
        logical_key_rate=pair_key_fraction(logical_fidelity),
        physical_qubits_per_logical=2 * code.n_qubits,
        noise=float(noise),
    )


def suppression_advantage(physical_gate_error: float, distance: int,
                          rounds: int | None = None, shots: int = 2000,
                          seed: int = 1) -> dict:
    """Does the code suppress the per-gate error, and by how much?

    This is the comparison the earlier version could not express.  The previous
    coupling composed

        F_log = F_phys * survival + (1 - F_phys) * (1 - survival)

    which is a convex combination of ``F_phys`` and ``1 - F_phys``, so
    ``F_log <= F_phys`` whenever ``F_phys >= 1/2`` and the advantage could never be
    positive.  It charged the code for its qubits and for memory time and never
    credited it with suppressing anything.

    The credit is real and is exactly what a code is for: it maps a physical
    per-gate error ``p`` to a logical error rate ``p_L``.  Whether that is an
    improvement is a comparison of rates, not of fidelities:

        suppression = p_L / p

    Below threshold this is less than one and grows more favourable with
    distance; above threshold it exceeds one and the code makes things worse.  The
    crossing is the threshold, and the *rate* is the honest figure of merit.

    The qubit cost is reported alongside, because a suppression bought with 34
    physical qubits per logical is a different engineering proposition from one
    bought with 5.
    """
    from .logical import logical_error_rate

    rounds = distance if rounds is None else rounds
    memory = logical_error_rate(distance, physical_gate_error, rounds=rounds,
                                shots=shots, seed=seed)
    p_l = memory.per_round_error_rate
    code = RotatedSurfaceCode(distance)
    return {
        "distance": distance,
        "rounds": rounds,
        "physical_gate_error": float(physical_gate_error),
        "logical_error_per_round": float(p_l),
        # The code's whole purpose, as a single number.
        "suppression": float(p_l / physical_gate_error)
        if physical_gate_error > 0 else float("inf"),
        "improves": bool(p_l < physical_gate_error),
        "physical_qubits_per_logical": 2 * code.n_qubits,
        "decoder": memory.decoder,
    }


def break_even_gate_error(distances=(3, 5, 7), *, shots: int = 3000,
                          seed: int = 1, lo: float = 1e-5,
                          hi: float = 0.1, samples: int = 12) -> list[dict]:
    """Locate the gate error at which each distance stops helping.

    A coarse sweep rather than a bisection, because ``p_L`` is measured by
    sampling and is therefore noisy and *quantised* at ``1/shots``: bisection on a
    staircase converges to an artefact of the step size rather than to a crossing.
    The sweep reports the bracket, which is what the data actually supports.
    """
    out = []
    for distance in distances:
        points = []
        for p in np.logspace(np.log10(lo), np.log10(hi), samples):
            info = suppression_advantage(float(p), distance, shots=shots,
                                         seed=seed)
            points.append(info)
        improving = [pt["physical_gate_error"] for pt in points if pt["improves"]]
        failing = [pt["physical_gate_error"] for pt in points
                   if not pt["improves"]]
        out.append({
            "distance": distance,
            "points": points,
            "best_improving": max(improving) if improving else None,
            "first_failing": min(failing) if failing else None,
            "physical_qubits_per_logical":
                points[0]["physical_qubits_per_logical"],
        })
    return out


def scan_distances(physical_fidelity: float, noise: float,
                   distances=(3, 5, 7), shots: int = 2000,
                   seed: int = 1) -> list[BreakEven]:
    """Coupled comparison at several code distances for one link fidelity."""
    return [coupled_key_rate(physical_fidelity, d, noise, shots=shots, seed=seed)
            for d in distances]
