"""Physical-layer realistic impairment models.

Maps hardware metrics (fiber attenuation, detector dark counts, T1/T2
memory lifetimes, pulse repetition rates) to quantum-channel parameters.

References
----------
- Fiber transmissivity:   η = 10^(-α·L/10)
- Dark-count probability: p_dc = 1 - exp(-R_dc · τ)
- T1 decay:              p_decay = 1 - exp(-Δt / T1)
- T2 dephasing:          p_dephase = 1 - exp(-Δt / T2)
"""

import numpy as np

# Common fibre parameters
FIBER_ATTENUATION_1550 = 0.2  # dB / km at 1550 nm
FIBER_ATTENUATION_1310 = 0.35  # dB / km at 1310 nm
FIBER_ATTENUATION_850 = 2.0  # dB / km at 850 nm


def fiber_transmissivity(length_km: float, alpha_db_km: float = 0.2) -> float:
    """Transmissivity η ∈ [0, 1] over a fibre of length L at loss α."""
    return 10.0 ** (-alpha_db_km * length_km / 10.0)


def fiber_loss_db(length_km: float, alpha_db_km: float = 0.2) -> float:
    """Total loss in dB over the fibre."""
    return alpha_db_km * length_km


def dark_count_probability(dark_count_rate_hz: float,
                           detection_window_s: float) -> float:
    """Probability of at least one dark count in a detection window."""
    return 1.0 - np.exp(-dark_count_rate_hz * detection_window_s)


def t1_decay_probability(delta_t: float, t1: float) -> float:
    """Probability that a |1⟩ decays to |0⟩ after time Δt."""
    return 1.0 - np.exp(-delta_t / t1) if t1 > 0 else 0.0


def t2_dephase_probability(delta_t: float, t2: float) -> float:
    """Probability of complete dephasing after time Δt."""
    return 1.0 - np.exp(-delta_t / t2) if t2 > 0 else 0.0


def memory_fidelity_after_dt(f0: float, delta_t: float,
                             t1: float, t2: float) -> float:
    """Fidelity of a stored **single qubit** after storage time Δt.

    Uses a simple exponential decay model:
      F(t) = 1 - (1 - f0) * (2 - exp(-Δt/T1) - exp(-Δt/T2)) / 2

    The asymptote is 0, which is correct here: for a single qubit, complete
    decay leaves the maximally mixed state ``I/2``, and ``<ψ|I/2|ψ> = 1/2`` for
    a *pure* state... but ``f0`` here is the fidelity of a state that has
    already lost purity, and the model is the standard exponential relaxation
    to zero used throughout this module.

    .. warning::
       **This is not the right function for a stored entangled pair.** A
       two-qubit Bell pair under memory noise has fidelity asymptoting to
       ``1/4`` (the overlap of any Bell state with ``I/4``), not 0.  Using this
       function there makes low-fidelity pairs *gain* fidelity as they age,
       because it extrapolates below the 0.25 floor.  For pairs, use
       :func:`bell_pair_fidelity_after_dt`.
    """
    if t1 <= 0 and t2 <= 0:
        return f0
    decay_t1 = 0.0 if t1 <= 0 else 1.0 - np.exp(-delta_t / t1)
    decay_t2 = 0.0 if t2 <= 0 else 1.0 - np.exp(-delta_t / t2)
    return f0 - (1.0 - f0) * (decay_t1 + decay_t2) * 0.5


def bell_pair_fidelity_after_dt(f0: float, delta_t: float,
                               t1: float, t2: float) -> float:
    """Fidelity of a stored **entangled pair** after storage time Δt.

    A Werner state ``W|Φ+><Φ+| + (1-W) I/4`` has fidelity ``F = (1+3W)/4`` with
    the target Bell state, and memory noise multiplies the Werner parameter:

        W(t) = W0 * exp(-Δt/T1) * exp(-Δt/T2)
        F(t) = (1 + 3*W(t)) / 4

    Two properties matter, and the single-qubit function above has neither:

    * **The floor is 1/4, not 0.**  ``I/4`` has overlap 1/4 with every Bell
      state, so no amount of memory noise can push a pair's fidelity below 1/4.
      A model that allows it is unphysical, and because the extrapolation is
      linear it makes badly-degraded pairs appear to *improve* with age.
    * **It composes with swapping.**  The same ``W`` is what
      :func:`~quantumnet.topology.routing.swapped_fidelity` multiplies, so decay
      and entanglement swapping are expressed in one consistent parameter.

    Memory noise is treated as independent per qubit, which is why the two decay
    factors multiply.  ``T2 <= 2*T1`` holds for any physical system; the
    function does not enforce it, because a caller-supplied preset may be
    approximate.
    """
    f0 = float(np.clip(f0, 0.0, 1.0))
    w0 = (4.0 * f0 - 1.0) / 3.0
    if w0 <= 0.0:
        return 0.25
    if t1 <= 0 and t2 <= 0:
        return f0
    survival = 1.0
    if t1 > 0:
        survival *= float(np.exp(-delta_t / t1))
    if t2 > 0:
        survival *= float(np.exp(-delta_t / t2))
    return (1.0 + 3.0 * w0 * survival) / 4.0


def entanglement_generation_rate(pulse_rate_hz: float,
                                 fiber_length_km: float,
                                 alpha_db_km: float = 0.2,
                                 detector_efficiency: float = 0.8) -> float:
    """Mean successful entanglement attempts per second.

    Assumes a single-photon scheme where success requires photon
    transmission through the fibre and detection at both ends.
    """
    eta = fiber_transmissivity(fiber_length_km, alpha_db_km)
    p_success = (detector_efficiency * eta) ** 2
    return pulse_rate_hz * p_success


def snr_for_distance(length_km: float,
                     alpha_db_km: float = 0.2,
                     dark_count_rate_hz: float = 10.0,
                     detector_efficiency: float = 0.8,
                     pulse_energy: float = 1.0) -> float:
    """Single-photon signal-to-noise ratio estimate at receiver."""
    eta = fiber_transmissivity(length_km, alpha_db_km)
    signal = pulse_energy * eta * detector_efficiency
    noise = dark_count_rate_hz * 1e-9
    return signal / max(noise, 1e-30)


# Channel parameter construction from hardware specs
def depolarizing_from_distance(length_km: float,
                               alpha_db_km: float = 0.2,
                               dark_count_rate_hz: float = 10.0,
                               pulse_rate_hz: float = 1e8,
                               detector_efficiency: float = 0.8) -> float:
    """Effective depolarising probability for a fibre link."""
    eta = fiber_transmissivity(length_km, alpha_db_km)
    p_dc = dark_count_probability(dark_count_rate_hz, 1.0 / pulse_rate_hz)
    p_loss = 1.0 - eta * detector_efficiency
    return min(1.0, p_loss + p_dc - p_loss * p_dc)


def amplitude_damping_from_t1(delta_t: float, t1: float) -> float:
    """γ parameter for amplitude-damping channel given storage time."""
    return t1_decay_probability(delta_t, t1)


def dephasing_from_t2(delta_t: float, t2: float) -> float:
    """γ parameter for dephasing channel given storage time."""
    return t2_dephase_probability(delta_t, t2)
