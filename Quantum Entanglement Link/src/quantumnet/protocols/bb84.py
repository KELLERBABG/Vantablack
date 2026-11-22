"""BB84 quantum key distribution (QKD).

Two levels live here:

* :func:`run_bb84` -- a density-matrix simulation of the protocol, qubit by
  qubit, with an intercept-resend eavesdropper expressed as a channel.
* :func:`run_bb84_decoy` -- the *analytic* decoy-state key-rate calculation on
  a lossy optical link.  No qubits are simulated here; this is the standard
  closed-form analysis that the QKD literature reports, and it is what makes a
  quoted key rate defensible against a photon-number-splitting attack.

References
----------
* C. H. Bennett and G. Brassard, "Quantum cryptography: public key
  distribution and coin tossing", Proc. IEEE Int. Conf. on Computers, Systems
  and Signal Processing, 175-179 (1984).
* H.-K. Lo, X. Ma, K. Chen, "Decoy state quantum key distribution",
  Phys. Rev. Lett. 94, 230504 (2005).  arXiv:quant-ph/0411004
* X. Ma, B. Qi, Y. Zhao, H.-K. Lo, "Practical decoy state for quantum key
  distribution", Phys. Rev. A 72, 012326 (2005).  arXiv:quant-ph/0503005
  -- the GLLP rate (their Eq. 1), the gain/QBER model (Eqs. 10-11), and the
  vacuum+weak estimators ``Y1_lower`` / ``e1_upper`` (their **Eqs. 32 and 35**;
  Eqs. 18-21 are the general two-decoy bounds, not these).
* D. Gottesman, H.-K. Lo, N. Lutkenhaus, J. Preskill, "Security of quantum key
  distribution with imperfect devices", Quantum Inf. Comput. 4, 325 (2004).
  arXiv:quant-ph/0212066   (the GLLP rate formula)
* C. C. W. Lim, M. Curty, N. Walenta, F. Xu, H. Zbinden, "Concise security
  bounds for practical decoy-state quantum key distribution",
  Phys. Rev. A 89, 022307 (2014).  **arXiv:1311.7129** -- the finite-key length
  ``l`` and the ``n^{+-}`` / ``m^{+-}`` fluctuation model used below.
* M. Curty, F. Xu, W. Cui, C. C. W. Lim, K. Tamaki, H.-K. Lo,
  "Finite-key analysis for measurement-device-independent quantum key
  distribution", Nat. Commun. 5, 3732 (2014).  **arXiv:1307.1081** -- note this
  is MDI-QKD, so it is not a like-for-like rate reference for BB84.
* T. Fung, X. Ma, H. F. Chau, "Practical issues in quantum-key-distribution
  postprocessing", Phys. Rev. A 85, 012307 (2012).  arXiv:1109.5082
  -- the random-sampling correction that bounds the phase error rate.
"""

from __future__ import annotations

import numpy as np

from ..core import QubitState, H, X, Z, apply, measure
from ..core.physical import (
    fiber_transmissivity,
    FIBER_ATTENUATION_1550,
)


BASES = {"Z": 0, "X": 1}
BASE_NAMES = ["Z", "X"]


def _encode(bit: int, basis: int) -> QubitState:
    state = QubitState.zero() if bit == 0 else QubitState.one()
    if basis == 1:
        state = apply(H, state, targets=[0])
    return state


def _measure(state: QubitState, basis: int, rng: np.random.Generator) -> int:
    if basis == 1:
        state = apply(H, state, targets=[0])
    outcomes, _ = measure(state, qubit_indices=[0], rng=rng)
    return outcomes[0]


def run_bb84(num_bits: int = 256, noise: float = 0.0, rng: np.random.Generator | None = None) -> dict:
    if rng is None:
        rng = np.random.default_rng()
    alice_bits = rng.integers(0, 2, size=num_bits)
    alice_bases = rng.integers(0, 2, size=num_bits)
    bob_bases = rng.integers(0, 2, size=num_bits)
    bob_results = np.empty(num_bits, dtype=int)
    for i in range(num_bits):
        state = _encode(int(alice_bits[i]), int(alice_bases[i]))
        if noise > 0:
            from ..core.noise import depolarizing_channel
            chan = depolarizing_channel(noise)
            state = chan.apply(state)
        bob_results[i] = _measure(state, int(bob_bases[i]), rng)
    match = alice_bases == bob_bases
    sifted_key = alice_bits[match]
    sifted_bob = bob_results[match]
    if len(sifted_key) < 2:
        return {"key": "", "qber": 0.0}
    n_est = max(1, len(sifted_key) // 4)
    est_indices = rng.choice(len(sifted_key), size=n_est, replace=False)
    errors = np.sum(sifted_key[est_indices] != sifted_bob[est_indices])
    qber = errors / n_est
    keep = np.ones(len(sifted_key), dtype=bool)
    keep[est_indices] = False
    key = "".join(str(int(b)) for b in sifted_key[keep])
    return {"key": key, "qber": float(qber), "raw_key_length": num_bits, "sifted_length": len(sifted_key)}


# Decoy-state BB84: the analytic key-rate calculation

#: Hardware presets: the first three are the decoy-state papers' 1550 nm fibre values,
#: ``sequencer_erlang`` mirrors SeQUeNCe's erbium/atom-cavity parameterisation, and
#: ``ideal`` is a loss-and-dark-count-free reference for the analytic tests.
DECOY_PRESETS: dict[str, dict] = {
    "gobby-yuan-shields": {
        "description": "GYS 2004 122 km fibre demo (id Quantique id210-class)",
        "pulse_rate_hz": 2e6,
        "detector_efficiency": 0.045,
        "dark_count_hz": 1.7e-6 * 2e6,  # 1.7e-6 per pulse at 2 MHz
        "alpha_db_km": 0.21,
        "e_detector": 0.033,
        "error_correction_inefficiency": 1.22,
        "mu": 0.5,
        "nu": 0.1,
    },
    "practical-1550": {
        "description": "Modern InGaAs SPAD, 100 MHz clock, 0.2 dB/km fibre",
        "pulse_rate_hz": 1e8,
        "detector_efficiency": 0.8,
        "dark_count_hz": 100.0,
        "alpha_db_km": FIBER_ATTENUATION_1550,
        "mu": 0.5,
        "nu": 0.1,
    },
    "snspd-1550": {
        "description": "SNSPD-class detectors: near-unity efficiency, ~10 Hz dark counts",
        "pulse_rate_hz": 1e8,
        "detector_efficiency": 0.93,
        "dark_count_hz": 10.0,
        "alpha_db_km": FIBER_ATTENUATION_1550,
        "mu": 0.6,
        "nu": 0.1,
    },
    "sequencer_erlang": {
        "description": "SeQUeNCe-comparable erbium/atom-cavity parameterisation",
        "pulse_rate_hz": 1e7,
        "detector_efficiency": 0.9,
        "dark_count_hz": 50.0,
        "alpha_db_km": FIBER_ATTENUATION_1550,
        "mu": 0.5,
        "nu": 0.1,
    },
    "ideal": {
        "description": "No dark counts, unit-efficiency detectors (analytic reference)",
        "pulse_rate_hz": 1e8,
        "detector_efficiency": 1.0,
        "dark_count_hz": 0.0,
        "alpha_db_km": FIBER_ATTENUATION_1550,
        "mu": 0.5,
        "nu": 0.1,
    },
}


def binary_entropy(x: float) -> float:
    """Shannon entropy H2(x) in bits, safe at the endpoints."""
    x = float(x)
    if x <= 0.0 or x >= 1.0:
        return 0.0
    return float(-x * np.log2(x) - (1.0 - x) * np.log2(1.0 - x))


def gain_and_qber(mu: float, eta: float, y0: float,
                  e_detector: float = 0.0) -> tuple[float, float]:
    """Observed gain ``Q_mu`` and QBER ``E_mu`` for a Poissonian source.

    With a Poissonian photon-number distribution, a channel of total
    transmissivity ``eta`` and a background/dark-count yield ``y0`` per pulse::

        Q_mu = y0 + 1 - exp(-eta * mu)
        E_mu = (y0/2 + e_det * (1 - exp(-eta * mu))) / Q_mu

    ``e_detector`` is the intrinsic misalignment error of the setup (the
    probability that an otherwise perfect detection lands in the wrong basis);
    ``y0/2`` is the usual assumption that dark counts are equally likely to
    produce either bit value.
    """
    if mu <= 0.0:
        return float(y0), 0.5
    p_click_signal = 1.0 - np.exp(-eta * mu)
    q = y0 + p_click_signal
    if q <= 0.0:
        return 0.0, 0.5
    e = (y0 * 0.5 + e_detector * p_click_signal) / q
    return float(q), float(min(max(e, 0.0), 0.5))


def decoy_single_photon_bounds(q_mu: float, q_nu: float, q_vac: float,
                               e_mu: float, e_nu: float,
                               mu: float, nu: float) -> dict:
    """Vacuum+weak-decoy estimators for ``Y1`` (lower) and ``e1`` (upper).

    These are **Eqs. (32) and (35)** of Ma, Qi, Zhao and Lo, Phys. Rev. A 72,
    012326 (2005) -- the vacuum + weak decoy analysis.  (Eqs. 18-21 of that
    paper are the *general two-decoy* bounds, which a reader looking for
    "the decoy equations" would find first; they are not these.)

    ``q_vac`` is the gain of the vacuum (intensity 0) state, which measures the
    background yield ``Y0`` directly.

    Returns ``y1_lower``, ``e1_upper``, ``y0_upper``, ``y0_lower`` and the
    decoy normalisation factor ``y1_lower_denominator``.
    """
    # Y0 is bounded above by the vacuum gain itself: every vacuum click is background,
    # so Q_vacuum = Y0 and Y0 <= Q_vacuum.
    y0_upper = float(min(1.0, q_vac))
    y0_lower = float(max(0.0, min(1.0, q_vac)))

    num = q_nu * np.exp(nu) - q_mu * np.exp(mu) * (nu / mu) ** 2
    den = nu - nu ** 2 / mu
    if den == 0.0:
        y1_lower = 0.0
        den = np.nan
    else:
        correction = (mu ** 2 - nu ** 2) / (mu ** 2) * y0_upper
        y1_lower = mu / (mu * nu - nu ** 2) * (num - correction)
    y1_lower = float(max(0.0, min(1.0, y1_lower)))

    # e1 upper bound: a maximal numerator needs the LOWER bound on Y0, so the subtracted
    # term is e0 * Y0^L with e0 = 1/2; it matters once fluctuations are added.
    if y1_lower <= 0.0:
        e1_upper = 0.5
    else:
        e1_upper = (e_nu * q_nu * np.exp(nu) - 0.5 * y0_lower) / (y1_lower * nu)
        if not np.isfinite(e1_upper):
            e1_upper = 0.5
        e1_upper = float(min(max(e1_upper, 0.0), 0.5))

    return {
        "y0_upper": y0_upper,
        "y0_lower": y0_lower,
        "y1_lower": y1_lower,
        "e1_upper": e1_upper,
        "y1_lower_denominator": float(den),
    }


def _counts_for(gain: float, n_pulses: float) -> float:
    """Expected detection count for a gain, over ``n_pulses`` pulses."""
    return max(0.0, float(gain) * float(n_pulses))


def finite_key_secret_length(
    n_x_signal: float,
    n_x_decoy: float,
    n_x_vacuum: float,
    n_z_signal: float,
    n_z_decoy: float,
    n_z_vacuum: float,
    *,
    mu_signal: float,
    mu_decoy: float,
    qber_z: float | None = None,
    n_z_errors: float | None = None,
    error_correction_inefficiency: float = 1.16,
    eps_cor: float = 1e-15,
    eps_sec: float = 1e-10,
    p_signal: float = 0.5,
    p_decoy: float = 0.25,
    p_vacuum: float = 0.25,
    n_z_error_signal: float | None = None,
    n_z_error_decoy: float | None = None,
    n_z_error_vacuum: float | None = None,
) -> dict:
    """Finite-key secret key length, in the Lim-Curty-Walenta-Xu form.

    This is the standard finite-key accounting (arXiv:1311.7129), not an
    approximate correction bolted onto the asymptotic rate.  Three things
    distinguish it, and all three were got wrong in the first implementation
    here:

    1. **The secrecy cost is an absolute block cost**, not a per-pulse density:
       ``6*log2(21/eps_sec) + log2(2/eps_cor)`` bits subtracted from the length.
       There is no ``4*log2(2/eps)/n`` term in this bound.  At
       ``eps_sec=1e-9, eps_cor=1e-15`` that cost is ~256.6 bits, where the
       naive form gave 123.6 -- an underestimate of 2.1x.
    2. **Statistical fluctuations are applied to the observed counts, inside
       the decoy estimators** -- ``n +- sqrt((n/2)*ln(21/eps_sec))`` -- and then
       pushed through the non-linear bounds.  Applying a fluctuation term as a
       blanket subtraction from the rate is wrong in placement and in
       magnitude (6.3x too large at ``eps=1e-9``).  Note the **natural**
       logarithm inside the root; only the block cost uses log2.
    3. **The phase error rate is bounded separately** from the observed QBER,
       via the Z basis plus the Fung et al. random-sampling correction.

    .. warning::
       **This is not "the asymptotic rate minus a penalty", and it can come out
       higher than** :func:`run_bb84_decoy`'s asymptotic rate.  That is not a
       bug, and it is not a violation of the finite-key bound.  The two numbers
       use *different* estimators for the same key: the asymptotic path uses the
       vacuum+weak ``e1_upper``, which is deliberately loose, while this path
       uses the phase-error bound plus the vacuum count ``s_X,0`` (which
       contributes key that the asymptotic expression drops entirely).  A
       tighter estimator legitimately yields more key.  Do not present one as a
       correction to the other, and do not difference them.

    Parameters are **detection counts** (not rates) at signal, decoy and vacuum
    intensities, in the X basis (parameter estimation) and the Z basis (key).

    The QBER is derived from the Z-basis counts by default.  ``qber_z`` overrides
    that with an externally measured value, and takes precedence when supplied.
    """
    eps = float(eps_sec)
    if eps <= 0.0:
        raise ValueError("eps_sec must be positive")
    if eps_cor <= 0.0:
        raise ValueError("eps_cor must be positive")

    ln_term = np.log(21.0 / eps)          # natural log, inside the root
    block_secrecy_cost = 6.0 * np.log2(21.0 / eps) + np.log2(2.0 / eps_cor)

    # LCWX Eq. 2: each fluctuation bracket uses the total count of its OWN basis,
    # ``sqrt(n_X/2 ln(21/eps))`` for X and ``sqrt(m_Z/2 ln(21/eps))`` for Z. Using the
    # Z-basis width for X is the defect described in the docstring.
    n_x_block = float(n_x_signal + n_x_decoy + n_x_vacuum)
    n_z_block = float(n_z_signal + n_z_decoy + n_z_vacuum)

    def bracket(n_obs: float, n_block: float, p_k: float, mu_k: float,
                sign: float) -> float:
        """``n_{B,k}^{+-} = (e^{mu_k}/p_k)[n_{B,k} +- sqrt(n_B/2 ln(21/eps))]``."""
        if p_k <= 0.0:
            raise ValueError(f"intensity probability must be positive, got {p_k}")
        width = float(np.sqrt(max(0.0, n_block) / 2.0 * ln_term))
        return float(np.exp(mu_k) / p_k * (float(n_obs) + sign * width))

    m1 = float(mu_signal)
    m2 = float(mu_decoy)
    m3 = 0.0                                     # the vacuum intensity
    p1, p2, p3 = float(p_signal), float(p_decoy), float(p_vacuum)
    if abs((p1 + p2 + p3) - 1.0) > 1e-9:
        raise ValueError(
            f"intensity probabilities must sum to 1, got {p1 + p2 + p3}"
        )

    # tau_n = sum_k e^{-mu_k} mu_k^n p_k / n!  -- the overall n-photon weight.
    tau_0 = p1 * np.exp(-m1) + p2 * np.exp(-m2) + p3 * np.exp(-m3)
    tau_1 = (p1 * m1 * np.exp(-m1) + p2 * m2 * np.exp(-m2)
             + p3 * m3 * np.exp(-m3))

    den = m1 * (m2 - m3) - m2 ** 2 + m3 ** 2

    def single_photon_bounds(signal, decoy, vacuum, block):
        """``(s_0, s_1)`` for one basis, by LCWX Eqs. (2)-(3)."""
        s_0 = max(0.0, tau_0 * (
            m2 * bracket(vacuum, block, p3, m3, -1.0)
            - m3 * bracket(decoy, block, p2, m2, +1.0)
        ) / (m2 - m3))
        if den == 0.0:
            s_1 = 0.0
        else:
            s_1 = max(0.0, tau_1 * m1 * (
                bracket(decoy, block, p2, m2, -1.0)
                - bracket(vacuum, block, p3, m3, +1.0)
                - (m2 ** 2 - m3 ** 2) / m1 ** 2
                * (bracket(signal, block, p1, m1, +1.0) - s_0 / tau_0)
            ) / den)
        return s_0, s_1

    if m2 == m3:
        raise ValueError("mu_decoy must differ from the vacuum intensity")

    # The Z-basis error counts feeding ``v_Z,1``: raw Z counts times the observed QBER
    # by default; supply them explicitly when a per-intensity breakdown exists.
    if n_z_error_decoy is None:
        rate = (qber_z if qber_z is not None else
                (n_z_errors / n_z_block if n_z_errors and n_z_block else 0.0))
        n_z_error_signal = n_z_signal * rate
        n_z_error_decoy = n_z_decoy * rate
        n_z_error_vacuum = n_z_vacuum * 0.5
    else:
        if n_z_error_vacuum is None:
            n_z_error_vacuum = 0.0
        if n_z_error_signal is None:
            if n_z_errors is not None:
                n_z_error_signal = max(
                    0.0, float(n_z_errors) - float(n_z_error_decoy) - float(n_z_error_vacuum)
                )
            else:
                rate = qber_z if qber_z is not None else 0.0
                n_z_error_signal = n_z_signal * rate

    m_z = float(n_z_error_signal) + float(n_z_error_decoy) + float(n_z_error_vacuum)

    s_x_0, s_x_1_lower = single_photon_bounds(
        n_x_signal, n_x_decoy, n_x_vacuum, n_x_block)

    # ``s_Z,1`` is a single-photon count from the raw Z detection counts; ``v_Z,1`` is a
    # single-photon phase-error count, so its bracket uses the Z-basis error counts.
    _, s_z_1_lower = single_photon_bounds(
        n_z_signal, n_z_decoy, n_z_vacuum, n_z_block)
    v_z_1_upper = max(0.0, tau_1 * (
        bracket(n_z_error_decoy, m_z, p2, m2, +1.0)
        - bracket(n_z_error_vacuum, m_z, p3, m3, -1.0)
    ) / (m2 - m3))

    # The phase-error RATE is ``v_Z1 / s_Z1``, both single-photon counts in the Z basis,
    # plus the Fung et al. correction; ``s_X1`` would mix bases.
    if s_x_1_lower <= 0.0 or s_z_1_lower <= 0.0 or v_z_1_upper <= 0.0:
        phi_x = 0.5
        gamma = 0.0
    else:
        ratio = min(1.0, v_z_1_upper / s_z_1_lower)
        c, dd = s_x_1_lower, s_z_1_lower
        if 0.0 < ratio < 1.0:
            # Fung et al. random-sampling correction (the gamma term), which needs
            # single-photon events in both bases to sample from.
            inner = ((c + dd) / (c * dd)) * (21.0 ** 2 / eps ** 2)
            gamma = np.sqrt(
                ((c + dd) * (1.0 - ratio) * ratio / (c * dd * np.log(2.0)))
                * np.log2(max(inner, 1.0))
            )
        else:
            gamma = 0.0
        phi_x = min(0.5, ratio + gamma)
        if phi_x >= 0.5:
            # The sampling bound saturated: no key is extractable from this estimator at
            # this block size. Reported as a zero length with the phase error visible.
            phi_x = 0.5

    # Defaulted from the Z-basis counts, so an optimistic QBER cannot inflate the key.
    n_z_total = float(n_z_signal + n_z_decoy + n_z_vacuum)
    if qber_z is not None:
        qber_z_observed = float(qber_z)
    elif n_z_errors is not None and n_z_total > 0:
        qber_z_observed = min(0.5, float(n_z_errors) / n_z_total)
    else:
        qber_z_observed = 0.0
    leak_ec = error_correction_inefficiency * binary_entropy(qber_z_observed) * n_x_block

    raw = (s_x_0 + s_x_1_lower
           - s_x_1_lower * binary_entropy(phi_x)
           - leak_ec
           - block_secrecy_cost)
    length = float(np.floor(max(0.0, raw)))

    return {
        "secret_key_length_bits": length,
        "s_x_0_lower": float(s_x_0),
        "s_x_1_lower": float(s_x_1_lower),
        "v_z_1_upper": float(v_z_1_upper),
        "phase_error_upper": float(phi_x),
        "random_sampling_correction": float(gamma),
        "sifted_key_bits": n_z_total,
        "qber_z_observed": float(qber_z_observed),
        "leak_ec_bits": float(leak_ec),
        "block_secrecy_cost_bits": float(block_secrecy_cost),
        "eps_cor": float(eps_cor),
        "eps_sec": float(eps),
    }


def run_bb84_decoy(
    distance_km: float = 50.0,
    *,
    mu: float = 0.5,
    nu: float = 0.1,
    pulse_rate_hz: float = 1e8,
    detector_efficiency: float = 0.8,
    dark_count_hz: float = 100.0,
    alpha_db_km: float = FIBER_ATTENUATION_1550,
    e_detector: float = 0.01,
    error_correction_inefficiency: float = 1.16,
    n_pulses: float | None = None,
    epsilon: float = 1e-10,
    num_decoy_intensities: int = 3,
) -> dict:
    """Analytic decoy-state BB84 key rate over a lossy fibre link.

    This is the *closed-form* analysis, not a qubit simulation.  It computes
    the GLLP/Shor-Preskill secret key rate with single-photon parameters
    bounded by the vacuum+weak decoy-state method, which is what makes the
    result defensible against a photon-number-splitting attack on a weak
    coherent pulse source.

    Parameters
    ----------
    distance_km:
        Fibre length.  Channel transmissivity is
        ``eta_channel = 10 ** (-alpha * L / 10)``.
    mu, nu:
        Signal and decoy mean photon numbers.  A third intensity of 0 (the
        vacuum state) is sent whenever ``num_decoy_intensities >= 3``.
    pulse_rate_hz:
        Laser repetition rate, used to convert bits/pulse to bits/second.
    detector_efficiency:
        Bob's detector quantum efficiency.
    dark_count_hz:
        Dark-count rate per detector; converted to a per-pulse probability
        with the detection window ``1 / pulse_rate_hz``.
    alpha_db_km:
        Fibre attenuation in dB/km (0.2 dB/km at 1550 nm).
    e_detector:
        Intrinsic misalignment error of the optical setup.
    error_correction_inefficiency:
        ``f_EC`` in the GLLP formula; 1.16 is the standard practical value.
    n_pulses:
        Number of pulses sent.  ``None`` means the asymptotic limit.  When
        given, the finite-key statistical-fluctuation penalty is subtracted.
    epsilon:
        Total security parameter for the finite-key correction.
    num_decoy_intensities:
        2 = weak decoy only (no vacuum state, so ``Y0`` must be assumed),
        3 = vacuum + weak decoy (the standard, and the default).

    Returns
    -------
    dict
        Key-rate numbers plus every intermediate quantity, so a caller can
        audit the arithmetic rather than trust the final figure.
    """
    if nu <= 0.0 or mu <= 0.0:
        raise ValueError("signal and decoy intensities must be positive")
    if nu >= mu:
        raise ValueError("decoy intensity nu must be weaker than signal mu")
    if distance_km < 0:
        raise ValueError("distance_km must be non-negative")
    if not 0.0 < detector_efficiency <= 1.0:
        raise ValueError("detector_efficiency must be in (0, 1]")
    if not 0.0 <= e_detector <= 0.5:
        raise ValueError("e_detector must be in [0, 0.5]")

    # --- channel and detector -------------------------------------------
    eta_channel = fiber_transmissivity(distance_km, alpha_db_km)
    eta = detector_efficiency * eta_channel
    detection_window_s = 1.0 / pulse_rate_hz
    y0 = 1.0 - np.exp(-dark_count_hz * detection_window_s)

    q_mu, e_mu = gain_and_qber(mu, eta, y0, e_detector)
    q_nu, e_nu = gain_and_qber(nu, eta, y0, e_detector)
    if num_decoy_intensities >= 3:
        q_vac, e_vac = gain_and_qber(0.0, eta, y0, e_detector)
        bounds = decoy_single_photon_bounds(q_mu, q_nu, q_vac, e_mu, e_nu, mu, nu)
    else:
        # Without a vacuum state, Y0 must be taken from the detector model.
        q_vac, e_vac = float(y0), 0.5
        bounds = {
            "y0_upper": float(y0),
            "y1_lower": 0.0,
            "e1_upper": 0.5,
            "y1_lower_denominator": np.nan,
        }

    y1_lower = bounds["y1_lower"]
    e1_upper = bounds["e1_upper"]
    q1_lower = mu * np.exp(-mu) * y1_lower  # Q1 = mu * e^-mu * Y1
    # GLLP / Shor-Preskill rate: R >= q * (-Q_mu * f_EC * H2(E_mu) + Q1 * (1 - H2(e1))).
    # q = 1/2 for basis reconciliation; Ma et al. Eq. 1, efficient BB84 takes q ~ 1.
    q_basis = 0.5
    gain_term = q_mu * error_correction_inefficiency * binary_entropy(e_mu)
    single_photon_term = q1_lower * (1.0 - binary_entropy(e1_upper))
    rate_per_pulse = q_basis * (single_photon_term - gain_term)

    finite_key = None
    finite_key_penalty_per_pulse = 0.0
    if n_pulses is not None and n_pulses > 0:
        # LCWX finite-key accounting: fluctuations go on observed counts and are pushed
        # through the decoy estimators; the secrecy cost is an absolute block cost, not
        # a per-pulse density. Under 50/50 basis choices, each sifted basis gets 0.25 of
        # the pulses, weighted by intensity probabilities p_k = (0.5, 0.25, 0.25).
        p_signal, p_decoy, p_vacuum = 0.5, 0.25, 0.25
        p_x_sift = 0.25
        p_z_sift = 0.25
        n_signal_x = _counts_for(q_mu, n_pulses) * p_signal * p_x_sift
        n_decoy_x = _counts_for(q_nu, n_pulses) * p_decoy * p_x_sift
        n_vac_x = _counts_for(q_vac, n_pulses) * p_vacuum * p_x_sift
        n_signal_z = _counts_for(q_mu, n_pulses) * p_signal * p_z_sift
        n_decoy_z = _counts_for(q_nu, n_pulses) * p_decoy * p_z_sift
        n_vac_z = _counts_for(q_vac, n_pulses) * p_vacuum * p_z_sift

        n_z_err_sig = n_signal_z * e_mu
        n_z_err_dec = n_decoy_z * e_nu
        n_z_err_vac = n_vac_z * 0.5

        finite_key = finite_key_secret_length(
            n_x_signal=n_signal_x,
            n_x_decoy=n_decoy_x,
            n_x_vacuum=n_vac_x,
            n_z_signal=n_signal_z,
            n_z_decoy=n_decoy_z,
            n_z_vacuum=n_vac_z,
            mu_signal=mu,
            mu_decoy=nu,
            n_z_errors=n_z_err_sig + n_z_err_dec + n_z_err_vac,
            n_z_error_signal=n_z_err_sig,
            n_z_error_decoy=n_z_err_dec,
            n_z_error_vacuum=n_z_err_vac,
            error_correction_inefficiency=error_correction_inefficiency,
            eps_sec=epsilon,
            p_signal=p_signal,
            p_decoy=p_decoy,
            p_vacuum=p_vacuum,
        )
        rate_per_pulse = finite_key["secret_key_length_bits"] / float(n_pulses)
        # The asymptotic figure is reported alongside; the difference is not a penalty,
        # as the two estimators differ and this one can legitimately be larger.
        finite_key_penalty_per_pulse = 0.0

    secure = rate_per_pulse > 0.0
    if not secure:
        rate_per_pulse = 0.0

    return {
        # headline numbers
        "key_rate_per_pulse": float(rate_per_pulse),
        "key_rate_hz": float(rate_per_pulse * pulse_rate_hz),
        "secure": bool(secure),
        # observed quantities
        "distance_km": float(distance_km),
        "loss_db": float(alpha_db_km * distance_km),
        "channel_transmissivity": float(eta_channel),
        "total_transmissivity": float(eta),
        "q_mu": float(q_mu),
        "e_mu": float(e_mu),
        "q_nu": float(q_nu),
        "e_nu": float(e_nu),
        "q_vac": float(q_vac),
        # decoy-state bounds
        "y0_upper": float(bounds["y0_upper"]),
        "y0_lower": float(bounds.get("y0_lower", bounds["y0_upper"])),
        "y1_lower": float(y1_lower),
        "e1_upper": float(e1_upper),
        "q1_lower": float(q1_lower),
        # rate decomposition (bits per pulse)
        "single_photon_term": float(q_basis * single_photon_term),
        "error_correction_term": float(q_basis * gain_term),
        "finite_key_penalty_per_pulse": float(finite_key_penalty_per_pulse),
        "finite_key": finite_key,
        # parameters, echoed for the audit trail
        "mu": float(mu),
        "nu": float(nu),
        "pulse_rate_hz": float(pulse_rate_hz),
        "detector_efficiency": float(detector_efficiency),
        "dark_count_hz": float(dark_count_hz),
        "dark_count_probability": float(y0),
        "alpha_db_km": float(alpha_db_km),
        "e_detector": float(e_detector),
        "error_correction_inefficiency": float(error_correction_inefficiency),
        "n_pulses": None if n_pulses is None else float(n_pulses),
        "epsilon": float(epsilon),
        "num_decoy_intensities": int(num_decoy_intensities),
        "asymptotic": n_pulses is None,
    }


def run_bb84_decoy_preset(preset: str, distance_km: float = 50.0,
                          **overrides) -> dict:
    """Run :func:`run_bb84_decoy` with a named hardware preset."""
    if preset not in DECOY_PRESETS:
        raise KeyError(
            f"unknown preset {preset!r}; available: {sorted(DECOY_PRESETS)}"
        )
    params = {k: v for k, v in DECOY_PRESETS[preset].items()
              if k != "description"}
    params.update(overrides)
    result = run_bb84_decoy(distance_km, **params)
    result["preset"] = preset
    result["preset_description"] = DECOY_PRESETS[preset]["description"]
    return result


def decoy_key_rate_curve(
    distances_km,
    preset: str = "practical-1550",
    **overrides,
) -> list[dict]:
    """Key rate at each distance in ``distances_km`` (used by ``bench``)."""
    return [run_bb84_decoy_preset(preset, float(d), **overrides)
            for d in distances_km]


def max_secure_distance_km(
    preset: str = "practical-1550",
    hi: float = 500.0,
    tol: float = 0.01,
    **overrides,
) -> float:
    """Longest fibre on which the preset still yields a positive key rate.

    Bisection on ``run_bb84_decoy``; the key rate is monotonically decreasing
    in distance, so the predicate is a clean threshold.

    **Degenerate case, and it is not theoretical.**  With no dark counts the
    asymptotic model has *no* maximum distance at all: both the single-photon
    and the error-correction terms scale with the channel transmissivity, so
    the rate stays positive for every finite length.  A bisection then reports
    a large finite number produced purely by floating-point cancellation of
    ``Q_nu*e^nu - Q_mu*e^mu*(nu/mu)^2`` -- not physics.  This function returns
    ``inf`` in that case, so the caller cannot mistake it for a reach.
    """
    if not run_bb84_decoy_preset(preset, tol, **overrides)["secure"]:
        return 0.0

    # A zero-dark-count channel has no loss-limited reach (see above).
    dark = overrides.get("dark_count_hz",
                         DECOY_PRESETS.get(preset, {}).get("dark_count_hz", 0.0))
    if dark <= 0.0:
        return float("inf")

    if run_bb84_decoy_preset(preset, hi, **overrides)["secure"]:
        # Still secure at the search ceiling: report the ceiling rather than pretending
        # to have found a maximum.
        return float(hi)

    lo = tol
    while hi - lo > tol:
        mid = 0.5 * (lo + hi)
        if run_bb84_decoy_preset(preset, mid, **overrides)["secure"]:
            lo = mid
        else:
            hi = mid
    return float(lo)
