"""Photonic hardware layer: detectors, Bell-state measurement, and time multiplexing.

What this adds
--------------
Until now the physical layer mapped distance to a *depolarizing probability* and
stopped.  Detector efficiency, dark counts, dead time, timing jitter and
multiplexing were either absent or collapsed into a single number in
``graph.QuantumLink``.  That is enough to rank routes, and not enough to predict
a generation *rate* or a *success probability* -- which is the difference between
a result that can be compared to an experiment and one that cannot.

Barrett-Kok
-----------
The double-heralded generation scheme of Barrett and Kok, Phys. Rev. A **71**,
060310(R) (2005), [arXiv:quant-ph/0408040](https://arxiv.org/abs/quant-ph/0408040).
Two memories are excited, the photons interfere on a 50:50 beam splitter, and
success is heralded by a coincidence.  Everything in the module follows from two
published facts about that scheme:

* **The ideal success probability is 1/2**, and the paper states that as the
  protocol's theoretical upper limit.  It is not a choice of parameters.
* **The probability is quadratic in detector efficiency** ("p has a quadratic
  dependence on eta").  Two photons must each survive and each be detected, so
  ``p ∝ eta_det^2``.

Loss therefore costs *rate*, not *fidelity*: a lost photon is a failed attempt,
not a corrupted pair.  That property is why Barrett-Kok is worth modelling
separately from a depolarizing channel, which conflates the two.

What degrades fidelity instead, and what this module models
-----------------------------------------------------------
* **Dark counts.**  A coincidence caused by two dark counts is
  indistinguishable from a real herald, so it contributes a maximally mixed
  pair.  This enters as an explicit mixture, which is why ``p_success`` and
  ``raw_fidelity`` are computed together rather than sequentially.
* **Mode mismatch.**  Frequency/polarisation/spatio-temporal mismatch reduces
  the heralded fidelity directly.
* **Memory decoherence** during the attempt, charged through
  :func:`~quantumnet.core.physical.bell_pair_fidelity_after_dt`.

Dead time and jitter are modelled as detector properties and applied to the
rate, not the per-attempt probability -- they make a detector unavailable for a
while, which is a scheduling fact, not a physics one.

References
----------
* S. D. Barrett, P. Kok, "Efficient high-fidelity quantum computation using
  matter qubits and linear optics", PRA 71, 060310(R) (2005).
* W. J. Munro et al., "Inside quantum repeaters", IEEE JSST-QE 21, 78 (2015).
* The SeQUeNCe/QuantumSavory cross-validation reference, which independently
  states the same model as ``p_BK = 0.5 * p_click^2`` with
  ``p_click = p_signal + p_dark - p_signal*p_dark``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .physical import fiber_transmissivity

#: Barrett-Kok's ideal success probability, and its stated upper limit.
BARRETT_KOK_IDEAL_SUCCESS = 0.5


@dataclass
class Detector:
    """A single-photon detector with the impairments that matter for rate.

    ``efficiency`` scales every click.  ``dark_count_rate_hz`` produces clicks
    with no photon.  ``dead_time_s`` makes the detector blind after a click, so
    it can be unavailable when the next attempt arrives -- which is the
    difference between a nominal repetition rate and an achievable one.
    ``jitter_s`` is the timing uncertainty; it does not change the per-attempt
    probability, but it bounds how finely arrival times can be resolved, which a
    coincidence window has to respect.
    """

    name: str = "spad"
    efficiency: float = 0.8
    dark_count_rate_hz: float = 100.0
    dead_time_s: float = 0.0
    jitter_s: float = 0.0
    afterpulse_probability: float = 0.0

    def __post_init__(self):
        if not 0.0 < self.efficiency <= 1.0:
            raise ValueError(f"detector efficiency must be in (0, 1], "
                             f"got {self.efficiency}")
        if self.dark_count_rate_hz < 0.0:
            raise ValueError("dark_count_rate_hz must be non-negative")
        if self.dead_time_s < 0.0 or self.jitter_s < 0.0:
            raise ValueError("dead_time_s and jitter_s must be non-negative")
        if not 0.0 <= self.afterpulse_probability <= 1.0:
            raise ValueError("afterpulse_probability must be in [0, 1]")

    def dark_count_probability(self, window_s: float) -> float:
        """Probability of at least one dark count in a detection window."""
        if self.dark_count_rate_hz <= 0.0 or window_s <= 0.0:
            return 0.0
        return float(1.0 - np.exp(-self.dark_count_rate_hz * window_s))

    def click_probability(self, photon_arrival_probability: float,
                          window_s: float) -> float:
        """Probability of a click, from signal *or* dark counts.

        The union of two independent events, so the dark term does not
        double-count occasions when both happen.
        """
        if not 0.0 <= photon_arrival_probability <= 1.0:
            raise ValueError("photon_arrival_probability must be in [0, 1]")
        signal = photon_arrival_probability * self.efficiency
        dark = self.dark_count_probability(window_s)
        return float(signal + dark - signal * dark)

    def afterpulse_click_probability(self, window_s: float,
                                     prior_click_probability: float) -> float:
        """Extra click probability contributed by afterpulsing.

        An afterpulse is a spurious click caused by a *previous* real detection --
        trapped charge released late in the avalanche.  It matters here for a
        specific reason: a Barrett-Kok herald needs one click per arm, and if one
        of those clicks is an afterpulse from the previous pulse, the herald is
        **false**.  The pair is not entangled, but the protocol cannot tell.

        Modelled as ``p_after * p_prior``, where ``p_prior`` is the probability the
        detector clicked on a preceding pulse.  That is the standard
        trap-population reading: afterpulsing requires a prior avalanche, so its
        rate is proportional to the click rate rather than constant.  A constant
        dark-count-like term would be a different mechanism and is already
        covered by ``dark_count_rate_hz``.
        """
        if self.afterpulse_probability <= 0.0:
            return 0.0
        if not 0.0 <= prior_click_probability <= 1.0:
            raise ValueError("prior_click_probability must be in [0, 1]")
        return float(self.afterpulse_probability * prior_click_probability)

    def is_blind(self, since_click_s: float) -> bool:
        """True while the detector is inside its dead time after a click."""
        return self.dead_time_s > 0.0 and since_click_s < self.dead_time_s

    def describe(self) -> str:
        return (f"{self.name}: eta={self.efficiency:g}, "
                f"dark={self.dark_count_rate_hz:g}/s, "
                f"dead={self.dead_time_s:g}s, jitter={self.jitter_s:g}s")


@dataclass
class PhotonicLink:
    """One arm of an elementary link: source, fibre, and detector.

    An elementary link in Barrett-Kok is *two* arms that interfere, so this
    models a single arm and :class:`BarrettKok` combines two of them.  Keeping
    them separate is what makes an asymmetric link (different arm lengths or
    different detectors) expressible.
    """

    length_km: float
    alpha_db_km: float = 0.2
    source_efficiency: float = 1.0
    detector: Detector = field(default_factory=Detector)
    memory_efficiency: float = 1.0

    def __post_init__(self):
        if self.length_km < 0.0:
            raise ValueError("length_km must be non-negative")
        if not 0.0 < self.source_efficiency <= 1.0:
            raise ValueError("source_efficiency must be in (0, 1]")
        if not 0.0 < self.memory_efficiency <= 1.0:
            raise ValueError("memory_efficiency must be in (0, 1]")

    @property
    def transmissivity(self) -> float:
        return float(fiber_transmissivity(self.length_km, self.alpha_db_km))

    @property
    def loss_db(self) -> float:
        return float(self.alpha_db_km * self.length_km)

    def photon_arrival_probability(self) -> float:
        """Probability a photon from this arm reaches and is coupled into it.

        Deliberately *excludes* detector efficiency: the click probability is
        where the detector acts, so that dark counts can be combined with the
        signal correctly rather than being folded in twice.
        """
        return float(self.source_efficiency
                     * self.memory_efficiency
                     * self.transmissivity)

    def total_efficiency(self) -> float:
        """Everything an emitted photon must survive, detection included."""
        return float(self.photon_arrival_probability()
                     * self.detector.efficiency)


@dataclass
class GenerationAttempt:
    """Outcome of one Barrett-Kok attempt on an elementary link."""

    success: bool
    success_probability: float
    raw_fidelity: float
    coincidence_from_signal: float
    coincidence_from_dark: float

    def describe(self) -> str:
        return (f"{'success' if self.success else 'failure'}: "
                f"p={self.success_probability:.3e}, "
                f"F_raw={self.raw_fidelity:.4f} "
                f"(signal {self.coincidence_from_signal:.3e}, "
                f"dark {self.coincidence_from_dark:.3e})")


@dataclass
class BarrettKok:
    """Double-heralded entanglement generation between two memories.

    The two arms are the paths from each memory to the midpoint beam splitter.
    Following Barrett and Kok, a single photon detected in each round heralds
    success, and the ideal probability is 1/2.
    """

    arm_a: PhotonicLink
    arm_b: PhotonicLink
    #: Fraction of the heralded state unaffected by frequency/polarisation/spatio-
    #: temporal mismatch; 1.0 is perfect mode matching.
    mode_matching: float = 1.0
    #: Coincidence window; sets the dark-count exposure per attempt.
    coincidence_window_s: float = 1e-9
    #: Fidelity when a herald was a dark coincidence: two independent dark counts carry
    #: no entanglement, so the pair is maximally mixed at 1/4 with any Bell state.
    dark_coincidence_fidelity: float = 0.25
    #: Multi-photon emission probability per pulse (source imperfection).
    multiphoton_probability: float = 0.0
    #: How much of the intended Bell state survives a multi-pair herald. 1.0 is unphysical,
    #: since which pair supplied each photon is unrecorded; 0.5 is the conservative reading,
    #: the uncorrelated pair contributing maximally-mixed weight.
    multipair_visibility: float = 0.5

    def __post_init__(self):
        if not 0.0 < self.mode_matching <= 1.0:
            raise ValueError("mode_matching must be in (0, 1]")
        if not 0.0 <= self.multipair_visibility <= 1.0:
            raise ValueError("multipair_visibility must be in [0, 1]")
        if self.coincidence_window_s < 0.0:
            raise ValueError("coincidence_window_s must be non-negative")
        if not 0.0 <= self.multiphoton_probability <= 1.0:
            raise ValueError("multiphoton_probability must be in [0, 1]")

    # -- probabilities -----------------------------------------------------

    def single_arm_click(self, arm: PhotonicLink) -> float:
        """Probability that one arm produces a click, signal or dark.

        ``p_click = p_signal + p_dark - p_signal*p_dark`` -- the union of two
        independent events, which is the form the SeQUeNCe/QuantumSavory
        cross-validation reference states independently as
        ``p_BK = 0.5 * p_click^2``.
        """
        return arm.detector.click_probability(
            arm.photon_arrival_probability(), self.coincidence_window_s)

    def dark_coincidence_probability(self) -> float:
        """Probability the herald came from dark counts on both arms."""
        p_a = self.arm_a.detector.dark_count_probability(
            self.coincidence_window_s)
        p_b = self.arm_b.detector.dark_count_probability(
            self.coincidence_window_s)
        return float(p_a * p_b)

    def signal_dark_coincidence_probability(self) -> float:
        """Probability the herald is a real photon on one arm and a dark count on the other."""
        p_sig_a = (self.arm_a.photon_arrival_probability()
                   * self.arm_a.detector.efficiency)
        p_sig_b = (self.arm_b.photon_arrival_probability()
                   * self.arm_b.detector.efficiency)
        p_dark_a = self.arm_a.detector.dark_count_probability(
            self.coincidence_window_s)
        p_dark_b = self.arm_b.detector.dark_count_probability(
            self.coincidence_window_s)
        return float(BARRETT_KOK_IDEAL_SUCCESS
                     * (p_sig_a * p_dark_b + p_dark_a * p_sig_b))

    def success_probability(self) -> float:
        """Per-attempt success probability.

        With ideal detectors and no dark counts this reduces to exactly
        ``BARRETT_KOK_IDEAL_SUCCESS`` times the product of the two arms' total
        efficiencies: the 1/2 from the beam splitter, and one factor per arm
        because both photons must survive transmission *and* be detected.

        A multi-photon contribution adds ``mu2``, the probability of emitting
        two pairs, to the single-pair success -- a second pair can also produce
        a coincidence.  It is off by default, because the published ideal case
        does not include it.
        """
        p_click_a = self.single_arm_click(self.arm_a)
        p_click_b = self.single_arm_click(self.arm_b)
        # A single photon detected in each round; the 1/2 is the beam splitter.
        p_single = BARRETT_KOK_IDEAL_SUCCESS * p_click_a * p_click_b
        if self.multiphoton_probability <= 0.0:
            return float(p_single)
        p_multi = self.multiphoton_probability * p_click_a * p_click_b
        return float(min(1.0, p_single + p_multi))

    def multiphoton_coincidence_probability(self) -> float:
        """Probability the herald came from a second emitted pair.

        ``multiphoton_probability`` is the chance that a pulse emits **two**
        pairs rather than one.  Either pair can supply the photon that reaches
        each arm, so a two-pair pulse produces a coincidence with essentially the
        same probability per arm as a one-pair pulse -- which is why this carries
        no extra efficiency factor and why it *raises the rate*.

        Formerly this term was added to ``success_probability`` and never applied
        to fidelity, so a source emitting two pairs per pulse was modelled as
        producing *more* entanglement of the *same* quality.  That is wrong in the
        direction that flatters the hardware.
        """
        if self.multiphoton_probability <= 0.0:
            return 0.0
        return float(self.multiphoton_probability
                     * self.single_arm_click(self.arm_a)
                     * self.single_arm_click(self.arm_b))

    def afterpulse_coincidence_probability(self) -> float:
        """Probability the herald is a genuine click plus an afterpulse.

        Both arms must click; one of those clicks is spurious.  So the herald is
        accepted by the protocol and is **wrong** -- the pair carries no
        entanglement between the memories, exactly as a dark coincidence does, but
        for a different reason.

        The prior-click probability is the arm's own single-photon click
        probability on the preceding pulse, which is what populates the traps.
        """
        p_ap_a = self.arm_a.detector.afterpulse_click_probability(
            self.coincidence_window_s, self.single_arm_click(self.arm_a))
        p_ap_b = self.arm_b.detector.afterpulse_click_probability(
            self.coincidence_window_s, self.single_arm_click(self.arm_b))
        if p_ap_a <= 0.0 and p_ap_b <= 0.0:
            return 0.0
        # Either arm's afterpulse can complete the coincidence; the both-afterpulse term
        # is negligible at these small probabilities and is dropped rather than stated.
        p_real_a = self.single_arm_click(self.arm_a)
        p_real_b = self.single_arm_click(self.arm_b)
        return float(p_ap_a * p_real_b + p_real_a * p_ap_b)

    def signal_coincidence_probability(self) -> float:
        """Per-attempt probability of a coincidence from real photons."""
        return float(BARRETT_KOK_IDEAL_SUCCESS
                     * self.arm_a.photon_arrival_probability()
                     * self.arm_a.detector.efficiency
                     * self.arm_b.photon_arrival_probability()
                     * self.arm_b.detector.efficiency)

    # -- fidelity ----------------------------------------------------------

    def raw_fidelity(self) -> float:
        """Fidelity of the heralded pair *before* any memory storage.

        Three coincidence causes, with different fidelities, combined as a
        mixture weighted by how likely each was:

        * **signal** -- a real photon on each arm.  Degraded only by mode
          mismatch.
        * **multi-pair** -- the same herald, but two pairs were emitted in the
          pulse.  Which pair supplied each detected photon is unrecorded, so the
          state is a mixture over the possible pairings rather than the intended
          Bell state.
        * **dark** -- two independent dark counts carry no entanglement, so the
          pair is maximally mixed and its fidelity with any Bell state is 1/4.

        .. warning::
           **The multi-pair fidelity is a stated model, not a derivation.**  The
           exact value needs the polarisation/time-bin mode structure and the
           detection pattern resolved, which this module does not carry.  What is
           implemented is that a multi-pair herald is **strictly worse than the
           single-pair signal** and **strictly better than a dark coincidence** --
           it is a real coincidence between real photons, but an ambiguous one.

           Specifically, one of the two pairs is the intended one and the other is
           an independent, uncorrelated pair, so the detected state is a mixture
           that includes a maximally-mixed component; ``multipair_visibility``
           sets the weight of the correlated part.  The default is the
           conservative reading that the extra pair contributes as much
           maximally-mixed weight as it does correlated weight.
        """
        p_signal = self.signal_coincidence_probability()
        p_multi = self.multiphoton_coincidence_probability()
        p_dark = self.dark_coincidence_probability()
        p_sig_dark = self.signal_dark_coincidence_probability()
        p_ap = self.afterpulse_coincidence_probability()
        total = p_signal + p_multi + p_dark + p_sig_dark + p_ap
        if total <= 0.0:
            return 0.0
        f_signal = 1.0 - (1.0 - self.mode_matching) / 2.0
        # Interpolate between the signal fidelity and the maximally-mixed value: at
        # visibility 1 a multi-pair herald matches a signal one, at 0 a dark count.
        v = float(np.clip(self.multipair_visibility, 0.0, 1.0))
        f_multi = f_signal * v + self.dark_coincidence_fidelity * (1.0 - v)
        # An afterpulse or signal-dark herald is a real photon on one arm and a spurious
        # click on the other, so it is uncorrelated and carries the maximally-mixed value too.
        return float((p_signal * f_signal
                      + p_multi * f_multi
                      + (p_dark + p_sig_dark + p_ap)
                      * self.dark_coincidence_fidelity) / total)

    def attempt(self, rng: np.random.Generator | None = None) -> GenerationAttempt:
        """Sample one attempt.  With no ``rng`` the expected values are returned."""
        p = self.success_probability()
        f = self.raw_fidelity()
        p_signal = self.signal_coincidence_probability()
        p_dark = self.dark_coincidence_probability()
        success = True if rng is None else bool(rng.random() < p)
        return GenerationAttempt(
            success=success, success_probability=p, raw_fidelity=f,
            coincidence_from_signal=p_signal, coincidence_from_dark=p_dark)

    # -- multiplexing ------------------------------------------------------

    def success_probability_multiplexed(self, modes: int) -> float:
        """Success probability with ``modes`` independent parallel attempts.

        One minus the probability that every mode failed, the standard
        temporal/frequency multiplexing gain.  It saturates toward 1 as modes
        grow, which is the point: multiplexing buys rate, not fidelity.
        """
        return multiplexed_success(self.success_probability(), modes)

    def generation_rate_hz(self, pulse_rate_hz: float,
                           modes: int = 1) -> float:
        """Mean successful attempts per second.

        Capped by detector dead time: a herald needs **both** detectors live, so
        the coincidence rate cannot exceed one per dead time of either.  This is
        a *bound*, not a busy-fraction model -- it says the hardware cannot
        deliver more than this, which is enough to stop the model reporting a
        rate the detectors could not sustain.  A tighter treatment would track
        each detector's recovery, which belongs with the scheduling layer rather
        than here.
        """
        p = self.success_probability_multiplexed(modes)
        nominal = float(pulse_rate_hz) * p
        dead_times = [arm.detector.dead_time_s for arm in (self.arm_a, self.arm_b)
                      if arm.detector.dead_time_s > 0.0]
        if not dead_times:
            return nominal
        return float(min(nominal, 1.0 / max(dead_times)))


def multiplexed_success(single_attempt_probability: float,
                        modes: int) -> float:
    """``1 - (1-p)^M`` for ``M`` independent modes, clamped to a probability."""
    if modes < 0:
        raise ValueError("modes must be non-negative")
    p = float(np.clip(single_attempt_probability, 0.0, 1.0))
    if modes == 0:
        return 0.0
    return float(1.0 - (1.0 - p) ** modes)


def ideal_success_from_loss(arm_a: PhotonicLink,
                            arm_b: PhotonicLink) -> float:
    """Closed form for the no-dark-count, perfect-mode-matching case.

    ``p = 1/2 * (eta_a * epsilon_a) * (eta_b * epsilon_b)`` where each arm's
    factor is its total end-to-end efficiency including detection.  This is the
    analytic reference the implementation is held to, and the *basis* of the M2
    acceptance test: the numerical path must reproduce it exactly when the
    complications it models are switched off.
    """
    return float(BARRETT_KOK_IDEAL_SUCCESS
                 * arm_a.total_efficiency()
                 * arm_b.total_efficiency())


def elementary_link_from_specs(
    length_km: float,
    *,
    alpha_db_km: float = 0.2,
    detector_efficiency: float = 0.8,
    dark_count_hz: float = 100.0,
    coincidences_window_s: float = 1e-9,
    memory_efficiency: float = 1.0,
    mode_matching: float = 1.0,
) -> BarrettKok:
    """Build a symmetric elementary link from scalar hardware specs.

    A convenience for the common case where both arms are identical, which is
    what a single fibre span between two nodes with a midpoint beam splitter is:
    each arm has length ``length_km / 2.0``.  Asymmetric spans call
    :class:`BarrettKok` directly with two different :class:`PhotonicLink` arms.
    """
    def arm() -> PhotonicLink:
        return PhotonicLink(
            length_km=length_km / 2.0,
            alpha_db_km=alpha_db_km,
            memory_efficiency=memory_efficiency,
            detector=Detector(efficiency=detector_efficiency,
                              dark_count_rate_hz=dark_count_hz),
        )

    return BarrettKok(arm_a=arm(), arm_b=arm(),
                      coincidence_window_s=coincidences_window_s,
                      mode_matching=mode_matching)


def compare_link_models(link) -> dict:
    """Compare a :class:`~quantumnet.topology.graph.QuantumLink`'s rate models.

    ``QuantumLink`` predates this module and computes its generation rate as
    ``pulse_rate * (detector_eff * transmissivity)^2`` -- a squared-efficiency
    heuristic that omits the 1/2 from the beam splitter and any dark counts.
    This returns both numbers side by side so the difference is visible and
    attributable rather than being a silent discrepancy between two parts of
    the codebase.

    The two are not expected to agree: the heuristic is roughly ``2x`` the
    Barrett-Kok figure at low dark counts, because the factor it drops is
    exactly the 1/2.

    The ratio is reported as ``None`` when the Barrett-Kok rate underflows to
    zero, rather than ``inf``: beyond a few hundred kilometres the probability
    is below what a float can carry, and an infinite ratio would read as a
    modelling failure instead of an exhausted dynamic range.
    """
    legacy = float(link.generation_rate())
    model = elementary_link_from_specs(
        link.length_km,
        alpha_db_km=link.alpha_db_km,
        detector_efficiency=link.detector_eff,
        dark_count_hz=link.dark_count_hz,
    )
    barrett_kok = model.generation_rate_hz(link.pulse_rate_hz)
    if barrett_kok > 0.0:
        ratio: float | None = legacy / barrett_kok
    elif legacy > 0.0:
        ratio = None      # underflow, not a disagreement
    else:
        ratio = 1.0       # both exhausted: no information either way
    return {
        "legacy_rate_hz": legacy,
        "barrett_kok_rate_hz": barrett_kok,
        "success_probability": model.success_probability(),
        "raw_fidelity": model.raw_fidelity(),
        "ratio": ratio,
        "length_km": float(link.length_km),
    }


def single_photon_attempt_probability(
    length_km: float,
    *,
    alpha_db_km: float = 0.2,
    detector_efficiency: float = 0.8,
    source_efficiency: float = 1.0,
) -> float:
    """Probability that one photon crosses the span *and* is detected.

    ``eta = source * 10^(-alpha*L/10) * detector_eff``.  The single-photon
    scheme this describes is the one ``QuantumLink.entanglement_generation_rate``
    models; it is provided here so the two schemes can be compared on equal
    footing rather than one being assumed to be the other.
    """
    return float(source_efficiency
                 * fiber_transmissivity(length_km, alpha_db_km)
                 * detector_efficiency)
