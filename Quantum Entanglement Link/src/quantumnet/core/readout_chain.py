"""Readout-chain recovery and afterpulsing, as a genuine state machine.

Why this is a *readout chain* model and not a detector model
-----------------------------------------------------------
The effect modelled here is **not intrinsic to the superconducting nanowire**. Burenkov
et al. (J. Appl. Phys. 113, 213102 (2013), arXiv:1306.3749) measured it, traced it to
reflections in the RF amplifier chain perturbing the bias, and showed it disappears when
a different amplifier with better low-frequency response is fitted:

    "We have no reason to think that the actual SNSPD itself has intrinsic afterpulsing."

So the name says readout chain, because that is what the physics is. A model called a
"detector state machine" would attribute to the device a behaviour that belongs to the
electronics around it -- and a reviewer would be right to reject it.

What the existing package does, and what this adds
--------------------------------------------------
:class:`~quantumnet.core.photonics.Detector` already carries ``afterpulse_probability``,
but applies it as a **flat constant**: no dependence on how long ago the previous click
was, and no memory of detector state. ``dead_time_s`` is likewise a scalar. Three measured
properties cannot be expressed that way:

1. **The recovery is not monotonic.** Efficiency is essentially zero below ~80 ns, then
   *overshoots above nominal* around ~180 ns, then settles back. A saturating
   ``1 - exp(-t/tau)`` -- the usual assumption -- is wrong here, and wrong in the
   direction that understates spurious counts at the worst moment.
2. **Afterpulsing is sharply time-localised**, peaking ~180 ns after a click with a
   secondary peak ~360 ns after (an afterpulse of an afterpulse).
3. **Both depend on the previous click**, so they need state, not a per-attempt constant.

The overshoot is the interesting part: the same bias perturbation that causes the
afterpulse *raises* detection efficiency for a moment. A model with a monotonic recovery
calibrated against this experiment would be a mis-calibration, not an approximation.

Metrics: what is computed, and what is deliberately not
-------------------------------------------------------
The quantity here is the **conditional detection probability**

    P(click at t = tau | click at t = 0)

which is an instrument property. It is *not* ``g^(2)(tau)``, which describes the photon
statistics of the light field and would be a source measurement. Burenkov et al. measure
the conditional form (their Fig. 9 and Fig. 10) and never use ``g^(2)``; using it here
would be a category error that produces plausible-looking numbers.

Calibration status -- read this before quoting anything
------------------------------------------------------
The parameters below are transcribed from the paper's **reported features**, not fitted to
its data points. That gives tests that assert real, falsifiable properties (dead zone,
overshoot, secondary peak, exponential bias dependence) without any claim to reproduce the
measured curve point for point.

Authoring a calibration named after Burenkov et al. and then comparing curves would imply
a fit to their data that has not been performed. When raw data becomes available,
:meth:`ReadoutChainRecovery.calibrated` is the entry point for a real fit and the
provenance field records where the numbers came from.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

#: Features reported by Burenkov et al. (2013), in seconds, transcribed from the paper's
#: stated values rather than fitted to its figures.
AFTERPULSE_PEAK_S = 180e-9
SECONDARY_AFTERPULSE_PEAK_S = 360e-9
DEAD_ZONE_S = 80e-9
DEAD_TIME_S = 150e-9
OVERSHOOT_PEAK_S = 180e-9


class ReadoutChainError(ValueError):
    """Raised for an invalid readout-chain configuration."""


@dataclass(frozen=True)
class RecoveryCurve:
    """Detection efficiency as a function of time since the previous click.

    Defined by **calibration points**, interpolated, rather than by a closed form. The
    reason is that the measured curve is non-monotonic with a peak above nominal, and any
    convenient closed form (``1 - exp(-t/tau)``, an error function, a logistic) is
    monotonic. Forcing the data through such a form would discard precisely the feature
    that makes this system interesting.

    ``efficiency`` values are relative to the nominal efficiency, so ``1.0`` is nominal and
    a value above 1 is the overshoot.
    """

    times_s: np.ndarray
    efficiency: np.ndarray
    nominal: float = 1.0
    provenance: str = "transcribed features, Burenkov et al. 2013"

    def __post_init__(self) -> None:
        times = np.asarray(self.times_s, dtype=float)
        eff = np.asarray(self.efficiency, dtype=float)
        if times.ndim != 1 or eff.ndim != 1 or times.size != eff.size:
            raise ReadoutChainError(
                f"times and efficiency must be 1-D and the same length, got "
                f"{times.shape} and {eff.shape}")
        if times.size < 2:
            raise ReadoutChainError("need at least two calibration points")
        if np.any(np.diff(times) <= 0):
            raise ReadoutChainError("calibration times must be strictly increasing")
        if not np.all(np.isfinite(eff)):
            raise ReadoutChainError("efficiency values must all be finite")
        object.__setattr__(self, "times_s", times)
        object.__setattr__(self, "efficiency", eff)

    def at(self, since_last_s: float | np.ndarray) -> np.ndarray:
        """Relative efficiency at one or more elapsed times.

        Clamped at both ends: before the first point and after the last, efficiency is held
        at the terminal values rather than extrapolated. Extrapolating an overshoot beyond
        its measured support would invent a feature.
        """
        t = np.asarray(since_last_s, dtype=float)
        return np.interp(t, self.times_s, self.efficiency * self.nominal)

    @property
    def overshoot_peak(self) -> float:
        """The largest relative efficiency on the measured curve."""
        return float(np.max(self.efficiency))

    @property
    def is_non_monotonic(self) -> bool:
        """True when the curve rises above nominal and comes back down.

        Checked structurally rather than asserted in prose, because 'non-monotonic' is the
        claim that distinguishes this model from the usual one.
        """
        above = self.efficiency > self.nominal * (1.0 + 1e-12)
        if not above.any():
            return False
        first_above = int(np.argmax(above))
        return bool(np.any(self.efficiency[first_above:] <= self.nominal))

    def describe(self) -> str:
        return (f"recovery curve, {self.times_s.size} points, "
                f"peak {self.overshoot_peak:.3f}x nominal at "
                f"{self.times_s[int(np.argmax(self.efficiency))] * 1e9:.0f} ns, "
                f"non-monotonic: {self.is_non_monotonic}")


def burenkov_2013_recovery(gamma: float = 1.45) -> RecoveryCurve:
    """The recovery shape reported by Burenkov et al., as relative efficiency.

    Transcribed from the paper's stated features (their Fig. 10 and Sec. VI): efficiency is
    essentially zero up to about 80 ns, rises to a peak *above* nominal at about 180 ns,
    and settles to nominal over the following several hundred nanoseconds.

    **``gamma`` is the overshoot factor and it is not a measured quantity.** The paper
    states that the efficiency exceeds nominal at the peak but does not give a fitted
    amplitude we can rely on, and the figure cannot be read to better than visual
    precision. Its default is therefore a *placeholder* chosen to be clearly above 1 so the
    non-monotonicity is explicit, and any result depending on its exact value is not
    calibrated. When raw data is fitted, this function is superseded.
    """
    if gamma <= 1.0:
        raise ReadoutChainError(
            f"gamma must exceed 1 for an overshoot; got {gamma}. A gamma <= 1 describes "
            f"the monotonic recovery this model exists to reject.")
    times = np.array([0.0, 40e-9, 80e-9, 110e-9, 140e-9, 180e-9, 240e-9,
                      320e-9, 450e-9, 700e-9, 1000e-9])
    eff = np.array([0.0, 0.0, 0.02, 0.30, 0.85, gamma, 1.15, 1.03, 1.0, 1.0, 1.0])
    return RecoveryCurve(
        times_s=times, efficiency=eff,
        provenance=("transcribed features (dead zone 80 ns, overshoot peak 180 ns) from "
                    "Burenkov et al. 2013, Fig. 10 / Sec. VI; overshoot amplitude is a "
                    "placeholder, not a fit"))


@dataclass
class AfterpulseKernel:
    """Conditional afterpulse probability as a function of elapsed time.

    ``P(click now | click at t = 0)``, as a sum of localised peaks. The paper reports a peak
    near 180 ns and a secondary near 360 ns, with the secondary arising from the first
    afterpulse rather than from the original click -- so the train is generated recursively
    rather than by one wide kernel.

    ``amplitude`` sets the total probability that an afterpulse occurs at all, and is the
    quantity that rises exponentially with bias current near the critical value.
    """

    amplitude: float
    primary_center_s: float = AFTERPULSE_PEAK_S
    primary_sigma_s: float = 35e-9
    secondary_center_s: float = SECONDARY_AFTERPULSE_PEAK_S
    secondary_sigma_s: float = 35e-9
    secondary_ratio: float = 0.35

    def __post_init__(self) -> None:
        if not 0.0 <= self.amplitude <= 1.0:
            raise ReadoutChainError(
                f"afterpulse amplitude must be in [0, 1], got {self.amplitude}")
        if self.primary_sigma_s <= 0.0 or self.secondary_sigma_s <= 0.0:
            raise ReadoutChainError("afterpulse widths must be positive")
        if not 0.0 <= self.secondary_ratio <= 1.0:
            raise ReadoutChainError(
                f"secondary_ratio must be in [0, 1], got {self.secondary_ratio}")

    def at(self, since_last_s: float | np.ndarray) -> np.ndarray:
        """Conditional afterpulse probability density at elapsed time(s)."""
        t = np.asarray(since_last_s, dtype=float)
        norm = 1.0 + self.secondary_ratio
        primary = np.exp(-0.5 * ((t - self.primary_center_s) / self.primary_sigma_s) ** 2)
        secondary = self.secondary_ratio * np.exp(
            -0.5 * ((t - self.secondary_center_s) / self.secondary_sigma_s) ** 2)
        return self.amplitude * (primary + secondary) / norm

    def peak_time_s(self) -> float:
        return self.primary_center_s

    def secondary_peak_time_s(self) -> float:
        return self.secondary_center_s


def afterpulse_amplitude_from_bias(bias_uA: float, critical_uA: float,
                                   *, scale: float = 1.0,
                                   reference_margin_uA: float = 0.1) -> float:
    """Afterpulse amplitude rising exponentially toward the critical current.

    The paper's Fig. 6 shows the afterpulse probability increasing exponentially as the
    bias approaches the critical value, and becoming negligible when the bias is reduced
    away from it. Modelled here on the margin ``I_c - I_b`` so that amplitude is a function
    of how close to critical the device is operated -- which is the behaviour, not an
    arbitrary curve in current.

    Returns a value in ``[0, 1]``. ``scale`` is a placeholder calibration: the paper gives
    the functional form and the qualitative trend but no fitted prefactor we can adopt, so
    a caller needing quantitative amplitude must supply real data through
    :meth:`ReadoutChainRecovery.calibrated`.
    """
    if critical_uA <= 0:
        raise ReadoutChainError(f"critical current must be positive, got {critical_uA}")
    if scale < 0.0:
        raise ReadoutChainError(f"scale must be non-negative, got {scale}")
    margin = critical_uA - bias_uA
    if margin <= 0:
        raise ReadoutChainError(
            f"bias {bias_uA} uA is at or above the critical current {critical_uA} uA; "
            f"the detector is not in a detecting regime")
    # Amplitude falls off with the relative margin, so the behaviour is set by how close
    # to critical the device runs rather than by the absolute current scale.
    relative = margin / max(reference_margin_uA, 1e-9)
    return float(min(1.0, scale * math.exp(-relative)))


@dataclass
class ReadoutChainRecovery:
    """A stateful readout chain: detection efficiency and afterpulsing with memory.

    Drop-in companion to :class:`~quantumnet.core.photonics.Detector`. Where the detector
    carries scalars (``dead_time_s``, ``afterpulse_probability``), this carries the *time
    structure* those scalars cannot express: efficiency as a function of elapsed time since
    the last click, and time-localised afterpulsing.

    The state machine is a single variable -- the time of the last detection -- because that
    is what the measured behaviour depends on. It is deliberately not a full recoverable
    simulation of the bias circuit, which would need parameters the paper does not report.
    """

    recovery: RecoveryCurve = field(default_factory=burenkov_2013_recovery)
    afterpulse: AfterpulseKernel = field(default_factory=lambda: AfterpulseKernel(0.0))
    dead_time_s: float = DEAD_TIME_S
    jitter_s: float = 0.0

    def __post_init__(self) -> None:
        if self.dead_time_s < 0.0:
            raise ReadoutChainError(f"dead_time_s must be non-negative")
        if self.jitter_s < 0.0:
            raise ReadoutChainError(f"jitter_s must be non-negative")

    def efficiency_after(self, since_last_s: float | np.ndarray | None):
        """Effective detection efficiency, given how long ago the last click was.

        ``None`` means no previous click, so nominal efficiency applies. Note the return
        can exceed nominal: the overshoot is a real prediction of this model, and clamping
        it to 1.0 would hide the feature the model was built for.
        """
        if since_last_s is None:
            return self.recovery.nominal
        return self.recovery.at(since_last_s)

    def is_blind(self, since_last_s: float) -> bool:
        """True while the chain has not recovered enough to detect at all."""
        if since_last_s < self.dead_time_s:
            return True
        return bool(self.recovery.at(since_last_s) <= 0.0)

    def detect(self, photon_times_s: Sequence[float], *, seed: int | None = None,
               nominal_efficiency: float = 1.0) -> list[float]:
        """Run photon arrival times through the chain, returning click times.

        Events are processed in time order. Each photon clicks with the efficiency
        appropriate to the time since the previous click. Each click may schedule an
        afterpulse, and an afterpulse may schedule a further one -- which is how the
        paper's secondary peak at ~360 ns arises, as an afterpulse *of the first
        afterpulse* rather than as a second, wider feature of the original click.

        The chain's state is a single timestamp: the last click. That is the state the
        measured behaviour depends on.
        """
        rng = np.random.default_rng(seed)
        times = sorted(float(t) for t in photon_times_s)
        clicks: list[float] = []

        def afterpulse_delay() -> float:
            """Draw from the two-peak mixture, or return a non-positive to mean none."""
            if self.afterpulse.amplitude <= 0.0:
                return float("nan")
            # amplitude is the total probability that an afterpulse occurs and the
            # mixture weight picks which peak, so the two are sampled separately.
            if rng.random() >= self.afterpulse.amplitude:
                return float("nan")
            total = 1.0 + self.afterpulse.secondary_ratio
            if rng.random() < 1.0 / total:
                return float(rng.normal(self.afterpulse.primary_center_s,
                                        self.afterpulse.primary_sigma_s))
            return float(rng.normal(self.afterpulse.secondary_center_s,
                                    self.afterpulse.secondary_sigma_s))

        def schedule(after: float, depth: int = 0) -> None:
            """Append a possible afterpulse following a click at ``after``."""
            delay = afterpulse_delay()
            if not (delay > 0.0):
                return
            at = after + delay
            # An afterpulse that lands while the chain is still blind is not registered,
            # the reference being the click that caused it, not the earlier click.
            if at - after < self.dead_time_s:
                return
            clicks.append(at)
            if depth == 0 and self.afterpulse.secondary_ratio > 0.0:
                schedule(at, depth=1)

        for t in times:
            # The state at this photon is the most recent click, afterpulses included.
            if clicks and clicks[-1] > t:
                continue
            last = clicks[-1] if clicks else None
            if last is not None and t - last < self.dead_time_s:
                continue
            eff = float(self.efficiency_after(None if last is None else t - last))
            if rng.random() < min(1.0, nominal_efficiency * eff):
                clicks.append(t)
                schedule(t)

        return sorted(clicks)

    def conditional_click_probability(self, delays_s: np.ndarray, *,
                                      nominal_efficiency: float = 1.0) -> np.ndarray:
        """``P(click at tau | click at 0)`` on a delay grid -- the validation metric.

        This is the quantity the paper measures and the one this model predicts. It is not
        ``g^(2)(tau)``: that describes the light field's photon statistics, whereas this is
        an instrument response to a known prior click.
        """
        delays = np.asarray(delays_s, dtype=float)
        if np.any(delays < 0):
            raise ReadoutChainError("delays must be non-negative")
        eff = self.recovery.at(delays)
        p_detect = np.clip(nominal_efficiency * eff, 0.0, 1.0)
        p_afterpulse = self.afterpulse.at(delays)
        # Either route produces a click: a real photon detected with the recovered
        # efficiency, or a spurious afterpulse; exclusive at these small probabilities.
        return np.clip(p_detect + p_afterpulse, 0.0, 1.0)

    @classmethod
    def calibrated(cls, recovery: RecoveryCurve, afterpulse: AfterpulseKernel, *,
                   dead_time_s: float = DEAD_TIME_S, source: str) -> "ReadoutChainRecovery":
        """Build from a real fit, recording where the numbers came from.

        The ``source`` argument is required and has no default. A calibration object whose
        provenance is unrecorded is indistinguishable from transcribed guesses, and that
        distinction is the whole point of this module existing separately from the flat
        ``afterpulse_probability`` scalar.
        """
        if not source or not source.strip():
            raise ReadoutChainError(
                "a calibrated readout chain must record its data source; pass the "
                "dataset or figure identifier so the calibration is auditable")
        obj = cls(recovery=recovery, afterpulse=afterpulse, dead_time_s=dead_time_s)
        object.__setattr__(obj, "provenance", source)
        return obj

    provenance: str = "transcribed features only -- NOT a fit to measured data"
