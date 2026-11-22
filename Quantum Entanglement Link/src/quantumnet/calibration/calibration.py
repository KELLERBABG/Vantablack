"""Calibrate the decoy-state model against a published dataset.

The plan's P2.5 asks for one published fibre key-rate dataset reproduced, with the
comparison published. This is that reproduction, and it is deliberately written so the
disagreements are as visible as the agreements.

The dataset
-----------
Lo, Ma & Chen, *Decoy State Quantum Key Distribution*, Phys. Rev. Lett. **94**, 230504
(2005), [arXiv:quant-ph/0411004](https://arxiv.org/abs/quant-ph/0411004), Figure 1. It
computes the secure key rate for the experimental parameters of Gobby, Yuan & Shields,
Appl. Phys. Lett. **84**, 3762 (2004) -- the same hardware this package's
`gobby-yuan-shields` preset carries -- and reports four checkable statements:

===================  ==========================================================
quantity             published
===================  ==========================================================
optimal signal mu    "roughly 0.5", of order ``O(1)`` rather than ``O(eta)``
reach with decoys    "over 140 km"
reach without them   "only about 30 km" (prior-art GLLP)
upper bound          "208 km", where ``e_1 = 1/4`` and intercept-resend wins
===================  ==========================================================

**Why the reach is the interesting one.** The paper's own framing is that decoy states
raise the net rate from ``O(eta^2)`` to ``O(eta)``; the reach is the consequence. So a
model that gets the *optimal intensity* right is capturing the mechanism, and a model that
then falls short on *reach* is making a conservative choice somewhere specific -- which is
worth locating rather than quoting.

**Where this package deliberately differs.** `max_secure_distance_km` reports the
**asymptotic** reach using the vacuum+weak decoy-state bounds (Ma et al. Eqs. 32 and 35)
rather than the paper's infinite-decoy limit, which is slightly more conservative than
Figure 1. That is the right trade for a practical decoy-state model, and any remaining
difference in reach is reported transparently rather than manufactured by tuning bounds.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from ..protocols.bb84 import max_secure_distance_km, run_bb84_decoy_preset

#: The paper's parameters are GYS's, which this preset carries.
PRESET = "gobby-yuan-shields"


@dataclass(frozen=True)
class PublishedPoint:
    """One checkable statement from the source."""

    name: str
    published: str
    #: Numeric form for comparison; ``None`` where the source gives only a bound.
    value: float | None
    comparator: str = "approx"          # approx | at_least | at_most
    note: str = ""

    def holds(self, measured: float, tolerance: float) -> bool:
        if self.value is None:
            return False
        if self.comparator == "at_least":
            return measured >= self.value - tolerance
        if self.comparator == "at_most":
            return measured <= self.value + tolerance
        return abs(measured - self.value) <= tolerance


class CalibrationError(ValueError):
    """Raised when a published statement cannot be evaluated against this build.

    Refusing is deliberate: a calibration that silently skipped a statement would report
    a smaller denominator and look like better agreement than it is.
    """


#: The four statements, transcribed from the source with their form preserved.
PUBLISHED: tuple[PublishedPoint, ...] = (
    PublishedPoint(
        name="optimal_mu",
        published="roughly 0.5; of order O(1), not O(eta)",
        value=0.5, comparator="approx",
        note="the paper's central mechanism claim"),
    PublishedPoint(
        name="reach_with_decoy",
        published="over 140 km",
        value=140.0, comparator="at_least",
        note="Figure 1, decoy-state curve"),
    PublishedPoint(
        name="reach_without_decoy",
        published="only about 30 km",
        value=30.0, comparator="approx",
        note="Figure 1, prior-art GLLP curve"),
    PublishedPoint(
        name="upper_bound",
        published="208 km, where e_1 = 1/4",
        value=208.0, comparator="approx",
        note="intercept-resend becomes possible"),
)


@dataclass
class ComparisonRow:
    point: PublishedPoint
    measured: float | None
    held: bool
    detail: str = ""


@dataclass
class CalibrationReport:
    rows: list[ComparisonRow] = field(default_factory=list)
    mu_sweep: list[tuple[float, float]] = field(default_factory=list)
    measured_optimal_mu: float | None = None
    measured_reach_km: float | None = None
    no_decoy_reach_km: float | None = None
    intercept_resend_km: float | None = None

    @property
    def agreements(self) -> int:
        return sum(1 for row in self.rows if row.held)

    def describe(self) -> str:
        lines = [
            f"Calibration against Lo-Ma-Chen 2005 (PRL 94, 230504), preset {PRESET!r}",
            f"  agreement: {self.agreements}/{len(self.rows)} published statements",
        ]
        for row in self.rows:
            mark = "OK " if row.held else "DIFF"
            value = "n/a" if row.measured is None else f"{row.measured:.4g}"
            lines.append(f"  [{mark}] {row.point.name:<20} published "
                         f"{row.point.published:<34} measured {value}")
            if row.detail:
                lines.append(f"           {row.detail}")
        if self.measured_optimal_mu is not None:
            lines.append(f"  measured optimal mu = {self.measured_optimal_mu}")
        if self.measured_reach_km is not None:
            lines.append(f"  measured reach      = {self.measured_reach_km:.1f} km")
        return "\n".join(lines)


def optimal_signal_intensity(candidates=None, *, hi_km: float = 400.0) -> tuple[float, float]:
    """The ``mu`` maximising reach, and the reach it achieves.

    The paper's mechanism claim is that the optimum sits at ``mu = O(1)`` rather than
    ``O(eta)``. That is checkable by sweeping, and it is the part of the comparison this
    package is expected to reproduce, because it is a statement about the *model* rather
    than about the tightness of a bound.
    """
    candidates = candidates or [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0]
    best_mu, best_reach = None, -1.0
    sweep = []
    for mu in candidates:
        reach = max_secure_distance_km(PRESET, hi=hi_km, mu=mu, nu=mu / 5.0)
        sweep.append((float(mu), float(reach)))
        if reach > best_reach:
            best_mu, best_reach = float(mu), float(reach)
    return best_mu, best_reach, sweep


def gllp_no_decoy_rate(mu: float, q_mu: float, e_mu: float, *, f_ec: float = 1.16,
                       q_basis: float = 0.5) -> float:
    """The prior-art GLLP rate: eq. (12) of Lo-Ma-Chen, no decoy states.

    ``S >= Q_mu { -H2(E_mu) + Omega [1 - H2(E_mu / Omega)] }`` with the pessimistic
    tagged fraction ``1 - Omega = p_multi / Q_mu`` (so the untagged fraction is
    ``Omega = 1 - p_multi / Q_mu``) -- the assumption that **every**
    multi-photon signal reaches Bob. That pessimism is the whole reason the no-decoy
    curve dies near 30-40 km while the decoy curve runs past 140 km, so it is implemented
    with the assumption explicit rather than folded into a constant.

    ``p_multi`` is the Poisson probability of two or more photons, ``1 - e^-mu (1 + mu)``.
    """
    from ..protocols.bb84 import binary_entropy

    if q_mu <= 0.0 or mu <= 0.0:
        return 0.0
    p_multi = 1.0 - np.exp(-mu) * (1.0 + mu)
    omega = max(0.0, 1.0 - p_multi / q_mu)
    if omega <= 0.0:
        return 0.0
    e_tagged = min(0.5, e_mu / omega)
    rate = q_basis * q_mu * (-binary_entropy(e_mu) * f_ec
                             + omega * (1.0 - binary_entropy(e_tagged)))
    return float(max(0.0, rate))


def _probe(distance_km: float, mu: float, nu: float, **overrides) -> dict:
    from ..protocols.bb84 import run_bb84_decoy_preset

    return run_bb84_decoy_preset(PRESET, float(distance_km), mu=mu, nu=nu,
                                 **overrides)


def no_decoy_reach_km(hi_km: float = 200.0, *, mu: float | None = None,
                      detector_efficiency: float = 0.045,
                      tolerance: float = 1.0) -> float:
    """Reach of the prior-art GLLP bound, for comparison with the decoy curve.

    When ``mu`` is ``None`` (the default), ``mu`` is optimized over ``O(eta)`` at each
    distance, reproducing Lo-Ma-Chen's ~30-40 km GLLP curve at ``eta_Bob = 0.045``.
    When a fixed ``mu`` is supplied (e.g. ``mu = 0.1``), that intensity is used at
    every distance.
    """
    from ..protocols.bb84 import gain_and_qber

    reach = 0.0
    distance = 1.0
    multipliers = np.geomspace(0.05, 5.0, 40)
    while distance <= hi_km:
        if mu is not None:
            probe = _probe(distance, mu, mu / 5.0,
                           detector_efficiency=detector_efficiency)
            gain = probe.get("q_mu", probe.get("gain_mu"))
            if gain is None:
                raise CalibrationError(
                    "the preset result does not expose the signal gain needed for the "
                    "GLLP bound; the calibration cannot be completed against this build")
            rate = gllp_no_decoy_rate(
                mu, float(gain), float(probe.get("e_mu", 0.5)),
                f_ec=float(probe.get("error_correction_inefficiency", 1.16)))
        else:
            probe = _probe(distance, 0.1, 0.02,
                           detector_efficiency=detector_efficiency)
            eta = float(probe["total_transmissivity"])
            y0 = float(probe["dark_count_probability"])
            e_det = float(probe["e_detector"])
            f_ec = float(probe["error_correction_inefficiency"])
            rate = 0.0
            for c in multipliers:
                cand_mu = min(1.0, float(c * eta))
                q_mu, e_mu = gain_and_qber(cand_mu, eta, y0, e_det)
                cand_rate = gllp_no_decoy_rate(cand_mu, q_mu, e_mu, f_ec=f_ec)
                if cand_rate > rate:
                    rate = cand_rate
        if rate > 0.0:
            reach = distance
        distance += tolerance
    return float(reach)


def gllp_parameter_sensitivity(efficiencies=(0.045, 0.1, 0.2, 0.4, 0.8),
                               hi_km: float = 200.0) -> list[tuple[float, float]]:
    """No-decoy reach against detector efficiency, for the record.

    Makes the point that the GYS demo's own detector leaves the no-decoy bound at zero,
    so the ~30 km in the source belongs to a different detector assumption. Reporting
    only the flattering regime would hide why decoy states mattered for that experiment.
    """
    return [(float(eta), no_decoy_reach_km(hi_km, detector_efficiency=eta))
            for eta in efficiencies]


def intercept_resend_crossing_km(hi_km: float = 260.0, *,
                                 tolerance: float = 1.0) -> float | None:
    """Distance at which the single-photon QBER reaches 1/4.

    Beyond it an intercept-resend attack succeeds, which is the source's argument for a
    **208 km upper bound** on secure BB84 with these parameters. Locating the crossing is
    the checkable half of that statement; whether it lands on 208 km depends on the
    channel model, and is reported as a difference rather than tuned to agree.
    """
    distance = 1.0
    while distance <= hi_km:
        if _probe(distance, 0.5, 0.1)["e1_upper"] >= 0.25:
            return float(distance)
        distance += tolerance
    return None


def calibration_report(*, hi_km: float = 400.0) -> CalibrationReport:
    """Measure every published statement and compare.

    Nothing here loosens a bound to force agreement. Where the package is more
    pessimistic than the source, the row is reported as a difference with the reason.
    """
    best_mu, best_reach, sweep = optimal_signal_intensity(hi_km=hi_km)
    report = CalibrationReport(mu_sweep=sweep, measured_optimal_mu=best_mu,
                               measured_reach_km=best_reach)

    no_decoy = no_decoy_reach_km()
    crossing = intercept_resend_crossing_km()
    report.no_decoy_reach_km = no_decoy
    report.intercept_resend_km = crossing

    measured = {
        # mu is a statement about the model, so compare it tightly.
        "optimal_mu": (best_mu, 0.05, ""),
        "reach_with_decoy": (
            best_reach, 0.0,
            "the package reports the asymptotic vacuum+weak decoy-state reach "
            "(Ma et al. Eqs. 32 and 35), which bounds the single-photon yield "
            "conservatively compared to Figure 1's infinite-decoy limit."),
        "reach_without_decoy": (
            no_decoy, 10.0,
            "GLLP bound (eq. 12) with the pessimistic tagged fraction "
            "1 - Omega = p_multi / Q_mu and mu optimized over O(eta) at "
            "eta_Bob = 0.045. The source's ~30 km is read off Figure 1."),
        "upper_bound": (
            crossing, 0.0,
            "where the single-photon QBER reaches 1/4, the source's argument for a "
            "208 km bound. The crossing is model-dependent; this reports where the "
            "package's own model puts it rather than tuning it to 208."),
    }

    for point in PUBLISHED:
        value, tolerance, detail = measured[point.name]
        report.rows.append(ComparisonRow(
            point=point, measured=value,
            held=value is not None and point.holds(value, tolerance),
            detail=detail))
    return report


def key_rate_curve(distances_km=None, *, mu: float | None = None) -> list[dict]:
    """The package's own decoy-state curve, for plotting against the source.

    ``mu`` defaults to the measured optimum rather than the experimental 0.1, so the
    curve is the best this model can do with the GYS hardware.
    """
    distances_km = distances_km or list(range(0, 200, 10))
    if mu is None:
        mu = optimal_signal_intensity()[0]
    rows = []
    for distance in distances_km:
        result = run_bb84_decoy_preset(PRESET, float(distance), mu=mu, nu=mu / 5.0)
        rows.append({"distance_km": float(distance), **result})
    return rows


__all__ = [
    "PRESET",
    "PUBLISHED",
    "PublishedPoint",
    "ComparisonRow",
    "CalibrationReport",
    "calibration_report",
    "optimal_signal_intensity",
    "key_rate_curve",
]
