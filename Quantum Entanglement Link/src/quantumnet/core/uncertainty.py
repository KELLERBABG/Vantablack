"""Uncertainty quantification, with the kinds of uncertainty kept apart.

Why this module exists
----------------------
Every number this package reported was a single point estimate. Measured on
``logical_error_rate`` at d = 3, p = 0.003 over five seeds:

    seed  3: 0.00200      mean   0.00200
    seed  7: 0.00250      sd     0.00050      <- 25% of the mean
    seed  9: 0.00150      spread 50% of the mean
    seed 11: 0.00250
    seed 13: 0.00150

A reader of "0.00200" has no way to know it carries that much spread. The value is not
wrong -- it is the mean of five seeds -- but the interval is part of the measurement and
was not being reported.

The three kinds, and why they must not be merged
------------------------------------------------
1. **Statistical.** Sampling noise. Boundable exactly for a counted rate, cheap to widen
   by taking more shots.
2. **Parameter.** The inputs are not known to fifteen digits. How far does a key rate move
   when detector efficiency moves by 5%?
3. **Model.** The package's remaining calibration differences (see the whitepaper,
   section 4.4). That disagreement is *not* sampling noise and *not* input
   precision. It is the model being a model.

This module computes (1) and (2) and **deliberately refuses to compute (3)**. A combined
interval that appeared to cover model error would be worse than no interval at all,
because it would look like a guarantee. Model disagreement is reported as a separate,
explicit caveat -- see :func:`Report.model_caveat`.

Nothing here reaches for a device. With no hardware attached, a quantile of a prior is
the honest form of "I am not certain", not a telemetry stream.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Sequence

import numpy as np

#: Default confidence level. 95% is the convention in the literature this package cites.
DEFAULT_LEVEL = 0.95


class UncertaintyError(ValueError):
    """Raised for an invalid uncertainty request."""


# Kind 1: statistical, from counted events

@dataclass(frozen=True)
class CountEstimate:
    """A rate from counted events, with an interval that respects the count.

    **Zero successes need a different rule, and it is not a special case to skip.** With
    zero observed events the normal approximation gives ``0 ± 0``, which claims certainty
    from absence. The correct statement is an upper bound, and the rule of three supplies
    it: with no events in ``n`` trials, the 95% upper bound is about ``3/n``. This package
    hits that case routinely -- ``d=7, p=0.003`` measured exactly 0 in 6000 shots -- so
    treating it as an edge case would put a false certainty in the most quotable row.
    """

    successes: int
    trials: int
    level: float = DEFAULT_LEVEL

    def __post_init__(self) -> None:
        if self.trials < 1:
            raise UncertaintyError(f"trials must be positive, got {self.trials}")
        if self.successes < 0:
            raise UncertaintyError(f"successes must be non-negative, got {self.successes}")
        if self.successes > self.trials:
            raise UncertaintyError(
                f"successes ({self.successes}) exceed trials ({self.trials})")
        if not 0.0 < self.level < 1.0:
            raise UncertaintyError(f"level must be in (0, 1), got {self.level}")

    @property
    def rate(self) -> float:
        return self.successes / self.trials

    @property
    def is_zero_observed(self) -> bool:
        return self.successes == 0

    def interval(self) -> tuple[float, float]:
        """A two-sided interval, or a one-sided upper bound when nothing was observed.

        Uses the Wilson score interval, which behaves at small counts and near the
        boundaries where the normal approximation does not. Implemented directly rather
        than pulled in, because the package's promise is ``numpy`` alone and this is
        twelve lines.
        """
        n, k = self.trials, self.successes
        z = _z_for(self.level)
        if k == 0:
            # Rule of three: 0 events in n trials bounds the rate at about 3/n.
            return 0.0, float(min(1.0, 3.0 / n))
        p = k / n
        denom = 1.0 + z * z / n
        centre = (p + z * z / (2 * n)) / denom
        half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
        return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def _z_for(level: float) -> float:
    """Two-sided normal quantile for a confidence level, without scipy.

    ``z`` for 0.95 is 1.959964; the values are tabulated for the levels anyone actually
    uses and interpolated by a rational approximation otherwise, so the module does not
    need a statistics dependency for four numbers.
    """
    table = {0.80: 1.281552, 0.90: 1.644854, 0.95: 1.959964,
             0.98: 2.326348, 0.99: 2.575829, 0.999: 3.290527}
    for known, z in table.items():
        if abs(level - known) < 1e-9:
            return z
    # Acklam's inverse normal CDF, good to about 1e-9 over this range.
    p = 1.0 - (1.0 - level) / 2.0
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]
    plow, phigh = 0.02425, 1 - 0.02425
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p > phigh:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
                ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    q, r = p - 0.5, (p - 0.5) ** 2
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
           (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)


def combine_counts(estimates: Iterable[CountEstimate]) -> CountEstimate:
    """Pool independent runs by summing counts.

    Pooling is often better than averaging rates: it keeps the total sample size, so the
    interval reflects all the work done. Averaging five per-seed rates and then quoting a
    per-seed interval would understate the evidence.
    """
    items = list(estimates)
    if not items:
        raise UncertaintyError("no estimates to combine")
    level = items[0].level
    if any(abs(e.level - level) > 1e-12 for e in items):
        raise UncertaintyError("cannot pool estimates at different confidence levels")
    return CountEstimate(successes=sum(e.successes for e in items),
                         trials=sum(e.trials for e in items), level=level)


# Kind 2: parameter sensitivity, by propagation

@dataclass
class Uncertain:
    """A parameter believed to a stated precision, not to fifteen digits.

    The distribution is not assumed. A caller supplies draws, or a ``(low, high)`` range
    read as a uniform interval, or a central value with a relative spread. Propagation is
    Monte Carlo through the real calculation rather than a linearised error formula,
    because the quantities here (Werner products, binary entropies, threshold crossings)
    are not close to linear in their inputs.
    """

    name: str
    draws: np.ndarray

    def __post_init__(self) -> None:
        d = np.asarray(self.draws, dtype=float)
        if d.ndim != 1 or d.size < 2:
            raise UncertaintyError(
                f"parameter {self.name!r} needs at least two draws, got shape {d.shape}")
        if not np.all(np.isfinite(d)):
            raise UncertaintyError(f"parameter {self.name!r} has non-finite draws")
        object.__setattr__(self, "draws", d)

    @property
    def nominal(self) -> float:
        return float(np.median(self.draws))


def uniform_parameter(name: str, low: float, high: float, *,
                      size: int = 200, seed: int = 0) -> Uncertain:
    """A parameter known only to lie in a range."""
    if not high >= low:
        raise UncertaintyError(f"{name}: high ({high}) must not be below low ({low})")
    rng = np.random.default_rng(seed)
    return Uncertain(name, rng.uniform(low, high, size=size))


def relative_parameter(name: str, nominal: float, rel_spread: float, *,
                       size: int = 200, seed: int = 0,
                       distribution: str = "normal") -> Uncertain:
    """A parameter known to a *relative* precision, e.g. detector efficiency to 5%.

    ``normal`` truncates at zero, because a detection efficiency drawn negative is not a
    hardware variation, it is a broken sampler -- and letting one through would corrupt
    the interval in a way that looks like physics.
    """
    if rel_spread < 0:
        raise UncertaintyError(f"{name}: rel_spread must be non-negative, got {rel_spread}")
    rng = np.random.default_rng(seed)
    scale = abs(nominal) * rel_spread
    if distribution == "normal":
        draws = rng.normal(nominal, scale, size=size)
    elif distribution == "uniform":
        draws = rng.uniform(nominal - scale, nominal + scale, size=size)
    else:
        raise UncertaintyError(
            f"unknown distribution {distribution!r}; use 'normal' or 'uniform'")
    return Uncertain(name, np.clip(draws, 0.0, None))


@dataclass
class Sensitivity:
    """How much a reported quantity moves when the inputs are allowed to vary."""

    name: str
    nominal: float
    low: float
    high: float
    draws: np.ndarray
    parameters: tuple[str, ...] = ()
    level: float = DEFAULT_LEVEL

    @property
    def half_width(self) -> float:
        # Cast to a Python float: a numpy scalar leaking into a caller's formatting or
        # comparison can surprise in ways unrelated to the statistics.
        return float(self.high - self.low) / 2.0

    @property
    def relative_half_width(self) -> float:
        if self.nominal == 0.0:
            return float("inf")
        return float(self.half_width / abs(self.nominal))

    def describe(self) -> str:
        pct = 100 * self.relative_half_width
        spread = "" if not math.isfinite(pct) else f" ({pct:.1f}% of nominal)"
        return (f"{self.name} = {self.nominal:.6g} "
                f"[{self.low:.6g}, {self.high:.6g}]{spread}")


def propagate(name: str, function: Callable[..., float],
              parameters: Sequence[Uncertain], *,
              level: float = DEFAULT_LEVEL) -> Sensitivity:
    """Run ``function`` over the joint draws of the uncertain parameters.

    Every parameter must supply the same number of draws, so they are paired by index
    rather than resampled. That matters when two inputs are correlated -- the correlated
    case in the chance-constrained placement work is exactly this -- and resampling would
    quietly destroy the correlation.
    """
    items = list(parameters)
    if not items:
        raise UncertaintyError("propagate needs at least one uncertain parameter")
    sizes = {p.draws.size for p in items}
    if len(sizes) != 1:
        raise UncertaintyError(
            "all parameters must supply the same number of draws so they stay paired; "
            f"got sizes {sorted(sizes)}")
    n = sizes.pop()

    values = np.empty(n, dtype=float)
    for i in range(n):
        # A caller's function may raise at the edge of its domain (math.log(0.0),
        # math.sqrt(-1)) or a non-finite float; either way report our own error.
        try:
            values[i] = function(**{p.name: float(p.draws[i]) for p in items})
        except (ValueError, ZeroDivisionError, OverflowError) as exc:
            raise UncertaintyError(
                f"{name}: the function raised {type(exc).__name__} ({exc}) on draw "
                f"{i} of {n}. The parameter ranges reach outside the function's domain, "
                f"so the interval would be meaningless. Narrow the ranges or guard the "
                f"function.") from exc

    if not np.all(np.isfinite(values)):
        bad = int(np.sum(~np.isfinite(values)))
        raise UncertaintyError(
            f"{name}: {bad} of {n} draws were non-finite; the interval would be "
            f"meaningless. Check the function at the edges of the parameter ranges.")

    alpha = (1.0 - level) / 2.0
    low, high = np.quantile(values, [alpha, 1.0 - alpha])
    return Sensitivity(
        name=name, nominal=float(np.median(values)), low=float(low), high=float(high),
        draws=values, parameters=tuple(p.name for p in items), level=level)


# Reporting: never let the three kinds look like one

@dataclass
class Report:
    """One reported quantity, with the uncertainty kinds kept visibly separate."""

    name: str
    value: float
    unit: str = ""
    #: Statistical interval from counted events, if any.
    statistical: tuple[float, float] | None = None
    #: Parameter-propagation interval, if any.
    parameter: tuple[float, float] | None = None
    #: Model disagreement. Text, never a number -- see the module docstring.
    model_caveat: str = ""
    notes: list[str] = field(default_factory=list)

    def line(self) -> str:
        unit = f" {self.unit}" if self.unit else ""
        parts = [f"{self.name} = {self.value:.6g}{unit}"]
        if self.statistical:
            lo, hi = self.statistical
            parts.append(f"stat [{lo:.6g}, {hi:.6g}]")
        if self.parameter:
            lo, hi = self.parameter
            parts.append(f"param [{lo:.6g}, {hi:.6g}]")
        return "   ".join(parts)

    def describe(self) -> str:
        lines = [self.line()]
        for note in self.notes:
            lines.append(f"    {note}")
        if self.model_caveat:
            lines.append(f"    MODEL, not covered by the intervals above: "
                         f"{self.model_caveat}")
        return "\n".join(lines)


def compare_with_reference(name: str, mine: float, reference: float, *,
                           statistical: tuple[float, float] | None = None,
                           model_caveat: str = "") -> Report:
    """Compare against a published value, saying whether the interval covers it.

    The useful output is not the difference, it is **whether the disagreement is
    explained by the stated uncertainty**. If the interval covers the reference, the
    difference is consistent with sampling noise. If it does not, something other than
    noise is at work and the report says so rather than leaving a reader to divide two
    numbers and guess.
    """
    report = Report(name=name, value=mine, statistical=statistical,
                    model_caveat=model_caveat)
    delta = mine - reference
    report.notes.append(f"reference {reference:.6g}   delta {delta:+.6g}")
    if statistical:
        lo, hi = statistical
        if lo <= reference <= hi:
            report.notes.append(
                "the reference lies INSIDE the statistical interval, so the difference "
                "is consistent with sampling noise")
        else:
            report.notes.append(
                "the reference lies OUTSIDE the statistical interval, so sampling noise "
                "does not explain the difference")
    return report


# The multi-seed runner: what turns a measured spread into a reported interval

def sampled_rate(name: str, run: Callable[[int], tuple[int, int]],
                 seeds: Sequence[int], *, level: float = DEFAULT_LEVEL,
                 model_caveat: str = "") -> Report:
    """Run a counted measurement over several seeds and pool the counts.

    ``run(seed)`` must return ``(events, trials)`` -- for a decoder benchmark,
    ``(logical_errors, shots + decode_failures)`` is *not* right, and the reason is the
    one the package already documents: **a shot the harness could not decode is not
    evidence that the code failed.** Folding decode failures into the numerator would
    overstate the error rate; folding them into the denominator would claim they were
    measured. They are excluded from both, and their count is reported as a separate
    note so the exclusion is visible rather than silent.

    Pooling rather than averaging matters: five runs of 2000 shots pooled report from
    10,000 shots, so the interval reflects all the work. Averaging five rates and then
    quoting a per-run interval would understate the evidence.

    The returned :class:`Report` carries the spread **between** seeds as a note in
    addition to the pooled interval. The two answer different questions -- how well the
    rate is known, versus how much a single run would have misled -- and a reader of the
    reported figure benefits from both.
    """
    seeds = list(seeds)
    if not seeds:
        raise UncertaintyError(f"{name}: no seeds supplied")

    estimates: list[CountEstimate] = []
    per_seed: list[float] = []
    unmeasured = 0
    for seed in seeds:
        events, trials, *rest = run(seed)
        unmeasured += int(rest[0]) if rest else 0
        if trials < 1:
            raise UncertaintyError(
                f"{name}: seed {seed} reported {trials} trials, so it carries no "
                f"information and would silently widen nothing")
        estimates.append(CountEstimate(events, trials, level=level))
        per_seed.append(events / trials)

    pooled = combine_counts(estimates)
    report = Report(name=name, value=pooled.rate, statistical=pooled.interval(),
                    model_caveat=model_caveat)
    report.notes.append(
        f"pooled {pooled.successes}/{pooled.trials} over {len(seeds)} seeds "
        f"({pooled.level:.0%} interval)")
    spread = max(per_seed) - min(per_seed)
    if pooled.rate > 0:
        report.notes.append(
            f"per-seed values {' '.join(f'{v:.5f}' for v in per_seed)}; "
            f"spread {spread:.5f} = {100 * spread / pooled.rate:.0f}% of the pooled rate")
    if unmeasured:
        report.notes.append(
            f"{unmeasured} shots were NOT reported by the harness and are excluded from "
            f"both counts rather than counted as errors")
    return report
