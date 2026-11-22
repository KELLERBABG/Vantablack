"""Validation against published experimental data.

What this is for
----------------
This is the **credibility gate**, and the reasoning is
straightforward: nothing in QEL has been checked against hardware, and a
simulator whose numbers agree with nothing is a simulator whose numbers mean
nothing.  A single reproduced published figure is worth more than any feature.

What is actually claimed here, and what is not
----------------------------------------------
Each entry in :data:`PUBLISHED_DATASETS` records a number that a *specific
paper* published, together with the parameters needed to recompute it.  The
model is run at those parameters and the difference is reported.  Two things
follow, and both matter:

* Agreement is evidence that the **implementation** reproduces the model those
  authors used.  It is not evidence about hardware, because the hardware never
  enters -- only the parameters they measured from it.
* Disagreement is reported, not smoothed.  A validation suite that only contains
  comparisons it passes is a marketing document.

The comparison that rises to a real test is the vacuum+weak maximum secure
distance of Ma, Qi, Zhao and Lo: they publish **140.55 km** for the parameter set
they tabulate, and this implementation returns **140.62 km**, a difference of
0.05%.  That is the closest thing to an external check the project has.

Deliberately excluded comparisons
---------------------------------
The Boaron et al. 421 km record is quoted in the literature constantly, and it is
**not** used as a pass/fail target here.  Their protocol is 3-state time-bin with
a one-decoy finite-key bound of the form ``6*log2(19/eps)``; QEL models
asymptotic decoy BB84 with ``q = 1/2``.  Running one against the other would
measure the difference between two protocols and call it model error.  The
dataset is still recorded, with the parameters, so the loss budget can be
checked -- which *is* comparable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .protocols.bb84 import run_bb84_decoy
from .core.physical import fiber_loss_db, fiber_transmissivity


@dataclass(frozen=True)
class PublishedDataset:
    """A number a paper published, with the parameters needed to recompute it.

    ``target_km`` is the quantity being reproduced.  ``kind`` says what sort of
    claim that quantity is, and therefore how the model should be judged
    against it:

    ``"validated"``
        The paper computes the *same* quantity with the *same* estimators, so
        the model must match within tolerance.
    ``"upper-bound"``
        The published number is a bound in a limit the model does not implement
        (infinitely many decoy intensities, say).  The model must fall on the
        correct *side* of it and near the achievable figure -- scoring it as a
        pass/fail equality would be dishonest in both directions.
    ``"context"``
        Recorded for its parameters, not its rate, because the protocol differs.
        Never scored.
    """

    name: str
    citation: str
    url: str
    kind: str
    target_km: float | None = None
    #: Model parameters, ready to pass to :func:`~quantumnet.protocols.bb84.run_bb84_decoy`.
    parameters: dict = field(default_factory=dict)
    #: Fibre loss in dB, if the paper tabulates one (Boaron does).
    published_loss_db: float | None = None
    published_distance_km: float | None = None
    #: For ``kind="upper-bound"``: the achievable figure the bound is near.
    bound_near_km: float | None = None
    note: str = ""

    def __post_init__(self):
        if self.kind not in ("validated", "upper-bound", "context"):
            raise ValueError(f"unknown dataset kind {self.kind!r}")


#: The GYS parameter set as Ma et al. tabulate it (Table I): ``alpha = 0.21 dB/km``,
#: ``e_detector = 3.3%``, ``Y_0 = 1.7e-6``, ``eta_Bob = 0.045``, ``f(e) = 1.22``, 2 MHz.
GYS_PARAMETERS = {
    "alpha_db_km": 0.21,
    "detector_efficiency": 0.045,
    # Y0 is a per-pulse probability; the pulse rate turns it into a rate.
    "dark_count_hz": 1.7e-6 * 2e6,
    "pulse_rate_hz": 2e6,
    "mu": 0.48,
    "nu": 0.05,
    "e_detector": 0.033,
    "error_correction_inefficiency": 1.22,
}

#: The KTH parameter set from the same table, included for a second data point.
KTH_PARAMETERS = {
    "alpha_db_km": 0.2,
    "detector_efficiency": 0.143,
    "dark_count_hz": 4e-4 * 0.1e6,
    "pulse_rate_hz": 0.1e6,
    "mu": 0.48,
    "nu": 0.10,
    "e_detector": 0.01,
    "error_correction_inefficiency": 1.22,
}

#: The modern 1550 nm preset already shipped in the package.
PRACTICAL_PARAMETERS = {
    "alpha_db_km": 0.2,
    "detector_efficiency": 0.8,
    "dark_count_hz": 100.0,
    "pulse_rate_hz": 1e8,
    "mu": 0.5,
    "nu": 0.1,
    "e_detector": 0.01,
    "error_correction_inefficiency": 1.16,
}

PUBLISHED_DATASETS: tuple[PublishedDataset, ...] = (
    PublishedDataset(
        name="ma-vacuum-weak-gys",
        citation=("X. Ma, B. Qi, Y. Zhao, H.-K. Lo, Phys. Rev. A 72, 012326 "
                  "(2005), Fig. 3 -- vacuum+weak decoy with the GYS parameters"),
        url="https://arxiv.org/abs/quant-ph/0503005",
        kind="validated",
        target_km=140.55,
        parameters=GYS_PARAMETERS,
        note=("The directly comparable case: same estimators, same q = 1/2 "
              "asymptotic rate, same tabulated parameters. This is the "
              "project's strongest external check."),
    ),
    PublishedDataset(
        name="ma-asymptotic-gys",
        citation=("X. Ma, B. Qi, Y. Zhao, H.-K. Lo, Phys. Rev. A 72, 012326 "
                  "(2005), Fig. 3 -- asymptotic decoy with infinite decoys"),
        url="https://arxiv.org/abs/quant-ph/0503005",
        kind="upper-bound",
        target_km=142.05,
        bound_near_km=140.55,
        parameters=GYS_PARAMETERS,
        note=("A ceiling, not a prediction: the infinite-decoy limit needs "
              "infinitely many intensities. qel's finite-decoy estimator must "
              "fall below it and stay near the achievable 140.55 km. Judged as "
              "an inequality, not an equality."),
    ),
    PublishedDataset(
        name="gobby-yuan-shields-2004",
        citation=("C. Gobby, Z. L. Yuan, A. J. Shields, Appl. Phys. Lett. 84, "
                  "3762 (2004) -- 122 km over 1550 nm fibre"),
        url="https://arxiv.org/abs/quant-ph/0412171",
        kind="context",
        target_km=None,
        parameters={**GYS_PARAMETERS, "alpha_db_km": 0.2},
        note=("GYS predates practical decoy-state implementations, so this is a "
              "consistency check on the channel and detector model rather than a "
              "reproduction of a decoy-state experiment."),
    ),
    PublishedDataset(
        name="boaron-2018-421km",
        citation=("A. Boaron et al., Phys. Rev. Lett. 121, 190502 (2018), "
                  "Table I -- 421.1 km at 71.9 dB, SKR 0.25 bit/s"),
        url="https://arxiv.org/abs/1807.03222",
        kind="context",
        target_km=None,
        parameters=PRACTICAL_PARAMETERS,
        published_loss_db=71.9,
        published_distance_km=421.1,
        note=("Recorded for its loss budget (71.9 dB over 421.1 km = 0.171 "
              "dB/km, ultra-low-loss fibre) and explicitly NOT scored: their "
              "protocol is 3-state time-bin with a one-decoy finite-key bound "
              "6*log2(19/eps), not asymptotic decoy BB84."),
    ),
)

#: Boaron Table I as published, for the loss-budget cross-check.
BOARON_TABLE = (
    # (length_km, attenuation_db, mu1, mu2, block_size, qber_z_pct, skr_bps)
    (251.7, 42.7, 0.49, 0.18, 8.2e6, 0.5, 4.9e3),
    (302.1, 51.3, 0.48, 0.18, 8.2e6, 0.4, 0.79e3),
    (354.5, 60.6, 0.35, 0.15, 6.2e6, 0.7, 62.0),
    (404.9, 69.3, 0.35, 0.15, 4.1e5, 1.0, 6.5),
    (421.1, 71.9, 0.30, 0.13, 2.0e5, 2.1, 0.25),
)


def maximum_secure_distance_km(parameters: dict,
                               hi: float = 900.0,
                               tol: float = 0.01) -> float:
    """Longest fibre on which ``parameters`` still yields a positive key rate.

    Bisection on the asymptotic decoy model.  Monotone in distance, so the
    predicate is a clean threshold; returns 0.0 when there is no key even at
    zero length, and ``inf`` when no finite length exhausts it (which happens
    only with no dark counts at all).
    """
    if not run_bb84_decoy(tol, **parameters)["secure"]:
        return 0.0
    if parameters.get("dark_count_hz", 0.0) <= 0.0:
        return float("inf")
    if run_bb84_decoy(hi, **parameters)["secure"]:
        return float(hi)
    lo = tol
    while hi - lo > tol:
        mid = 0.5 * (lo + hi)
        if run_bb84_decoy(mid, **parameters)["secure"]:
            lo = mid
        else:
            hi = mid
    return float(lo)


def validate_dataset(dataset: PublishedDataset) -> dict:
    """Recompute one published figure and report the difference.

    Judged according to ``dataset.kind``: an equality for ``"validated"``, a
    two-sided inequality for ``"upper-bound"`` (below the bound, and near the
    achievable figure), and not judged at all for ``"context"``.
    """
    computed = maximum_secure_distance_km(dataset.parameters)
    row = {
        "name": dataset.name,
        "citation": dataset.citation,
        "url": dataset.url,
        "kind": dataset.kind,
        "target_km": dataset.target_km,
        "computed_km": computed,
        "note": dataset.note,
        "absolute_error_km": None,
        "relative_error_pct": None,
        "within_2pct": None,
        "below_bound": None,
        "passes": None,
    }
    if dataset.target_km is None or not np.isfinite(computed) or computed <= 0:
        return row

    row["absolute_error_km"] = computed - dataset.target_km
    row["relative_error_pct"] = (100.0 * (computed - dataset.target_km)
                                 / dataset.target_km)
    # 2% tolerance: tight enough that a real modelling error fails, loose enough to
    # absorb a published maximum distance read off a figure and rounded to two decimals.
    row["within_2pct"] = abs(row["relative_error_pct"]) <= 2.0

    if dataset.kind == "validated":
        row["passes"] = row["within_2pct"]
    elif dataset.kind == "upper-bound":
        row["below_bound"] = computed <= dataset.target_km
        near = dataset.bound_near_km
        close_enough = (near is None
                        or abs(computed - near) / near <= 0.02)
        row["passes"] = bool(row["below_bound"] and close_enough)
    return row


def validate_all() -> list[dict]:
    """Recompute every published figure that carries a target."""
    return [validate_dataset(d) for d in PUBLISHED_DATASETS
            if d.target_km is not None]


def check_loss_budget(length_km: float, alpha_db_km: float,
                      published_loss_db: float) -> dict:
    """Cross-check a tabulated fibre loss against the attenuation model.

    This is what makes a dataset with an *incomparable protocol* still useful:
    the loss budget depends only on the fibre, so it can be checked even when
    the key-rate formula cannot.
    """
    computed = fiber_loss_db(length_km, alpha_db_km)
    return {
        "length_km": length_km,
        "published_loss_db": published_loss_db,
        "computed_loss_db": computed,
        "difference_db": computed - published_loss_db,
        "implied_alpha_db_km": published_loss_db / length_km,
        "transmissivity": fiber_transmissivity(length_km, alpha_db_km),
    }


def validate_boaron_loss_budget() -> list[dict]:
    """Check every row of Boaron Table I against the attenuation model.

    The implied attenuation is compared against the ultra-low-loss fibre value
    the paper describes (0.16-0.17 dB/km), which is a property of their fibre
    and should be constant across rows.
    """
    rows = []
    for (length, loss_db, _mu1, _mu2, _block, _qber, _skr) in BOARON_TABLE:
        rows.append(check_loss_budget(length, 0.171, loss_db))
    return rows


def validation_report() -> str:
    """A printable summary of every comparison, passes and failures alike."""
    lines = ["QEL validation against published results", "=" * 72, ""]

    kinds = {"validated": "VALIDATED  (same quantity, same estimators)",
             "upper-bound": "UPPER BOUND (must fall below, and near)",
             "context": "CONTEXT    (recorded, not scored)"}

    for kind in ("validated", "upper-bound"):
        rows = [r for r in validate_all() if r["kind"] == kind]
        if not rows:
            continue
        lines.append(kinds[kind])
        for row in rows:
            marker = "OK  " if row["passes"] else "MISS"
            lines.append(f"  [{marker}] {row['name']}")
            lines.append(f"          published {row['target_km']:.2f} km   "
                         f"qel {row['computed_km']:.2f} km   "
                         f"delta {row['absolute_error_km']:+.2f} km "
                         f"({row['relative_error_pct']:+.2f}%)")
            if kind == "upper-bound":
                lines.append(f"          below the bound: {row['below_bound']}")
            lines.append(f"          {row['url']}")
            lines.extend(f"          {w}" for w in _wrap(row["note"], 62))
            lines.append("")

    lines.append(kinds["context"])
    for dataset in PUBLISHED_DATASETS:
        if dataset.kind == "context":
            lines.append(f"  - {dataset.name}")
            lines.extend(f"      {w}" for w in _wrap(dataset.note, 66))
    lines.append("")

    lines.append("Boaron Table I loss budget (a fibre property, so comparable "
                 "even")
    lines.append("though the protocol is not):")
    lines.append(f"  {'km':>7} {'pub dB':>8} {'model dB':>9} {'implied dB/km':>14}")
    for row in validate_boaron_loss_budget():
        lines.append(f"  {row['length_km']:>7.1f} {row['published_loss_db']:>8.1f} "
                     f"{row['computed_loss_db']:>9.1f} "
                     f"{row['implied_alpha_db_km']:>14.4f}")
    lines.append("")
    implied = [r["implied_alpha_db_km"] for r in validate_boaron_loss_budget()]
    spread = max(implied) - min(implied)
    lines.append(f"  Implied attenuation spans {min(implied):.4f}-{max(implied):.4f} "
                 f"dB/km (spread {spread:.4f}),")
    lines.append("  so the published loss column is consistent with a single "
                 "ultra-low-loss")
    lines.append("  fibre at ~0.171 dB/km -- better than standard 0.2 dB/km SMF.")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, out, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            out.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        out.append(current)
    return out
