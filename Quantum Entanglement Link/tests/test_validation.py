"""Validation against published experimental results.

The credibility gate.  A simulator whose numbers agree with nothing is a
simulator whose numbers mean nothing, so each comparison here recomputes a figure
a specific paper published, at the parameters that paper tabulated.

Two properties this file is built to protect:

* **A pass must be a real match**, not a loose band.  The tolerance is 2%, which
  is tight enough that a modelling error fails and loose enough to absorb a
  maximum distance read off a figure and rounded to two decimals.
* **An incomparable dataset must not be scored.**  Quoting a 421 km record
  against a different protocol would measure the protocol difference and call it
  model error.  Those datasets are recorded with their parameters and explicitly
  excluded, and a test asserts they stay excluded.
"""

from __future__ import annotations

import pytest

from quantumnet.validation import (
    BOARON_TABLE,
    GYS_PARAMETERS,
    PUBLISHED_DATASETS,
    PublishedDataset,
    check_loss_budget,
    maximum_secure_distance_km,
    validate_all,
    validate_boaron_loss_budget,
    validate_dataset,
    validation_report,
)


# ---------------------------------------------------------------------------
# The headline comparison
# ---------------------------------------------------------------------------

def test_vacuum_weak_reproduces_ma_et_al_published_maximum():
    """The project's strongest external check.

    Ma, Qi, Zhao and Lo publish a maximum secure distance of **140.55 km** for
    the vacuum+weak decoy method at the GYS parameters they tabulate.  Same
    estimators, same asymptotic rate, same q = 1/2 -- so this is a like-for-like
    reproduction, not an analogy.
    """
    dataset = next(d for d in PUBLISHED_DATASETS
                   if d.name == "ma-vacuum-weak-gys")
    row = validate_dataset(dataset)
    assert row["computed_km"] == pytest.approx(140.55, rel=0.02)
    assert row["passes"] is True
    # and tight enough to be meaningful: within a kilometre
    assert abs(row["absolute_error_km"]) < 1.0


def test_the_asymptotic_figure_is_judged_as_a_bound_not_an_equality():
    """142.05 km is the infinite-decoy ceiling, so equality would be wrong.

    The model uses finitely many intensities and *must* fall below it while
    staying near the achievable 140.55 km.  Scoring it as a pass/fail match
    would be dishonest in both directions: it would fail a correct model or
    accept an inflated one.
    """
    dataset = next(d for d in PUBLISHED_DATASETS
                   if d.name == "ma-asymptotic-gys")
    assert dataset.kind == "upper-bound"
    row = validate_dataset(dataset)
    assert row["below_bound"] is True
    assert row["computed_km"] < dataset.target_km
    assert row["computed_km"] == pytest.approx(dataset.bound_near_km, rel=0.02)
    assert row["passes"] is True


def test_the_model_falls_between_the_achievable_and_the_bound():
    """Ordering sanity: achievable <= model <= ceiling."""
    achievable = 140.55
    ceiling = 142.05
    computed = maximum_secure_distance_km(GYS_PARAMETERS)
    assert achievable <= computed <= ceiling


# ---------------------------------------------------------------------------
# Datasets that must stay unscored
# ---------------------------------------------------------------------------

def test_boaron_is_recorded_but_not_scored():
    """A different protocol cannot be a pass/fail target.

    Their 3-state time-bin scheme uses a one-decoy finite-key bound
    ``6*log2(19/eps)``; qel models asymptotic decoy BB84.  Scoring the rates
    against each other would measure the protocol difference.
    """
    dataset = next(d for d in PUBLISHED_DATASETS if d.name == "boaron-2018-421km")
    assert dataset.kind == "context"
    assert dataset.target_km is None
    assert dataset.published_loss_db == pytest.approx(71.9)
    assert "not scored" in dataset.note.lower() or "NOT scored" in dataset.note


def test_context_datasets_are_excluded_from_the_scored_set():
    scored = {row["name"] for row in validate_all()}
    for dataset in PUBLISHED_DATASETS:
        if dataset.kind == "context":
            assert dataset.name not in scored


def test_only_validated_and_bounded_datasets_carry_targets():
    for dataset in PUBLISHED_DATASETS:
        if dataset.kind == "context":
            assert dataset.target_km is None
        else:
            assert dataset.target_km is not None


def test_every_dataset_cites_a_source():
    """A published number without a citation is an assertion."""
    for dataset in PUBLISHED_DATASETS:
        assert dataset.citation
        assert dataset.url.startswith("https://")


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError, match="unknown dataset kind"):
        PublishedDataset(name="x", citation="c", url="https://x", kind="nonsense")


# ---------------------------------------------------------------------------
# The loss budget, which IS comparable across protocols
# ---------------------------------------------------------------------------

def test_boaron_loss_budget_matches_the_attenuation_model():
    """Fibre loss depends only on the fibre, so it can be checked regardless."""
    rows = validate_boaron_loss_budget()
    assert len(rows) == len(BOARON_TABLE)
    for row in rows:
        assert abs(row["difference_db"]) < 0.5, (
            f"{row['length_km']} km: model {row['computed_loss_db']:.1f} dB vs "
            f"published {row['published_loss_db']:.1f} dB"
        )


def test_boaron_implies_a_single_ultra_low_loss_fibre():
    """The implied attenuation must be constant, and better than standard SMF.

    Boaron describe ultra-low-loss fibre; if the implied coefficient drifted
    across rows the published table would be internally inconsistent, or their
    spans would use different fibre.
    """
    implied = [r["implied_alpha_db_km"] for r in validate_boaron_loss_budget()]
    assert max(implied) - min(implied) < 0.005, f"implied attenuation varies: {implied}"
    for value in implied:
        assert 0.16 <= value <= 0.18, f"implied {value} dB/km is not ULL fibre"
        assert value < 0.2, "ULL fibre should beat standard 0.2 dB/km SMF"


def test_loss_budget_helper_reports_both_sides():
    row = check_loss_budget(100.0, 0.2, 20.0)
    assert row["computed_loss_db"] == pytest.approx(20.0)
    assert row["difference_db"] == pytest.approx(0.0)
    assert row["implied_alpha_db_km"] == pytest.approx(0.2)
    assert row["transmissivity"] == pytest.approx(10 ** -2.0)


# ---------------------------------------------------------------------------
# The bisection
# ---------------------------------------------------------------------------

def test_maximum_distance_is_where_the_rate_crosses_zero():
    reach = maximum_secure_distance_km(GYS_PARAMETERS)
    from quantumnet.protocols.bb84 import run_bb84_decoy
    assert run_bb84_decoy(reach - 1.0, **GYS_PARAMETERS)["secure"]
    assert not run_bb84_decoy(reach + 1.0, **GYS_PARAMETERS)["secure"]


def test_reach_shrinks_as_dark_counts_rise():
    """Dark counts set the reach, so adding them must shorten it."""
    quiet = maximum_secure_distance_km({**GYS_PARAMETERS, "dark_count_hz": 1.0})
    noisy = maximum_secure_distance_km({**GYS_PARAMETERS, "dark_count_hz": 1e5})
    assert noisy < quiet


def test_no_dark_counts_means_no_loss_limited_reach():
    """Both rate terms scale with transmissivity, so nothing exhausts it."""
    assert maximum_secure_distance_km(
        {**GYS_PARAMETERS, "dark_count_hz": 0.0}) == float("inf")


def test_hopeless_parameters_return_zero_not_a_small_number():
    hopeless = {**GYS_PARAMETERS, "e_detector": 0.45}
    assert maximum_secure_distance_km(hopeless) == 0.0


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

def test_report_shows_every_category_including_unscored():
    text = validation_report()
    assert "VALIDATED" in text
    assert "UPPER BOUND" in text
    assert "CONTEXT" in text and "not scored" in text
    assert "boaron-2018-421km" in text
    assert "loss budget" in text


def test_report_quotes_the_published_figures():
    text = validation_report()
    assert "140.55" in text and "142.05" in text


def test_scored_comparisons_all_pass():
    """If the model drifts, this fails loudly rather than in a footnote."""
    failures = [r["name"] for r in validate_all() if r["passes"] is False]
    assert not failures, f"published comparisons failed: {failures}"
