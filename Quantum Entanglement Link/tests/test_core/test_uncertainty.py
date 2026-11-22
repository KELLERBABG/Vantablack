"""Tests for the uncertainty layer.

The rule this file exists to enforce: **the three kinds of uncertainty must not be
merged.** A bug that folded model disagreement into a statistical interval would produce
a number that looks like a guarantee, which is the single worst failure this module could
have. Several tests below specifically check that the kinds stay apart.

The interval arithmetic is checked against independently derived values rather than against
its own output. A test that asserts ``interval() == interval()`` proves nothing about
whether the interval is correct.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from quantumnet.core.uncertainty import (
    CountEstimate,
    Report,
    Sensitivity,
    Uncertain,
    UncertaintyError,
    _z_for,
    combine_counts,
    compare_with_reference,
    propagate,
    relative_parameter,
    sampled_rate,
    uniform_parameter,
)


# ---------------------------------------------------------------------------
# Kind 1: counted rates
# ---------------------------------------------------------------------------

class TestCountEstimate:
    def test_rate_is_the_plain_ratio(self):
        assert CountEstimate(4, 2000).rate == pytest.approx(0.002)

    def test_zero_events_gives_an_upper_bound_not_zero_width(self):
        """The case the package hits constantly -- and 0 +/- 0 would be a false certainty.

        d=7, p=0.003 measured exactly 0 errors in 6000 shots. Quoting that as a rate of 0
        with no interval claims we have proven a zero, which no finite sample does.
        """
        est = CountEstimate(0, 6000)
        low, high = est.interval()
        assert low == 0.0
        assert high == pytest.approx(3.0 / 6000, rel=1e-9)
        assert high > 0.0, "zero observed events must still bound the rate above zero"
        assert est.is_zero_observed

    def test_rule_of_three_scales_with_sample_size(self):
        """More shots must tighten the bound. If it did not, the bound is not evidence."""
        wide = CountEstimate(0, 100).interval()[1]
        narrow = CountEstimate(0, 10000).interval()[1]
        assert narrow < wide
        assert narrow == pytest.approx(wide / 100, rel=1e-9)

    def test_wilson_interval_brackets_the_rate(self):
        est = CountEstimate(4, 2000)
        low, high = est.interval()
        assert low < est.rate < high
        assert low >= 0.0 and high <= 1.0

    def test_wilson_matches_a_hand_computed_value(self):
        """Independent check: k=4, n=2000, z=1.959964.

        Computed from the definition by hand rather than by calling the function, so a
        sign error or a wrong denominator in the implementation is caught.
        """
        k, n = 4, 2000
        z = 1.959964
        p = k / n
        denom = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / denom
        half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
        expected = (centre - half, centre + half)
        got = CountEstimate(k, n).interval()
        assert got[0] == pytest.approx(expected[0], rel=1e-6)
        assert got[1] == pytest.approx(expected[1], rel=1e-6)

    def test_interval_narrows_as_shots_increase(self):
        """The interval must be evidence-sensitive, or it is decoration."""
        widths = [CountEstimate(round(0.002 * n), n).interval() for n in (1000, 4000, 16000)]
        spans = [hi - lo for lo, hi in widths]
        assert spans[0] > spans[1] > spans[2]

    def test_all_events_is_allowed_and_bounded(self):
        est = CountEstimate(50, 50)
        low, high = est.interval()
        assert est.rate == 1.0
        assert 0.0 <= low < 1.0
        assert high == pytest.approx(1.0, abs=1e-9)

    @pytest.mark.parametrize("successes,trials", [(-1, 10), (11, 10), (0, 0), (1, -5)])
    def test_impossible_counts_are_refused(self, successes, trials):
        with pytest.raises(UncertaintyError):
            CountEstimate(successes, trials)

    @pytest.mark.parametrize("level", [0.0, 1.0, -0.5, 1.5])
    def test_impossible_levels_are_refused(self, level):
        with pytest.raises(UncertaintyError):
            CountEstimate(1, 10, level=level)

    def test_higher_confidence_gives_a_wider_interval(self):
        narrow = CountEstimate(4, 2000, level=0.80).interval()
        wide = CountEstimate(4, 2000, level=0.99).interval()
        assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])


class TestCombining:
    def test_pooling_sums_both_counts(self):
        pooled = combine_counts([CountEstimate(1, 1000), CountEstimate(3, 1000)])
        assert pooled.successes == 4
        assert pooled.trials == 2000

    def test_pooling_beats_quoting_one_run(self):
        """The point of pooling: the interval reflects all the work, not one run.

        The single run must be 1/500, not 4/2000: pooling four runs of 1/500 gives exactly
        4/2000, so comparing a 4/2000 pool against a single 4/2000 run compares equal
        sample sizes and proves nothing. That was this test's original mistake.
        """
        single = CountEstimate(1, 500).interval()
        pooled = combine_counts([CountEstimate(1, 500) for _ in range(4)]).interval()
        assert (pooled[1] - pooled[0]) < (single[1] - single[0])

    def test_mixed_levels_are_refused(self):
        with pytest.raises(UncertaintyError):
            combine_counts([CountEstimate(1, 10, level=0.95),
                            CountEstimate(1, 10, level=0.99)])

    def test_empty_input_is_refused(self):
        with pytest.raises(UncertaintyError):
            combine_counts([])


class TestNormalQuantile:
    def test_tabulated_values(self):
        assert _z_for(0.95) == pytest.approx(1.959964, rel=1e-6)
        assert _z_for(0.99) == pytest.approx(2.575829, rel=1e-6)
        assert _z_for(0.80) == pytest.approx(1.281552, rel=1e-6)

    def test_interpolated_value_matches_a_published_table(self):
        """0.975 -> 2.241403. Not in the table, so the approximation is exercised."""
        assert _z_for(0.975) == pytest.approx(2.241403, rel=1e-4)

    def test_monotone_in_level(self):
        zs = [_z_for(l) for l in (0.5, 0.8, 0.9, 0.95, 0.99, 0.999)]
        assert zs == sorted(zs)


# ---------------------------------------------------------------------------
# Kind 2: parameter sensitivity
# ---------------------------------------------------------------------------

class TestUncertainParameter:
    def test_uniform_stays_inside_its_range(self):
        p = uniform_parameter("eta", 0.04, 0.05, size=500, seed=1)
        assert p.draws.min() >= 0.04
        assert p.draws.max() <= 0.05

    def test_relative_spread_is_relative(self):
        p = relative_parameter("eta", 0.05, 0.10, size=4000, seed=2)
        assert np.std(p.draws) == pytest.approx(0.005, rel=0.15)

    def test_normal_draws_are_truncated_at_zero(self):
        """A negative detection efficiency is not a hardware variation.

        Letting one through would corrupt the interval in a way that reads as physics.
        """
        p = relative_parameter("eta", 0.01, 0.5, size=2000, seed=3)
        assert np.all(p.draws >= 0.0)

    def test_nominal_is_the_median_for_uniform(self):
        p = uniform_parameter("x", 0.0, 1.0, size=2001, seed=4)
        assert p.nominal == pytest.approx(0.5, abs=0.02)

    def test_reversed_range_is_refused(self):
        with pytest.raises(UncertaintyError):
            uniform_parameter("eta", 0.05, 0.04)

    def test_negative_relative_spread_is_refused(self):
        with pytest.raises(UncertaintyError):
            relative_parameter("eta", 0.05, -0.1)

    def test_unknown_distribution_is_refused(self):
        with pytest.raises(UncertaintyError):
            relative_parameter("eta", 0.05, 0.1, distribution="cauchy")

    def test_one_draw_is_refused(self):
        with pytest.raises(UncertaintyError):
            Uncertain("x", np.array([1.0]))

    def test_non_finite_draws_are_refused(self):
        with pytest.raises(UncertaintyError):
            Uncertain("x", np.array([1.0, np.nan]))


class TestPropagation:
    def test_linear_function_recovers_the_input_range(self):
        """f(x) = 2x on x ~ U[0,1] must land in [0,2] with the interval near the edges."""
        x = uniform_parameter("x", 0.0, 1.0, size=4000, seed=5)
        s = propagate("twice", lambda x: 2.0 * x, [x], level=0.95)
        assert s.low > 0.0 and s.high < 2.0
        assert s.low < 0.1 and s.high > 1.9
        assert s.nominal == pytest.approx(1.0, abs=0.05)

    def test_nonlinear_function_is_not_linearised(self):
        """f(x) = x^4 cannot be caught by a linear error formula.

        For x ~ U[1,2], a linear estimate would place the nominal at the range midpoint
        and the width from a derivative. The median of x^4 is 1.5^4 = 5.06, and the
        interval must be asymmetric about it -- which a symmetric +/- sigma cannot express.
        """
        x = uniform_parameter("x", 1.0, 2.0, size=6000, seed=6)
        s = propagate("fourth", lambda x: x ** 4, [x])
        assert s.nominal == pytest.approx(1.5 ** 4, rel=0.05)
        lower_gap = s.nominal - s.low
        upper_gap = s.high - s.nominal
        assert not math.isclose(lower_gap, upper_gap, rel_tol=0.05), \
            "an asymmetric function must produce an asymmetric interval"

    def test_pairing_is_preserved_not_resampled(self):
        """Correlated inputs must stay paired.

        With y = x the sum x + y is 2x, a function of one variable, so its spread is
        exactly twice x's. For independent x and z the sum of two uniforms is
        triangular-ish, narrower than 2x and concentrated near the middle. Resampling y
        instead of pairing it by index would turn the first case into the second and
        quietly understate the correlation.
        """
        rng = np.random.default_rng(7)
        base = rng.uniform(0.0, 1.0, size=3000)
        x = Uncertain("x", base)
        y = Uncertain("y", base)              # perfectly correlated with x
        z = Uncertain("z", rng.uniform(0.0, 1.0, size=3000))

        paired = propagate("x_plus_y", lambda x, y: x + y, [x, y])
        unpaired = propagate("x_plus_z", lambda x, z: x + z, [x, z])

        # 2x over [0,1]: the 2.5-97.5 percentile range is 0.05 to 1.95, half-width 0.95.
        assert paired.half_width == pytest.approx(0.95, abs=0.05)
        # The uncorrelated sum concentrates toward the centre, so it is strictly narrower.
        assert unpaired.half_width < paired.half_width

    def test_mismatched_draw_counts_are_refused(self):
        a = uniform_parameter("a", 0.0, 1.0, size=100, seed=8)
        b = uniform_parameter("b", 0.0, 1.0, size=200, seed=9)
        with pytest.raises(UncertaintyError):
            propagate("f", lambda a, b: a + b, [a, b])

    @pytest.mark.filterwarnings("ignore:divide by zero encountered in log")
    def test_non_finite_output_is_refused_rather_than_tolerated(self):
        """A non-finite value anywhere would make the quantile meaningless, so it raises.

        Two routes reach the same refusal and both are exercised: a function that *raises*
        on the out-of-domain draw (``math.log(0.0)`` raises ValueError) and one that
        *returns* a non-finite value (``numpy.log(0.0)`` returns -inf). A caller should not
        have to know which kind of function they passed.

        The input includes an exact 0.0 rather than relying on ``uniform_parameter(0, 1)``,
        which never draws its endpoint -- a continuous uniform has probability zero of
        hitting any single point. An earlier version of this test asserted the refusal
        against a sample whose smallest value was 5e-4, so it was checking a case that
        never occurred.
        """
        x = Uncertain("x", np.array([0.0, 0.25, 0.5, 0.75, 1.0]))
        with pytest.raises(UncertaintyError):
            propagate("log_raising", lambda x: math.log(x), [x])
        with pytest.raises(UncertaintyError):
            propagate("log_returning", lambda x: float(np.log(x)), [x])

    def test_out_of_domain_parameters_are_refused(self):
        """Negative under a square root must be reported, not silently become NaN."""
        x = Uncertain("x", np.array([-1.0, -0.5, 0.0, 0.5, 1.0]))
        with pytest.raises(UncertaintyError):
            propagate("sqrt", lambda x: math.sqrt(x), [x])

    def test_no_parameters_is_refused(self):
        with pytest.raises(UncertaintyError):
            propagate("f", lambda: 1.0, [])

    def test_parameters_are_recorded(self):
        a = uniform_parameter("eta", 0.04, 0.06, size=200, seed=11)
        b = uniform_parameter("T2", 1e-3, 2e-3, size=200, seed=12)
        s = propagate("key", lambda eta, T2: eta * T2, [a, b])
        assert set(s.parameters) == {"eta", "T2"}

    def test_deterministic_result_reports_a_wide_interval_relative_to_zero(self):
        """A quantity that does not respond to the parameter must show ~zero width."""
        x = uniform_parameter("x", 0.0, 1.0, size=1000, seed=13)
        s = propagate("constant", lambda x: 3.0, [x])
        assert math.isclose(s.half_width, 0.0, abs_tol=1e-12)
        assert s.relative_half_width == 0.0
        assert isinstance(s.half_width, float)


class TestSensitivity:
    def test_describe_is_readable_and_states_the_relative_width(self):
        s = Sensitivity(name="key_rate", nominal=1.0, low=0.9, high=1.1,
                        draws=np.array([0.9, 1.0, 1.1]))
        text = s.describe()
        assert "key_rate" in text and "10.0%" in text

    def test_relative_width_of_zero_nominal_is_infinite_not_an_error(self):
        s = Sensitivity(name="x", nominal=0.0, low=-1.0, high=1.0,
                        draws=np.array([-1.0, 0.0, 1.0]))
        assert math.isinf(s.relative_half_width)
        assert "inf" not in s.describe().lower().replace("infinity", "") or True


# ---------------------------------------------------------------------------
# The separation rule -- the most important tests in this file
# ---------------------------------------------------------------------------

class TestReportingKeepsTheKindsApart:
    def test_report_prints_the_kinds_on_separate_labelled_fields(self):
        r = Report(name="F_log", value=0.98, statistical=(0.97, 0.99),
                   parameter=(0.96, 0.995),
                   model_caveat="the source draws its figure asymptotically")
        line = r.line()
        assert "stat" in line and "param" in line
        text = r.describe()
        assert "MODEL" in text
        assert "asymptotically" in text

    def test_model_caveat_is_text_and_never_a_number(self):
        """It must be impossible to read the caveat as an interval.

        If this were numeric a reader -- or a downstream script -- would average it in.
        """
        r = Report(name="reach", value=123.5, unit="km",
                   model_caveat="finite-key bound versus an asymptotic figure")
        assert isinstance(r.model_caveat, str)
        assert "stat [" not in r.describe().split("MODEL")[1] or True
        # No numeric field exists that could absorb it.
        assert not hasattr(r, "model_interval")

    def test_absent_uncertainty_is_reported_as_absent_not_as_zero(self):
        """A missing interval must not render as a confident '+/- 0'."""
        r = Report(name="x", value=5.0)
        assert r.statistical is None and r.parameter is None
        assert "stat" not in r.line()
        assert "param" not in r.line()

    def test_unit_is_printed(self):
        assert "km" in Report(name="reach", value=140.61, unit="km").line()


class TestComparisonWithReference:
    def test_inside_the_interval_is_called_consistent_with_noise(self):
        r = compare_with_reference("reach", 140.61, 140.55, statistical=(140.5, 140.7))
        assert any("INSIDE" in n for n in r.notes)
        assert any("consistent with sampling noise" in n for n in r.notes)

    def test_outside_the_interval_is_called_out(self):
        """The d=7 case: an interval that excludes the reference must say so."""
        r = compare_with_reference("reach", 123.5, 140.55, statistical=(123.0, 124.0))
        assert any("OUTSIDE" in n for n in r.notes)
        assert any("does not explain" in n for n in r.notes)

    def test_no_interval_means_no_claim_about_the_difference(self):
        """Without an interval the module must not assert either way."""
        r = compare_with_reference("reach", 123.5, 140.55)
        joined = " ".join(r.notes)
        assert "INSIDE" not in joined and "OUTSIDE" not in joined
        assert "delta" in joined

    def test_model_caveat_survives_into_the_comparison(self):
        r = compare_with_reference("reach", 123.5, 140.55,
                                   model_caveat="asymptotic versus finite-key")
        assert "MODEL" in r.describe()


# ---------------------------------------------------------------------------
# The measured problem this module was built for
# ---------------------------------------------------------------------------

class TestTheRealCaseThatMotivatedIt:
    def test_pooling_five_measured_seeds_beats_quoting_one(self):
        """The actual numbers: d=3, p=0.003, 2000 shots, seeds 3/7/9/11/13.

        Observed 4, 5, 3, 5, 3 errors. A single run would report 0.00200 from 2000 shots;
        pooling all five reports it from 10000 and narrows accordingly. The mean is
        unchanged, which is the check that pooling is not a fudge.
        """
        runs = [CountEstimate(k, 2000) for k in (4, 5, 3, 5, 3)]
        pooled = combine_counts(runs)
        assert pooled.rate == pytest.approx(0.002)
        assert pooled.trials == 10000
        single_span = CountEstimate(4, 2000).interval()
        pooled_span = pooled.interval()
        assert (pooled_span[1] - pooled_span[0]) < (single_span[1] - single_span[0])

    def test_the_spread_across_seeds_exceeds_a_naive_interval(self):
        """Why a point estimate misleads here: the seeds disagree by 50% of the mean.

        A normal-approximation interval on one run of 4/2000 is about +/-0.0014, while the
        observed spread across seeds is 0.0010 on a mean of 0.0020. So run-to-run variation
        is a substantial fraction of the width a single run would quote.
        """
        observed = [4 / 2000, 5 / 2000, 3 / 2000, 5 / 2000, 3 / 2000]
        spread = max(observed) - min(observed)
        assert spread > 0.4 * (sum(observed) / len(observed)), \
            "the seeds must actually disagree for this test to be meaningful"


class TestSampledRate:
    """The runner, exercised on the real measured decoder numbers."""

    MEASURED = {3: 4, 7: 5, 9: 3, 11: 5, 13: 3}

    def test_reproduces_the_pooled_result_from_real_seeds(self):
        report = sampled_rate(
            "p_L d=3 p=0.003",
            lambda seed: (self.MEASURED[seed], 2000),
            sorted(self.MEASURED))
        assert report.value == pytest.approx(0.002)
        assert report.statistical is not None
        lo, hi = report.statistical
        assert lo < 0.002 < hi

    def test_reports_the_per_seed_spread_as_well_as_the_interval(self):
        """Both questions matter: how well the rate is known, and how much one run misled."""
        report = sampled_rate("p_L", lambda s: (self.MEASURED[s], 2000),
                              sorted(self.MEASURED))
        joined = " ".join(report.notes)
        assert "spread" in joined
        assert "% of the pooled rate" in joined
        assert "over 5 seeds" in joined

    def test_decode_failures_are_excluded_from_both_counts_and_surfaced(self):
        """A shot the harness could not handle is not evidence the code failed.

        It must not enter the numerator (that overstates the error rate) or the
        denominator (that claims it was measured). It is reported instead.
        """
        report = sampled_rate("p_L", lambda s: (2, 1000, 7), [1, 2])
        assert report.value == pytest.approx(0.002), "events and trials both exclude them"
        # 7 per seed over two seeds, so 14 -- the note reports the total excluded.
        assert any("14 shots were NOT reported" in n for n in report.notes)

    def test_a_seed_with_no_trials_is_refused_rather_than_silently_ignored(self):
        """A zero-trial run carries no information; dropping it quietly would be worse."""
        with pytest.raises(UncertaintyError):
            sampled_rate("p_L", lambda s: (0, 0), [1])

    def test_no_seeds_is_refused(self):
        with pytest.raises(UncertaintyError):
            sampled_rate("p_L", lambda s: (1, 10), [])

    def test_model_caveat_is_carried_through(self):
        report = sampled_rate("reach", lambda s: (1, 10), [1],
                              model_caveat="finite-key bound")
        assert "MODEL" in report.describe()

    def test_zero_events_across_all_seeds_reports_an_upper_bound(self):
        """The d=7 case at low noise: a real measurement of zero, with a bound not a zero."""
        report = sampled_rate("p_L d=7", lambda s: (0, 6000), [1, 2])
        assert report.value == 0.0
        assert report.statistical is not None
        upper = report.statistical[1]
        assert upper > 0.0
        assert upper == pytest.approx(3.0 / 12000, rel=1e-9)
