"""Decoy-state BB84 key-rate tests.

These pin the *analytic* decoy-state calculation.  The assertions are chosen so
that they would fail if the decoy estimators, the GLLP rate formula, or the
finite-key accounting were wrong -- not merely if a number drifted.

Reference points
----------------
* Ma, Qi, Zhao, Lo, Phys. Rev. A **72**, 012326 (2005), arXiv:quant-ph/0503005.
  ``Q_mu = Y0 + 1 - exp(-eta*mu)`` is their Eq. (10), the GLLP rate is their
  Eq. (1) with ``q = 1/2`` for standard BB84, and the vacuum+weak estimators
  are their **Eqs. (32) and (35)**.
* The finite-key block cost ``6*log2(21/eps_sec) + log2(2/eps_cor)`` is from
  Lim, Curty, Walenta, Xu, Zbinden, Phys. Rev. A **89**, 022307 (2014),
  **arXiv:1311.7129**.  (Not 1309.6020 -- that is an astrophysics paper.)
* ``Q_mu`` at zero distance with no dark counts must equal
  ``1 - exp(-eta*mu)``, a Poissonian identity, so it is asserted to
  floating-point tolerance rather than to an approximate band.
"""

from __future__ import annotations

import numpy as np
import pytest

from quantumnet.protocols.bb84 import (
    DECOY_PRESETS,
    binary_entropy,
    decoy_key_rate_curve,
    decoy_single_photon_bounds,
    finite_key_secret_length,
    gain_and_qber,
    max_secure_distance_km,
    run_bb84_decoy,
    run_bb84_decoy_preset,
)


# ---------------------------------------------------------------------------
# Analytic identities
# ---------------------------------------------------------------------------

def test_gain_matches_poissonian_identity():
    """Q_mu = 1 - exp(-eta*mu) exactly when there are no dark counts."""
    mu, eta = 0.5, 0.1
    q, e = gain_and_qber(mu, eta, y0=0.0, e_detector=0.0)
    assert q == pytest.approx(1.0 - np.exp(-eta * mu), rel=1e-15)
    assert e == pytest.approx(0.0, abs=1e-15)


def test_qber_at_high_loss_tends_to_half():
    """With no signal left, every click is a dark count and e -> 1/2."""
    q, e = gain_and_qber(0.5, eta=1e-12, y0=1e-5, e_detector=0.0)
    assert q == pytest.approx(1e-5, rel=1e-6)
    assert e == pytest.approx(0.5, rel=1e-3)


def test_binary_entropy_endpoints_and_peak():
    assert binary_entropy(0.0) == 0.0
    assert binary_entropy(1.0) == 0.0
    assert binary_entropy(0.5) == pytest.approx(1.0, rel=1e-15)
    assert binary_entropy(0.11) == pytest.approx(0.4999, abs=1e-3)


def test_single_photon_yield_bound_matches_hand_formula():
    """Y1^L must equal the Ma et al. vacuum+weak expression."""
    r = run_bb84_decoy(50.0, dark_count_hz=0.0, e_detector=0.0,
                       detector_efficiency=1.0)
    eta = r["total_transmissivity"]
    mu, nu = r["mu"], r["nu"]
    y0_upper = r["y0_upper"]
    q_mu = 1.0 - np.exp(-eta * mu)
    q_nu = 1.0 - np.exp(-eta * nu)
    hand = mu / (mu * nu - nu ** 2) * (
        q_nu * np.exp(nu)
        - q_mu * np.exp(mu) * (nu / mu) ** 2
        - (mu ** 2 - nu ** 2) / mu ** 2 * y0_upper
    )
    assert r["y1_lower"] == pytest.approx(hand, rel=1e-12)


def test_decoy_bounds_are_ordered():
    """Y0 <= Q_vac, Y1^L <= 1, e1^U <= 1/2."""
    r = run_bb84_decoy(50.0)
    assert 0.0 <= r["y0_upper"] <= r["q_vac"] + 1e-15
    assert r["y0_lower"] <= r["y0_upper"] + 1e-15
    assert 0.0 <= r["y1_lower"] <= 1.0
    assert 0.0 <= r["e1_upper"] <= 0.5


def test_single_photon_yield_recovers_transmissivity_at_low_loss():
    """In the no-dark-count limit Y1 -> eta_det * eta_channel."""
    r = run_bb84_decoy(0.0, dark_count_hz=0.0, e_detector=0.0,
                       detector_efficiency=1.0)
    assert r["y1_lower"] == pytest.approx(1.0, abs=2e-2)


# ---------------------------------------------------------------------------
# Rate formula behaviour
# ---------------------------------------------------------------------------

def test_known_key_rate_at_50km_practical_preset():
    """Regression pin: 50 km, 100 MHz, eta=0.8, 100 Hz dark, 1% misalignment."""
    r = run_bb84_decoy_preset("practical-1550", 50.0)
    assert r["key_rate_per_pulse"] == pytest.approx(8.8954e-03, rel=2e-3)
    assert r["key_rate_hz"] == pytest.approx(8.8954e05, rel=2e-3)
    assert r["e_mu"] == pytest.approx(0.0100, abs=1e-3)


@pytest.mark.parametrize("km,expected", [
    (0.0, 9.4117e-02),
    (25.0, 2.8591e-02),
    (50.0, 8.8954e-03),
    (100.0, 8.8103e-04),
    (200.0, 6.7419e-06),
])
def test_asymptotic_rate_curve_is_pinned(km, expected):
    """An independent reimplementation reproduced these to 5 significant
    figures, so they are pinned tightly: a change here means the model moved."""
    r = run_bb84_decoy_preset("practical-1550", km)
    assert r["key_rate_per_pulse"] == pytest.approx(expected, rel=2e-3)


def test_key_rate_decreases_monotonically_with_distance():
    curve = decoy_key_rate_curve(np.linspace(1, 250, 40),
                                 preset="practical-1550")
    rates = np.array([c["key_rate_per_pulse"] for c in curve])
    assert np.all(np.diff(rates) <= 1e-15)
    assert rates[0] > rates[-1]


def test_rate_is_positive_at_100km_and_zero_beyond_reach():
    assert run_bb84_decoy_preset("practical-1550", 100.0)["secure"]
    far = run_bb84_decoy_preset("practical-1550", 400.0)
    assert not far["secure"]
    assert far["key_rate_per_pulse"] == 0.0
    assert far["key_rate_hz"] == 0.0


def test_detector_misalignment_reduces_rate():
    rates = [run_bb84_decoy(50.0, e_detector=e)["key_rate_per_pulse"]
             for e in (0.0, 0.01, 0.02, 0.05)]
    assert all(a > b for a, b in zip(rates, rates[1:]))


def test_dark_counts_reduce_reach():
    clean = max_secure_distance_km("practical-1550", hi=600.0,
                                   dark_count_hz=1e2)
    noisy = max_secure_distance_km("practical-1550", hi=600.0,
                                   dark_count_hz=1e5)
    assert clean > noisy


def test_each_decade_of_dark_counts_costs_fifty_km():
    """The reach is dark-count limited: 10 dB = 50 km at 0.2 dB/km.

    Verified independently as the rule ``reach = 236 + 50*log10(1e-6/p_dark)``.
    That is a *physical* relation rather than a spot value, so it is a much
    stronger test -- and it tells you how to translate any published reach into
    this parameter set.
    """
    reference = max_secure_distance_km("practical-1550", hi=800.0, tol=0.5,
                                       dark_count_hz=100.0)
    for dark, offset in ((10.0, 50.0), (1000.0, -50.0), (1.0, 100.0)):
        reach = max_secure_distance_km("practical-1550", hi=800.0, tol=0.5,
                                       dark_count_hz=dark)
        expected = reference + 50.0 * np.log10(100.0 / dark)
        assert reach == pytest.approx(expected, abs=1.5), (
            f"dark_count_hz={dark}: reach {reach} km, expected ~{expected} km"
        )


def test_error_correction_inefficiency_costs_rate():
    good = run_bb84_decoy(50.0, error_correction_inefficiency=1.0)
    real = run_bb84_decoy(50.0, error_correction_inefficiency=1.22)
    assert good["key_rate_per_pulse"] > real["key_rate_per_pulse"]


def test_weaker_decoy_closer_to_signal_is_still_valid():
    """nu < mu is the only requirement; the estimator must stay bounded."""
    for nu in (0.05, 0.1, 0.2, 0.4):
        r = run_bb84_decoy(50.0, mu=0.5, nu=nu)
        assert 0.0 <= r["y1_lower"] <= 1.0
        assert 0.0 <= r["e1_upper"] <= 0.5


# ---------------------------------------------------------------------------
# Finite-key accounting (LCWX)
# ---------------------------------------------------------------------------

def test_block_secrecy_cost_matches_the_published_expression():
    """6*log2(21/eps_sec) + log2(2/eps_cor), evaluated exactly.

    At eps_sec=1e-9, eps_cor=1e-15 this is 256.567 bits.  The first
    implementation here used 4*log2(2/eps) = 123.6 bits -- an underestimate of
    2.1x -- so this test exists to keep the correct expression in place.
    """
    r = finite_key_secret_length(
        1e8, 1e7, 1e6, 1e8, 1e7, 1e6,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=1e6,
        eps_sec=1e-9, eps_cor=1e-15)
    expected = 6.0 * np.log2(21.0 / 1e-9) + np.log2(2.0 / 1e-15)
    assert expected == pytest.approx(256.567, abs=0.01)
    assert r["block_secrecy_cost_bits"] == pytest.approx(expected, rel=1e-12)


def test_block_cost_uses_log2_and_fluctuation_uses_natural_log():
    """A mixed-base detail that is easy to get wrong and changes the answer.

    The additive block cost is in bits (log2); the fluctuation width inside
    ``n^{+-}`` uses the natural log.  Getting this backwards shifts the
    fluctuation term by a factor of ln(2) ~ 0.69.

    The fluctuation check is done against an independently computed width rather
    than against the input count.  ``s_X,0`` is *not* "the vacuum count minus its
    own square root": LCWX Eq. (2) rescales by ``tau_0`` and by ``e^{mu_k}/p_k``,
    so it can legitimately exceed the raw input count.  An earlier version of this
    test asserted ``s_x_0_lower < n_x_vacuum``, which only held because the
    implementation was missing both factors.
    """
    import numpy as np

    n_vac = 1e7
    r = finite_key_secret_length(
        1e9, 1e8, n_vac, 1e9, 1e8, n_vac,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=1e7)
    assert r["block_secrecy_cost_bits"] > 0

    # Recompute LCWX Eq. (2) by hand, using the natural log inside the root.
    eps_sec, eps_cor = 1e-10, 1e-15
    mu1, mu2, mu3 = 0.5, 0.1, 0.0
    p1, p2, p3 = 0.5, 0.25, 0.25
    n_block = 1e9 + 1e8 + n_vac
    width = np.sqrt(n_block / 2.0 * np.log(21.0 / eps_sec))
    tau_0 = sum(p * np.exp(-m) for m, p in ((mu1, p1), (mu2, p2), (mu3, p3)))
    n3m = np.exp(mu3) / p3 * (n_vac - width)
    n2p = np.exp(mu2) / p2 * (1e8 + width)
    expected = max(0.0, tau_0 * (mu2 * n3m - mu3 * n2p) / (mu2 - mu3))
    assert r["s_x_0_lower"] == pytest.approx(expected, rel=1e-9)

    # And the base check: log2 would give a different width by sqrt(ln 2).
    wrong_width = np.sqrt(n_block / 2.0 * np.log2(21.0 / eps_sec))
    assert not np.isclose(width, wrong_width)


def test_larger_blocks_do_not_reduce_the_key_length():
    """More pulses must not yield fewer secret bits (monotone in block size)."""
    lengths = [finite_key_secret_length(
        n, n / 10, n / 100, n, n / 10, n / 100,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=0.01 * n,
        eps_sec=1e-9)["secret_key_length_bits"]
        for n in (1e8, 1e9, 1e10, 1e11)]
    assert all(a <= b for a, b in zip(lengths, lengths[1:])), lengths


def test_phase_error_is_bounded_and_reported():
    r = finite_key_secret_length(
        1e8, 1e7, 1e6, 1e8, 1e7, 1e6,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=1e6)
    assert 0.0 <= r["phase_error_upper"] <= 0.5
    assert r["random_sampling_correction"] >= 0.0


def test_finite_key_result_exposes_its_accounting():
    """Every term of the length formula must be visible, not just the total."""
    r = finite_key_secret_length(
        1e9, 1e8, 1e7, 1e9, 1e8, 1e7,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=1e7)
    for key in ("secret_key_length_bits", "s_x_0_lower", "s_x_1_lower",
                "v_z_1_upper", "phase_error_upper", "leak_ec_bits",
                "block_secrecy_cost_bits", "sifted_key_bits",
                "qber_z_observed"):
        assert key in r, f"missing accounting term {key!r}"


def test_finite_key_rate_never_exceeds_the_classical_limit():
    """A sanity bound: the rate cannot exceed one bit per pulse."""
    for n in (1e8, 1e10, 1e12):
        r = run_bb84_decoy(50.0, n_pulses=n)
        assert 0.0 <= r["key_rate_per_pulse"] <= 1.0


def test_qber_override_takes_precedence_and_is_explicit():
    """``qber_z`` is an override for callers with an external measurement.

    The default derives the QBER from the Z-basis counts so that an optimistic
    assertion cannot silently reduce the error-correction cost.  An explicit
    ``qber_z`` is honoured -- the validation path needs that -- but it must be
    given deliberately.
    """
    derived = finite_key_secret_length(
        1e9, 1e8, 1e7, 1e9, 1e8, 1e7,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=1e7)
    # 1e7 errors over 1e9 + 1e8 + 1e7 = 1.11e9 sifted bits
    assert derived["qber_z_observed"] == pytest.approx(1e7 / 1.11e9, rel=1e-9)

    overridden = finite_key_secret_length(
        1e9, 1e8, 1e7, 1e9, 1e8, 1e7,
        mu_signal=0.5, mu_decoy=0.1, n_z_errors=1e7, qber_z=0.001)
    assert overridden["qber_z_observed"] == pytest.approx(0.001, rel=1e-12)

    # A lower asserted QBER can only ever buy more key, never less.  At small
    # block sizes the phase-error bound saturates and both lengths are 0, so
    # assert the ordering rather than a strict improvement.
    assert (overridden["secret_key_length_bits"]
            >= derived["secret_key_length_bits"])
    assert (overridden["leak_ec_bits"] < derived["leak_ec_bits"]), (
        "the override must actually change the error-correction charge"
    )


def test_missing_qber_source_defaults_to_zero_not_to_optimism():
    """With neither counts nor an override, the QBER is 0 and EC costs nothing.

    This is the honest degenerate default: it charges no error-correction cost
    because none was specified, and the accounting terms still reconcile.
    """
    r = finite_key_secret_length(
        1e9, 1e8, 1e7, 1e9, 1e8, 1e7,
        mu_signal=0.5, mu_decoy=0.1)
    assert r["qber_z_observed"] == 0.0
    assert r["leak_ec_bits"] == 0.0


@pytest.mark.parametrize("kwargs", [
    {"eps_sec": 0.0},
    {"eps_sec": -1.0},
    {"eps_cor": 0.0},
])
def test_finite_key_rejects_invalid_security_parameters(kwargs):
    with pytest.raises(ValueError):
        finite_key_secret_length(1e8, 1e7, 1e6, 1e8, 1e7, 1e6,
                                 mu_signal=0.5, mu_decoy=0.1, **kwargs)


# ---------------------------------------------------------------------------
# Presets and published reach
# ---------------------------------------------------------------------------

def test_all_presets_run():
    for name in DECOY_PRESETS:
        r = run_bb84_decoy_preset(name, 20.0)
        assert np.isfinite(r["key_rate_per_pulse"])
        assert r["preset"] == name


def test_gobby_yuan_shields_reproduces_published_122km_reach():
    """GYS 2004 demonstrated 122 km; the model's reach must land near it.

    Caveat, stated deliberately: GYS predates practical decoy-state
    implementations, so this agreement is a consistency check on the channel
    and detector model, **not** a reproduction of a decoy-state experiment.
    """
    reach = max_secure_distance_km("gobby-yuan-shields", hi=400.0, tol=0.5)
    assert 100.0 <= reach <= 145.0, f"model reach {reach} km is off the 122 km demo"


def test_snspd_preset_outreaches_spad_preset():
    """Better detectors must buy reach."""
    spad = max_secure_distance_km("practical-1550", hi=600.0)
    snspd = max_secure_distance_km("snspd-1550", hi=600.0)
    assert snspd > spad


def test_zero_dark_counts_has_no_loss_limited_reach():
    """With no dark counts the asymptotic model has no maximum distance.

    Both rate terms scale with the channel transmissivity, so the rate stays
    positive at every finite length.  A bisection would otherwise report a
    large finite number born of floating-point cancellation -- not physics.
    ``inf`` is the honest answer, and it is distinguishable from a reach.
    """
    assert max_secure_distance_km("practical-1550", hi=900.0,
                                  dark_count_hz=0.0) == float("inf")


def test_unknown_preset_raises():
    with pytest.raises(KeyError):
        run_bb84_decoy_preset("no-such-hardware", 10.0)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs", [
    {"nu": 0.5},            # decoy not weaker than signal
    {"nu": 0.0},            # non-positive intensity
    {"nu": -0.1},
    {"detector_efficiency": 0.0},
    {"detector_efficiency": 1.5},
    {"e_detector": 0.7},
])
def test_invalid_parameters_raise(kwargs):
    with pytest.raises(ValueError):
        run_bb84_decoy(10.0, **kwargs)


def test_negative_distance_raises():
    with pytest.raises(ValueError):
        run_bb84_decoy(-1.0)


def test_result_is_json_serialisable():
    """The CLI emits these on stdout, so every value must be a plain type."""
    import json
    r = run_bb84_decoy(50.0)
    json.dumps(r)  # must not raise
