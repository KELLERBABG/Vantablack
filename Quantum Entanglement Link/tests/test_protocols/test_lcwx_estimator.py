"""Differential tests for the LCWX finite-key estimator.

The finite-key path once returned a zero key length **as a legitimate number** --
no exception, `secure` still true, and the asymptotic validation path unaffected,
so nothing failed loudly. Four distinct defects were found by differential
testing against an independently written reference implementation:

1. the fluctuation width used the count *at one intensity* instead of the basis
   block total;
2. the intensity probabilities ``p_k`` and the correct ``tau_0`` were missing;
3. the phase error was divided by the X-basis single-photon count instead of the
   Z-basis one;
4. the Z-basis **single-photon count** was fed *error-weighted* counts, driving it
   to zero, while the phase-error numerator needs exactly those error counts.

Defect 4 is the one worth remembering: the Z basis needs **two** count families,
and using one for both jobs is what made every parameter choice return zero.

These tests pin the estimator against values computed independently from the
LCWX equations, so a future edit that reintroduces any of the four fails here.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from quantumnet.protocols.bb84 import (
    binary_entropy,
    finite_key_secret_length,
    run_bb84_decoy,
)


def _reference_channel(L_km: float, N: float, qx: float, p1: float, p2: float,
                       mu1: float, mu2: float, mu3: float = 0.0,
                       eta_det: float = 0.8, p_dark: float = 1e-6,
                       alpha: float = 0.2, e_mis: float = 0.01):
    """Counts in both bases, straight from the Ma-style channel model.

    Returns ``(n_x, n_z, n_z_error, e_obs)`` as per-intensity lists.  Computed
    once and fed to the estimator, because the reference script derives its
    counts internally while ``finite_key_secret_length`` takes them as
    arguments -- comparing the two without doing this compares count
    conventions, not formulas.
    """
    p3 = 1.0 - p1 - p2
    eta = 10 ** (-alpha * L_km / 10) * eta_det
    Y0, e0 = p_dark, 0.5
    ks, ps = [mu1, mu2, mu3], [p1, p2, p3]
    R = [Y0 + 1 - math.exp(-eta * k) for k in ks]
    E = [(e0 * Y0 + e_mis * (1 - math.exp(-eta * k))) / r for k, r in zip(ks, R)]
    n_x = [N * qx * qx * p * r for p, r in zip(ps, R)]
    n_z = [N * (1 - qx) ** 2 * p * r for p, r in zip(ps, R)]
    n_z_err = [N * (1 - qx) ** 2 * p * r * e for p, r, e in zip(ps, R, E)]
    e_obs = sum(p * r * e for p, r, e in zip(ps, R, E)) / sum(
        p * r for p, r in zip(ps, R))
    return n_x, n_z, n_z_err, e_obs


def _estimate(L_km=100.0, N=1e10, qx=0.8935368226420126,
              p1=0.5929869366884731, p2=0.2765471937920671,
              mu1=0.5608429655375814, mu2=0.26528194158401214,
              eps_sec=1e-9, qber_z=None, **kw):
    n_x, n_z, n_z_err, e_obs = _reference_channel(L_km, N, qx, p1, p2, mu1, mu2)
    return finite_key_secret_length(
        n_x_signal=n_x[0], n_x_decoy=n_x[1], n_x_vacuum=n_x[2],
        n_z_signal=n_z[0], n_z_decoy=n_z[1], n_z_vacuum=n_z[2],
        n_z_error_signal=n_z_err[0], n_z_error_decoy=n_z_err[1],
        n_z_error_vacuum=n_z_err[2],
        mu_signal=mu1, mu_decoy=mu2, eps_sec=eps_sec, eps_cor=1e-15,
        qber_z=e_obs if qber_z is None else qber_z,
        p_signal=p1, p_decoy=p2, p_vacuum=1 - p1 - p2, **kw)


# ---------------------------------------------------------------------------
# The headline: a key is actually produced
# ---------------------------------------------------------------------------

def test_a_healthy_channel_produces_a_positive_key():
    """The regression that matters most.

    Before the fixes this returned ``0`` for **every** parameter set, and
    returned it as a legitimate float.  A positive length at a good channel is
    the single most important assertion in this file.
    """
    out = _estimate()
    assert out["secret_key_length_bits"] > 0, (
        "the finite-key path produced no key on a healthy channel"
    )
    assert out["phase_error_upper"] < 0.5, (
        "the phase error saturated, which zeroes the key at any distance"
    )


def test_the_key_grows_with_the_block_size_once_above_the_floor():
    """More pulses must mean more key, above a finite-size floor.

    At ``N = 1e8`` the phase-error bound **saturates** and at ``N = 1e9`` no key is
    yet extractable.  Above that floor both the total and the per-pulse rate rise.
    """
    tiny = _estimate(N=1e8)
    assert tiny["secret_key_length_bits"] == 0
    assert tiny["phase_error_upper"] == pytest.approx(0.5)

    small = _estimate(N=1e9)
    assert small["secret_key_length_bits"] == 0
    assert small["phase_error_upper"] < 0.5

    lengths = [_estimate(N=n)["secret_key_length_bits"]
               for n in (1e10, 1e11, 1e12)]
    assert all(x > 0 for x in lengths), lengths
    assert lengths == sorted(lengths), lengths
    rates = [x / n for x, n in zip(lengths, (1e10, 1e11, 1e12))]
    assert rates == sorted(rates), rates


def test_a_bigger_block_tightens_the_phase_error_bound():
    """The fluctuation width shrinks relative to the counts as the block grows."""
    phases = [_estimate(N=n)["phase_error_upper"] for n in (1e10, 1e11, 1e12)]
    assert phases == sorted(phases, reverse=True), phases


def test_the_key_falls_with_distance():
    """A longer fibre cannot yield more key."""
    lengths = [_estimate(L_km=d)["secret_key_length_bits"]
               for d in (0.0, 50.0, 100.0)]
    assert lengths == sorted(lengths, reverse=True), lengths


# ---------------------------------------------------------------------------
# Defect 4: the Z basis needs two distinct count families
# ---------------------------------------------------------------------------

def test_the_z_single_photon_count_is_not_error_weighted():
    """Feeding error counts into ``s_Z,1`` zeroes it and kills the key.

    This is defect 4, and it is the subtle one: ``v_Z,1`` (the phase-error
    numerator) *must* use error counts, while ``s_Z,1`` (the denominator) must
    use raw counts.  Using the error counts for both makes the denominator
    collapse, the ratio diverge, and the key zero -- for every channel.
    """
    correct = _estimate()
    n_x, n_z, n_z_err, e_obs = _reference_channel(
        100.0, 1e10, 0.8935368226420126, 0.5929869366884731,
        0.2765471937920671, 0.5608429655375814, 0.26528194158401214)

    # Deliberately wrong: error-weighted counts used for the Z basis everywhere.
    wrong = finite_key_secret_length(
        n_x_signal=n_x[0], n_x_decoy=n_x[1], n_x_vacuum=n_x[2],
        n_z_signal=n_z_err[0], n_z_decoy=n_z_err[1], n_z_vacuum=n_z_err[2],
        n_z_error_signal=n_z_err[0], n_z_error_decoy=n_z_err[1],
        n_z_error_vacuum=n_z_err[2],
        mu_signal=0.5608429655375814, mu_decoy=0.26528194158401214,
        eps_sec=1e-9, qber_z=e_obs,
        p_signal=0.5929869366884731, p_decoy=0.2765471937920671,
        p_vacuum=1 - 0.5929869366884731 - 0.2765471937920671)

    assert correct["secret_key_length_bits"] > 0
    assert wrong["secret_key_length_bits"] == 0, (
        "the error-weighted denominator should collapse; if it does not, the "
        "test no longer demonstrates defect 4"
    )
    assert correct["phase_error_upper"] < wrong["phase_error_upper"]


# ---------------------------------------------------------------------------
# Defects 1-3
# ---------------------------------------------------------------------------

def test_the_fluctuation_width_uses_the_basis_block_size():
    """Defect 1: the width belongs to the basis total, not one intensity.

    Checked by scaling only the *block*: adding counts at the vacuum intensity
    changes ``n_X`` and therefore the width applied to every count, which a
    per-intensity variance could not produce.
    """
    base = _estimate()
    widened = finite_key_secret_length(
        n_x_signal=2.12e7, n_x_decoy=4.683e6, n_x_vacuum=1.0417e3 * 100,
        n_z_signal=3.009e5, n_z_decoy=6.648e4, n_z_vacuum=14.79,
        mu_signal=0.5608429655375814, mu_decoy=0.26528194158401214,
        eps_sec=1e-9, qber_z=0.010151146,
        p_signal=0.5929869366884731, p_decoy=0.2765471937920671,
        p_vacuum=1 - 0.5929869366884731 - 0.2765471937920671)
    assert widened["s_x_0_lower"] != base["s_x_0_lower"]


def test_intensity_probabilities_must_sum_to_one():
    """Defect 2 introduced ``p_k``; a mis-set set must be refused, not absorbed."""
    with pytest.raises(ValueError, match="probabilities must sum to 1"):
        finite_key_secret_length(
            1e9, 1e8, 1e7, 1e9, 1e8, 1e7,
            mu_signal=0.5, mu_decoy=0.1, p_signal=0.5, p_decoy=0.5,
            p_vacuum=0.5)


def test_the_phase_error_uses_the_z_basis_denominator():
    """Defect 3: ``phi = v_Z1/s_Z1 + gamma``, not ``v_Z1/s_X1``.

    Detected by starving the X basis while leaving the Z basis healthy.  The
    phase error is then **still** governed by Z and stays unsaturated; if it were
    computed from ``s_X,1`` it would depend on the X counts and collapse.

    Note the estimator *does* require ``s_X,1 > 0`` before it will report anything,
    because the key length is built from the X-basis single-photon count -- so a
    fully starved X basis saturates ``phi`` by design.  The discriminator is
    therefore a *moderately* reduced X basis: Z is untouched, so ``phi`` must be
    identical to the healthy case.
    """
    healthy = _estimate()
    half_x = finite_key_secret_length(
        n_x_signal=2.12e7 / 2, n_x_decoy=4.683e6 / 2, n_x_vacuum=1.0417e3 / 2,
        n_z_signal=3.009e5, n_z_decoy=6.648e4, n_z_vacuum=14.79,
        n_z_error_signal=3.009e5 * 0.010151146,
        n_z_error_decoy=6.648e4 * 0.010151146,
        n_z_error_vacuum=14.79 * 0.5,
        mu_signal=0.5608429655375814, mu_decoy=0.26528194158401214,
        eps_sec=1e-9, qber_z=0.010151146,
        p_signal=0.5929869366884731, p_decoy=0.2765471937920671,
        p_vacuum=1 - 0.5929869366884731 - 0.2765471937920671)

    # The Z basis is unchanged, so the phase error must stay essentially put.
    # It is not *identical*: the Fung correction ``gamma`` takes both ``s_Z1`` and
    # ``s_X1`` as arguments, so halving the X basis perturbs it slightly.  The
    # discriminator is that the change is tiny -- if ``phi`` were built from
    # ``s_X1`` directly, halving it would nearly double the ratio and drive the
    # phase error to the 0.5 cap.
    assert healthy["phase_error_upper"] < 0.5
    assert half_x["phase_error_upper"] < 0.5
    relative_shift = abs(half_x["phase_error_upper"]
                         - healthy["phase_error_upper"]) / healthy[
                             "phase_error_upper"]
    assert relative_shift < 0.01, (
        f"halving the X basis moved the phase error by {relative_shift:.1%}, "
        f"which means the X-basis count is driving it"
    )


def test_the_block_cost_is_still_the_lcw_x_absolute_cost():
    """The one part that was right from the start must stay right."""
    eps_sec, eps_cor = 1e-9, 1e-15
    expected = 6.0 * np.log2(21.0 / eps_sec) + np.log2(2.0 / eps_cor)
    out = _estimate(eps_sec=eps_sec)
    assert out["block_secrecy_cost_bits"] == pytest.approx(expected, rel=1e-12)


def test_the_phase_error_is_capped_at_one_half():
    """A rate cannot exceed 1/2; saturation means no key is extractable."""
    for qber in (0.0, 0.01, 0.1, 0.4):
        out = _estimate(qber_z=qber)
        assert 0.0 <= out["phase_error_upper"] <= 0.5


def test_a_worse_qber_cannot_improve_the_key():
    good = _estimate(qber_z=0.005)["secret_key_length_bits"]
    poor = _estimate(qber_z=0.03)["secret_key_length_bits"]
    assert poor <= good


def test_v_z_1_upper_uses_total_z_error_count_m_z():
    """Fluctuation width for ``v_Z,1`` uses ``m_Z`` (total Z errors), not ``n_Z``."""
    p1, p2, p3 = 0.5, 0.25, 0.25
    m1, m2 = 0.5, 0.1
    eps = 1e-10
    n_z_sig, n_z_dec, n_z_vac = 1e7, 2e6, 1e3
    e_sig, e_dec, e_vac = 2e5, 4e4, 5e2
    m_z = e_sig + e_dec + e_vac
    out = finite_key_secret_length(
        1e8, 2e7, 1e4, n_z_sig, n_z_dec, n_z_vac,
        n_z_error_signal=e_sig, n_z_error_decoy=e_dec, n_z_error_vacuum=e_vac,
        mu_signal=m1, mu_decoy=m2, eps_sec=eps, qber_z=0.02,
        p_signal=p1, p_decoy=p2, p_vacuum=p3,
    )
    tau_1 = p1 * m1 * math.exp(-m1) + p2 * m2 * math.exp(-m2)
    width = math.sqrt(m_z / 2.0 * math.log(21.0 / eps))
    expected_v_z_1 = tau_1 * (
        math.exp(m2) / p2 * (e_dec + width) - (1.0 / p3) * (e_vac - width)
    ) / m2
    assert out["v_z_1_upper"] == pytest.approx(expected_v_z_1, rel=1e-12)


def test_leak_ec_is_computed_on_x_basis_key_block():
    """Error correction leakage is paid on the key-generation basis ``n_X``."""
    n_x = (1e8, 2e7, 1e4)
    n_z = (1e6, 2e5, 1e2)
    qber_z = 0.02
    f_ec = 1.22
    out = finite_key_secret_length(
        *n_x, *n_z,
        mu_signal=0.5, mu_decoy=0.1, qber_z=qber_z,
        error_correction_inefficiency=f_ec,
    )
    assert out["leak_ec_bits"] == pytest.approx(
        f_ec * binary_entropy(qber_z) * sum(n_x), rel=1e-12
    )


def test_run_bb84_decoy_finite_key_uses_p_k_and_sifting():
    """``run_bb84_decoy(..., n_pulses=...)`` weights counts by ``p_k`` and 0.25 sifting."""
    n_pulses = 1e11
    res = run_bb84_decoy(50.0, n_pulses=n_pulses)
    assert res["secure"] is True
    assert res["key_rate_per_pulse"] > 0.0
    fk = res["finite_key"]
    expected_n_z = n_pulses * 0.25 * (0.5 * res["q_mu"] + 0.25 * res["q_nu"] + 0.25 * res["q_vac"])
    assert fk["sifted_key_bits"] == pytest.approx(expected_n_z, rel=1e-12)
