"""CLI contract tests for the physical-layer budget command."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", *args],
        capture_output=True, text=True, timeout=300,
    )


def test_link_reports_both_models_and_the_ideal_ceiling():
    r = _run("link", "--distance", "50")
    assert r.returncode == 0, r.stderr
    assert "Barrett-Kok" in r.stdout
    assert "single-photon" in r.stdout
    assert "p <= 1/2" in r.stdout


def test_link_json_is_one_parseable_document():
    r = _run("link", "--distance", "50", "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["distance_km"] == 50.0
    assert doc["loss_db"] == pytest.approx(10.0)
    assert doc["transmissivity"] == pytest.approx(0.1, rel=1e-9)


def test_link_success_probability_matches_the_closed_form():
    """The command's headline number must equal ``1/2 * (eta*T)^2``.

    Checked against the CLI rather than the library so the surface a user reads
    is the one under test.
    """
    doc = json.loads(_run("link", "--distance", "50", "--detector-efficiency",
                          "0.8", "--dark-count", "0", "--window", "0",
                          "--json-output").stdout)
    expected = 0.5 * (0.8 * 0.1) ** 2
    assert doc["barrett_kok_success_probability"] == pytest.approx(expected,
                                                                   rel=1e-12)


def test_link_rate_is_half_the_legacy_rate_without_dark_counts():
    doc = json.loads(_run("link", "--distance", "50", "--dark-count", "0",
                          "--window", "0", "--json-output").stdout)
    # Midpoint beam splitter gives T(L) attenuation for Barrett-Kok vs T(L)^2
    # for the single-photon heuristic, so BK = 0.5 * legacy / T(L).
    assert (doc["barrett_kok_rate_hz"]
            == pytest.approx(0.5 * doc["single_photon_rate_hz"]
                             / doc["transmissivity"], rel=1e-9))


def test_link_loss_costs_rate_not_fidelity():
    near = json.loads(_run("link", "--distance", "10", "--dark-count", "0",
                           "--json-output").stdout)
    far = json.loads(_run("link", "--distance", "200", "--dark-count", "0",
                          "--json-output").stdout)
    assert far["barrett_kok_rate_hz"] < near["barrett_kok_rate_hz"]
    assert far["barrett_kok_raw_fidelity"] == pytest.approx(
        near["barrett_kok_raw_fidelity"], rel=1e-9)


def test_link_loss_follows_the_fibre_law():
    """Every 50 km at 0.2 dB/km is 10 dB, so transmissivity falls 10x."""
    a = json.loads(_run("link", "--distance", "50", "--json-output").stdout)
    b = json.loads(_run("link", "--distance", "100", "--json-output").stdout)
    assert a["transmissivity"] / b["transmissivity"] == pytest.approx(10.0,
                                                                     rel=1e-6)


def test_link_dark_counts_raise_the_rate_and_lower_the_fidelity():
    """A dark coincidence is a false herald: more clicks, worse pairs."""
    clean = json.loads(_run("link", "--distance", "100", "--dark-count", "0",
                            "--json-output").stdout)
    noisy = json.loads(_run("link", "--distance", "100", "--dark-count",
                            "1e7", "--json-output").stdout)
    assert noisy["barrett_kok_rate_hz"] >= clean["barrett_kok_rate_hz"]
    assert noisy["barrett_kok_raw_fidelity"] <= clean["barrett_kok_raw_fidelity"]


def test_link_mode_mismatch_lowers_fidelity_without_moving_the_rate():
    matched = json.loads(_run("link", "--mode-matching", "1.0",
                              "--json-output").stdout)
    mismatched = json.loads(_run("link", "--mode-matching", "0.6",
                                 "--json-output").stdout)
    assert mismatched["barrett_kok_raw_fidelity"] < matched[
        "barrett_kok_raw_fidelity"]
    assert mismatched["barrett_kok_success_probability"] == pytest.approx(
        matched["barrett_kok_success_probability"], rel=1e-12)


def test_link_output_is_deterministic():
    first = _run("link", "--json-output").stdout
    second = _run("link", "--json-output").stdout
    assert first == second
