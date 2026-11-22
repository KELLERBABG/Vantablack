"""CLI contract tests for the decoy-state commands (`qkd`, `bench`).

The CLI's documented contract is: exactly one JSON document on stdout in
``--json-output`` mode, human-readable text otherwise, and a non-zero exit
status when the request cannot be answered.  These tests exercise that contract
by invoking the module through ``subprocess`` so they test the real entry point
rather than a helper.
"""

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


# ---------------------------------------------------------------------------
# qkd
# ---------------------------------------------------------------------------

def test_qkd_human_output_reports_a_rate_at_50km():
    r = _run("qkd", "--distance", "50")
    assert r.returncode == 0, r.stderr
    assert "SECURE KEY RATE" in r.stdout
    assert "bits/s" in r.stdout
    # the known value for the default preset at 50 km
    assert "8.895411e+05" in r.stdout


def test_qkd_json_output_is_one_parseable_document():
    r = _run("qkd", "--distance", "50", "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)          # must not raise
    assert doc["distance_km"] == 50.0
    assert doc["secure"] is True
    assert doc["key_rate_per_pulse"] > 0
    assert doc["preset"] == "practical-1550"


def test_qkd_reports_no_key_beyond_reach():
    """Past the reach of the preset the honest answer is 'none', not a number."""
    r = _run("qkd", "--distance", "400")
    assert r.returncode == 0, r.stderr
    assert "none" in r.stdout.lower()

    j = _run("qkd", "--distance", "400", "--json-output")
    doc = json.loads(j.stdout)
    assert doc["secure"] is False
    assert doc["key_rate_per_pulse"] == 0.0
    assert doc["key_rate_hz"] == 0.0


def test_qkd_accepts_preset_and_overrides():
    r = _run("qkd", "--distance", "20", "--preset", "snspd-1550",
             "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["preset"] == "snspd-1550"
    assert doc["detector_efficiency"] == pytest.approx(0.93)

    o = _run("qkd", "--distance", "20", "--mu", "0.4", "--nu", "0.05",
             "--json-output")
    doc = json.loads(o.stdout)
    assert doc["mu"] == pytest.approx(0.4)
    assert doc["nu"] == pytest.approx(0.05)


def test_qkd_pulses_selects_the_finite_key_path():
    """``--pulses`` must switch to the LCWX finite-key accounting."""
    inf = json.loads(_run("qkd", "--distance", "50", "--json-output").stdout)
    fin = json.loads(_run("qkd", "--distance", "50", "--pulses", "1e9",
                          "--json-output").stdout)
    assert inf["asymptotic"] is True
    assert inf["finite_key"] is None
    assert fin["asymptotic"] is False
    # the finite-key path reports its own accounting terms
    assert fin["finite_key"] is not None
    assert fin["finite_key"]["block_secrecy_cost_bits"] > 0.0
    assert 0.0 <= fin["key_rate_per_pulse"] <= 1.0


def test_finite_key_does_not_beat_the_pulse_rate_limit():
    """No accounting path may report more than one bit per pulse."""
    for n in ("1e6", "1e9", "1e12"):
        doc = json.loads(_run("qkd", "--distance", "50", "--pulses", n,
                              "--json-output").stdout)
        assert doc["key_rate_per_pulse"] <= 1.0
        assert doc["key_rate_hz"] <= doc["pulse_rate_hz"]


def test_qkd_unknown_preset_fails_loudly_on_stderr():
    r = _run("qkd", "--preset", "no-such-hardware")
    assert r.returncode != 0
    assert "unknown preset" in r.stderr
    assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# bench
# ---------------------------------------------------------------------------

def test_bench_prints_a_curve_and_a_reach():
    r = _run("bench", "--start", "0", "--stop", "120", "--step", "30")
    assert r.returncode == 0, r.stderr
    assert "key rate vs distance" in r.stdout
    assert "max secure distance" in r.stdout


def test_bench_json_is_parseable_and_monotone():
    r = _run("bench", "--start", "0", "--stop", "200", "--step", "25",
             "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    pts = doc["points"]
    assert len(pts) == 9
    rates = [p["key_rate_per_pulse"] for p in pts]
    # non-increasing in distance
    assert all(a >= b for a, b in zip(rates, rates[1:]))
    assert rates[0] > 0
    assert doc["max_secure_distance_km"] > 0


def test_bench_multi_preset_returns_a_list_of_documents():
    r = _run("bench", "--start", "0", "--stop", "60", "--step", "60",
             "--preset", "practical-1550", "--preset", "snspd-1550",
             "--json-output")
    assert r.returncode == 0, r.stderr
    docs = json.loads(r.stdout)
    assert isinstance(docs, list)
    assert [d["preset"] for d in docs] == ["practical-1550", "snspd-1550"]


def test_bench_unknown_preset_fails_loudly():
    r = _run("bench", "--preset", "nope")
    assert r.returncode != 0
    assert "unknown preset" in r.stderr


def test_bench_defaults_to_the_practical_preset():
    r = _run("bench", "--start", "0", "--stop", "10", "--step", "10",
             "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["preset"] == "practical-1550"
