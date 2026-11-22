"""CLI contract tests for the validation command."""

from __future__ import annotations

import json
import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", *args],
        capture_output=True, text=True, timeout=600,
    )


def test_validate_exits_zero_when_the_comparisons_pass():
    r = _run("validate")
    assert r.returncode == 0, f"validation failed:\n{r.stdout}\n{r.stderr}"
    assert "published" in r.stdout


def test_validate_reports_both_scored_categories():
    r = _run("validate")
    assert "VALIDATED" in r.stdout
    assert "UPPER BOUND" in r.stdout


def test_validate_names_the_unscored_datasets_rather_than_hiding_them():
    """A comparison that does not apply must be visible, not omitted."""
    r = _run("validate")
    assert "CONTEXT" in r.stdout
    assert "boaron-2018-421km" in r.stdout


def test_validate_json_is_one_parseable_document():
    r = _run("validate", "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)          # must not raise
    assert "comparisons" in doc
    assert "not_scored" in doc
    assert "loss_budget" in doc


def test_validate_json_comparisons_carry_their_citations():
    doc = json.loads(_run("validate", "--json-output").stdout)
    assert doc["comparisons"], "no comparisons reported"
    for row in doc["comparisons"]:
        assert row["url"].startswith("https://")
        assert row["citation"]
        assert row["kind"] in ("validated", "upper-bound")


def test_validate_json_marks_the_incomparable_ones():
    doc = json.loads(_run("validate", "--json-output").stdout)
    names = {row["name"] for row in doc["not_scored"]}
    assert "boaron-2018-421km" in names
    for row in doc["not_scored"]:
        assert row["kind"] == "context"


def test_validate_json_exposes_the_loss_budget_cross_check():
    doc = json.loads(_run("validate", "--json-output").stdout)
    budget = doc["loss_budget"]
    assert len(budget) == 5
    for row in budget:
        assert abs(row["difference_db"]) < 0.5
        assert 0.16 <= row["implied_alpha_db_km"] <= 0.18


def test_validate_output_is_deterministic():
    assert _run("validate", "--json-output").stdout == \
        _run("validate", "--json-output").stdout
