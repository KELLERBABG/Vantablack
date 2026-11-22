"""CLI contract tests for the memory-contention command.

Same contract as the other commands: exactly one JSON document on stdout in
``--json-output`` mode, readable text otherwise, and a non-zero exit when the
request cannot be answered.
"""

from __future__ import annotations

import json
import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", *args],
        capture_output=True, text=True, timeout=300,
    )


def test_contend_reports_granted_and_refused():
    r = _run("contend")
    assert r.returncode == 0, r.stderr
    assert "granted" in r.stdout and "refused" in r.stdout
    assert "GRANTED" in r.stdout


def test_contend_json_is_one_parseable_document():
    r = _run("contend", "--json-output")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)          # must not raise
    assert doc["nodes"] == 4
    assert doc["memory_per_node"] == 2
    assert doc["demands"] == 4
    assert doc["granted"] + doc["refused"] == doc["demands"]
    assert len(doc["outcomes"]) == doc["demands"]


def test_contention_actually_refuses_when_the_pool_is_small():
    """The command's whole point: a small pool must not serve everything."""
    doc = json.loads(_run("contend", "--nodes", "3", "--memory", "2",
                          "--demands", "6", "--json-output").stdout)
    assert doc["refused"] > 0
    refused = [o for o in doc["outcomes"] if not o["granted"]]
    assert all(o["reason"] for o in refused), "a refusal must say why"
    assert all(o["delivered_fidelity"] == 0.0 for o in refused)


def test_a_large_pool_serves_every_demand():
    """A control: refusals must come from contention, not a broken command."""
    doc = json.loads(_run("contend", "--nodes", "3", "--memory", "40",
                          "--demands", "3", "--json-output").stdout)
    assert doc["refused"] == 0
    assert doc["granted"] == 3


def test_granted_outcomes_report_a_route_and_a_fidelity():
    doc = json.loads(_run("contend", "--memory", "8", "--demands", "2",
                          "--json-output").stdout)
    granted = [o for o in doc["outcomes"] if o["granted"]]
    assert granted
    for outcome in granted:
        assert len(outcome["path"]) >= 2
        assert 0.0 < outcome["delivered_fidelity"] <= 1.0


def test_granted_count_never_exceeds_capacity():
    """Bounded, not optimistic: grants x pairs cannot exceed the pool."""
    doc = json.loads(_run("contend", "--nodes", "2", "--memory", "3",
                          "--demands", "9", "--json-output").stdout)
    assert doc["granted"] <= 3
    assert doc["granted"] + doc["refused"] == 9


def test_too_few_nodes_is_refused_loudly():
    r = _run("contend", "--nodes", "1")
    assert r.returncode != 0
    assert "at least 2 nodes" in r.stderr
    assert r.stdout.strip() == ""


def test_zero_memory_is_refused_loudly():
    r = _run("contend", "--memory", "0")
    assert r.returncode != 0
    assert "--memory" in r.stderr


def test_contend_is_deterministic():
    first = _run("contend", "--json-output").stdout
    second = _run("contend", "--json-output").stdout
    assert first == second
