"""Contract tests for the Rust bridge interface (``ghost-net --json-output``).

The Vantablack daemon spawns ``python -m quantumnet ghost-net ... --json-output``
and parses stdout with a strict JSON parser. These tests pin that contract:
exactly one JSON document on stdout, diagnostics on stderr, fixed field set.
"""

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from quantumnet.cli import KEY_FIDELITY_CUTOFF, QKD_LABEL_SEED, _qkd_key_for_route

SRC = Path(__file__).resolve().parents[2] / "src"

FIELDS = {"success", "path", "end_to_end_fidelity", "swap_nodes", "qkd_key_hex",
          "key_fidelity", "distillation_rounds"}


def _write_topology(tmp_path: Path) -> Path:
    """A vantablack-format export: four nodes in a line, 8 km hops.

    The hop length decides the route fidelity these tests observe, so it is
    chosen to be a realistic metro link rather than a degenerate one. Note that
    *no* length clears the BB84 cutoff on its own -- see
    `test_distillation_is_what_makes_a_route_usable`.
    """
    topo = {
        "generator": "vantablack",
        "exported_at": "2026-01-01T00:00:00Z",
        "nodes": [
            {"fingerprint": "aaaa", "addr": "10.0.0.1:2270"},
            {"fingerprint": "bbbb", "addr": "10.0.0.2:2270"},
            {"fingerprint": "cccc", "addr": "10.0.0.3:2270"},
            {"fingerprint": "dddd", "addr": "10.0.0.4:2270"},
        ],
        "links": [
            {"a": "aaaa", "b": "bbbb", "length_km": 8.0},
            {"a": "bbbb", "b": "cccc", "length_km": 8.0},
            {"a": "cccc", "b": "dddd", "length_km": 8.0},
        ],
        "positions": {
            "aaaa": [0.0, 0.0],
            "bbbb": [8.0, 0.0],
            "cccc": [16.0, 0.0],
            "dddd": [24.0, 0.0],
        },
    }
    p = tmp_path / "ghost-topology.json"
    p.write_text(json.dumps(topo), encoding="utf-8")
    return p


def _run_qkd_derive(fidelity: float, seed: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", "qkd-derive",
         "--fidelity", str(fidelity), "--seed", str(seed), "--json-output"],
        capture_output=True, text=True, timeout=120, cwd=str(SRC),
    )


def _run_ghost_net(topo: Path, src: str, dst: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", "ghost-net",
         "--topology", str(topo), "--from", src, "--to", dst,
         "--json-output"],
        capture_output=True, text=True, timeout=120,
        cwd=str(SRC),  # package importable without installation
    )


def test_json_output_success_contract(tmp_path):
    topo = _write_topology(tmp_path)
    proc = _run_ghost_net(topo, "aaaa", "dddd")

    assert proc.returncode == 0, proc.stderr
    # Exactly one JSON document on stdout -- the strict parser must not choke.
    doc = json.loads(proc.stdout)
    assert set(doc) == FIELDS
    assert doc["success"] is True
    assert doc["path"] == ["aaaa", "bbbb", "cccc", "dddd"]
    assert doc["swap_nodes"] == ["bbbb", "cccc"]
    f = doc["end_to_end_fidelity"]
    assert math.isfinite(f) and 0.0 < f < 1.0
    # The *route* fidelity is what the swapping chain achieved, and it is capped
    # by the dark-count floor below the BB84 cutoff -- so it is reported as
    # measured, never inflated to justify a key.
    assert f < KEY_FIDELITY_CUTOFF, (
        "a distributed route cannot clear the cutoff at this dark-count floor; "
        f"if this now passes ({f}), the model changed and the tests below need revisiting"
    )
    assert doc["qkd_key_hex"] is None or (
        isinstance(doc["qkd_key_hex"], str) and len(doc["qkd_key_hex"]) == 64
    )


def test_distillation_is_what_makes_a_route_usable(tmp_path):
    """A route alone never yields a key; distillation is the whole difference.

    The dark-count floor holds *every* link below the cutoff, so before
    distillation the anchor would always degrade and a live session would never
    gain a quantum epoch. This pins the three facts that make it work: the route
    fidelity is below the cutoff, the reported key fidelity is above it, and the
    key is present.
    """
    topo = _write_topology(tmp_path)
    doc = json.loads(_run_ghost_net(topo, "aaaa", "dddd").stdout)

    assert doc["success"] is True
    assert doc["end_to_end_fidelity"] < KEY_FIDELITY_CUTOFF
    assert doc["key_fidelity"] >= KEY_FIDELITY_CUTOFF
    assert doc["distillation_rounds"] >= 1
    assert isinstance(doc["qkd_key_hex"], str) and len(doc["qkd_key_hex"]) == 64


def test_the_key_fidelity_label_reproduces_the_same_key_on_the_other_peer(tmp_path):
    """The two-peer agreement, at the level the two subcommands implement it.

    The starting peer routes and distils, then sends only the label. The
    answering peer derives from that label. If these two paths disagree, the
    session mix is refused and the epoch never moves -- so the equality here is
    the property the whole exchange rests on.
    """
    topo = _write_topology(tmp_path)
    routed = json.loads(_run_ghost_net(topo, "aaaa", "dddd").stdout)
    assert routed["qkd_key_hex"] is not None

    fetched = json.loads(_run_qkd_derive(routed["key_fidelity"], QKD_LABEL_SEED).stdout)
    assert fetched["qkd_key_hex"] == routed["qkd_key_hex"]

    # And the route's own fidelity is *not* a usable label at this floor: the
    # distinction is load-bearing, not cosmetic.
    from_route_fidelity = json.loads(
        _run_qkd_derive(routed["end_to_end_fidelity"], QKD_LABEL_SEED).stdout
    )
    assert from_route_fidelity["qkd_key_hex"] is None


def test_distillation_is_a_no_op_when_the_route_already_clears_the_cutoff():
    # No route reaches this today (the dark-count floor). The branch is kept and
    # pinned so a future physical model that *does* reach it stays correct.
    from quantumnet.cli import _distil_to_key_fidelity

    fid, rounds, kept = _distil_to_key_fidelity(0.95, QKD_LABEL_SEED)
    assert (fid, rounds) == (0.95, 0)
    assert kept == 256


def test_json_output_route_failure_still_emits_one_json_doc(tmp_path):
    topo = _write_topology(tmp_path)
    proc = _run_ghost_net(topo, "aaaa", "dddd")  # fine...
    assert proc.returncode == 0

    # An unknown fingerprint fails gracefully with a JSON object, not a traceback.
    proc2 = _run_ghost_net(topo, "nope", "dddd")
    assert proc2.returncode != 0
    doc = json.loads(proc2.stdout)
    assert doc["success"] is False
    assert doc["path"] == []
    assert doc["qkd_key_hex"] is None


def test_json_output_no_route_meeting_constraint(tmp_path):
    topo = _write_topology(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "quantumnet", "ghost-net",
         "--topology", str(topo), "--from", "aaaa", "--to", "dddd",
         "--min-fidelity", "0.999999", "--json-output"],
        capture_output=True, text=True, timeout=120, cwd=str(SRC),
    )
    doc = json.loads(proc.stdout)
    assert doc["success"] is False
    assert doc["path"] == []
    assert doc["end_to_end_fidelity"] == 0.0


def test_qkd_derive_emits_one_json_document_with_a_key():
    proc = _run_qkd_derive(0.95, 0x51EE)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert set(doc) == FIELDS
    assert doc["success"] is True
    assert doc["path"] == [] and doc["swap_nodes"] == []
    assert doc["end_to_end_fidelity"] == 0.95
    assert isinstance(doc["qkd_key_hex"], str)
    assert len(doc["qkd_key_hex"]) == 64


def test_qkd_derive_is_reproducible_across_processes_and_seed_sensitive():
    """The two-peer agreement rests on this: same parameters, same key.

    Two independent invocations must produce byte-identical material, because
    the daemon derives the same key on both ends and never sends it. A
    different seed must produce different material, or the seed would not be
    doing anything.
    """
    first = json.loads(_run_qkd_derive(0.95, 0x51EE).stdout)["qkd_key_hex"]
    second = json.loads(_run_qkd_derive(0.95, 0x51EE).stdout)["qkd_key_hex"]
    other = json.loads(_run_qkd_derive(0.95, 0x1234).stdout)["qkd_key_hex"]

    assert first == second
    assert first != other


def test_qkd_derive_below_the_security_cutoff_reports_no_key():
    proc = _run_qkd_derive(0.5, 0x51EE)
    assert proc.returncode != 0
    doc = json.loads(proc.stdout)
    assert set(doc) == FIELDS
    assert doc["success"] is False
    assert doc["qkd_key_hex"] is None


def test_qkd_key_helper_yields_32_bytes():
    # High-fidelity link (clears the QBER cutoff): 32 bytes of real BB84 key.
    key = _qkd_key_for_route(0.95)
    assert key is not None and len(key) == 32
    # Deterministic for a fixed seed -- the bridge can replay it.
    assert key == _qkd_key_for_route(0.95)
    # Hopeless fidelity (QBER past the 11% security threshold): the honest
    # answer is "no key", never garbage bits.
    assert _qkd_key_for_route(0.0) is None
    assert _qkd_key_for_route(0.25) is None
