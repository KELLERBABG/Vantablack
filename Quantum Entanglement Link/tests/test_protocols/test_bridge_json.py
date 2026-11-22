"""Schema-agnostic contract tests for the Rust bridge interface (``import --json-output``).

These tests pin that any topology importer (QEL json, ghostnet, dot) produces
the same strict single-JSON-document contract on stdout, fixed field set,
diagnostics on stderr, and no traceback.  The document shape is defined by
QEL, not by the daemon -- the ghostnet adapter is covered by a companion
test file.

The topology source is chosen per test via ``schema_id``; nothing in this
file knows where a topology came from.
"""

import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from quantumnet.cli import KEY_FIDELITY_CUTOFF, QKD_LABEL_SEED, _qkd_key_for_route
from quantumnet.topology.importers import importer_for

SRC = Path(__file__).resolve().parents[2] / "src"

FIELDS = {"success", "path", "end_to_end_fidelity", "swap_nodes", "qkd_key_hex",
          "key_fidelity", "distillation_rounds"}

#: Temp file per schema, named so the CLI can resolve the importer from the
#: extension alone (its real contract -- no schema_id on the command line).
_TMP_NAMES = {
    "qel-json": "test_bridge_tmp.qel.json",
    "ghostnet": "test_bridge_tmp.ggn",
    "vantablack": "test_bridge_tmp.ggn",
    "dot": "test_bridge_tmp.dot",
}

#: Scratch directory for the temp topologies.
#:
#: These files used to be written into ``SRC`` -- inside the package -- and left
#: there, so every test run dirtied the working tree with four untracked files.
#: A test must not write into the source tree.  A single module-scoped directory
#: keeps the files out of the repo while still putting them on disk, which the
#: CLI genuinely needs: it resolves the importer from the file extension, so it
#: cannot be handed an in-memory document.
_TMP_DIR = tempfile.TemporaryDirectory(prefix="qel-bridge-")


def _write_and_parse(topo, schema_id: str) -> str:
    """Write ``topo`` (dict or dot source) to a temp file and parse it through
    the importer, proving the format is importable.  Returns the file path,
    which ``_run_import`` then feeds to the CLI as ``--topology``."""
    try:
        name = _TMP_NAMES[schema_id]
    except KeyError:
        raise ValueError(f"no temp filename for schema {schema_id!r}") from None
    path = Path(_TMP_DIR.name) / name
    if isinstance(topo, dict):
        path.write_text(json.dumps(topo), encoding="utf-8")
    else:
        path.write_text(topo, encoding="utf-8")
    doc = importer_for(str(path), schema_id)(str(path)).parse()
    assert doc["nodes"], "importer produced no nodes"
    assert doc["links"], "importer produced no links"
    return str(path)


def _run_import(path, src: str = "A", dst: str = "D", **extra_args) -> subprocess.CompletedProcess:
    extra = []
    for flag, value in extra_args.items():
        extra += [f"--{flag.replace('_', '-')}", str(value)]
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", "import",
         "--topology", str(path), "--from", src, "--to", dst, *extra,
         "--json-output"],
        capture_output=True, text=True, timeout=120, cwd=str(SRC),
    )


def test_json_output_success_contract(tmp_path):
    """A valid import prints exactly one JSON document on stdout, with the
    full field set and a finite end-to-end fidelity below the cutoff."""
    doc = _write_and_parse(
        {
            "schema_version": "1.0",
            "generated_at": "2026-10-07T00:00:00Z",
            "nodes": [
                {"id": "A", "x_km": 0.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
                {"id": "R0", "x_km": 8.0, "y_km": 0.0, "t1_s": 200, "t2_s": 100, "is_repeater": True},
                {"id": "R1", "x_km": 16.0, "y_km": 0.0, "t1_s": 200, "t2_s": 100, "is_repeater": True},
                {"id": "D", "x_km": 24.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
            ],
            "links": [
                {"a": "A", "b": "R0", "length_km": 8.0, "alpha_db_km": 0.2},
                {"a": "R0", "b": "R1", "length_km": 8.0, "alpha_db_km": 0.2},
                {"a": "R1", "b": "D", "length_km": 8.0, "alpha_db_km": 0.2},
            ],
        },
        "qel-json",
    )
    proc = _run_import(doc, "A", "D")

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert set(payload) == FIELDS
    assert payload["success"] is True
    assert payload["path"] == ["A", "R0", "R1", "D"]
    assert payload["swap_nodes"] == ["R0", "R1"]
    f = payload["end_to_end_fidelity"]
    assert math.isfinite(f) and 0.0 < f < 1.0
    # The route fidelity is what the swapping chain achieved, and it is capped
    # by the dark-count floor below the BB84 cutoff -- so it is reported as
    # measured, never inflated to justify a key.
    assert f < KEY_FIDELITY_CUTOFF, (
        f"a distributed route cannot clear the cutoff at this dark-count floor; "
        f"if this now passes ({f}), the model changed and the tests below need revisiting"
    )
    assert payload["qkd_key_hex"] is None or (
        isinstance(payload["qkd_key_hex"], str) and len(payload["qkd_key_hex"]) == 64
    )


def test_import_is_format_agnostic(tmp_path):
    """The same three importers must produce the same routing contract."""
    nodes = [
        {"id": "A", "x_km": 0.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
        {"id": "R0", "x_km": 8.0, "y_km": 0.0, "t1_s": 200, "t2_s": 100, "is_repeater": True},
        {"id": "R1", "x_km": 16.0, "y_km": 0.0, "t1_s": 200, "t2_s": 100, "is_repeater": True},
        {"id": "D", "x_km": 24.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
    ]
    links = [
        {"a": "A", "b": "R0", "length_km": 8.0, "alpha_db_km": 0.2},
        {"a": "R0", "b": "R1", "length_km": 8.0, "alpha_db_km": 0.2},
        {"a": "R1", "b": "D", "length_km": 8.0, "alpha_db_km": 0.2},
    ]
    topologies = {
        "qel-json": {
            "schema_version": "1.0",
            "generated_at": "2026-10-07T00:00:00Z",
            "nodes": nodes,
            "links": links,
        },
        "ghostnet": {
            "generator": "vantablack",
            "exported_at": "2026-01-01T00:00:00Z",
            "nodes": [{"fingerprint": n["id"], "addr": f"10.0.0.{i}:2270"} for i, n in enumerate(nodes)],
            "links": [{"a": l["a"], "b": l["b"]} for l in links],
            "positions": {n["id"]: [n["x_km"], n["y_km"]] for n in nodes},
        },
        "dot": "digraph QEL {\n" + "".join(f"  {n['id']};\n" for n in nodes)
             + "".join(f"  {l['a']} -> {l['b']} [len={l['length_km']}];\n" for l in links) + "}\n",
    }

    payloads = {}
    for schema_id, topo in topologies.items():
        doc = _write_and_parse(topo, schema_id)
        proc = _run_import(doc, "A", "D")
        assert proc.returncode == 0, proc.stderr
        payloads[schema_id] = proc.stdout
        payload = json.loads(proc.stdout)
        assert set(payload) == FIELDS
        assert payload["success"] is True
        assert payload["path"] == ["A", "R0", "R1", "D"]
        assert payload["swap_nodes"] == ["R0", "R1"]
        # Routing + distillation are deterministic in (fidelity, seed), so the
        # same geometry must yield the same key material (or the same "no key")
        # whichever format carried it in.  Byte-identical is the strongest form
        # of that: don't pin None vs hex here, pin equality.
    assert len(set(payloads.values())) == 1, "formats produced divergent routing results"


def test_json_output_route_failure_still_emits_one_json_doc(tmp_path):
    """An unroutable path (unknown fingerprint) still returns a single JSON
    document with success=false -- never a traceback."""
    doc = _write_and_parse(
        {
            "schema_version": "1.0",
            "generated_at": "2026-10-07T00:00:00Z",
            "nodes": [
                {"id": "A", "x_km": 0.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
                {"id": "R0", "x_km": 8.0, "y_km": 0.0, "t1_s": 200, "t2_s": 100, "is_repeater": True},
                {"id": "D", "x_km": 24.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
            ],
            "links": [
                {"a": "A", "b": "R0", "length_km": 8.0, "alpha_db_km": 0.2},
                {"a": "R0", "b": "D", "length_km": 16.0, "alpha_db_km": 0.2},
            ],
        },
        "qel-json",
    )

    proc = _run_import(doc, "A", "D")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["success"] is True
    assert payload["path"] == ["A", "R0", "D"]
    assert payload["swap_nodes"] == ["R0"]

    bad = _run_import(doc, "A", "nope")
    assert bad.returncode != 0
    payload = json.loads(bad.stdout)
    assert payload["success"] is False
    assert payload["path"] == []
    assert payload["qkd_key_hex"] is None


def test_json_output_no_route_meeting_constraint(tmp_path):
    doc = _write_and_parse(
        {
            "schema_version": "1.0",
            "generated_at": "2026-10-07T00:00:00Z",
            "nodes": [
                {"id": "A", "x_km": 0.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
                {"id": "R0", "x_km": 8.0, "y_km": 0.0, "t1_s": 200, "t2_s": 100, "is_repeater": True},
                {"id": "D", "x_km": 24.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
            ],
            "links": [
                {"a": "A", "b": "R0", "length_km": 8.0, "alpha_db_km": 0.2},
                {"a": "R0", "b": "D", "length_km": 16.0, "alpha_db_km": 0.2},
            ],
        },
        "qel-json",
    )
    # Raise the min fidelity above what a 24 km metro link can achieve, so the
    # route is rejected but the CLI still returns JSON with success=false.
    # `doc` is the temp file path returned by _write_and_parse above; the file
    # is already on disk in the qel-json shape.
    proc = _run_import(doc, "A", "D", min_fidelity=0.999999)
    payload = json.loads(proc.stdout)
    assert payload["success"] is False
    assert payload["path"] == []
    assert payload["end_to_end_fidelity"] == 0.0


def test_qkd_derive_emits_one_json_document_with_a_key():
    path = Path(_TMP_DIR.name) / "test_bridge_tmp.json"
    topo = {
        "schema_version": "1.0",
        "generated_at": "2026-10-07T00:00:00Z",
        "nodes": [
            {"id": "A", "x_km": 0.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
            {"id": "D", "x_km": 5.0, "y_km": 0.0, "t1_s": 100, "t2_s": 50, "is_repeater": False},
        ],
        "links": [{"a": "A", "b": "D", "length_km": 5.0, "alpha_db_km": 0.2}],
    }
    path.write_text(json.dumps(topo), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "quantumnet", "qkd-derive",
         "--fidelity", "0.95", "--seed", "0x51EE", "--json-output"],
        capture_output=True, text=True, timeout=120, cwd=str(SRC),
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert set(payload) == FIELDS
    assert payload["success"] is True
    assert payload["path"] == [] and payload["swap_nodes"] == []
    assert payload["end_to_end_fidelity"] == 0.95
    assert isinstance(payload["qkd_key_hex"], str)
    assert len(payload["qkd_key_hex"]) == 64


def test_qkd_derive_is_reproducible_across_processes_and_seed_sensitive():
    """The two-peer agreement rests on this: same parameters, same key.

    Two independent invocations must produce byte-identical material, because
    the daemon derives the same key on both ends and never sends it.  A
    different seed must produce different material, or the seed would not be
    doing anything.
    """
    first = _run_qkd_derive(0.95, 0x51EE)
    second = _run_qkd_derive(0.95, 0x51EE)
    other = _run_qkd_derive(0.95, 0x1234)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert other.returncode == 0, other.stderr
    assert first.stdout == second.stdout
    payload_first = json.loads(first.stdout)
    payload_other = json.loads(other.stdout)
    first_hex, other_hex = payload_first["qkd_key_hex"], payload_other["qkd_key_hex"]
    assert first_hex != other_hex
    assert len(first_hex) == 64 and len(other_hex) == 64


def _run_qkd_derive(fidelity: float, seed: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "quantumnet", "qkd-derive",
         "--fidelity", str(fidelity), "--seed", str(seed), "--json-output"],
        capture_output=True, text=True, timeout=120, cwd=str(SRC),
    )


def test_qkd_derive_below_the_security_cutoff_reports_no_key():
    proc = _run_qkd_derive(0.5, 0x51EE)
    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert set(payload) == FIELDS
    assert payload["success"] is False
    assert payload["qkd_key_hex"] is None


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
