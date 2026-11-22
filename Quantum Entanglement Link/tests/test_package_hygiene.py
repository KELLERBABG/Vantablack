"""The package must be safely importable and introspectable.

This is not a style preference.  ``quantumnet/__main__.py`` used to call
``main()`` at module scope, so importing it parsed ``sys.argv`` and ran the CLI.
Any tool that imports every module to check for breakage -- which is how the
broken ``run_bb84_decoy`` import was found -- would instead execute the CLI.
These tests keep that from coming back.
"""

from __future__ import annotations

import importlib
import pkgutil
import subprocess
import sys

import pytest


def test_importing_main_module_does_not_run_the_cli(capsys):
    """Import must have no output and must not parse argv."""
    sys.modules.pop("quantumnet.__main__", None)
    importlib.import_module("quantumnet.__main__")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_every_module_imports_cleanly():
    """Every module in the package must import without raising.

    A stale name in a package ``__init__`` breaks the package, the CLI, the demo
    and every test module touching them, while a file listing still looks fine.
    """
    import quantumnet

    failures = []
    for info in pkgutil.walk_packages(quantumnet.__path__,
                                      prefix="quantumnet."):
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{info.name}: {type(exc).__name__}: {exc}")
    assert not failures, "modules failed to import:\n" + "\n".join(failures)


def test_audit_script_reports_clean():
    """``scripts/audit_imports.py`` must exit 0 against the current tree."""
    from pathlib import Path

    script = Path(__file__).resolve().parent.parent / "scripts" / "audit_imports.py"
    r = subprocess.run([sys.executable, str(script)],
                       capture_output=True, text=True, timeout=300,
                       cwd=str(script.parent.parent))
    assert r.returncode == 0, f"audit failed:\n{r.stdout}\n{r.stderr}"
    assert "0 failed to import" in r.stdout


def test_cli_help_lists_the_documented_commands():
    """The README's command list must match the CLI's."""
    r = subprocess.run([sys.executable, "-m", "quantumnet", "--help"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0
    for cmd in ("bb84", "e91", "teleport", "superdense", "swap", "shor",
                "steane", "distill", "memory", "all", "stabilizer",
                "physical", "topology", "import", "qkd-derive", "qkd",
                "bench"):
        assert cmd in r.stdout, f"command {cmd!r} missing from CLI help"


@pytest.mark.parametrize("args", [
    ["qkd", "--distance", "50"],
    ["bench", "--start", "0", "--stop", "20", "--step", "20"],
])
def test_new_commands_run(args):
    r = subprocess.run([sys.executable, "-m", "quantumnet", *args],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip()
