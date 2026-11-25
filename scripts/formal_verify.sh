#!/usr/bin/env bash
# Verify the formal models against the committed attestation, without rewriting
# it. `scripts/formal_attest.sh` is the only supported way to *change* a model;
# this is the CI-side check that the committed attestation still describes the
# bytes in the tree and that ProVerif still produces exactly the attested
# RESULT lines (including the positive reachability witnesses).
#
# Requires ProVerif and python3 on PATH (or PROVERIF=/path/to/proverif).
# Usage: scripts/formal_verify.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PROVERIF="${PROVERIF:-proverif}"

"${PYTHON:-python3}" - <<'PY'
import hashlib
import json
import os
import subprocess
import sys

proverif = os.environ.get("PROVERIF", "proverif")
with open("formal/attestations.json", encoding="utf-8") as fh:
    attestation = json.load(fh)

version = "unknown"
banner = subprocess.run([proverif, "-version"], capture_output=True, text=True)
for line in (banner.stdout + banner.stderr).splitlines():
    if line.startswith("Proverif "):
        version = line.split()[1].rstrip(".")

ok = True
for model in attestation["models"]:
    path = model["file"]
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if digest != model["sha256"]:
        print(f"{path}: HASH MISMATCH — run scripts/formal_attest.sh and commit both")
        ok = False
        continue

    run = subprocess.run([proverif, path], capture_output=True, text=True)
    output = run.stdout + "\n" + run.stderr
    results = [
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith("RESULT")
    ]
    if results == model["results"]:
        print(f"{path}: OK ({len(results)} results)")
        continue

    ok = False
    print(f"{path}: RESULT MISMATCH")
    for attested, live in zip(model["results"], results):
        if attested != live:
            print(f"  attested: {attested}")
            print(f"  live:     {live}")
    if len(results) != len(model["results"]):
        print(f"  {len(model['results'])} attested vs {len(results)} live results")

if not ok:
    sys.exit(1)
print(f"all {len(attestation['models'])} models reproduce the committed attestation (proverif {version})")
PY
