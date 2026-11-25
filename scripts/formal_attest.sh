#!/usr/bin/env bash
# Regenerate formal/attestations.json from live ProVerif runs.
#
# `build.rs` refuses to compile when a formal/*.pv file no longer matches the
# committed attestation, so this is the only supported way to change a model:
# run the proofs, record the hashes and the observed RESULT lines, commit both.
#
# Requires ProVerif on PATH (or PROVERIF=/path/to/proverif).
set -euo pipefail
cd "$(dirname "$0")/.."

export PYTHON="${PYTHON:-python3}"
export PROVERIF="${PROVERIF:-proverif}"
"$PYTHON" - <<'PY'
import datetime
import glob
import hashlib
import json
import os
import subprocess

proverif = os.environ["PROVERIF"]
version = "unknown"

# ProVerif has no successful --version flag; it prints its banner on stderr and
# exits 2, which is still enough to record the exact version that ran.
banner = subprocess.run([proverif, "-version"], capture_output=True, text=True)
for line in (banner.stdout + banner.stderr).splitlines():
    if line.startswith("Proverif "):
        version = line.split()[1].rstrip(".")

models = []
for path in sorted(glob.glob("formal/*.pv")):
    run = subprocess.run(
        [proverif, path], capture_output=True, text=True
    )
    output = run.stdout + "\n" + run.stderr
    for line in output.splitlines():
        if line.startswith("Proverif "):
            version = line.split()[1].rstrip(".")
    results = [
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith("RESULT")
    ]
    if not results:
        raise SystemExit(f"{path}: ProVerif produced no RESULT lines")
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    models.append(
        {"file": path, "sha256": digest, "results": results}
    )

attestation = {
    "generated_at": datetime.date.today().isoformat(),
    "proverif": version,
    "models": models,
}
with open("formal/attestations.json.tmp", "w", encoding="utf-8") as fh:
    json.dump(attestation, fh, indent=2)
    fh.write("\n")
os.replace("formal/attestations.json.tmp", "formal/attestations.json")
print(f"wrote formal/attestations.json ({len(models)} models, ProVerif {version})")
PY
