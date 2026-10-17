# Future upgrades — what could be added next

**Audience:** contributors and operators planning the next round of work on Vantablack.
**Status of this file:** a planning outline, not a promise. Items below are *possible*
future directions, some of them already hinted at in `ROADMAP.md`, some not. None of them
is scheduled, and several of them touch vendored third-party code whose future is
outside this repository's control.

This file exists so that the repository's "current state" documents (`README.md`,
`docs/SPECIFICATIONS.md`, `docs/OPERATOR_GUIDE.md`, `formal/README.md`) can stay
descriptive of what *is*, while this file holds what *might be*. When an item here
becomes real, move its facts out of here and into the descriptive documents, and leave
a one-line note behind.

---

## 1. Things the current docs already point at

These are not new ideas — they are the open items the existing markdown already
mentions, restated here so they don't get lost. Each one is a candidate for a future
commit that moves it from "documented as open" to "done".

#### 1.1 Packaging and installers
- Per-user Windows installer (`installer/ggn.iss` + `scripts/build_installer.ps1`), Debian `.deb` packaging (`[package.metadata.deb]` in `Cargo.toml` + `packaging/debian/`), and Android APK CI builds (`.github/workflows/release.yml`) are already in-tree.
- Still open from `ROADMAP.md`: Windows Service registration (`windows-service` crate), Authenticode / macOS notarization code-signing, `.rpm` packaging, and Apple Silicon `.dmg` installer.

### 1.2 Self-healing watchdog
- `ROADMAP.md` calls for interface-stall detection and automatic TUN recycling with a
  sub-3-second re-handshake target.
- The current daemon does not implement that; a dead interface is whatever the OS does.

### 1.3 Mobile pairing
- `ROADMAP.md` calls for a 1-click QR pairing flow in the desktop control center.
- The control center already renders a `ggn://pair` QR (that is present today); the
  "1-click" framing in the roadmap is the upgrade: a pairing flow that does not require
  an operator to copy-paste a URI by hand.

### 1.4 Documentation portal and airgap manual
- `ROADMAP.md` calls for a live docs portal and an `docs/AIRGAP_DEPLOYMENT.md`.
- `scripts/build_docs_portal.py` builds `docs/index.html`; `docs/AIRGAP_DEPLOYMENT.md` does not yet exist in-tree.

### 1.5 Research-primitive feature gate
- Landed: the 15 unreachable `ghost::net` modules are gated behind `--features research` (off by default) and verified in CI; see `docs/DORMANT_MODULES.md`.

### 1.6 Formal models
- `formal/README.md` states exactly what the two ProVerif models establish and exactly
  what they do not. The "what is not established" list is the honest inventory of future
  modeling work, if anyone wants to do it. Notably unmodelled: the double ratchet, forward
  secrecy and post-compromise security, key-compromise impersonation, relay/onion/multi-hop
  behaviour, and the wire format.

---

## 2. Vendored third-party code: QEL and ABOS

Vantablack v0.8.11 vendors two external projects:

- **QEL** — the `Quantum Entanglement Link/` directory, a stripped-back snapshot of
  `https://github.com/KELLERBABG/QEL`, used by `src/ghost/layers/l10_qel.rs` as the
  `sim` backend for the L10 quantum anchor.
- **ABOS** — the `abos/` workspace, a copy of `https://github.com/KELLERBABG/ABOS`,
  used (behind the `sdr` cargo feature) by `src/ghost/net/sdr_bridge.rs` as the skywave
  physical layer.

Both are **vendored**, not forked with a live upstream link in-tree, and both are known
to be out of date with their upstream repositories. This section records what that means
for anyone proposing an upgrade.

### 2.1 QEL (`Quantum Entanglement Link/`)

**What v0.8.11 actually uses from it.** The L10 simulated backend talks to the vendored
tree as a Python package: it runs `python -m quantumnet ghost-net ...` and
`python -m quantumnet qkd-derive ...` with `Quantum Entanglement Link/` as the CWD and
`Quantum Entanglement Link/src` prepended to `PYTHONPATH`, and it probes availability by
importing `quantumnet`. That is the entire interface v0.8.11 depends on.

**Measured state of the vendored tree vs upstream.** The vendored tree is a **subset** of
the upstream repo at the time it was dropped in. Upstream ships a much larger surface
(additional protocol/encoding modules, a larger `src/quantumnet/` layout, a larger tests/
tree, and documentation files) that the vendored snapshot does not contain. The vendored
tree keeps the pieces the daemon routes through (`src/quantumnet/{core,protocols,topology}`,
`cli.py`, and the 122-test `tests/` suite) and omits the rest.

**How it loads out-of-the-box.** Because `SimulatedQel` prepends `Quantum Entanglement Link/src`
to `PYTHONPATH` when spawning Python, `import quantumnet` and the CLI subcommands work
directly against the vendored tree whenever Python + `numpy` are installed, without requiring
a separate `pip install -e "Quantum Entanglement Link"`.

**What an upgrade would touch.** Bringing the vendored QEL tree back toward upstream is not a
Vantablack-only change: it is updating vendored third-party code. The parts Vantablack cares
about are narrow (the `quantumnet` package entrypoint, the two CLI commands the anchor runs,
`pyproject.toml`/`poetry.lock`, and whatever the probe's `import quantumnet` resolves). An
upgrade should be checked against at least:

1. Does `import quantumnet` succeed from the vendored tree the way the probe expects?
2. Do `python -m quantumnet ghost-net --json-output` and `python -m quantumnet qkd-derive --json-output`
   still produce the JSON contract `l10_qel.rs` parses (`QuantumRouteResult`)?
3. Does the `qkd-sim/1/...` label contract still round-trip the way `l10_qel.rs::parse_label`
   and the round-trip test expect?

If upstream QEL changed any of those, the Vantablack side (the JSON parsing, the label format,
the seed/fidelity contract, the degraded-logging prose) may also need an update. The current
code documents the simulated-backend limitation honestly in `l10_qel.rs` and in
`docs/SPECIFICATIONS.md` §2.4 (the simulated key is deterministic in `(fidelity, seed)` with a
constant seed, so in a `sim` build the mix contributes epoch agreement, not secrecy). Any
upstream change that alters that contract would need the documentation to follow. The honest
description of what the two anchors actually claim — including the `sim`-only caveat and the
vendored-snapshot state — is in `docs/ANCHORS_CODEBASE_INTEGRATION.md` §1–§2.

### 2.2 ABOS (`abos/`)

**What v0.8.11 actually uses from it.** ABOS is used behind the `sdr` cargo feature, via
`abos::ABOSSystem` in `src/ghost/net/sdr_bridge.rs`. Without that feature (or without SDR
hardware) the bridge runs in synthetic mode. The workspace is compiled as part of the Vantablack
build when the feature is on.

**Measured state of the vendored tree vs upstream.** The vendored `abos/` workspace is a copy
of the upstream ABOS repo that is missing some root-level files the upstream repo carries
(e.g. a `LICENSE` file, `rust-toolchain.toml`, and the HTML index/docs files the upstream repo
serves). The crate layout itself is intact — the 13 workspace crates are present — so the
Vantablack build's ABOS dependency is on the workspace crates, not on the missing root files.

**What an upgrade would touch.** Like QEL, this is updating vendored third-party code. The
Vantablack side depends on `abos::ABOSSystem` and the SDR bridge plumbing. An upgrade should at
minimum confirm that the workspace still compiles with the feature enabled and that the symbols
`sdr_bridge.rs` references still exist. If the upgrade is meant to also bring the repository's
own docs (README, whitepaper, license, toolchain pinning) back in line with upstream, that is a
separate documentation decision for the `abos/` tree, not a Vantablack functional change.

**Honest caveat.** The vendored ABOS tree is a snapshot whose upstream is outside this
repository. If upstream ABOS moves in a way that breaks the `sdr` feature's interface, the
Vantablack `sdr` builds break, and there is no in-tree guarantee that the vendored copy stays
buildable against any particular upstream tip. That is inherent to vendoring.

---

## 3. Possible Vantablack-native additions (no upstream dependency)

These are things that would live entirely in Vantablack code or markdown. They are unordered
and unfunded; they are here as a menu, not a plan.

### 3.1 A single configuration reference
Today the environment-reference story is split: `docs/config.env.example` is the live-ish file
the daemon parses, and `docs/OPERATOR_GUIDE.md` §8 has a table. A dedicated
`docs/CONFIGURATION.md` that is cross-checked against the actual parsed variables (including the
`GHOST_BYPASS_*`, `GHOST_VPN_*`, `GHOST_SKYWAVE_*`, `GHOST_QUANTUM_*`, `GHOST_NO_GUI`,
`GHOST_LOG` family and the per-mode variables) would give operators one place to look. The
risk is staleness: such a file has to be re-verified against `src/` whenever a variable is
added or removed, so it needs an owner or it will drift.

### 3.2 WAN simulation runbook
The 7-node Docker Compose topology and the four scenarios are documented in
`docs/SPECIFICATIONS.md` §8–§9 and `docs/VERIFICATION_AND_BENCHMARKS.md`, but there is no
single `docs/WAN_SIMULATION.md` that is only about reproducing the simulation: exact prerequisites
(Docker, `sch_netem`), exact `docker compose` commands, what to expect in each container's logs,
and how to read the dashboard and the `/api/telemetry` feed. Such a file would be a natural home
for the "how do I run the thing the benchmarks and the spec both point at" question.

### 3.3 Lint and hygiene policy
`ROADMAP.md` and the build docs mention the `-D warnings` clippy gate and the lint-hardening
pass, but there is no dedicated `docs/LINT_POLICY.md` stating what is enforced, what the three
auditable exemptions are, and how to add a new one without weakening the gate. The exemption list
is real (it is enforced by CI), so a document that states it explicitly is more truthful than
leaving it implicit.

### 3.4 Installer and packaging documentation
The README has an "Install on Windows" section and an Inno Setup build note, and
`docs/BUILDING.md` has the compiler/SDK paths, but there is no `docs/INSTALLERS.md` that collects
the installer story (Windows setup, Linux packages, Android APK, Apple Silicon) and the
signing/packaging decisions in one place. That is the natural home for the `ROADMAP.md`
packaging milestone once it starts moving.

### 3.5 ProVerif install/run guidance
`formal/README.md` states how to run the two models and what they establish, but it does not
document how to obtain ProVerif on each platform. `docs/BUILDING.md` gives the Windows download
path for the ProVerif binary; a short note in `formal/README.md` or a cross-reference from it
would keep the formal-model instructions self-contained.

---

## 4. Things to approach carefully

These are not "add this" items; they are "if you touch this, be aware" notes.

- **Do not refreeze the vendored QEL/ABOS snapshots by re-diffing them against a stale upstream
  tip and treating the diff as authoritative.** The vendored trees are snapshots; upstream has
  moved since. Any upgrade needs a real, current upstream checkout and a deliberate choice about
  which upstream state to vendor, not a guess anchored to whatever tip was used the first time.
- **Do not widen the lint exemptions to make a new feature pass.** The three exemptions exist for
  a reason; if a new feature wants one, argue for it explicitly in the commit rather than silently
  enlarging the exception list.
- **Do not let a new configuration variable land without updating at least one of
  `docs/config.env.example` or `docs/OPERATOR_GUIDE.md`, and preferably both.** A variable that
  the daemon parses but no document explains is a future support burden.
- **Do not claim a security property in the descriptive docs that `formal/README.md` does not
  list as a query.** The formal models are the boundary of what "proven" currently means here;
  expanding that boundary means adding a model, not rewriting a paragraph.

---

## 5. How to use this file

- If you are **reviewing** a PR, check whether it silently turns one of the "not landed" items
  above into a claim of completion without the corresponding code or doc change.
- If you are **writing** a new feature, decide whether it belongs in a descriptive document
  (`README.md`, `docs/SPECIFICATIONS.md`, `docs/OPERATOR_GUIDE.md`, `formal/README.md`) or
  whether it is itself a future-looking note that stays here.
- If you are **upgrading vendored QEL or ABOS**, read §2 first, then vendor against a current
  upstream checkout, then update whatever Vantablack contract (JSON, label, probe, bridge symbols)
  the vendor change touches.
