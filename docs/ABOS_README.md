# Atmospheric Broadcast OS (ABOS)

A software-defined radio (SDR) operating system written in Rust that enables
**covert, resilient, long-range communication** by exploiting ionospheric
propagation physics. ABOS treats the atmosphere itself as a distributed relay,
memory buffer, and stealth medium.

> **Status:** Build, tests, fmt, and clippy (`-D warnings`) are green across all 13 workspace crates. Every declared crate contains real, tested code (T4 feature-complete).

---

## What it does

ABOS combines **spread-spectrum stealth**, **cognitive radio**,
**delay-tolerant networking (DTN)** and **ionospheric sounding** into one design
for decentralized mesh communication *without routing tables*. It targets
Near-Vertical Incidence Skywave (NVIS) propagation in the 2–10 MHz amateur
band, where signals reflect off the ionosphere almost straight down and reach
beyond line of sight with no fixed infrastructure.

A transmission is split into shards, FEC-encoded, DSSS-spread, stealth-masked
and delivered through DTN store-and-forward with opportunistic scheduling — see
`ABOS_WHITEPAPER.md` for the technical description or open the documentation portal (`docs.html`).

---

## Requirements

- A recent **Rust toolchain** (`cargo`/`rustc`, edition 2021). Verified with
  Rust 1.97 (Windows x86_64).
- Actual RF operation additionally requires SDR hardware (e.g. LimeSDR,
  HackRF, USRP) and — in most jurisdictions — an amateur-radio or experimental
  license for the NVIS/meteor bands. See the legal note in `ABOS_WHITEPAPER.md`.

No system-level radio software (e.g. the on-wire SDR backend) is bundled; the
repo builds and tests fully offline.

---

## Build & test

> This document was moved out of the ABOS source tree into the repository
> `docs/` directory. Every command below is run from the `abos/` subdirectory
> (`cd abos`).

Build the whole workspace (debug and release):

```console
cargo build                      # debug
cargo build --release --workspace
```

Run the full test suite across every crate:

```console
cargo test --workspace
```

Expected result: the workspace compiles with no errors and the tests pass
(**103 unit/integration tests** across the crates, plus doc-tests). See
[Status & known gaps](#status--known-gaps).

Run the static linter (must be warning-free, as enforced by CI):

```console
cargo clippy --workspace --all-targets -- -D warnings
```

Run the formatter check:

```console
cargo fmt --all -- --check
```

---

## Quick start (CLI binary)

The command-line interface is the `abos` binary provided by the `abos-cli`
crate (10 subcommands, clap-derived). After a release build:

```console
cargo run -p abos-cli -- status      # Show loaded configuration
cargo run -p abos-cli -- configure   # Print current config values
cargo run -p abos-cli -- scan        # Scan the spectrum (requires SDR/stub)
cargo run -p abos-cli -- chirp 3 10 0.1  # Chirp-sounder waveform (validated args)
cargo run -p abos-cli -- transmit <file>
cargo run -p abos-cli -- receive
cargo run -p abos-cli -- mesh        # Mesh coordination state (peers/ACKs)
cargo run -p abos-cli -- forward     # Retransmit queue + bundle store stats
```

Configuration lives in `abos_config.json` (created automatically with defaults
if missing). RF subcommands require an actual SDR device and appropriate
licence; the pure-computation commands (`chirp`, `configure`, `status`) run
without hardware.

---

## Workspace layout

| Crate | Role | State |
|---|---|---|
| `abos` (root) | System orchestrator `ABOSSystem` + library | Implemented, tested (5) |
| `abos-hal` | SDR abstraction, DMA, GPIO, GPSDO timer | Implemented (stub drivers; real HW = T5) |
| `abos-dsp` | DDC, AGC, I/Q correction, Costas, Gardner, OFDM, FFT, RRC | Implemented, tested |
| `abos-phy` | DSSS, FHSS, scrambler, burst builder/parser | Implemented, tested (DSSS roundtrip) |
| `abos-fec` | LDPC (systematic H=[A\|I]), BICM interleaver, soft LLR, CRC32 | Implemented, tested (syndrome-verified) |
| `abos-protocol` | Shard split, DTN bundle, buffer-bounce, scheduler, routing, **mesh** | Implemented, tested (10 mesh tests) |
| `abos-cognitive` | Spectrum scanner, jammer detect, white-space, adaptive MCS | Implemented |
| `abos-iono` | Chirp sounder, f0F2, NVIS selection, meteor, MUF | Implemented |
| `abos-stealth` | Cyclostationary masking, phase noise, amp dither, burst rand | Implemented |
| `abos-storage` | Persistent DTN bundle store (TTL/eviction, dedup), config | Implemented, tested (4) |
| `abos-common` | Complex math, PN/Gold codes, AES/HMAC crypto, node ID | Implemented, tested (14) |
| `abos-cli` | clap CLI (`abos` binary, 10 subcommands) | Implemented |
| `abos-gui` | Dashboard: headless `GuiState` + egui view | Implemented, tested (11) |
| `abos-tests` | Loopback channel, e2e/mesh/fault-injection harness | Implemented, tested (27) |

The `abos` binary is produced by the **`abos-cli` crate** (`[[bin]] name =
"abos"`), not the root package.

---

## Status & known gaps

- **Green:** full workspace compiles (`cargo build`, `cargo build --release`),
  `cargo test --workspace` passes (**103 tests** across all crates, including
  the e2e loopback, 3-node mesh and fault-injection suites),
  `cargo fmt --all -- --check` is clean, and
  `cargo clippy --workspace --all-targets -- -D warnings` has zero warnings.
  CI (`.github/workflows/ci.yml`) enforces all four on every push/PR.
- **Implemented (T4):** mesh/Ghost-node coordination (beacons, ACK
  aggregation with exponential backoff, shard-availability tracking, live
  forwarding path), clap CLI with 10 validated subcommands, headless GUI
  state + egui view, bundle store with TTL/eviction and dedup, and the
  `abos-tests` harness (loopback channel, byte-identical e2e roundtrip,
  fault injection).
- **Honest gaps (T5):** SDR hardware drivers are simulation stubs (zero-fill
  reads); live over-the-air behaviour was **not** verified (no radio
  hardware available). No structured logging/metrics yet, and no fuzzing.
- The repository declares **no license file** (all rights reserved by
  default).

---

## Documentation

- `ABOS_WHITEPAPER.md` — complete technical whitepaper covering ionospheric physics, RF chains, crypto, and modulation schemes.
- `docs.html` / [Documentation Hub](https://atmo.kellersystems.dev/docs.html) — interactive single-page technical portal, CLI guide, architecture specifications, and verification matrices.

---

## License & disclaimer

The repository declares no license file. Without an explicit license, all
rights are reserved by default; seek permission from the maintainers before
reuse. Radio operation on NVIS/meteor bands is regulated and generally
requires a licence in most jurisdictions — you are responsible for lawful use.
