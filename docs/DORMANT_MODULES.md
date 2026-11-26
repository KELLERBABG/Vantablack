# Dormant `research` Modules (`#[cfg(feature = "research")]`)

> **Scope:** This document inventories the **14** modules currently gated behind `#[cfg(feature = "research")]` (referenced in `Cargo.toml`), separates them by implementation readiness, and specifies the **exact daemon/core hooks** for an implementing agent in the `research -> v4.0.0` stage.  
> **Note:** `landauer.rs` and `photonic_orbit.rs` were removed (`a9a3ea2`), and `sdr` (`abos`) / `qkd-tls` (`l10_qel_etsi`) hardware backends were rolled back (`20b7f7d`).

---

## Tier 1 — Ready to Wire (`7` Modules, Pure Software)

Wire these first into the live daemon/product path:

| Module | What It Does | Exact Wiring Target(s) | Formal / Test Anchor |
|---|---|---|---|
| `src/ghost/net/braid_identity.rs` | Hash-chained, transcript-braided key evolution with atomic `fsync` and `400 B` epidemic Clone-Suicide Proofs (`O(ln N)` gossip collision). | `src/ghost/session/ratchet.rs`, `src/daemon/auth.rs`, `src/daemon/peer_loop.rs` (gossip tips in `GHOST_PEX2`), `src/daemon/dtn.rs` | `formal/braid_identity.pv` |
| `src/ghost/v2/erosion.rs` | Threshold ephemerizer (`Chrono-Erosion`) using Ristretto255 + DLEQ + `l8_memsec` zeroize for unconditional post-expiry oblivion. | `src/daemon/dtn.rs`, `src/ghost/net/dead_drop.rs`, `src/ghost/v2/continuum.rs` | `formal/chrono_erosion.pv` |
| `src/ghost/net/dead_drop.rs` | Autonomous encrypted mesh dead-drop & self-eating storage for asynchronous shard handoff. | `src/daemon/dtn.rs`, `src/ghost/net/dtn_reconcile.rs`, `src/ghost/v2/erosion.rs` | `formal/chrono_erosion.pv` |
| `src/ghost/net/entropy_beacon.rs` | Cooperative threshold randomness beacon across mesh peers for epoch/slot unpredictability. | `src/daemon/beacon.rs`, `src/ghost/v2/erosion.rs`, `src/ghost/v2/btcr.rs` | `cargo test --lib --features research entropy_beacon` |
| `src/ghost/net/polysemy.rs` | `Causal Polysemy` — encodes $k$-subset contingency realities into $n$ path shards (`Wi-Fi`, `5G`, etc.) with 0-bit counterfactual leakage. | `src/ghost/v2/hpeb.rs`, `src/daemon/bonding.rs`, `src/ghost/v2/continuum.rs` | `formal/causal_polysemy.pv` |
| `src/ghost/net/mesh_archive.rs` | Unlinkable public archival mirroring of erasure-coded shards across the mesh. | `src/daemon/node.rs`, `src/ghost/net/shardsec.rs`, `src/ghost/net/dead_drop.rs` | `cargo test --lib --features research mesh_archive` |
| `src/ghost/net/bandwidth_voucher.rs` | Lightweight anti-Sybil bandwidth vouchers (note: largely superseded/complemented by `src/ghost/v2/btcr.rs` v2). | `src/ghost/v2/btcr.rs`, `src/ghost/net/relay.rs` | `formal/btcr_v2.pv` |

---

## Tier 2 — Scoped / Needs Calibration (`4` Modules)

Only wire with the explicit scope constraints below:

| Module | What It Does | Blocker / Scope Rule | Target Hook(s) |
|---|---|---|---|
| `src/ghost/net/sharded_compute.rs` (+ `lagrange.rs`) | Private, straggler- & Byzantine-resilient inference (`LC-Vantablack`) over $\mathbb{F}_p$. | **Scope rule:** Only offload linear/quadratic layers ($d \le 2$); keep non-linear activations (`Softmax`/`GELU`) client-side so $N$ stays small. | `src/daemon/node.rs`, `src/ghost/net/sharded_compute/lagrange.rs` |
| `src/ghost/net/sheaf.rs` | Epistemic Sheaf Cohomology ($H^1$ obstruction & Hodge curl) for split-world/eclipse detection. | **Calibration rule:** Avoid raw noisy WAN RTTs unless calibrated; prefer discrete $\mathbb{F}_2^m$ key/cert discrepancy cochains first to avoid false positives. | `src/ghost/v2/xray.rs`, `src/ghost/net/collective_defense.rs` |
| `src/ghost/net/metabolic.rs` | Radioactive half-life authority decay ($W_a(t) \le 1$ per domain). | **Sybil rule:** Must bind domains $a$ to verified ASN/RPKI clusters (not self-declared IDs). | `src/ghost/net/security.rs`, `src/ghost/v2/xray.rs` |
| `src/ghost/net/energy_currency.rs` | Proof-of-Erasure-Repair credit accounting. | **Abuse rule:** Require mutually signed receipts between distinct Sybil-resistant peers (`btcr.rs` / `pow.rs`) to prevent self-repair inflation. | `src/ghost/net/relay.rs`, `src/ghost/v2/btcr.rs` |

---

## Tier 3 — Deferred / External Hardware or Heavy Infrastructure (`3` Modules)

**Do NOT wire into the default `v4.0.0` daemon** unless external hardware/infrastructure is explicitly added:

| Module | What It Does | Why Deferred |
|---|---|---|
| `src/ghost/net/sovereign_cloud.rs` | Relativistic `LightCone-Proof` jurisdiction enforcement. | Software RTT alone only proves `KeyDisjoint`; true `PhysicallyDisjoint` requires non-exportable `hardware-tpm` + $\ge 3$ trusted geographic anchors. |
| `src/ghost/net/model_gossip.rs` | Decentralized behavioral model gossip over mesh metadata. | Vulnerable to Byzantine model poisoning without heavy robust aggregation + Sybil staking. |
| `src/ghost/net/stego_physics.rs` | Theoretical physical-layer covert shard modulation prototype. | Requires real SDR hardware (`abos-hal`) calibration; SDR hardware support was rolled back. |

---

## Agent Verification Checklist

After wiring any Tier 1 or Tier 2 module:
1. `cargo check --lib` and `cargo check --lib --features research`
2. `cargo test --lib --features research`
3. `cargo clippy --all-targets --features research -- -D warnings`
4. If any `.pv` model in `formal/` changed, re-run ProVerif `2.05` (`scripts/formal_verify.sh`) and update `formal/attestations.json` (enforced by `build.rs`).
