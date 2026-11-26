# Vantablack `v3.0.0` Agent Execution Pipeline

> Master index and staged build pipeline taking `[OS] Vantablack` from `v2.1.8` to `v3.0.0`. Every stage links the exact specification, proof, audit, and source files an autonomous agent needs.

---

## 0. Mandatory Versioning & Verification Rules

Every agent executing any step of this pipeline **must** obey these release rules:

1. **Milestone / Feature Updates (`v2.x.0`):**
   - Every completed milestone or feature addition **must** bump the minor version to `v2.x.0` (e.g., `2.2.0`, `2.3.0`, `2.4.0`, …) in [`Cargo.toml`](../Cargo.toml) and record a dated entry in [`CHANGELOG.md`](../CHANGELOG.md) before moving to the next milestone.
2. **Bugfixes During Any Mission (`v2.0.x` / patch bump):**
   - Every bugfix discovered or resolved *during* a mission **must** be tracked as a patch increment (`v2.0.x` on the `2.0` line, or `v2.<minor>.x` on the active milestone branch) in [`Cargo.toml`](../Cargo.toml) and [`CHANGELOG.md`](../CHANGELOG.md) with root cause and verification output.
3. **Verification Gate (Required Before Every Bump):**
   - `cargo test --no-fail-fast` (relevant unit/integration suites + full lib suite)
   - `cargo clippy --all-targets -- -D warnings` (zero warnings)
   - `proverif` on all `formal/*.pv` models whenever protocol/formal files are touched.
4. **No Policy Echoes / No Vacuous Proofs:**
   - Never fabricate `State::Verified` from configuration flags, and never accept a ProVerif model without a verified positive reachability witness.

---

## 1. Master Reference Index

### 1.1 Strategy, Audits, Proofs & Inventions (`DEV/`)
| Document | Purpose in Pipeline |
|---|---|
| [`DEV/EPISTEMIC_MANIFESTO.md`](EPISTEMIC_MANIFESTO.md) | Core identity, 3 axioms, Non-Newtonian / Point-Blindness framing |
| [`DEV/EPISTEMIC_AUDIT_V2.md`](EPISTEMIC_AUDIT_V2.md) | Verified `v2.1.8` flaws + Theorem 1 (Multipath bound) + NVIS physics bound |
| [`DEV/EPISTEMIC_HARDENING.md`](EPISTEMIC_HARDENING.md) | Immediate surgical fix specs for `BTCr`, ProVerif, `HPEB`, `X-Ray`, `Chronos`, `RACS`, NVIS |
| [`DEV/INVENTIONS_AND_PROOFS.md`](INVENTIONS_AND_PROOFS.md) | Inventions 1–11 & Theorems 2–11 (Ramp Bonding, `BTCr v2`, $N_{\text{eff}}$, `LightCone-Proof`, `Subliminal Tail`, `Chrono-Erosion`, `Causal-Hop`, `RF-CRKG`, `LC-Vantablack`, `Proof-Carrying Claim Graph`) |
| [`DEV/UNPRECEDENTED_PRIMITIVES.md`](UNPRECEDENTED_PRIMITIVES.md) | Experimental frontier primitives & prior-art audit (`Causal Polysemy`, `Braid-Locked Identity`, `Metabolic Crypto`, `Sheaf Cohomology`, `Blind Census`, `Photonic Secret Orbit`) |
| [`DEV/ANCHORS_CODEBASE_INTEGRATION.md`](ANCHORS_CODEBASE_INTEGRATION.md) | Honest status & contracts of L10 QEL (`sim`/`etsi014`) and `abos/` SDR bridge |
| [`DEV/VERIFICATION_AND_BENCHMARKS.md`](VERIFICATION_AND_BENCHMARKS.md) | Verification harness and benchmark methodology |
| [`DEV/ROADMAP.md`](ROADMAP.md) | Remaining optional/external release items (code signing, airgap docs) |
| [`DEV/future_upgrades.md`](future_upgrades.md) | Historical audit baseline and long-term backlog |
| [`DEV/FREE_SOFTWARE.md`](FREE_SOFTWARE.md) | Open-source licensing & ethos |

### 1.2 Architecture, Specs & Formal Models
- [`README.md`](../README.md), [`Cargo.toml`](../Cargo.toml), [`CHANGELOG.md`](../CHANGELOG.md), [`build.rs`](../build.rs)
- [`docs/SPECIFICATIONS.md`](../docs/SPECIFICATIONS.md), [`docs/SOTA.md`](../docs/SOTA.md), [`docs/EXPERIMENTAL_FEATURES.md`](../docs/EXPERIMENTAL_FEATURES.md)
- [`formal/README.md`](../formal/README.md), [`formal/ghost_session.pv`](../formal/ghost_session.pv), [`formal/session_ratchet.pv`](../formal/session_ratchet.pv), [`formal/ghost_circuit_unlinkability.pv`](../formal/ghost_circuit_unlinkability.pv), [`formal/shardsec_space_time.pv`](../formal/shardsec_space_time.pv)

### 1.3 Core Source & Physical Subsystems
- **v2 Everyday & Epistemic Core:** `src/ghost/v2/{btcr.rs, api.rs, xray.rs, regime.rs, hpeb.rs, chronos.rs, racs.rs, continuum.rs, portal.rs, expose.rs, party.rs, fleet.rs, vbdns.rs, front.rs, masque.rs, boomerang.rs}`
- **Crypto & Erasure Layers:** `src/ghost/layers/{l0_identity.rs, l1_kem.rs, l2_aead.rs, l3_shamir.rs, l4_rs.rs, l8_memsec.rs, l10_qel.rs, l10_qel_etsi.rs}`
- **Mesh, Routing & Research:** `src/ghost/net/{mod.rs, shardsec.rs, sovereign_cloud.rs, sharded_compute.rs, sdr_bridge.rs}`
- **Daemon, Control & UI:** `src/main.rs`, `src/control.rs`, `src/socks.rs`, `src/cli.rs`, `assets/wan_dashboard.html`
- **ABOS HF/NVIS:** `abos/WHITEPAPER.md`, `abos/abos-hal/src/sdr.rs`, `abos/abos-iono/src/sounder.rs`, `abos/abos-fec/src/ldpc.rs`

---

## 2. Staged Pipeline (`v2.1.8` $\to$ `v3.0.0`)

### Stage 1 (`v2.2.0`) — Cryptographic & Formal Credibility
**Goal:** Eliminate every broken security claim and vacuous proof before public scrutiny.
- **Read:** `DEV/EPISTEMIC_AUDIT_V2.md` (§3–§4), `DEV/EPISTEMIC_HARDENING.md` (§1–§2), `DEV/INVENTIONS_AND_PROOFS.md` (Invention 2).
- **Edit:**
  - `src/ghost/v2/btcr.rs`, `src/ghost/v2/api.rs` — private root key from `identity.key`, quantized `(day, tier)` bucket keys, and spent-receipt nullifier set.
  - `formal/ghost_session.pv`, `formal/session_ratchet.pv`, `formal/ghost_circuit_unlinkability.pv`, `formal/README.md` — DH commutativity, fixed PQ encapsulation, `origin_id` usage, and mandatory positive reachability witnesses.
- **Gate:** `cargo test --lib btcr`, `proverif` passing all models + positive reachability witnesses, `cargo clippy --all-targets -- -D warnings`.

### Stage 2 (`v2.3.0`) — Honest Multipath (`HPEB` + Vandermonde Ramp Bonding)
**Goal:** Enforce Theorem 1 ($m \ge c + f + 1$) and unify L3 Shamir + L4 RS into $(c, r, f)$ Ramp Bonding.
- **Read:** `DEV/EPISTEMIC_AUDIT_V2.md` (§2), `DEV/EPISTEMIC_HARDENING.md` (§3), `DEV/INVENTIONS_AND_PROOFS.md` (Invention 1).
- **Edit:** `src/ghost/v2/hpeb.rs`, `src/ghost/layers/l4_rs.rs`, `src/ghost/layers/l3_shamir.rs`.
- **Gate:** Explicit 2-path Confidentiality (`2-of-2 XOR`) vs. Availability (`1-of-2`) modes + $m \ge 3$ Vandermonde Ramp unit/property tests passing.

### Stage 3 (`v2.4.0`) — Epistemic Truth Ledger (`X-Ray` + $N_{\text{eff}}$ + `Proof-Carrying Claim Graph`)
**Goal:** Make it a compile-time/runtime impossibility for `api.rs` or the UI to fabricate `Verified` claims.
- **Read:** `DEV/EPISTEMIC_AUDIT_V2.md` (§1), `DEV/EPISTEMIC_HARDENING.md` (§4.1), `DEV/INVENTIONS_AND_PROOFS.md` (Inventions 3 & 11).
- **Edit:** `src/ghost/v2/xray.rs`, `src/ghost/v2/api.rs`, `src/ghost/v2/regime.rs`, `src/daemon/`, `build.rs`.
- **Gate:** `WireWitness<P>` type-level gating, live 3-hop signed echo witnesses, measured TX cover counters, and Rényi-2 $N_{\text{eff}}$ ASN/domain clustering tested in `xray` and `api`.

### Stage 4 (`v2.5.0`) — Traffic & Clock Physics (`Shaped-RACS`, `Horizon-Chronos`, Narrowband NVIS)
**Goal:** Close timing/burst-end side channels and align ABOS NVIS specs with wave physics.
- **Read:** `DEV/EPISTEMIC_AUDIT_V2.md` (§5–§6), `DEV/EPISTEMIC_HARDENING.md` (§4.2–§4.4), `DEV/INVENTIONS_AND_PROOFS.md` (Invention 4).
- **Edit:** `src/ghost/v2/chronos.rs`, `src/ghost/v2/racs.rs`, `abos/WHITEPAPER.md`, gated strictly to `Ghost`/`Vantablack` regimes so `Fast`/`Shielded` latency stays unharmed.
- **Gate:** `chronos` and `racs` tests + regime isolation verified.

### Stage 5 (`v2.6.0`) — Adoption Engine (2,500-Node UX & Viral Everyday Surfaces)
**Goal:** Turn CLI power tools into effortless 1-click desktop/mobile workflows for zero-friction onboarding.
- **Read:** `DEV/ROADMAP.md`, `DEV/future_upgrades.md`, `assets/wan_dashboard.html`.
- **Edit:** `assets/wan_dashboard.html`, `src/control.rs`, `src/socks.rs`, `src/cli.rs`, `src/ghost/v2/{portal.rs, expose.rs, party.rs, fleet.rs, vbdns.rs}`, `packaging/`.
- **Deliverables:** 1-click TUN/DNS, 1-click `Drop` / `Expose` / `Party` room codes, opt-in AC-powered `Blind Relay` toggle feeding `BTCr v2`, signed installers (`winget` / `brew` / `.deb` / APK), and 1-line `--relay-only` Docker container.

### Stage 6 (`v2.7.0`) — Physical & Coercion-Resistant Hardening (`LightCone-Proof`, `Subliminal Tail`, `Blind Census`)
**Goal:** Ship zero-IP population proofs (`X / 200` community unlock), relativistic jurisdiction verification, and coercion-proof dual-plane framing.
- **Read:** `DEV/INVENTIONS_AND_PROOFS.md` (Inventions 5, 6, 8, 9), `DEV/UNPRECEDENTED_PRIMITIVES.md` (§5).
- **Edit:** `src/ghost/net/sovereign_cloud.rs`, `src/ghost/net/mod.rs`, `src/ghost/layers/l2_aead.rs`, `src/ghost/layers/l10_qel.rs`, `src/ghost/v2/xray.rs`.

### Stage 7 (`v3.0.0`) — Full Epistemic Mesh Release
**Goal:** Unify all verified subsystems into `vantablack v3.0.0` (with optional research tracks `Causal Polysemy`, `Chrono-Erosion`, `Epistemic Sheaf Cohomology`, and `LC-Vantablack` cleanly gated or promoted once benchmarked).
- **Read:** `DEV/INVENTIONS_AND_PROOFS.md` (Inventions 7 & 10), `DEV/UNPRECEDENTED_PRIMITIVES.md` (§1–§4, §6–§7).
- **Release Gate:** Full E2E multi-NAT & multi-hop suite, non-vacuous ProVerif CI pass, reproducible build hashes, signed packages, and `X-Ray` live truth ledger clean.
