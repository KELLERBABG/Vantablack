# Physical Anchors: Codebase Integration

> **Scope:** Rust modules, the Python bridge, and the protocols that connect them.
> **Status labels:** every anchor here is **experimental**. The default build is
> in-simulation end to end. One production path is now *built* — an ETSI GS QKD 014
> client for a real QKD appliance (§2.4) — but it has been verified only against a
> mock appliance, never against hardware. Nothing in this document describes
> operation against real radio hardware or a real optical QKD appliance.
> **Target subsystems:**
> - **Anchor 1:** `abos/` — Rust SDR / skywave stack, optional `sdr` feature.
> - **Anchor 2:** `Quantum Entanglement Link/` — the `quantumnet` Python engine.
> - **Integration host:** `src/ghost/` — the Vantablack (GGN) daemon.

---

## 1. What is actually wired today

Both anchors are **opt-in**: the default `cargo build` compiles neither the ABOS
path dependency nor any Python invocation, and every surface tells the operator
which mode it is in.

| Capability | Where it lives | State |
|---|---|---|
| Skywave carrier selected as the last fallback rung | `src/ghost/net/fallback.rs` | **Shipped.** `choose_fallback_with_skywave(..)`; skywave is chosen only when the bridge reports an NVIS frequency. |
| ABOS DSP pipeline on that carrier | `src/ghost/net/sdr_bridge.rs` | **Shipped.** Full ABOS chain when built `--features sdr`; synthetic loopback carrier otherwise. |
| Egress/ingress over the carrier | `src/main.rs` | **Shipped.** Three egress arms transmit through `SkywaveBridge::global()`; an ingress drain task feeds received frames back into the node. |
| Quantum anchor controller + capability probe | `src/ghost/layers/l10_qel.rs` | **Shipped.** Two backends, selected at runtime by `GHOST_QEL_BACKEND`; probed once at boot, cached, logged once. |
| `quantumnet ghost-net --json-output` contract | `Quantum Entanglement Link/src/quantumnet/cli.py` | **Shipped.** One JSON document on stdout, diagnostics on stderr. |
| **ETSI GS QKD 014** key-delivery client for a real QKD appliance | `src/ghost/layers/l10_qel_etsi.rs` | **Shipped** (client side). `status`/`enc_keys`/`dec_keys` over HTTP/1.1, mutual TLS behind the `qkd-tls` feature. Verified against a mock appliance; **not** against real hardware. |
| Quantum entropy mixed into a live session's ratchet | `src/ghost/session/mod.rs`, `src/main.rs` | **Shipped.** A maintenance tick obtains a key for each connected peer, contracts it into the next epoch, and both sides advance together — see §5. |
| Control-plane surface for both anchors | `src/control.rs` | **Shipped.** `GET /api/v1/anchors/status`, `POST /api/v1/anchors/qel/route`. |

The honest gaps are named in §8. In particular: the skywave carrier is a
**virtual/synthetic channel** in the default build, ABOS hardware drivers are
simulation stubs, and the *simulated* QEL backend derives keys from a noise model
rather than a photon measurement. The `etsi014` backend is written, tested and
ready for an appliance — but no appliance was available to test it against, so
what is verified is that it speaks the standard's wire format correctly, not that
a particular vendor's appliance answers as the standard says it should.

---

## 2. Anchor 2 — the QEL quantum controller

### 2.1 Shape of the integration

```
                       Vantablack daemon (src/main.rs)
                                  │  GHOST_QUANTUM=1 / --quantum
                                  ▼
              src/ghost/layers/l10_qel.rs :: QuantumAnchorController
    ┌──────────────────────────────────────────────────────────────────┐
    │ backend = "sim" (default)                                        │
    │  1. probe():  python -c "import quantumnet"   (cwd = QEL dir)    │
    │     → QelAnchorState, cached in a OnceLock, logged exactly once  │
    │  2. resolve_topology_path(): absolutize + refuse to spawn if the │
    │     mesh export is missing (no wasted interpreter start-up)      │
    │  3. spawn:  python -m quantumnet ghost-net \                     │
    │              --topology <abs path> --from <fp> --to <fp> \       │
    │              --json-output   (stdin null, 45 s cap, kill_on_drop)│
    │     (the answering peer instead spawns `qkd-derive --fidelity F  │
    │      --seed S`, which needs no topology export — see 5.1)        │
    │  4. parse one JSON document → QuantumRouteResult                 │
    ├──────────────────────────────────────────────────────────────────┤
    │ backend = "etsi014"                                              │
    │  1. probe():  GET  {kme}/{peer_sae}/status                       │
    │  2. acquire:  GET  {kme}/{peer_sae}/enc_keys?number=1&size=256   │
    │     redeem:   POST {kme}/{peer_sae}/dec_keys  {"key_IDs":[…]}    │
    │  → the label is the standard's `key_ID`, and it is the only part  │
    │    that crosses the Vantablack link (see §2.4)                   │
    └──────────────────────────────────────────────────────────────────┘
                                  │  32-byte key + opaque label (or None)
                                  ▼
                  src/ghost/layers/l1_kem.rs :: kdf_rk_quantum_mix
                  src/ghost/session/ratchet.rs :: mix_quantum_entropy
                  src/ghost/session/mod.rs :: begin/answer/finish_quantum_mix
                                  │
                                  ▼
                     src/main.rs :: the live session exchange (§5.1)
```

The controller **fails soft**. `establish_quantum_link` returns a `QelOutcome`
with an `error` string; it never propagates an error to the daemon. A session
without a quantum key is exactly as secure as it was before this layer existed —
the anchor is additive entropy, not a dependency.

### 2.2 The controller

`src/ghost/layers/l10_qel.rs`:

```rust
pub enum QelAnchorState {
    Available,   // keys can be obtained right now
    Degraded,    // present but refusing us: a fixable configuration problem
    Unavailable, // unreachable: there is nothing to fix from this node
    Unprobed,    // only observable before the boot probe finishes
}

/// Which key-delivery backend this node runs. Chosen once, from
/// `GHOST_QEL_BACKEND`, and never substituted afterwards.
pub enum QelBackend {
    Simulated(SimulatedQel),   // "sim" (default) — the vendored Python engine
    Etsi014(Etsi014Client),    // "etsi014"       — a real QKD appliance
    /// "etsi014" was asked for and could not be configured. Held *instead of*
    /// a working backend, never in addition to one: falling back to the
    /// simulator would change what the mixed entropy actually is, silently.
    Misconfigured { reason: String },
}

pub struct QuantumRouteResult {
    pub success: bool,
    pub path: Vec<String>,
    pub end_to_end_fidelity: f64,
    pub swap_nodes: Vec<String>,
    pub qkd_key_hex: Option<String>,
    pub key_fidelity: Option<f64>,
    pub distillation_rounds: u32,
}

impl QuantumAnchorController {
    pub fn from_env() -> Self;                   // the backend the operator asked for
    pub fn backend_name(&self) -> &'static str;   // "simulated" | "etsi014" | "misconfigured"
    pub fn backend_report(&self) -> serde_json::Value; // non-secret, for the control plane

    pub async fn state(&self) -> QelAnchorState; // cached probe result
    pub async fn probe(&self) -> QelAnchorState; // 15 s cap, logs once per outcome

    /// The starting peer. `topology_json_path` is used only by the simulated
    /// backend; the appliance needs no mesh export.
    pub async fn acquire_key(
        &self,
        topology_json_path: &Path,
        our_fp: &str,
        peer_fp: &str,
    ) -> QelOutcome;                             // never returns Err

    /// The answering peer: turn the label the starter signed back into the same
    /// key. On the appliance that is `dec_keys`; on the simulator it is a
    /// derivation at the `(fidelity, seed)` the label names.
    pub async fn redeem_key(&self, peer_fp: &str, label: &str) -> QelOutcome;

    /// Route a quantum path over a topology export. Simulated backend only —
    /// an appliance has no notion of a route, and says so rather than returning
    /// a misleading empty one.
    pub async fn establish_quantum_link(
        &self,
        topology_json_path: &Path,
        from_fp: &str,
        to_fp: &str,
    ) -> QelOutcome;

    pub fn routes_over_topology(&self) -> bool;
}

/// A label is opaque to every layer above the backend: the simulated one writes a
/// versioned `qkd-sim/1/f=…/s=…` derivation label, and an appliance supplies its
/// `key_ID`. Whichever it is, exactly one non-secret string travels.
pub const QEL_KDF_SEED: u64 = 0x51EE;
pub const QEL_SIM_LABEL_PREFIX: &str = "qkd-sim/1";

impl QuantumRouteResult {
    /// The fidelity that *labels the key*: post-distillation where the engine
    /// reports it, the raw route otherwise.
    pub fn key_label_fidelity(&self) -> f64;
}

/// One process-wide controller, installed at boot; `shared_controller()`
/// falls back to a fresh env-derived one for tests and tools.
pub fn install_global_controller(ctrl: Arc<QuantumAnchorController>) -> bool;
pub fn shared_controller() -> Arc<QuantumAnchorController>;
```

Two timeouts bound the simulated backend's interaction, deliberately nested so
the caller always gets an answer: the boot **probe** is capped at 15 s
(`probe()` → `Degraded`), and one **route computation** is capped at 45 s
(`QEL_PROCESS_TIMEOUT`). Both are below the 60 s the control endpoint's own
clients allow, so the endpoint answers even in the worst case — with a degraded
result, never a hang. The appliance backend adds its own pair, and they mean
different things: `GHOST_QKD_TIMEOUT_MS` (default 10 s) bounds a *response* —
which may mean the appliance took the key and lost the answer — while a *connect*
is separately capped (10 s) and classified as unreachable.

The probe result is stored in a `OnceLock`, so the daemon logs the state of a
half-installed anchor **once** and normal mesh operation never re-probes.

### 2.3 The JSON contract (`--json-output`)

`Quantum Entanglement Link/src/quantumnet/cli.py` gained `--json-output` on the
`ghost-net` subcommand with a strict stream discipline:

- **stdout** carries exactly one JSON document and nothing else;
- **stderr** carries every diagnostic (warnings, progress, tracebacks).

```json
{
  "success": true,
  "path": ["<fpA>", "<repeater>", "<fpB>"],
  "end_to_end_fidelity": 0.6286,
  "swap_nodes": ["<repeater>"],
  "key_fidelity": 0.8920,
  "distillation_rounds": 2,
  "qkd_key_hex": "00ff11ee…"
}
```

On the failure path the process still prints a single well-formed document with
`success: false` and exits non-zero; the Rust side treats a non-zero exit as
authoritative and surfaces stderr.

#### What `key_fidelity` does — and does not — determine

Read this before trusting a label to name a *unique* key. It names the
**parameters**, which is what the two peers need (`parse_label` reproduces the
same call on the other side), but on this engine the parameters do not pin the
bytes:

- `qkd-derive` returns **Alice's own seeded sifted bit stream**, and the noise
  level enters only through the QBER gate. Measured: every fidelity from 0.872 up
  to 0.99 yields the **same 32 bytes** for a given seed, while 0.870 and below
  yields none.
- The seed is the constant `QEL_KDF_SEED`, so two simulated sessions mix the
  *same* key.

So in this build the mix contributes **epoch agreement**, not entropy — and the
honest wording is not "structural entropy" but "a constant derivation both sides
can reproduce". This is a property of the vendored simulation (error correction and
privacy amplification are not applied to the returned material), not of the Rust
layer, and `a_route_key_and_the_key_redeemed_from_its_label_are_identical` pins it
so a change cannot pass unnoticed. The **ETSI backend has no such degeneracy**:
there the label is an appliance `key_ID` and each ID names one key.

#### `end_to_end_fidelity` is not `key_fidelity`

The two are different numbers on purpose, and the difference is the whole reason
the anchor can produce entropy at all.

A route's **`end_to_end_fidelity`** is capped by the library's detector
dark-count floor at ≈0.85 — measured at **0.8497 for a 10-metre link**, falling to
0.63 at 10 km. The BB84 security cutoff sits just past **0.87** (checked
directly: 0.870 yields no key, 0.872 does). So a raw route can *never* clear the
cutoff, at any distance, and the honest answer for a route alone would be
`qkd_key_hex: null` always.

**Entanglement distillation is what closes the gap**, and it is the library's
own protocol, not a fitted curve: `_distil_to_key_fidelity` seeds an ensemble of
noisy Bell pairs at the route's fidelity and runs BBSSW rounds
(`run_distillation_round` from `quantumnet.protocols.distillation`) until the
survivors are good enough. Both the ensemble and the rng are seeded, so the
result is reproducible for a given `(fidelity, seed)` — which is what lets one
label identify one key on both peers.

| Link | Route fidelity | Rounds | Key fidelity | Key |
|---|---|---|---|---|
| 10 m | 0.8497 | 1 | 0.9370 | yes |
| 5 km | 0.7266 | 2 | 0.9293 | yes |
| 10 km | 0.6286 | 2 | 0.8920 | yes |
| 100 km | 0.2560 | 5 | 0.9291 | yes |

Distillation costs rate, not fidelity: each round halves the pair count and is
successful with the probability BBSSW implies.

**`qkd_key_hex` is still legitimately `null`** when even distillation cannot
reach the cutoff — a channel too noisy to distil (below the protocol's 0.5 fixed
point), or an export with no routable link at all. That is an honest physics
result, not a bug, and the daemon reports it as a degraded anchor rather than
inventing key material.

`key_fidelity` and `distillation_rounds` are `#[serde(default)]` on the Rust
side, so a document from an engine that predates distillation still parses and
[`QuantumRouteResult::key_label_fidelity`] falls back to the route fidelity.

### 2.4 The second backend — ETSI GS QKD 014

`src/ghost/layers/l10_qel_etsi.rs` talks to a real QKD appliance over the
standardised REST key-delivery API (ETSI GS QKD 014 V1.1.1). It is the same
controller seam, a different source of keys: an appliance that a quantum optical
channel fed, instead of a Python noise model.

| Role | Call | Path |
|---|---|---|
| Master SAE (starts the mix) | `Get key` | `GET  {kme}/{slave_SAE_ID}/enc_keys?number=1&size=256` |
| Master SAE (health) | `Get status` | `GET  {kme}/{slave_SAE_ID}/status` |
| Slave SAE (answers the mix) | `Get key with key IDs` | `POST {kme}/{master_SAE_ID}/dec_keys` |

Both responses share the standard's envelope: `{"keys":[{"key_ID":…,"key":…}]}`
with the key base64-encoded. The **`key_ID` is the label** that travels in the
signed session-mix PDU — which is exactly the notification channel the standard
declares out of scope and leaves to the application. Key material never crosses
the Vantablack link.

Three properties of the API shape the code, and each is a place a naive client
gets it wrong:

- **A `Get key` call consumes the key.** So nothing retries. A timeout is
  reported as *"a key may have been consumed"* rather than as a clean failure,
  because retrying silently burns key material the appliance may never generate
  again at the same rate and orphans the ID the peer is about to redeem.
- **The key size is vendor policy.** The standard only promises it lies between
  `min_key_size` and `max_key_size`, so the delivered material is HKDF'd to the 32
  bytes a session epoch needs, *salt = key ID* — a 128-bit appliance key still
  yields a full epoch key, and the same material under two IDs can never produce
  the same epoch key. A pool that advertises a range excluding
  `GHOST_QKD_KEY_BITS` is reported as `Degraded` with the figures, before a session
  silently never mixes.
- **The path segment is always the *other* party's SAE ID.** A node cannot derive
  its peer's SAE ID from the fingerprint — they are operator-assigned, and the KME
  is configured with them — so an unmapped peer is *reported*, never guessed. A
  guess would at best earn a 400 and at worst address a different peer's pool.

#### Configuration

| Variable | Meaning |
|---|---|
| `GHOST_QEL_BACKEND` | `sim` (default) or `etsi014` |
| `GHOST_QKD_KME_URL` | Base URL of the local KME. Accepts the root, `…/api/v1`, or `…/api/v1/keys`; normalised to the last of those |
| `GHOST_QKD_SAE_ID` | This node's SAE ID (the certificate carries the authoritative identity; this is what the operator calls it) |
| `GHOST_QKD_PEER_SAE_ID` | The peer, for a two-node deployment |
| `GHOST_QKD_SAE_MAP` | Path to `{"<peer fingerprint>": "<peer SAE ID>"}` for deployments with more than one peer |
| `GHOST_QKD_CA_PEM` | PEM bundle of the CA that signed the KME's certificate |
| `GHOST_QKD_CLIENT_CERT` / `GHOST_QKD_CLIENT_KEY` | The mTLS client identity — both or neither |
| `GHOST_QKD_KEY_BITS` | Key size to request (default 256, the smallest every implementation supports) |
| `GHOST_QKD_TIMEOUT_MS` | Per-request response timeout (default 10 s) |
| `GHOST_QKD_INSECURE` | Lab escape hatch: accept any server certificate. Warned about at connect, and reported in the control plane |

The standard makes mutual TLS mandatory. So the client implements it — private
CA or the platform trust store, TLS 1.2+, the `ring` provider — behind the
optional `qkd-tls` feature, and **refuses an `https://` URL in a build without
it** rather than falling back to plaintext. Quietly sending key material in the
clear would be the worst possible failure mode for this layer, so it is a
compile-time choice with a loud runtime error, not a silent downgrade.

```bash
ghost-QKD site A                          ghost-QKD site B
GHOST_QEL_BACKEND=etsi014                 GHOST_QEL_BACKEND=etsi014
GHOST_QKD_KME_URL=https://kme-a:8443      GHOST_QKD_KME_URL=https://kme-b:8443
GHOST_QKD_SAE_ID=sae-a                    GHOST_QKD_SAE_ID=sae-b
GHOST_QKD_PEER_SAE_ID=sae-b               GHOST_QKD_PEER_SAE_ID=sae-a
GHOST_QKD_CA_PEM=…/kme-ca.pem             GHOST_QKD_CA_PEM=…/kme-ca.pem
GHOST_QKD_CLIENT_CERT=…/sae-a.pem         GHOST_QKD_CLIENT_CERT=…/sae-b.pem
GHOST_QKD_CLIENT_KEY=…/sae-a.key          GHOST_QKD_CLIENT_KEY=…/sae-b.key
```

Each KME is local to its SAE (that is the deployment shape the standard assumes,
and the reason the two nodes each hold their own appliance); the `downstream`
link ID that the two appliances negotiated is what makes `enc_keys` on one side
and `dec_keys` on the other name the same key. Both nodes must also agree on
`GHOST_QKD_KEY_BITS` only insofar as their pools allow it — the derivation is
over whatever material arrives, with the key ID as the salt.

**Verified:** the request/response shapes, the two-role exchange end to end, the
chunked framing a gateway adds, TLS against a private CA, a certificate from an
untrusted CA being refused, mTLS, the insecure-flag path, the empty-pool and
unknown-ID refusals, and the timeout's *"may have been consumed"* wording — all
against a mock appliance (`tests/qkd_etsi014_kme.rs`, 18 tests). **Not verified:**
any real appliance. There was none available, and a mock is not a substitute for
one — vendor-specific quirks live exactly in the places a standard leaves open.

---

## 3. Anchor 1 — the in-memory ABOS radio carrier

### 3.1 Making a `!Send` subsystem live in an async daemon

`abos::ABOSSystem` holds `dyn SDRDevice` handles and `ThreadRng`-backed stealth
injectors, so it is **`!Send`** and cannot be held across an `.await`. The bridge
therefore confines it to a **dedicated DSP actor thread**: the actor owns the
`ABOSSystem`, the public `SkywaveBridge` is `Send + Sync`, and the two
communicate over a channel. When the `sdr` feature is off, no actor is started
and the bridge reports itself as synthetic.

```toml
// Cargo.toml — the default build is unaffected
[dependencies]
abos = { path = "abos", optional = true }

[features]
sdr = ["dep:abos"]
```

### 3.2 The bridge surface

`src/ghost/net/sdr_bridge.rs`:

```rust
pub const SKYWAVE_UDP_ENV: &str = "GHOST_SKYWAVE_UDP";

pub struct SkywaveTelemetry {
    pub carrier_freq_hz: u64,
    pub estimated_f0f2_hz: f64,
    pub dsss_processing_gain_db: f64,
    pub tx_packet_count: u64,
    pub rx_packet_count: u64,
    pub tx_dsp_bytes: u64,
    pub meteor_burst_window_open: bool,
    pub sdr_active: bool,
    pub virtual_carrier: Option<SocketAddr>,
    pub virtual_carrier_peer: Option<SocketAddr>,
}

impl SkywaveBridge {
    pub async fn with_virtual_carrier(bind_carrier: bool) -> Result<Self, SdrBridgeError>;
    pub fn install_global(self: &Arc<Self>) -> bool;
    pub fn global() -> Option<&'static Arc<SkywaveBridge>>;

    pub fn activate_synthetic(&self, carrier_freq_hz: u64);
    pub async fn start_virtual_carrier(&self);

    pub fn is_active(&self) -> bool;
    pub fn nvis_freq_khz(&self) -> Option<u32>;   // the ladder's gate
    pub fn telemetry(&self) -> SkywaveTelemetry;

    pub async fn transmit(&self, data: &[u8]) -> Result<(), SdrBridgeError>;
    pub async fn process_and_send(&self, payload: &[u8]) -> Result<Vec<u8>, SdrBridgeError>;

    pub fn rx_from_carrier(&self, data: &[u8]);
    pub fn try_rx(&self) -> Vec<Vec<u8>>;
    pub fn has_inbound(&self) -> bool;
    pub fn update_iono_metrics(&self, f0f2_hz: f64, meteor_active: bool);
}
```

`process_and_send` drives the full ABOS chain when the DSP actor is available —
bundle → LDPC FEC → DSSS/OFDM modulation → I/Q — and falls back to the synthetic
framing path otherwise. Its output is what crosses the virtual carrier.

### 3.3 The virtual carrier

Because no radio hardware is assumed, transmission needs a channel the bridge
can actually write to. `start_virtual_carrier()` binds a UDP socket:

| `GHOST_SKYWAVE_UDP` | Behaviour |
|---|---|
| unset | bind `127.0.0.1:0` (loopback, ephemeral) — the default, and the only mode in tests |
| `<addr:port>` | bind that address and loop frames back to itself |
| `<bind>\|<peer>` | bind `<bind>`, ship frames to `<peer>` — the two-node case |

The carrier is **loopback-only unless an operator explicitly overrides it**: a
misconfigured or hostile environment cannot silently turn the daemon into an
open reflector. `ship_to_carrier()` writes to the self-loop target and
`ship_to_peer(addr)` to the configured peer; inbound datagrams are queued and
drained by the daemon's ingress task.

### 3.4 The ladder

`src/ghost/net/fallback.rs` owns the ordering, and skywave is deliberately last:

```rust
pub enum FallbackPath {
    Direct,
    MeshRelay { relay_fp: String, relay_addr: SocketAddr },
    Turn { peer_relayed: SocketAddr },
    Skywave { nvis_freq_khz: u32 },
}

pub fn choose_fallback_with_skywave(
    our_fp: &str,
    target_fp: &str,
    relay_candidates: &[(String, SocketAddr)],
    turn: Option<SocketAddr>,
    skywave: Option<u32>,
) -> Option<FallbackPath>;
```

Direct → mesh relay (WAN candidates before LAN ones) → TURN → **skywave**. The
`skywave` argument is `Some(nvis_freq_khz)` only when the bridge is active, which
is why an unconfigured daemon can never select a rung it cannot carry traffic
on. `choose_fallback()` is the same ladder with `None` for callers that operate
no bridge.

Skywave is last because it is slow (100 bps – 12 kbps) and half-duplex: it beats
silence, and anything faster beats it.

#### Declaring a peer radio-only (`GHOST_SKYWAVE_ONLY`)

The ladder is walked by *failure*: a peer reaches a fallback rung only after a
real ICE check has failed. That is the right default, and it is the wrong answer
for the operator who already knows the peer has no usable IP path — an RF-only
site, a severed inter-domain route, a link that must not be used. Waiting for a
check to fail costs the check budget and, worse, a check that *succeeds* clears
the route again.

`GHOST_SKYWAVE_ONLY=<fp>[,<fp>...]` is that operator's declaration. It is
resolved **through the same ladder**, with the terrestrial rungs withheld
(`&[]` relay candidates, no TURN allocation):

```rust
fallback::choose_fallback_with_skywave(our_fp, peer_fp, &[], None, nvis_freq_khz)
```

so it can only ever *pre-empt* the ladder's answer, never record a route the
ladder would not itself have chosen. From that point the peer is never checked
and its route is never cleared — the declaration outranks a measurement, because
the reason for it does not go away when a candidate pair happens to answer.

A declaration that cannot be honoured changes nothing and says so: an entry that
is not a 16-digit fingerprint is reported rather than ignored (a typo that
pinned nothing would leave the operator believing the peer is on the radio), and
naming a peer when the carrier is not armed logs `no route pinned` instead of
recording a route that has no transport. Watch the boot log for
`GHOST_SKYWAVE_ONLY: peer pinned to the skywave carrier`.

This is the switch `tests/skywave_fallback_e2e.rs` uses to put *direct, mesh
relay and TURN* out of action and prove a frame crosses the radio rung anyway
(§9). It is a declaration, not a physical cut: the same declaration is what a
real deployment uses, and the test's assertion is that the carrier's own
counters moved — cover traffic rides the mesh socket directly and cannot move
them.

---

## 4. End-to-end flow inside the daemon

```
GHOST_SKYWAVE=1 ──► SkywaveBridge::with_virtual_carrier(true)
                    ├── install_global()          (one process-wide bridge)
                    ├── activate_synthetic(5_350_000)   // no `sdr` feature
                    └── spawn ingress-drain task  → node receive path

GHOST_QUANTUM=1 ───► QuantumAnchorController::autodetect()
                    └── install_global_controller(...)
```

Egress sites in `src/main.rs` consult `SkywaveBridge::global()`: a failed NAT
punch records a fallback path via `choose_fallback_with_skywave(..)`, and the
shard, VPN and ratchet egress arms hand their bytes to the bridge when the
selected path is `Skywave`. Inbound frames are pulled with `try_rx()` by the
drain task and re-injected exactly like mesh datagrams.

---

## 5. Quantum entropy in the ratchet — the real KDF

The ratchet is **HKDF-SHA256**, not BLAKE3 (BLAKE3 is not a dependency of this
crate). The mixing primitive is domain-separated from every other KDF use:

`src/ghost/layers/l1_kem.rs`:

```rust
/// Domain-separated from every other KDF use, so a quantum key can never stand
/// in for a ratchet root or an epoch key.
pub const RATCHET_QUANTUM_MIX_INFO: &[u8] = b"GHOST_NET_RATCHET_QEL_ENTROPY_v1";

/// Returns (next_root_key, chain_initiator_to_responder, chain_responder_to_initiator),
/// the same shape as `kdf_rk_hybrid`, so the caller reseeds the chains exactly
/// as a DH step would.
pub fn kdf_rk_quantum_mix(
    root_key: &[u8; 32],
    quantum_key: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]);
```

`src/ghost/session/ratchet.rs`:

```rust
impl SessionRatchet {
    /// Both peers must call this with the same key in the same epoch, or their
    /// chains diverge. Returns the new epoch number.
    pub fn mix_quantum_entropy(&mut self, quantum_key: &[u8; 32]) -> u64;
}
```

The mix retires the current epoch (retained in the normal grace window, so
in-flight frames still open), reseeds **both** directional chains, and bumps the
epoch counter. It is one-way: the output reveals nothing about the quantum key,
and the quantum key alone recovers nothing without the prior root.

**Honest status:** this *is* called from the live session path. `mix_quantum_entropy`
is the derivation underneath the session-level exchange described next.

### 5.1 The live exchange

A session's next epoch is contracted from quantum entropy without either peer
sending a key. The two halves live next to the DH ratchet step they mirror, and
use the same prepared-epoch machinery — which is why the answering side can open
an epoch it has not installed.

```
  starter (lower fingerprint)                      answerer
  ───────────────────────────                      ────────
  quantum_mix_maintenance_once()
    refresh mesh export (from measured ranges)   [sim backend only]
    acquire_key(topology, lo → hi)
      sim    → route, distil, key, label "qkd-sim/1/f=…/s=…"
      etsi   → GET  {kme}/{peer_sae}/enc_keys, label = key_ID
    session.begin_quantum_mix(key, label)
      → prepares epoch n+1, tag = HMAC(key)
    seal PDU on epoch n ──────────────────────────►  handle_qel_mix_pdu()
                                                      verify signature (pinned id)
                                                      admit (crossed-mix tie-break)
                                                      redeem_key(label)
                                                      → the same key, by label
                                                      answer_quantum_mix(...)
                                                      → tag must match, else refuse
                                  ◄────────────── seal answer on epoch n
    verify signature
    finish_quantum_mix(epoch, tag)
      → epoch n+1 installed
                                                     activate n+1 when the first
                                                     frame in it authenticates
```

Why each piece is the way it is:

- **A tag proves agreement before either side moves.** `ratchet_confirm` over the
  new epoch key travels in both PDUs; a mismatch abandons the mix with the live
  epoch untouched. Without it, two peers deriving different keys would each
  install epoch `n+1` — the same generation number over different keys, after
  which nothing on the link opens and no later exchange can repair it.
- **One driver per session, chosen from public data.** The peer whose fingerprint
  sorts lower starts the mix and the other answers, exactly the tie-break
  `admit_peer_step` uses. The answering side therefore needs no route and no
  topology export — it fetches at the label the starter signed.
- **The answering peer resolves the label, not its own view of the mesh.** The two
  nodes' exports legitimately differ (each knows its own links), so re-routing
  locally would put them on different keys and refuse a mix that should have
  completed. On the appliance backend this is not an accommodation at all — it is
  the standard's own model: both ends of a real QKD link fetch the same key by ID.
- **Nothing secret crosses the wire.** The PDU carries the epoch, the **label** and
  the tag; the key is never sent, because the source of the key (the quantum
  channel, or the model that stands in for one) is what made the two sides agree.
  A `qkd-sim/1/…` label names a derivation, an appliance `key_ID` names a key pool
  entry, and the session layer treats both as opaque strings it must agree on.
- **A mix and a DH step are mutually exclusive.** Both consume the
  prepared-epoch slot and both advance the generation, so `begin_quantum_mix`
  refuses while `ratchet_in_progress`, and `begin_ratchet_step` refuses while
  `quantum_mix_in_progress`.
- **The attempt is throttled** (`QUANTUM_MIX_RETRY`, 60 s) because it can cost a
  python subprocess, and **bounded** (`QUANTUM_MIX_STALL`, 90 s) so an unanswered
  mix cannot hold the slot forever.

For the export to be routable at all, each link must carry a length: the quantum
layer derives a link's attenuation from its physical extent, and a link with no
length is not an optical link, so it is skipped. `mesh_topology_json` emits
`length_km` from the contact plan's measured `range_km` — the same round-trip
measurement the DTN router routes on — and emits **no number at all** for a peer
it has not timed, rather than fabricating one.

Tests: `a_quantum_mix_advances_both_sides_to_one_epoch`,
`the_responder_can_be_the_one_that_starts_the_mix`,
`divergent_quantum_keys_refuse_the_mix_and_move_nothing`,
`a_mix_pdu_signed_by_a_stranger_never_reaches_the_derivation` (byte path), plus
`a_mix_and_a_dh_step_are_mutually_exclusive`,
`a_crossed_mix_is_resolved_by_the_fingerprint_order`,
`the_mix_attempt_is_throttled_by_the_retry_interval` and
`an_unanswered_mix_stalls_without_touching_the_epoch` (session level).

---

## 6. Control plane and CLI

### 6.1 Runtime flags

`src/cli.rs` matches argv directly (it is not clap-based) and translates the
flags into the environment variables `run_node` reads:

```
--skywave    →  GHOST_SKYWAVE=1   (ABOS skywave fallback carrier)
--quantum    →  GHOST_QUANTUM=1   (QEL quantum anchor)
```

Both are also settable directly as environment variables. `ggn sdr-status`
prints the carrier band and current skywave interface state.

### 6.2 HTTP API (default port **2270**, `GHOST_WEB_PORT`)

`GET /api/v1/anchors/status` — real shape:

```json
{
  "abos_skywave": {
    "status": "online",
    "synthetic": true,
    "carrier_freq_hz": 5350000,
    "estimated_f0f2_hz": 0.0,
    "dsss_processing_gain_db": 0.0,
    "tx_packets": 0,
    "rx_packets": 0,
    "tx_dsp_bytes": 0,
    "meteor_burst_window_open": false,
    "virtual_carrier": "127.0.0.1:54123",
    "virtual_carrier_peer": null
  },
  "qel_quantum": {
    "status": "available",
    "last_route": null,
    "backend": {
      "name": "etsi014",
      "engine": "ETSI GS QKD 014 key delivery",
      "kme_url": "https://kme.site-a.example:8443/api/v1/keys",
      "sae_id": "sae-a",
      "key_bits": 256,
      "request_timeout_ms": 10000,
      "tls": true,
      "client_certificate": "/etc/ggn/sae-a.pem",
      "peer_sae_map": 0,
      "two_node_default": true,
      "certificate_verification": "custom CA bundle",
      "last_status": {
        "stored_key_count": 25000,
        "key_size": 256,
        "min_key_size": 64,
        "max_key_size": 1024,
        "source_KME_ID": "kme-a",
        "target_KME_ID": "kme-b"
      }
    },
    "routes_over_topology": false,
    "note": "experimental — see docs/ANCHORS_CODEBASE_INTEGRATION.md §8 for what is and is not claimed"
  }
}
```

`backend` is **not secret-bearing**: an operator-facing status document fetched
over loopback HTTP is not the place for key material or a token, and the report is
pinned by a test that asserts neither appears. `certificate_verification` is
surfaced rather than merely logged, so a node running with
`GHOST_QKD_INSECURE=1` cannot hide it from whoever is looking at the control
plane. `routes_over_topology` is `false` on the appliance backend, and the route
endpoint then explains why `POST /api/v1/anchors/qel/route` has nothing to compute
rather than returning an empty path.

`synthetic` is `true` whenever the build has no `sdr` feature, so the surface
never implies hardware it does not have. When the bridge was never installed,
`abos_skywave` degrades to `{"status": "offline"}`.

`POST /api/v1/anchors/qel/route` — body `{"from": "<fingerprint>", "to":
"<fingerprint>"}`. Like every mutation on this server it is PIN-gated
(`X-Pin`). It runs a real route computation through the shared controller and
answers (on the `etsi014` backend there is no route to compute, so it answers
`200` with `success: false` and the reason — not a 5xx):

- `200` with `{"anchor_state", "success", "route", "key_derived", "error"}` —
  including when the computation degrades (`success: false`, an `error` string);
- `400` when the body is not the required JSON object.

Bad input is rejected before any work happens, and an unavailable anchor never
produces a 5xx.

---

## 7. Production successors

The seams above are chosen so that real hardware drops in without changing the
layers around them. One of the two is now built; the other is not.

- **Skywave — not built.** The bridge's `ABOSSystem` slot is where a real
  `SDRDevice` driver goes (LimeSDR/HackRF/USRP); the ladder, telemetry and egress
  paths do not change.
- **QEL — built, appliance side.** `src/ghost/layers/l10_qel_etsi.rs` is the
  ETSI GS QKD 014 client (§2.4), selected with `GHOST_QEL_BACKEND=etsi014`. The
  layer above it did not move: `acquire_key`/`redeem_key` still return a 32-byte
  key and an opaque label, and `mix_quantum_entropy` is untouched. What remains is
  the part only hardware can settle — a real appliance, its vendor's quirks, and
  the private CA and client certificates an operator issues for it.

The skywave successor is not implemented, and no part of this repository was
verified against real radio hardware. The QKD half was verified against a mock
appliance implementing the standard's wire format — which is a statement about
this client, not about any vendor's appliance.

---

## 8. What is deliberately *not* claimed

### The simulated backend (the default)

- QEL derives keys from a **simulated** noise model. It is not a physical photon
  measurement, and no quantum channel exists between peers.
- Consequently, the session mix adds **no entropy at all** in this build, and it
  is worth stating that plainly rather than softening it to "structural entropy".
  The label that names the key travels in the signed PDU, so both peers — and
  anyone who had already broken the session — can derive it; and because the
  simulation returns the same bytes for every fidelity above the cutoff under a
  constant seed (§2.3), every simulated session mixes the *same* key. What the
  exchange still guarantees, and what every test asserts, is that the two sides
  agree on one key and move to the same epoch together. It is not a claim that the
  key is unknown to a third party.

### The appliance backend

- The `etsi014` backend speaks the standard's wire format correctly, and that is
  all that has been shown. **No real QKD appliance was available to test against.**
  A mock is the only honest way to test a client for an appliance you do not have,
  and it cannot tell you how a specific vendor's implementation deviates from the
  standard in the places the standard leaves open. Treat the first connection to a
  real KME as a commissioning exercise, not as a regression.
- Even with a working appliance, the key is secret only to the extent that the
  quantum channel and the appliance are. Vantablack contributes the *transport* of
  a public key ID and the mixing of the delivered material; it verifies nothing
  about the photons, and there is no way for it to.
- The simulated and appliance backends make **different** claims about the entropy
  a session mixes in, which is why selecting one is final: a misconfigured
  `etsi014` node reports `degraded` and a reason and keeps its classical epochs. It
  never quietly becomes the simulator.

### Both backends

- The anchors are **additive and optional**: with `GHOST_SKYWAVE` and
  `GHOST_QUANTUM` unset, behaviour is exactly what it was before. A session with no
  quantum key is exactly as secure as it was before this layer existed.
- The skywave carrier moves bytes through a **virtual loopback UDP channel** in
  the default build. It is not transmitting on any radio band.
- `GHOST_SKYWAVE_ONLY` puts the three terrestrial rungs out of action by
  *declaration*, not by cutting the IP path. A pinned peer's frames take the
  radio rung; the same processes still hold a mesh socket that could reach each
  other, which is why the end-to-end test asserts on the carrier's own counters
  and the per-shard routing line rather than on delivery alone.
- ABOS's SDR drivers are simulation stubs (zero-fill reads). No over-the-air
  behaviour has been verified.

---

## 9. Verification commands

```bash
# Anchor 1 — ladder ordering + virtual carrier (default build)
cargo test --no-default-features --test p1_relay skywave
cargo test --no-default-features --test test_skywave_carrier

# Both anchors — two live daemons, a real session, and a chat frame that
# crosses the skywave rung with direct/relay/TURN all out of action (~13 s)
cargo test --test skywave_fallback_e2e -- --nocapture

# Anchor 1 — the real ABOS DSP dependency compiles behind the feature
cargo check --no-default-features --features sdr

# Anchor 2 — simulated backend: controller unit tests (the live subprocess
# test is #[ignore]d)
cargo test --no-default-features --lib l10_qel
cargo test --no-default-features --lib l10_qel -- --ignored

# Anchor 2 — ETSI GS QKD 014 client against the mock appliance (plaintext: 12 tests)
cargo test --no-default-features --test qkd_etsi014_kme

# Anchor 2 — the same, plus TLS, mTLS and certificate-refusal (18 tests)
cargo test --no-default-features --features qkd-tls --test qkd_etsi014_kme

# Both anchors — control-plane surface end to end
cargo test --no-default-features --test control_center_api test_anchors_api_surface

# Anchor 2 — the JSON contract the Rust side parses
cd "Quantum Entanglement Link" && pytest tests/test_protocols/test_bridge_json.py -v

# Manual: both anchors on, then read the status surface
GHOST_NO_GUI=1 GHOST_SKYWAVE=1 GHOST_QUANTUM=1 ./target/debug/vantablack.exe
curl -s http://127.0.0.1:2270/api/v1/anchors/status

# Manual: the appliance backend against a live KME (site A)
GHOST_NO_GUI=1 GHOST_QUANTUM=1 \
  GHOST_QEL_BACKEND=etsi014 \
  GHOST_QKD_KME_URL=https://kme.site-a.example:8443 \
  GHOST_QKD_SAE_ID=sae-a GHOST_QKD_PEER_SAE_ID=sae-b \
  GHOST_QKD_CA_PEM=/etc/ggn/kme-ca.pem \
  GHOST_QKD_CLIENT_CERT=/etc/ggn/sae-a.pem \
  GHOST_QKD_CLIENT_KEY=/etc/ggn/sae-a.key \
  ./target/debug/vantablack.exe
curl -s http://127.0.0.1:2270/api/v1/anchors/status | jq .qel_quantum.backend
```

The QEL route endpoint needs a mesh export to route over. Produce one with the
daemon's `EXPORTTOPOLOGY` command; without it the endpoint answers immediately
with `success: false` and `"no mesh topology export at <path>"`. The appliance
backend does not route at all, so that endpoint reports `success: false` with an
explanation there — session mixes are unaffected, because they call
`enc_keys`/`dec_keys` instead.

A build without `qkd-tls` is complete except for TLS: selecting `etsi014` against
an `https://` KME in such a build is refused outright, and the reason says to
rebuild with the feature.
