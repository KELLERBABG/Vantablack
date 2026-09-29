//! L10 — Quantum Entropy Anchor (QEL) controller
//!
//! Couples Vantablack sessions with **key material from a quantum channel** so a
//! session's ratchet epochs are not solely a function of the classical handshake.
//! Two backends implement that, selected at runtime:
//!
//! | Backend | `GHOST_QEL_BACKEND` | Where the key comes from |
//! |---|---|---|
//! | [`SimulatedQel`] | `sim` (default) | the vendored Python `Quantum Entanglement Link/` stack: route over a mesh export, distil, simulate BB84 |
//! | [`Etsi014Client`] | `etsi014` | a **real QKD appliance** over the ETSI GS QKD 014 REST key-delivery API |
//!
//! Both produce the same thing a session needs — 32 bytes and a **label** that
//! names them — and the label is the only part that travels. The starting peer
//! obtains a key and tells the other side its label inside the signed session-mix
//! PDU; the answering peer turns that label back into the *same* key. Key material
//! never crosses the Vantablack link.
//!
//! ```text
//!                     Vantablack daemon (src/main.rs)
//!                                │  GHOST_QUANTUM=1 / --quantum
//!                                ▼
//!            src/ghost/layers/l10_qel.rs :: QuantumAnchorController
//!   ┌────────────────────────────────────────────────────────────────────┐
//!   │ backend = sim      : python -m quantumnet ghost-net | qkd-derive   │
//!   │ backend = etsi014  : GET  {kme}/{peer_sae}/enc_keys                │
//!   │                      POST {kme}/{peer_sae}/dec_keys                │
//!   └────────────────────────────────────────────────────────────────────┘
//!                                │  (32-byte key, opaque label)
//!                                ▼
//!                   src/ghost/session/mod.rs :: the epoch mix
//!                   src/main.rs            :: the live exchange (§5.1 of the
//!                                             anchors integration doc)
//! ```
//!
//! # Fail soft, but never silently *upgrade* a claim
//!
//! Every failure here is a degraded answer, never a daemon error: a session
//! without a quantum key is exactly as secure as it was before this layer existed.
//! The one thing the controller will not do is substitute one backend for another.
//! An operator who selected `etsi014` and misconfigured it gets an anchor that
//! reports `degraded` and a reason — never a quiet fall back to the simulator,
//! because the two make different security claims and only one of them is true of
//! the entropy a session then mixes in.
//!
//! # The honest difference between the backends
//!
//! The simulated backend derives its key from the same noise model the route was
//! computed under, and the *label* fully determines the key — so in a `sim` build
//! the mix contributes structural entropy and epoch agreement, not secrecy. The
//! ETSI backend asks an appliance that was fed by a quantum channel, so the key is
//! something neither peer chose. See `docs/ANCHORS_CODEBASE_INTEGRATION.md` §8 for
//! what is and is not claimed.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::ghost::layers::l10_qel_etsi::{
    Etsi014Client, Etsi014Config, Etsi014Error, EtsiStatus, ENV_BACKEND,
};

/// How long a route computation may run before it is abandoned. Must stay
/// below any caller's own deadline (the control endpoint's client gives up at
/// 60 s), so the endpoint always answers — worst case with a degraded result.
const QEL_PROCESS_TIMEOUT: Duration = Duration::from_secs(45);

/// The derivation seed the simulated backend pins for a session mix.
///
/// A constant (rather than a per-session nonce) is what lets one label name one
/// key: the simulated channel is reproducible, so `(fidelity, seed)` determines
/// the material. It costs nothing — the secret is the quantum channel's
/// contribution, not the seed. A production deployment uses the `etsi014` backend
/// instead, where the label is the appliance's key ID.
pub const QEL_KDF_SEED: u64 = 0x51EE;

/// Version tag on a simulated key label.
///
/// Present so a label from one algorithm can never be silently reinterpreted by
/// another: the answering peer refuses a label it does not understand rather than
/// deriving the wrong key from it.
pub const QEL_SIM_LABEL_PREFIX: &str = "qkd-sim/1";

/// The process-wide controller, installed once at boot so the whole daemon
/// shares one probe result (and one subprocess code path).
static CONTROLLER: OnceLock<Arc<QuantumAnchorController>> = OnceLock::new();

/// Install the process-wide controller (daemon boot). Returns `false` if one
/// was already installed.
pub fn install_global_controller(ctrl: Arc<QuantumAnchorController>) -> bool {
    CONTROLLER.set(ctrl).is_ok()
}

/// The shared controller, or a fresh env-derived one when boot never installed
/// one (tests, tools).
pub fn shared_controller() -> Arc<QuantumAnchorController> {
    CONTROLLER
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(QuantumAnchorController::from_env()))
}

/// The backend name an operator selected, for logs and the control plane.
pub fn selected_backend_name() -> String {
    std::env::var(ENV_BACKEND).unwrap_or_else(|_| "sim".to_string())
}

/// The JSON contract of `quantumnet ghost-net --json-output`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRouteResult {
    pub success: bool,
    pub path: Vec<String>,
    /// The route's fidelity as distributed: what the swapping chain achieved.
    pub end_to_end_fidelity: f64,
    pub swap_nodes: Vec<String>,
    pub qkd_key_hex: Option<String>,
    /// The fidelity the key was derived at, *after* entanglement distillation,
    /// and how many rounds that took.
    ///
    /// This is the label the session mix pins — not [`Self::end_to_end_fidelity`] —
    /// because it is the number that identifies which key material the channel
    /// produced. The distinction is not cosmetic: a route's fidelity is capped by
    /// the dark-count floor at ~0.85, below the BB84 cutoff, so routing alone can
    /// never yield a key and the distilled figure is always the one that matters.
    ///
    /// `None` on a document from an older engine, in which case the route
    /// fidelity stands in.
    #[serde(default)]
    pub key_fidelity: Option<f64>,
    #[serde(default)]
    pub distillation_rounds: u32,
}

impl QuantumRouteResult {
    /// The fidelity that labels the key: post-distillation where the engine
    /// reports it, the raw route otherwise.
    pub fn key_label_fidelity(&self) -> f64 {
        self.key_fidelity.unwrap_or(self.end_to_end_fidelity)
    }
}

/// Whether the anchor can run on this machine, probed once at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QelAnchorState {
    /// The backend's runtime is usable: keys may be obtained.
    Available = 0,
    /// A runtime exists but is not usable — the quantumnet package is missing, or
    /// the appliance answered an error rather than nothing: operator action needed.
    Degraded = 1,
    /// The backend's transport is unreachable, or there is no usable runtime at
    /// all. Nothing the session can do about it.
    Unavailable = 2,
    /// The probe has not completed yet (only observable before boot finishes).
    Unprobed = 3,
}

impl QelAnchorState {
    pub fn as_str(&self) -> &'static str {
        match self {
            QelAnchorState::Available => "available",
            QelAnchorState::Degraded => "degraded",
            QelAnchorState::Unavailable => "unavailable",
            QelAnchorState::Unprobed => "unprobed",
        }
    }
}

/// Outcome of acquiring or redeeming key material, including anchor bookkeeping.
#[derive(Debug, Clone, Serialize)]
pub struct QelOutcome {
    pub anchor_state: QelAnchorState,
    /// The route that produced the key, on the simulated backend. `None` when the
    /// backend does not route (ETSI 014 delivers by key ID).
    pub route: Option<QuantumRouteResult>,
    pub key: Option<[u8; 32]>,
    /// The opaque label naming this key. Travels in the signed session-mix PDU;
    /// never key material.
    pub label: Option<String>,
    pub error: Option<String>,
}

impl QelOutcome {
    /// A degraded outcome: no key, a reason, and the anchor's own state.
    pub fn degraded(state: QelAnchorState, error: impl Into<String>) -> Self {
        Self {
            anchor_state: state,
            route: None,
            key: None,
            label: None,
            error: Some(error.into()),
        }
    }
}

// ── The simulated backend ───────────────────────────────────────────────────

/// The vendored `Quantum Entanglement Link/` stack, driven as a subprocess.
pub struct SimulatedQel {
    qel_dir: PathBuf,
    python_bin: String,
}

impl Default for SimulatedQel {
    fn default() -> Self {
        Self::autodetect()
    }
}

impl SimulatedQel {
    /// Backend pointed at the vendored QEL directory.
    pub fn new<P: AsRef<Path>>(qel_dir: P) -> Self {
        Self {
            qel_dir: qel_dir.as_ref().to_path_buf(),
            python_bin: "python".to_string(),
        }
    }

    /// Locate the QEL directory relative to the running binary / CWD.
    pub fn autodetect() -> Self {
        Self::new(PathBuf::from("Quantum Entanglement Link"))
    }

    pub fn dir(&self) -> &Path {
        &self.qel_dir
    }

    /// The label naming the key derived at `(fidelity, seed)`.
    ///
    /// The parameters travel **verbatim**, as their raw bits: the label is what the
    /// answering peer derives from, so both ends must read back the same `f64` and
    /// the same `u64`, never two values that are merely close.
    ///
    /// # What this label names, and what it does not
    ///
    /// It identifies the derivation *parameters*, which is the contract the two
    /// peers need — `parse_label` reproduces the same call on the other side, and
    /// that is the whole requirement. It does **not** identify the resulting bytes
    /// uniquely, and the difference is worth knowing rather than assuming.
    ///
    /// Measured against this engine: `qkd-derive` returns Alice's own seeded sifted
    /// bit stream, with the noise level entering only through the QBER gate. So
    /// **every fidelity above the ~0.87 cutoff yields the same 32 bytes for a given
    /// seed** — and [`QEL_KDF_SEED`] is a constant. Two simulated sessions therefore
    /// mix the *same* key. That is a property of the simulation, not of this file,
    /// and it is why the simulated mix is documented as epoch agreement rather than
    /// as a source of secrecy (`a_route_key_and_the_key_redeemed_from_its_label_are_
    /// identical` pins it). A real appliance has no such degeneracy: there the label
    /// is a `key_ID`, and each ID names one key.
    pub fn label(fidelity: f64, seed: u64) -> String {
        format!(
            "{QEL_SIM_LABEL_PREFIX}/f={:016x}/s={:016x}",
            fidelity.to_bits(),
            seed
        )
    }

    /// Parse a label back into the parameters it names.
    ///
    /// Refuses anything this build did not write: an unrecognised label is an
    /// answerable "no", where guessing would derive the wrong key and move one
    /// side's epoch alone.
    pub fn parse_label(label: &str) -> Result<(f64, u64), String> {
        let mut parts = label.split('/');
        let (prefix, version) = (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        );
        let expected = QEL_SIM_LABEL_PREFIX.split('/').collect::<Vec<_>>();
        if prefix != expected[0] {
            return Err(format!(
                "key label {label:?} was not produced by this backend (expected {QEL_SIM_LABEL_PREFIX})"
            ));
        }
        if version != expected[1] {
            return Err(format!(
                "key label version {version:?} is not supported (this build writes {})",
                expected[1]
            ));
        }
        let fidelity_hex = parts
            .next()
            .and_then(|p| p.strip_prefix("f="))
            .ok_or_else(|| format!("key label {label:?} has no fidelity field"))?;
        let seed_hex = parts
            .next()
            .and_then(|p| p.strip_prefix("s="))
            .ok_or_else(|| format!("key label {label:?} has no seed field"))?;
        if parts.next().is_some() {
            return Err(format!("key label {label:?} has trailing fields"));
        }
        let fidelity_bits = u64::from_str_radix(fidelity_hex, 16)
            .map_err(|e| format!("key label {label:?} fidelity is not hex: {e}"))?;
        let seed = u64::from_str_radix(seed_hex, 16)
            .map_err(|e| format!("key label {label:?} seed is not hex: {e}"))?;
        let fidelity = f64::from_bits(fidelity_bits);
        if !fidelity.is_finite() || !(0.0..=1.0).contains(&fidelity) {
            return Err(format!(
                "key label {label:?} names fidelity {fidelity}, which is not in 0..=1"
            ));
        }
        Ok((fidelity, seed))
    }

    async fn probe(&self) -> QelAnchorState {
        // Cold python start can take seconds under load; the probe must never
        // wedge a caller for longer than this.
        match tokio::time::timeout(Duration::from_secs(15), self.run_probe()).await {
            Ok(s) => s,
            Err(_) => {
                warn!(
                    dir = %self.qel_dir.display(),
                    "qel: probe timed out after 15s — anchor degraded (not logged again)"
                );
                QelAnchorState::Degraded
            }
        }
    }

    async fn run_probe(&self) -> QelAnchorState {
        let output = match Command::new(&self.python_bin)
            .args(["-c", "import quantumnet"])
            .current_dir(&self.qel_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                debug!(error = %e, "qel: probe could not spawn python");
                return QelAnchorState::Unavailable;
            }
        };
        if !output.status.success() {
            return QelAnchorState::Degraded;
        }
        QelAnchorState::Available
    }

    /// Route over a live mesh export, distil, and derive the key material.
    ///
    /// Returns a degraded [`QelOutcome`] — never an error to the caller — when the
    /// runtime is unavailable or the computation fails.
    async fn establish_quantum_link(
        &self,
        state: QelAnchorState,
        topology_json_path: &Path,
        from_fp: &str,
        to_fp: &str,
    ) -> QelOutcome {
        if state != QelAnchorState::Available {
            return QelOutcome::degraded(
                state,
                format!("qel anchor is {state:?}; enable it by installing the quantumnet package"),
            );
        }
        info!(
            from = from_fp,
            to = to_fp,
            "qel: computing quantum entanglement route over live mesh"
        );

        // The subprocess runs with the QEL directory as its CWD, so a relative
        // topology path (resolved against the daemon's CWD) would break. Make
        // it absolute against *this* process's CWD first, and preflight it:
        // without a mesh topology export there is nothing to route over, and
        // spawning python would only produce a traceback after a full
        // interpreter start-up. Answer immediately instead.
        let topo_abs = match Self::resolve_topology_path(topology_json_path) {
            Ok(p) => p,
            Err(e) => return QelOutcome::degraded(state, e),
        };

        let args: Vec<String> = [
            "-m",
            "quantumnet",
            "ghost-net",
            "--topology",
            &topo_abs.to_string_lossy(),
            "--from",
            from_fp,
            "--to",
            to_fp,
            "--json-output",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let result = match self.run_json(state, args, "route").await {
            Ok(r) => r,
            Err(degraded) => return degraded,
        };
        if !result.success {
            return QelOutcome {
                anchor_state: state,
                route: Some(result),
                key: None,
                label: None,
                error: Some("no fidelity-constrained route between the given peers".to_string()),
            };
        }
        let key = result
            .qkd_key_hex
            .as_deref()
            .and_then(|hex| Self::parse_quantum_key(hex).ok());
        // Both figures, because the gap between them is the interesting part: a
        // route is always below the cutoff, and the key only exists because
        // distillation moved it above.
        info!(
            route_fidelity = result.end_to_end_fidelity,
            key_fidelity = result.key_label_fidelity(),
            distillation_rounds = result.distillation_rounds,
            key = key.is_some(),
            "qel: quantum route established"
        );
        let label = key
            .is_some()
            .then(|| Self::label(result.key_label_fidelity(), QEL_KDF_SEED));
        QelOutcome {
            anchor_state: state,
            route: Some(result),
            key,
            label,
            error: None,
        }
    }

    /// Fetch the key material at an explicit `(fidelity, seed)` label — the
    /// **answering** side of a session quantum mix.
    ///
    /// Both ends of a real QKD link fetch the *same* key by an identifier, not by
    /// re-deriving it: the quantum channel is what made them agree, and the
    /// appliance hands each end the material under a key ID. The simulated
    /// equivalent is this call: the label travels in the signed mix PDU and the
    /// answering peer derives from it instead of from its own view of the mesh.
    /// That matters because the two nodes' topology exports legitimately differ —
    /// each knows its own links — so re-routing locally would put the two sides on
    /// different keys and refuse a mix that should have completed.
    ///
    /// No topology export is needed on this path, so a node can answer a mix with
    /// nothing but the anchor installed.
    async fn derive_key_at(&self, state: QelAnchorState, fidelity: f64, seed: u64) -> QelOutcome {
        if state != QelAnchorState::Available {
            return QelOutcome::degraded(
                state,
                format!("qel anchor is {state:?}; enable it by installing the quantumnet package"),
            );
        }
        if !fidelity.is_finite() || !(0.0..=1.0).contains(&fidelity) {
            return QelOutcome::degraded(
                state,
                format!("refusing to derive at fidelity {fidelity}"),
            );
        }
        // Derived from the *bits* the starter sent, so the two ends are provably
        // asking for the same key: rust's float Display round-trips exactly and
        // python parses the nearest f64 back to the identical value. Formatting
        // with a fixed precision instead would silently move the key.
        let args: Vec<String> = [
            "-m",
            "quantumnet",
            "qkd-derive",
            "--fidelity",
            &format!("{fidelity}"),
            "--seed",
            &seed.to_string(),
            "--json-output",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let doc = match self.run_json(state, args, "key fetch").await {
            Ok(d) => d,
            Err(degraded) => return degraded,
        };
        let key = doc
            .qkd_key_hex
            .as_deref()
            .and_then(|hex| Self::parse_quantum_key(hex).ok());
        info!(
            fidelity,
            seed,
            key = key.is_some(),
            "qel: key material fetched at label"
        );
        QelOutcome {
            anchor_state: state,
            // No route was walked on this path, and saying otherwise would put a
            // bogus entry in the control plane's `last_route`.
            route: None,
            key,
            label: Some(Self::label(fidelity, seed)),
            error: if key.is_none() {
                Some(
                    "no key at that fidelity (QBER at or above the 11% security cutoff)"
                        .to_string(),
                )
            } else {
                None
            },
        }
    }

    /// Run one `quantumnet … --json-output` invocation and parse the single JSON
    /// document on its stdout.
    ///
    /// Every failure comes back as a degraded [`QelOutcome`] carrying the reason,
    /// so a caller only has to decide what a *successful* document means. Note
    /// the deliberate asymmetry with an error return: the anchor is additive, so
    /// "could not compute" is a result the session acts on, not an error it
    /// propagates.
    async fn run_json(
        &self,
        state: QelAnchorState,
        args: Vec<String>,
        what: &str,
    ) -> Result<QuantumRouteResult, QelOutcome> {
        let started = std::time::Instant::now();
        let output = match tokio::time::timeout(QEL_PROCESS_TIMEOUT, async {
            let child = Command::new(&self.python_bin)
                .args(&args)
                .current_dir(&self.qel_dir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            debug!(pid = ?child.id(), what, "qel: quantumnet subprocess spawned");
            let out = child.wait_with_output().await;
            // A slow child is the one interesting datum when an operator
            // reports the anchor "hanging": log the round trip either way.
            debug!(
                what,
                elapsed_ms = started.elapsed().as_millis() as u64,
                status = ?out.as_ref().ok().and_then(|o| o.status.code()),
                stdout = out.as_ref().map(|o| o.stdout.len()).unwrap_or(0),
                stderr = out.as_ref().map(|o| o.stderr.len()).unwrap_or(0),
                "qel: quantumnet subprocess reaped"
            );
            out
        })
        .await
        {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Err(QelOutcome::degraded(
                    state,
                    format!("failed to spawn quantumnet process: {e}"),
                ))
            }
            Err(_) => {
                // kill_on_drop reaps the timed-out python on scope exit.
                return Err(QelOutcome::degraded(
                    state,
                    format!(
                        "quantumnet {what} timed out after {}s",
                        QEL_PROCESS_TIMEOUT.as_secs()
                    ),
                ));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // The failure JSON on stdout still parses (contract), but treat a
            // nonzero exit as authoritative.
            if let Ok(doc) = serde_json::from_str::<QuantumRouteResult>(stdout.trim()) {
                if !doc.success {
                    // Prefer the engine's own diagnostics, but do not *depend* on
                    // them: `qkd-derive` refuses a sub-cutoff fidelity with a
                    // machine-readable document and **no** stderr, so reporting
                    // stderr alone would hand an operator `"no key fetch: "` and
                    // nothing else. The document always carries the figure that
                    // explains the refusal, so fall back to it.
                    let reason = if stderr.is_empty() {
                        format!(
                            "the engine produced no key at fidelity {:.4}{}",
                            doc.key_label_fidelity(),
                            if doc.distillation_rounds > 0 {
                                format!(" after {} distillation round(s)", doc.distillation_rounds)
                            } else {
                                String::new()
                            }
                        )
                    } else {
                        stderr
                    };
                    return Err(QelOutcome::degraded(state, format!("no {what}: {reason}")));
                }
            }
            return Err(QelOutcome::degraded(
                state,
                format!("quantumnet {what} execution failed: {stderr}"),
            ));
        }

        match serde_json::from_str(stdout.trim()) {
            Ok(r) => Ok(r),
            Err(e) => Err(QelOutcome::degraded(
                state,
                format!("failed to parse quantumnet {what} JSON output: {e} (raw: {stdout})"),
            )),
        }
    }

    /// Absolutize the topology export path (the subprocess runs with a
    /// different CWD) and refuse to spawn python when it is missing.
    fn resolve_topology_path(topology_json_path: &Path) -> Result<PathBuf, String> {
        let abs = if topology_json_path.is_absolute() {
            topology_json_path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(topology_json_path)
        };
        if !abs.is_file() {
            return Err(format!(
                "no mesh topology export at {} — run EXPORTTOPOLOGY on the node first",
                abs.display()
            ));
        }
        Ok(abs)
    }

    /// Extract a 32-byte quantum symmetric key from the BB84 hex payload.
    pub fn parse_quantum_key(hex_str: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| e.to_string())?;
        if bytes.len() < 32 {
            return Err(format!(
                "quantum key length must be at least 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        Ok(key)
    }
}

// ── The controller ──────────────────────────────────────────────────────────

/// Which key-delivery backend the anchor runs on.
enum QelBackend {
    Simulated(SimulatedQel),
    Etsi014(Etsi014Client),
    /// The operator selected a backend that could not be configured. Held
    /// *instead of* a working backend, never in addition to one: falling back to
    /// the simulator after a misconfigured `etsi014` would change what the mixed
    /// entropy actually is without anyone being told.
    Misconfigured {
        reason: String,
    },
}

/// The L10 anchor controller. Cheap to clone; the probe result is shared.
pub struct QuantumAnchorController {
    backend: QelBackend,
    state: AtomicU8,
    probed: OnceLock<QelAnchorState>,
    /// The most recent appliance status, for the control plane.
    last_status: parking_lot::Mutex<Option<EtsiStatus>>,
}

impl Default for QuantumAnchorController {
    fn default() -> Self {
        Self::from_env()
    }
}

impl QuantumAnchorController {
    /// Build the controller the operator asked for, from the environment.
    pub fn from_env() -> Self {
        let backend = match selected_backend_name().trim().to_ascii_lowercase().as_str() {
            "" | "sim" | "simulated" | "quantumnet" => {
                QelBackend::Simulated(SimulatedQel::autodetect())
            }
            "etsi014" | "etsi" | "qkd014" => match Etsi014Config::from_env() {
                Ok(cfg) => QelBackend::Etsi014(Etsi014Client::new(cfg)),
                Err(e) => QelBackend::Misconfigured {
                    reason: e.to_string(),
                },
            },
            other => QelBackend::Misconfigured {
                reason: format!(
                    "{ENV_BACKEND}={other:?} is not a backend this build knows \
                     (expected \"sim\" or \"etsi014\")"
                ),
            },
        };
        Self {
            backend,
            state: AtomicU8::new(QelAnchorState::Unprobed as u8),
            probed: OnceLock::new(),
            last_status: parking_lot::Mutex::new(None),
        }
    }

    /// A controller on the simulated backend pointed at `qel_dir` (tests, tools).
    pub fn new<P: AsRef<Path>>(qel_dir: P) -> Self {
        Self {
            backend: QelBackend::Simulated(SimulatedQel::new(qel_dir)),
            state: AtomicU8::new(QelAnchorState::Unprobed as u8),
            probed: OnceLock::new(),
            last_status: parking_lot::Mutex::new(None),
        }
    }

    /// A controller on an already-built appliance client (tests, tools).
    pub fn with_etsi_client(client: Etsi014Client) -> Self {
        Self {
            backend: QelBackend::Etsi014(client),
            state: AtomicU8::new(QelAnchorState::Unprobed as u8),
            probed: OnceLock::new(),
            last_status: parking_lot::Mutex::new(None),
        }
    }

    /// The backend in use: `simulated`, `etsi014`, or `misconfigured`.
    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            QelBackend::Simulated(_) => "simulated",
            QelBackend::Etsi014(_) => "etsi014",
            QelBackend::Misconfigured { .. } => "misconfigured",
        }
    }

    /// A non-secret description of the backend, for the control plane.
    ///
    /// Deliberately carries no key material and no token: an operator-facing
    /// status document is not the place for secrets, and it is fetched over a
    /// loopback HTTP endpoint.
    pub fn backend_report(&self) -> serde_json::Value {
        let mut report = serde_json::json!({ "name": self.backend_name() });
        match &self.backend {
            QelBackend::Simulated(sim) => {
                report["engine"] = serde_json::json!("quantumnet (simulated)");
                report["dir"] = serde_json::json!(sim.dir().to_string_lossy());
            }
            QelBackend::Etsi014(client) => {
                let cfg = client.config();
                report["engine"] = serde_json::json!("ETSI GS QKD 014 key delivery");
                report["kme_url"] = serde_json::json!(cfg.base_url);
                report["sae_id"] = serde_json::json!(cfg.our_sae_id);
                report["key_bits"] = serde_json::json!(cfg.key_bits);
                report["request_timeout_ms"] = serde_json::json!(cfg.timeout.as_millis() as u64);
                report["tls"] = serde_json::json!(cfg.is_https() && cfg!(feature = "qkd-tls"));
                report["client_certificate"] =
                    serde_json::json!(cfg.client_identity().map(|p| p.display().to_string()));
                report["peer_sae_map"] = serde_json::json!(cfg.sae_map.len());
                report["two_node_default"] = serde_json::json!(cfg.is_two_node_default());
                // Surfaced rather than merely logged: an operator should be able
                // to see from the control plane that this node is not verifying
                // the appliance's certificate.
                report["certificate_verification"] = serde_json::json!(if cfg.insecure {
                    "disabled (GHOST_QKD_INSECURE)"
                } else if cfg.ca_pem.is_some() {
                    "custom CA bundle"
                } else {
                    "system trust store"
                });
                if let Some(status) = self.last_status.lock().clone() {
                    report["last_status"] = serde_json::json!({
                        "stored_key_count": status.stored_key_count,
                        "key_size": status.key_size,
                        "min_key_size": status.min_key_size,
                        "max_key_size": status.max_key_size,
                        "source_KME_ID": status.source_kme_id,
                        "target_KME_ID": status.target_kme_id,
                    });
                }
            }
            QelBackend::Misconfigured { reason } => {
                report["engine"] = serde_json::Value::Null;
                report["error"] = serde_json::json!(reason);
            }
        }
        report
    }

    fn state_from_u8(v: u8) -> QelAnchorState {
        match v {
            0 => QelAnchorState::Available,
            1 => QelAnchorState::Degraded,
            2 => QelAnchorState::Unavailable,
            _ => QelAnchorState::Unprobed,
        }
    }

    /// The cached anchor state (probing first if necessary).
    pub async fn state(&self) -> QelAnchorState {
        if let Some(s) = self.probed.get() {
            return *s;
        }
        let s = Self::state_from_u8(self.state.load(Ordering::Relaxed));
        if s != QelAnchorState::Unprobed {
            return s;
        }
        let s = self.probe().await;
        // Best effort: a concurrent probe lands the same answer.
        self.state.store(s as u8, Ordering::Relaxed);
        s
    }

    /// Probe, once, whether the selected backend can deliver keys.
    ///
    /// The result is cached for the process lifetime, so a half-installed or
    /// misconfigured anchor is reported (and logged) once and normal mesh
    /// operation never re-probes.
    pub async fn probe(&self) -> QelAnchorState {
        if let Some(s) = self.probed.get() {
            return *s;
        }
        let state = match &self.backend {
            QelBackend::Simulated(sim) => {
                let s = sim.probe().await;
                match s {
                    QelAnchorState::Available => info!(
                        dir = %sim.dir().display(),
                        "qel: anchor available — quantumnet engine reachable"
                    ),
                    QelAnchorState::Degraded => warn!(
                        dir = %sim.dir().display(),
                        "qel: anchor degraded — python found but 'import quantumnet' failed \
                         (install with: pip install -e \"Quantum Entanglement Link\"). \
                         Sessions continue without quantum entropy; this is not logged again."
                    ),
                    QelAnchorState::Unavailable => warn!(
                        "qel: anchor unavailable — no usable python interpreter; \
                         sessions continue without quantum entropy; this is not logged again"
                    ),
                    QelAnchorState::Unprobed => unreachable!("run_probe never returns Unprobed"),
                }
                s
            }
            QelBackend::Etsi014(client) => self.probe_etsi(client).await,
            QelBackend::Misconfigured { reason } => {
                warn!(
                    error = %reason,
                    "qel: anchor misconfigured — sessions continue without quantum entropy; \
                     this is not logged again"
                );
                QelAnchorState::Degraded
            }
        };
        let _ = self.probed.set(state);
        state
    }

    async fn probe_etsi(&self, client: &Etsi014Client) -> QelAnchorState {
        match client.probe().await {
            Ok(status) => {
                // Report an appliance that cannot serve the size we ask for: it is
                // reachable, so `Available`, but an operator needs the mismatch
                // called out before a session silently never mixes.
                if status.supports_key_bits(client.config().key_bits) == Some(false) {
                    warn!(
                        kme = %client.config().base_url,
                        requested_bits = client.config().key_bits,
                        advertised = %status.describe(),
                        "qel: appliance reachable but does not advertise the requested key size — \
                         set GHOST_QKD_KEY_BITS to a size it accepts"
                    );
                    *self.last_status.lock() = Some(status);
                    return QelAnchorState::Degraded;
                }
                info!(
                    kme = %client.config().base_url,
                    sae = %client.config().our_sae_id,
                    status = %status.describe(),
                    "qel: anchor available — ETSI GS QKD 014 appliance reachable"
                );
                *self.last_status.lock() = Some(status);
                QelAnchorState::Available
            }
            // Transport: the appliance is down, or the TLS configuration is
            // unusable. An operator can do nothing from the session side.
            Err(e) if e.is_transport() => {
                warn!(
                    kme = %client.config().base_url,
                    error = %e,
                    "qel: anchor unavailable — the QKD appliance is not answering; \
                     sessions continue without quantum entropy; this is not logged again"
                );
                QelAnchorState::Unavailable
            }
            // Reachable and refusing us: a wrong SAE ID, a missing client
            // certificate, a pool that will not serve our peer. All actionable.
            Err(e) => {
                warn!(
                    kme = %client.config().base_url,
                    error = %e,
                    "qel: anchor degraded — the QKD appliance refused this SAE; \
                     check the SAE IDs, the client certificate and the key pool; \
                     this is not logged again"
                );
                QelAnchorState::Degraded
            }
        }
    }

    /// Obtain fresh key material for a session with `peer_fp` — the **starting**
    /// side of a mix.
    ///
    /// `topology_json_path` is used only by the simulated backend, which routes
    /// over a mesh export; the appliance does not need one.
    pub async fn acquire_key(
        &self,
        topology_json_path: &Path,
        our_fp: &str,
        peer_fp: &str,
    ) -> QelOutcome {
        let state = self.state().await;
        match &self.backend {
            QelBackend::Simulated(sim) => {
                sim.establish_quantum_link(state, topology_json_path, our_fp, peer_fp)
                    .await
            }
            QelBackend::Etsi014(client) => match client.acquire_key(peer_fp).await {
                Ok(key) => {
                    let epoch_key = key.epoch_key();
                    info!(
                        peer = %peer_fp,
                        key_id = %key.key_id,
                        bits = key.material.len() * 8,
                        "qel: epoch key acquired from the QKD appliance"
                    );
                    QelOutcome {
                        anchor_state: QelAnchorState::Available,
                        route: None,
                        key: Some(epoch_key),
                        label: Some(key.key_id),
                        error: None,
                    }
                }
                Err(e) => QelOutcome::degraded(self.state_for_error(&e), e.to_string()),
            },
            QelBackend::Misconfigured { reason } => QelOutcome::degraded(
                QelAnchorState::Degraded,
                format!("qel backend misconfigured: {reason}"),
            ),
        }
    }

    /// Turn `label` back into the key it names — the **answering** side of a mix.
    ///
    /// On the appliance backend the label is the standard's `key_ID`, so this is
    /// the `dec_keys` call: the material was produced by the quantum channel and
    /// neither peer chose it.
    pub async fn redeem_key(&self, peer_fp: &str, label: &str) -> QelOutcome {
        let state = self.state().await;
        match &self.backend {
            QelBackend::Simulated(sim) => match SimulatedQel::parse_label(label) {
                Ok((fidelity, seed)) => sim.derive_key_at(state, fidelity, seed).await,
                Err(e) => QelOutcome::degraded(state, e),
            },
            QelBackend::Etsi014(client) => match client.redeem_key(peer_fp, label).await {
                Ok(key) => {
                    let epoch_key = key.epoch_key();
                    info!(
                        peer = %peer_fp,
                        key_id = %key.key_id,
                        "qel: epoch key redeemed from the QKD appliance"
                    );
                    QelOutcome {
                        anchor_state: QelAnchorState::Available,
                        route: None,
                        key: Some(epoch_key),
                        label: Some(key.key_id),
                        error: None,
                    }
                }
                Err(e) => QelOutcome::degraded(self.state_for_error(&e), e.to_string()),
            },
            QelBackend::Misconfigured { reason } => QelOutcome::degraded(
                QelAnchorState::Degraded,
                format!("qel backend misconfigured: {reason}"),
            ),
        }
    }

    /// Map a backend error onto an anchor state.
    ///
    /// The distinction the operator needs: *unreachable* is not actionable from
    /// the node, *refused* is a configuration problem.
    fn state_for_error(&self, e: &Etsi014Error) -> QelAnchorState {
        if e.is_transport() {
            QelAnchorState::Unavailable
        } else {
            QelAnchorState::Degraded
        }
    }

    /// Route a quantum path between two peers over a topology export.
    ///
    /// Kept for the control plane's route endpoint, which is a *routing* query.
    /// The appliance backend has no such notion — it delivers key material by ID —
    /// and says so rather than returning a misleading empty route.
    pub async fn establish_quantum_link(
        &self,
        topology_json_path: &Path,
        from_fp: &str,
        to_fp: &str,
    ) -> QelOutcome {
        let state = self.state().await;
        match &self.backend {
            QelBackend::Simulated(sim) => {
                sim.establish_quantum_link(state, topology_json_path, from_fp, to_fp)
                    .await
            }
            QelBackend::Etsi014(_) => QelOutcome::degraded(
                state,
                "the etsi014 backend has no route computation: ETSI GS QKD 014 delivers key \
                 material by key ID, so there is no path to compute. Session mixes still work — \
                 they call enc_keys/dec_keys instead.",
            ),
            QelBackend::Misconfigured { reason } => QelOutcome::degraded(
                QelAnchorState::Degraded,
                format!("qel backend misconfigured: {reason}"),
            ),
        }
    }

    /// Whether this backend routes over a mesh export (the control plane uses
    /// this to explain why a route query is not available).
    pub fn routes_over_topology(&self) -> bool {
        matches!(self.backend, QelBackend::Simulated(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quantum_key_accepts_64_hex_chars() {
        let hex = "00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee";
        let key = SimulatedQel::parse_quantum_key(hex).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0xff);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn parse_quantum_key_rejects_short_and_malformed() {
        assert!(SimulatedQel::parse_quantum_key("aabbcc").is_err());
        assert!(SimulatedQel::parse_quantum_key("zz").is_err());
        assert!(SimulatedQel::parse_quantum_key("").is_err());
    }

    #[test]
    fn parses_the_python_json_contract() {
        let raw = r#"{"success": true, "path": ["a", "b", "c"], "end_to_end_fidelity": 0.9123,
                      "swap_nodes": ["b"], "key_fidelity": 0.9307, "distillation_rounds": 1,
                      "qkd_key_hex": "00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee00ff11ee"}"#;
        let r: QuantumRouteResult = serde_json::from_str(raw).unwrap();
        assert!(r.success);
        assert_eq!(r.path.len(), 3);
        assert_eq!(r.swap_nodes, vec!["b".to_string()]);
        assert_eq!(r.distillation_rounds, 1);
        // The label the session mix pins is the distilled fidelity, not the
        // route's -- the route is below the BB84 cutoff by construction.
        assert_eq!(r.key_label_fidelity(), 0.9307);
        assert!(SimulatedQel::parse_quantum_key(r.qkd_key_hex.as_deref().unwrap()).is_ok());
    }

    #[test]
    fn parses_the_failure_json_contract() {
        let raw = r#"{"success": false, "path": [], "end_to_end_fidelity": 0.0,
                      "swap_nodes": [], "key_fidelity": null, "distillation_rounds": 0,
                      "qkd_key_hex": null}"#;
        let r: QuantumRouteResult = serde_json::from_str(raw).unwrap();
        assert!(!r.success);
        assert!(r.qkd_key_hex.is_none());
        assert!(r.key_fidelity.is_none());
    }

    #[test]
    fn an_older_document_without_the_label_falls_back_to_the_route_fidelity() {
        // The two added fields are `serde(default)`, so a document from an
        // engine that predates distillation still parses rather than failing
        // the whole route.
        let raw = r#"{"success": false, "path": [], "end_to_end_fidelity": 0.0,
                      "swap_nodes": [], "qkd_key_hex": null}"#;
        let r: QuantumRouteResult = serde_json::from_str(raw).unwrap();
        assert_eq!(r.key_label_fidelity(), 0.0);
        assert_eq!(r.distillation_rounds, 0);
    }

    /// A key label must survive the round trip bit-for-bit — a lossy rendering
    /// would hand the two peers different keys and the mix would be refused for no
    /// visible reason.
    #[test]
    fn a_key_label_round_trips_every_field_exactly() {
        for (f, seed) in [
            (0.0f64, 0u64),
            (1.0, 0x51EE),
            (0.85, 0),
            (0.8800000000000001, u64::MAX),
            (
                f64::from_bits(0x3FEC_CCCC_CCCC_CCCD),
                12_345_678_901_234_567,
            ),
        ] {
            let label = SimulatedQel::label(f, seed);
            let (back_f, back_seed) = SimulatedQel::parse_label(&label).expect("round trip");
            assert_eq!(
                back_f.to_bits(),
                f.to_bits(),
                "fidelity {f} did not survive {label:?}"
            );
            assert_eq!(back_seed, seed);
        }
    }

    /// A label this build did not write is refused, not guessed at: deriving the
    /// wrong key from an alien label would move one side's epoch alone.
    #[test]
    fn a_foreign_or_malformed_label_is_refused() {
        for bad in [
            "",
            "0.9/0x51ee",
            "qkd-sim/2/f=0000000000000000/s=00000000000051ee", // wrong version
            "qkd-etsi/1/f=0000000000000000/s=00000000000051ee",
            "qkd-sim/1/f=zzzz/s=00000000000051ee",
            "qkd-sim/1/s=00000000000051ee",
            "qkd-sim/1/f=0000000000000000",
            // A valid-looking label with a fidelity outside 0..1.
            "qkd-sim/1/f=7ff0000000000000/s=00000000000051ee", // +inf
            "qkd-sim/1/f=3ff0000000000001/s=00000000000051ee", // > 1
            "qkd-sim/1/f=0000000000000000/s=00000000000051ee/extra",
        ] {
            assert!(
                SimulatedQel::parse_label(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        // The well-formed one still parses, so the list above is not passing for
        // the wrong reason.
        assert!(SimulatedQel::parse_label(&SimulatedQel::label(0.9, QEL_KDF_SEED)).is_ok());
    }

    #[test]
    fn the_label_is_short_enough_for_the_mix_pdu() {
        // The PDU carries the label in a fixed 128-byte field; a sim label that
        // overflowed it would be silently truncated on the wire.
        let label = SimulatedQel::label(0.937_008_462_446_596_7, QEL_KDF_SEED);
        assert!(
            label.len() <= crate::ghost::session::QEL_MIX_MAX_LABEL,
            "label {label:?} ({} bytes) exceeds the PDU field",
            label.len()
        );
    }

    #[test]
    fn an_unknown_backend_name_is_misconfigured_rather_than_a_silent_fallback() {
        // The environment is process-wide, so this test owns the variable for its
        // duration; nothing else in the suite reads it concurrently.
        let previous = std::env::var(ENV_BACKEND).ok();
        std::env::set_var(ENV_BACKEND, "qkd-over-carrier-pigeon");
        let ctrl = QuantumAnchorController::from_env();
        assert_eq!(ctrl.backend_name(), "misconfigured");
        let report = ctrl.backend_report();
        assert!(report["error"].as_str().unwrap().contains("carrier-pigeon"));
        match previous {
            Some(v) => std::env::set_var(ENV_BACKEND, v),
            None => std::env::remove_var(ENV_BACKEND),
        }
    }

    #[test]
    fn the_etsi_backend_without_a_kme_url_is_misconfigured_not_simulated() {
        let previous_backend = std::env::var(ENV_BACKEND).ok();
        let previous_url = std::env::var(crate::ghost::layers::l10_qel_etsi::ENV_KME_URL).ok();
        std::env::set_var(ENV_BACKEND, "etsi014");
        std::env::remove_var(crate::ghost::layers::l10_qel_etsi::ENV_KME_URL);
        let ctrl = QuantumAnchorController::from_env();
        assert_eq!(
            ctrl.backend_name(),
            "misconfigured",
            "an appliance that was asked for but not configured must not become the simulator"
        );
        match previous_backend {
            Some(v) => std::env::set_var(ENV_BACKEND, v),
            None => std::env::remove_var(ENV_BACKEND),
        }
        if let Some(v) = previous_url {
            std::env::set_var(crate::ghost::layers::l10_qel_etsi::ENV_KME_URL, v);
        }
    }

    /// A missing topology export must be reported without spawning python.
    #[test]
    fn missing_topology_is_refused_before_spawning_python() {
        let missing = std::env::temp_dir().join("vanta_no_such_topology_9f2c.json");
        let _ = std::fs::remove_file(&missing);
        let err = SimulatedQel::resolve_topology_path(&missing)
            .expect_err("missing topology must be refused");
        assert!(err.contains("no mesh topology export"), "got: {err}");
    }

    /// An existing export resolves to an absolute path, so the subprocess
    /// (which runs in the QEL directory) can still open it.
    #[test]
    fn existing_topology_resolves_to_an_absolute_path() {
        let file = std::env::temp_dir().join("vanta_topology_9f2c.json");
        std::fs::write(&file, "{}").unwrap();
        let resolved = SimulatedQel::resolve_topology_path(&file).unwrap();
        assert!(resolved.is_absolute());
        assert_eq!(resolved, file);
        let _ = std::fs::remove_file(&file);
    }

    /// The real subprocess, only where Python + the package exist.
    #[tokio::test]
    #[ignore = "requires python + quantumnet installed (pip install -e \"Quantum Entanglement Link\")"]
    async fn live_subprobe_and_route() {
        let ctrl = QuantumAnchorController::new("Quantum Entanglement Link");
        assert_eq!(ctrl.state().await, QelAnchorState::Available);
    }

    /// **The property the label design rests on**, end to end on the simulated
    /// backend: the key the *starter* routes and the key the *answerer* gets from
    /// the label must be the same bytes, or the two peers prepare epochs from
    /// different keys and the mix is refused for no visible reason.
    ///
    /// This is the sim twin of the appliance test
    /// `both_nodes_derive_one_epoch_key_from_a_key_id`: there the two ends share a
    /// `key_ID`, here they share a `qkd-sim/1/…` derivation label, and in both cases
    /// the assertion is `key == key` with nothing secret on the wire.
    ///
    /// Runs only where the engine exists (prints `SKIP` otherwise, the way the
    /// control-plane test does), because the derivation *is* a python subprocess —
    /// there is no way to test this without it, and faking it would test nothing.
    #[tokio::test]
    async fn a_route_key_and_the_key_redeemed_from_its_label_are_identical() {
        let sim = SimulatedQel::autodetect();
        let state = sim.probe().await;
        if state != QelAnchorState::Available {
            println!(
                "SKIP: qel anchor is {state:?} — install with pip install -e \"Quantum Entanglement Link\""
            );
            return;
        }

        // A two-node export with a length, because the quantum layer derives a
        // link's attenuation from its physical extent and skips a link with none.
        let topo = std::env::temp_dir().join(format!(
            "vanta_qel_label_roundtrip_{}.json",
            std::process::id()
        ));
        std::fs::write(
            &topo,
            r#"{
              "schema_version": 1,
              "generator": "vantablack",
              "exported_at": 0,
              "nodes": [
                {"fingerprint": "labelfrom0000000", "addr": "10.0.0.1:2270"},
                {"fingerprint": "labelto000000000", "addr": "10.0.0.2:2270"}
              ],
              "links": [{"a": "labelfrom0000000", "b": "labelto000000000", "length_km": 10.0}]
            }"#,
        )
        .expect("write topology export");

        // The starter: route, distil, derive, and name the key it derived.
        let starter = sim
            .establish_quantum_link(state, &topo, "labelfrom0000000", "labelto000000000")
            .await;
        let key = starter.key.expect("a routed key");
        let label = starter.label.expect("the label naming it");
        assert!(
            label.starts_with(QEL_SIM_LABEL_PREFIX),
            "a simulated label carries its own version tag: {label}"
        );
        assert!(
            label.len() <= crate::ghost::session::QEL_MIX_MAX_LABEL,
            "and fits the PDU field it travels in: {label}"
        );
        assert!(
            !label.contains(&hex::encode(key)),
            "the label must name the key, never contain it: {label}"
        );

        // The answerer: parse the label the PDU carried, derive from it, and get
        // the same bytes. It has no topology export of its own — that is the point.
        let (fidelity, seed) = SimulatedQel::parse_label(&label).expect("a label we wrote");
        let answerer = sim.derive_key_at(state, fidelity, seed).await;
        assert_eq!(
            answerer.key.map(|k| k.to_vec()),
            Some(key.to_vec()),
            "a mix would be refused if these differed; label = {label}"
        );
        assert_eq!(
            answerer.label.as_deref(),
            Some(label.as_str()),
            "and the answering side reports the same label back"
        );

        // Asking twice gives the same bytes, which is what makes a label
        // sufficient on the answering side at all.
        let again = sim.derive_key_at(state, fidelity, seed).await;
        assert_eq!(
            again.key.map(|k| k.to_vec()),
            Some(key.to_vec()),
            "the derivation is deterministic in (fidelity, seed)"
        );

        // Below the BB84 cutoff there is **no** key, and the answering side must be
        // told that rather than handed something derived anyway: a mix built on
        // material the other end does not have would prepare an epoch alone.
        // Measured edge: F 0.870 yields nothing, F 0.872 does.
        let below = sim.derive_key_at(state, 0.85, seed).await;
        assert!(
            below.key.is_none(),
            "0.85 is under the cutoff and must yield nothing"
        );
        assert!(
            below.error.as_deref().is_some_and(|e| e.contains("0.85")),
            "and the refusal must name the fidelity it refused, not report an empty \
             stderr: {:?}",
            below.error
        );

        // **A limitation of the simulated engine, pinned so it cannot change
        // silently.** `qkd-derive` returns Alice's own seeded sifted bits, and its
        // noise parameter enters only through the QBER gate — so every fidelity
        // above the cutoff maps to the *same* 32 bytes, and with a constant seed
        // every simulated session mixes the same key. In this build the mix's real
        // contribution is epoch agreement, not entropy (see
        // `docs/ANCHORS_CODEBASE_INTEGRATION.md` §8). If this assertion ever starts
        // failing, the engine grew error correction and privacy amplification —
        // good news, and §8 needs rewriting.
        let higher = SimulatedQel::label(fidelity + 0.05, seed);
        let (higher_f, higher_s) = SimulatedQel::parse_label(&higher).unwrap();
        let same_for_higher = sim.derive_key_at(state, higher_f, higher_s).await;
        assert_eq!(
            same_for_higher.key.map(|k| k.to_vec()),
            Some(key.to_vec()),
            "the simulated engine does not vary its key with fidelity above the cutoff"
        );

        let _ = std::fs::remove_file(&topo);
    }
}
