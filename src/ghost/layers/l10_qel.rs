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

pub const ENV_BACKEND: &str = "GHOST_QEL_BACKEND";

const QEL_PROCESS_TIMEOUT: Duration = Duration::from_secs(45);

pub const QEL_KDF_SEED: u64 = 0x51EE;

pub const QEL_SIM_LABEL_PREFIX: &str = "qkd-sim/1";

static CONTROLLER: OnceLock<Arc<QuantumAnchorController>> = OnceLock::new();

pub fn install_global_controller(ctrl: Arc<QuantumAnchorController>) -> bool {
    CONTROLLER.set(ctrl).is_ok()
}

pub fn shared_controller() -> Arc<QuantumAnchorController> {
    CONTROLLER
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(QuantumAnchorController::from_env()))
}

pub fn selected_backend_name() -> String {
    std::env::var(ENV_BACKEND).unwrap_or_else(|_| "sim".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRouteResult {
    pub success: bool,
    pub path: Vec<String>,
    pub end_to_end_fidelity: f64,
    pub swap_nodes: Vec<String>,
    pub qkd_key_hex: Option<String>,
    #[serde(default)]
    pub key_fidelity: Option<f64>,
    #[serde(default)]
    pub distillation_rounds: u32,
}

impl QuantumRouteResult {
    pub fn key_label_fidelity(&self) -> f64 {
        self.key_fidelity.unwrap_or(self.end_to_end_fidelity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QelAnchorState {
    Available = 0,
    Degraded = 1,
    Unavailable = 2,
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

#[derive(Debug, Clone, Serialize)]
pub struct QelOutcome {
    pub anchor_state: QelAnchorState,
    pub route: Option<QuantumRouteResult>,
    pub key: Option<[u8; 32]>,
    pub label: Option<String>,
    pub error: Option<String>,
}

impl QelOutcome {
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
    pub fn new<P: AsRef<Path>>(qel_dir: P) -> Self {
        Self {
            qel_dir: qel_dir.as_ref().to_path_buf(),
            python_bin: "python".to_string(),
        }
    }

    pub fn autodetect() -> Self {
        Self::new(PathBuf::from("Quantum Entanglement Link"))
    }

    pub fn dir(&self) -> &Path {
        &self.qel_dir
    }

    pub fn label(fidelity: f64, seed: u64) -> String {
        format!(
            "{QEL_SIM_LABEL_PREFIX}/f={:016x}/s={:016x}",
            fidelity.to_bits(),
            seed
        )
    }

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

    fn python_path_env(&self) -> std::ffi::OsString {
        let src_dir = std::fs::canonicalize(self.qel_dir.join("src"))
            .unwrap_or_else(|_| PathBuf::from("src"));
        let mut paths = vec![src_dir];
        if let Some(existing) = std::env::var_os("PYTHONPATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        std::env::join_paths(paths).unwrap_or_else(|_| std::ffi::OsString::from("src"))
    }

    async fn run_probe(&self) -> QelAnchorState {
        let output = match Command::new(&self.python_bin)
            .args(["-c", "import quantumnet.cli"])
            .current_dir(&self.qel_dir)
            .env("PYTHONPATH", self.python_path_env())
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
                .env("PYTHONPATH", self.python_path_env())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            debug!(pid = ?child.id(), what, "qel: quantumnet subprocess spawned");
            let out = child.wait_with_output().await;
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
            if let Ok(doc) = serde_json::from_str::<QuantumRouteResult>(stdout.trim()) {
                if !doc.success {
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

pub const RF_RECIPROCITY_LABEL_PREFIX: &str = "rf-reciprocity/1";

pub const RF_MIN_SECRET_BITS: usize = 256;

const RF_BLOCK_BITS: usize = 7;
const RF_SYNDROME_BITS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReciprocityCapture {
    pub alice: Vec<f64>,
    pub bob: Vec<f64>,
    #[serde(default)]
    pub eve: Vec<f64>,
}

pub struct RfKey {
    key: [u8; 32],
    label: String,
    raw_bits: usize,
    leaked_bits: usize,
    secret_bits: usize,
    confirmation: [u8; 8],
}

impl RfKey {
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn raw_bits(&self) -> usize {
        self.raw_bits
    }

    pub fn leaked_bits(&self) -> usize {
        self.leaked_bits
    }

    pub fn secret_bits(&self) -> usize {
        self.secret_bits
    }

    pub fn confirmation(&self) -> [u8; 8] {
        self.confirmation
    }
}

impl std::fmt::Debug for RfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RfKey")
            .field("label", &self.label)
            .field("raw_bits", &self.raw_bits)
            .field("leaked_bits", &self.leaked_bits)
            .field("secret_bits", &self.secret_bits)
            .finish_non_exhaustive()
    }
}

const RF_MIN_SAMPLES: usize = 512;

fn reciprocity_bits(samples: &[f64]) -> Vec<u8> {
    samples.windows(2).map(|w| u8::from(w[1] >= w[0])).collect()
}

fn binary_entropy(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        0.0
    } else {
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    }
}

fn bit_error_rate(a: &[u8], b: &[u8]) -> f64 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.5;
    }
    let errors = (0..n).filter(|&i| a[i] != b[i]).count();
    errors as f64 / n as f64
}

fn bsc_information(ber: f64) -> f64 {
    (1.0 - binary_entropy(ber)).clamp(0.0, 1.0)
}

fn hamming_syndrome(block: &[u8]) -> u8 {
    let s1 = block[0] ^ block[2] ^ block[4] ^ block[6];
    let s2 = block[1] ^ block[2] ^ block[5] ^ block[6];
    let s3 = block[3] ^ block[4] ^ block[5] ^ block[6];
    (s1 & 1) | ((s2 & 1) << 1) | ((s3 & 1) << 2)
}

pub struct ReciprocityExchange {
    alice: Vec<u8>,
    bob: Vec<u8>,
    eve: Vec<u8>,
}

impl ReciprocityExchange {
    pub fn from_capture(capture: &ReciprocityCapture) -> Result<Self, String> {
        if capture.alice.len() < RF_MIN_SAMPLES || capture.bob.len() < RF_MIN_SAMPLES {
            return Err(format!(
                "reciprocity capture has {} / {} soundings; at least {RF_MIN_SAMPLES} are needed ",
                capture.alice.len(),
                capture.bob.len()
            ));
        }
        let alice = reciprocity_bits(&capture.alice);
        let bob = reciprocity_bits(&capture.bob);
        let eve = reciprocity_bits(&capture.eve);
        Self::from_bits(alice, bob, eve)
    }

    pub fn from_bits(alice: Vec<u8>, bob: Vec<u8>, eve: Vec<u8>) -> Result<Self, String> {
        let usable = alice.len().min(bob.len());
        if usable < RF_BLOCK_BITS {
            return Err(format!(
                "only {usable} quantized bits; no block to reconcile"
            ));
        }
        let usable = usable - (usable % RF_BLOCK_BITS);
        if alice[..usable].iter().chain(&bob[..usable]).any(|b| *b > 1) {
            return Err("quantized bits must be 0 or 1".to_string());
        }
        Ok(Self {
            alice: alice[..usable].to_vec(),
            bob: bob[..usable].to_vec(),
            eve: eve[..eve.len().min(usable)].to_vec(),
        })
    }

    pub fn raw_bits(&self) -> usize {
        self.alice.len()
    }

    pub fn capacity_bits_per_sample(&self) -> f64 {
        let i_ab = bsc_information(bit_error_rate(&self.alice, &self.bob));
        let eve_view = if self.eve.is_empty() {
            0.0
        } else {
            bsc_information(bit_error_rate(&self.alice, &self.eve))
                .min(bsc_information(bit_error_rate(&self.bob, &self.eve)))
        };
        i_ab - eve_view
    }

    pub fn alice_syndrome(&self) -> Vec<u8> {
        self.alice
            .as_chunks::<RF_BLOCK_BITS>()
            .0
            .iter()
            .map(|block| hamming_syndrome(block))
            .collect()
    }

    pub fn bob_reconciled(&self, syndrome: &[u8]) -> Result<Vec<u8>, String> {
        let blocks = self.bob.len() / RF_BLOCK_BITS;
        if syndrome.len() != blocks {
            return Err(format!(
                "syndrome has {} blocks, expected {blocks}",
                syndrome.len()
            ));
        }
        let mut out = self.bob.clone();
        for (index, alice_parity) in syndrome.iter().copied().enumerate() {
            if alice_parity > 7 {
                return Err(format!("block {index} has invalid syndrome {alice_parity}"));
            }
            let block = &self.bob[index * RF_BLOCK_BITS..(index + 1) * RF_BLOCK_BITS];
            let s = hamming_syndrome(block) ^ alice_parity;
            match s {
                0 => {}
                1..=7 => out[index * RF_BLOCK_BITS + (s as usize - 1)] ^= 1,
                _ => unreachable!("3-bit XOR cannot exceed 7"),
            }
        }
        Ok(out)
    }

    pub fn derive_key(&self, transcript: &[u8]) -> Result<RfKey, String> {
        let capacity = self.capacity_bits_per_sample();
        if capacity <= 0.0 {
            return Err(format!(
                "reciprocity channel has no secret capacity ({capacity:.3} bits/bit), so no key is derived"
            ));
        }
        let syndrome = self.alice_syndrome();
        let bob = self.bob_reconciled(&syndrome)?;
        if bob != self.alice {
            return Err(
                "reconciliation did not converge: too many errors for a single-error block code"
                    .to_string(),
            );
        }
        let blocks = self.alice.len() / RF_BLOCK_BITS;
        let leaked = blocks * RF_SYNDROME_BITS;
        let secret_bits = self.alice.len().saturating_sub(leaked);
        if secret_bits < RF_MIN_SECRET_BITS + 128 {
            return Err(format!(
                "{secret_bits} bits survive reconciliation and amplification, below the {}+128 floor",
                RF_MIN_SECRET_BITS
            ));
        }

        let mut ikm = Vec::with_capacity(self.alice.len() / 8);
        for chunk in self.alice.chunks(8) {
            let mut byte = 0u8;
            for (i, bit) in chunk.iter().enumerate() {
                byte |= bit << i;
            }
            ikm.push(byte);
        }
        use sha2::{Digest, Sha256};
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"VB-RF-CRKG-SALT-V1");
        salt_hasher.update(transcript);
        let salt = salt_hasher.finalize();
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut key = [0u8; 32];
        hk.expand(b"VB-RF-CRKG-SESSION-V1", &mut key)
            .map_err(|e| format!("HKDF refused a 32-byte output: {e}"))?;

        use hmac::{Hmac, Mac};
        let mut confirmation = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| format!("HMAC rejected the derived key: {e}"))?;
        confirmation.update(b"VB-RF-CRKG-CONFIRM-V1");
        confirmation.update(transcript);
        let tag = confirmation.finalize().into_bytes();
        let mut confirmation = [0u8; 8];
        confirmation.copy_from_slice(&tag[..8]);

        Ok(RfKey {
            key,
            label: format!(
                "{RF_RECIPROCITY_LABEL_PREFIX}/b={}/l={}/c={:016x}",
                self.alice.len(),
                leaked,
                capacity.to_bits()
            ),
            raw_bits: self.alice.len(),
            leaked_bits: leaked,
            secret_bits,
            confirmation,
        })
    }
}

pub const MONOTONE_COMBINER_DOMAIN: &[u8] = b"VB-L10-MONOTONE-COMBINER-V1";

pub fn combine_monotone(
    k_x25519: &[u8; 32],
    k_mlkem: &[u8; 32],
    k_l10: &[u8; 32],
    transcript: &[u8],
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut inner =
        Hmac::<Sha256>::new_from_slice(k_l10).expect("HMAC-SHA256 accepts a 32-byte key");
    inner.update(MONOTONE_COMBINER_DOMAIN);
    inner.update(transcript);
    let inner = inner.finalize().into_bytes();

    let mut middle =
        Hmac::<Sha256>::new_from_slice(k_x25519).expect("HMAC-SHA256 accepts a 32-byte key");
    middle.update(&inner);
    let middle = middle.finalize().into_bytes();

    let mut outer =
        Hmac::<Sha256>::new_from_slice(k_mlkem).expect("HMAC-SHA256 accepts a 32-byte key");
    outer.update(&middle);
    let out = outer.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

enum QelBackend {
    Simulated(SimulatedQel),
    Misconfigured { reason: String },
}

pub struct QuantumAnchorController {
    backend: QelBackend,
    state: AtomicU8,
    probed: OnceLock<QelAnchorState>,
}

impl Default for QuantumAnchorController {
    fn default() -> Self {
        Self::from_env()
    }
}

impl QuantumAnchorController {
    pub fn from_env() -> Self {
        let backend = match selected_backend_name().trim().to_ascii_lowercase().as_str() {
            "" | "sim" | "simulated" | "quantumnet" => {
                QelBackend::Simulated(SimulatedQel::autodetect())
            }
            "etsi014" | "etsi" | "qkd014" => QelBackend::Misconfigured {
                reason: "ETSI GS QKD 014 hardware backend has been removed for now".to_string(),
            },
            "rf_reciprocity" | "rf-reciprocity" | "rf" => QelBackend::Misconfigured {
                reason: "rf_reciprocity needs an interactive syndrome exchange and cannot be a \
                         label-based key backend; use l10_qel::ReciprocityExchange in-band"
                    .to_string(),
            },
            other => QelBackend::Misconfigured {
                reason: format!(
                    "{ENV_BACKEND}={other:?} is not a backend this build knows \
                     (expected \"sim\", \"etsi014\" or \"rf_reciprocity\")"
                ),
            },
        };
        Self {
            backend,
            state: AtomicU8::new(QelAnchorState::Unprobed as u8),
            probed: OnceLock::new(),
        }
    }

    pub fn new<P: AsRef<Path>>(qel_dir: P) -> Self {
        Self {
            backend: QelBackend::Simulated(SimulatedQel::new(qel_dir)),
            state: AtomicU8::new(QelAnchorState::Unprobed as u8),
            probed: OnceLock::new(),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            QelBackend::Simulated(_) => "simulated",
            QelBackend::Misconfigured { .. } => "misconfigured",
        }
    }

    pub fn backend_report(&self) -> serde_json::Value {
        let mut report = serde_json::json!({ "name": self.backend_name() });
        match &self.backend {
            QelBackend::Simulated(sim) => {
                report["engine"] = serde_json::json!("quantumnet (simulated)");
                report["dir"] = serde_json::json!(sim.dir().to_string_lossy());
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

    pub async fn state(&self) -> QelAnchorState {
        if let Some(s) = self.probed.get() {
            return *s;
        }
        let s = Self::state_from_u8(self.state.load(Ordering::Relaxed));
        if s != QelAnchorState::Unprobed {
            return s;
        }
        let s = self.probe().await;
        self.state.store(s as u8, Ordering::Relaxed);
        s
    }

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
                         (ensure \"Quantum Entanglement Link/src\" exists and numpy is installed: \
                          pip install -e \"Quantum Entanglement Link\"). \
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
            QelBackend::Misconfigured { reason } => QelOutcome::degraded(
                QelAnchorState::Degraded,
                format!("qel backend misconfigured: {reason}"),
            ),
        }
    }

    pub async fn redeem_key(&self, _peer_fp: &str, label: &str) -> QelOutcome {
        let state = self.state().await;
        match &self.backend {
            QelBackend::Simulated(sim) => match SimulatedQel::parse_label(label) {
                Ok((fidelity, seed)) => sim.derive_key_at(state, fidelity, seed).await,
                Err(e) => QelOutcome::degraded(state, e),
            },
            QelBackend::Misconfigured { reason } => QelOutcome::degraded(
                QelAnchorState::Degraded,
                format!("qel backend misconfigured: {reason}"),
            ),
        }
    }

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
            QelBackend::Misconfigured { reason } => QelOutcome::degraded(
                QelAnchorState::Degraded,
                format!("qel backend misconfigured: {reason}"),
            ),
        }
    }

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
        let raw = r#"{"success": false, "path": [], "end_to_end_fidelity": 0.0,
                      "swap_nodes": [], "qkd_key_hex": null}"#;
        let r: QuantumRouteResult = serde_json::from_str(raw).unwrap();
        assert_eq!(r.key_label_fidelity(), 0.0);
        assert_eq!(r.distillation_rounds, 0);
    }

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
            "qkd-sim/1/f=7ff0000000000000/s=00000000000051ee", // +inf
            "qkd-sim/1/f=3ff0000000000001/s=00000000000051ee", // > 1
            "qkd-sim/1/f=0000000000000000/s=00000000000051ee/extra",
        ] {
            assert!(
                SimulatedQel::parse_label(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(SimulatedQel::parse_label(&SimulatedQel::label(0.9, QEL_KDF_SEED)).is_ok());
    }

    #[test]
    fn the_label_is_short_enough_for_the_mix_pdu() {
        let label = SimulatedQel::label(0.937_008_462_446_596_7, QEL_KDF_SEED);
        assert!(
            label.len() <= crate::ghost::session::QEL_MIX_MAX_LABEL,
            "label {label:?} ({} bytes) exceeds the PDU field",
            label.len()
        );
    }

    #[test]
    fn an_unknown_backend_name_is_misconfigured_rather_than_a_silent_fallback() {
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
    fn the_etsi_backend_is_reported_as_removed() {
        let previous_backend = std::env::var(ENV_BACKEND).ok();
        std::env::set_var(ENV_BACKEND, "etsi014");
        let ctrl = QuantumAnchorController::from_env();
        assert_eq!(ctrl.backend_name(), "misconfigured");
        match previous_backend {
            Some(v) => std::env::set_var(ENV_BACKEND, v),
            None => std::env::remove_var(ENV_BACKEND),
        }
    }

    #[test]
    fn missing_topology_is_refused_before_spawning_python() {
        let missing = std::env::temp_dir().join("vanta_no_such_topology_9f2c.json");
        let _ = std::fs::remove_file(&missing);
        let err = SimulatedQel::resolve_topology_path(&missing)
            .expect_err("missing topology must be refused");
        assert!(err.contains("no mesh topology export"), "got: {err}");
    }

    #[test]
    fn existing_topology_resolves_to_an_absolute_path() {
        let file = std::env::temp_dir().join("vanta_topology_9f2c.json");
        std::fs::write(&file, "{}").unwrap();
        let resolved = SimulatedQel::resolve_topology_path(&file).unwrap();
        assert!(resolved.is_absolute());
        assert_eq!(resolved, file);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    #[ignore = "requires python + numpy (or pip install -e \"Quantum Entanglement Link\")"]
    async fn live_subprobe_and_route() {
        let ctrl = QuantumAnchorController::new("Quantum Entanglement Link");
        assert_eq!(ctrl.state().await, QelAnchorState::Available);
    }

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

        let again = sim.derive_key_at(state, fidelity, seed).await;
        assert_eq!(
            again.key.map(|k| k.to_vec()),
            Some(key.to_vec()),
            "the derivation is deterministic in (fidelity, seed)"
        );

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

#[cfg(test)]
mod rf_tests {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn bit(&mut self) -> u8 {
            (self.next() >> 33) as u8 & 1
        }

        fn bits(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.bit()).collect()
        }
    }

    fn correlated_pair(blocks: usize, error_every: usize) -> (Vec<u8>, Vec<u8>) {
        let mut rng = Rng::new(0x51EE);
        let alice = rng.bits(blocks * RF_BLOCK_BITS);
        let mut bob = alice.clone();
        for block in (0..blocks).step_by(error_every.max(1)) {
            let offset = (rng.next() as usize) % RF_BLOCK_BITS;
            bob[block * RF_BLOCK_BITS + offset] ^= 1;
        }
        (alice, bob)
    }

    #[test]
    fn reciprocity_derives_the_same_secret_on_both_ends() {
        let (alice, bob) = correlated_pair(200, 10);
        let mut rng = Rng::new(7);
        let eve = rng.bits(alice.len());
        let exchange =
            ReciprocityExchange::from_bits(alice, bob, eve).expect("sample stream is usable");
        assert!(
            exchange.capacity_bits_per_sample() > 0.5,
            "a mostly-agreeing channel with an independent eavesdropper has capacity"
        );

        let first = exchange.derive_key(b"handshake-1").expect("alice derives");
        let second = exchange
            .derive_key(b"handshake-1")
            .expect("same inputs, same key");
        assert_eq!(first.key(), second.key());
        assert_eq!(first.confirmation(), second.confirmation());
        assert!(first.label().starts_with(RF_RECIPROCITY_LABEL_PREFIX));
        assert_eq!(first.raw_bits(), 200 * RF_BLOCK_BITS);
        assert_eq!(first.leaked_bits(), 200 * RF_SYNDROME_BITS);
        assert_eq!(
            first.secret_bits(),
            200 * (RF_BLOCK_BITS - RF_SYNDROME_BITS),
            "what survives is the data bits, after the syndrome leak"
        );

        let other = exchange.derive_key(b"handshake-2").expect("derive");
        assert_ne!(first.key(), other.key());
    }

    #[test]
    fn reciprocity_refuses_a_channel_an_eavesdropper_can_follow() {
        let (alice, _) = correlated_pair(200, 10);
        let mut rng = Rng::new(99);
        let bob = rng.bits(alice.len());
        let exchange = ReciprocityExchange::from_bits(alice.clone(), bob.clone(), bob)
            .expect("bits are well formed");
        assert!(
            exchange.capacity_bits_per_sample() <= 0.0,
            "if Eve sees what Bob sees, there is no secret"
        );
        assert!(exchange.derive_key(b"t").is_err());
    }

    #[test]
    fn reciprocity_refuses_a_capture_too_short_to_amplify() {
        let (alice, bob) = correlated_pair(20, 5);
        let exchange = ReciprocityExchange::from_bits(alice, bob, Vec::new()).expect("usable");
        let err = exchange.derive_key(b"t").expect_err("too few bits");
        assert!(err.contains("below the"), "unexpected refusal: {err}");
    }

    #[test]
    fn a_real_sounding_capture_flows_through_quantization_and_agrees() {
        let alice: Vec<f64> = (0..1024)
            .map(|i| (i as f64 * 0.05).sin() + (i as f64 * 0.31).cos() * 0.2)
            .collect();
        let capture = ReciprocityCapture {
            alice: alice.clone(),
            bob: alice,
            eve: Vec::new(),
        };
        let exchange = ReciprocityExchange::from_capture(&capture).expect("capture is long enough");
        assert_eq!(exchange.capacity_bits_per_sample(), 1.0);
        let key = exchange.derive_key(b"capture").expect("derive");
        assert_ne!(key.key(), [0u8; 32]);
        assert!(key.secret_bits() >= RF_MIN_SECRET_BITS);
    }

    #[test]
    fn the_monotone_combiner_binds_every_input() {
        let x = [0x11u8; 32];
        let m = [0x22u8; 32];
        let l = [0x33u8; 32];
        let base = combine_monotone(&x, &m, &l, b"transcript");
        assert_eq!(base, combine_monotone(&x, &m, &l, b"transcript"));
        assert_ne!(base, combine_monotone(&[0x12u8; 32], &m, &l, b"transcript"));
        assert_ne!(base, combine_monotone(&x, &[0x23u8; 32], &l, b"transcript"));
        assert_ne!(base, combine_monotone(&x, &m, &[0x34u8; 32], b"transcript"));
        assert_ne!(base, combine_monotone(&x, &m, &l, b"other"));

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut inner = Hmac::<Sha256>::new_from_slice(&l).unwrap();
        inner.update(MONOTONE_COMBINER_DOMAIN);
        inner.update(b"transcript");
        let inner = inner.finalize().into_bytes();
        let mut middle = Hmac::<Sha256>::new_from_slice(&x).unwrap();
        middle.update(&inner);
        let middle = middle.finalize().into_bytes();
        let mut outer = Hmac::<Sha256>::new_from_slice(&m).unwrap();
        outer.update(&middle);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&outer.finalize().into_bytes());
        assert_eq!(base, expected);
    }
}
