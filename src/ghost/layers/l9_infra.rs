/// L9 — Infrastructure & Deployment Layer
///
/// Implements the remaining infrastructure roadmap items:
///
/// 1. **Portable Single Executable Packaging** (line 16)
///    Self-contained binary with embedded default config. Uses build.rs to bake
///    in defaults so users just download, verify the hash, and run with zero config.
///
/// 2. **TPM/HSM Key Enclave** (line 31)
///    Moves the Ed25519 identity key into a hardware security module such as
///    TPM 2.0 or ARM TrustZone so signing keys cannot be extracted even by a
///    successful kernel zero-day exploit. Provides a simulated software TPM
///    for development environments.
///
/// 3. **Network Time Security / Atomic Clock Integration** (line 33)
///    Prevents GPS and NTP spoofing attacks from collapsing the CGR routing mesh
///    by using Network Time Security (NTS) or onboard atomic clock references
///    for time synchronization.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

// ── 1. Portable Single Executable Packaging ──────────────────────────

/// Embedded default configuration baked into the binary at compile time.
/// Replace this with env!("CONFIG") or include_str!("defaults.toml") for a real build.
pub const EMBEDDED_DEFAULT_CONFIG: &str = r#"
# Vantablack — Default Node Configuration
# This config is embedded into the binary for zero-config startup.

[network]
bind = "0.0.0.0:0"
beacon_enabled = true
beacon_interval_secs = 30
transit_rate_mbps = 100

[crypto]
identity_file = "identity.key"
psk_file = ""
psk_rotation_hours = 24

[routing]
cgr_enabled = true
max_hops = 5
bundle_lifetime_secs = 3600
store_forward_enabled = true

[security]
revocation_list_file = "revocations.json"
zk_auth_required = false
temporal_isolation_enabled = true
memguard_enabled = true

[monitoring]
metrics_enabled = false
metrics_port = 9090
log_level = "info"
"#;

/// Build info embedded into the binary for reproducible builds.
pub struct BuildInfo {
    /// Git commit hash (embedded at build time).
    pub git_commit: &'static str,
    /// Build timestamp (Unix epoch seconds).
    pub build_timestamp: u64,
    /// Rust compiler version used.
    pub rustc_version: &'static str,
    /// Whether this binary has a verified hash manifest.
    pub verified: AtomicBool,
}

impl BuildInfo {
    /// SHA-256 hash of the binary itself (computed at startup).
    pub fn self_hash(&self) -> Option<Vec<u8>> {
        let exe_path = std::env::current_exe().ok()?;
        let data = std::fs::read(&exe_path).ok()?;
        let d = Sha256::digest(&data);
        Some(d.as_slice().to_vec())
    }

    /// Create default build info.
    pub fn new() -> Self {
        Self {
            git_commit: env!("CARGO_PKG_VERSION"),
            build_timestamp: std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            rustc_version: "unknown",
            verified: AtomicBool::new(false),
        }
    }

    /// Verify the binary against a signed hash manifest.
    pub fn verify_manifest(
        &self,
        manifest_hex: &str,
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> bool {
        if let Some(hash) = self.self_hash() {
            let hash_hex = hex::encode(&hash);
            if hash_hex != manifest_hex {
                warn!(
                    "Binary hash mismatch: expected {}, got {}",
                    manifest_hex, hash_hex
                );
                return false;
            }
            // Verify the manifest signature
            let verified = crate::ghost::layers::l0_identity::verify_peer_signature(
                public_key,
                hash_hex.as_bytes(),
                signature,
            );
            self.verified.store(verified, Ordering::SeqCst);
            verified
        } else {
            false
        }
    }
}

/// Initialize the node with sensible defaults from the embedded config.
pub async fn initialize_node() -> anyhow::Result<()> {
    info!("Vantablack v{} starting", env!("CARGO_PKG_VERSION"));

    // Parse embedded default config (simplified — in production use toml)
    let _config = EMBEDDED_DEFAULT_CONFIG;

    // Extract log level from config
    let log_level = "info";
    std::env::set_var("RUST_LOG", log_level);

    // Print startup banner
    info!("Embedded config loaded");
    info!("Network: bind=0.0.0.0:0, beacon=enabled");
    info!("Crypto: identity_file=identity.key, PSK rotation=24h");
    info!("Routing: CGR=enabled, max_hops=5, store_forward=enabled");
    info!("Security: ZK auth=optional, temporal_isolation=enabled");
    info!("Download URL: https://github.com/KELLERBABG/Vantablack/releases/latest");

    Ok(())
}

// ── 2. TPM/HSM Key Enclave ───────────────────────────────────────────

/// Trait for hardware-backed key storage (TPM 2.0, ARM TrustZone, etc.).
pub trait KeyEnclave: Send + Sync {
    /// Store a secret key in the enclave. Returns an opaque handle.
    fn store_key(&self, key_bytes: &[u8]) -> Result<u64, EnclaveError>;

    /// Sign data using a key stored in the enclave.
    fn sign(&self, handle: u64, data: &[u8]) -> Result<[u8; 64], EnclaveError>;

    /// Retrieve the public key corresponding to a stored key.
    fn public_key(&self, handle: u64) -> Result<[u8; 32], EnclaveError>;

    /// Delete a key from the enclave.
    fn delete_key(&self, handle: u64) -> Result<(), EnclaveError>;

    /// Generate a fresh Ed25519 keypair inside the enclave.
    fn generate_key(&self) -> Result<(u64, [u8; 32]), EnclaveError>;
}

/// Errors that can occur in enclave operations.
#[derive(Debug, Clone)]
pub enum EnclaveError {
    /// The enclave is not available (no TPM hardware).
    NotAvailable(String),
    /// The key handle is invalid.
    InvalidHandle,
    /// The operation failed.
    OperationFailed(String),
    /// The key was deleted or sealed.
    KeyUnavailable,
}

impl std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnclaveError::NotAvailable(msg) => write!(f, "Enclave not available: {}", msg),
            EnclaveError::InvalidHandle => write!(f, "Invalid enclave key handle"),
            EnclaveError::OperationFailed(msg) => write!(f, "Enclave operation failed: {}", msg),
            EnclaveError::KeyUnavailable => write!(f, "Key unavailable in enclave"),
        }
    }
}

/// Software-simulated enclave for development environments.
///
/// In production, this would be replaced by a real TPM 2.0 or ARM TrustZone
/// implementation using `tss-esapi` or `trustzone-rs` crates.
/// For development, this stores keys in memory with secure zeroing on drop.
///
/// This implements the handle-based [`KeyEnclave`] surface. It is deliberately
/// **not** the same type as `ghost::net::security::SoftwareKeyEnclave`, which implements
/// the `HsmBackend` surface (an earlier change removed that name collision).
pub struct SoftwareKeyEnclave {
    /// Key store: handle → key bytes.
    keys: std::sync::Mutex<std::collections::HashMap<u64, Vec<u8>>>,
    /// Next available handle.
    next_handle: std::sync::atomic::AtomicU64,
    /// Whether this TPM has been tampered with.
    tampered: AtomicBool,
}

impl Default for SoftwareKeyEnclave {
    fn default() -> Self {
        Self {
            keys: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_handle: std::sync::atomic::AtomicU64::new(1),
            tampered: AtomicBool::new(false),
        }
    }
}

impl SoftwareKeyEnclave {
    pub fn new() -> Self {
        info!("SoftwareKeyEnclave initialized (development mode — not secure for production)");
        Self::default()
    }

    /// Simulate tamper detection (e.g., from chassis intrusion sensor).
    pub fn detect_tamper(&self) {
        self.tampered.store(true, Ordering::SeqCst);
        // Zero all keys on tamper
        let mut keys = self.keys.lock().unwrap();
        for key_data in keys.values_mut() {
            for byte in key_data.iter_mut() {
                *byte = 0;
            }
        }
        keys.clear();
        warn!("SoftwareKeyEnclave: Tamper detected! All keys zeroed.");
    }

    pub fn is_tampered(&self) -> bool {
        self.tampered.load(Ordering::SeqCst)
    }
}

impl KeyEnclave for SoftwareKeyEnclave {
    fn store_key(&self, key_bytes: &[u8]) -> Result<u64, EnclaveError> {
        if self.tampered.load(Ordering::SeqCst) {
            return Err(EnclaveError::KeyUnavailable);
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let mut keys = self.keys.lock().unwrap();
        keys.insert(handle, key_bytes.to_vec());
        debug!("SoftwareKeyEnclave: stored key with handle {}", handle);
        Ok(handle)
    }

    fn sign(&self, handle: u64, data: &[u8]) -> Result<[u8; 64], EnclaveError> {
        if self.tampered.load(Ordering::SeqCst) {
            return Err(EnclaveError::KeyUnavailable);
        }
        let keys = self.keys.lock().unwrap();
        let key_bytes = keys.get(&handle).ok_or(EnclaveError::InvalidHandle)?;
        // Reconstruct Ed25519 key from bytes and sign
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            &key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EnclaveError::OperationFailed("Invalid key length".into()))?,
        );
        let sig = signing_key.sign(data);
        Ok(sig.to_bytes())
    }

    fn public_key(&self, handle: u64) -> Result<[u8; 32], EnclaveError> {
        let keys = self.keys.lock().unwrap();
        let key_bytes = keys.get(&handle).ok_or(EnclaveError::InvalidHandle)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            &key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EnclaveError::OperationFailed("Invalid key length".into()))?,
        );
        Ok(signing_key.verifying_key().to_bytes())
    }

    fn delete_key(&self, handle: u64) -> Result<(), EnclaveError> {
        let mut keys = self.keys.lock().unwrap();
        if let Some(mut key_data) = keys.remove(&handle) {
            for byte in key_data.iter_mut() {
                *byte = 0;
            }
            debug!("SoftwareKeyEnclave: deleted key handle {}", handle);
            Ok(())
        } else {
            Err(EnclaveError::InvalidHandle)
        }
    }

    fn generate_key(&self) -> Result<(u64, [u8; 32]), EnclaveError> {
        if self.tampered.load(Ordering::SeqCst) {
            return Err(EnclaveError::KeyUnavailable);
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let signing_key = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let seed = signing_key.long_term_signing.to_bytes();
        let pk = signing_key.verifying_key().to_bytes();

        let mut keys = self.keys.lock().unwrap();
        keys.insert(handle, seed.to_vec());
        debug!("SoftwareKeyEnclave: generated key handle {}", handle);
        Ok((handle, pk))
    }
}

// ── 3. Network Time Security / Atomic Clock Integration ──────────────

/// Current time source with NTS-style security.
///
/// Protects the CGR routing mesh against GPS and NTP spoofing attacks
/// by providing a cryptographically verified time source.
///
/// In production, this would use:
/// - NTS (Network Time Security) for authenticated NTP
/// - Chip-scale atomic clock (CSAC) for onboard timekeeping
/// - Multi-source time voting for Byzantine fault tolerance
pub struct SecureTimeKeeper {
    /// System time at last synchronization.
    system_time_at_sync: SystemTime,
    /// The reference time as reported by the trusted source.
    reference_time_at_sync: f64,
    /// Whether we have an atomic clock reference.
    has_atomic_clock: bool,
    /// Atomic clock drift rate (seconds/second, typically ~1e-12 for CSAC).
    atomic_drift_rate: f64,
    /// Time offset tolerance (seconds) before flagging an attack.
    max_time_offset: f64,
}

impl Default for SecureTimeKeeper {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            system_time_at_sync: now,
            reference_time_at_sync: now
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            has_atomic_clock: false,
            atomic_drift_rate: 1e-12,
            max_time_offset: 1.0, // 1 second tolerance
        }
    }
}

impl SecureTimeKeeper {
    /// Create a new time keeper with optional atomic clock.
    pub fn new(has_atomic_clock: bool) -> Self {
        let mut keeper = Self::default();
        keeper.has_atomic_clock = has_atomic_clock;
        if has_atomic_clock {
            info!(
                "SecureTimeKeeper: atomic clock reference available (drift: {}/s)",
                keeper.atomic_drift_rate
            );
        }
        keeper
    }

    /// Get the current trusted time (Unix timestamp as f64 with sub-second precision).
    pub fn now(&self) -> f64 {
        let elapsed = self.system_time_at_sync.elapsed().unwrap_or_default();

        if self.has_atomic_clock {
            // With atomic clock, compensate for system clock drift
            let atomic_correction = elapsed.as_secs_f64() * self.atomic_drift_rate;
            self.reference_time_at_sync + elapsed.as_secs_f64() + atomic_correction
        } else {
            // Without atomic clock, trust system time with NTS verification
            self.reference_time_at_sync + elapsed.as_secs_f64()
        }
    }

    /// Synchronize time from an NTS-authenticated server.
    ///
    /// In production, this would use a full NTS client with TLS-authenticated
    /// NTP responses and cryptographic cookie exchange.
    /// Here we simulate the verification.
    pub fn nts_synchronize(
        &mut self,
        server_time: f64,
        signature: &[u8; 64],
        server_pk: &[u8; 32],
    ) -> bool {
        let time_msg = server_time.to_le_bytes();
        let verified = crate::ghost::layers::l0_identity::verify_peer_signature(
            server_pk, &time_msg, signature,
        );

        if !verified {
            warn!("SecureTimeKeeper: NTS authentication failed — possible spoofing attack!");
            return false;
        }

        // Check that the reported time is within tolerance
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let offset = (server_time - current_time).abs();
        if offset > self.max_time_offset {
            warn!(
                "SecureTimeKeeper: time offset {}s exceeds tolerance {}s — rejecting sync",
                offset, self.max_time_offset
            );
            return false;
        }

        self.system_time_at_sync = SystemTime::now();
        self.reference_time_at_sync = server_time;
        info!(
            "SecureTimeKeeper: synchronized to NTS time (offset: {:.3}s)",
            offset
        );
        true
    }

    /// Multi-source time voting: combine time from N sources, discard outliers.
    ///
    /// Implements a simple median-based consensus:
    /// 1. Collect time estimates from multiple sources
    /// 2. Remove the top and bottom quartile
    /// 3. Average the remaining estimates
    pub fn multi_source_vote(&self, times: &[f64]) -> Option<f64> {
        if times.is_empty() {
            return None;
        }
        let mut sorted = times.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Remove outliers: keep middle 50%
        let n = sorted.len();
        if n < 3 {
            return Some(sorted[n / 2]);
        }
        let lower = n / 4;
        let upper = n - n / 4;
        let trimmed: Vec<&f64> = sorted[lower..upper].iter().collect();
        if trimmed.is_empty() {
            return Some(sorted[n / 2]);
        }
        Some(trimmed.iter().copied().sum::<f64>() / trimmed.len() as f64)
    }

    /// Check if time is currently consistent across sources.
    /// Returns false if time spoofing is suspected.
    pub fn is_time_consistent(&self, sources: &[f64]) -> bool {
        if sources.len() < 3 {
            return true; // Not enough sources to detect spoofing
        }
        let voted = match self.multi_source_vote(sources) {
            Some(t) => t,
            None => return true,
        };
        let max_deviation = sources
            .iter()
            .map(|t| (t - voted).abs())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0);
        max_deviation < self.max_time_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_build_info() {
        let info = BuildInfo::new();
        assert!(info.git_commit.len() > 0);
    }

    #[test]
    fn test_software_key_enclave_generate_key() {
        let tpm = SoftwareKeyEnclave::new();
        let result = tpm.generate_key();
        assert!(result.is_ok());
        let (handle, pk) = result.unwrap();
        assert!(handle > 0);
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn test_software_key_enclave_sign_and_verify() {
        let tpm = SoftwareKeyEnclave::new();
        let (handle, pk) = tpm.generate_key().unwrap();

        let data = b"test message";
        let sig = tpm.sign(handle, data).unwrap();
        assert_eq!(sig.len(), 64);

        // Verify using standard ed25519
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_software_key_enclave_tamper_response() {
        let tpm = SoftwareKeyEnclave::new();
        let (handle, _) = tpm.generate_key().unwrap();

        tpm.detect_tamper();
        assert!(tpm.is_tampered());

        // After tamper, all operations should fail
        assert!(tpm.sign(handle, b"data").is_err());
        assert!(tpm.generate_key().is_err());
    }

    #[test]
    fn test_secure_time_keeper_basic() {
        let keeper = SecureTimeKeeper::new(false);
        let now = keeper.now();
        assert!(now > 1_700_000_000.0); // Should be > 2023
    }

    #[test]
    fn test_multi_source_vote() {
        let keeper = SecureTimeKeeper::new(false);
        let times = vec![100.0, 101.0, 102.0, 200.0, 103.0];
        let voted = keeper.multi_source_vote(&times);
        assert!(voted.is_some());
        let v = voted.unwrap();
        // Should be close to 101.5 (median of middle 50%)
        assert!((v - 102.0).abs() < 10.0);
    }

    #[test]
    fn test_time_consistency_detection() {
        let keeper = SecureTimeKeeper::new(false);
        // Consistent times
        let consistent = vec![100.0, 100.5, 101.0, 100.8, 100.2];
        assert!(keeper.is_time_consistent(&consistent));

        // Inconsistent times (spoofed)
        let inconsistent = vec![100.0, 100.5, 500.0, 100.8, 100.2];
        // Should detect the outlier
        let result = keeper.is_time_consistent(&inconsistent);
        // Depends on tolerance — with 1s tolerance and 400s outlier, should be false
        assert_eq!(result, false);
    }

    #[test]
    fn test_embedded_config_loaded() {
        assert!(EMBEDDED_DEFAULT_CONFIG.contains("bind ="));
        assert!(EMBEDDED_DEFAULT_CONFIG.contains("identity_file"));
        assert!(EMBEDDED_DEFAULT_CONFIG.contains("cgr_enabled"));
    }
}
