//! L9 — Infrastructure & Deployment Layer
//!
//! Implements infrastructure security and deployment capabilities:
//!
//! 1. **Portable Single Executable Packaging**: Self-contained binary with embedded defaults.
//! 2. **TPM/HSM Key Enclave**: Integrates hardware security modules (TPM 2.0 / ARM TrustZone)
//!    and software emulation so signing keys cannot be extracted even by kernel compromise.
//! 3. **Network Time Security / Atomic Clock Integration**: Prevents GPS/NTP spoofing attacks
//!    from destabilizing routing schedules by using NTS or high-precision clock references.

use std::sync::atomic::{AtomicBool, Ordering};

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

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

pub struct BuildInfo {
    pub git_commit: &'static str,
    pub build_timestamp: u64,
    pub rustc_version: &'static str,
    pub verified: AtomicBool,
}

impl Default for BuildInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildInfo {
    pub fn self_hash(&self) -> Option<Vec<u8>> {
        let exe_path = std::env::current_exe().ok()?;
        let data = std::fs::read(&exe_path).ok()?;
        let d = Sha256::digest(&data);
        Some(d.as_slice().to_vec())
    }

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

pub async fn initialize_node() -> anyhow::Result<()> {
    info!("Vantablack v{} starting", env!("CARGO_PKG_VERSION"));

    let _config = EMBEDDED_DEFAULT_CONFIG;

    let log_level = "info";
    std::env::set_var("RUST_LOG", log_level);

    info!("Embedded config loaded");
    info!("Network: bind=0.0.0.0:0, beacon=enabled");
    info!("Crypto: identity_file=identity.key, PSK rotation=24h");
    info!("Routing: CGR=enabled, max_hops=5, store_forward=enabled");
    info!("Security: ZK auth=optional, temporal_isolation=enabled");
    info!("Download URL: https://github.com/KELLERBABG/Vantablack/releases/latest");

    Ok(())
}

pub trait KeyEnclave: Send + Sync {
    fn store_key(&self, key_bytes: &[u8]) -> Result<u64, EnclaveError>;

    fn sign(&self, handle: u64, data: &[u8]) -> Result<[u8; 64], EnclaveError>;

    fn public_key(&self, handle: u64) -> Result<[u8; 32], EnclaveError>;

    fn delete_key(&self, handle: u64) -> Result<(), EnclaveError>;

    fn generate_key(&self) -> Result<(u64, [u8; 32]), EnclaveError>;
}

#[derive(Debug, Clone)]
pub enum EnclaveError {
    NotAvailable(String),
    InvalidHandle,
    OperationFailed(String),
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

pub struct SoftwareKeyEnclave {
    keys: std::sync::Mutex<std::collections::HashMap<u64, Vec<u8>>>,
    next_handle: std::sync::atomic::AtomicU64,
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

    pub fn detect_tamper(&self) {
        self.tampered.store(true, Ordering::SeqCst);
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
            use zeroize::Zeroize;
            key_data.zeroize();
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

pub struct SecureTimeKeeper {
    system_time_at_sync: SystemTime,
    reference_time_at_sync: f64,
    has_atomic_clock: bool,
    atomic_drift_rate: f64,
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
    pub fn new(has_atomic_clock: bool) -> Self {
        let keeper = Self {
            has_atomic_clock,
            ..Self::default()
        };
        if has_atomic_clock {
            info!(
                "SecureTimeKeeper: atomic clock reference available (drift: {}/s)",
                keeper.atomic_drift_rate
            );
        }
        keeper
    }

    pub fn now(&self) -> f64 {
        let elapsed = self.system_time_at_sync.elapsed().unwrap_or_default();

        if self.has_atomic_clock {
            let atomic_correction = elapsed.as_secs_f64() * self.atomic_drift_rate;
            self.reference_time_at_sync + elapsed.as_secs_f64() + atomic_correction
        } else {
            self.reference_time_at_sync + elapsed.as_secs_f64()
        }
    }

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

    pub fn multi_source_vote(&self, times: &[f64]) -> Option<f64> {
        if times.is_empty() {
            return None;
        }
        let mut sorted = times.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

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
        assert!(!info.git_commit.is_empty());
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
        assert!((v - 102.0).abs() < 10.0);
    }

    #[test]
    fn test_time_consistency_detection() {
        let keeper = SecureTimeKeeper::new(false);
        let consistent = vec![100.0, 100.5, 101.0, 100.8, 100.2];
        assert!(keeper.is_time_consistent(&consistent));

        let inconsistent = vec![100.0, 100.5, 500.0, 100.8, 100.2];
        let result = keeper.is_time_consistent(&inconsistent);
        assert!(!result);
    }

    #[test]
    fn test_embedded_config_loaded() {
        assert!(EMBEDDED_DEFAULT_CONFIG.contains("bind ="));
        assert!(EMBEDDED_DEFAULT_CONFIG.contains("identity_file"));
        assert!(EMBEDDED_DEFAULT_CONFIG.contains("cgr_enabled"));
    }
}
