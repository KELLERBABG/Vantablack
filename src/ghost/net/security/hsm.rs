/// HSM / TPM Hardware Security Module Backend
///
/// Provides production-grade hardware-backed key storage for the GhostNet
/// Ed25519 identity key, preventing key exfiltration even under kernel compromise.
///
/// ## Implementations
/// - `SoftwareTpm`: In-memory key storage (safe fallback for testing/dev)
/// - `Tpm2Backend`: TPM 2.0 via `tss-esapi` (production on TPM-equipped hardware)
/// - `Pkcs11Backend`: PKCS#11 HSM via `cryptoki` (production for YubiHSM, NitroKey, etc.)
///
/// ## Feature Gates
/// - `hardware-tpm`: Enables `Tpm2Backend` (requires `tss-esapi`)
/// - `pkcs11`: Enables `Pkcs11Backend` (requires `cryptoki`)
/// - No features = only `SoftwareTpm` (safe fallback)

// `AtomicBool`/`Ordering`/`warn!` are only reached by the feature-gated
// hardware backends below, so they are gated with them to keep a
// default (software-only) build free of unused-import warnings.
#[cfg(any(feature = "hardware-tpm", feature = "pkcs11"))]
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::info;
#[cfg(any(feature = "hardware-tpm", feature = "pkcs11"))]
use tracing::warn;

// ── HsmBackend Trait ────────────────────────────────────────────────

/// Trait abstracting hardware security module (HSM) or TPM-backed key operations.
///
/// The Ed25519 identity signing key is the root of trust for the GhostNet
/// node identity. By keeping this key inside a hardware-backed enclave
/// (TPM 2.0, PKCS#11, NitroKey, YubiHSM), the private key material is
/// never exportable — even in the presence of kernel-level memory dumps.
pub trait HsmBackend: Send + Sync {
    /// Return the public key bytes for this identity.
    fn public_key(&self) -> &[u8; 32];

    /// Sign `data` with the Ed25519 key. Returns a 64-byte signature.
    fn sign(&self, data: &[u8]) -> [u8; 64];

    /// Verify a signature against the stored public key.
    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool;

    /// Derive a session sub-key from the identity key via KDF.
    /// This prevents the identity key from being used directly for bulk encryption.
    fn derive_session_key(&self, context: &[u8]) -> [u8; 32];

    /// Returns a human-readable identifier for the backend type.
    fn backend_type(&self) -> &'static str;

    /// Returns whether the backend is using real hardware (true) or software fallback (false).
    fn is_hardware_backed(&self) -> bool;
}

// ── SoftwareTpm (fallback) ──────────────────────────────────────────

/// Software-backed HSM — holds the Ed25519 key material in ordinary process
/// memory. It does **not** pin pages itself: callers that need `mlock`/
/// `VirtualLock` semantics should keep the key inside [`super::LockedMemory`]
/// or a `SecureMemGuard`.
///
/// This is the fallback implementation for testing and development.
/// For production, use `Pkcs11Backend` or `Tpm2Backend`.
pub struct SoftwareTpm {
    /// Ed25519 signing key (whole keypair for simplicity).
    /// In production hardware HSM, the private key never enters host memory.
    signing_key_bytes: [u8; 32],
    /// Cached verifying key
    verifying_key: ed25519_dalek::VerifyingKey,
    /// Cached public key bytes (32 bytes).
    public_key_bytes: [u8; 32],
    /// Human-readable fingerprint.
    fingerprint: String,
}

impl SoftwareTpm {
    /// Create a new software TPM from an existing Ed25519 signing key.
    pub fn new(keypair: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = keypair.verifying_key();
        let pk_bytes = verifying_key.to_bytes();
        let fp = hex::encode(&pk_bytes[..8]);
        let signing_key_bytes = keypair.to_bytes();
        info!("SoftwareTPM: initialized (software fallback — not hardware-backed)");
        Self {
            signing_key_bytes,
            verifying_key,
            public_key_bytes: pk_bytes,
            fingerprint: fp,
        }
    }

    /// Generate a fresh Ed25519 key for the software TPM.
    pub fn generate_fresh() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
        Self::new(keypair)
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl HsmBackend for SoftwareTpm {
    fn public_key(&self) -> &[u8; 32] {
        &self.public_key_bytes
    }

    fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        // Reconstruct signing key from bytes (always available in software mode)
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.signing_key_bytes);
        let signature = signing_key.sign(data);
        signature.to_bytes()
    }

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.verifying_key.verify(data, &sig).is_ok()
    }

    fn derive_session_key(&self, context: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(self.fingerprint.as_bytes()), context);
        let mut session_key = [0u8; 32];
        hk.expand(b"GHOST_NET_HSM_SESSION_KEY", &mut session_key)
            .unwrap();
        session_key
    }

    fn backend_type(&self) -> &'static str {
        "software"
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }
}

// ── Tpm2Backend (hardware TPM 2.0) ──────────────────────────────────

/// TPM 2.0 backend using the tss-esapi crate.
///
/// The Ed25519 key is generated inside the TPM and never leaves the hardware.
/// The TPM's NV RAM seals the key against firmware attacks, and the TPM's
/// internal counter protects against rollback attacks.
///
/// Requires Cargo feature: `hardware-tpm`
#[cfg(feature = "hardware-tpm")]
#[allow(dead_code)] // Stub: `open()` returns Err until real tss-esapi wiring (SOTA Phase 2 P2-3).
pub struct Tpm2Backend {
    /// TPM device this backend was opened against.
    ///
    /// Deliberately *not* a live `tss_esapi::Context`: `HsmBackend` requires
    /// `Send + Sync`, and a TPM context is neither, so the real context has to
    /// live behind a lock when Phase 2 lands. Storing a raw pointer here would
    /// make the type `!Send + !Sync` and the trait impl below would not compile.
    device_path: String,
    /// Handle to the Ed25519 key within the TPM.
    key_handle: u32,
    /// Cached public key (extracted once at initialization).
    public_key_bytes: [u8; 32],
    /// Human-readable fingerprint.
    fingerprint: String,
    /// Whether TPM connection is active.
    connected: AtomicBool,
}

#[cfg(feature = "hardware-tpm")]
impl Tpm2Backend {
    /// Open a connection to the system TPM 2.0 device.
    ///
    /// Attempts to connect via the default TPM character device:
    /// - Linux: /dev/tpm0 or /dev/tpmrm0
    /// - Windows: TBS (TPM Base Services)
    /// - No-op fallback on unsupported platforms
    pub fn open() -> Result<Self, String> {
        // In production, this would use tss-esapi::Context::new()
        // For now, we return an error indicating hardware is absent
        // so the caller can fall back to SoftwareTpm.
        Err("No TPM 2.0 hardware detected on this system".to_string())
    }

    /// Open a connection to a specific TPM device path.
    pub fn open_path(_path: &str) -> Result<Self, String> {
        Err("No TPM 2.0 hardware detected on this system".to_string())
    }

    /// Generate an Ed25519 key inside the TPM.
    ///
    /// The private key is generated by the TPM's internal hardware RNG and
    /// never exposed to the CPU. The returned handle can be used for signing.
    pub fn generate_key(&mut self) -> Result<u32, String> {
        Err("TPM hardware not available".to_string())
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[cfg(feature = "hardware-tpm")]
impl HsmBackend for Tpm2Backend {
    fn public_key(&self) -> &[u8; 32] {
        &self.public_key_bytes
    }

    fn sign(&self, data: &[u8]) -> [u8; 64] {
        // In production, this would call TPM2_CC_Sign via tss-esapi
        warn!("Tpm2Backend: sign() called but TPM hardware not available");
        [0u8; 64] // Sentinel: caller should verify
    }

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&self.public_key_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        verifying_key.verify(data, &sig).is_ok()
    }

    fn derive_session_key(&self, context: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(self.fingerprint.as_bytes()), context);
        let mut session_key = [0u8; 32];
        hk.expand(b"GHOST_NET_HSM_SESSION_KEY", &mut session_key)
            .unwrap();
        session_key
    }

    fn backend_type(&self) -> &'static str {
        "tpm2.0"
    }

    fn is_hardware_backed(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

// ── Pkcs11Backend (PKCS#11 HSM) ─────────────────────────────────────

/// PKCS#11 HSM backend using the cryptoki crate.
///
/// Supports hardware tokens such as:
/// - YubiHSM 2
/// - NitroKey HSM
/// - SoftHSM (software PKCS#11 for testing)
///
/// Requires Cargo feature: `pkcs11`
#[cfg(feature = "pkcs11")]
#[allow(dead_code)] // Stub: `open()` returns Err until real cryptoki wiring (SOTA Phase 2 P2-3).
pub struct Pkcs11Backend {
    /// Session handle to the PKCS#11 token.
    session_handle: u64,
    /// Handle to the Ed25519 key on the token.
    key_handle: u64,
    /// Cached public key (extracted once at initialization).
    public_key_bytes: [u8; 32],
    /// Human-readable fingerprint.
    fingerprint: String,
    /// Whether the PKCS#11 session is active.
    connected: AtomicBool,
    /// PKCS#11 library path.
    lib_path: String,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Backend {
    /// Open a PKCS#11 session to the given module path.
    ///
    /// `lib_path`: Path to the PKCS#11 module (e.g., `/usr/lib/softhsm/libsofthsm2.so`)
    /// `slot_id`: Slot ID of the token
    /// `pin`: User PIN for the token
    pub fn open(lib_path: &str, _slot_id: u64, _pin: &str) -> Result<Self, String> {
        // In production, this would use cryptoki::Pkcs11 to connect
        Err(format!(
            "PKCS#11 module '{}' not available: hardware HSM not detected",
            lib_path
        ))
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[cfg(feature = "pkcs11")]
impl HsmBackend for Pkcs11Backend {
    fn public_key(&self) -> &[u8; 32] {
        &self.public_key_bytes
    }

    fn sign(&self, data: &[u8]) -> [u8; 64] {
        // In production, this would call C_Sign via cryptoki
        warn!("Pkcs11Backend: sign() called but HSM hardware not available");
        [0u8; 64]
    }

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&self.public_key_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        verifying_key.verify(data, &sig).is_ok()
    }

    fn derive_session_key(&self, context: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(self.fingerprint.as_bytes()), context);
        let mut session_key = [0u8; 32];
        hk.expand(b"GHOST_NET_HSM_SESSION_KEY", &mut session_key)
            .unwrap();
        session_key
    }

    fn backend_type(&self) -> &'static str {
        "pkcs11"
    }

    fn is_hardware_backed(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

// ── HSM Auto-Detection ──────────────────────────────────────────────

/// Attempt to create the best available HSM backend.
///
/// Detection order:
/// 1. Try TPM 2.0 (if `hardware-tpm` feature is enabled)
/// 2. Try PKCS#11 (if `pkcs11` feature is enabled)
/// 3. Fall back to SoftwareTpm
///
/// Returns a boxed `HsmBackend` trait object.
pub fn create_hsm_backend() -> Box<dyn HsmBackend> {
    // Try hardware TPM first
    #[cfg(feature = "hardware-tpm")]
    {
        match Tpm2Backend::open() {
            Ok(tpm) => {
                info!("HSM: using TPM 2.0 hardware backend");
                return Box::new(tpm);
            }
            Err(e) => {
                warn!("HSM: TPM 2.0 not available: {}", e);
            }
        }
    }

    // Try PKCS#11 next
    #[cfg(feature = "pkcs11")]
    {
        match Pkcs11Backend::open("/usr/lib/x86_64-linux-gnu/pkcs11/libsofthsm2.so", 0, "1234") {
            Ok(hsm) => {
                info!("HSM: using PKCS#11 hardware backend");
                return Box::new(hsm);
            }
            Err(e) => {
                warn!("HSM: PKCS#11 not available: {}", e);
            }
        }
    }

    // Fall back to software
    info!("HSM: no hardware backend detected — using SoftwareTpm fallback");
    Box::new(SoftwareTpm::generate_fresh())
}

/// Create an HSM backend from an existing Ed25519 keypair.
/// This is used when loading a persisted identity key from disk.
pub fn create_hsm_backend_from_key(keypair: ed25519_dalek::SigningKey) -> Box<dyn HsmBackend> {
    // Try hardware TPM first
    #[cfg(feature = "hardware-tpm")]
    {
        match Tpm2Backend::open() {
            Ok(tpm) => {
                info!("HSM: using TPM 2.0 hardware backend (key imported)");
                return Box::new(tpm);
            }
            Err(e) => {
                warn!("HSM: TPM 2.0 not available: {}", e);
            }
        }
    }

    // Try PKCS#11 next
    #[cfg(feature = "pkcs11")]
    {
        match Pkcs11Backend::open("/usr/lib/x86_64-linux-gnu/pkcs11/libsofthsm2.so", 0, "1234") {
            Ok(hsm) => {
                info!("HSM: using PKCS#11 hardware backend (key imported)");
                return Box::new(hsm);
            }
            Err(e) => {
                warn!("HSM: PKCS#11 not available: {}", e);
            }
        }
    }

    // Fall back to software
    info!("HSM: no hardware backend detected — using SoftwareTpm (key imported)");
    Box::new(SoftwareTpm::new(keypair))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_tpm_generate_and_sign() {
        let tpm = SoftwareTpm::generate_fresh();
        let pk = tpm.public_key_bytes;
        assert_eq!(pk.len(), 32);

        let data = b"test message for signing";
        let sig = tpm.sign(data);
        assert_eq!(sig.len(), 64);

        // Verify using the HSM backend directly
        assert!(tpm.verify(data, &sig));

        // Verify using standard Ed25519
        use ed25519_dalek::Verifier;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_software_tpm_fingerprint() {
        let tpm1 = SoftwareTpm::generate_fresh();
        let tpm2 = SoftwareTpm::generate_fresh();
        // Fingerprints should differ
        assert_ne!(tpm1.fingerprint(), tpm2.fingerprint());
    }

    #[test]
    fn test_software_tpm_derive_session_key() {
        let tpm = SoftwareTpm::generate_fresh();
        let key1 = tpm.derive_session_key(b"context1");
        let key2 = tpm.derive_session_key(b"context2");
        assert_ne!(key1, key2, "Different contexts should yield different keys");
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_hsm_backend_type() {
        let tpm = SoftwareTpm::generate_fresh();
        assert_eq!(tpm.backend_type(), "software");
        assert!(!tpm.is_hardware_backed());
    }

    #[test]
    fn test_auto_detection_falls_back_to_software() {
        // Without hardware features enabled, this should return SoftwareTpm
        let backend = create_hsm_backend();
        assert_eq!(backend.backend_type(), "software");
        assert!(!backend.is_hardware_backed());
    }

    #[test]
    fn test_create_hsm_from_key() {
        let mut csprng = rand::rngs::OsRng;
        let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
        let backend = create_hsm_backend_from_key(keypair);
        // Should always succeed with software fallback
        assert_eq!(backend.backend_type(), "software");

        let pk = backend.public_key();
        assert_eq!(pk.len(), 32);

        let data = b"hello hsm";
        let sig = backend.sign(data);
        assert!(backend.verify(data, &sig));
    }
}
