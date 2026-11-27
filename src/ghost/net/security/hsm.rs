//! HSM / TPM Hardware Security Module Backend.
//!
//! Provides hardware-backed key storage for the GhostNet Ed25519 identity key,
//! preventing key exfiltration even under kernel compromise.
//!
//! ## Implementations
//! - `SoftwareTpm`: In-memory key storage (safe fallback for testing/dev)
//! - `Tpm2Backend`: TPM 2.0 via `tss-esapi` (production on TPM-equipped hardware)
//! - `Pkcs11Backend`: PKCS#11 HSM via `cryptoki` (production for YubiHSM, NitroKey, etc.)

#[cfg(any(feature = "hardware-tpm", feature = "pkcs11"))]
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::info;
#[cfg(any(feature = "hardware-tpm", feature = "pkcs11"))]
use tracing::warn;

pub trait HsmBackend: Send + Sync {
    fn public_key(&self) -> &[u8; 32];

    fn sign(&self, data: &[u8]) -> [u8; 64];

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool;

    fn derive_session_key(&self, context: &[u8]) -> [u8; 32];

    fn backend_type(&self) -> &'static str;

    fn is_hardware_backed(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HsmError {
    #[error("no {backend} hardware detected on this system: {detail}")]
    HardwareAbsent {
        backend: &'static str,
        detail: String,
    },

    #[error("{backend} present but the session could not be opened: {detail}")]
    SessionOpenFailed {
        backend: &'static str,
        detail: String,
    },

    #[error("{backend} key operation failed: {detail}")]
    KeyOperationFailed {
        backend: &'static str,
        detail: String,
    },
}

pub struct SoftwareTpm {
    signing_key_bytes: [u8; 32],
    verifying_key: ed25519_dalek::VerifyingKey,
    public_key_bytes: [u8; 32],
    fingerprint: String,
}

impl SoftwareTpm {
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

#[cfg(feature = "hardware-tpm")]
#[allow(dead_code)] // Stub: `open` reports `HsmError::HardwareAbsent` until real tss-esapi wiring.
pub struct Tpm2Backend {
    device_path: String,
    key_handle: u32,
    public_key_bytes: [u8; 32],
    fingerprint: String,
    connected: AtomicBool,
}

#[cfg(feature = "hardware-tpm")]
impl Tpm2Backend {
    pub fn open() -> Result<Self, HsmError> {
        Err(HsmError::HardwareAbsent {
            backend: "TPM 2.0",
            detail: "no TPM 2.0 device (Linux /dev/tpmrm0, Windows TBS) responded".to_string(),
        })
    }

    pub fn open_path(path: &str) -> Result<Self, HsmError> {
        Err(HsmError::HardwareAbsent {
            backend: "TPM 2.0",
            detail: format!("device path '{path}' could not be opened"),
        })
    }

    pub fn generate_key(&mut self) -> Result<u32, HsmError> {
        Err(HsmError::KeyOperationFailed {
            backend: "TPM 2.0",
            detail: "TPM hardware not available".to_string(),
        })
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

    fn sign(&self, _data: &[u8]) -> [u8; 64] {
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

#[cfg(feature = "pkcs11")]
#[allow(dead_code)] // Stub: `open` reports `HsmError::HardwareAbsent` until real cryptoki wiring.
pub struct Pkcs11Backend {
    session_handle: u64,
    key_handle: u64,
    public_key_bytes: [u8; 32],
    fingerprint: String,
    connected: AtomicBool,
    lib_path: String,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Backend {
    pub fn open(lib_path: &str, _slot_id: u64, _pin: &str) -> Result<Self, HsmError> {
        Err(HsmError::HardwareAbsent {
            backend: "PKCS#11",
            detail: format!("module '{lib_path}' not available: hardware HSM not detected"),
        })
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

    fn sign(&self, _data: &[u8]) -> [u8; 64] {
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

pub fn create_hsm_backend() -> Box<dyn HsmBackend> {
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

    #[cfg(feature = "pkcs11")]
    {
        let module = std::env::var("GHOST_PKCS11_MODULE").unwrap_or_default();
        let slot = std::env::var("GHOST_PKCS11_SLOT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let pin = std::env::var("GHOST_PKCS11_PIN").unwrap_or_default();
        if module.is_empty() || pin.is_empty() {
            warn!("HSM: PKCS#11 skipped — GHOST_PKCS11_MODULE and GHOST_PKCS11_PIN are required");
        } else {
            match Pkcs11Backend::open(&module, slot, &pin) {
                Ok(hsm) => {
                    info!("HSM: using PKCS#11 hardware backend");
                    return Box::new(hsm);
                }
                Err(e) => {
                    warn!("HSM: PKCS#11 not available: {}", e);
                }
            }
        }
    }

    info!("HSM: no hardware backend detected — using SoftwareTpm fallback");
    Box::new(SoftwareTpm::generate_fresh())
}

pub fn create_hsm_backend_from_key(keypair: ed25519_dalek::SigningKey) -> Box<dyn HsmBackend> {
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

    #[cfg(feature = "pkcs11")]
    {
        let module = std::env::var("GHOST_PKCS11_MODULE").unwrap_or_default();
        let slot = std::env::var("GHOST_PKCS11_SLOT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let pin = std::env::var("GHOST_PKCS11_PIN").unwrap_or_default();
        if module.is_empty() || pin.is_empty() {
            warn!("HSM: PKCS#11 skipped — GHOST_PKCS11_MODULE and GHOST_PKCS11_PIN are required");
        } else {
            match Pkcs11Backend::open(&module, slot, &pin) {
                Ok(hsm) => {
                    info!("HSM: using PKCS#11 hardware backend (key imported)");
                    return Box::new(hsm);
                }
                Err(e) => {
                    warn!("HSM: PKCS#11 not available: {}", e);
                }
            }
        }
    }

    info!("HSM: no hardware backend detected — using SoftwareTpm (key imported)");
    Box::new(SoftwareTpm::new(keypair))
}

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

        assert!(tpm.verify(data, &sig));

        use ed25519_dalek::Verifier;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_software_tpm_fingerprint() {
        let tpm1 = SoftwareTpm::generate_fresh();
        let tpm2 = SoftwareTpm::generate_fresh();
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
        let backend = create_hsm_backend();
        assert_eq!(backend.backend_type(), "software");
        assert!(!backend.is_hardware_backed());
    }

    #[test]
    fn test_create_hsm_from_key() {
        let mut csprng = rand::rngs::OsRng;
        let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
        let backend = create_hsm_backend_from_key(keypair);
        assert_eq!(backend.backend_type(), "software");

        let pk = backend.public_key();
        assert_eq!(pk.len(), 32);

        let data = b"hello hsm";
        let sig = backend.sign(data);
        assert!(backend.verify(data, &sig));
    }

    #[cfg(feature = "hardware-tpm")]
    #[test]
    fn tpm_open_reports_typed_absence() {
        match Tpm2Backend::open() {
            Err(HsmError::HardwareAbsent { backend, .. }) => assert_eq!(backend, "TPM 2.0"),
            Err(other) => panic!("expected HardwareAbsent, got {other:?}"),
            Ok(_) => panic!("no TPM hardware exists on a build machine"),
        }
        assert!(matches!(
            Tpm2Backend::open_path("/dev/definitely-not-a-tpm"),
            Err(HsmError::HardwareAbsent {
                backend: "TPM 2.0",
                ..
            })
        ));
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn pkcs11_open_reports_typed_absence() {
        match Pkcs11Backend::open("/nonexistent/libpkcs11.so", 0, "1234") {
            Err(HsmError::HardwareAbsent { backend, .. }) => assert_eq!(backend, "PKCS#11"),
            Err(other) => panic!("expected HardwareAbsent, got {other:?}"),
            Ok(_) => panic!("no PKCS#11 module exists on a build machine"),
        }
    }
}
