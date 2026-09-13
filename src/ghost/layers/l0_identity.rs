use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
/// L0 — Ed25519 Identity Layer
///
/// The permanent cryptographic identity of a GhostNet node.
/// Each device generates a fresh Ed25519 keypair at startup.
/// The public key serves as the node's fingerprint, and the
/// private key is used to sign handshake key material (Layer 1)
/// to prove authorship and prevent key substitution attacks.
///
/// Signature format: 64 bytes (Ed25519)
/// Public key size: 32 bytes
/// Fingerprint: first 8 bytes of public key (hex-encoded)
use std::fs;
use std::path::Path;

/// Default filename for the persistent Ed25519 identity key.
pub const IDENTITY_FILE: &str = "identity.key";

/// Environment variable that overrides [`IDENTITY_FILE`].
pub const IDENTITY_FILE_ENV: &str = "GHOST_IDENTITY_FILE";

/// Resolve the identity-key path for this process.
///
/// `GHOST_IDENTITY_FILE` overrides the default. Without an override, two nodes
/// launched from the same working directory load the same key and therefore
/// advertise the same fingerprint — an operational trap for the two-node smoke
/// test (PROTOTYPE.md flaw #6), and the reason the test suite raced over a
/// single `identity.key`.
pub fn identity_file_path() -> String {
    std::env::var(IDENTITY_FILE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| IDENTITY_FILE.to_string())
}

/// A GhostNet identity backed by an Ed25519 signing key.
pub struct GhostIdentity {
    /// The long-term signing key (private). Never leaves the device.
    pub long_term_signing: SigningKey,
}

impl GhostIdentity {
    /// Generate a fresh identity with random entropy.
    pub fn generate_fresh() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            long_term_signing: signing_key,
        }
    }

    /// Load identity from a file, or generate a fresh one and save it.
    pub fn load_or_generate(path: &str) -> Self {
        if Path::new(path).exists() {
            match fs::read(path) {
                Ok(data) if data.len() == 32 => {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&data);
                    let signing_key = SigningKey::from_bytes(&seed);
                    return Self {
                        long_term_signing: signing_key,
                    };
                }
                _ => {
                    eprintln!("Corrupted identity file at {}, generating fresh key", path);
                }
            }
        }
        let identity = Self::generate_fresh();
        let seed = identity.long_term_signing.to_bytes();
        let write_res = {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)
                    .and_then(|mut file| file.write_all(&seed))
            }
            #[cfg(not(unix))]
            {
                fs::write(path, seed)
            }
        };
        if let Err(e) = write_res {
            eprintln!("Warning: could not save identity to {}: {}", path, e);
        } else {
            eprintln!("Saved new identity to {}", path);
        }
        identity
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.long_term_signing.verifying_key()
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// Compute the human-readable fingerprint (first 8 bytes hex).
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.public_key_bytes()[0..8])
    }

    /// Sign arbitrary data with the identity key.
    /// Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.long_term_signing.sign(data)
    }

    /// Verify a signature against this identity's public key.
    pub fn verify(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.verifying_key().verify(data, signature)
    }
}

/// Verify a signature from a peer's public key bytes.
pub fn verify_peer_signature(peer_pk_bytes: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
    if let Ok(peer_pk) = VerifyingKey::from_bytes(peer_pk_bytes) {
        let sig = Signature::from_bytes(signature);
        return peer_pk.verify(data, &sig).is_ok();
    }
    false
}
