use crate::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Encrypt plaintext with AES-256-GCM
/// Returns (nonce, ciphertext) where nonce is 12 bytes
pub fn encrypt_aes256(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::CryptoError(format!("AES key setup: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::CryptoError(format!("AES encryption: {}", e)))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt AES-256-GCM ciphertext
pub fn decrypt_aes256(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::CryptoError(format!("AES key setup: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| Error::CryptoError(format!("AES decryption: {}", e)))?;

    Ok(plaintext)
}

/// Derive a 32-byte key from a shared secret and salt using HMAC-SHA256
pub fn derive_key(shared_secret: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut mac: HmacSha256 = Mac::new_from_slice(shared_secret).expect("HMAC key length is valid");
    mac.update(salt);
    let result = mac.finalize();
    let code = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&code);
    output
}

/// Generate a random 32-byte seed using OS entropy
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Hash a public key to a NodeId using SHA-256
pub fn node_id_from_public_key(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&result);
    node_id
}

/// Compute HMAC-SHA256 for shard verification
type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac: HmacSha256 = Mac::new_from_slice(key).expect("HMAC key length is valid");
    mac.update(data);
    let result = mac.finalize();
    let code = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&code);
    output
}
