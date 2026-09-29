use abos_common::crypto;
use abos_common::error::{Error, Result};
use abos_common::types::*;

/// Create a DTN bundle from payload data
pub fn create_bundle(payload: &[u8], source: NodeId, lifetime: u64) -> Bundle {
    let bundle_id = crypto::hmac_sha256(b"bundle", payload);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Bundle {
        bundle_id,
        source_node: source,
        creation_timestamp: timestamp,
        lifetime_seconds: lifetime,
        payload: payload.to_vec(),
        hop_count: 0,
        ttl: lifetime as u32,
    }
}

/// Serialize a bundle to bytes using bincode
pub fn serialize_bundle(bundle: &Bundle) -> Result<Vec<u8>> {
    bincode::serialize(bundle).map_err(|e| Error::ProtocolError(format!("Serialization: {}", e)))
}

/// Deserialize a bundle from bytes
pub fn deserialize_bundle(data: &[u8]) -> Result<Bundle> {
    bincode::deserialize(data).map_err(|e| Error::ProtocolError(format!("Deserialization: {}", e)))
}

/// Check if a bundle has expired
pub fn is_bundle_expired(bundle: &Bundle) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > bundle.creation_timestamp + bundle.lifetime_seconds
}

/// Encrypt bundle payload with AES-256-GCM
pub fn encrypt_bundle(key: &[u8; 32], bundle: &mut Bundle) -> Result<()> {
    let (nonce, ciphertext) = crypto::encrypt_aes256(key, &bundle.payload)?;
    // Store nonce + ciphertext in payload
    bundle.payload = [nonce.as_slice(), ciphertext.as_slice()].concat();
    Ok(())
}

/// Decrypt bundle payload
pub fn decrypt_bundle(key: &[u8; 32], bundle: &mut Bundle) -> Result<()> {
    if bundle.payload.len() < 12 {
        return Err(Error::CryptoError("Bundle too short for decryption".into()));
    }
    let (nonce, ciphertext) = bundle.payload.split_at(12);
    let plaintext = crypto::decrypt_aes256(key, nonce, ciphertext)?;
    bundle.payload = plaintext;
    Ok(())
}
