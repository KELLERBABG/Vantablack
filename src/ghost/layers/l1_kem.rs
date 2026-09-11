/// L1 — Hybrid Key Encapsulation Mechanism (KEM) Layer
///
/// Implements the hybrid classical + post-quantum key exchange:
///   X25519 (ECDH)  — Elliptic-curve Diffie-Hellman over Curve25519 (~128-bit classical security)
///   Kyber-512      — NIST-standardized post-quantum KEM based on MLWE
///
/// ## Out-of-Band Symmetric Key Mixing (Defense-in-Depth)
/// A continuously rotating 256-bit Pre-Shared Key (PSK) is mixed into the HKDF
/// derivation as an additional entropy source. This provides defense-in-depth
/// against future Kyber cryptanalysis: even if both X25519 and Kyber-512 are
/// broken, an attacker who has not captured the PSK channel cannot derive the
/// master key.
///
/// The PSK is mixed into the HKDF extract phase as additional salt:
///   master_key = HKDF-SHA256(salt = PSK || zeros, ikm = x25519_ss || kyber_ss)
///
/// PDU layout in the PQ-Exchange:
///   [0..16]   Magic bytes "GHOST_HANDSHAKE_"
///   [16..48]  X25519 public key (32 bytes)
///   [48..848] Kyber-512 public key (800 bytes)
///   [848..880] Ed25519 public key (32 bytes)  — L0 identity
///   [880..944] Ed25519 signature (64 bytes)   — L0 proof
///   Total: 944 bytes

use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use ml_kem::kem::{Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{DecapsulationKey512, EncapsulationKey, EncapsulationKey512, MlKem512};

/// The total size of the handshake PDU before sharding.
pub const HANDSHAKE_BLOB_LEN: usize = 944;

/// Derive the hybrid master key from both shared secrets via HKDF-SHA256.
///
/// If a PSK is provided (Some), it is mixed into the HKDF salt as an
/// additional entropy source for defense-in-depth against Kyber cryptanalysis.
/// If None, a zero salt is used for backward compatibility.
pub fn derive_hybrid_master_key(x25519_shared: &[u8; 32], kyber_shared: &[u8]) -> [u8; 32] {
    derive_hybrid_master_key_with_psk(x25519_shared, kyber_shared, None)
}

/// Derive the hybrid master key with optional PSK mixing.
///
/// The PSK is mixed into the HKDF salt phase:
///   salt = PSK || zeros_padding (32 bytes total)
///   master_key = HKDF-SHA256(salt, ikm = x25519_ss || kyber_ss)
///
/// This ensures that even if both X25519 and Kyber-512 are cryptographically
/// broken, an attacker without the PSK cannot derive the session key.
pub fn derive_hybrid_master_key_with_psk(
    x25519_shared: &[u8; 32],
    kyber_shared: &[u8],
    psk: Option<&[u8; 32]>,
) -> [u8; 32] {
    let salt = match psk {
        Some(key) => {
            // Use PSK as the HKDF salt
            *key
        }
        None => [0u8; 32],
    };

    let ikm = [x25519_shared.as_slice(), kyber_shared].concat();

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut master_key = [0u8; 32];
    hk.expand(b"GHOST_NET_MASTER_KEY_v2", &mut master_key).unwrap();
    master_key
}

/// Generate an X25519 ephemeral keypair.
pub fn generate_x25519_keypair() -> (EphemeralSecret, XPublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = XPublicKey::from(&secret);
    (secret, public)
}

/// Generate a Kyber-512 (ML-KEM-512) keypair.
pub fn generate_kyber_keypair() -> (EncapsulationKey512, DecapsulationKey512) {
    let (dk, ek) = MlKem512::generate_keypair();
    (ek, dk)
}

/// Encapsulate a shared secret with Kyber-512 (Bob side).
pub fn kyber_encapsulate(peer_pk: &[u8]) -> Result<([u8; 768], Vec<u8>), &'static str> {
    let ek = EncapsulationKey::<MlKem512>::new_from_slice(peer_pk)
        .map_err(|_| "Invalid Kyber public key")?;
    let (ct, ss) = ek.encapsulate();
    let ct_bytes: [u8; 768] = ct.into();
    Ok((ct_bytes, ss.as_slice().to_vec()))
}

/// Compute a truncated session hash (4 bytes) from the master key.
/// Used in the GTF header to link packets to their session.
pub fn compute_session_hash(key: &[u8; 32]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(key);
    let bytes = d.as_slice();
    let mut hash = [0u8; 4];
    hash.copy_from_slice(&bytes[..4]);
    hash
}

/// Build the 944-byte PQ-Exchange Handshake PDU.
pub fn build_handshake_pdu(
    identity_pk: &[u8; 32],
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &XPublicKey,
    kyber_pub: &EncapsulationKey512,
) -> Vec<u8> {
    let mut pdu = vec![0u8; HANDSHAKE_BLOB_LEN];
    pdu[0..16].copy_from_slice(b"GHOST_HANDSHAKE_");
    pdu[16..48].copy_from_slice(x_pub.as_bytes());
    pdu[48..848].copy_from_slice(&kyber_pub.to_bytes());
    pdu[848..880].copy_from_slice(identity_pk);

    let mut signed_material = vec![0u8; 832];
    signed_material[0..32].copy_from_slice(x_pub.as_bytes());
    signed_material[32..832].copy_from_slice(&kyber_pub.to_bytes());

    let sig = identity_sign(&signed_material);
    pdu[880..944].copy_from_slice(&sig);
    pdu
}

/// Parse a received handshake PDU into its components.
pub struct HandshakeBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_pub: [u8; 800],
    pub identity_pk: [u8; 32],
    pub signature: [u8; 64],
}

/// Parse the 944-byte handshake blob.
pub fn parse_handshake_pdu(data: &[u8]) -> Option<HandshakeBlob> {
    if data.len() < HANDSHAKE_BLOB_LEN || !data.starts_with(b"GHOST_HANDSHAKE_") {
        return None;
    }

    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[16..48]);

    let mut kyber_pub = [0u8; 800];
    kyber_pub.copy_from_slice(&data[48..848]);

    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&data[848..880]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[880..944]);

    Some(HandshakeBlob { x25519_pub, kyber_pub, identity_pk, signature })
}

pub const RESPONSE_BLOB_LEN: usize = 912; // 16 magic + 32 X25519 pub + 768 ct + 32 identity + 64 sig

/// Build a signed response PDU. Layout:
///   [0..16]   "GHOST_RESPONSE__"
///   [16..48]  Responder's X25519 public key
///   [48..816] Kyber-512 ciphertext (768 bytes)
///   [816..848] Responder's Ed25519 identity public key
///   [848..912] Ed25519 signature over (x_pub || ct)
pub fn build_response_pdu(
    responder_identity_pk: &[u8; 32],
    responder_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub_bytes: &[u8; 32],
    ct_bytes: &[u8; 768],
) -> Vec<u8> {
    let mut pdu = vec![0u8; RESPONSE_BLOB_LEN];
    pdu[0..16].copy_from_slice(b"GHOST_RESPONSE__");
    pdu[16..48].copy_from_slice(x_pub_bytes);
    pdu[48..816].copy_from_slice(ct_bytes);
    pdu[816..848].copy_from_slice(responder_identity_pk);
    let mut signed_material = vec![0u8; 800];
    signed_material[0..32].copy_from_slice(x_pub_bytes);
    signed_material[32..800].copy_from_slice(ct_bytes);
    let sig = responder_sign(&signed_material);
    pdu[848..912].copy_from_slice(&sig);
    pdu
}

pub struct ResponseBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_ct: [u8; 768],
    pub identity_pk: [u8; 32],
    pub signature: [u8; 64],
}

pub fn parse_response_pdu(data: &[u8]) -> Option<ResponseBlob> {
    if data.len() < RESPONSE_BLOB_LEN || !data.starts_with(b"GHOST_RESPONSE__") {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[16..48]);
    let mut kyber_ct = [0u8; 768];
    kyber_ct.copy_from_slice(&data[48..816]);
    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&data[816..848]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[848..912]);
    Some(ResponseBlob { x25519_pub, kyber_ct, identity_pk, signature })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_with_psk_differs_from_without() {
        let x25519_ss = [0xABu8; 32];
        let kyber_ss = vec![0xCDu8; 32];
        let psk = [0x42u8; 32];

        let key_no_psk = derive_hybrid_master_key(&x25519_ss, &kyber_ss);
        let key_with_psk = derive_hybrid_master_key_with_psk(&x25519_ss, &kyber_ss, Some(&psk));

        // Keys should be different with PSK vs without
        assert_ne!(key_no_psk, key_with_psk, "PSK mixing should produce different keys");
    }

    #[test]
    fn test_derive_with_psk_deterministic() {
        let x25519_ss = [0xABu8; 32];
        let kyber_ss = vec![0xCDu8; 32];
        let psk = [0x42u8; 32];

        let key1 = derive_hybrid_master_key_with_psk(&x25519_ss, &kyber_ss, Some(&psk));
        let key2 = derive_hybrid_master_key_with_psk(&x25519_ss, &kyber_ss, Some(&psk));

        assert_eq!(key1, key2, "Same inputs should produce same key");
    }

    #[test]
    fn test_derive_with_different_psk_different_keys() {
        let x25519_ss = [0xABu8; 32];
        let kyber_ss = vec![0xCDu8; 32];

        let key_a = derive_hybrid_master_key_with_psk(&x25519_ss, &kyber_ss, Some(&[0x01u8; 32]));
        let key_b = derive_hybrid_master_key_with_psk(&x25519_ss, &kyber_ss, Some(&[0x02u8; 32]));

        assert_ne!(key_a, key_b, "Different PSKs should produce different keys");
    }
}