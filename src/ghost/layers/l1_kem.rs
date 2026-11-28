//! L1 — Hybrid Key Encapsulation Mechanism (KEM) Layer.
//!
//! Implements hybrid classical and post-quantum key agreement combining X25519 (ECDH)
//! with ML-KEM-512 / ML-KEM-768 (FIPS 203) and optional Pre-Shared Key (PSK) mixing.
//!
//! ## Out-of-Band Symmetric Key Mixing (Defense-in-Depth)
//! A continuously rotating 256-bit Pre-Shared Key (PSK) is mixed into the HKDF
//! derivation as an additional salt source to provide defense-in-depth against
//! future lattice cryptanalysis:
//!   `master_key = HKDF-SHA256(salt = PSK || zeros, ikm = x25519_ss || kyber_ss)`
//!
//! ## PDU Wire Layout (944 bytes)
//! - `[0..16]`: Magic header `GHOST_HANDSHAKE_`
//! - `[16..48]`: X25519 ephemeral public key (32 bytes)
//! - `[48..848]`: Kyber-512 public key (800 bytes)
//! - `[848..880]`: Ed25519 public key (32 bytes, L0 identity)
//! - `[880..944]`: Ed25519 signature (64 bytes, L0 proof)

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
pub use ml_kem::{
    DecapsulationKey512, DecapsulationKey768, EncapsulationKey, EncapsulationKey512,
    EncapsulationKey768,
};
use ml_kem::{MlKem512, MlKem768};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

pub const HANDSHAKE_BLOB_LEN: usize = 944;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridCipherSuite {
    X25519MlKem512V2,
    X25519MlKem768V3,
}

impl HybridCipherSuite {
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::X25519MlKem512V2 => 1,
            Self::X25519MlKem768V3 => 2,
        }
    }

    pub const fn from_wire_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::X25519MlKem512V2),
            2 => Some(Self::X25519MlKem768V3),
            _ => None,
        }
    }

    pub fn hkdf_label(self) -> &'static [u8] {
        match self {
            Self::X25519MlKem512V2 => b"GHOST_NET_MASTER_KEY_v2/X25519-MLKEM512",
            Self::X25519MlKem768V3 => b"GHOST_NET_MASTER_KEY_v3/X25519-MLKEM768",
        }
    }
}

pub fn negotiate_cipher_suite(
    local: &[HybridCipherSuite],
    remote_wire_ids: &[u8],
) -> Option<HybridCipherSuite> {
    [
        HybridCipherSuite::X25519MlKem768V3,
        HybridCipherSuite::X25519MlKem512V2,
    ]
    .into_iter()
    .find(|suite| local.contains(suite) && remote_wire_ids.contains(&suite.wire_id()))
}

pub fn derive_hybrid_master_key(x25519_shared: &[u8; 32], kyber_shared: &[u8]) -> [u8; 32] {
    derive_hybrid_master_key_with_psk(x25519_shared, kyber_shared, None)
}

pub fn derive_hybrid_master_key_with_psk(
    x25519_shared: &[u8; 32],
    kyber_shared: &[u8],
    psk: Option<&[u8; 32]>,
) -> [u8; 32] {
    derive_hybrid_master_key_with_suite(
        HybridCipherSuite::X25519MlKem512V2,
        x25519_shared,
        kyber_shared,
        psk,
    )
}

pub fn derive_hybrid_master_key_with_suite(
    suite: HybridCipherSuite,
    x25519_shared: &[u8; 32],
    kyber_shared: &[u8],
    psk: Option<&[u8; 32]>,
) -> [u8; 32] {
    let salt = match psk {
        Some(key) => *key,
        None => [0u8; 32],
    };

    let ikm = [x25519_shared.as_slice(), kyber_shared].concat();

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut master_key = [0u8; 32];
    hk.expand(suite.hkdf_label(), &mut master_key).unwrap();
    master_key
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceProof {
    pub beacon_entropy_hash: [u8; 32],
    pub epoch_window: u64,
}

impl PresenceProof {
    pub const PRESENCE_DOMAIN: &'static [u8] = b"GGN_PRESENT_TENSE_PROOF_V1";

    pub fn new(beacon_entropy: &[u8], epoch_window: u64) -> Self {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(Self::PRESENCE_DOMAIN);
        hasher.update(epoch_window.to_be_bytes());
        hasher.update(beacon_entropy);
        let res = hasher.finalize();
        let mut beacon_entropy_hash = [0u8; 32];
        beacon_entropy_hash.copy_from_slice(&res);
        Self {
            beacon_entropy_hash,
            epoch_window,
        }
    }

    pub fn verify(
        &self,
        expected_entropy: &[u8],
        current_epoch_window: u64,
        max_window_skew: u64,
    ) -> Result<(), &'static str> {
        let diff = self.epoch_window.abs_diff(current_epoch_window);
        if diff > max_window_skew {
            return Err("presence proof epoch window out of bounds (replay or future claim)");
        }
        let expected = Self::new(expected_entropy, self.epoch_window);
        if expected.beacon_entropy_hash != self.beacon_entropy_hash {
            return Err("presence proof entropy mismatch (remote peer not co-present in epoch)");
        }
        Ok(())
    }
}

pub fn derive_hybrid_master_key_with_presence(
    suite: HybridCipherSuite,
    x25519_shared: &[u8; 32],
    kyber_shared: &[u8],
    psk: Option<&[u8; 32]>,
    presence: Option<&PresenceProof>,
) -> [u8; 32] {
    let mut base_salt = match psk {
        Some(key) => *key,
        None => [0u8; 32],
    };
    if let Some(proof) = presence {
        for (i, b) in proof.beacon_entropy_hash.iter().enumerate() {
            base_salt[i % 32] ^= b;
        }
    }
    let mut ikm = [x25519_shared.as_slice(), kyber_shared].concat();
    if let Some(proof) = presence {
        ikm.extend_from_slice(&proof.epoch_window.to_be_bytes());
    }
    let hk = Hkdf::<Sha256>::new(Some(&base_salt[..]), &ikm);
    let mut master_key = [0u8; 32];
    hk.expand(suite.hkdf_label(), &mut master_key).unwrap();
    master_key
}

pub const HYBRID_BIND_LABEL: &[u8] = b"GHOST_NET_HYBRID_BIND_v2";

pub fn derive_hybrid_master_key_with_transcript(
    suite: HybridCipherSuite,
    x25519_shared: &[u8; 32],
    kyber_shared: &[u8],
    psk: Option<&[u8; 32]>,
    initiator_x_pub: &[u8; 32],
    responder_x_pub: &[u8; 32],
    kyber_ct: &[u8],
    initiator_pq_commitment: &[u8; 32],
    responder_pq_commitment: &[u8; 32],
) -> [u8; 32] {
    let cap = HYBRID_BIND_LABEL
        .len()
        .saturating_add(32)
        .saturating_add(kyber_shared.len())
        .saturating_add(64)
        .saturating_add(kyber_ct.len())
        .saturating_add(64);
    let mut ikm = Vec::with_capacity(cap);
    ikm.extend_from_slice(HYBRID_BIND_LABEL);
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);
    ikm.extend_from_slice(initiator_x_pub);
    ikm.extend_from_slice(responder_x_pub);
    ikm.extend_from_slice(kyber_ct);
    ikm.extend_from_slice(initiator_pq_commitment);
    ikm.extend_from_slice(responder_pq_commitment);

    let salt = match psk {
        Some(key) => *key,
        None => [0u8; 32],
    };
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut master_key = [0u8; 32];
    hk.expand(suite.hkdf_label(), &mut master_key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    master_key
}

pub fn generate_x25519_keypair() -> (EphemeralSecret, XPublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = XPublicKey::from(&secret);
    (secret, public)
}

pub fn generate_kyber_keypair() -> (EncapsulationKey512, DecapsulationKey512) {
    let (dk, ek) = MlKem512::generate_keypair();
    (ek, dk)
}

pub fn generate_kyber768_keypair() -> (EncapsulationKey768, DecapsulationKey768) {
    let (dk, ek) = MlKem768::generate_keypair();
    (ek, dk)
}

pub fn kyber768_encapsulate(peer_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let ek = EncapsulationKey::<MlKem768>::new_from_slice(peer_pk)
        .map_err(|_| "Invalid ML-KEM-768 public key")?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

pub fn kyber768_decapsulate(
    secret_key: &DecapsulationKey768,
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext)
        .map_err(|_| "Invalid ML-KEM-768 ciphertext")?;
    Ok(secret_key.decapsulate(&ct).as_slice().to_vec())
}

pub fn kyber_encapsulate(peer_pk: &[u8]) -> Result<([u8; 768], Vec<u8>), &'static str> {
    let ek = EncapsulationKey::<MlKem512>::new_from_slice(peer_pk)
        .map_err(|_| "Invalid Kyber public key")?;
    let (ct, ss) = ek.encapsulate();
    let ct_bytes: [u8; 768] = ct.into();
    Ok((ct_bytes, ss.as_slice().to_vec()))
}

pub fn compute_session_hash(key: &[u8; 32]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(key);
    let bytes = d.as_slice();
    let mut hash = [0u8; 4];
    hash.copy_from_slice(&bytes[..4]);
    hash
}

pub const UNIFORM_HANDSHAKE_BLOB_LEN: usize = HANDSHAKE_BLOB_LEN;
pub const UNIFORM_RESPONSE_BLOB_LEN: usize = RESPONSE_BLOB_LEN;

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

pub struct HandshakeBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_pub: [u8; 800],
    pub identity_pk: [u8; 32],
    pub signature: [u8; 64],
}

pub const HANDSHAKE_V3_MAGIC: &[u8; 16] = b"GHOST_HS_V3_____";
pub const RESPONSE_V3_MAGIC: &[u8; 16] = b"GHOST_RSP_V3____";

#[derive(Debug, Clone)]
pub struct SuiteHandshakeBlob {
    pub suite: HybridCipherSuite,
    pub x25519_pub: [u8; 32],
    pub kyber_pub: Vec<u8>,
    pub identity_pk: [u8; 32],
    pub signature: [u8; 64],
}

pub fn build_handshake_pdu_suite(
    suite: HybridCipherSuite,
    identity_pk: &[u8; 32],
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &XPublicKey,
    kyber_pub: &[u8],
) -> Option<Vec<u8>> {
    let expected = match suite {
        HybridCipherSuite::X25519MlKem512V2 => 800,
        HybridCipherSuite::X25519MlKem768V3 => 1184,
    };
    if kyber_pub.len() != expected {
        return None;
    }
    let mut material = Vec::with_capacity(1 + 32 + kyber_pub.len() + 32);
    material.push(suite.wire_id());
    material.extend_from_slice(x_pub.as_bytes());
    material.extend_from_slice(kyber_pub);
    material.extend_from_slice(identity_pk);
    let sig = identity_sign(&material);
    let mut pdu = Vec::with_capacity(16 + material.len() + 64);
    pdu.extend_from_slice(HANDSHAKE_V3_MAGIC);
    pdu.push(suite.wire_id());
    pdu.extend_from_slice(x_pub.as_bytes());
    pdu.extend_from_slice(kyber_pub);
    pdu.extend_from_slice(identity_pk);
    pdu.extend_from_slice(&sig);
    Some(pdu)
}

pub fn parse_handshake_pdu_suite(data: &[u8]) -> Option<SuiteHandshakeBlob> {
    if data.len() < 16 + 1 + 32 + 32 + 64 || !data.starts_with(HANDSHAKE_V3_MAGIC) {
        return None;
    }
    let suite = HybridCipherSuite::from_wire_id(data[16])?;
    let pk_len = match suite {
        HybridCipherSuite::X25519MlKem512V2 => 800,
        HybridCipherSuite::X25519MlKem768V3 => 1184,
    };
    let total = 16 + 1 + 32 + pk_len + 32 + 64;
    if data.len() != total {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[17..49]);
    let pk_start = 49;
    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&data[pk_start + pk_len..pk_start + pk_len + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[pk_start + pk_len + 32..]);
    Some(SuiteHandshakeBlob {
        suite,
        x25519_pub,
        kyber_pub: data[pk_start..pk_start + pk_len].to_vec(),
        identity_pk,
        signature,
    })
}

pub fn build_uniform_handshake_pdu(
    identity_pk: &[u8; 32],
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &XPublicKey,
    kyber_pub: &EncapsulationKey512,
) -> Vec<u8> {
    let mut pdu = vec![0u8; UNIFORM_HANDSHAKE_BLOB_LEN];
    rand::thread_rng().fill_bytes(&mut pdu[..16]);
    pdu[16..48].copy_from_slice(x_pub.as_bytes());
    pdu[48..848].copy_from_slice(&kyber_pub.to_bytes());
    pdu[848..880].copy_from_slice(identity_pk);
    let mut signed_material = Vec::with_capacity(16 + 32 + 800 + 32);
    signed_material.extend_from_slice(&pdu[..880]);
    let sig = identity_sign(&signed_material);
    pdu[880..944].copy_from_slice(&sig);
    pdu
}

pub fn parse_uniform_handshake_pdu(data: &[u8]) -> Option<HandshakeBlob> {
    if data.len() < UNIFORM_HANDSHAKE_BLOB_LEN {
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
    Some(HandshakeBlob {
        x25519_pub,
        kyber_pub,
        identity_pk,
        signature,
    })
}

pub fn uniform_handshake_signed_material(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < UNIFORM_HANDSHAKE_BLOB_LEN {
        return None;
    }
    Some(data[..880].to_vec())
}

fn normal_ccdf(z: f64) -> f64 {
    if z < -8.0 {
        return 1.0;
    }
    if z > 8.0 {
        return 0.0;
    }
    let x = z / std::f64::consts::SQRT_2;
    let abs_x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * abs_x);
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let erfc = poly * (-abs_x * abs_x).exp();
    if x >= 0.0 {
        0.5 * erfc
    } else {
        1.0 - 0.5 * erfc
    }
}

pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] = freq[b as usize].saturating_add(1);
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn calculate_chi_square_uniformity(data: &[u8]) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 1.0);
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] = freq[b as usize].saturating_add(1);
    }
    let len = data.len() as f64;
    let expected = len / 256.0;
    let mut chi_square = 0.0;
    for &count in &freq {
        let diff = count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    let df = 255.0;
    let term1 = (chi_square / df).cbrt();
    let term2 = 1.0 - (2.0 / (9.0 * df));
    let denom = (2.0 / (9.0 * df)).sqrt();
    let z = (term1 - term2) / denom;
    let p_value = normal_ccdf(z);

    (chi_square, p_value)
}

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

    Some(HandshakeBlob {
        x25519_pub,
        kyber_pub,
        identity_pk,
        signature,
    })
}

pub const RESPONSE_BLOB_LEN: usize = 912; // 16 magic + 32 X25519 pub + 768 ct + 32 identity + 64 sig

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

#[derive(Debug, Clone)]
pub struct SuiteResponseBlob {
    pub suite: HybridCipherSuite,
    pub x25519_pub: [u8; 32],
    pub kyber_ct: Vec<u8>,
    pub identity_pk: [u8; 32],
    pub signature: [u8; 64],
}

pub fn build_response_pdu_suite(
    suite: HybridCipherSuite,
    identity_pk: &[u8; 32],
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub_bytes: &[u8; 32],
    ct_bytes: &[u8],
) -> Option<Vec<u8>> {
    let expected = match suite {
        HybridCipherSuite::X25519MlKem512V2 => 768,
        HybridCipherSuite::X25519MlKem768V3 => 1088,
    };
    if ct_bytes.len() != expected {
        return None;
    }
    let mut material = Vec::with_capacity(1 + 32 + ct_bytes.len() + 32);
    material.push(suite.wire_id());
    material.extend_from_slice(x_pub_bytes);
    material.extend_from_slice(ct_bytes);
    material.extend_from_slice(identity_pk);
    let sig = identity_sign(&material);
    let mut pdu = Vec::with_capacity(16 + material.len() + 64);
    pdu.extend_from_slice(RESPONSE_V3_MAGIC);
    pdu.push(suite.wire_id());
    pdu.extend_from_slice(x_pub_bytes);
    pdu.extend_from_slice(ct_bytes);
    pdu.extend_from_slice(identity_pk);
    pdu.extend_from_slice(&sig);
    Some(pdu)
}

pub fn parse_response_pdu_suite(data: &[u8]) -> Option<SuiteResponseBlob> {
    if data.len() < 16 + 1 + 32 + 32 + 64 || !data.starts_with(RESPONSE_V3_MAGIC) {
        return None;
    }
    let suite = HybridCipherSuite::from_wire_id(data[16])?;
    let ct_len = match suite {
        HybridCipherSuite::X25519MlKem512V2 => 768,
        HybridCipherSuite::X25519MlKem768V3 => 1088,
    };
    let total = 16 + 1 + 32 + ct_len + 32 + 64;
    if data.len() != total {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[17..49]);
    let ct_start = 49;
    let mut identity_pk = [0u8; 32];
    identity_pk.copy_from_slice(&data[ct_start + ct_len..ct_start + ct_len + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[ct_start + ct_len + 32..]);
    Some(SuiteResponseBlob {
        suite,
        x25519_pub,
        kyber_ct: data[ct_start..ct_start + ct_len].to_vec(),
        identity_pk,
        signature,
    })
}

pub fn build_uniform_response_pdu(
    responder_identity_pk: &[u8; 32],
    responder_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub_bytes: &[u8; 32],
    ct_bytes: &[u8; 768],
) -> Vec<u8> {
    let mut pdu = vec![0u8; UNIFORM_RESPONSE_BLOB_LEN];
    rand::thread_rng().fill_bytes(&mut pdu[..16]);
    pdu[16..48].copy_from_slice(x_pub_bytes);
    pdu[48..816].copy_from_slice(ct_bytes);
    pdu[816..848].copy_from_slice(responder_identity_pk);
    let mut signed_material = Vec::with_capacity(16 + 32 + 768 + 32);
    signed_material.extend_from_slice(&pdu[..848]);
    let sig = responder_sign(&signed_material);
    pdu[848..912].copy_from_slice(&sig);
    pdu
}

pub fn parse_uniform_response_pdu(data: &[u8]) -> Option<ResponseBlob> {
    if data.len() < UNIFORM_RESPONSE_BLOB_LEN {
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
    Some(ResponseBlob {
        x25519_pub,
        kyber_ct,
        identity_pk,
        signature,
    })
}

pub fn uniform_response_signed_material(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < UNIFORM_RESPONSE_BLOB_LEN {
        return None;
    }
    Some(data[..848].to_vec())
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
    Some(ResponseBlob {
        x25519_pub,
        kyber_ct,
        identity_pk,
        signature,
    })
}

pub const HANDSHAKE_NEGOTIATION_MAGIC: &[u8; 16] = b"GHOST_HS_NEG_V7_";
pub const RESPONSE_NEGOTIATION_MAGIC: &[u8; 16] = b"GHOST_RSP_NEG_V7";

#[derive(Debug, Clone)]
pub struct NegotiatedHandshakeBlob {
    pub supported: Vec<HybridCipherSuite>,
    pub x25519_pub: [u8; 32],
    pub kyber_keys: Vec<(HybridCipherSuite, Vec<u8>)>,
    pub identity_pk: [u8; 32],
    pub pq_commitment: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct NegotiatedResponseBlob {
    pub suite: HybridCipherSuite,
    pub x25519_pub: [u8; 32],
    pub kyber_ct: Vec<u8>,
    pub identity_pk: [u8; 32],
    pub pq_commitment: [u8; 32],
    pub signature: [u8; 64],
}

fn suite_key_len(suite: HybridCipherSuite) -> usize {
    match suite {
        HybridCipherSuite::X25519MlKem512V2 => 800,
        HybridCipherSuite::X25519MlKem768V3 => 1184,
    }
}

fn suite_ct_len(suite: HybridCipherSuite) -> usize {
    match suite {
        HybridCipherSuite::X25519MlKem512V2 => 768,
        HybridCipherSuite::X25519MlKem768V3 => 1088,
    }
}

fn negotiation_material(
    supported: &[HybridCipherSuite],
    x25519_pub: &[u8; 32],
    kyber_keys: &[(HybridCipherSuite, Vec<u8>)],
    identity_pk: &[u8; 32],
    pq_commitment: &[u8; 32],
) -> Option<Vec<u8>> {
    if supported.is_empty() || supported.len() > 2 || kyber_keys.len() != supported.len() {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(HANDSHAKE_NEGOTIATION_MAGIC);
    out.push(supported.len() as u8);
    out.extend(supported.iter().map(|s| s.wire_id()));
    out.extend_from_slice(x25519_pub);
    for suite in supported {
        let (_, key) = kyber_keys.iter().find(|(s, _)| s == suite)?;
        if key.len() != suite_key_len(*suite) {
            return None;
        }
        out.push(suite.wire_id());
        out.extend_from_slice(&(key.len() as u16).to_be_bytes());
        out.extend_from_slice(key);
    }
    out.extend_from_slice(identity_pk);
    out.extend_from_slice(pq_commitment);
    out.push(0x00);
    Some(out)
}

pub fn build_negotiated_handshake_pdu(
    supported: &[HybridCipherSuite],
    identity_pk: &[u8; 32],
    pq_commitment: &[u8; 32],
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &XPublicKey,
    kyber_keys: &[(HybridCipherSuite, Vec<u8>)],
) -> Option<Vec<u8>> {
    let material = negotiation_material(
        supported,
        x_pub.as_bytes(),
        kyber_keys,
        identity_pk,
        pq_commitment,
    )?;
    let sig = identity_sign(&material);
    let mut out = material;
    out.extend_from_slice(&sig);
    Some(out)
}

pub fn parse_negotiated_handshake_pdu(data: &[u8]) -> Option<NegotiatedHandshakeBlob> {
    let try_parse = |len: usize, allow_reserved: bool| -> Option<NegotiatedHandshakeBlob> {
        if len < 16 + 1 + 32 + 32 + 32 + 64 + if allow_reserved { 1 } else { 0 }
            || !data.starts_with(HANDSHAKE_NEGOTIATION_MAGIC)
        {
            return None;
        }
        let count = *data.get(16)? as usize;
        if count == 0 || count > 2 || len <= 17 + 32 + 32 + 64 + if allow_reserved { 1 } else { 0 }
        {
            return None;
        }
        let mut at: usize = 17;
        let mut supported = Vec::with_capacity(count);
        for _ in 0..count {
            let suite = HybridCipherSuite::from_wire_id(*data.get(at)?)?;
            if supported.contains(&suite) {
                return None;
            }
            supported.push(suite);
            at = at.checked_add(1)?;
        }
        let x_start = at;
        let x_end = x_start.checked_add(32)?;
        let x25519_pub: [u8; 32] = data.get(x_start..x_end)?.try_into().ok()?;
        at = x_end;
        let mut kyber_keys = Vec::with_capacity(count);
        for _ in 0..count {
            let suite = HybridCipherSuite::from_wire_id(*data.get(at)?)?;
            at = at.checked_add(1)?;
            let len2 =
                u16::from_be_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize;
            at = at.checked_add(2)?;
            if len2 != suite_key_len(suite) || kyber_keys.iter().any(|(s, _)| *s == suite) {
                return None;
            }
            let key = data.get(at..at.checked_add(len2)?)?.to_vec();
            at = at.checked_add(len2)?;
            kyber_keys.push((suite, key));
        }
        let identity_pk: [u8; 32] = data.get(at..at.checked_add(32)?)?.try_into().ok()?;
        at = at.checked_add(32)?;
        let pq_commitment: [u8; 32] = data.get(at..at.checked_add(32)?)?.try_into().ok()?;
        at = at.checked_add(32)?;
        if at < len && data[at] == 0x00 {
            if !allow_reserved || len != at.checked_add(1)?.checked_add(64)? {
                return None;
            }
            at = at.checked_add(1)?;
        } else if len != at.checked_add(64)? {
            return None;
        }
        let sig_end = at.checked_add(64)?;
        let signature: [u8; 64] = data.get(at..sig_end)?.try_into().ok()?;
        if sig_end != len
            || kyber_keys.iter().map(|(s, _)| s).collect::<Vec<_>>()
                != supported.iter().collect::<Vec<_>>()
        {
            return None;
        }
        Some(NegotiatedHandshakeBlob {
            supported,
            x25519_pub,
            kyber_keys,
            identity_pk,
            pq_commitment,
            signature,
        })
    };

    if let Some(blob) = try_parse(data.len(), true) {
        return Some(blob);
    }
    if let Some(blob) = try_parse(data.len(), false) {
        return Some(blob);
    }

    if data.len().is_multiple_of(2) && data.last() == Some(&0x00) && data.len() > 1 {
        if let Some(blob) = try_parse(data.len() - 1, false) {
            return Some(blob);
        }
    }
    None
}

fn response_material(
    suite: HybridCipherSuite,
    x25519_pub: &[u8; 32],
    kyber_ct: &[u8],
    identity_pk: &[u8; 32],
    pq_commitment: &[u8; 32],
) -> Option<Vec<u8>> {
    if kyber_ct.len() != suite_ct_len(suite) {
        return None;
    }
    let mut out = Vec::with_capacity(16 + 1 + 32 + kyber_ct.len() + 32 + 32);
    out.extend_from_slice(RESPONSE_NEGOTIATION_MAGIC);
    out.push(suite.wire_id());
    out.extend_from_slice(x25519_pub);
    out.extend_from_slice(kyber_ct);
    out.extend_from_slice(identity_pk);
    out.extend_from_slice(pq_commitment);
    Some(out)
}

pub fn build_negotiated_response_pdu(
    suite: HybridCipherSuite,
    identity_pk: &[u8; 32],
    pq_commitment: &[u8; 32],
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub_bytes: &[u8; 32],
    ct_bytes: &[u8],
) -> Option<Vec<u8>> {
    let mut out = response_material(suite, x_pub_bytes, ct_bytes, identity_pk, pq_commitment)?;
    let sig = identity_sign(&out);
    out.extend_from_slice(&sig);
    Some(out)
}

pub fn negotiated_response_len(suite: HybridCipherSuite) -> usize {
    let ct_len = suite_ct_len(suite);
    16 + 1 + 32 + ct_len + 32 + 32 + 64
}

pub fn parse_negotiated_response_pdu(data: &[u8]) -> Option<NegotiatedResponseBlob> {
    if data.len() < 16 + 1 + 32 + 32 + 32 + 64 || !data.starts_with(RESPONSE_NEGOTIATION_MAGIC) {
        return None;
    }
    let suite = HybridCipherSuite::from_wire_id(data[16])?;
    let ct_start = 49;
    let ct_len = suite_ct_len(suite);
    let identity_start = ct_start + ct_len;
    let pq_start = identity_start + 32;
    let total = negotiated_response_len(suite);
    if data.len() < total || data.len() > total + 1 {
        return None;
    }
    let x25519_pub: [u8; 32] = data[17..49].try_into().ok()?;
    let kyber_ct = data[ct_start..identity_start].to_vec();
    let identity_pk: [u8; 32] = data[identity_start..pq_start].try_into().ok()?;
    let pq_commitment: [u8; 32] = data[pq_start..pq_start + 32].try_into().ok()?;
    let signature: [u8; 64] = data[pq_start + 32..pq_start + 32 + 64].try_into().ok()?;
    Some(NegotiatedResponseBlob {
        suite,
        x25519_pub,
        kyber_ct,
        identity_pk,
        pq_commitment,
        signature,
    })
}

pub const RATCHET_ROOT_INFO: &[u8] = b"GHOST_NET_RATCHET_ROOT_v2";

pub const RATCHET_INIT_INFO: &[u8] = b"GHOST_NET_RATCHET_INIT_v2";

pub const RATCHET_EPOCH_INFO: &[u8] = b"GHOST_NET_EPOCH_KEY_v2";

pub const CHAIN_STEP_NEXT: u8 = 0x01;
pub const CHAIN_STEP_KEY: u8 = 0x02;

pub const RATCHET_QUANTUM_MIX_INFO: &[u8] = b"GHOST_NET_RATCHET_QEL_ENTROPY_v1";

type HmacSha256 = Hmac<Sha256>;

pub fn kdf_rk_hybrid(
    root_key: &[u8; 32],
    x25519_shared: &[u8; 32],
    kem_shared: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut ikm = Vec::with_capacity(32 + kem_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kem_shared);

    let hk = Hkdf::<Sha256>::new(Some(&root_key[..]), &ikm);
    let mut out = [0u8; 96];
    hk.expand(RATCHET_ROOT_INFO, &mut out)
        .expect("96 bytes is a valid HKDF-SHA256 output length");

    let mut new_root = [0u8; 32];
    new_root.copy_from_slice(&out[..32]);
    let mut chain_to_resp = [0u8; 32];
    chain_to_resp.copy_from_slice(&out[32..64]);
    let mut chain_to_init = [0u8; 32];
    chain_to_init.copy_from_slice(&out[64..96]);
    (new_root, chain_to_resp, chain_to_init)
}

pub fn kdf_rk_quantum_mix(
    root_key: &[u8; 32],
    quantum_key: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(&root_key[..]), quantum_key);
    let mut out = [0u8; 96];
    hk.expand(RATCHET_QUANTUM_MIX_INFO, &mut out)
        .expect("96 bytes is a valid HKDF-SHA256 output length");

    let mut new_root = [0u8; 32];
    new_root.copy_from_slice(&out[..32]);
    let mut chain_to_resp = [0u8; 32];
    chain_to_resp.copy_from_slice(&out[32..64]);
    let mut chain_to_init = [0u8; 32];
    chain_to_init.copy_from_slice(&out[64..96]);
    (new_root, chain_to_resp, chain_to_init)
}

pub fn seed_ratchet_chains(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(&master_key[..]), &[]);
    let mut out = [0u8; 64];
    hk.expand(RATCHET_INIT_INFO, &mut out)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut to_resp = [0u8; 32];
    to_resp.copy_from_slice(&out[..32]);
    let mut to_init = [0u8; 32];
    to_init.copy_from_slice(&out[32..]);
    (to_resp, to_init)
}

pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = hmac_sha256(chain_key, &[CHAIN_STEP_NEXT]);
    let step_key = hmac_sha256(chain_key, &[CHAIN_STEP_KEY]);
    (next, step_key)
}

pub fn ratchet_confirm(epoch_key: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(epoch_key, b"GHOST_RATCHET_CONFIRM_v2")
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

pub fn derive_epoch_key(chain_key: &[u8; 32], epoch: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&chain_key[..]), &epoch.to_be_bytes());
    let mut key = [0u8; 32];
    hk.expand(RATCHET_EPOCH_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_rk_depends_on_both_halves() {
        let root = [0x11u8; 32];
        let dh = [0x22u8; 32];
        let kem = vec![0x33u8; 32];

        let (r0, c0a, c0b) = kdf_rk_hybrid(&root, &dh, &kem);
        let (r1, c1a, c1b) = kdf_rk_hybrid(&root, &[0x44u8; 32], &kem);
        let (r2, c2a, c2b) = kdf_rk_hybrid(&root, &dh, &[0x55u8; 32]);
        assert_ne!(r0, r1);
        assert_ne!(c0a, c1a);
        assert_ne!(c0b, c1b);
        assert_ne!(r0, r2);
        assert_ne!(c0a, c2a);
        assert_ne!(c0b, c2b);

        let (r3, _, _) = kdf_rk_hybrid(&[0xEEu8; 32], &dh, &kem);
        assert_ne!(r0, r3);

        assert_ne!(c0a, c0b);
    }

    #[test]
    fn test_ratchet_confirm_is_a_derivation_not_the_key() {
        let key = [0x42u8; 32];
        let tag = ratchet_confirm(&key);
        assert_ne!(tag, key, "the confirmation must not be the key itself");
        assert_eq!(tag, ratchet_confirm(&key));
        assert_ne!(tag, ratchet_confirm(&[0x43u8; 32]));
    }

    #[test]
    fn test_seed_ratchet_chains_is_directional() {
        let master = [0x5Au8; 32];
        let (to_resp, to_init) = seed_ratchet_chains(&master);
        assert_ne!(to_resp, to_init);
        assert_eq!(seed_ratchet_chains(&master), (to_resp, to_init));
        assert_ne!(to_resp, master);
    }

    #[test]
    fn test_kdf_ck_steps_are_one_way_and_distinct() {
        let ck = [0x77u8; 32];
        let (next, key) = kdf_ck(&ck);
        assert_ne!(next, key, "the two outputs must be domain-separated");
        assert_ne!(next, ck, "a chain step must advance");

        let mut seen = std::collections::HashSet::new();
        let mut cur = ck;
        for _ in 0..64 {
            let (n, k) = kdf_ck(&cur);
            assert!(seen.insert(k), "a step key repeated");
            cur = n;
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn test_epoch_keys_are_distinct_across_epochs() {
        let chain = [0x99u8; 32];
        let a = derive_epoch_key(&chain, 0);
        let b = derive_epoch_key(&chain, 1);
        let c = derive_epoch_key(&[0xAAu8; 32], 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, derive_epoch_key(&chain, 0), "derivation must be stable");
    }

    #[test]
    fn test_ratchet_kdf_is_domain_separated_from_handshake() {
        let root = [0x01u8; 32];
        let dh = [0x02u8; 32];
        let kem = vec![0x03u8; 32];
        let (new_root, chain_a, chain_b) = kdf_rk_hybrid(&root, &dh, &kem);
        let handshake = derive_hybrid_master_key(&dh, &kem);
        assert_ne!(new_root, handshake);
        assert_ne!(chain_a, handshake);
        assert_ne!(chain_b, handshake);
    }

    #[test]
    fn test_derive_with_psk_differs_from_without() {
        let x25519_ss = [0xABu8; 32];
        let kyber_ss = vec![0xCDu8; 32];
        let psk = [0x42u8; 32];

        let key_no_psk = derive_hybrid_master_key(&x25519_ss, &kyber_ss);
        let key_with_psk = derive_hybrid_master_key_with_psk(&x25519_ss, &kyber_ss, Some(&psk));

        assert_ne!(
            key_no_psk, key_with_psk,
            "PSK mixing should produce different keys"
        );
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

    #[test]
    fn test_suite_wire_ids_and_deterministic_negotiation() {
        let local = [
            HybridCipherSuite::X25519MlKem512V2,
            HybridCipherSuite::X25519MlKem768V3,
        ];
        assert_eq!(
            HybridCipherSuite::from_wire_id(1),
            Some(HybridCipherSuite::X25519MlKem512V2)
        );
        assert_eq!(
            HybridCipherSuite::from_wire_id(2),
            Some(HybridCipherSuite::X25519MlKem768V3)
        );
        assert_eq!(HybridCipherSuite::from_wire_id(0), None);
        assert_eq!(
            negotiate_cipher_suite(&local, &[1, 2]),
            Some(HybridCipherSuite::X25519MlKem768V3)
        );
        assert_eq!(
            negotiate_cipher_suite(&local, &[1]),
            Some(HybridCipherSuite::X25519MlKem512V2)
        );
        assert_eq!(negotiate_cipher_suite(&local, &[99]), None);
    }

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let (public, secret) = generate_kyber768_keypair();
        let (ciphertext, shared_a) = kyber768_encapsulate(&public.to_bytes()).expect("encapsulate");
        let shared_b = kyber768_decapsulate(&secret, &ciphertext).expect("decapsulate");
        assert_eq!(shared_a, shared_b);
        assert_ne!(ciphertext, vec![0u8; ciphertext.len()]);
    }

    #[test]
    fn test_cipher_suite_domains_are_separate() {
        let x = [0x11u8; 32];
        let kem = [0x22u8; 32];
        let v2 = derive_hybrid_master_key_with_suite(
            HybridCipherSuite::X25519MlKem512V2,
            &x,
            &kem,
            None,
        );
        let v3 = derive_hybrid_master_key_with_suite(
            HybridCipherSuite::X25519MlKem768V3,
            &x,
            &kem,
            None,
        );
        assert_ne!(v2, v3, "suite negotiation must not reuse the v2 KDF domain");
    }

    #[test]
    fn test_versioned_wire_handshake_and_response_roundtrip() {
        let identity = [0xA5u8; 32];
        let (_, x_public) = generate_x25519_keypair();
        let (kem_public, _) = generate_kyber768_keypair();
        let handshake = build_handshake_pdu_suite(
            HybridCipherSuite::X25519MlKem768V3,
            &identity,
            |_| [0x5Au8; 64],
            &x_public,
            &kem_public.to_bytes(),
        )
        .expect("valid v3 handshake");
        let parsed = parse_handshake_pdu_suite(&handshake).expect("parse v3 handshake");
        assert_eq!(parsed.suite, HybridCipherSuite::X25519MlKem768V3);
        assert_eq!(parsed.kyber_pub.len(), 1184);
        assert_eq!(parsed.identity_pk, identity);

        let ciphertext = vec![0x3Cu8; 1088];
        let response = build_response_pdu_suite(
            parsed.suite,
            &identity,
            |_| [0x6Bu8; 64],
            &x_public.to_bytes(),
            &ciphertext,
        )
        .expect("valid v3 response");
        let response = parse_response_pdu_suite(&response).expect("parse v3 response");
        assert_eq!(response.suite, parsed.suite);
        assert_eq!(response.kyber_ct, ciphertext);
    }

    #[test]
    fn test_uniform_handshake_and_response_use_random_authenticated_prefixes() {
        let identity = [0xA5u8; 32];
        let (_, x_public) = generate_x25519_keypair();
        let (kem_public, _) = generate_kyber_keypair();
        let handshake =
            build_uniform_handshake_pdu(&identity, |_| [0x5Au8; 64], &x_public, &kem_public);
        let handshake2 =
            build_uniform_handshake_pdu(&identity, |_| [0x5Au8; 64], &x_public, &kem_public);
        assert_eq!(handshake.len(), UNIFORM_HANDSHAKE_BLOB_LEN);
        assert_ne!(&handshake[..16], &handshake2[..16]);
        let parsed = parse_uniform_handshake_pdu(&handshake).expect("uniform handshake parses");
        let material = uniform_handshake_signed_material(&handshake).expect("signed material");
        assert_eq!(&material[..16], &handshake[..16]);
        assert_eq!(parsed.identity_pk, identity);

        let ct = [0x3Cu8; 768];
        let response =
            build_uniform_response_pdu(&identity, |_| [0x6Bu8; 64], x_public.as_bytes(), &ct);
        assert_eq!(response.len(), UNIFORM_RESPONSE_BLOB_LEN);
        let response_parsed =
            parse_uniform_response_pdu(&response).expect("uniform response parses");
        assert_eq!(response_parsed.kyber_ct, ct);
        assert_eq!(
            uniform_response_signed_material(&response).unwrap()[..16],
            response[..16]
        );
    }

    #[test]
    fn test_uniform_parsers_reject_short_buffers_but_do_not_require_magic() {
        assert!(parse_uniform_handshake_pdu(&[0u8; UNIFORM_HANDSHAKE_BLOB_LEN - 1]).is_none());
        assert!(parse_uniform_response_pdu(&[0u8; UNIFORM_RESPONSE_BLOB_LEN - 1]).is_none());
        assert!(parse_uniform_handshake_pdu(&[0xFFu8; UNIFORM_HANDSHAKE_BLOB_LEN]).is_some());
        assert!(parse_uniform_response_pdu(&[0xFFu8; UNIFORM_RESPONSE_BLOB_LEN]).is_some());
    }

    #[test]
    fn test_versioned_wire_rejects_suite_length_mismatch() {
        let mut malformed = Vec::from(HANDSHAKE_V3_MAGIC.as_slice());
        malformed.extend_from_slice(&[2u8; 1 + 32 + 1183 + 32 + 64]);
        assert!(parse_handshake_pdu_suite(&malformed).is_none());
    }

    #[test]
    fn test_explicit_suite_list_selects_strongest_common_and_binds_all_keys() {
        let identity = [0x31u8; 32];
        let pq_comm = [0x77u8; 32];
        let (_, x_public) = generate_x25519_keypair();
        let (pk512, _) = generate_kyber_keypair();
        let (pk768, _) = generate_kyber768_keypair();
        let supported = [
            HybridCipherSuite::X25519MlKem768V3,
            HybridCipherSuite::X25519MlKem512V2,
        ];
        let keys = vec![
            (
                HybridCipherSuite::X25519MlKem768V3,
                pk768.to_bytes().to_vec(),
            ),
            (
                HybridCipherSuite::X25519MlKem512V2,
                pk512.to_bytes().to_vec(),
            ),
        ];
        let wire = build_negotiated_handshake_pdu(
            &supported,
            &identity,
            &pq_comm,
            |_| [0x44; 64],
            &x_public,
            &keys,
        )
        .expect("suite list builds");
        let parsed = parse_negotiated_handshake_pdu(&wire).expect("suite list parses");
        assert_eq!(parsed.supported, supported);
        assert_eq!(parsed.identity_pk, identity);
        assert_eq!(parsed.pq_commitment, pq_comm);
        assert_eq!(parsed.kyber_keys[0].1.len(), 1184);
        assert_eq!(parsed.kyber_keys[1].1.len(), 800);
        let remote = [HybridCipherSuite::X25519MlKem512V2.wire_id()];
        assert_eq!(
            negotiate_cipher_suite(&parsed.supported, &remote),
            Some(HybridCipherSuite::X25519MlKem512V2)
        );
        assert_eq!(
            negotiate_cipher_suite(&parsed.supported, &[1, 2]),
            Some(HybridCipherSuite::X25519MlKem768V3)
        );
    }

    #[test]
    fn test_explicit_suite_list_rejects_duplicate_or_malformed_entries() {
        let identity = [0x31u8; 32];
        let pq_comm = [0x77u8; 32];
        let (_, x_public) = generate_x25519_keypair();
        let (pk512, _) = generate_kyber_keypair();
        let wire = build_negotiated_handshake_pdu(
            &[HybridCipherSuite::X25519MlKem512V2],
            &identity,
            &pq_comm,
            |_| [0x44; 64],
            &x_public,
            &[(
                HybridCipherSuite::X25519MlKem512V2,
                pk512.to_bytes().to_vec(),
            )],
        )
        .expect("suite list builds");
        let mut malformed = wire.clone();
        malformed[17] = 2;
        assert!(parse_negotiated_handshake_pdu(&malformed).is_none());
        let mut truncated = wire;
        truncated.pop();
        assert!(parse_negotiated_handshake_pdu(&truncated).is_none());
    }

    #[test]
    fn test_uniform_handshake_chi_square_and_entropy_proof() {
        let mut uniform_hs_stream = Vec::new();
        let mut uniform_resp_stream = Vec::new();
        let mut legacy_stream = Vec::new();
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x47484F5354); // "GHOST"

        for _ in 0..60 {
            let mut identity = [0u8; 32];
            rng.fill_bytes(&mut identity);
            let (_, x_public) = generate_x25519_keypair();
            let (kem_public, _) = generate_kyber_keypair();
            let (ct, _) = kem_public.encapsulate();

            let mut mock_sig = [0u8; 64];
            rng.fill_bytes(&mut mock_sig);

            let u_hs = build_uniform_handshake_pdu(&identity, |_| mock_sig, &x_public, &kem_public);
            uniform_hs_stream.extend_from_slice(&u_hs);

            let ct_fixed: &[u8; 768] = ct
                .as_slice()
                .try_into()
                .expect("ML-KEM-512 ct is 768 bytes");
            let u_resp =
                build_uniform_response_pdu(&identity, |_| mock_sig, x_public.as_bytes(), ct_fixed);
            uniform_resp_stream.extend_from_slice(&u_resp);

            let leg_pdu = build_handshake_pdu(&identity, |_| mock_sig, &x_public, &kem_public);
            legacy_stream.extend_from_slice(&leg_pdu);
        }

        let hs_entropy = calculate_shannon_entropy(&uniform_hs_stream);
        let resp_entropy = calculate_shannon_entropy(&uniform_resp_stream);
        let leg_entropy = calculate_shannon_entropy(&legacy_stream);

        assert!(
            hs_entropy > 7.90,
            "Uniform handshake entropy should exceed 7.90: got {}",
            hs_entropy
        );
        assert!(
            resp_entropy > 7.95,
            "Uniform response entropy should exceed 7.95: got {}",
            resp_entropy
        );

        let (resp_chi, resp_p) = calculate_chi_square_uniformity(&uniform_resp_stream);
        let (leg_chi, leg_p) = calculate_chi_square_uniformity(&legacy_stream);

        assert!(
            resp_p > 0.01,
            "Uniform response PDU failed chi-square test: chi2={}, p={}",
            resp_chi,
            resp_p
        );

        assert!(
            leg_chi > resp_chi,
            "Legacy handshake should exhibit higher chi-square deviation than uniform: legacy={}, resp={}",
            leg_chi,
            resp_chi
        );
        assert!(
            leg_entropy < resp_entropy,
            "Legacy handshake with ASCII header should have lower entropy: legacy={}, resp={}",
            leg_entropy,
            resp_entropy
        );
        let _ = leg_p;
    }

    #[test]
    fn test_present_tense_mesh_presence_proof_and_replay_rejection() {
        let current_entropy = b"live_poisson_beacon_entropy_pool_data";
        let live_epoch = 50u64;

        let proof = PresenceProof::new(current_entropy, live_epoch);
        assert!(proof.verify(current_entropy, live_epoch, 1).is_ok());

        assert!(proof.verify(current_entropy, live_epoch + 1, 1).is_ok());
        assert!(proof.verify(current_entropy, live_epoch - 1, 1).is_ok());

        let stale_proof = PresenceProof::new(current_entropy, 10);
        let stale_res = stale_proof.verify(current_entropy, live_epoch, 1);
        assert!(
            stale_res.is_err(),
            "Replay from past epoch must be rejected"
        );

        let fake_entropy = b"attacker_forged_or_remote_entropy_data";
        let mismatched_proof = PresenceProof::new(fake_entropy, live_epoch);
        let mismatch_res = mismatched_proof.verify(current_entropy, live_epoch, 1);
        assert!(
            mismatch_res.is_err(),
            "Mismatched beacon entropy must be rejected"
        );

        let x_ss = [0x11u8; 32];
        let kyber_ss = [0x22u8; 32];
        let key1 = derive_hybrid_master_key_with_presence(
            HybridCipherSuite::X25519MlKem512V2,
            &x_ss,
            &kyber_ss,
            None,
            Some(&proof),
        );
        let key2 = derive_hybrid_master_key_with_presence(
            HybridCipherSuite::X25519MlKem512V2,
            &x_ss,
            &kyber_ss,
            None,
            Some(&proof),
        );
        assert_eq!(key1, key2);

        let key_other = derive_hybrid_master_key_with_presence(
            HybridCipherSuite::X25519MlKem512V2,
            &x_ss,
            &kyber_ss,
            None,
            Some(&mismatched_proof),
        );
        assert_ne!(key1, key_other);
    }
}
