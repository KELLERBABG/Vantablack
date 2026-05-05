use reed_solomon_erasure::galois_8::ReedSolomon;
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use gf256::shamir::shamir;
use ed25519_dalek::{SigningKey, Signer};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KyberTrait;

pub const HANDSHAKE_BLOB_LEN: usize = 960;
pub const HANDSHAKE_SHARD_LEN: usize = HANDSHAKE_BLOB_LEN / 2; // 480

/// Derive a 12-byte ChaCha20-Poly1305 nonce from a 64-bit monotonic counter.
///
/// Layout: `[ counter (8 B, big-endian) | 0x00 0x00 0x00 0x00 (4 B) ]`
///
/// Because the counter is strictly monotonic and unique per message, the nonce
/// is unique per (key, message) pair, satisfying the AEAD uniqueness requirement.
pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Encrypt `data` in-place using ChaCha20-Poly1305 with the given 32-byte key.
/// The nonce is derived from `counter`, which must be unique per message under
/// this key. The 16-byte Poly1305 authentication tag is appended to `data`.
pub fn encrypt_message(key: &[u8; 32], counter: u64, data: &mut Vec<u8>) {
    let enc_key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap());
    enc_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_from_counter(counter)),
            aead::Aad::empty(),
            data,
        )
        .unwrap();
}

/// Decrypt and authenticate an in-place ciphertext using ChaCha20-Poly1305.
/// `counter` must match the value used during encryption. Returns a slice of
/// the plaintext on success, or an error if the tag is invalid or nonce mismatches.
pub fn decrypt_message<'a>(key: &[u8], counter: u64, data: &'a mut Vec<u8>) -> Result<&'a [u8], ring::error::Unspecified> {
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
    let dec_key = LessSafeKey::new(unbound);
    dec_key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce_from_counter(counter)),
        aead::Aad::empty(),
        data,
    )
}

/// Split `data` into two equal halves, compute a Reed-Solomon (2,1) parity shard,
/// and return all three shards `[shard0, shard1, parity]`.
pub fn rs_encode(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
    if data.len() % 2 != 0 {
        data.push(0);
    }
    let mid = data.len() / 2;
    let mut shards = vec![
        data[0..mid].to_vec(),
        data[mid..].to_vec(),
        vec![0u8; mid],
    ];
    ReedSolomon::new(2, 1).unwrap().encode(&mut shards).unwrap();
    shards
}

/// Attempt to reconstruct the original two data shards from any two of the
/// three provided `Option<Vec<u8>>` shards. Returns `Ok(())` on success.
pub fn rs_reconstruct(shards: &mut Vec<Option<Vec<u8>>>) -> Result<(), reed_solomon_erasure::Error> {
    ReedSolomon::new(2, 1).unwrap().reconstruct(shards)
}

/// Generate three Shamir shares of `secret` with a (2-of-3) threshold.
pub fn shamir_split(secret: &mut [u8; 32]) -> Vec<Vec<u8>> {
    shamir::generate(secret, 3, 2)
}

/// Reconstruct a secret from two Shamir shares.
pub fn shamir_join(share0: &[u8], share1: &[u8]) -> Vec<u8> {
    shamir::reconstruct(&[share0.to_vec(), share1.to_vec()])
}

/// Generate a fresh random 32-byte key using the OS CSPRNG.
pub fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    SystemRandom::new().fill(&mut key).unwrap();
    key
}

/// Holds all key material generated at startup for a single peer identity.
pub struct PeerIdentity {
    pub signing_key: SigningKey,
    pub x_public: XPublicKey,
    /// Consumed during actual key exchange; kept here for handshake blob construction.
    pub kyber_public: kyber512::PublicKey,
}

impl PeerIdentity {
    /// Generate a fresh ephemeral identity: Ed25519 signing key, X25519 public key,
    /// and a Kyber512 keypair. The X25519 secret is consumed here; extend this
    /// struct if ECDH completion is required later.
    pub fn generate(seed: &[u8; 32], x_secret: EphemeralSecret) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let x_public = XPublicKey::from(&x_secret);
        let (kyber_public, _kyber_secret) = kyber512::keypair();
        Self { signing_key, x_public, kyber_public }
    }

    /// Fingerprint: first 8 bytes of the Ed25519 verifying key, hex-encoded.
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.signing_key.verifying_key().to_bytes()[0..8])
    }

    /// Build the 960-byte handshake blob:
    /// `[magic(16) | x25519_pub(32) | kyber512_pub(800) | ed25519_vk(32) | sig(64)]`
    pub fn build_handshake_blob(&self) -> Vec<u8> {
        let mut blob = vec![0u8; HANDSHAKE_BLOB_LEN];
        blob[0..16].copy_from_slice(b"GHOST_HANDSHAKE_");
        blob[16..48].copy_from_slice(self.x_public.as_bytes());
        blob[48..848].copy_from_slice(self.kyber_public.as_bytes());

        let sig = self.signing_key.sign(self.kyber_public.as_bytes());
        blob[848..880].copy_from_slice(&self.signing_key.verifying_key().to_bytes());
        blob[880..944].copy_from_slice(&sig.to_bytes());
        blob
    }
}
