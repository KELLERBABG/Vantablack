/// L3 — Shamir's Secret Sharing Layer (GF(256))
///
/// Implements a (2,3) threshold scheme over GF(256):
/// - 3 shares are generated from a 32-byte secret
/// - Any 2 shares are sufficient to reconstruct the secret
/// - A single share reveals ZERO information (information-theoretic security)
///
/// This means no single intercepted GTF packet exposes the key material.
/// An adversary must capture at least 2 correctly paired shards to
/// recover the master key.
use gf256::shamir::shamir;

/// Split a 32-byte secret into 3 shares using (2,3) Shamir SSS.
/// Returns 3 shares, each approximately sizeof(secret) + overhead.
pub fn split_secret(secret: &mut [u8; 32]) -> Vec<Vec<u8>> {
    shamir::generate(secret, 3, 2)
}

/// Reconstruct the original secret from any 2 valid shares.
/// Returns the reconstructed bytes.
pub fn join_shares(share0: &[u8], share1: &[u8]) -> Vec<u8> {
    shamir::reconstruct(&[share0.to_vec(), share1.to_vec()])
}
