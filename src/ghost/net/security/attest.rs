//! DPE/TPM-shaped attestation envelope.
//!
//! ## What this is — and what it is not
//!
//! This is the **format and its verification**, not a hardware integration.
//! Nothing here talks to a device: there is no TPM and no DPE, and no test in
//! this module can prove that a *real* quote is authentic. What it does is fix
//! the wire shape a quote travels in, and the checks an envelope must pass
//! ([`AttestationEnvelope::verify`]), so that wiring a real backend later is a
//! matter of *producing* the fields rather than renegotiating their layout.
//!
//! The shape mirrors a DPE `CertifyKey` / TPM `Quote` result on purpose:
//!
//! * a **measurement digest** (the TPM's PCR digest / DPE's `measurement`),
//! * a **nonce** chosen by the verifier (freshness, anti-replay),
//! * the **issuer public key** the quote is bound to, and
//! * a **signature** over all of the above.
//!
//! The signature is Ed25519 via the in-tree `ed25519_dalek`, so an envelope is
//! verifiable with no hardware at all. A future hybrid (ML-DSA) issuer rides the
//! same layout with a longer signature field and a bumped [`VERSION`].
//!
//! ## Wire format (version 1)
//!
//! ```text
//! offset  size  field
//!      0     6  magic         "GGNATT"
//!      6     1  version       == VERSION
//!      7    32  quote_digest  measurement (PCR / DPE digest)
//!     39    32  nonce         verifier-chosen freshness value
//!     71    32  issuer_pk     Ed25519 public key of the quoter
//!    103    64  signature     Ed25519 over bytes [0, 103)
//! ```
//!
//! Every field is a byte string, so no endianness question arises. The version
//! byte is a *bump* point rather than a flag day: [`decode`](AttestationEnvelope::decode)
//! refuses a version it does not know instead of guessing.

use subtle::ConstantTimeEq;

pub const MAGIC: [u8; 6] = *b"GGNATT";
pub const VERSION: u8 = 1;
pub const DIGEST_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const ISSUER_PK_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

const HEADER_LEN: usize = MAGIC.len() + 1;
const SIGNED_LEN: usize = HEADER_LEN + DIGEST_LEN + NONCE_LEN + ISSUER_PK_LEN;
pub const ENCODED_LEN: usize = SIGNED_LEN + SIGNATURE_LEN;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    #[error("attestation envelope is {got} bytes, expected {expected}")]
    BadLength { got: usize, expected: usize },
    #[error("attestation envelope magic is wrong")]
    BadMagic,
    #[error("unsupported attestation envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("attestation envelope names a different issuer key")]
    IssuerMismatch,
    #[error("attestation envelope nonce does not match the expected nonce")]
    NonceMismatch,
    #[error("attestation signature does not verify")]
    BadSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEnvelope {
    pub quote_digest: [u8; DIGEST_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub issuer_pk: [u8; ISSUER_PK_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

impl AttestationEnvelope {
    fn signed_region(
        quote_digest: &[u8; DIGEST_LEN],
        nonce: &[u8; NONCE_LEN],
        issuer_pk: &[u8; ISSUER_PK_LEN],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(quote_digest);
        out.extend_from_slice(nonce);
        out.extend_from_slice(issuer_pk);
        out
    }

    pub fn issue(
        issuer: &ed25519_dalek::SigningKey,
        quote_digest: [u8; DIGEST_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Self {
        use ed25519_dalek::Signer;
        let issuer_pk = issuer.verifying_key().to_bytes();
        let region = Self::signed_region(&quote_digest, &nonce, &issuer_pk);
        let signature = issuer.sign(&region).to_bytes();
        Self {
            quote_digest,
            nonce,
            issuer_pk,
            signature,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Self::signed_region(&self.quote_digest, &self.nonce, &self.issuer_pk);
        out.extend_from_slice(&self.signature);
        debug_assert_eq!(out.len(), ENCODED_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AttestError> {
        if bytes.len() != ENCODED_LEN {
            return Err(AttestError::BadLength {
                got: bytes.len(),
                expected: ENCODED_LEN,
            });
        }
        if bytes[..MAGIC.len()] != MAGIC {
            return Err(AttestError::BadMagic);
        }
        let version = bytes[MAGIC.len()];
        if version != VERSION {
            return Err(AttestError::UnsupportedVersion(version));
        }

        let mut quote_digest = [0u8; DIGEST_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut issuer_pk = [0u8; ISSUER_PK_LEN];
        let mut signature = [0u8; SIGNATURE_LEN];
        quote_digest.copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN + DIGEST_LEN]);
        nonce.copy_from_slice(&bytes[HEADER_LEN + DIGEST_LEN..HEADER_LEN + DIGEST_LEN + NONCE_LEN]);
        issuer_pk.copy_from_slice(&bytes[HEADER_LEN + DIGEST_LEN + NONCE_LEN..SIGNED_LEN]);
        signature.copy_from_slice(&bytes[SIGNED_LEN..ENCODED_LEN]);

        Ok(Self {
            quote_digest,
            nonce,
            issuer_pk,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_nonce: &[u8; NONCE_LEN],
        issuer_pk: &[u8; ISSUER_PK_LEN],
    ) -> Result<(), AttestError> {
        use ed25519_dalek::Verifier;
        if !bool::from(self.nonce.as_slice().ct_eq(expected_nonce.as_slice())) {
            return Err(AttestError::NonceMismatch);
        }
        if !bool::from(self.issuer_pk.as_slice().ct_eq(issuer_pk.as_slice())) {
            return Err(AttestError::IssuerMismatch);
        }
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.issuer_pk)
            .map_err(|_| AttestError::BadSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        let region = Self::signed_region(&self.quote_digest, &self.nonce, &self.issuer_pk);
        verifying_key
            .verify(&region, &signature)
            .map_err(|_| AttestError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn encode_decode_round_trips() {
        let sk = issuer();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);
        let bytes = env.encode();
        assert_eq!(bytes.len(), ENCODED_LEN);
        assert_eq!(&bytes[..MAGIC.len()], &MAGIC);
        assert_eq!(bytes[MAGIC.len()], VERSION);
        let back = AttestationEnvelope::decode(&bytes).expect("a well-formed envelope decodes");
        assert_eq!(back, env, "decode is the exact inverse of encode");
    }

    #[test]
    fn a_valid_envelope_verifies() {
        let sk = issuer();
        let pk = sk.verifying_key().to_bytes();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);
        assert_eq!(env.verify(&[0x22; NONCE_LEN], &pk), Ok(()));
    }

    #[test]
    fn a_stale_nonce_is_rejected() {
        let sk = issuer();
        let pk = sk.verifying_key().to_bytes();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);
        assert_eq!(
            env.verify(&[0x23; NONCE_LEN], &pk),
            Err(AttestError::NonceMismatch)
        );
    }

    #[test]
    fn a_tampered_nonce_in_the_envelope_is_rejected() {
        let sk = issuer();
        let pk = sk.verifying_key().to_bytes();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);

        let mut bytes = env.encode();
        bytes[HEADER_LEN + DIGEST_LEN] ^= 0x01; // first byte of the nonce
        let tampered = AttestationEnvelope::decode(&bytes).expect("still well-framed");
        assert_ne!(tampered.nonce, env.nonce, "the nonce field did change");
        assert_eq!(
            tampered.verify(&tampered.nonce, &pk),
            Err(AttestError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_digest_is_rejected() {
        let sk = issuer();
        let pk = sk.verifying_key().to_bytes();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);

        let mut bytes = env.encode();
        bytes[HEADER_LEN] ^= 0x01; // first byte of the digest
        let tampered = AttestationEnvelope::decode(&bytes).expect("still well-framed");
        assert_eq!(
            tampered.verify(&[0x22; NONCE_LEN], &pk),
            Err(AttestError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let sk = issuer();
        let pk = sk.verifying_key().to_bytes();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);

        let mut bytes = env.encode();
        bytes[SIGNED_LEN] ^= 0x01; // first byte of the signature
        let tampered = AttestationEnvelope::decode(&bytes).expect("still well-framed");
        assert_eq!(
            tampered.verify(&[0x22; NONCE_LEN], &pk),
            Err(AttestError::BadSignature)
        );
    }

    #[test]
    fn an_envelope_from_another_issuer_is_rejected() {
        let sk = issuer();
        let other = issuer();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);
        assert_eq!(
            env.verify(&[0x22; NONCE_LEN], &other.verifying_key().to_bytes()),
            Err(AttestError::IssuerMismatch)
        );
    }

    #[test]
    fn decode_refuses_the_wrong_shape() {
        let sk = issuer();
        let env = AttestationEnvelope::issue(&sk, [0x11; DIGEST_LEN], [0x22; NONCE_LEN]);
        let good = env.encode();

        let short = &good[..ENCODED_LEN - 1];
        assert_eq!(
            AttestationEnvelope::decode(short),
            Err(AttestError::BadLength {
                got: ENCODED_LEN - 1,
                expected: ENCODED_LEN
            })
        );

        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(
            AttestationEnvelope::decode(&bad_magic),
            Err(AttestError::BadMagic)
        );

        let mut bad_version = good;
        bad_version[MAGIC.len()] = VERSION.wrapping_add(1);
        assert_eq!(
            AttestationEnvelope::decode(&bad_version),
            Err(AttestError::UnsupportedVersion(VERSION.wrapping_add(1)))
        );
    }
}
