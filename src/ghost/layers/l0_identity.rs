//! L0 — Hybrid Identity Layer: Ed25519 + ML-DSA-65.
//!
//! Provides the permanent cryptographic identity of a GhostNet node combining
//! classical Ed25519 and post-quantum ML-DSA-65 (FIPS 204) signatures to guarantee
//! unforgeable node identity against both classical and quantum adversaries.
//!
//! ## Architectural Invariants
//! - **Ed25519**: Classical half defining node fingerprint (first 8 bytes of pubkey hex).
//! - **ML-DSA-65**: Post-quantum half derived from independent entropy to survive classical key break.
//! - **Hybrid Signatures**: Both Ed25519 and ML-DSA-65 must verify to prevent downgrade attacks.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{
    signature::{Signer as PqSigner, Verifier as PqVerifier},
    EncodedVerifyingKey, KeyExport, KeyInit, Keypair, MlDsa65, Seed as MlDsaSeed,
    Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use rand::RngCore;
use std::fs;
use std::path::Path;

pub const IDENTITY_FILE: &str = "identity.key";
pub const IDENTITY_FILE_ENV: &str = "GHOST_IDENTITY_FILE";

const IDENTITY_MAGIC: &[u8; 8] = b"GGNIDENT";
const IDENTITY_VERSION_HYBRID: u8 = 2;
const IDENTITY_V1_LEN: usize = 32;
const IDENTITY_V2_LEN: usize = 8 + 1 + 32 + 32;

pub const ML_DSA_65_SIG_LEN: usize = 3309;
pub const ML_DSA_65_PK_LEN: usize = 1952;
pub const ED25519_SIG_LEN: usize = 64;
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

pub fn identity_file_path() -> String {
    match std::env::var(IDENTITY_FILE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(explicit) => explicit,
        None => crate::ghost::paths::data_file_string(IDENTITY_FILE),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519: [u8; ED25519_SIG_LEN],
    pub pq: Vec<u8>,
}

impl HybridSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.pq);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HYBRID_SIG_LEN {
            return None;
        }
        let mut ed25519 = [0u8; ED25519_SIG_LEN];
        ed25519.copy_from_slice(&bytes[..ED25519_SIG_LEN]);
        Some(HybridSignature {
            ed25519,
            pq: bytes[ED25519_SIG_LEN..].to_vec(),
        })
    }
}

#[derive(Clone)]
pub struct GhostIdentity {
    pub long_term_signing: SigningKey,
    pq_signing: MlDsaSigningKey<MlDsa65>,
}

impl GhostIdentity {
    pub fn generate_fresh() -> Self {
        let mut ed_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ed_seed);
        let mut pq_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pq_seed);
        Self::from_seeds(ed_seed, pq_seed)
    }

    fn from_seeds(mut ed_seed: [u8; 32], mut pq_seed: [u8; 32]) -> Self {
        use zeroize::Zeroize;
        let identity = Self {
            long_term_signing: SigningKey::from_bytes(&ed_seed),
            pq_signing: MlDsaSigningKey::from_seed(&MlDsaSeed::from(pq_seed)),
        };
        ed_seed.zeroize();
        pq_seed.zeroize();
        identity
    }

    pub fn is_amnesia_mode() -> bool {
        std::env::var("GHOST_AMNESIA")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    pub fn load_or_generate_opts(path: &str, amnesia: bool) -> Self {
        if amnesia || Self::is_amnesia_mode() {
            eprintln!("GHOST_AMNESIA active: ephemeral in-memory identity generated; zero persistent disk state.");
            return Self::generate_fresh();
        }
        if Path::new(path).exists() {
            match fs::read(path) {
                Ok(data) => match Self::parse_identity_file(&data) {
                    Ok((ed_seed, pq_seed, upgraded)) => {
                        let identity = Self::from_seeds(ed_seed, pq_seed);
                        if upgraded {
                            eprintln!(
                                "Upgraded identity file at {} to the hybrid format (Ed25519 + ML-DSA-65); \
                                 fingerprint {} is unchanged",
                                path,
                                identity.fingerprint()
                            );
                            identity.save(path);
                        }
                        return identity;
                    }
                    Err(why) => {
                        eprintln!("Corrupted identity file at {}: {}", path, why);
                    }
                },
                Err(e) => {
                    eprintln!("Could not read identity file at {}: {}", path, e);
                }
            }
        }
        let identity = Self::generate_fresh();
        identity.save(path);
        identity
    }

    pub fn load_or_generate(path: &str) -> Self {
        Self::load_or_generate_opts(path, false)
    }

    fn parse_identity_file(data: &[u8]) -> Result<([u8; 32], [u8; 32], bool), &'static str> {
        if data.len() == IDENTITY_V1_LEN {
            let mut ed_seed = [0u8; 32];
            ed_seed.copy_from_slice(data);
            let mut pq_seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut pq_seed);
            return Ok((ed_seed, pq_seed, true));
        }
        if data.len() == IDENTITY_V2_LEN {
            if &data[..8] != IDENTITY_MAGIC {
                return Err("wrong magic");
            }
            if data[8] != IDENTITY_VERSION_HYBRID {
                return Err("unknown identity-file version");
            }
            let mut ed_seed = [0u8; 32];
            ed_seed.copy_from_slice(&data[9..41]);
            let mut pq_seed = [0u8; 32];
            pq_seed.copy_from_slice(&data[41..73]);
            return Ok((ed_seed, pq_seed, false));
        }
        Err("unexpected length")
    }

    fn save(&self, path: &str) {
        use zeroize::Zeroize;
        let mut buf = Vec::with_capacity(IDENTITY_V2_LEN);
        buf.extend_from_slice(IDENTITY_MAGIC);
        buf.push(IDENTITY_VERSION_HYBRID);
        buf.extend_from_slice(&self.long_term_signing.to_bytes());
        buf.extend_from_slice(self.pq_signing.to_bytes().as_slice());
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
                    .and_then(|mut file| file.write_all(&buf))
            }
            #[cfg(not(unix))]
            {
                fs::write(path, &buf)
            }
        };
        buf.zeroize();
        if let Err(e) = write_res {
            eprintln!("Warning: could not save identity to {}: {}", path, e);
        } else {
            eprintln!("Saved identity to {}", path);
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.long_term_signing.verifying_key()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    pub fn pq_public_key_bytes(&self) -> Vec<u8> {
        self.pq_signing
            .verifying_key()
            .to_bytes()
            .as_slice()
            .to_vec()
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(&self.public_key_bytes()[0..8])
    }

    pub fn node_id_v3(&self) -> NodeIdV3 {
        NodeIdV3::compute(&self.public_key_bytes(), &self.pq_public_key_bytes())
    }

    pub fn pq_fingerprint(&self) -> String {
        self.node_id_v3().to_short_hex()
    }

    pub fn derive_burnable(&self, peer_fp: &str, epoch: u32) -> (SigningKey, String) {
        use hkdf::Hkdf;
        use sha2::Sha256;
        use zeroize::Zeroize;

        let master_seed = self.long_term_signing.to_bytes();
        let hk = Hkdf::<Sha256>::new(Some(b"GHOST_BURNABLE_ID_v1"), &master_seed);
        let mut info = Vec::with_capacity(peer_fp.len() + 4);
        info.extend_from_slice(peer_fp.as_bytes());
        info.extend_from_slice(&epoch.to_be_bytes());

        let mut derived_seed = [0u8; 32];
        hk.expand(&info, &mut derived_seed)
            .expect("32 bytes is valid length for HKDF expansion");

        let burnable_key = SigningKey::from_bytes(&derived_seed);
        derived_seed.zeroize();

        let burnable_fp = hex::encode(&burnable_key.verifying_key().to_bytes()[0..8]);
        (burnable_key, burnable_fp)
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.long_term_signing.sign(data)
    }

    pub fn sign_hybrid(&self, data: &[u8]) -> HybridSignature {
        let pq = self.pq_signing.sign(data);
        HybridSignature {
            ed25519: self.long_term_signing.sign(data).to_bytes(),
            pq: pq.encode().as_slice().to_vec(),
        }
    }

    pub fn verify(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.verifying_key().verify(data, signature)
    }

    pub fn pq_commitment(&self) -> [u8; 32] {
        pq_commitment(&self.pq_public_key_bytes())
    }

    pub fn verify_hybrid(&self, data: &[u8], signature: &HybridSignature) -> bool {
        verify_peer_hybrid(
            &self.public_key_bytes(),
            &self.pq_public_key_bytes(),
            data,
            signature,
        )
    }
}

pub fn pq_commitment(pq_public_key: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"ggn-pq-commitment-v1");
    h.update(pq_public_key);
    h.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeIdV3(pub [u8; 32]);

impl NodeIdV3 {
    pub fn compute(ed25519_pk: &[u8; 32], mldsa65_pk: &[u8]) -> Self {
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(b"VB-ID-V3");
        h.update(ed25519_pk);
        h.update(mldsa65_pk);
        Self(h.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.0[..16]);
        out
    }

    pub fn to_short_hex(&self) -> String {
        hex::encode(self.short_bytes())
    }

    pub fn to_ula_ipv6(&self) -> std::net::Ipv6Addr {
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1] = 0x7b;
        octets[2..16].copy_from_slice(&self.0[..14]);
        std::net::Ipv6Addr::from(octets)
    }
}

pub fn verify_pq_identity_binding(
    expected_id: &NodeIdV3,
    ed25519_pk: &[u8; 32],
    mldsa65_pk: &[u8],
) -> Result<(), &'static str> {
    use subtle::ConstantTimeEq;
    if mldsa65_pk.len() != ML_DSA_65_PK_LEN {
        return Err("invalid ML-DSA-65 public key length");
    }
    let computed = NodeIdV3::compute(ed25519_pk, mldsa65_pk);
    if computed.0.ct_eq(&expected_id.0).into() {
        Ok(())
    } else {
        Err("PQ identity binding mismatch")
    }
}

pub fn verify_peer_signature(peer_pk_bytes: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
    if let Ok(peer_pk) = VerifyingKey::from_bytes(peer_pk_bytes) {
        let sig = Signature::from_bytes(signature);
        return peer_pk.verify(data, &sig).is_ok();
    }
    false
}

pub fn verify_pq_signature(pq_pk_bytes: &[u8], data: &[u8], signature: &[u8]) -> bool {
    if signature.len() != ML_DSA_65_SIG_LEN || pq_pk_bytes.len() != ML_DSA_65_PK_LEN {
        return false;
    }
    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa65>::try_from(pq_pk_bytes) else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::new(&encoded_key);
    let Ok(sig) = MlDsaSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    vk.verify(data, &sig).is_ok()
}

pub fn verify_peer_hybrid(
    peer_pk_bytes: &[u8; 32],
    peer_pq_pk_bytes: &[u8],
    data: &[u8],
    signature: &HybridSignature,
) -> bool {
    verify_peer_signature(peer_pk_bytes, data, &signature.ed25519)
        && verify_pq_signature(peer_pq_pk_bytes, data, &signature.pq)
}

pub const BINDING_VERSION_HYBRID: u8 = 0x02;

pub const BINDING_LEN_HYBRID: usize =
    1 + 32 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

pub fn identity_binding_material(channel_binding: &[u8], pq_pk: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(channel_binding.len() + pq_pk.len());
    msg.extend_from_slice(channel_binding);
    msg.extend_from_slice(pq_pk);
    msg
}

pub fn create_identity_binding(identity: &GhostIdentity, channel_binding: &[u8]) -> Vec<u8> {
    let pq_pk = identity.pq_public_key_bytes();
    let msg = identity_binding_material(channel_binding, &pq_pk);
    let sig = identity.sign_hybrid(&msg);
    let mut out = Vec::with_capacity(BINDING_LEN_HYBRID);
    out.push(BINDING_VERSION_HYBRID);
    out.extend_from_slice(&identity.public_key_bytes());
    out.extend_from_slice(&pq_pk);
    out.extend_from_slice(&sig.ed25519);
    out.extend_from_slice(&sig.pq);
    out
}

pub fn verify_hybrid_binding(
    peer_ed_pk: &[u8; 32],
    expected_pq_commitment: Option<&[u8; 32]>,
    channel_binding: &[u8],
    binding: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if binding.len() != BINDING_LEN_HYBRID || binding[0] != BINDING_VERSION_HYBRID {
        return Err("invalid binding length or version");
    }
    if &binding[1..33] != peer_ed_pk {
        return Err("mismatched peer Ed25519 key");
    }
    let pq_pk = &binding[33..33 + ML_DSA_65_PK_LEN];
    if let Some(expected_com) = expected_pq_commitment {
        if &pq_commitment(pq_pk) != expected_com {
            return Err("mismatched PQ commitment");
        }
    }
    let ed_sig = &binding[33 + ML_DSA_65_PK_LEN..33 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN];
    let pq_sig = &binding[33 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN..];
    let material = identity_binding_material(channel_binding, pq_pk);
    let Ok(ed_sig_arr) = <&[u8; ED25519_SIG_LEN]>::try_from(ed_sig) else {
        return Err("invalid Ed25519 signature format");
    };
    if !verify_peer_signature(peer_ed_pk, &material, ed_sig_arr) {
        return Err("Ed25519 signature invalid");
    }
    if !verify_pq_signature(pq_pk, &material, pq_sig) {
        return Err("ML-DSA-65 signature invalid");
    }
    Ok(pq_pk.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> String {
        let dir =
            std::env::temp_dir().join(format!("ggn-identity-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("identity.key").to_string_lossy().into_owned()
    }

    #[test]
    fn the_declared_lengths_are_the_crates_lengths() {
        let id = GhostIdentity::generate_fresh();
        assert_eq!(id.pq_public_key_bytes().len(), ML_DSA_65_PK_LEN);
        assert_eq!(id.sign_hybrid(b"m").pq.len(), ML_DSA_65_SIG_LEN);
        assert_eq!(id.sign_hybrid(b"m").encode().len(), HYBRID_SIG_LEN);
    }

    #[test]
    fn the_commitment_is_a_hash_of_the_pq_key_and_nothing_else() {
        use sha2::Digest;
        let id = GhostIdentity::generate_fresh();
        assert_eq!(id.pq_commitment(), pq_commitment(&id.pq_public_key_bytes()));
        let other = GhostIdentity::generate_fresh();
        assert_ne!(id.pq_commitment(), other.pq_commitment());
        let bare = sha2::Sha256::digest(id.pq_public_key_bytes());
        assert_ne!(id.pq_commitment().to_vec(), bare.to_vec());
    }

    #[test]
    fn a_hybrid_signature_verifies_only_with_both_halves() {
        let id = GhostIdentity::generate_fresh();
        let other = GhostIdentity::generate_fresh();
        let msg = b"handshake-material";
        let sig = id.sign_hybrid(msg);

        assert!(id.verify_hybrid(msg, &sig));
        assert!(verify_peer_hybrid(
            &id.public_key_bytes(),
            &id.pq_public_key_bytes(),
            msg,
            &sig
        ));
        assert!(!id.verify_hybrid(b"other-material", &sig));
        assert!(!verify_peer_hybrid(
            &other.public_key_bytes(),
            &id.pq_public_key_bytes(),
            msg,
            &sig
        ));
        assert!(!verify_peer_hybrid(
            &id.public_key_bytes(),
            &other.pq_public_key_bytes(),
            msg,
            &sig
        ));
    }

    #[test]
    fn neither_half_can_carry_a_tampered_signature() {
        let id = GhostIdentity::generate_fresh();
        let msg = b"material";
        let mut sig = id.sign_hybrid(msg);
        sig.ed25519[0] ^= 0x01;
        assert!(!id.verify_hybrid(msg, &sig));

        let mut sig = id.sign_hybrid(msg);
        sig.pq[0] ^= 0x01;
        assert!(!id.verify_hybrid(msg, &sig));
    }

    #[test]
    fn the_wire_encoding_round_trips_and_rejects_other_lengths() {
        let id = GhostIdentity::generate_fresh();
        let sig = id.sign_hybrid(b"material");
        let enc = sig.encode();
        assert_eq!(HybridSignature::decode(&enc).as_ref(), Some(&sig));
        assert!(HybridSignature::decode(&enc[..enc.len() - 1]).is_none());
        assert!(HybridSignature::decode(&[]).is_none());
    }

    #[test]
    fn a_malformed_pq_signature_is_refused() {
        let id = GhostIdentity::generate_fresh();
        let msg = b"material";
        assert!(!verify_pq_signature(&id.pq_public_key_bytes(), msg, &[]));
        assert!(!verify_pq_signature(
            &id.pq_public_key_bytes(),
            msg,
            &vec![0u8; ML_DSA_65_SIG_LEN - 1]
        ));
        assert!(!verify_pq_signature(
            &id.pq_public_key_bytes(),
            msg,
            &vec![0u8; ML_DSA_65_SIG_LEN]
        ));
        let other = GhostIdentity::generate_fresh();
        let sig = id.sign_hybrid(msg);
        assert!(!verify_pq_signature(
            &other.pq_public_key_bytes(),
            msg,
            &sig.pq
        ));
    }

    #[test]
    fn the_pq_key_is_not_derived_from_the_classical_seed() {
        let seed = [7u8; 32];
        let path_a = tmp_path("independence-a");
        let path_b = tmp_path("independence-b");
        for path in [&path_a, &path_b] {
            std::fs::write(path, seed).expect("write a v1 identity file");
            let _ = std::fs::remove_file(path);
            std::fs::write(path, seed).expect("write a v1 identity file");
        }
        let a = GhostIdentity::load_or_generate(&path_a);
        let b = GhostIdentity::load_or_generate(&path_b);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_ne!(a.pq_public_key_bytes(), b.pq_public_key_bytes());
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn a_v1_identity_file_is_upgraded_without_changing_the_fingerprint() {
        let path = tmp_path("migrate");
        let seed = [3u8; 32];
        std::fs::write(&path, seed).expect("write a v1 identity file");
        assert_eq!(
            std::fs::read(&path).expect("read").len(),
            IDENTITY_V1_LEN,
            "the fixture must start as a v1 file"
        );

        let upgraded = GhostIdentity::load_or_generate(&path);
        let expected_fingerprint =
            hex::encode(&SigningKey::from_bytes(&seed).verifying_key().to_bytes()[0..8]);
        assert_eq!(
            upgraded.fingerprint(),
            expected_fingerprint,
            "the classical half — and so every pairing — must survive the upgrade"
        );
        assert_eq!(
            std::fs::read(&path).expect("read").len(),
            IDENTITY_V2_LEN,
            "the hybrid form must be written back"
        );

        let reloaded = GhostIdentity::load_or_generate(&path);
        assert_eq!(reloaded.public_key_bytes(), upgraded.public_key_bytes());
        assert_eq!(
            reloaded.pq_public_key_bytes(),
            upgraded.pq_public_key_bytes()
        );
        let msg = b"after-a-restart";
        assert!(reloaded.verify_hybrid(msg, &upgraded.sign_hybrid(msg)));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unreadable_identity_file_yields_a_fresh_identity() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, b"not an identity").expect("write");
        let id = GhostIdentity::load_or_generate(&path);
        assert_eq!(id.fingerprint().len(), 16);
        assert_eq!(std::fs::read(&path).expect("read").len(), IDENTITY_V2_LEN);
        let _ = std::fs::remove_file(&path);

        let mut bad = Vec::new();
        bad.extend_from_slice(b"NOTGGNID");
        bad.push(IDENTITY_VERSION_HYBRID);
        bad.extend_from_slice(&[1u8; 32]);
        bad.extend_from_slice(&[2u8; 32]);
        assert!(GhostIdentity::parse_identity_file(&bad).is_err());
        let mut bad_version = bad.clone();
        bad_version[..8].copy_from_slice(IDENTITY_MAGIC);
        bad_version[8] = 0x7f;
        assert!(GhostIdentity::parse_identity_file(&bad_version).is_err());
    }

    #[test]
    fn test_hybrid_identity_binding_roundtrip() {
        let alice = GhostIdentity::generate_fresh();
        let bob = GhostIdentity::generate_fresh();
        let channel = b"test-channel-binding-1234";

        let binding = create_identity_binding(&alice, channel);
        assert_eq!(binding.len(), BINDING_LEN_HYBRID);

        let pq_pk = verify_hybrid_binding(
            &alice.public_key_bytes(),
            Some(&alice.pq_commitment()),
            channel,
            &binding,
        )
        .expect("valid binding must verify");
        assert_eq!(pq_pk, alice.pq_public_key_bytes());

        assert!(verify_hybrid_binding(
            &alice.public_key_bytes(),
            Some(&alice.pq_commitment()),
            b"different-channel",
            &binding,
        )
        .is_err());

        assert!(verify_hybrid_binding(
            &bob.public_key_bytes(),
            Some(&alice.pq_commitment()),
            channel,
            &binding,
        )
        .is_err());

        assert!(verify_hybrid_binding(
            &alice.public_key_bytes(),
            Some(&bob.pq_commitment()),
            channel,
            &binding,
        )
        .is_err());
    }

    #[test]
    fn test_burnable_identity_1000_distinct_peers_yield_1000_unique_fps() {
        use std::collections::HashSet;
        let identity = GhostIdentity::generate_fresh();
        let master_fp = identity.fingerprint();

        let mut fps = HashSet::new();
        for i in 0..1000 {
            let peer_fp = format!("peer_{:04x}", i);
            let (_key, burnable_fp) = identity.derive_burnable(&peer_fp, 0);

            assert_ne!(burnable_fp, master_fp);
            assert_eq!(burnable_fp.len(), 16); // 8 bytes hex = 16 hex chars
            fps.insert(burnable_fp);
        }

        assert_eq!(fps.len(), 1000);
    }

    #[test]
    fn test_burnable_identity_deterministic_recovery_and_epoch_rotation() {
        let identity = GhostIdentity::generate_fresh();
        let peer_fp = "a1b2c3d4e5f60718";

        let (k1, fp1) = identity.derive_burnable(peer_fp, 0);
        let (k2, fp2) = identity.derive_burnable(peer_fp, 0);
        assert_eq!(fp1, fp2);
        assert_eq!(k1.to_bytes(), k2.to_bytes());

        let (k_next, fp_next) = identity.derive_burnable(peer_fp, 1);
        assert_ne!(fp1, fp_next);
        assert_ne!(k1.to_bytes(), k_next.to_bytes());

        let message = b"hello from burnable ghost identity";
        let signature = k1.sign(message);
        assert!(k1
            .verifying_key()
            .verify_strict(message, &signature)
            .is_ok());
    }

    #[test]
    fn test_amnesia_mode_zero_disk_state() {
        let temp_dir =
            std::env::temp_dir().join(format!("ggn_amnesia_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let key_path = temp_dir.join("ephemeral_identity.key");
        let key_path_str = key_path.to_str().unwrap();

        let id = GhostIdentity::load_or_generate_opts(key_path_str, true);

        assert!(
            !key_path.exists(),
            "Amnesia mode must never write identity.key to disk"
        );
        assert_eq!(id.fingerprint().len(), 16);

        let normal_id = GhostIdentity::load_or_generate_opts(key_path_str, false);

        assert!(key_path.exists(), "Normal mode writes identity.key to disk");
        assert_eq!(normal_id.fingerprint().len(), 16);

        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn node_id_v3_is_deterministic_and_matches_sha3_256() {
        use sha3::Digest;
        let id = GhostIdentity::generate_fresh();
        let ed_pk = id.public_key_bytes();
        let pq_pk = id.pq_public_key_bytes();

        let node_id = id.node_id_v3();
        assert_eq!(node_id, NodeIdV3::compute(&ed_pk, &pq_pk));
        assert!(verify_pq_identity_binding(&node_id, &ed_pk, &pq_pk).is_ok());

        let mut h = sha3::Sha3_256::new();
        h.update(b"VB-ID-V3");
        h.update(ed_pk);
        h.update(&pq_pk);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(node_id.as_bytes(), &expected);
    }

    #[test]
    fn node_id_v3_rejects_swapped_mldsa65_key_even_with_same_ed25519_key() {
        let victim = GhostIdentity::generate_fresh();
        let attacker = GhostIdentity::generate_fresh();

        let expected_id = victim.node_id_v3();
        let victim_ed_pk = victim.public_key_bytes();
        let attacker_pq_pk = attacker.pq_public_key_bytes();

        let res = verify_pq_identity_binding(&expected_id, &victim_ed_pk, &attacker_pq_pk);
        assert!(res.is_err());
        assert_ne!(
            NodeIdV3::compute(&victim_ed_pk, &attacker_pq_pk),
            expected_id
        );
    }

    #[test]
    fn node_id_v3_rejects_malformed_mldsa65_key_length() {
        let id = GhostIdentity::generate_fresh();
        let expected_id = id.node_id_v3();
        let ed_pk = id.public_key_bytes();
        let short_pq_pk = vec![0u8; ML_DSA_65_PK_LEN - 1];

        assert!(verify_pq_identity_binding(&expected_id, &ed_pk, &short_pq_pk).is_err());
    }

    #[test]
    fn node_id_v3_display_and_ula_helpers() {
        let id = GhostIdentity::generate_fresh();
        let node_id = id.node_id_v3();

        let pq_fp = id.pq_fingerprint();
        assert_eq!(pq_fp.len(), 32);
        assert_eq!(pq_fp, node_id.to_short_hex());
        assert_eq!(hex::encode(node_id.short_bytes()), pq_fp);

        let ula = node_id.to_ula_ipv6();
        let octets = ula.octets();
        assert_eq!(octets[0], 0xfd);
        assert_eq!(octets[1], 0x7b);
        assert_eq!(&octets[2..16], &node_id.as_bytes()[..14]);
    }
}
