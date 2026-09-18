use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{
    signature::{Signer as PqSigner, Verifier as PqVerifier},
    EncodedVerifyingKey, KeyExport, KeyInit, Keypair, MlDsa65, Seed as MlDsaSeed,
    Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use rand::RngCore;
/// L0 — Hybrid identity: Ed25519 + ML-DSA-65 (SOTA P2-1).
///
/// The permanent cryptographic identity of a GhostNet node, and the reason it is
/// **hybrid** rather than Ed25519-only: every other defence in this stack —
/// ML-KEM-512 key agreement, ChaCha20-Poly1305 transport, RS sharding — rests on
/// the identity being unforgeable, and Ed25519 alone is forgeable by Shor's
/// algorithm on a cryptographically relevant quantum computer. A node whose name
/// can be forged cannot be trusted to hold a session, however good the session's
/// own cryptography is.
///
/// ## Two keys, two independent secrets
///
/// * **Ed25519** — the classical half, and the one that defines the fingerprint
///   (first 8 bytes of the public key, hex). Unchanged from v0.4.1, because every
///   peer table, allowlist (`GHOST_VPN_CLIENTS`) and cached pairing is keyed on
///   that string; re-deriving it would un-pair every existing node.
/// * **ML-DSA-65** (FIPS 204, security category 3) — the post-quantum half. Its
///   seed is drawn from its **own** entropy, never derived from the Ed25519 seed.
///   That is not tidiness: a PQ key derived from the classical secret would be
///   recovered by whoever breaks the classical key, which is exactly the event
///   the PQ half exists to survive.
///
/// ## The file, and the migration
///
/// * **v1** (what v0.4.1 wrote): exactly 32 bytes — the Ed25519 seed.
/// * **v2** (this): `GGNIDENT` + version byte + 32-byte Ed25519 seed + 32-byte
///   ML-DSA seed = 73 bytes.
///
/// A v1 file is upgraded **in place** on first load: the Ed25519 key is preserved
/// (so the fingerprint — and every pairing — is preserved), a fresh ML-DSA key is
/// generated from new entropy, and the file is rewritten as v2. An unreadable file
/// still means a fresh identity, which is the pre-existing behaviour and is
/// reported on stderr rather than silently.
///
/// ## What proves what
///
/// [`GhostIdentity::sign`] is Ed25519 and stays 64 bytes, so the beacons and
/// handshake PDUs that already carry it are untouched and interoperate with
/// un-upgraded peers. [`GhostIdentity::sign_hybrid`] additionally signs with
/// ML-DSA-65 and returns both signatures as one value; a hybrid signature is
/// **valid only if both halves verify**, so the classical half cannot be used to
/// downgrade a peer that checks both.
///
/// Signature format: 64 bytes (Ed25519), or 3373 bytes (hybrid: Ed25519 ‖ ML-DSA-65)
/// Public key size: 32 bytes (Ed25519), 1952 bytes (ML-DSA-65)
/// Fingerprint: first 8 bytes of the Ed25519 public key (hex-encoded)
use std::fs;
use std::path::Path;

/// Default filename for the persistent identity key.
pub const IDENTITY_FILE: &str = "identity.key";

/// Environment variable that overrides [`IDENTITY_FILE`].
pub const IDENTITY_FILE_ENV: &str = "GHOST_IDENTITY_FILE";

/// Magic at the head of an identity file written by this version.
const IDENTITY_MAGIC: &[u8; 8] = b"GGNIDENT";
/// Version byte for the hybrid (Ed25519 + ML-DSA-65) format.
const IDENTITY_VERSION_HYBRID: u8 = 2;
/// A v1 identity file is exactly the Ed25519 seed and nothing else.
const IDENTITY_V1_LEN: usize = 32;
/// v2: `GGNIDENT`(8) + version(1) + Ed25519 seed(32) + ML-DSA seed(32).
const IDENTITY_V2_LEN: usize = 8 + 1 + 32 + 32;

/// Encoded ML-DSA-65 signature length (FIPS 204). Asserted against the crate in
/// tests, so a dependency change that alters it fails loudly instead of
/// mis-parsing signatures written by the other side.
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// Encoded ML-DSA-65 verifying-key length.
pub const ML_DSA_65_PK_LEN: usize = 1952;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
/// A hybrid signature is the Ed25519 half followed by the ML-DSA-65 half.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

/// Resolve the identity-key path for this process.
///
/// `GHOST_IDENTITY_FILE` overrides the default, which is what separate nodes of
/// a two-node smoke test use so they do not advertise the same fingerprint
/// (PROTOTYPE.md flaw #6).
///
/// Without an override the key lives in the per-user application-data
/// directory (see [`crate::ghost::paths`]) rather than in the current working
/// directory. A key that moved with the shell's cwd meant that launching the
/// same binary from somewhere else silently produced a *different* node — and
/// therefore broke every existing pairing.
pub fn identity_file_path() -> String {
    match std::env::var(IDENTITY_FILE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(explicit) => explicit,
        None => crate::ghost::paths::data_file_string(IDENTITY_FILE),
    }
}

/// An Ed25519 signature alongside an ML-DSA-65 signature over the same bytes.
///
/// Both halves sign the same message and both are required to verify. The value
/// is deliberately a pair rather than a single byte string with a length prefix,
/// so no caller can accidentally treat "the classical half that verified" as a
/// complete proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub ed25519: [u8; ED25519_SIG_LEN],
    /// ML-DSA-65 signature ([`ML_DSA_65_SIG_LEN`] bytes).
    pub pq: Vec<u8>,
}

impl HybridSignature {
    /// Wire encoding: Ed25519 half first, then the ML-DSA-65 half.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.pq);
        out
    }

    /// Parse a wire encoding, rejecting anything of the wrong length.
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

/// A GhostNet identity backed by an Ed25519 signing key and an independent
/// ML-DSA-65 signing key.
#[derive(Clone)]
pub struct GhostIdentity {
    /// The long-term classical signing key (private). Never leaves the device.
    pub long_term_signing: SigningKey,
    /// The post-quantum signing key (private), from entropy of its own.
    pq_signing: MlDsaSigningKey<MlDsa65>,
}

impl GhostIdentity {
    /// Generate a fresh identity with random entropy for **both** keys.
    pub fn generate_fresh() -> Self {
        let mut ed_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ed_seed);
        let mut pq_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pq_seed);
        Self::from_seeds(ed_seed, pq_seed)
    }

    /// Build an identity from the two independent seeds.
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

    /// Load identity from a file, or generate a fresh ephemeral one without writing to disk
    /// if `amnesia` is true (Invention §20: Ephemeral Amnesia Mode).
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

    /// Load identity from a file, or generate a fresh one and save it.
    pub fn load_or_generate(path: &str) -> Self {
        Self::load_or_generate_opts(path, false)
    }

    /// Parse either identity-file version.
    ///
    /// Returns the two seeds and whether the file was in the pre-hybrid format
    /// (in which case it has to be written back out).
    fn parse_identity_file(data: &[u8]) -> Result<([u8; 32], [u8; 32], bool), &'static str> {
        if data.len() == IDENTITY_V1_LEN {
            let mut ed_seed = [0u8; 32];
            ed_seed.copy_from_slice(data);
            // New entropy, not a KDF of the classical seed: see the module docs.
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

    /// Write this identity to `path` in the v2 (hybrid) format.
    ///
    /// The buffer holding both seeds is zeroized after the write: the file is the
    /// only place a seed should ever sit, and a copy left in a heap allocation is
    /// a copy an attacker with a memory dump can read.
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

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.long_term_signing.verifying_key()
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// The post-quantum public key, encoded (1952 bytes for ML-DSA-65).
    pub fn pq_public_key_bytes(&self) -> Vec<u8> {
        self.pq_signing.verifying_key().to_bytes().as_slice().to_vec()
    }

    /// Compute the human-readable fingerprint (first 8 bytes hex).
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.public_key_bytes()[0..8])
    }

    /// Derive an unlinkable, one-time burnable identity for a specific peer and epoch (§3 Burnable Ghost IDs).
    ///
    /// Cryptographically isolates identity across peers:
    /// `seed_burnable = HKDF-SHA256(salt: b"GHOST_BURNABLE_ID_v1", ikm: master_seed, info: peer_fp || epoch)`
    ///
    /// Observers or intermediate peers on different ASNs see completely different, uncorrelated
    /// Ed25519 public keys and fingerprints.
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

    /// Sign arbitrary data with the identity key.
    /// Returns a 64-byte Ed25519 signature.
    ///
    /// Unchanged in size and meaning: the beacon and handshake encodings that
    /// already carry this signature keep working, including against peers that
    /// have not been upgraded. Use [`Self::sign_hybrid`] where both proofs fit.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.long_term_signing.sign(data)
    }

    /// Sign with both keys, returning a proof that requires both to verify.
    ///
    /// `data` is signed verbatim by each key; the caller decides what is in it.
    /// For a binding it must include the *other* key's public material, or the
    /// proof binds the message to each key separately rather than binding the
    /// keys to each other.
    pub fn sign_hybrid(&self, data: &[u8]) -> HybridSignature {
        let pq = self.pq_signing.sign(data);
        HybridSignature {
            ed25519: self.long_term_signing.sign(data).to_bytes(),
            pq: pq.encode().as_slice().to_vec(),
        }
    }

    /// Verify a signature against this identity's public key.
    pub fn verify(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.verifying_key().verify(data, signature)
    }

    /// SHA-256 commitment to the post-quantum public key.
    ///
    /// For planes that cannot carry a 5.4 kB hybrid proof — a beacon datagram is
    /// 512–1472 bytes — the commitment is what fits: it names the PQ key without
    /// revealing it, and a verifier that has it can then check the key a peer
    /// proves possession of somewhere there *is* room (the QUIC binding today).
    /// That check is what makes the post-quantum half load-bearing rather than
    /// merely present: without a commitment to compare against, an adversary who
    /// forges the classical half may substitute a PQ key of their own.
    pub fn pq_commitment(&self) -> [u8; 32] {
        pq_commitment(&self.pq_public_key_bytes())
    }

    /// Verify a hybrid signature against this identity's own keys.
    ///
    /// A self-check for callers and tests; a peer check goes through
    /// [`verify_peer_hybrid`], which takes the peer's public material.
    pub fn verify_hybrid(&self, data: &[u8], signature: &HybridSignature) -> bool {
        verify_peer_hybrid(
            &self.public_key_bytes(),
            &self.pq_public_key_bytes(),
            data,
            signature,
        )
    }

}

/// SHA-256 commitment to an encoded ML-DSA-65 public key.
///
/// Domain-separated (`ggn-pq-commitment-v1`) so the digest cannot be confused with
/// a hash of the same bytes in another role.
pub fn pq_commitment(pq_public_key: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"ggn-pq-commitment-v1");
    h.update(pq_public_key);
    h.finalize().into()
}

/// Verify a signature from a peer's public key bytes.
pub fn verify_peer_signature(peer_pk_bytes: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
    if let Ok(peer_pk) = VerifyingKey::from_bytes(peer_pk_bytes) {
        let sig = Signature::from_bytes(signature);
        return peer_pk.verify(data, &sig).is_ok();
    }
    false
}

/// Verify an ML-DSA-65 signature from a peer's encoded public key.
///
/// A key that does not decode, a signature of the wrong length, or a signature
/// that does not verify are all `false`: the caller's decision is the same in
/// every case, and distinguishing them would only invite treating one as a
/// recoverable condition.
pub fn verify_pq_signature(pq_pk_bytes: &[u8], data: &[u8], signature: &[u8]) -> bool {
    if signature.len() != ML_DSA_65_SIG_LEN || pq_pk_bytes.len() != ML_DSA_65_PK_LEN {
        return false;
    }
    // The key has to be decoded into its fixed-size encoding before the type can
    // check it: this is where a truncated or over-long key is rejected.
    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa65>::try_from(pq_pk_bytes) else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::new(&encoded_key);
    let Ok(sig) = MlDsaSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    vk.verify(data, &sig).is_ok()
}

/// Verify a hybrid signature from a peer's public material.
///
/// **Both** halves must verify. There is no "either half" mode: a caller that
/// accepted the classical half alone would be back to an identity that a quantum
/// adversary can forge, which is the whole reason the second half exists.
pub fn verify_peer_hybrid(
    peer_pk_bytes: &[u8; 32],
    peer_pq_pk_bytes: &[u8],
    data: &[u8],
    signature: &HybridSignature,
) -> bool {
    verify_peer_signature(peer_pk_bytes, data, &signature.ed25519)
        && verify_pq_signature(peer_pq_pk_bytes, data, &signature.pq)
}

/// Version byte for the hybrid identity binding payload (SOTA G3).
pub const BINDING_VERSION_HYBRID: u8 = 0x02;

/// Length of the full hybrid identity binding wire payload (5,358 bytes).
pub const BINDING_LEN_HYBRID: usize =
    1 + 32 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

/// Construct the signed payload material for an identity binding.
pub fn identity_binding_material(channel_binding: &[u8], pq_pk: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(channel_binding.len() + pq_pk.len());
    msg.extend_from_slice(channel_binding);
    msg.extend_from_slice(pq_pk);
    msg
}

/// Construct a full 5,358-byte hybrid identity binding signing the given channel binding.
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

/// Verify a peer's hybrid identity binding against its pinned Ed25519 key,
/// optional expected PQ commitment, and channel binding.
/// Returns the peer's ML-DSA-65 public key on success.
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
        let dir = std::env::temp_dir().join(format!(
            "ggn-identity-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("identity.key").to_string_lossy().into_owned()
    }

    /// The lengths this module hard-codes must be the lengths the crate produces,
    /// or a signature from another node would be mis-parsed rather than refused.
    #[test]
    fn the_declared_lengths_are_the_crates_lengths() {
        let id = GhostIdentity::generate_fresh();
        assert_eq!(id.pq_public_key_bytes().len(), ML_DSA_65_PK_LEN);
        assert_eq!(id.sign_hybrid(b"m").pq.len(), ML_DSA_65_SIG_LEN);
        assert_eq!(id.sign_hybrid(b"m").encode().len(), HYBRID_SIG_LEN);
    }

    /// The commitment names the PQ key: same key, same commitment; different key,
    /// different commitment; and it is not the bare hash of the key.
    #[test]
    fn the_commitment_is_a_hash_of_the_pq_key_and_nothing_else() {
        use sha2::Digest;
        let id = GhostIdentity::generate_fresh();
        assert_eq!(id.pq_commitment(), pq_commitment(&id.pq_public_key_bytes()));
        let other = GhostIdentity::generate_fresh();
        assert_ne!(id.pq_commitment(), other.pq_commitment());
        let bare = sha2::Sha256::digest(&id.pq_public_key_bytes());
        assert_ne!(id.pq_commitment().to_vec(), bare.to_vec());
    }

    #[test]
    fn a_hybrid_signature_verifies_only_with_both_halves() {
        let id = GhostIdentity::generate_fresh();
        let other = GhostIdentity::generate_fresh();
        let msg = b"handshake-material";
        let sig = id.sign_hybrid(msg);

        assert!(id.verify_hybrid(msg, &sig));
        // The peer's own material is what a verifier has, so check that path too.
        assert!(verify_peer_hybrid(
            &id.public_key_bytes(),
            &id.pq_public_key_bytes(),
            msg,
            &sig
        ));
        // A different message is refused.
        assert!(!id.verify_hybrid(b"other-material", &sig));
        // Someone else's Ed25519 key is refused...
        assert!(!verify_peer_hybrid(
            &other.public_key_bytes(),
            &id.pq_public_key_bytes(),
            msg,
            &sig
        ));
        // ...and so is someone else's PQ key, even with the right classical half.
        // This is the property a classical-only check cannot give: a peer that
        // forges Ed25519 still cannot produce the PQ half.
        assert!(!verify_peer_hybrid(
            &id.public_key_bytes(),
            &other.pq_public_key_bytes(),
            msg,
            &sig
        ));
    }

    /// A tampered half must fail, whichever half is tampered with.
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

    /// A truncated or oversized PQ signature is refused rather than guessed at.
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
        // Right length, wrong bytes: a zero signature is not a valid one.
        assert!(!verify_pq_signature(
            &id.pq_public_key_bytes(),
            msg,
            &vec![0u8; ML_DSA_65_SIG_LEN]
        ));
        // Right signature, wrong key.
        let other = GhostIdentity::generate_fresh();
        let sig = id.sign_hybrid(msg);
        assert!(!verify_pq_signature(&other.pq_public_key_bytes(), msg, &sig.pq));
    }

    /// The PQ key must not be derived from the classical secret: if it were, the
    /// attacker who breaks Ed25519 (the event this half exists for) would get it
    /// for free.
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
        // Same classical key — so the same fingerprint, and the same pairing —
        // but the PQ halves must differ, because they came from their own entropy.
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_ne!(a.pq_public_key_bytes(), b.pq_public_key_bytes());
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    /// A v1 file is upgraded in place, and the upgrade is durable.
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

        // Reloading gives the same PQ identity; a PQ key that changed per boot
        // would be one no peer could ever learn.
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

    /// A file that is neither version is refused, and the node gets a fresh
    /// identity rather than a panic or a half-read key.
    #[test]
    fn an_unreadable_identity_file_yields_a_fresh_identity() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, b"not an identity").expect("write");
        let id = GhostIdentity::load_or_generate(&path);
        assert_eq!(id.fingerprint().len(), 16);
        // And the fresh identity was written back in the hybrid format.
        assert_eq!(std::fs::read(&path).expect("read").len(), IDENTITY_V2_LEN);
        let _ = std::fs::remove_file(&path);

        // Wrong magic, right length: also refused.
        let mut bad = Vec::new();
        bad.extend_from_slice(b"NOTGGNID");
        bad.push(IDENTITY_VERSION_HYBRID);
        bad.extend_from_slice(&[1u8; 32]);
        bad.extend_from_slice(&[2u8; 32]);
        assert!(GhostIdentity::parse_identity_file(&bad).is_err());
        // Right magic, unknown version: refused rather than read as v2.
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

        // Valid verification
        let pq_pk = verify_hybrid_binding(
            &alice.public_key_bytes(),
            Some(&alice.pq_commitment()),
            channel,
            &binding,
        )
        .expect("valid binding must verify");
        assert_eq!(pq_pk, alice.pq_public_key_bytes());

        // Mismatched channel binding fails
        assert!(verify_hybrid_binding(
            &alice.public_key_bytes(),
            Some(&alice.pq_commitment()),
            b"different-channel",
            &binding,
        )
        .is_err());

        // Mismatched Ed25519 key fails
        assert!(verify_hybrid_binding(
            &bob.public_key_bytes(),
            Some(&alice.pq_commitment()),
            channel,
            &binding,
        )
        .is_err());

        // Mismatched PQ commitment fails
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

            // Never leaks or equals the master fingerprint
            assert_ne!(burnable_fp, master_fp);
            assert_eq!(burnable_fp.len(), 16); // 8 bytes hex = 16 hex chars
            fps.insert(burnable_fp);
        }

        // All 1000 peers must receive mathematically unique, uncorrelated identities
        assert_eq!(fps.len(), 1000);
    }

    #[test]
    fn test_burnable_identity_deterministic_recovery_and_epoch_rotation() {
        let identity = GhostIdentity::generate_fresh();
        let peer_fp = "a1b2c3d4e5f60718";

        // 1. Same peer and same epoch reconstructs the exact same key and fingerprint
        let (k1, fp1) = identity.derive_burnable(peer_fp, 0);
        let (k2, fp2) = identity.derive_burnable(peer_fp, 0);
        assert_eq!(fp1, fp2);
        assert_eq!(k1.to_bytes(), k2.to_bytes());

        // 2. Epoch rotation (epoch 0 -> epoch 1) yields a completely different identity
        let (k_next, fp_next) = identity.derive_burnable(peer_fp, 1);
        assert_ne!(fp1, fp_next);
        assert_ne!(k1.to_bytes(), k_next.to_bytes());

        // 3. Signature verification with burnable identity
        let message = b"hello from burnable ghost identity";
        let signature = k1.sign(message);
        assert!(k1.verifying_key().verify_strict(message, &signature).is_ok());
    }

    #[test]
    fn test_amnesia_mode_zero_disk_state() {
        let temp_dir = std::env::temp_dir().join(format!("ggn_amnesia_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let key_path = temp_dir.join("ephemeral_identity.key");
        let key_path_str = key_path.to_str().unwrap();

        // 1. Enable amnesia mode explicitly via options
        let id = GhostIdentity::load_or_generate_opts(key_path_str, true);
        
        // Key file must NOT exist on disk
        assert!(!key_path.exists(), "Amnesia mode must never write identity.key to disk");
        assert_eq!(id.fingerprint().len(), 16);

        // 2. Normal mode
        let normal_id = GhostIdentity::load_or_generate_opts(key_path_str, false);
        
        // In normal mode, key file is written
        assert!(key_path.exists(), "Normal mode writes identity.key to disk");
        assert_eq!(normal_id.fingerprint().len(), 16);

        // Clean up
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }
}
