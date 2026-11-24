//! `BTCr` / Blind-Pass — relay work that a phone can spend anonymously.
//!
//! A mains-powered home PC relays encrypted traffic overnight and earns bearer
//! **TransitTickets**; the tickets sync over the private mesh to a CGNAT phone
//! and are spent at public relays. The relay that earns a ticket must not learn
//! which ticket the phone later spends, or the credit economy becomes a
//! behaviour ledger.
//!
//! The construction is a Ristretto255 VOPRF with a batched Chaum–Pedersen DLEQ
//! proof, keyed by **quantized buckets** and rooted in the node's private
//! identity secret:
//!
//! ```text
//! identity.key --HKDF("VB-BTCR-V2")--> k_root   (never leaves the node)
//! k_{day,tier} = H_scalar("VB-BTCR-BUCKET-V2" ‖ k_root ‖ day ‖ tier)
//! K_{day,tier} = k_{day,tier} · G               (published per bucket)
//!
//! client:   M = H2G(input),  B = r·M             (r random, never leaves)
//! issuer:   E = k_{day,tier}·B, DLEQ{ log_G K == log_B E }
//! client:   N = r⁻¹·E = k_{day,tier}·M           (verifies the DLEQ first)
//! relay:    accept iff N == k_{day,tier}·M, unexpired, never spent
//! ```
//!
//! **Why a bucket.** A per-ticket key would make `K` a fingerprint of the ticket
//! itself. Tickets are therefore issued against a UTC-day bucket and a fixed
//! work tier (1 MiB, 16 MiB, 256 MiB), so every ticket minted in the same bucket
//! verifies under the *same* published key and the anonymity set is not one.
//!
//! **Why the root is private.** v1 derived `k` from the node fingerprint. The
//! fingerprint is public, so anyone could recompute the scalar and mint tickets
//! offline. The root now comes from the private `identity.key` seed through a
//! domain-separated HKDF, and no public input reaches it.
//!
//! The DLEQ matters: without it an issuer can return `E = k'·B` for a key it
//! does not publish, and the client cannot tell a valid ticket from a worthless
//! one until it is already at a relay. [`Ticket`] therefore carries both `M` and
//! `N`, and [`Issuer::verify_ticket`] is the check every relay performs.
//!
//! Issuance is gated by a signed **work receipt** (`btcr-receipt:v1`): the
//! issuer refuses to mint anything without a receipt from an allowlisted
//! beneficiary key, so a ticket cannot be created out of nothing. Each receipt
//! is redeemable once — its nullifier is `SHA256("VB-BTCR-RCPT" ‖ worker ‖
//! epoch ‖ beneficiary)` — and ticket double spends are refused separately by a
//! per-ticket nullifier. The wallet is a plain JSON file the operator can copy
//! between devices.
//!
//! Not built: a network-wide relay registry and ticket gossip. Tickets are
//! issued, verified and spent locally; distributing them is the mesh's job.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Domain separator for hashing an arbitrary input to a Ristretto point.
const H2G_DOMAIN: &[u8] = b"VB-BTCR-H2G-V1";
/// Domain separator for the private root key derived from `identity.key`.
const ROOT_SEED_DOMAIN: &[u8] = b"VB-BTCR-V2";
/// Domain separator for a quantized `(day, tier)` bucket scalar.
const BUCKET_DOMAIN: &[u8] = b"VB-BTCR-BUCKET-V2";
/// Domain separator for the nullifier (one spend per ticket, not per input).
const NULLIFIER_DOMAIN: &[u8] = b"VB-BTCR-NULLIFIER-V1";
/// Domain separator for the receipt nullifier (one mint per work receipt).
const RECEIPT_NULLIFIER_DOMAIN: &[u8] = b"VB-BTCR-RCPT";
/// Version byte in the 81-byte ticket encoding.
pub const TICKET_VERSION: u8 = 2;
/// Default ticket lifetime: the rest of the current UTC-day bucket.
pub const DEFAULT_TICKET_TTL_SECS: u64 = 24 * 3600;
/// A ticket is 81 bytes: version, M, N, expiry, work credit.
pub const TICKET_ENCODED_LEN: usize = 81;
/// Fixed work tiers. `work_bytes` is always exactly one of these, so the ticket
/// length and value distribution do not identify the issuer or the receipt.
pub const TIER_BYTES: [u64; 3] = [1 << 20, 16 << 20, 256 << 20];

/// The quantized metadata a ticket shares with every other ticket minted in the
/// same bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bucket {
    /// UTC-day index, `unix_secs / 86400 + 1` at issuance.
    pub day: u32,
    /// Index into [`TIER_BYTES`].
    pub tier: u8,
}

/// The UTC-day bucket a ticket issued at `now` belongs to.
///
/// `+1` puts the ticket in *tomorrow's* bucket, so an issuance at 23:59 UTC is
/// still valid for a full day instead of expiring seconds later.
pub fn bucket_day(now: u64) -> u32 {
    (now / 86_400 + 1).min(u32::MAX as u64) as u32
}

/// The last second a ticket in `day` is valid.
pub fn expiry_for_day(day: u32) -> u64 {
    (day as u64 + 1) * 86_400
}

/// Recover the bucket day from the quantized expiry stored in a ticket.
fn day_of_expiry(expires_at: u64) -> u32 {
    (expires_at / 86_400).saturating_sub(1).min(u32::MAX as u64) as u32
}

/// The largest tier at or below `work_bytes`.
///
/// Floor, never ceiling: a receipt for 3 MiB earns the 1 MiB tier, so
/// quantization can only under-issue relative to the work proved.
pub fn tier_for(work_bytes: u64) -> u8 {
    let mut tier = 0u8;
    for (index, bytes) in TIER_BYTES.iter().enumerate() {
        if work_bytes >= *bytes {
            tier = index as u8;
        }
    }
    tier
}

/// Credit carried by a tier index, clamped to the last tier.
pub fn tier_bytes(tier: u8) -> u64 {
    TIER_BYTES[(tier as usize).min(TIER_BYTES.len() - 1)]
}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Hash an arbitrary byte string to a Ristretto point.
pub fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(H2G_DOMAIN);
    h.update((input.len() as u32).to_be_bytes());
    h.update(input);
    RistrettoPoint::hash_from_bytes::<Sha512>(&h.finalize())
}

/// Decode a 32-byte hex Ristretto point.
pub fn decode_point(hex_str: &str) -> Result<RistrettoPoint, String> {
    point_from_hex(hex_str)
}

fn point_from_hex(hex_str: &str) -> Result<RistrettoPoint, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid point hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("point must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| "point is not a canonical Ristretto encoding".to_string())
}

// ── DLEQ ────────────────────────────────────────────────────────────────────

/// Chaum–Pedersen proof that the issuer used one key for `G -> K` and `B -> E`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dleq {
    pub c: String,
    pub s: String,
}

fn dleq_challenge(
    k: &RistrettoPoint,
    b: &RistrettoPoint,
    e: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"VB-BTCR-DLEQ-V1");
    for p in [&RISTRETTO_BASEPOINT_POINT, k, b, e, a1, a2] {
        h.update(p.compress().as_bytes());
    }
    Scalar::from_hash(h)
}

impl Dleq {
    fn prove(
        secret: &Scalar,
        public: &RistrettoPoint,
        blinded: &RistrettoPoint,
        eval: &RistrettoPoint,
    ) -> Self {
        let t = random_scalar();
        let a1 = t * RISTRETTO_BASEPOINT_POINT;
        let a2 = t * blinded;
        let c = dleq_challenge(public, blinded, eval, &a1, &a2);
        let s = t + c * secret;
        Self {
            c: hex::encode(c.to_bytes()),
            s: hex::encode(s.to_bytes()),
        }
    }

    /// Verify `log_G K == log_B E` without learning the secret.
    pub fn verify(
        &self,
        public: &RistrettoPoint,
        blinded: &RistrettoPoint,
        eval: &RistrettoPoint,
    ) -> bool {
        let (Ok(c_bytes), Ok(s_bytes)) = (hex::decode(&self.c), hex::decode(&self.s)) else {
            return false;
        };
        if c_bytes.len() != 32 || s_bytes.len() != 32 {
            return false;
        }
        let mut c_arr = [0u8; 32];
        let mut s_arr = [0u8; 32];
        c_arr.copy_from_slice(&c_bytes);
        s_arr.copy_from_slice(&s_bytes);
        let c = Scalar::from_canonical_bytes(c_arr);
        let s = Scalar::from_canonical_bytes(s_arr);
        let (Some(c), Some(s)) = (Option::<Scalar>::from(c), Option::<Scalar>::from(s)) else {
            return false;
        };
        // Rebuild A1/A2 from the response: A = s·X − c·Y.
        let a1 = s * RISTRETTO_BASEPOINT_POINT - c * public;
        let a2 = s * blinded - c * eval;
        dleq_challenge(public, blinded, eval, &a1, &a2) == c
    }
}

// ── Issuer ──────────────────────────────────────────────────────────────────

/// The blind-signing authority. The root scalar never leaves this struct, and
/// the bucket scalars it derives are never stored or published.
pub struct Issuer {
    root: Scalar,
}

impl Issuer {
    /// Derive the private root from the node's `identity.key` secret.
    ///
    /// The identity seed is the only input. The 32-byte Ed25519 secret is
    /// expanded through HKDF-SHA256 under [`ROOT_SEED_DOMAIN`], so the ticket
    /// root is independent of the handshake key (a ticket compromise cannot
    /// forge sessions, and a session compromise cannot mint tickets) while
    /// still surviving a restart without a second key file.
    pub fn from_identity_seed(seed: &[u8; 32]) -> Self {
        let hk = hkdf::Hkdf::<Sha256>::new(None, seed);
        let mut okm = [0u8; 64];
        hk.expand(ROOT_SEED_DOMAIN, &mut okm)
            .expect("64 bytes is a valid HKDF output length");
        let root = Scalar::from_bytes_mod_order_wide(&okm);
        okm.fill(0);
        Self { root }
    }

    /// Alias kept for callers that traffic in "a seed" rather than "the identity
    /// seed". Both mean the same thing: private key material, never a public name.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_identity_seed(seed)
    }

    /// The bucket scalar `k_{day,tier}`. Never leaves this type in the clear.
    pub fn secret_for(&self, day: u32, tier: u8) -> Scalar {
        let mut h = Sha512::new();
        h.update(BUCKET_DOMAIN);
        h.update(self.root.to_bytes());
        h.update(day.to_be_bytes());
        h.update([tier]);
        Scalar::from_hash(h)
    }

    /// The published bucket key `K_{day,tier} = k_{day,tier}·G`.
    pub fn public_for(&self, day: u32, tier: u8) -> RistrettoPoint {
        self.secret_for(day, tier) * RISTRETTO_BASEPOINT_POINT
    }

    pub fn public_hex_for(&self, day: u32, tier: u8) -> String {
        hex::encode(self.public_for(day, tier).compress().as_bytes())
    }

    /// Blind-evaluate one request inside `(day, tier)` and attach a DLEQ proof
    /// tying the evaluation to that bucket's published key.
    pub fn evaluate(
        &self,
        blinded_hex: &str,
        day: u32,
        tier: u8,
    ) -> Result<(String, Dleq), String> {
        let blinded = point_from_hex(blinded_hex)?;
        let secret = self.secret_for(day, tier);
        let public = secret * RISTRETTO_BASEPOINT_POINT;
        let eval = secret * blinded;
        let proof = Dleq::prove(&secret, &public, &blinded, &eval);
        Ok((hex::encode(eval.compress().as_bytes()), proof))
    }

    /// The check a relay performs: `N == k_{day,tier}·M` for the ticket's own
    /// claimed bucket. A ticket minted in another bucket fails here, which is
    /// what stops a relay from re-labelling its metadata.
    pub fn verify_ticket(&self, ticket: &Ticket) -> bool {
        let (Ok(m), Ok(n)) = (point_from_hex(&ticket.m), point_from_hex(&ticket.n)) else {
            return false;
        };
        let bucket = ticket.bucket();
        self.secret_for(bucket.day, bucket.tier) * m == n
    }
}

// ── Client-side blinding ────────────────────────────────────────────────────

/// A blinded request plus the blinding factor the client must keep.
#[derive(Clone)]
pub struct BlindRequest {
    pub input: String,
    pub blinded: String,
    r: Scalar,
}

impl std::fmt::Debug for BlindRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlindRequest")
            .field("input", &self.input)
            .field("blinded", &self.blinded)
            .field("r", &"<hidden>")
            .finish()
    }
}

/// Blind `input` with fresh randomness. The issuer learns nothing about `input`.
pub fn blind(input: &[u8]) -> BlindRequest {
    let m = hash_to_group(input);
    let r = random_scalar();
    let blinded = r * m;
    BlindRequest {
        input: hex::encode(input),
        blinded: hex::encode(blinded.compress().as_bytes()),
        r,
    }
}

/// Verify the issuer's DLEQ and unblind the evaluation into a spendable ticket.
pub fn finalize(
    request: &BlindRequest,
    eval_hex: &str,
    proof: &Dleq,
    issuer_public_hex: &str,
    day: u32,
    tier: u8,
) -> Result<Ticket, String> {
    let public = point_from_hex(issuer_public_hex)?;
    let eval = point_from_hex(eval_hex)?;
    let blinded = point_from_hex(&request.blinded)?;
    if !proof.verify(&public, &blinded, &eval) {
        return Err("issuer DLEQ proof is invalid; the ticket would not verify at a relay".into());
    }
    let input = hex::decode(&request.input).map_err(|e| format!("bad input hex: {e}"))?;
    let m = hash_to_group(&input);
    // The DLEQ proved E = k·B for the published K, so unblinding with r⁻¹
    // yields N = k·M. Checking N against K without k is impossible, which is
    // exactly why the proof is mandatory before this point.
    let n = request.r.invert() * eval;
    Ok(Ticket {
        m: hex::encode(m.compress().as_bytes()),
        n: hex::encode(n.compress().as_bytes()),
        expires_at: expiry_for_day(day),
        work_bytes: tier_bytes(tier),
    })
}

/// A bearer transit ticket. Possession is the credit; it carries no identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// Blinded input point `M`. Public.
    pub m: String,
    /// Unblinded evaluation `N = k·M`. This is the bearer secret.
    pub n: String,
    pub expires_at: u64,
    /// Relay bytes this ticket was issued against.
    pub work_bytes: u64,
}

impl Ticket {
    pub fn encode(&self) -> Result<String, String> {
        let m = hex::decode(&self.m).map_err(|e| format!("bad M: {e}"))?;
        let n = hex::decode(&self.n).map_err(|e| format!("bad N: {e}"))?;
        if m.len() != 32 || n.len() != 32 {
            return Err("M and N must be 32 bytes each".into());
        }
        let mut out = Vec::with_capacity(TICKET_ENCODED_LEN);
        out.push(TICKET_VERSION);
        out.extend_from_slice(&m);
        out.extend_from_slice(&n);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.work_bytes.to_be_bytes());
        Ok(hex::encode(out))
    }

    pub fn decode(encoded: &str) -> Result<Self, String> {
        let bytes = hex::decode(encoded.trim()).map_err(|e| format!("invalid ticket hex: {e}"))?;
        if bytes.len() != TICKET_ENCODED_LEN {
            return Err(format!(
                "ticket must be {TICKET_ENCODED_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        if bytes[0] != TICKET_VERSION {
            return Err(format!("unsupported ticket version {}", bytes[0]));
        }
        let mut expiry = [0u8; 8];
        let mut work = [0u8; 8];
        expiry.copy_from_slice(&bytes[65..73]);
        work.copy_from_slice(&bytes[73..81]);
        Ok(Self {
            m: hex::encode(&bytes[1..33]),
            n: hex::encode(&bytes[33..65]),
            expires_at: u64::from_be_bytes(expiry),
            work_bytes: u64::from_be_bytes(work),
        })
    }

    /// The quantized bucket this ticket was issued in.
    pub fn bucket(&self) -> Bucket {
        Bucket {
            day: day_of_expiry(self.expires_at),
            tier: tier_for(self.work_bytes),
        }
    }

    /// One spendable unit, independent of which relay sees it first.
    pub fn nullifier(&self) -> String {
        let mut h = Sha256::new();
        h.update(NULLIFIER_DOMAIN);
        h.update(hex::decode(&self.n).unwrap_or_default());
        hex::encode(h.finalize())
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }
}

// ── Work receipts ───────────────────────────────────────────────────────────

/// A relay's signed claim of bytes forwarded during one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub worker: String,
    pub work_bytes: u64,
    pub epoch: u64,
    /// Ed25519 signature over [`receipt_message`], hex.
    pub signature: String,
    /// Beneficiary public key that must sign the receipt, hex.
    pub beneficiary: String,
}

impl Receipt {
    /// Deterministic one-mint-per-receipt identifier.
    ///
    /// It is stable for the same `(worker, epoch, beneficiary)` triple, so a
    /// replayed receipt is recognised even when the issuer has restarted (the
    /// spent-receipt set is rebuildable from the wallet ledger) and even if the
    /// receipt is wrapped in a fresh blinding request.
    pub fn nullifier(&self) -> String {
        let mut h = Sha256::new();
        h.update(RECEIPT_NULLIFIER_DOMAIN);
        h.update(self.worker.as_bytes());
        h.update(self.epoch.to_be_bytes());
        h.update(self.beneficiary.as_bytes());
        hex::encode(h.finalize())
    }
}

pub fn receipt_message(worker: &str, work_bytes: u64, epoch: u64) -> Vec<u8> {
    format!("btcr-receipt:v1|{worker}|{work_bytes}|{epoch}").into_bytes()
}

pub fn sign_receipt(
    key: &SigningKey,
    worker: &str,
    work_bytes: u64,
    epoch: u64,
) -> Result<Receipt, String> {
    if work_bytes == 0 {
        return Err("a receipt for zero relayed bytes earns nothing".into());
    }
    let sig = key.sign(&receipt_message(worker, work_bytes, epoch));
    Ok(Receipt {
        worker: worker.to_string(),
        work_bytes,
        epoch,
        signature: hex::encode(sig.to_bytes()),
        beneficiary: hex::encode(key.verifying_key().to_bytes()),
    })
}

pub fn verify_receipt(receipt: &Receipt, allowed: &VerifyingKey) -> Result<(), String> {
    let pk_bytes =
        hex::decode(&receipt.beneficiary).map_err(|e| format!("bad beneficiary key: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err("beneficiary key must be 32 bytes".into());
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let stated = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("beneficiary key is not a valid Ed25519 key: {e}"))?;
    if stated != *allowed {
        return Err("receipt was signed by a key that is not this node's beneficiary".into());
    }
    let sig_bytes =
        hex::decode(&receipt.signature).map_err(|e| format!("bad signature hex: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err("receipt signature must be 64 bytes".into());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    allowed
        .verify_strict(
            &receipt_message(&receipt.worker, receipt.work_bytes, receipt.epoch),
            &Signature::from_bytes(&sig_arr),
        )
        .map_err(|_| "receipt signature does not verify".to_string())
}

/// Issue a ticket only after checking a beneficiary-signed work receipt.
pub fn issue_for_work(
    issuer: &Issuer,
    receipt: &Receipt,
    beneficiary: &VerifyingKey,
    request: &BlindRequest,
    now: u64,
) -> Result<(Ticket, Dleq), String> {
    verify_receipt(receipt, beneficiary)?;
    let bucket = Bucket {
        day: bucket_day(now),
        tier: tier_for(receipt.work_bytes),
    };
    // Evaluate before claiming the receipt, so a malformed blinding request
    // does not burn a unit of work.
    let (eval, proof) = issuer.evaluate(&request.blinded, bucket.day, bucket.tier)?;
    redeem_receipt(receipt)?;
    let ticket = finalize(
        request,
        &eval,
        &proof,
        &issuer.public_hex_for(bucket.day, bucket.tier),
        bucket.day,
        bucket.tier,
    )?;
    Ok((ticket, proof))
}

/// Claim a receipt for minting. A second mint from the same receipt is refused.
///
/// The check is deliberately separate from [`verify_receipt`]: a signature says
/// the receipt is authentic, not that it is unspent. Callers that mint directly
/// (the HTTP surface) must go through this too.
pub fn redeem_receipt(receipt: &Receipt) -> Result<(), String> {
    let mut guard = ledger().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.receipts.insert(receipt.nullifier()) {
        guard.rejected_duplicate_receipts = guard.rejected_duplicate_receipts.saturating_add(1);
        return Err(format!(
            "work receipt already redeemed (worker={} epoch={})",
            receipt.worker, receipt.epoch
        ));
    }
    Ok(())
}

// ── Ledger: double-spend refusal ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct LedgerSnapshot {
    pub issued: u64,
    pub spent: u64,
    pub rejected_receipts: u64,
    pub rejected_duplicate_receipts: u64,
    pub rejected_replays: u64,
    pub spent_nullifiers: usize,
    pub spent_receipts: usize,
    pub gossip_merged: u64,
}

#[derive(Default)]
struct Ledger {
    issued: u64,
    spent: u64,
    rejected_receipts: u64,
    rejected_duplicate_receipts: u64,
    rejected_replays: u64,
    nullifiers: HashSet<String>,
    receipts: HashSet<String>,
    gossip_merged: u64,
}

fn ledger() -> &'static Mutex<Ledger> {
    static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(Ledger::default()))
}

pub fn record_issue() {
    let mut guard = ledger().lock().unwrap_or_else(|e| e.into_inner());
    guard.issued = guard.issued.saturating_add(1);
}

pub fn record_rejected_receipt() {
    let mut guard = ledger().lock().unwrap_or_else(|e| e.into_inner());
    guard.rejected_receipts = guard.rejected_receipts.saturating_add(1);
}

/// Spend a ticket. A second spend of the same ticket is refused.
pub fn spend(issuer: &Issuer, ticket: &Ticket, now: u64) -> Result<(), String> {
    if ticket.is_expired(now) {
        return Err(format!("ticket expired at {}", ticket.expires_at));
    }
    if !issuer.verify_ticket(ticket) {
        return Err("ticket does not verify against this issuer".into());
    }
    let mut guard = ledger().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.nullifiers.insert(ticket.nullifier()) {
        guard.rejected_replays = guard.rejected_replays.saturating_add(1);
        return Err("ticket already spent (nullifier replay refused)".into());
    }
    guard.spent = guard.spent.saturating_add(1);
    Ok(())
}

pub fn snapshot() -> LedgerSnapshot {
    let guard = ledger().lock().unwrap_or_else(|e| e.into_inner());
    LedgerSnapshot {
        issued: guard.issued,
        spent: guard.spent,
        rejected_receipts: guard.rejected_receipts,
        rejected_duplicate_receipts: guard.rejected_duplicate_receipts,
        rejected_replays: guard.rejected_replays,
        spent_nullifiers: guard.nullifiers.len(),
        spent_receipts: guard.receipts.len(),
        gossip_merged: guard.gossip_merged,
    }
}

// ── Wallet ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Wallet {
    pub tickets: Vec<Ticket>,
}

pub fn wallet_path() -> PathBuf {
    let base = std::env::var("GHOST_DATA_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&base).join("v2").join("btcr_wallet.json")
}

impl Wallet {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))
    }

    /// Merge tickets by `M` (the unique blinded input), newest credit wins.
    pub fn merge(&mut self, other: &Wallet) -> usize {
        let mut added: usize = 0;
        for ticket in &other.tickets {
            if let Some(existing) = self.tickets.iter_mut().find(|t| t.m == ticket.m) {
                if ticket.work_bytes > existing.work_bytes {
                    *existing = ticket.clone();
                }
                continue;
            }
            self.tickets.push(ticket.clone());
            added = added.saturating_add(1);
        }
        added
    }

    pub fn total_credit(&self) -> u64 {
        self.tickets.iter().map(|t| t.work_bytes).sum()
    }

    pub fn prune_expired(&mut self, now: u64) -> usize {
        let before = self.tickets.len();
        self.tickets.retain(|t| !t.is_expired(now));
        before - self.tickets.len()
    }
}

/// Encode up to `max` unexpired tickets from `wallet` into a compact length-prefixed
/// mesh gossip batch: `[count u8]([len u16 BE][encoded ticket UTF-8]...)`.
pub fn encode_gossip_batch(wallet: &Wallet, max: usize, now: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0u8);
    let mut count: u8 = 0;
    for ticket in &wallet.tickets {
        if ticket.is_expired(now) || count as usize >= max || count == u8::MAX {
            continue;
        }
        let Ok(enc) = ticket.encode() else {
            continue;
        };
        let bytes = enc.as_bytes();
        let Ok(len_u16) = u16::try_from(bytes.len()) else {
            continue;
        };
        if out.len() + 2 + bytes.len() > 2048 && count > 0 {
            break;
        }
        out.extend_from_slice(&len_u16.to_be_bytes());
        out.extend_from_slice(bytes);
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Vec::new();
    }
    out[0] = count;
    out
}

/// Decode a gossip batch produced by [`encode_gossip_batch`], dropping expired or malformed entries.
pub fn decode_gossip_batch(bytes: &[u8], now: u64) -> Wallet {
    let mut wallet = Wallet::default();
    if bytes.is_empty() {
        return wallet;
    }
    let count = bytes[0] as usize;
    let mut pos = 1usize;
    for _ in 0..count {
        if pos + 2 > bytes.len() {
            break;
        }
        let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if pos + len > bytes.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&bytes[pos..pos + len]) {
            if let Ok(ticket) = Ticket::decode(s) {
                if !ticket.is_expired(now) {
                    wallet.tickets.push(ticket);
                }
            }
        }
        pos += len;
    }
    wallet
}

/// Export up to `max` unexpired tickets from the node's wallet for `GHOST_BTCR____` PEX gossip.
pub fn export_gossip_batch(max: usize) -> Vec<u8> {
    let wallet = Wallet::load(&wallet_path());
    encode_gossip_batch(&wallet, max, super::now_secs())
}

/// Merge an incoming `GHOST_BTCR____` gossip batch into the node's wallet on disk.
pub fn ingest_gossip_batch(bytes: &[u8]) -> usize {
    let now = super::now_secs();
    let incoming = decode_gossip_batch(bytes, now);
    if incoming.tickets.is_empty() {
        return 0;
    }
    let path = wallet_path();
    let mut wallet = Wallet::load(&path);
    wallet.prune_expired(now);
    let added = wallet.merge(&incoming);
    if added > 0 {
        let _ = wallet.save(&path);
        ledger()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .gossip_merged += added as u64;
    }
    added
}

// ── Reporting ───────────────────────────────────────────────────────────────

/// Status for `/api/v2/btcr`, parameterised by the **private** issuer.
///
/// The published key is per bucket, so the report names the bucket in force
/// rather than a stable node-wide key.
pub fn status_json(issuer: &Issuer, now: u64) -> serde_json::Value {
    let wallet = Wallet::load(&wallet_path());
    let snap = snapshot();
    let bucket = Bucket {
        day: bucket_day(now),
        tier: tier_for(TIER_BYTES[0]),
    };
    serde_json::json!({
        "issuer": issuer.public_hex_for(bucket.day, bucket.tier),
        "bucket": { "day": bucket.day, "tier": bucket.tier },
        "tiers_bytes": TIER_BYTES,
        "algorithm": "ristretto255-voprf+dleq+bucket-keys",
        "ticket_bytes": TICKET_ENCODED_LEN,
        "wallet": wallet_path().display().to_string(),
        "wallet_tickets": wallet.tickets.len(),
        "wallet_credit_bytes": wallet.total_credit(),
        "issued": snap.issued,
        "spent": snap.spent,
        "rejected_receipts": snap.rejected_receipts,
        "rejected_duplicate_receipts": snap.rejected_duplicate_receipts,
        "rejected_replays": snap.rejected_replays,
        "spent_receipts": snap.spent_receipts,
        "gossip_merged": snap.gossip_merged,
        "issuance_requires": "beneficiary-signed btcr-receipt:v1 with work_bytes > 0, redeemed once",
        "root": "HKDF-SHA256(identity.key, \"VB-BTCR-V2\") — the fingerprint is never an input",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beneficiary() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn issuer_from_seed(seed: u8) -> Issuer {
        Issuer::from_identity_seed(&[seed; 32])
    }

    /// A receipt with a process-unique epoch: the redeemed-receipt set is
    /// process-global, so a shared `(worker, epoch)` would collide across tests.
    fn unique_receipt(key: &SigningKey, worker: &str, work: u64) -> Receipt {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let epoch = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        sign_receipt(key, worker, work, epoch).unwrap()
    }

    #[test]
    fn blind_issue_unblind_and_spend() {
        let issuer = issuer_from_seed(1);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "home-pc", 4_000_000);
        let request = blind(b"phone-session-1");
        assert_ne!(
            request.blinded, request.input,
            "the issuer must not see the input"
        );

        let now = 86_400 * 1_000;
        let (ticket, proof) =
            issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, now).unwrap();
        assert!(issuer.verify_ticket(&ticket));

        // The ticket carries quantized metadata, not the receipt's raw numbers.
        let bucket = ticket.bucket();
        assert_eq!(bucket.day, bucket_day(now));
        assert_eq!(bucket.tier, 0, "4 MB floors to the 1 MiB tier");
        assert_eq!(ticket.work_bytes, TIER_BYTES[0]);
        assert_eq!(ticket.expires_at, expiry_for_day(bucket.day));

        // The DLEQ is over the bucket key, and verifies independently.
        let public = issuer.public_for(bucket.day, bucket.tier);
        let (eval, proof2) = issuer
            .evaluate(&request.blinded, bucket.day, bucket.tier)
            .unwrap();
        let blinded = point_from_hex(&request.blinded).unwrap();
        let eval = point_from_hex(&eval).unwrap();
        assert!(proof2.verify(&public, &blinded, &eval));
        assert!(proof.verify(&public, &blinded, &eval));

        spend(&issuer, &ticket, now).unwrap();
    }

    #[test]
    fn a_replayed_ticket_is_refused() {
        let issuer = issuer_from_seed(2);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "relay", 1_000_000);
        let request = blind(b"one-shot");
        let (ticket, _) =
            issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 100).unwrap();
        assert!(spend(&issuer, &ticket, 200).is_ok());
        let err = spend(&issuer, &ticket, 200).unwrap_err();
        assert!(err.contains("nullifier"), "{err}");
    }

    #[test]
    fn issuance_without_a_valid_receipt_is_refused() {
        let issuer = issuer_from_seed(3);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "relay", 10_000);
        let mut tampered = receipt.clone();
        tampered.work_bytes = 999_999_999; // changed after signing
        let request = blind(b"unearned");
        let err =
            issue_for_work(&issuer, &tampered, &key.verifying_key(), &request, 100).unwrap_err();
        assert!(err.contains("signature"), "{err}");

        let zero = Receipt {
            work_bytes: 0,
            ..unique_receipt(&key, "relay", 1)
        };
        assert!(verify_receipt(&zero, &key.verifying_key()).is_err());
    }

    #[test]
    fn a_work_receipt_can_only_be_redeemed_once() {
        let issuer = issuer_from_seed(4);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "overnight-relay", 2 << 20);
        let first = issue_for_work(
            &issuer,
            &receipt,
            &key.verifying_key(),
            &blind(b"first-mint"),
            100,
        );
        assert!(first.is_ok());
        let replay = issue_for_work(
            &issuer,
            &receipt,
            &key.verifying_key(),
            &blind(b"second-mint"),
            100,
        );
        let err = replay.unwrap_err();
        assert!(err.contains("already redeemed"), "{err}");
        assert_eq!(receipt.nullifier(), receipt.nullifier(), "deterministic");
        let mut other = receipt.clone();
        other.epoch += 1;
        assert_ne!(
            other.nullifier(),
            receipt.nullifier(),
            "a different epoch is a different unit of work"
        );
    }

    #[test]
    fn a_different_issuer_key_cannot_validate_the_ticket() {
        let issuer = issuer_from_seed(5);
        let other = issuer_from_seed(6);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "relay", 500_000);
        let (ticket, _) = issue_for_work(
            &issuer,
            &receipt,
            &key.verifying_key(),
            &blind(b"cross-issuer"),
            100,
        )
        .unwrap();
        assert!(!other.verify_ticket(&ticket));
    }

    #[test]
    fn the_root_key_is_private_and_seed_determined() {
        // Same private seed, same issuer — restarts keep working.
        assert_eq!(
            issuer_from_seed(9).public_hex_for(1, 0),
            issuer_from_seed(9).public_hex_for(1, 0)
        );
        // Different identity, different key. No public string is an input, so
        // knowing a node's fingerprint tells an attacker nothing about this.
        assert_ne!(
            issuer_from_seed(9).public_hex_for(1, 0),
            issuer_from_seed(10).public_hex_for(1, 0)
        );
    }

    #[test]
    fn bucket_keys_are_distinct_per_day_and_tier() {
        let issuer = issuer_from_seed(11);
        let keys = [
            issuer.public_hex_for(1, 0),
            issuer.public_hex_for(2, 0),
            issuer.public_hex_for(1, 1),
            issuer.public_hex_for(1, 2),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "each (day, tier) is its own key");
            }
        }
    }

    #[test]
    fn metadata_is_quantized_to_a_day_and_a_tier() {
        assert_eq!(bucket_day(0), 1);
        assert_eq!(bucket_day(86_400 - 1), 1);
        assert_eq!(bucket_day(86_400), 2);
        assert_eq!(expiry_for_day(2), 3 * 86_400);
        assert_eq!(day_of_expiry(expiry_for_day(7)), 7);

        assert_eq!(tier_for(0), 0);
        assert_eq!(tier_for(TIER_BYTES[0] - 1), 0);
        assert_eq!(tier_for(TIER_BYTES[0]), 0);
        assert_eq!(tier_for(TIER_BYTES[1]), 1);
        assert_eq!(tier_for(TIER_BYTES[2] + 1), 2);
        assert_eq!(tier_bytes(0), 1 << 20);
        assert_eq!(tier_bytes(99), 256 << 20);
    }

    #[test]
    fn a_ticket_does_not_verify_outside_its_bucket() {
        let issuer = issuer_from_seed(12);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "relay", 20 << 20);
        let (ticket, _) = issue_for_work(
            &issuer,
            &receipt,
            &key.verifying_key(),
            &blind(b"bucket"),
            100,
        )
        .unwrap();
        assert!(issuer.verify_ticket(&ticket));
        assert_eq!(ticket.bucket().tier, 1);

        // Re-labelling the day moves it to a key the issuer never signed with.
        let mut shifted = ticket.clone();
        shifted.expires_at += 86_400;
        assert!(!issuer.verify_ticket(&shifted));

        // Re-labelling the tier does the same.
        let mut retiered = ticket.clone();
        retiered.work_bytes = TIER_BYTES[2];
        assert!(!issuer.verify_ticket(&retiered));
    }

    #[test]
    fn ticket_encoding_round_trips_in_81_bytes() {
        let issuer = issuer_from_seed(13);
        let key = beneficiary();
        let receipt = unique_receipt(&key, "encoding", 42);
        let (ticket, _) = issue_for_work(
            &issuer,
            &receipt,
            &key.verifying_key(),
            &blind(b"encoding-test"),
            10,
        )
        .unwrap();
        let encoded = ticket.encode().unwrap();
        assert_eq!(encoded.len(), TICKET_ENCODED_LEN * 2);
        assert_eq!(Ticket::decode(&encoded).unwrap(), ticket);
        assert!(Ticket::decode("00").is_err());

        // A v1 ticket is refused rather than reinterpreted.
        let mut v1 = hex::decode(&encoded).unwrap();
        v1[0] = 1;
        assert!(Ticket::decode(&hex::encode(v1)).is_err());
    }

    #[test]
    fn wallet_merge_is_a_union_by_blinded_input() {
        let issuer = issuer_from_seed(14);
        let key = beneficiary();
        let mut a = Wallet::default();
        let mut b = Wallet::default();
        for (wallet, seed, work) in [
            (&mut a, b"w1".as_slice(), 4 << 20),
            (&mut b, b"w2".as_slice(), 20 << 20),
        ] {
            let request = blind(seed);
            let receipt = unique_receipt(&key, "relay", work);
            let (ticket, _) =
                issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 10).unwrap();
            wallet.tickets.push(ticket);
        }
        assert_eq!(a.merge(&b), 1);
        assert_eq!(a.merge(&b), 0, "the union is idempotent");
        assert_eq!(a.tickets.len(), 2);
        assert_eq!(a.total_credit(), TIER_BYTES[0] + TIER_BYTES[1]);
    }

    #[test]
    fn gossip_batch_round_trips_and_filters_expired() {
        let issuer = issuer_from_seed(15);
        let key = beneficiary();
        let mut w = Wallet::default();
        let r1 = unique_receipt(&key, "home", 1_000_000);
        let r2 = unique_receipt(&key, "home", 2_000_000);
        let (t1, _) =
            issue_for_work(&issuer, &r1, &key.verifying_key(), &blind(b"g1"), 100).unwrap();
        let (mut t2, _) =
            issue_for_work(&issuer, &r2, &key.verifying_key(), &blind(b"g2"), 100).unwrap();
        t2.expires_at = 50; // expired at now=100
        w.tickets.push(t1.clone());
        w.tickets.push(t2);

        let batch = encode_gossip_batch(&w, 16, 100);
        assert!(!batch.is_empty());
        let decoded = decode_gossip_batch(&batch, 100);
        assert_eq!(decoded.tickets.len(), 1);
        assert_eq!(decoded.tickets[0].m, t1.m);
        assert_eq!(decoded.tickets[0].work_bytes, TIER_BYTES[0]);
    }
}
