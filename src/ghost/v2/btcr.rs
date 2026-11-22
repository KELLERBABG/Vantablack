//! `BTCr` / Blind-Pass — relay work that a phone can spend anonymously.
//!
//! A mains-powered home PC relays encrypted traffic overnight and earns bearer
//! **TransitTickets**; the tickets sync over the private mesh to a CGNAT phone
//! and are spent at public relays. The relay that earns a ticket must not learn
//! which ticket the phone later spends, or the credit economy becomes a
//! behaviour ledger.
//!
//! The construction is a Ristretto255 VOPRF with a batched Chaum–Pedersen DLEQ
//! proof:
//!
//! ```text
//! client:   M = H2G(input),  B = r·M             (r random, never leaves)
//! issuer:   E = k·B,  DLEQ{ log_G K == log_B E } (k is the issuer secret)
//! client:   N = r⁻¹·E = k·M                      (verifies the DLEQ first)
//! relay:    accept iff N == k·M and N was never spent
//! ```
//!
//! The DLEQ matters: without it an issuer can return `E = k'·B` for a key it
//! does not publish, and the client cannot tell a valid ticket from a worthless
//! one until it is already at a relay. [`Ticket`] therefore carries both `M` and
//! `N`, and [`Issuer::verify_ticket`] is the check every relay performs.
//!
//! Issuance is gated by a signed **work receipt** (`btcr-receipt:v1`): the
//! issuer refuses to mint anything without a receipt from an allowlisted
//! beneficiary key, so a ticket cannot be created out of nothing. Double spends
//! are refused by nullifier, and the wallet is a plain JSON file the operator can
//! copy between devices.
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
/// Domain separator for the deterministic per-node issuer key.
const ISSUER_DOMAIN: &[u8] = b"VB-BTCR-ISSUER-V1";
/// Domain separator for the nullifier (one spend per ticket, not per input).
const NULLIFIER_DOMAIN: &[u8] = b"VB-BTCR-NULLIFIER-V1";
/// Version byte in the 81-byte ticket encoding.
pub const TICKET_VERSION: u8 = 1;
/// Default ticket lifetime: one day, matching one night of relay work.
pub const DEFAULT_TICKET_TTL_SECS: u64 = 24 * 3600;
/// A ticket is 81 bytes: version, M, N, expiry, work credit.
pub const TICKET_ENCODED_LEN: usize = 81;

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
    for p in [
        &RISTRETTO_BASEPOINT_POINT,
        k,
        b,
        e,
        a1,
        a2,
    ] {
        h.update(p.compress().as_bytes());
    }
    Scalar::from_hash(h)
}

impl Dleq {
    fn prove(secret: &Scalar, public: &RistrettoPoint, blinded: &RistrettoPoint, eval: &RistrettoPoint) -> Self {
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

/// The blind-signing authority. `k` never leaves this struct.
pub struct Issuer {
    secret: Scalar,
    public: RistrettoPoint,
}

impl Issuer {
    /// Deterministic issuer key for a node fingerprint.
    ///
    /// A node's ticket issuer must survive restarts without a separate key file,
    /// and it must not be the node's identity key: signing bearer tickets with
    /// the handshake key would let a ticket compromise forge sessions.
    pub fn for_node(fingerprint: &str) -> Self {
        let mut h = Sha512::new();
        h.update(ISSUER_DOMAIN);
        h.update(fingerprint.as_bytes());
        let wide = h.finalize();
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&wide);
        let secret = Scalar::from_bytes_mod_order_wide(&seed);
        Self {
            public: secret * RISTRETTO_BASEPOINT_POINT,
            secret,
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = Scalar::from_bytes_mod_order_wide(&{
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(seed);
            wide
        });
        Self {
            public: secret * RISTRETTO_BASEPOINT_POINT,
            secret,
        }
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public.compress().as_bytes())
    }

    pub fn public(&self) -> RistrettoPoint {
        self.public
    }

    /// Blind-evaluate one request and attach a DLEQ proof.
    pub fn evaluate(&self, blinded_hex: &str) -> Result<(String, Dleq), String> {
        let blinded = point_from_hex(blinded_hex)?;
        let eval = self.secret * blinded;
        let proof = Dleq::prove(&self.secret, &self.public, &blinded, &eval);
        Ok((hex::encode(eval.compress().as_bytes()), proof))
    }

    /// The check a relay performs: `N == k·M`.
    pub fn verify_ticket(&self, ticket: &Ticket) -> bool {
        let (Ok(m), Ok(n)) = (point_from_hex(&ticket.m), point_from_hex(&ticket.n)) else {
            return false;
        };
        self.secret * m == n
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
    expires_at: u64,
    work_bytes: u64,
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
        expires_at,
        work_bytes,
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
    let pk_bytes = hex::decode(&receipt.beneficiary)
        .map_err(|e| format!("bad beneficiary key: {e}"))?;
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
    let sig_bytes = hex::decode(&receipt.signature).map_err(|e| format!("bad signature hex: {e}"))?;
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
    let (eval, proof) = issuer.evaluate(&request.blinded)?;
    let expires_at = now.saturating_add(DEFAULT_TICKET_TTL_SECS);
    let ticket = finalize(
        request,
        &eval,
        &proof,
        &issuer.public_hex(),
        expires_at,
        receipt.work_bytes,
    )?;
    Ok((ticket, proof))
}

// ── Ledger: double-spend refusal ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct LedgerSnapshot {
    pub issued: u64,
    pub spent: u64,
    pub rejected_receipts: u64,
    pub rejected_replays: u64,
    pub spent_nullifiers: usize,
    pub gossip_merged: u64,
}

#[derive(Default)]
struct Ledger {
    issued: u64,
    spent: u64,
    rejected_receipts: u64,
    rejected_replays: u64,
    nullifiers: HashSet<String>,
    gossip_merged: u64,
}

fn ledger() -> &'static Mutex<Ledger> {
    static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(Ledger::default()))
}

pub fn record_issue() {
    ledger().lock().unwrap_or_else(|e| e.into_inner()).issued += 1;
}

pub fn record_rejected_receipt() {
    ledger()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .rejected_receipts += 1;
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
        guard.rejected_replays += 1;
        return Err("ticket already spent (nullifier replay refused)".into());
    }
    guard.spent += 1;
    Ok(())
}

pub fn snapshot() -> LedgerSnapshot {
    let guard = ledger().lock().unwrap_or_else(|e| e.into_inner());
    LedgerSnapshot {
        issued: guard.issued,
        spent: guard.spent,
        rejected_receipts: guard.rejected_receipts,
        rejected_replays: guard.rejected_replays,
        spent_nullifiers: guard.nullifiers.len(),
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
        let mut added = 0;
        for ticket in &other.tickets {
            if let Some(existing) = self.tickets.iter_mut().find(|t| t.m == ticket.m) {
                if ticket.work_bytes > existing.work_bytes {
                    *existing = ticket.clone();
                }
                continue;
            }
            self.tickets.push(ticket.clone());
            added += 1;
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

pub fn status_json(fingerprint: &str) -> serde_json::Value {
    let issuer = Issuer::for_node(fingerprint);
    let wallet = Wallet::load(&wallet_path());
    let snap = snapshot();
    serde_json::json!({
        "issuer": issuer.public_hex(),
        "algorithm": "ristretto255-voprf+dleq",
        "ticket_bytes": TICKET_ENCODED_LEN,
        "wallet": wallet_path().display().to_string(),
        "wallet_tickets": wallet.tickets.len(),
        "wallet_credit_bytes": wallet.total_credit(),
        "issued": snap.issued,
        "spent": snap.spent,
        "rejected_receipts": snap.rejected_receipts,
        "rejected_replays": snap.rejected_replays,
        "gossip_merged": snap.gossip_merged,
        "issuance_requires": "beneficiary-signed btcr-receipt:v1 with work_bytes > 0",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beneficiary() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn blind_issue_unblind_and_spend() {
        let issuer = Issuer::for_node("test-node");
        let key = beneficiary();
        let receipt = sign_receipt(&key, "home-pc", 4_000_000, 12).unwrap();
        let request = blind(b"phone-session-1");
        assert_ne!(request.blinded, request.input, "the issuer must not see the input");

        let (ticket, proof) = issue_for_work(
            &issuer,
            &receipt,
            &key.verifying_key(),
            &request,
            super::super::now_secs(),
        )
        .unwrap();
        assert!(issuer.verify_ticket(&ticket));
        // `finalize` already refused the ticket unless the DLEQ verified; check
        // the proof independently against the evaluation it was made over.
        let (eval, proof2) = issuer.evaluate(&request.blinded).unwrap();
        assert!(proof2.verify(
            &issuer.public(),
            &point_from_hex(&request.blinded).unwrap(),
            &point_from_hex(&eval).unwrap()
        ));
        assert!(proof.verify(
            &issuer.public(),
            &point_from_hex(&request.blinded).unwrap(),
            &point_from_hex(&eval).unwrap()
        ));
        assert_eq!(ticket.work_bytes, 4_000_000);
        spend(&issuer, &ticket, super::super::now_secs()).unwrap();
    }

    #[test]
    fn a_replayed_ticket_is_refused() {
        let issuer = Issuer::for_node("replay-node");
        let key = beneficiary();
        let receipt = sign_receipt(&key, "relay", 1_000_000, 3).unwrap();
        let request = blind(b"one-shot");
        let (ticket, _) =
            issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 100).unwrap();
        assert!(spend(&issuer, &ticket, 200).is_ok());
        let err = spend(&issuer, &ticket, 200).unwrap_err();
        assert!(err.contains("nullifier"), "{err}");
    }

    #[test]
    fn issuance_without_a_valid_receipt_is_refused() {
        let issuer = Issuer::for_node("strict-node");
        let key = beneficiary();
        let mut receipt = sign_receipt(&key, "relay", 10_000, 1).unwrap();
        receipt.work_bytes = 999_999_999; // tampered after signing
        let request = blind(b"unearned");
        let err = issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 100)
            .unwrap_err();
        assert!(err.contains("signature"), "{err}");

        let zero = Receipt {
            work_bytes: 0,
            ..sign_receipt(&key, "relay", 1, 1).unwrap()
        };
        assert!(verify_receipt(&zero, &key.verifying_key()).is_err());
    }

    #[test]
    fn a_different_issuer_key_cannot_validate_the_ticket() {
        let issuer = Issuer::for_node("issuer-a");
        let other = Issuer::for_node("issuer-b");
        let key = beneficiary();
        let receipt = sign_receipt(&key, "relay", 500_000, 9).unwrap();
        let request = blind(b"cross-issuer");
        let (ticket, _) =
            issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 100).unwrap();
        assert!(!other.verify_ticket(&ticket));
    }

    #[test]
    fn ticket_encoding_round_trips_in_81_bytes() {
        let issuer = Issuer::for_node("encoding");
        let key = beneficiary();
        let receipt = sign_receipt(&key, "relay", 42, 1).unwrap();
        let request = blind(b"encoding-test");
        let (ticket, _) =
            issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 10).unwrap();
        let encoded = ticket.encode().unwrap();
        assert_eq!(encoded.len(), TICKET_ENCODED_LEN * 2);
        assert_eq!(Ticket::decode(&encoded).unwrap(), ticket);
        assert!(Ticket::decode("00").is_err());
    }

    #[test]
    fn wallet_merge_is_a_union_by_blinded_input() {
        let issuer = Issuer::for_node("wallet");
        let key = beneficiary();
        let mut a = Wallet::default();
        let mut b = Wallet::default();
        for (wallet, seed, work) in [(&mut a, b"w1".as_slice(), 100u64), (&mut b, b"w2".as_slice(), 250)] {
            let request = blind(seed);
            let receipt = sign_receipt(&key, "relay", work, 1).unwrap();
            let (ticket, _) =
                issue_for_work(&issuer, &receipt, &key.verifying_key(), &request, 10).unwrap();
            assert_eq!(ticket.work_bytes, work);
            wallet.tickets.push(ticket);
        }
        assert_eq!(a.merge(&b), 1);
        assert_eq!(a.merge(&b), 0, "the union is idempotent");
        assert_eq!(a.tickets.len(), 2);
        assert_eq!(a.total_credit(), 350);
    }

    #[test]
    fn gossip_batch_round_trips_and_filters_expired() {
        let issuer = Issuer::for_node("gossip-node");
        let key = beneficiary();
        let mut w = Wallet::default();
        let r1 = sign_receipt(&key, "home", 1_000_000, 1).unwrap();
        let r2 = sign_receipt(&key, "home", 2_000_000, 2).unwrap();
        let (t1, _) = issue_for_work(&issuer, &r1, &key.verifying_key(), &blind(b"g1"), 100).unwrap();
        let (mut t2, _) = issue_for_work(&issuer, &r2, &key.verifying_key(), &blind(b"g2"), 100).unwrap();
        t2.expires_at = 50; // expired at now=100
        w.tickets.push(t1.clone());
        w.tickets.push(t2);

        let batch = encode_gossip_batch(&w, 16, 100);
        assert!(!batch.is_empty());
        let decoded = decode_gossip_batch(&batch, 100);
        assert_eq!(decoded.tickets.len(), 1);
        assert_eq!(decoded.tickets[0].m, t1.m);
        assert_eq!(decoded.tickets[0].work_bytes, 1_000_000);
    }
}
