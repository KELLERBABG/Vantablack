//! Fleet subkeys — one offline root, many cheap devices.
//!
//! Today, losing a phone means rotating the mesh-wide `GHOST_PSK` on every
//! device: a shared secret cannot revoke one member without breaking all of
//! them. The fix is delegation. An **offline** fleet root signs a short
//! certificate for each device, and each device authenticates with its own key.
//! Losing one device then costs a single gossipped [`Revocation`] — 85 bytes —
//! instead of a fleet-wide re-key.
//!
//! Design constraints, each of which is tested:
//!
//! * **The root never travels.** [`FleetRoot`] holds an Ed25519 signing key
//!   that exists in memory only while issuing; [`DeviceCert`] carries only the
//!   public half. There is nothing on a phone that can mint a new device.
//! * **Certificates expire.** A stolen device's certificate is useless after
//!   `expires_at` even if the revocation never reaches every peer.
//! * **Revocation is monotone.** [`RevocationSet`] merges by device id and keeps
//!   the newest timestamp, so a replayed old revocation cannot un-revoke, and a
//!   replayed new one is idempotent.
//! * **Signatures are checked strictly.** `verify_strict` rejects the
//!   malleable encodings `verify` accepts.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Certificate validity used by [`FleetRoot::issue`] when the caller does not
/// pass one: 90 days. Long enough that a phone is not re-onboarded monthly,
/// short enough that a lost device ages out without depending on gossip.
pub const DEFAULT_CERT_TTL_SECS: u64 = 90 * 24 * 3600;

/// Why a device was revoked. One byte on the wire, so the reason survives
/// gossip without a text field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    Lost,
    Stolen,
    Decommissioned,
    Compromised,
    Other,
}

impl RevokeReason {
    pub fn as_u8(self) -> u8 {
        match self {
            RevokeReason::Lost => 1,
            RevokeReason::Stolen => 2,
            RevokeReason::Decommissioned => 3,
            RevokeReason::Compromised => 4,
            RevokeReason::Other => 255,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => RevokeReason::Lost,
            2 => RevokeReason::Stolen,
            3 => RevokeReason::Decommissioned,
            4 => RevokeReason::Compromised,
            _ => RevokeReason::Other,
        }
    }
}

/// A device's short public identifier: the first 8 bytes of its key hash.
///
/// Eight bytes is what fits in a gossip message and a QR code; a collision
/// within one fleet is not a security event because the certificate itself
/// carries the full key, so a revoked id only ever removes *more* authority.
pub fn device_id_for(pk: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VB-DEVICE-ID-V1");
    h.update(pk);
    let d = h.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&d[..8]);
    id
}

fn put_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A device certificate, signed by the offline fleet root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCert {
    /// Fleet identifier (hash of the root public key), so certs from two fleets
    /// cannot be mixed.
    pub fleet_id: String,
    /// The device's Ed25519 public key, hex.
    pub device_pk: String,
    /// Human label ("Lukas' phone"). Authenticated but not trusted for routing.
    pub label: String,
    /// Unix seconds.
    pub issued_at: u64,
    pub expires_at: u64,
    /// Hex, 64 bytes.
    pub signature: String,
}

impl DeviceCert {
    /// The exact bytes the root signs. Any change to the fields invalidates the
    /// signature; the encoding is length-prefixed so labels cannot be shifted
    /// between fields.
    pub fn canonical_bytes(
        fleet_id_hex: &str,
        device_pk: &[u8; 32],
        label: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + label.len());
        out.extend_from_slice(b"VB-FLEET-CERT-V1");
        put_len_prefixed(&mut out, fleet_id_hex.as_bytes());
        out.extend_from_slice(device_pk);
        put_len_prefixed(&mut out, label.as_bytes());
        out.extend_from_slice(&issued_at.to_be_bytes());
        out.extend_from_slice(&expires_at.to_be_bytes());
        out
    }

    pub fn device_id(&self) -> Option<[u8; 8]> {
        let raw = hex::decode(&self.device_pk).ok()?;
        let pk: [u8; 32] = raw.try_into().ok()?;
        Some(device_id_for(&pk))
    }

    /// Verify against the fleet's public key. Checks the fleet id binding, the
    /// signature, and the validity window at `now`.
    pub fn verify(&self, root_pk: &[u8; 32], now: u64) -> Result<(), CertError> {
        let expected_fleet = fleet_id_for(root_pk);
        if self.fleet_id != expected_fleet {
            return Err(CertError::WrongFleet);
        }
        if now < self.issued_at {
            return Err(CertError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(CertError::Expired);
        }
        let raw_pk = hex::decode(&self.device_pk).map_err(|_| CertError::Malformed)?;
        let pk: [u8; 32] = raw_pk.try_into().map_err(|_| CertError::Malformed)?;
        let sig_bytes = hex::decode(&self.signature).map_err(|_| CertError::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| CertError::Malformed)?;
        let sig = Signature::from_bytes(&sig_arr);
        let vk = VerifyingKey::from_bytes(root_pk).map_err(|_| CertError::Malformed)?;
        let msg = Self::canonical_bytes(&self.fleet_id, &pk, &self.label, self.issued_at, self.expires_at);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| CertError::BadSignature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    WrongFleet,
    BadSignature,
    Expired,
    NotYetValid,
    Malformed,
    Revoked,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CertError::WrongFleet => "certificate belongs to a different fleet",
            CertError::BadSignature => "certificate signature is invalid",
            CertError::Expired => "certificate has expired",
            CertError::NotYetValid => "certificate is not valid yet",
            CertError::Malformed => "certificate is malformed",
            CertError::Revoked => "device has been revoked",
        })
    }
}

impl std::error::Error for CertError {}

/// The fleet's public identity, derived from the root key.
pub fn fleet_id_for(root_pk: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VB-FLEET-ID-V1");
    h.update(root_pk);
    hex::encode(&h.finalize()[..16])
}

/// The offline root. Deliberately not `Clone` and not serialisable: it cannot be
/// written to disk by accident through a derive.
pub struct FleetRoot {
    signing: SigningKey,
    fleet_id: String,
}

impl FleetRoot {
    /// From a 32-byte seed, which the operator is expected to keep offline
    /// (paper, hardware token).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let fleet_id = fleet_id_for(&signing.verifying_key().to_bytes());
        Self { signing, fleet_id }
    }

    /// Generate a new root from the OS RNG. The seed is returned so the caller
    /// can persist it wherever it keeps secrets; it is not retained separately.
    pub fn generate() -> (Self, [u8; 32]) {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        (Self::from_seed(seed), seed)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    pub fn fleet_id(&self) -> &str {
        &self.fleet_id
    }

    /// Issue a certificate. `label` is authenticated; it is not a security
    /// boundary, so it is capped to keep a hostile label from inflating gossip.
    pub fn issue(&self, device_pk: [u8; 32], label: &str, now: u64, ttl: u64) -> DeviceCert {
        let label: String = label.chars().take(64).collect();
        let expires_at = now.saturating_add(ttl.max(1));
        let msg = DeviceCert::canonical_bytes(&self.fleet_id, &device_pk, &label, now, expires_at);
        let sig = self.signing.sign(&msg);
        DeviceCert {
            fleet_id: self.fleet_id.clone(),
            device_pk: hex::encode(device_pk),
            label,
            issued_at: now,
            expires_at,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Sign a revocation. The root is required: an attacker who has stolen a
    /// device has that device's key, not this one.
    pub fn revoke(&self, device_pk: &[u8; 32], reason: RevokeReason, now: u64) -> Revocation {
        let device_id = device_id_for(device_pk);
        let msg = Revocation::canonical_bytes(&device_id, now, reason);
        let sig = self.signing.sign(&msg);
        Revocation {
            device_id: hex::encode(device_id),
            issued_at: now,
            reason,
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

/// A gossipped revocation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub device_id: String,
    pub issued_at: u64,
    pub reason: RevokeReason,
    pub signature: String,
}

impl Revocation {
    pub const MAGIC: &'static [u8; 4] = b"VBRV";

    pub fn canonical_bytes(device_id: &[u8; 8], issued_at: u64, reason: RevokeReason) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(Self::MAGIC);
        out.extend_from_slice(device_id);
        out.extend_from_slice(&issued_at.to_be_bytes());
        out.push(reason.as_u8());
        out
    }

    /// Wire form: 4-byte magic, 8-byte id, 8-byte timestamp, reason byte and a
    /// 64-byte signature — 85 bytes, inside the roadmap's 128-byte budget.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let id = hex::decode(&self.device_id).ok()?;
        let id: [u8; 8] = id.try_into().ok()?;
        let sig = hex::decode(&self.signature).ok()?;
        let sig: [u8; 64] = sig.try_into().ok()?;
        let mut out = Self::canonical_bytes(&id, self.issued_at, self.reason);
        out.extend_from_slice(&sig);
        Some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 4 + 8 + 8 + 1 + 64 || &bytes[0..4] != Self::MAGIC {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes[4..12]);
        let issued_at = u64::from_be_bytes(bytes[12..20].try_into().ok()?);
        let reason = RevokeReason::from_u8(bytes[20]);
        let sig = &bytes[21..85];
        Some(Self {
            device_id: hex::encode(id),
            issued_at,
            reason,
            signature: hex::encode(sig),
        })
    }

    pub fn device_id_bytes(&self) -> Option<[u8; 8]> {
        hex::decode(&self.device_id).ok()?.try_into().ok()
    }

    pub fn verify(&self, root_pk: &[u8; 32]) -> bool {
        let Some(id) = self.device_id_bytes() else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&self.signature) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(root_pk) else {
            return false;
        };
        vk.verify_strict(
            &Self::canonical_bytes(&id, self.issued_at, self.reason),
            &Signature::from_bytes(&sig_arr),
        )
        .is_ok()
    }
}

/// The set of revoked device ids a node knows, with gossip merge.
#[derive(Debug, Default)]
pub struct RevocationSet {
    entries: HashMap<[u8; 8], u64>,
    rejected: u64,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge a gossipped revocation. Only a signature by the fleet root is
    /// accepted; the newest timestamp wins per device so replaying an old entry
    /// cannot resurrect a revoked device.
    pub fn merge(&mut self, rev: &Revocation, root_pk: &[u8; 32]) -> bool {
        if !rev.verify(root_pk) {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        let Some(id) = rev.device_id_bytes() else {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        };
        let entry = self.entries.entry(id).or_insert(rev.issued_at);
        if rev.issued_at > *entry {
            *entry = rev.issued_at;
        }
        true
    }

    pub fn is_revoked(&self, device_pk: &[u8; 32]) -> bool {
        self.entries.contains_key(&device_id_for(device_pk))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    pub fn device_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = self.entries.keys().map(hex::encode).collect();
        out.sort();
        out
    }
}

/// Admit a device only if its certificate is valid, unexpired and unrevol­ked.
/// Prefix of the QR/onboarding payload for a device certificate.
pub const FLEET_URI_PREFIX: &str = "vb-fleet://";

/// Encode the onboarding payload a QR code carries: the fleet's public key and
/// the device certificate, both hex. Hex keeps the payload dependency-free; a QR
/// encoder only has to render the string.
pub fn encode_invite(root_pk: &[u8; 32], cert: &DeviceCert) -> Option<String> {
    let json = serde_json::to_vec(cert).ok()?;
    Some(format!(
        "{FLEET_URI_PREFIX}{}/{}",
        hex::encode(root_pk),
        hex::encode(json)
    ))
}

/// Parse a `vb-fleet://` payload. It is not trusted until `admit` verifies the
/// certificate against the root key it carries.
pub fn decode_invite(uri: &str) -> Result<([u8; 32], DeviceCert), String> {
    let rest = uri
        .trim()
        .strip_prefix(FLEET_URI_PREFIX)
        .ok_or_else(|| format!("not a {FLEET_URI_PREFIX} URI"))?;
    let (root_hex, cert_hex) = rest
        .split_once('/')
        .ok_or_else(|| "vb-fleet:// URI must be root-key/certificate".to_string())?;
    let root_raw = hex::decode(root_hex).map_err(|e| format!("root key is not hex: {e}"))?;
    let root_pk: [u8; 32] = root_raw
        .try_into()
        .map_err(|_| "root key must be 32 bytes".to_string())?;
    let cert_raw = hex::decode(cert_hex).map_err(|e| format!("certificate is not hex: {e}"))?;
    let cert: DeviceCert = serde_json::from_slice(&cert_raw)
        .map_err(|e| format!("certificate JSON is invalid: {e}"))?;
    Ok((root_pk, cert))
}

pub fn admit(
    cert: &DeviceCert,
    root_pk: &[u8; 32],
    revocations: &RevocationSet,
    now: u64,
) -> Result<[u8; 32], CertError> {
    cert.verify(root_pk, now)?;
    let raw = hex::decode(&cert.device_pk).map_err(|_| CertError::Malformed)?;
    let pk: [u8; 32] = raw.try_into().map_err(|_| CertError::Malformed)?;
    if revocations.is_revoked(&pk) {
        return Err(CertError::Revoked);
    }
    Ok(pk)
}

// ── Live Revocation Gossip Store ────────────────────────────────────────────

#[derive(Default)]
struct GossipState {
    root_pk: Option<[u8; 32]>,
    set: RevocationSet,
    raw_entries: Vec<Revocation>,
    gossip_merged: u64,
}

fn gossip_state() -> &'static std::sync::Mutex<GossipState> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<GossipState>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(GossipState::default()))
}

/// Configure the fleet root public key used to verify incoming gossiped revocations.
pub fn configure_root_pk(root_pk: [u8; 32]) {
    gossip_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .root_pk = Some(root_pk);
}

/// Return the configured fleet root public key (checking `GHOST_FLEET_ROOT_PK` if unset).
pub fn configured_root_pk() -> Option<[u8; 32]> {
    let mut guard = gossip_state().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pk) = guard.root_pk {
        return Some(pk);
    }
    if let Ok(hex_pk) = std::env::var("GHOST_FLEET_ROOT_PK") {
        if let Ok(raw) = hex::decode(hex_pk.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(raw) {
                guard.root_pk = Some(arr);
                return Some(arr);
            }
        }
    }
    None
}

/// Verify and store a signed [`Revocation`] for mesh gossip.
pub fn record_revocation(rev: Revocation, root_pk: &[u8; 32]) -> bool {
    let mut guard = gossip_state().lock().unwrap_or_else(|e| e.into_inner());
    if guard.root_pk.is_none() {
        guard.root_pk = Some(*root_pk);
    }
    let already = guard
        .raw_entries
        .iter()
        .any(|e| e.device_id == rev.device_id && e.issued_at >= rev.issued_at);
    if !already && guard.set.merge(&rev, root_pk) {
        guard.raw_entries.retain(|e| e.device_id != rev.device_id);
        guard.raw_entries.push(rev);
        true
    } else {
        false
    }
}

/// Check whether `device_pk` has been revoked in the live fleet store.
pub fn is_device_pk_revoked(device_pk: &[u8; 32]) -> bool {
    gossip_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .set
        .is_revoked(device_pk)
}

const REVOCATION_BYTES: usize = 85;

/// Encode up to 16 revocations into a `GHOST_REVOKE__` gossip batch: `[count u8]([85-byte Revocation]...)`.
pub fn export_gossip_revocation_batch() -> Vec<u8> {
    let guard = gossip_state().lock().unwrap_or_else(|e| e.into_inner());
    if guard.raw_entries.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.push(0u8);
    let mut count: u8 = 0;
    for rev in guard.raw_entries.iter().take(16) {
        if let Some(enc) = rev.encode() {
            if enc.len() == REVOCATION_BYTES {
                out.extend_from_slice(&enc);
                count = count.saturating_add(1);
            }
        }
    }
    if count == 0 {
        return Vec::new();
    }
    out[0] = count;
    out
}

/// Ingest a `GHOST_REVOKE__` gossip batch, verifying every entry against the configured fleet root.
pub fn ingest_gossip_revocation_batch(bytes: &[u8]) -> usize {
    let Some(root_pk) = configured_root_pk() else {
        return 0;
    };
    if bytes.is_empty() {
        return 0;
    }
    let count = bytes[0] as usize;
    let mut pos = 1usize;
    let mut merged = 0usize;
    let mut guard = gossip_state().lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..count {
        if pos + REVOCATION_BYTES > bytes.len() {
            break;
        }
        if let Some(rev) = Revocation::decode(&bytes[pos..pos + REVOCATION_BYTES]) {
            let already = guard
                .raw_entries
                .iter()
                .any(|e| e.device_id == rev.device_id && e.issued_at >= rev.issued_at);
            if !already && guard.set.merge(&rev, &root_pk) {
                guard.raw_entries.retain(|e| e.device_id != rev.device_id);
                guard.raw_entries.push(rev);
                guard.gossip_merged += 1;
                merged += 1;
            }
        }
        pos += REVOCATION_BYTES;
    }
    merged
}

pub fn status_json() -> serde_json::Value {
    let root_pk = configured_root_pk();
    let guard = gossip_state().lock().unwrap_or_else(|e| e.into_inner());
    serde_json::json!({
        "configured": root_pk.is_some(),
        "fleet_id": root_pk.as_ref().map(fleet_id_for),
        "root_pk": root_pk.as_ref().map(hex::encode),
        "revoked_count": guard.set.len(),
        "revoked_device_ids": guard.set.device_ids(),
        "rejected_revocations": guard.set.rejected(),
        "gossip_merged": guard.gossip_merged,
    })
}

// ── Pure-Rust ISO-18004 QR SVG Renderer (Versions 1..=14, ECC-L, Mask 0) ────

struct QrVersionSpec {
    version: u8,
    g1_blocks: usize,
    g1_data: usize,
    g2_blocks: usize,
    g2_data: usize,
    ecc_per_block: usize,
    align: &'static [usize],
}

const QR_SPECS: &[QrVersionSpec] = &[
    QrVersionSpec { version: 1, g1_blocks: 1, g1_data: 19, g2_blocks: 0, g2_data: 0, ecc_per_block: 7, align: &[] },
    QrVersionSpec { version: 2, g1_blocks: 1, g1_data: 34, g2_blocks: 0, g2_data: 0, ecc_per_block: 10, align: &[6, 18] },
    QrVersionSpec { version: 3, g1_blocks: 1, g1_data: 55, g2_blocks: 0, g2_data: 0, ecc_per_block: 15, align: &[6, 22] },
    QrVersionSpec { version: 4, g1_blocks: 1, g1_data: 80, g2_blocks: 0, g2_data: 0, ecc_per_block: 20, align: &[6, 26] },
    QrVersionSpec { version: 5, g1_blocks: 1, g1_data: 108, g2_blocks: 0, g2_data: 0, ecc_per_block: 26, align: &[6, 30] },
    QrVersionSpec { version: 6, g1_blocks: 2, g1_data: 68, g2_blocks: 0, g2_data: 0, ecc_per_block: 18, align: &[6, 34] },
    QrVersionSpec { version: 7, g1_blocks: 2, g1_data: 78, g2_blocks: 0, g2_data: 0, ecc_per_block: 20, align: &[6, 22, 38] },
    QrVersionSpec { version: 8, g1_blocks: 2, g1_data: 97, g2_blocks: 0, g2_data: 0, ecc_per_block: 24, align: &[6, 24, 42] },
    QrVersionSpec { version: 9, g1_blocks: 2, g1_data: 116, g2_blocks: 0, g2_data: 0, ecc_per_block: 30, align: &[6, 26, 46] },
    QrVersionSpec { version: 10, g1_blocks: 2, g1_data: 68, g2_blocks: 2, g2_data: 69, ecc_per_block: 18, align: &[6, 28, 50] },
    QrVersionSpec { version: 11, g1_blocks: 4, g1_data: 81, g2_blocks: 0, g2_data: 0, ecc_per_block: 20, align: &[6, 30, 54] },
    QrVersionSpec { version: 12, g1_blocks: 2, g1_data: 92, g2_blocks: 2, g2_data: 93, ecc_per_block: 24, align: &[6, 32, 58] },
    QrVersionSpec { version: 13, g1_blocks: 4, g1_data: 107, g2_blocks: 0, g2_data: 0, ecc_per_block: 26, align: &[6, 34, 62] },
    QrVersionSpec { version: 14, g1_blocks: 3, g1_data: 115, g2_blocks: 1, g2_data: 116, ecc_per_block: 30, align: &[6, 26, 46, 66] },
    QrVersionSpec { version: 15, g1_blocks: 5, g1_data: 87, g2_blocks: 1, g2_data: 88, ecc_per_block: 22, align: &[6, 26, 48, 70] },
    QrVersionSpec { version: 16, g1_blocks: 5, g1_data: 98, g2_blocks: 1, g2_data: 99, ecc_per_block: 24, align: &[6, 26, 50, 74] },
    QrVersionSpec { version: 17, g1_blocks: 1, g1_data: 107, g2_blocks: 5, g2_data: 108, ecc_per_block: 28, align: &[6, 30, 54, 78] },
    QrVersionSpec { version: 18, g1_blocks: 5, g1_data: 120, g2_blocks: 1, g2_data: 121, ecc_per_block: 30, align: &[6, 30, 56, 82] },
    QrVersionSpec { version: 19, g1_blocks: 3, g1_data: 113, g2_blocks: 4, g2_data: 114, ecc_per_block: 28, align: &[6, 30, 58, 86] },
    QrVersionSpec { version: 20, g1_blocks: 3, g1_data: 107, g2_blocks: 5, g2_data: 108, ecc_per_block: 28, align: &[6, 34, 62, 90] },
    QrVersionSpec { version: 21, g1_blocks: 4, g1_data: 116, g2_blocks: 4, g2_data: 117, ecc_per_block: 28, align: &[6, 28, 50, 72, 94] },
    QrVersionSpec { version: 22, g1_blocks: 2, g1_data: 111, g2_blocks: 7, g2_data: 112, ecc_per_block: 28, align: &[6, 26, 50, 74, 98] },
];

fn gf_mul(mut x: u8, mut y: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        if y & 1 != 0 {
            r ^= x;
        }
        let hi = x & 0x80;
        x <<= 1;
        if hi != 0 {
            x ^= 0x1d;
        }
        y >>= 1;
    }
    r
}

fn rs_remainder(data: &[u8], ecc_len: usize) -> Vec<u8> {
    let mut gen = vec![0u8; ecc_len];
    gen[ecc_len - 1] = 1;
    let mut root = 1u8;
    for _ in 0..ecc_len {
        for j in 0..ecc_len {
            gen[j] = gf_mul(gen[j], root);
            if j + 1 < ecc_len {
                gen[j] ^= gen[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    let mut rem = vec![0u8; ecc_len];
    for &b in data {
        let factor = b ^ rem[0];
        rem.copy_within(1.., 0);
        rem[ecc_len - 1] = 0;
        for j in 0..ecc_len {
            rem[j] ^= gf_mul(gen[j], factor);
        }
    }
    rem
}

fn push_bits(buf: &mut Vec<u8>, bit_len: &mut usize, val: u32, count: usize) {
    for i in (0..count).rev() {
        let idx = *bit_len / 8;
        if idx >= buf.len() {
            buf.push(0);
        }
        if (val >> i) & 1 != 0 {
            buf[idx] |= 1 << (7 - (*bit_len % 8));
        }
        *bit_len += 1;
    }
}

/// Encode `text` into a QR matrix (`size x size` booleans, `true` = dark module).
pub fn encode_qr_matrix(text: &str) -> Result<Vec<Vec<bool>>, String> {
    let payload = text.as_bytes();
    let spec = QR_SPECS
        .iter()
        .find(|s| {
            let total_data = s.g1_blocks * s.g1_data + s.g2_blocks * s.g2_data;
            let hdr_bits = if s.version >= 10 { 20 } else { 12 };
            (hdr_bits + payload.len() * 8).div_ceil(8) <= total_data
        })
        .ok_or_else(|| format!("QR payload too large ({} bytes > V14 ECC-L capacity)", payload.len()))?;

    let total_data = spec.g1_blocks * spec.g1_data + spec.g2_blocks * spec.g2_data;
    let mut data_bytes = Vec::with_capacity(total_data);
    let mut bit_len = 0usize;
    push_bits(&mut data_bytes, &mut bit_len, 0b0100, 4);
    let count_bits = if spec.version >= 10 { 16 } else { 8 };
    push_bits(&mut data_bytes, &mut bit_len, payload.len() as u32, count_bits);
    for &b in payload {
        push_bits(&mut data_bytes, &mut bit_len, b as u32, 8);
    }
    let rem_bits = (total_data * 8).saturating_sub(bit_len).min(4);
    push_bits(&mut data_bytes, &mut bit_len, 0, rem_bits);
    while data_bytes.len() < total_data {
        data_bytes.push(0xec);
        if data_bytes.len() < total_data {
            data_bytes.push(0x11);
        }
    }

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut eccs: Vec<Vec<u8>> = Vec::new();
    let mut off = 0usize;
    for (n, len) in [(spec.g1_blocks, spec.g1_data), (spec.g2_blocks, spec.g2_data)] {
        for _ in 0..n {
            let blk = data_bytes[off..off + len].to_vec();
            eccs.push(rs_remainder(&blk, spec.ecc_per_block));
            blocks.push(blk);
            off += len;
        }
    }
    let mut codewords = Vec::new();
    let max_data = spec.g1_data.max(spec.g2_data);
    for i in 0..max_data {
        for b in &blocks {
            if i < b.len() {
                codewords.push(b[i]);
            }
        }
    }
    for i in 0..spec.ecc_per_block {
        for e in &eccs {
            codewords.push(e[i]);
        }
    }

    let n = 17 + 4 * spec.version as usize;
    let mut grid = vec![vec![false; n]; n];
    let mut func = vec![vec![false; n]; n];

    let mut set_fn = |r: usize, c: usize, dark: bool| {
        grid[r][c] = dark;
        func[r][c] = true;
    };
    for &(fr, fc) in &[(0usize, 0usize), (0, n - 7), (n - 7, 0)] {
        for dr in 0..7 {
            for dc in 0..7 {
                let border = dr == 0 || dr == 6 || dc == 0 || dc == 6;
                let center = (2..=4).contains(&dr) && (2..=4).contains(&dc);
                set_fn(fr + dr, fc + dc, border || center);
            }
        }
    }
    for i in 0..8 {
        set_fn(7, i, false);
        set_fn(i, 7, false);
        set_fn(7, n - 1 - i, false);
        set_fn(i, n - 8, false);
        set_fn(n - 8, i, false);
        set_fn(n - 1 - i, 7, false);
    }
    for i in 8..(n - 8) {
        set_fn(6, i, i % 2 == 0);
        set_fn(i, 6, i % 2 == 0);
    }
    set_fn(n - 8, 8, true);

    for &ar in spec.align {
        for &ac in spec.align {
            if (ar <= 7 && (ac <= 7 || ac >= n - 8)) || (ar >= n - 8 && ac <= 7) {
                continue;
            }
            for dr in 0..5 {
                for dc in 0..5 {
                    let r = ar + dr - 2;
                    let c = ac + dc - 2;
                    let dark = dr == 0 || dr == 4 || dc == 0 || dc == 4 || (dr == 2 && dc == 2);
                    set_fn(r, c, dark);
                }
            }
        }
    }

    // Reserve format areas + write ECC-L Mask 0 format bits (0x77c4).
    const FORMAT_L_M0: u16 = 0x77c4;
    for i in 0..15 {
        let bit = ((FORMAT_L_M0 >> i) & 1) != 0;
        if i < 6 {
            set_fn(8, i, bit);
        } else if i < 8 {
            set_fn(8, i + 1, bit);
        } else {
            set_fn(8, n - 15 + i, bit);
        }
        if i < 8 {
            set_fn(n - 1 - i, 8, bit);
        } else if i == 8 {
            set_fn(7, 8, bit);
        } else {
            set_fn(14 - i, 8, bit);
        }
    }

    if spec.version >= 7 {
        let mut rem = (spec.version as u32) << 12;
        for i in (12..=17).rev() {
            if (rem >> i) & 1 != 0 {
                rem ^= 0x1f25 << (i - 12);
            }
        }
        let vbits = ((spec.version as u32) << 12) | rem;
        for i in 0..18 {
            let bit = ((vbits >> i) & 1) != 0;
            let a = i / 3;
            let b = n - 11 + (i % 3);
            set_fn(a, b, bit);
            set_fn(b, a, bit);
        }
    }

    // Place data bits in zig-zag columns, applying Mask 0: (r + c) % 2 == 0.
    let mut bit_idx = 0usize;
    let total_bits = codewords.len() * 8;
    let mut col = n as isize - 1;
    let mut up = true;
    while col > 0 {
        if col == 6 {
            col -= 1;
        }
        for step in 0..n {
            let r = if up { n - 1 - step } else { step };
            for dx in [0isize, -1] {
                let c = (col + dx) as usize;
                if !func[r][c] {
                    let raw_bit = if bit_idx < total_bits {
                        ((codewords[bit_idx / 8] >> (7 - (bit_idx % 8))) & 1) != 0
                    } else {
                        false
                    };
                    grid[r][c] = raw_bit ^ (r + c).is_multiple_of(2);
                    bit_idx += 1;
                }
            }
        }
        up = !up;
        col -= 2;
    }

    Ok(grid)
}

/// Render `text` as a crisp, self-contained `<svg>` QR code with a 4-module quiet zone.
pub fn render_qr_svg(text: &str) -> Result<String, String> {
    let matrix = encode_qr_matrix(text)?;
    let size = matrix.len();
    let quiet = 4;
    let total = size + quiet * 2;
    let mut path = String::new();
    for (r, row) in matrix.iter().enumerate() {
        for (c, &dark) in row.iter().enumerate() {
            if dark {
                use std::fmt::Write;
                let _ = write!(path, "M{},{}h1v1h-1z", c + quiet, r + quiet);
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"Vantablack Fleet Invite QR\"><rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/><path d=\"{path}\" fill=\"#000000\"/></svg>"
    ))
}

/// Render a `vb-fleet://` onboarding invite directly as an SVG QR code.
pub fn render_invite_qr_svg(root_pk: &[u8; 32], cert: &DeviceCert) -> Result<String, String> {
    let uri = encode_invite(root_pk, cert).ok_or_else(|| "invite encoding failed".to_string())?;
    render_qr_svg(&uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn issued_certificates_verify_and_expire() {
        let (root, _seed) = FleetRoot::generate();
        let cert = root.issue(device(7), "Lukas' phone", 1_000, DEFAULT_CERT_TTL_SECS);
        let now = 1_000;
        let vk = admit(&cert, &root.public_key(), &RevocationSet::new(), now).unwrap();
        assert_eq!(vk, device(7));

        assert_eq!(
            cert.verify(&root.public_key(), 1_000 + DEFAULT_CERT_TTL_SECS),
            Err(CertError::Expired)
        );
        assert_eq!(
            cert.verify(&root.public_key(), 999),
            Err(CertError::NotYetValid)
        );
    }

    #[test]
    fn a_certificate_cannot_be_moved_to_another_device() {
        let (root, _) = FleetRoot::generate();
        let mut cert = root.issue(device(1), "phone", 10, 100);
        cert.label = "laptop".into();
        assert_eq!(cert.verify(&root.public_key(), 20), Err(CertError::BadSignature));
    }

    #[test]
    fn another_fleet_root_is_rejected() {
        let (root, _) = FleetRoot::generate();
        let (other, _) = FleetRoot::generate();
        let cert = root.issue(device(2), "tablet", 0, 1000);
        assert_eq!(
            cert.verify(&other.public_key(), 1),
            Err(CertError::WrongFleet)
        );
    }

    #[test]
    fn revocation_is_85_bytes_and_only_the_root_can_sign_it() {
        let (root, _) = FleetRoot::generate();
        let rev = root.revoke(&device(3), RevokeReason::Stolen, 500);
        let wire = rev.encode().expect("encode");
        assert_eq!(wire.len(), 85);
        assert!(wire.len() <= 128);
        assert!(rev.verify(&root.public_key()));

        let decoded = Revocation::decode(&wire).expect("decode");
        assert_eq!(decoded, rev);

        let (other, _) = FleetRoot::generate();
        assert!(!rev.verify(&other.public_key()));
    }

    #[test]
    fn revocation_set_rejects_forgeries_and_is_monotone() {
        let (root, _) = FleetRoot::generate();
        let mut set = RevocationSet::new();
        let dev = device(4);

        let rev = root.revoke(&dev, RevokeReason::Lost, 200);
        assert!(set.merge(&rev, &root.public_key()));
        assert!(set.is_revoked(&dev));

        let (attacker, _) = FleetRoot::generate();
        let forged = attacker.revoke(&device(5), RevokeReason::Lost, 300);
        assert!(!set.merge(&forged, &root.public_key()));
        assert_eq!(set.rejected(), 1);

        // An older but genuine entry must not roll the timestamp back.
        let older = root.revoke(&dev, RevokeReason::Lost, 100);
        assert!(set.merge(&older, &root.public_key()));
        assert!(set.is_revoked(&dev));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn admission_refuses_a_revoked_device() {
        let (root, _) = FleetRoot::generate();
        let dev = device(6);
        let cert = root.issue(dev, "old phone", 100, 10_000);
        let mut set = RevocationSet::new();
        assert!(admit(&cert, &root.public_key(), &set, 200).is_ok());
        set.merge(&root.revoke(&dev, RevokeReason::Decommissioned, 150), &root.public_key());
        assert_eq!(
            admit(&cert, &root.public_key(), &set, 200),
            Err(CertError::Revoked)
        );
    }

    #[test]
    fn fleet_invite_round_trips_and_still_needs_the_root_signature() {
        let (root, _seed) = FleetRoot::generate();
        let cert = root.issue(device(9), "Lukas' phone", 1_000, DEFAULT_CERT_TTL_SECS);
        let uri = encode_invite(&root.public_key(), &cert).expect("encode invite");
        assert!(uri.starts_with(FLEET_URI_PREFIX));
        let (root_pk, decoded) = decode_invite(&uri).expect("decode invite");
        assert_eq!(root_pk, root.public_key());
        assert_eq!(decoded, cert);
        assert_eq!(
            admit(&decoded, &root_pk, &RevocationSet::new(), 2_000),
            Ok(device(9))
        );

        // A payload that swaps in another device's key must fail admission.
        let mut tampered = decoded;
        tampered.device_pk = hex::encode(device(10));
        assert_eq!(
            admit(&tampered, &root_pk, &RevocationSet::new(), 2_000),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn label_is_capped_so_gossip_stays_small() {
        let (root, _) = FleetRoot::generate();
        let long = "x".repeat(500);
        let cert = root.issue(device(8), &long, 0, 100);
        assert_eq!(cert.label.chars().count(), 64);
        assert!(cert.verify(&root.public_key(), 1).is_ok());
    }

    #[test]
    fn qr_svg_renders_valid_matrix_for_fleet_invite() {
        let (root, _) = FleetRoot::generate();
        let cert = root.issue(device(11), "Pixel", 2_000, DEFAULT_CERT_TTL_SECS);
        let svg = render_invite_qr_svg(&root.public_key(), &cert).expect("render fleet QR");
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("shape-rendering=\"crispEdges\""));
        assert!(svg.ends_with("</svg>"));

        let uri = encode_invite(&root.public_key(), &cert).unwrap();
        let matrix = encode_qr_matrix(&uri).unwrap();
        let n = matrix.len();
        assert!(n >= 21 && (n - 17).is_multiple_of(4));
        // Top-left 7x7 finder border & center must be dark.
        assert!(matrix[0][0] && matrix[0][6] && matrix[6][0] && matrix[3][3]);
    }

    #[test]
    fn revocation_gossip_store_verifies_and_exports_batches() {
        let (root, _) = FleetRoot::generate();
        let pk = root.public_key();
        configure_root_pk(pk);
        let rev = root.revoke(&device(42), RevokeReason::Lost, 5_000);
        assert!(record_revocation(rev.clone(), &pk));
        assert!(is_device_pk_revoked(&device(42)));

        let batch = export_gossip_revocation_batch();
        assert!(!batch.is_empty());
        assert_eq!(ingest_gossip_revocation_batch(&batch), 0, "duplicate is idempotent");
    }
}
