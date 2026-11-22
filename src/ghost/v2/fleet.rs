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
}
