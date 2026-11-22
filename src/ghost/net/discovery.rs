//! Zero-Knowledge 3-Tier Peer Discovery & Blind Rendezvous Subsystem.
//!
//! Eliminates centralized directory exposure, Kademlia crawler surveillance,
//! and timing correlation attacks on public discovery relays.
//!
//! Architecture:
//! - **Tier 1 (Local Disk Cache)**: Authenticated peer descriptors cached in `peers.bin`
//!   (`VBPCACHE1` legacy v1 and `VBPCACHE2` v2). Rebooting nodes reconnect directly with
//!   zero external network footprint.
//! - **Tier 2 (Out-Of-Band Rendezvous)**: `vb://<hex>` (v1) and compact `vb://2.<base64url>`
//!   (v2) peer URIs plus `vb-net://<base64url>` network invite URIs containing signed
//!   cryptographic descriptors for direct exchange (Signal, QR code, air-gapped USB).
//! - **Tier 3 (Blind Ephemeral Rendezvous)**: Fixed-size (1024 B) ChaCha20-Poly1305 encrypted
//!   rendezvous blobs with fresh random 12-byte nonces, indexed by deterministic epoch keys
//!   (`K_epoch = HKDF(SwarmSecret, Epoch)`). Third-party hosts (Cloudflare Workers / BEP-44 DHT)
//!   see only high-entropy random bytes and zero node graphs.
//! - **Genesis Bootstrapper**: When a node has zero verified peers (`N = 0`) after an IP rotation,
//!   it enters `GenesisSeed` mode to discover initial peers; once >= 1 peer session is verified,
//!   it transitions to `MeshRelay` mode where all peer updates propagate over encrypted 1-hop mesh relays.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::ghost::layers::l0_identity::{verify_peer_signature, GhostIdentity};

/// Prefix for out-of-band Vantablack peer URIs (v1 legacy and v2 base64url).
pub const VB_URI_PREFIX: &str = "vb://";
/// Prefix for compact v2 base64url peer descriptor URIs.
pub const VB_V2_URI_PREFIX: &str = "vb://2.";
/// Prefix for compact base64url network invite URIs.
pub const VB_NET_URI_PREFIX: &str = "vb-net://";

/// NAT traversal classification byte.
pub const NAT_DIRECT: u8 = 0;
pub const NAT_CONE: u8 = 1;
pub const NAT_RESTRICTED: u8 = 2;
pub const NAT_SYMMETRIC: u8 = 3;
pub const NAT_UNKNOWN: u8 = 4;

/// Node capability bitflags carried in [`PeerDescriptorV2`].
pub const CAP_RELAY: u8 = 1 << 0;
pub const CAP_EXIT: u8 = 1 << 1;
pub const CAP_VPN_HUB: u8 = 1 << 2;
pub const CAP_QUIC: u8 = 1 << 3;
/// This node offers exit service from its own residential connection, i.e. it is
/// a *home* exit (roadmap item 3). Clients require this bit, not merely
/// [`CAP_EXIT`], before they will bind their exit path to it: a home exit is a
/// deliberate, operator-owned endpoint, and choosing one by accident would send
/// traffic through a stranger's house.
pub const CAP_HOME_EXIT: u8 = 1 << 4;

/// Fixed wire size for blind mailbox encrypted payloads (`12B nonce + 996B padded plaintext + 16B tag`).
pub const BLIND_NONCE_LEN: usize = 12;
pub const BLIND_TAG_LEN: usize = 16;
pub const BLIND_MAILBOX_WIRE_LEN: usize = 1024;
pub const BLIND_MAILBOX_PLAINTEXT_LEN: usize =
    BLIND_MAILBOX_WIRE_LEN - BLIND_NONCE_LEN - BLIND_TAG_LEN;
pub const BLIND_MAILBOX_MAX_PAYLOAD_LEN: usize = BLIND_MAILBOX_PLAINTEXT_LEN - 2;

const MAX_LAN_ENDPOINTS: usize = 32;
const MAX_CACHE_ENTRIES: usize = 4096;
const DEFAULT_BLIND_MAX_SKEW_SECS: u64 = 7200;
const EPOCH_FALLBACK_WINDOW_SECS: u64 = 300;
const CACHE_V2_MAX_AGE_SECS: u64 = 86400 * 30;

// ── Pure-Rust URL-safe Base64 (no-pad) codec ─────────────────────────

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes using unpadded URL-safe Base64 (RFC 4648 §5).
pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        out.push(B64URL_ALPHABET[b0 >> 2] as char);
        match chunk.len() {
            1 => {
                out.push(B64URL_ALPHABET[(b0 & 0x03) << 4] as char);
            }
            2 => {
                let b1 = chunk[1] as usize;
                out.push(B64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
                out.push(B64URL_ALPHABET[(b1 & 0x0f) << 2] as char);
            }
            3 => {
                let b1 = chunk[1] as usize;
                let b2 = chunk[2] as usize;
                out.push(B64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
                out.push(B64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
                out.push(B64URL_ALPHABET[b2 & 0x3f] as char);
            }
            _ => unreachable!(),
        }
    }
    out
}

#[inline]
fn decode_b64_char(c: u8, allow_standard: bool) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        b'+' if allow_standard => Some(62),
        b'/' if allow_standard => Some(63),
        _ => None,
    }
}

/// Decode unpadded URL-safe Base64 (RFC 4648 §5). Rejects malformed length and trailing non-zero bits.
pub fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    decode_b64_internal(input, false, false)
}

/// Decode either standard Base64 (with optional `=` padding) or URL-safe Base64.
fn base64_decode_flexible(input: &str) -> Option<Vec<u8>> {
    decode_b64_internal(input, true, true)
}

fn decode_b64_internal(input: &str, allow_standard: bool, allow_padding: bool) -> Option<Vec<u8>> {
    let trimmed = input.trim();
    let bytes = if allow_padding {
        trimmed.trim_end_matches('=').as_bytes()
    } else {
        if trimmed.contains('=') {
            return None;
        }
        trimmed.as_bytes()
    };

    if bytes.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let (chunks, rem) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let v0 = decode_b64_char(chunk[0], allow_standard)?;
        let v1 = decode_b64_char(chunk[1], allow_standard)?;
        let v2 = decode_b64_char(chunk[2], allow_standard)?;
        let v3 = decode_b64_char(chunk[3], allow_standard)?;
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        out.push((v2 << 6) | v3);
    }

    match rem.len() {
        0 => {}
        2 => {
            let v0 = decode_b64_char(rem[0], allow_standard)?;
            let v1 = decode_b64_char(rem[1], allow_standard)?;
            if (v1 & 0x0f) != 0 {
                return None;
            }
            out.push((v0 << 2) | (v1 >> 4));
        }
        3 => {
            let v0 = decode_b64_char(rem[0], allow_standard)?;
            let v1 = decode_b64_char(rem[1], allow_standard)?;
            let v2 = decode_b64_char(rem[2], allow_standard)?;
            if (v2 & 0x03) != 0 {
                return None;
            }
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
        }
        _ => return None,
    }

    Some(out)
}

fn encode_socket_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_socket_addr(bytes: &[u8], at: &mut usize) -> Option<SocketAddr> {
    let ip_ver = *bytes.get(*at)?;
    *at += 1;
    let ip = match ip_ver {
        4 => {
            let end = at.checked_add(4)?;
            let slice = bytes.get(*at..end)?;
            let octets: [u8; 4] = slice.try_into().ok()?;
            *at = end;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            let end = at.checked_add(16)?;
            let slice = bytes.get(*at..end)?;
            let octets: [u8; 16] = slice.try_into().ok()?;
            *at = end;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    let port_end = at.checked_add(2)?;
    let port_bytes: [u8; 2] = bytes.get(*at..port_end)?.try_into().ok()?;
    *at = port_end;
    Some(SocketAddr::new(ip, u16::from_be_bytes(port_bytes)))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ml_kem_hash16(ml_kem_pk: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(ml_kem_pk);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

// ── Legacy PeerDescriptor (v1) ───────────────────────────────────────

/// Authenticated peer descriptor (v1) for out-of-band exchange and local disk caching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub ed25519_pk: [u8; 32],
    pub ml_kem_hash: [u8; 16],
    pub endpoint: SocketAddr,
    pub nat_type: u8,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl PeerDescriptor {
    pub const MAGIC: &'static [u8; 4] = b"VBPD";

    /// Create and sign a new peer descriptor for this node.
    pub fn sign_new(
        identity: &GhostIdentity,
        ml_kem_pk: &[u8],
        endpoint: SocketAddr,
        nat_type: u8,
    ) -> Self {
        let ml_kem_hash = ml_kem_hash16(ml_kem_pk);
        let now = current_unix_secs();

        let ed25519_pk = identity.public_key_bytes();
        let signing_material =
            Self::signing_bytes(&ed25519_pk, &ml_kem_hash, endpoint, nat_type, now);
        let signature = identity.sign(&signing_material).to_bytes();

        Self {
            ed25519_pk,
            ml_kem_hash,
            endpoint,
            nat_type,
            timestamp: now,
            signature,
        }
    }

    fn signing_bytes(
        pk: &[u8; 32],
        kem_hash: &[u8; 16],
        endpoint: SocketAddr,
        nat_type: u8,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(80);
        b.extend_from_slice(Self::MAGIC);
        b.extend_from_slice(pk);
        b.extend_from_slice(kem_hash);
        encode_socket_addr(&mut b, endpoint);
        b.push(nat_type);
        b.extend_from_slice(&timestamp.to_be_bytes());
        b
    }

    /// Verify signature and timestamp of this descriptor.
    pub fn verify(&self, max_skew_secs: u64) -> bool {
        let now = current_unix_secs();

        if self.timestamp > now.saturating_add(max_skew_secs) {
            return false;
        }
        if now > self.timestamp && (now - self.timestamp) > max_skew_secs {
            return false;
        }

        let material = Self::signing_bytes(
            &self.ed25519_pk,
            &self.ml_kem_hash,
            self.endpoint,
            self.nat_type,
            self.timestamp,
        );
        verify_peer_signature(&self.ed25519_pk, &material, &self.signature)
    }

    /// Binary serialization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(140);
        b.extend_from_slice(Self::MAGIC);
        b.extend_from_slice(&self.ed25519_pk);
        b.extend_from_slice(&self.ml_kem_hash);
        encode_socket_addr(&mut b, self.endpoint);
        b.push(self.nat_type);
        b.extend_from_slice(&self.timestamp.to_be_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    /// Binary deserialization.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 32 + 16 + 1 + 4 + 2 + 1 + 8 + 64 || &bytes[..4] != Self::MAGIC {
            return None;
        }
        let mut at = 4;
        let mut ed25519_pk = [0u8; 32];
        ed25519_pk.copy_from_slice(bytes.get(at..at + 32)?);
        at += 32;

        let mut ml_kem_hash = [0u8; 16];
        ml_kem_hash.copy_from_slice(bytes.get(at..at + 16)?);
        at += 16;

        let endpoint = decode_socket_addr(bytes, &mut at)?;
        let nat_type = *bytes.get(at)?;
        at += 1;
        let timestamp = u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?);
        at += 8;
        let signature: [u8; 64] = bytes.get(at..at + 64)?.try_into().ok()?;

        Some(Self {
            ed25519_pk,
            ml_kem_hash,
            endpoint,
            nat_type,
            timestamp,
            signature,
        })
    }

    /// Encode into a legacy `vb://<hex>` URI for out-of-band manual exchange.
    pub fn to_uri(&self) -> String {
        format!("{}{}", VB_URI_PREFIX, hex::encode(self.to_bytes()))
    }

    /// Parse a legacy `vb://<hex>` URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let trimmed = uri.trim();
        let payload = trimmed.strip_prefix(VB_URI_PREFIX)?;
        if payload.starts_with("2.") {
            return None;
        }
        let bytes = hex::decode(payload).ok()?;
        Self::from_bytes(&bytes)
    }
}

// ── Unified Signed PeerDescriptorV2 ──────────────────────────────────

/// Unified signed v2 peer descriptor carrying PQ identity commitment, LAN + WAN endpoints,
/// capabilities, optional ICE offer, and Ed25519 signature over all preceding fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptorV2 {
    pub ed25519_pk: [u8; 32],
    pub pq_commitment: [u8; 32],
    pub ml_kem_hash: [u8; 16],
    pub endpoint: SocketAddr,
    pub lan_endpoints: Vec<SocketAddr>,
    pub mesh_port: u16,
    pub nat_type: u8,
    pub capabilities: u8,
    pub ice_offer: Option<String>,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl PeerDescriptorV2 {
    pub const MAGIC: &'static [u8; 4] = b"VBP2";

    /// Create and sign a new v2 peer descriptor using the current Unix timestamp.
    pub fn sign_new(
        identity: &GhostIdentity,
        ml_kem_pk: &[u8],
        endpoint: SocketAddr,
        lan_endpoints: Vec<SocketAddr>,
        mesh_port: u16,
        nat_type: u8,
        capabilities: u8,
        ice_offer: Option<String>,
    ) -> Self {
        Self::sign_new_with_timestamp(
            identity,
            ml_kem_pk,
            endpoint,
            lan_endpoints,
            mesh_port,
            nat_type,
            capabilities,
            ice_offer,
            current_unix_secs(),
        )
    }

    /// Create and sign a new v2 peer descriptor at an explicit Unix timestamp.
    pub fn sign_new_with_timestamp(
        identity: &GhostIdentity,
        ml_kem_pk: &[u8],
        endpoint: SocketAddr,
        mut lan_endpoints: Vec<SocketAddr>,
        mesh_port: u16,
        nat_type: u8,
        capabilities: u8,
        ice_offer: Option<String>,
        timestamp: u64,
    ) -> Self {
        lan_endpoints.truncate(MAX_LAN_ENDPOINTS);
        let ed25519_pk = identity.public_key_bytes();
        let pq_commitment = identity.pq_commitment();
        let ml_kem_hash = ml_kem_hash16(ml_kem_pk);

        let signing_material = Self::signing_bytes(
            &ed25519_pk,
            &pq_commitment,
            &ml_kem_hash,
            endpoint,
            &lan_endpoints,
            mesh_port,
            nat_type,
            capabilities,
            ice_offer.as_deref(),
            timestamp,
        );
        let signature = identity.sign(&signing_material).to_bytes();

        Self {
            ed25519_pk,
            pq_commitment,
            ml_kem_hash,
            endpoint,
            lan_endpoints,
            mesh_port,
            nat_type,
            capabilities,
            ice_offer,
            timestamp,
            signature,
        }
    }

    /// 16-char hex node fingerprint (first 8 bytes of Ed25519 public key).
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.ed25519_pk[..8])
    }

    fn signing_bytes(
        ed25519_pk: &[u8; 32],
        pq_commitment: &[u8; 32],
        ml_kem_hash: &[u8; 16],
        endpoint: SocketAddr,
        lan_endpoints: &[SocketAddr],
        mesh_port: u16,
        nat_type: u8,
        capabilities: u8,
        ice_offer: Option<&str>,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(128 + lan_endpoints.len() * 8);
        b.extend_from_slice(Self::MAGIC);
        b.extend_from_slice(ed25519_pk);
        b.extend_from_slice(pq_commitment);
        b.extend_from_slice(ml_kem_hash);
        encode_socket_addr(&mut b, endpoint);

        let lan_count = lan_endpoints.len().min(MAX_LAN_ENDPOINTS);
        b.push(lan_count as u8);
        for lan in lan_endpoints.iter().take(lan_count) {
            encode_socket_addr(&mut b, *lan);
        }

        b.extend_from_slice(&mesh_port.to_be_bytes());
        b.push(nat_type);
        b.push(capabilities);

        match ice_offer {
            Some(offer) => {
                let raw = offer.as_bytes();
                let capped = raw.len().min(u16::MAX as usize);
                b.push(1);
                b.extend_from_slice(&(capped as u16).to_be_bytes());
                b.extend_from_slice(&raw[..capped]);
            }
            None => b.push(0),
        }

        b.extend_from_slice(&timestamp.to_be_bytes());
        b
    }

    /// Verify Ed25519 signature over all fields and timestamp freshness within `max_skew_secs`.
    pub fn verify(&self, max_skew_secs: u64) -> bool {
        let now = current_unix_secs();
        if self.timestamp > now.saturating_add(max_skew_secs) {
            return false;
        }
        if now > self.timestamp && (now - self.timestamp) > max_skew_secs {
            return false;
        }
        if self.lan_endpoints.len() > MAX_LAN_ENDPOINTS {
            return false;
        }
        if let Some(offer) = &self.ice_offer {
            if offer.len() > u16::MAX as usize {
                return false;
            }
        }

        let material = Self::signing_bytes(
            &self.ed25519_pk,
            &self.pq_commitment,
            &self.ml_kem_hash,
            self.endpoint,
            &self.lan_endpoints,
            self.mesh_port,
            self.nat_type,
            self.capabilities,
            self.ice_offer.as_deref(),
            self.timestamp,
        );
        verify_peer_signature(&self.ed25519_pk, &material, &self.signature)
    }

    /// Canonical binary serialization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Self::signing_bytes(
            &self.ed25519_pk,
            &self.pq_commitment,
            &self.ml_kem_hash,
            self.endpoint,
            &self.lan_endpoints,
            self.mesh_port,
            self.nat_type,
            self.capabilities,
            self.ice_offer.as_deref(),
            self.timestamp,
        );
        b.extend_from_slice(&self.signature);
        b
    }

    /// Strict binary deserialization (bounds-checked, rejects trailing bytes).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 32 + 32 + 16 + 7 + 1 + 2 + 1 + 1 + 1 + 8 + 64
            || &bytes[..4] != Self::MAGIC
        {
            return None;
        }
        let mut at = 4;

        let ed25519_pk: [u8; 32] = bytes.get(at..at + 32)?.try_into().ok()?;
        at += 32;
        let pq_commitment: [u8; 32] = bytes.get(at..at + 32)?.try_into().ok()?;
        at += 32;
        let ml_kem_hash: [u8; 16] = bytes.get(at..at + 16)?.try_into().ok()?;
        at += 16;

        let endpoint = decode_socket_addr(bytes, &mut at)?;

        let lan_count = *bytes.get(at)? as usize;
        at += 1;
        if lan_count > MAX_LAN_ENDPOINTS {
            return None;
        }
        let mut lan_endpoints = Vec::with_capacity(lan_count);
        for _ in 0..lan_count {
            lan_endpoints.push(decode_socket_addr(bytes, &mut at)?);
        }

        let mesh_port = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
        at += 2;
        let nat_type = *bytes.get(at)?;
        at += 1;
        let capabilities = *bytes.get(at)?;
        at += 1;

        let has_ice = *bytes.get(at)?;
        at += 1;
        let ice_offer = match has_ice {
            0 => None,
            1 => {
                let len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
                at += 2;
                let end = at.checked_add(len)?;
                let s = std::str::from_utf8(bytes.get(at..end)?).ok()?.to_string();
                at = end;
                Some(s)
            }
            _ => return None,
        };

        let timestamp = u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?);
        at += 8;
        let signature: [u8; 64] = bytes.get(at..at + 64)?.try_into().ok()?;
        at += 64;

        if at != bytes.len() {
            return None;
        }

        Some(Self {
            ed25519_pk,
            pq_commitment,
            ml_kem_hash,
            endpoint,
            lan_endpoints,
            mesh_port,
            nat_type,
            capabilities,
            ice_offer,
            timestamp,
            signature,
        })
    }

    /// Encode into compact URL-safe Base64 URI: `vb://2.<base64url>`.
    pub fn to_uri(&self) -> String {
        format!("{}{}", VB_V2_URI_PREFIX, base64url_encode(&self.to_bytes()))
    }

    /// Decode from compact URL-safe Base64 URI: `vb://2.<base64url>`.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let trimmed = uri.trim();
        let payload = trimmed.strip_prefix(VB_V2_URI_PREFIX)?;
        let bytes = base64url_decode(payload)?;
        Self::from_bytes(&bytes)
    }
}

/// Parsed out-of-band `vb://` peer URI (either legacy v1 or unified v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedPeerUri {
    V1(PeerDescriptor),
    V2(PeerDescriptorV2),
}

/// Parse either `vb://2.<base64url>` or legacy `vb://<hex>`.
pub fn parse_peer_uri(uri: &str) -> Option<ParsedPeerUri> {
    let trimmed = uri.trim();
    if trimmed.starts_with(VB_V2_URI_PREFIX) {
        PeerDescriptorV2::from_uri(trimmed).map(ParsedPeerUri::V2)
    } else if trimmed.starts_with(VB_URI_PREFIX) {
        PeerDescriptor::from_uri(trimmed).map(ParsedPeerUri::V1)
    } else {
        None
    }
}

// ── NetworkInvite (`vb-net://<base64url>`) ────────────────────────────

/// Out-of-band private mesh invite sharing swarm secret, blind rendezvous URL,
/// and an optional signed bootstrap [`PeerDescriptorV2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInvite {
    pub network_name: String,
    pub swarm_secret: [u8; 32],
    pub rendezvous_url: Option<String>,
    pub bootstrap_peer: Option<PeerDescriptorV2>,
}

impl NetworkInvite {
    pub const MAGIC: &'static [u8; 4] = b"VBN1";

    /// Binary serialization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(96);
        b.extend_from_slice(Self::MAGIC);

        let name_bytes = self.network_name.as_bytes();
        let name_len = name_bytes.len().min(u16::MAX as usize);
        b.extend_from_slice(&(name_len as u16).to_be_bytes());
        b.extend_from_slice(&name_bytes[..name_len]);

        b.extend_from_slice(&self.swarm_secret);

        match &self.rendezvous_url {
            Some(url) => {
                let raw = url.as_bytes();
                let len = raw.len().min(u16::MAX as usize);
                b.push(1);
                b.extend_from_slice(&(len as u16).to_be_bytes());
                b.extend_from_slice(&raw[..len]);
            }
            None => b.push(0),
        }

        match &self.bootstrap_peer {
            Some(peer) => {
                let raw = peer.to_bytes();
                let len = raw.len().min(u16::MAX as usize);
                b.push(1);
                b.extend_from_slice(&(len as u16).to_be_bytes());
                b.extend_from_slice(&raw[..len]);
            }
            None => b.push(0),
        }

        b
    }

    /// Strict binary deserialization (rejects trailing bytes and invalid UTF-8).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 2 + 32 + 1 + 1 || &bytes[..4] != Self::MAGIC {
            return None;
        }
        let mut at = 4;

        let name_len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
        at += 2;
        let name_end = at.checked_add(name_len)?;
        let network_name = std::str::from_utf8(bytes.get(at..name_end)?)
            .ok()?
            .to_string();
        at = name_end;

        let swarm_secret: [u8; 32] = bytes.get(at..at + 32)?.try_into().ok()?;
        at += 32;

        let has_url = *bytes.get(at)?;
        at += 1;
        let rendezvous_url = match has_url {
            0 => None,
            1 => {
                let len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
                at += 2;
                let end = at.checked_add(len)?;
                let url = std::str::from_utf8(bytes.get(at..end)?).ok()?.to_string();
                at = end;
                Some(url)
            }
            _ => return None,
        };

        let has_peer = *bytes.get(at)?;
        at += 1;
        let bootstrap_peer = match has_peer {
            0 => None,
            1 => {
                let len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
                at += 2;
                let end = at.checked_add(len)?;
                let peer = PeerDescriptorV2::from_bytes(bytes.get(at..end)?)?;
                at = end;
                Some(peer)
            }
            _ => return None,
        };

        if at != bytes.len() {
            return None;
        }

        Some(Self {
            network_name,
            swarm_secret,
            rendezvous_url,
            bootstrap_peer,
        })
    }

    /// Verify the embedded bootstrap peer signature and timestamp (returns `true` if none present).
    pub fn verify_bootstrap(&self, max_skew_secs: u64) -> bool {
        match &self.bootstrap_peer {
            Some(peer) => peer.verify(max_skew_secs),
            None => true,
        }
    }

    /// Encode into `vb-net://<base64url>` URI.
    pub fn to_uri(&self) -> String {
        format!(
            "{}{}",
            VB_NET_URI_PREFIX,
            base64url_encode(&self.to_bytes())
        )
    }

    /// Decode from `vb-net://<base64url>` URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let trimmed = uri.trim();
        let payload = trimmed.strip_prefix(VB_NET_URI_PREFIX)?;
        let bytes = base64url_decode(payload)?;
        Self::from_bytes(&bytes)
    }
}

// ── Tier 1: Local Disk Cache ─────────────────────────────────────────

/// Tier 1: Local authenticated peer disk cache (`peers.bin`).
pub struct LocalPeerCache;

impl LocalPeerCache {
    /// Save active v1 peer descriptors to local disk cache.
    pub fn save<P: AsRef<Path>>(path: P, peers: &[PeerDescriptor]) -> std::io::Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"VBPCACHE1");
        buf.extend_from_slice(&(peers.len() as u32).to_be_bytes());
        for p in peers {
            let bytes = p.to_bytes();
            buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(&bytes);
        }
        std::fs::write(path, buf)
    }

    /// Load cached v1 peer descriptors from local disk.
    pub fn load<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<PeerDescriptor>> {
        let raw = std::fs::read(path)?;
        if raw.len() < 13 || &raw[..9] != b"VBPCACHE1" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid peer cache header",
            ));
        }
        let count_slice: [u8; 4] = raw[9..13]
            .try_into()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let count = u32::from_be_bytes(count_slice) as usize;
        let mut at = 13;
        let mut peers = Vec::with_capacity(count.min(MAX_CACHE_ENTRIES));

        for _ in 0..count {
            if at + 2 > raw.len() {
                break;
            }
            let len_slice: [u8; 2] = raw[at..at + 2]
                .try_into()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let len = u16::from_be_bytes(len_slice) as usize;
            at += 2;
            if at + len > raw.len() {
                break;
            }
            if let Some(desc) = PeerDescriptor::from_bytes(&raw[at..at + len]) {
                if desc.verify(CACHE_V2_MAX_AGE_SECS) {
                    peers.push(desc);
                }
            }
            at += len;
        }

        Ok(peers)
    }

    /// Save active v2 peer descriptors to local disk cache (`VBPCACHE2`).
    pub fn save_v2<P: AsRef<Path>>(path: P, peers: &[PeerDescriptorV2]) -> std::io::Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"VBPCACHE2");
        let count = peers.len().min(MAX_CACHE_ENTRIES);
        buf.extend_from_slice(&(count as u32).to_be_bytes());
        for p in peers.iter().take(count) {
            let bytes = p.to_bytes();
            let len = u16::try_from(bytes.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "descriptor exceeds 64 KiB",
                )
            })?;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&bytes);
        }
        std::fs::write(path, buf)
    }

    /// Load cached v2 peer descriptors from local disk (`VBPCACHE2`),
    /// pruning entries older than 30 days or failing signature verification.
    pub fn load_v2<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<PeerDescriptorV2>> {
        Self::load_v2_with_max_age(path, CACHE_V2_MAX_AGE_SECS)
    }

    /// Load cached v2 peer descriptors from local disk (`VBPCACHE2`) with an explicit max age,
    /// pruning expired or invalid-signature entries on load.
    pub fn load_v2_with_max_age<P: AsRef<Path>>(
        path: P,
        max_age_secs: u64,
    ) -> std::io::Result<Vec<PeerDescriptorV2>> {
        let raw = std::fs::read(path)?;
        if raw.len() < 13 || &raw[..9] != b"VBPCACHE2" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid v2 peer cache header",
            ));
        }
        let count_slice: [u8; 4] = raw[9..13]
            .try_into()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let count = (u32::from_be_bytes(count_slice) as usize).min(MAX_CACHE_ENTRIES);
        let mut at = 13;
        let mut peers = Vec::with_capacity(count);

        for _ in 0..count {
            if at + 2 > raw.len() {
                break;
            }
            let len_slice: [u8; 2] = raw[at..at + 2]
                .try_into()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let len = u16::from_be_bytes(len_slice) as usize;
            at += 2;
            if at + len > raw.len() {
                break;
            }
            if let Some(desc) = PeerDescriptorV2::from_bytes(&raw[at..at + len]) {
                if desc.verify(max_age_secs) {
                    peers.push(desc);
                }
            }
            at += len;
        }

        Ok(peers)
    }
}

// ── Tier 3: Blind Ephemeral Rendezvous ───────────────────────────────

/// Tier 3: Zero-knowledge blind rendezvous engine on Cloudflare Workers / BEP-44 DHT.
pub struct BlindRendezvous;

impl BlindRendezvous {
    /// Compute deterministic epoch slot key for a shared swarm secret and hourly time epoch.
    pub fn derive_epoch_key(swarm_secret: &[u8], epoch_hour: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"vb-rendezvous-v1"), swarm_secret);
        let mut okm = [0u8; 32];
        hk.expand(&epoch_hour.to_be_bytes(), &mut okm)
            .expect("32 bytes is valid length for HKDF-SHA256");
        okm
    }

    /// Compute deterministic blind slot ID for querying the public worker or DHT.
    pub fn derive_slot_id(epoch_key: &[u8; 32], slot_index: u32) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"vb-slot-v1"), epoch_key);
        let mut slot_id = [0u8; 32];
        hk.expand(&slot_index.to_be_bytes(), &mut slot_id)
            .expect("32 bytes is valid length");
        slot_id
    }

    /// Pad an arbitrary payload (`<= 994 B`) with random chaff to 996 B plaintext and encrypt
    /// with a fresh random 12-byte nonce, yielding a fixed 1024-byte wire payload:
    /// `[nonce: 12B][ciphertext(u16 len || payload || random chaff): 996B][tag: 16B]`.
    pub fn encrypt_blob(epoch_key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        if payload.len() > BLIND_MAILBOX_MAX_PAYLOAD_LEN {
            return Err("payload exceeds 994-byte max for 1024B blind mailbox blob");
        }
        let mut plaintext = vec![0u8; BLIND_MAILBOX_PLAINTEXT_LEN];
        plaintext[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        plaintext[2..2 + payload.len()].copy_from_slice(payload);
        OsRng.fill_bytes(&mut plaintext[2 + payload.len()..]);

        let mut nonce_bytes = [0u8; BLIND_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| "ChaCha20Poly1305 blind blob encryption failed")?;

        let mut out = Vec::with_capacity(BLIND_NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a `[nonce: 12B][ciphertext + 16B tag]` blind mailbox blob and strip random chaff padding.
    pub fn decrypt_blob(epoch_key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < BLIND_NONCE_LEN + BLIND_TAG_LEN {
            return None;
        }
        let (nonce_bytes, ct) = ciphertext.split_at(BLIND_NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
        let plain = cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).ok()?;
        if plain.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        if 2 + len > plain.len() {
            return None;
        }
        Some(plain[2..2 + len].to_vec())
    }

    /// Encrypt a legacy v1 peer descriptor with a fresh random 12-byte nonce prepended to ciphertext.
    pub fn encrypt_descriptor(
        epoch_key: &[u8; 32],
        descriptor: &PeerDescriptor,
    ) -> Result<Vec<u8>, &'static str> {
        let mut nonce_bytes = [0u8; BLIND_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
        let plain = descriptor.to_bytes();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plain.as_ref())
            .map_err(|_| "ChaCha20Poly1305 blind encryption failed")?;

        let mut out = Vec::with_capacity(BLIND_NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a v1 blind rendezvous payload (`[nonce: 12B][ciphertext + 16B tag]`).
    pub fn decrypt_descriptor(epoch_key: &[u8; 32], ciphertext: &[u8]) -> Option<PeerDescriptor> {
        if ciphertext.len() < BLIND_NONCE_LEN + BLIND_TAG_LEN {
            return None;
        }
        let (nonce_bytes, ct) = ciphertext.split_at(BLIND_NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
        let plain = cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).ok()?;
        let desc = PeerDescriptor::from_bytes(&plain)?;
        if desc.verify(DEFAULT_BLIND_MAX_SKEW_SECS) {
            Some(desc)
        } else {
            None
        }
    }

    /// Encrypt and chaff-pad a [`PeerDescriptorV2`] into a fixed 1024-byte blind mailbox payload.
    pub fn encrypt_descriptor_v2(
        epoch_key: &[u8; 32],
        descriptor: &PeerDescriptorV2,
    ) -> Result<Vec<u8>, &'static str> {
        Self::encrypt_blob(epoch_key, &descriptor.to_bytes())
    }

    /// Decrypt, unpad, parse, and verify a [`PeerDescriptorV2`] from a blind mailbox payload.
    pub fn decrypt_descriptor_v2(
        epoch_key: &[u8; 32],
        ciphertext: &[u8],
    ) -> Option<PeerDescriptorV2> {
        let plain = Self::decrypt_blob(epoch_key, ciphertext)?;
        let desc = PeerDescriptorV2::from_bytes(&plain)?;
        if desc.verify(DEFAULT_BLIND_MAX_SKEW_SECS) {
            Some(desc)
        } else {
            None
        }
    }
}

// ── Blind Mailbox HTTP Client (B2) ───────────────────────────────────

/// Zero-knowledge HTTP client for blind mailbox rendezvous workers.
///
/// Only transmits opaque 1024-byte AEAD ciphertexts under deterministic slot hashes
/// (`PUT /v2/slot/<slot_hex>/<ephemeral_id>`, `GET /v2/slot/<slot_hex>`) with zero plaintext IP,
/// fingerprint, or port query parameters.
#[derive(Clone, Debug)]
pub struct BlindMailboxClient {
    client: reqwest::Client,
    slot_index: u32,
    max_skew_secs: u64,
}

impl Default for BlindMailboxClient {
    fn default() -> Self {
        Self::new().expect("default reqwest client builds cleanly")
    }
}

impl BlindMailboxClient {
    /// Construct a new blind mailbox HTTP client with a 10-second request timeout.
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            slot_index: 0,
            max_skew_secs: DEFAULT_BLIND_MAX_SKEW_SECS,
        })
    }

    /// Construct a client with explicit slot index and descriptor skew tolerance.
    pub fn with_options(slot_index: u32, max_skew_secs: u64) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            slot_index,
            max_skew_secs,
        })
    }

    /// Derive `(slot_hex, epoch_key)` for a given swarm secret, epoch hour, and slot index.
    pub fn slot_hex_for_epoch(
        swarm_secret: &[u8],
        epoch_hour: u64,
        slot_index: u32,
    ) -> (String, [u8; 32]) {
        let epoch_key = BlindRendezvous::derive_epoch_key(swarm_secret, epoch_hour);
        let slot_id = BlindRendezvous::derive_slot_id(&epoch_key, slot_index);
        (hex::encode(slot_id), epoch_key)
    }

    /// Encrypt and publish a [`PeerDescriptorV2`] to the current hourly blind mailbox slot.
    pub async fn publish_descriptor(
        &self,
        base_url: &str,
        swarm_secret: &[u8],
        descriptor: &PeerDescriptorV2,
    ) -> Result<(), String> {
        let epoch_hour = current_unix_secs() / 3600;
        self.publish_descriptor_at_epoch(base_url, swarm_secret, epoch_hour, descriptor)
            .await
    }

    /// Generate a random 16-byte (32-hex-char) ephemeral subkey identifier.
    pub fn generate_ephemeral_id() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Compute a 16-bit proof-of-work nonce (`X-VB-PoW` header) bound to
    /// `(slot_hex, ephemeral_id, body)`.
    pub fn compute_pow_nonce(slot_hex: &str, ephemeral_id: &str, body: &[u8]) -> String {
        let prefix = format!(
            "{}:{}:",
            slot_hex.to_ascii_lowercase(),
            ephemeral_id.to_ascii_lowercase()
        );
        let mut nonce: u64 = 0;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(nonce.to_be_bytes());
            hasher.update(body);
            let digest = hasher.finalize();
            if digest[0] == 0 && digest[1] == 0 {
                return hex::encode(nonce.to_be_bytes());
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    /// Verify a 16-bit proof-of-work nonce (`X-VB-PoW` header) against
    /// `(slot_hex, ephemeral_id, body)`.
    pub fn verify_pow_nonce(
        slot_hex: &str,
        ephemeral_id: &str,
        nonce_hex: &str,
        body: &[u8],
    ) -> bool {
        let Ok(nonce_bytes) = hex::decode(nonce_hex) else {
            return false;
        };
        if nonce_bytes.len() != 8 {
            return false;
        }
        let prefix = format!(
            "{}:{}:",
            slot_hex.to_ascii_lowercase(),
            ephemeral_id.to_ascii_lowercase()
        );
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(&nonce_bytes);
        hasher.update(body);
        let digest = hasher.finalize();
        digest[0] == 0 && digest[1] == 0
    }

    /// Encrypt and publish a [`PeerDescriptorV2`] to an explicit `epoch_hour` slot.
    pub async fn publish_descriptor_at_epoch(
        &self,
        base_url: &str,
        swarm_secret: &[u8],
        epoch_hour: u64,
        descriptor: &PeerDescriptorV2,
    ) -> Result<(), String> {
        let (slot_hex, epoch_key) =
            Self::slot_hex_for_epoch(swarm_secret, epoch_hour, self.slot_index);
        let blob = BlindRendezvous::encrypt_descriptor_v2(&epoch_key, descriptor)
            .map_err(|e| e.to_string())?;
        let ephemeral_id = Self::generate_ephemeral_id();
        let pow_nonce = Self::compute_pow_nonce(&slot_hex, &ephemeral_id, &blob);
        let url = format!(
            "{}/v2/slot/{}/{}",
            base_url.trim_end_matches('/'),
            slot_hex,
            ephemeral_id
        );

        let resp = self
            .client
            .put(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-VB-PoW", pow_nonce)
            .body(blob)
            .send()
            .await
            .map_err(|e| format!("blind mailbox PUT failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("blind mailbox PUT returned HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// Fetch, decrypt, and verify valid [`PeerDescriptorV2`] descriptors from the blind mailbox.
    ///
    /// Queries `epoch_hour` and falls back to `epoch_hour - 1` during the first 5 minutes
    /// of an hour (or whenever the current epoch slot yields no valid swarm descriptors).
    /// Garbage blobs or blobs encrypted for other swarms are silently skipped.
    pub async fn fetch_descriptors(
        &self,
        base_url: &str,
        swarm_secret: &[u8],
    ) -> Result<Vec<PeerDescriptorV2>, String> {
        let now_secs = current_unix_secs();
        let epoch_hour = now_secs / 3600;
        let in_rollover_window = (now_secs % 3600) < EPOCH_FALLBACK_WINDOW_SECS;

        let mut merged: HashMap<[u8; 32], PeerDescriptorV2> = HashMap::new();
        let mut last_err: Option<String> = None;

        match self
            .fetch_descriptors_at_epoch(base_url, swarm_secret, epoch_hour)
            .await
        {
            Ok(peers) => {
                for p in peers {
                    Self::upsert_newest(&mut merged, p);
                }
            }
            Err(e) => last_err = Some(e),
        }

        if (in_rollover_window || merged.is_empty()) && epoch_hour > 0 {
            match self
                .fetch_descriptors_at_epoch(base_url, swarm_secret, epoch_hour - 1)
                .await
            {
                Ok(peers) => {
                    for p in peers {
                        Self::upsert_newest(&mut merged, p);
                    }
                    last_err = None;
                }
                Err(e) => {
                    if last_err.is_none() && merged.is_empty() {
                        last_err = Some(e);
                    }
                }
            }
        }

        if merged.is_empty() {
            if let Some(err) = last_err {
                return Err(err);
            }
        }

        Ok(merged.into_values().collect())
    }

    /// Fetch, decrypt, and signature-verify descriptors from an explicit `epoch_hour` slot.
    pub async fn fetch_descriptors_at_epoch(
        &self,
        base_url: &str,
        swarm_secret: &[u8],
        epoch_hour: u64,
    ) -> Result<Vec<PeerDescriptorV2>, String> {
        let (slot_hex, epoch_key) =
            Self::slot_hex_for_epoch(swarm_secret, epoch_hour, self.slot_index);
        let url = format!("{}/v2/slot/{}", base_url.trim_end_matches('/'), slot_hex);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("blind mailbox GET failed: {e}"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            return Err(format!("blind mailbox GET returned HTTP {}", resp.status()));
        }

        let encoded_blobs: Vec<String> = resp
            .json()
            .await
            .map_err(|e| format!("blind mailbox JSON parse error: {e}"))?;

        let mut merged: HashMap<[u8; 32], PeerDescriptorV2> = HashMap::new();
        for b64 in encoded_blobs {
            let Some(raw) = base64_decode_flexible(&b64) else {
                continue;
            };
            let Some(plain) = BlindRendezvous::decrypt_blob(&epoch_key, &raw) else {
                continue;
            };
            let Some(desc) = PeerDescriptorV2::from_bytes(&plain) else {
                continue;
            };
            if desc.verify(self.max_skew_secs) {
                Self::upsert_newest(&mut merged, desc);
            }
        }

        Ok(merged.into_values().collect())
    }

    fn upsert_newest(map: &mut HashMap<[u8; 32], PeerDescriptorV2>, desc: PeerDescriptorV2) {
        match map.get_mut(&desc.ed25519_pk) {
            Some(existing) if existing.timestamp >= desc.timestamp => {}
            Some(existing) => *existing = desc,
            None => {
                map.insert(desc.ed25519_pk, desc);
            }
        }
    }
}

// ── Oblivious Multi-Substrate Rendezvous (OMR) ────────────────────────

/// Hardcoded public genesis swarm secret; rejected by default unless explicitly opted in.
pub const PUBLIC_GENESIS_SWARM_SECRET: &[u8] = b"vantablack-genesis-v1";

/// Policy check: reject the hardcoded `"vantablack-genesis-v1"` fallback unless
/// `allow_public_swarm` is explicitly enabled.
pub fn validate_swarm_secret_policy(
    swarm_secret: &[u8],
    allow_public_swarm: bool,
) -> Result<(), &'static str> {
    if swarm_secret.is_empty() {
        return Err("swarm secret must not be empty");
    }
    if swarm_secret == PUBLIC_GENESIS_SWARM_SECRET && !allow_public_swarm {
        return Err(
            "hardcoded 'vantablack-genesis-v1' fallback rejected unless public-swarm mode is explicitly enabled",
        );
    }
    Ok(())
}

/// Configuration for 2-of-3 Oblivious Multi-Substrate Rendezvous (OMR).
#[derive(Clone, Debug)]
pub struct OmrSplitConfig {
    pub epoch_duration_secs: u64,
    pub max_skew_secs: u64,
    pub slot_index: u32,
    pub allow_public_genesis_fallback: bool,
}

impl Default for OmrSplitConfig {
    fn default() -> Self {
        Self {
            epoch_duration_secs: 3600,
            max_skew_secs: DEFAULT_BLIND_MAX_SKEW_SECS,
            slot_index: 0,
            allow_public_genesis_fallback: false,
        }
    }
}

/// Opaque per-substrate share envelope: 1 Shamir 2-of-3 key share + 1024B AEAD-encrypted descriptor.
///
/// A single substrate learns neither the descriptor nor the full social graph, because
/// `key_share` is a single (2,3) Shamir share revealing zero information about the AEAD key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OmrShareEnvelope {
    pub share_index: u8,
    pub key_share: Vec<u8>,
    pub encrypted_blob: Vec<u8>,
}

/// Pluggable transport substrate for OMR share publishing and fetching.
pub trait OmrSubstrate: Send + Sync {
    fn name(&self) -> &'static str;

    fn publish_share<'a>(
        &'a self,
        slot_hex: &'a str,
        envelope: &'a OmrShareEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

    fn fetch_shares<'a>(
        &'a self,
        slot_hex: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<OmrShareEnvelope>, String>> + Send + 'a>,
    >;
}

/// Hardened `/v2/slot/` Worker substrate backed by [`BlindMailboxClient`].
#[derive(Clone, Debug)]
pub struct WorkerSlotSubstrate {
    pub base_url: String,
    pub client: BlindMailboxClient,
}

impl WorkerSlotSubstrate {
    pub fn new(base_url: impl Into<String>, client: BlindMailboxClient) -> Self {
        Self {
            base_url: base_url.into(),
            client,
        }
    }
}

impl OmrSubstrate for WorkerSlotSubstrate {
    fn name(&self) -> &'static str {
        "worker-v2-slot"
    }

    fn publish_share<'a>(
        &'a self,
        slot_hex: &'a str,
        envelope: &'a OmrShareEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let body =
                serde_json::to_vec(envelope).map_err(|e| format!("worker serialize error: {e}"))?;
            let eph_id = BlindMailboxClient::generate_ephemeral_id();
            let pow = BlindMailboxClient::compute_pow_nonce(slot_hex, &eph_id, &body);
            let url = format!(
                "{}/v2/slot/{}/{}",
                self.base_url.trim_end_matches('/'),
                slot_hex,
                eph_id
            );
            let resp = self
                .client
                .client
                .put(&url)
                .header("X-VB-PoW", pow)
                .body(body)
                .send()
                .await
                .map_err(|e| format!("worker PUT failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("worker PUT returned HTTP {}", resp.status()));
            }
            Ok(())
        })
    }

    fn fetch_shares<'a>(
        &'a self,
        slot_hex: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<OmrShareEnvelope>, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let url = format!(
                "{}/v2/slot/{}",
                self.base_url.trim_end_matches('/'),
                slot_hex
            );
            let resp = self
                .client
                .client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("worker GET failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("worker GET returned HTTP {}", resp.status()));
            }
            let items: Vec<String> = resp
                .json()
                .await
                .map_err(|e| format!("worker JSON decode failed: {e}"))?;
            let mut out = Vec::new();
            for item in items {
                if let Some(raw) = base64_decode_flexible(&item) {
                    if let Ok(env) = serde_json::from_slice::<OmrShareEnvelope>(&raw) {
                        out.push(env);
                    }
                }
            }
            Ok(out)
        })
    }
}

/// Cleaned NIP-01 ephemeral Nostr event (`kind = 20000`) for opaque OMR share transport.
/// Uses `["d", slot_hex]` tags with zero plaintext `["fp", ...]` or `"vantablack_mesh"` tags.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OmrNostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl OmrNostrEvent {
    pub fn from_opaque_share(
        slot_hex: &str,
        share_bytes: &[u8],
        nostr_pubkey: String,
        created_at: u64,
        sig: String,
    ) -> Self {
        let content = hex::encode(share_bytes);
        let mut hasher = Sha256::new();
        hasher.update(created_at.to_be_bytes());
        hasher.update(slot_hex.as_bytes());
        hasher.update(content.as_bytes());
        let event_id = hex::encode(hasher.finalize());
        Self {
            id: event_id,
            pubkey: nostr_pubkey,
            created_at,
            kind: 20000,
            tags: vec![vec!["d".into(), slot_hex.to_string()]],
            content,
            sig,
        }
    }

    pub fn slot_hex(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "d")
            .map(|t| t[1].as_str())
    }

    pub fn extract_opaque_share(&self) -> Option<Vec<u8>> {
        hex::decode(&self.content).ok()
    }
}

/// Transport trait for cleaned Nostr ephemeral `["d", slot_hex]` events.
pub trait NostrRelayTransport: Send + Sync {
    fn publish_event<'a>(
        &'a self,
        event: OmrNostrEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

    fn query_slot<'a>(
        &'a self,
        slot_hex: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<OmrNostrEvent>, String>> + Send + 'a>,
    >;
}

/// Cleaned Nostr ephemeral event substrate using `["d", slot_hex]` tags.
pub struct NostrSlotSubstrate<T: NostrRelayTransport> {
    pub transport: T,
    pub nostr_pubkey: String,
}

impl<T: NostrRelayTransport> NostrSlotSubstrate<T> {
    pub fn new(transport: T, nostr_pubkey: impl Into<String>) -> Self {
        Self {
            transport,
            nostr_pubkey: nostr_pubkey.into(),
        }
    }
}

impl<T: NostrRelayTransport> OmrSubstrate for NostrSlotSubstrate<T> {
    fn name(&self) -> &'static str {
        "nostr-ephemeral-d-slot"
    }

    fn publish_share<'a>(
        &'a self,
        slot_hex: &'a str,
        envelope: &'a OmrShareEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let payload =
                serde_json::to_vec(envelope).map_err(|e| format!("nostr serialize error: {e}"))?;
            let event = OmrNostrEvent::from_opaque_share(
                slot_hex,
                &payload,
                self.nostr_pubkey.clone(),
                current_unix_secs(),
                String::new(),
            );
            self.transport.publish_event(event).await
        })
    }

    fn fetch_shares<'a>(
        &'a self,
        slot_hex: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<OmrShareEnvelope>, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let events = self.transport.query_slot(slot_hex).await?;
            let mut out = Vec::new();
            for ev in events {
                if let Some(raw) = ev.extract_opaque_share() {
                    if let Ok(env) = serde_json::from_slice::<OmrShareEnvelope>(&raw) {
                        out.push(env);
                    }
                }
            }
            Ok(out)
        })
    }
}

/// Transport trait for DoH-TXT or DHT opaque slot storage.
pub trait DohDhtTransport: Send + Sync {
    fn put_record<'a>(
        &'a self,
        slot_hex: &'a str,
        record_bytes: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

    fn get_records<'a>(
        &'a self,
        slot_hex: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Vec<u8>>, String>> + Send + 'a>,
    >;
}

/// DoH-TXT / DHT substrate for OMR share transport.
pub struct DohDhtSubstrate<T: DohDhtTransport> {
    pub transport: T,
}

impl<T: DohDhtTransport> DohDhtSubstrate<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: DohDhtTransport> OmrSubstrate for DohDhtSubstrate<T> {
    fn name(&self) -> &'static str {
        "doh-txt-dht"
    }

    fn publish_share<'a>(
        &'a self,
        slot_hex: &'a str,
        envelope: &'a OmrShareEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let payload = serde_json::to_vec(envelope)
                .map_err(|e| format!("doh/dht serialize error: {e}"))?;
            self.transport.put_record(slot_hex, &payload).await
        })
    }

    fn fetch_shares<'a>(
        &'a self,
        slot_hex: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<OmrShareEnvelope>, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let records = self.transport.get_records(slot_hex).await?;
            let mut out = Vec::new();
            for rec in records {
                if let Ok(env) = serde_json::from_slice::<OmrShareEnvelope>(&rec) {
                    out.push(env);
                }
            }
            Ok(out)
        })
    }
}

/// Publishes a [`PeerDescriptorV2`] by encrypting it under a fresh 32-byte key and
/// splitting that key 2-of-3 via [`crate::ghost::layers::l3_shamir`] across 3 substrates.
pub struct OmrPublisher {
    pub config: OmrSplitConfig,
    pub substrates: Vec<Box<dyn OmrSubstrate>>,
}

impl OmrPublisher {
    pub fn new(config: OmrSplitConfig, substrates: Vec<Box<dyn OmrSubstrate>>) -> Self {
        Self { config, substrates }
    }

    pub async fn publish(
        &self,
        swarm_secret: &[u8],
        descriptor: &PeerDescriptorV2,
    ) -> Result<usize, String> {
        validate_swarm_secret_policy(swarm_secret, self.config.allow_public_genesis_fallback)
            .map_err(|e| e.to_string())?;

        if self.substrates.len() < 3 {
            return Err("OMR requires at least 3 independent substrates".to_string());
        }

        let epoch_hour = current_unix_secs() / self.config.epoch_duration_secs.max(1);
        let (slot_hex, _) = BlindMailboxClient::slot_hex_for_epoch(
            swarm_secret,
            epoch_hour,
            self.config.slot_index,
        );

        let mut blob_key = [0u8; 32];
        OsRng.fill_bytes(&mut blob_key);
        let encrypted_blob = BlindRendezvous::encrypt_descriptor_v2(&blob_key, descriptor)
            .map_err(|e| e.to_string())?;
        let shares = crate::ghost::layers::l3_shamir::split_secret_bytes(&blob_key);
        blob_key.fill(0);

        let mut succeeded = 0usize;
        for (idx, substrate) in self.substrates.iter().take(3).enumerate() {
            let envelope = OmrShareEnvelope {
                share_index: idx as u8,
                key_share: shares[idx].clone(),
                encrypted_blob: encrypted_blob.clone(),
            };
            if substrate.publish_share(&slot_hex, &envelope).await.is_ok() {
                succeeded += 1;
            }
        }

        if succeeded < 2 {
            return Err(format!(
                "OMR publish failed: only {succeeded}/3 substrates succeeded (need >= 2)"
            ));
        }
        Ok(succeeded)
    }
}

/// Resolves [`PeerDescriptorV2`] records by fetching shares from independent substrates
/// and reconstructing the AEAD key from any 2-of-3 Shamir shares.
pub struct OmrResolver {
    pub config: OmrSplitConfig,
    pub substrates: Vec<Box<dyn OmrSubstrate>>,
}

impl OmrResolver {
    pub fn new(config: OmrSplitConfig, substrates: Vec<Box<dyn OmrSubstrate>>) -> Self {
        Self { config, substrates }
    }

    pub async fn resolve(&self, swarm_secret: &[u8]) -> Result<Vec<PeerDescriptorV2>, String> {
        validate_swarm_secret_policy(swarm_secret, self.config.allow_public_genesis_fallback)
            .map_err(|e| e.to_string())?;

        let epoch_hour = current_unix_secs() / self.config.epoch_duration_secs.max(1);
        let (slot_hex, _) = BlindMailboxClient::slot_hex_for_epoch(
            swarm_secret,
            epoch_hour,
            self.config.slot_index,
        );

        let mut by_blob: HashMap<[u8; 32], Vec<OmrShareEnvelope>> = HashMap::new();
        for substrate in &self.substrates {
            if let Ok(envelopes) = substrate.fetch_shares(&slot_hex).await {
                for env in envelopes {
                    let blob_hash: [u8; 32] = Sha256::digest(&env.encrypted_blob).into();
                    by_blob.entry(blob_hash).or_default().push(env);
                }
            }
        }

        let mut merged: HashMap<[u8; 32], PeerDescriptorV2> = HashMap::new();
        for (_blob_hash, envs) in by_blob {
            if envs.len() < 2 {
                continue;
            }
            'pair_search: for i in 0..envs.len() {
                for j in (i + 1)..envs.len() {
                    if envs[i].share_index == envs[j].share_index {
                        continue;
                    }
                    let rec = crate::ghost::layers::l3_shamir::join_shares(
                        &envs[i].key_share,
                        &envs[j].key_share,
                    );
                    if rec.len() != 32 {
                        continue;
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&rec);
                    if let Some(plain) =
                        BlindRendezvous::decrypt_blob(&key, &envs[i].encrypted_blob)
                    {
                        if let Some(desc) = PeerDescriptorV2::from_bytes(&plain) {
                            if desc.verify(self.config.max_skew_secs) {
                                BlindMailboxClient::upsert_newest(&mut merged, desc);
                                break 'pair_search;
                            }
                        }
                    }
                }
            }
        }

        Ok(merged.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_descriptor_roundtrip_and_uri() {
        let id = GhostIdentity::generate_fresh();
        let kem_pk = [0x55u8; 1184];
        let endpoint = SocketAddr::from(([198, 51, 100, 14], 4433));
        let desc = PeerDescriptor::sign_new(&id, &kem_pk, endpoint, NAT_CONE);

        assert!(desc.verify(60));

        let uri = desc.to_uri();
        assert!(uri.starts_with(VB_URI_PREFIX));

        let parsed = PeerDescriptor::from_uri(&uri).expect("failed to parse URI");
        assert_eq!(desc, parsed);
        assert!(parsed.verify(60));
    }

    #[test]
    fn test_blind_rendezvous_encryption() {
        let id = GhostIdentity::generate_fresh();
        let kem_pk = [0x22u8; 1184];
        let endpoint = SocketAddr::from(([203, 0, 113, 8], 8080));
        let desc = PeerDescriptor::sign_new(&id, &kem_pk, endpoint, NAT_DIRECT);

        let swarm_secret = b"my-private-mesh-secret-key-12345";
        let epoch_hour = 1714658400; // Sample Unix epoch hour
        let epoch_key = BlindRendezvous::derive_epoch_key(swarm_secret, epoch_hour);
        let slot_id = BlindRendezvous::derive_slot_id(&epoch_key, 0);

        assert_ne!(slot_id, [0u8; 32]);

        let enc1 = BlindRendezvous::encrypt_descriptor(&epoch_key, &desc).expect("encrypt failed");
        let enc2 = BlindRendezvous::encrypt_descriptor(&epoch_key, &desc).expect("encrypt failed");

        // Fresh 12-byte random nonces produce distinct ciphertexts even for the identical payload & key
        assert_ne!(&enc1[..BLIND_NONCE_LEN], &enc2[..BLIND_NONCE_LEN]);
        assert_ne!(enc1, enc2);
        // Cloudflare sees only random bytes:
        assert_ne!(&enc1[..4], PeerDescriptor::MAGIC);
        assert_ne!(
            &enc1[BLIND_NONCE_LEN..BLIND_NONCE_LEN + 4],
            PeerDescriptor::MAGIC
        );

        let dec1 = BlindRendezvous::decrypt_descriptor(&epoch_key, &enc1).expect("decrypt1 failed");
        let dec2 = BlindRendezvous::decrypt_descriptor(&epoch_key, &enc2).expect("decrypt2 failed");
        assert_eq!(desc, dec1);
        assert_eq!(desc, dec2);
    }

    #[test]
    fn test_blind_blob_fixed_size_and_distinct_nonces() {
        let epoch_key = BlindRendezvous::derive_epoch_key(b"swarm-secret", 480000);
        let payload = b"secret-descriptor-payload";

        let blob1 = BlindRendezvous::encrypt_blob(&epoch_key, payload).expect("blob1");
        let blob2 = BlindRendezvous::encrypt_blob(&epoch_key, payload).expect("blob2");

        assert_eq!(blob1.len(), BLIND_MAILBOX_WIRE_LEN);
        assert_eq!(blob2.len(), BLIND_MAILBOX_WIRE_LEN);
        assert_ne!(&blob1[..BLIND_NONCE_LEN], &blob2[..BLIND_NONCE_LEN]);
        assert_ne!(blob1, blob2);

        assert_eq!(
            BlindRendezvous::decrypt_blob(&epoch_key, &blob1).as_deref(),
            Some(payload.as_slice())
        );
        assert_eq!(
            BlindRendezvous::decrypt_blob(&epoch_key, &blob2).as_deref(),
            Some(payload.as_slice())
        );

        let mut tampered = blob1.clone();
        tampered[20] ^= 0xff;
        assert!(BlindRendezvous::decrypt_blob(&epoch_key, &tampered).is_none());
    }

    #[test]
    fn test_base64url_roundtrip_and_validation() {
        for len in 0..=32 {
            let input: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = base64url_encode(&input);
            assert!(!encoded.contains('='));
            assert!(!encoded.contains('+'));
            assert!(!encoded.contains('/'));
            assert_eq!(base64url_decode(&encoded), Some(input));
        }
        assert!(base64url_decode("abc=").is_none());
        assert!(base64url_decode("a").is_none());
        assert!(base64url_decode("ab+d").is_none());
    }

    #[test]
    fn test_peer_descriptor_v2_and_network_invite() {
        let id = GhostIdentity::generate_fresh();
        let kem_pk = [0x33u8; 1184];
        let endpoint = SocketAddr::from(([198, 51, 100, 42], 55225));
        let lan = vec![
            SocketAddr::from(([192, 168, 1, 10], 55225)),
            SocketAddr::from(([10, 0, 0, 5], 55225)),
        ];
        let desc = PeerDescriptorV2::sign_new(
            &id,
            &kem_pk,
            endpoint,
            lan,
            55225,
            NAT_CONE,
            CAP_RELAY | CAP_QUIC,
            Some("ufrag:pwd@198.51.100.42:55225".to_string()),
        );
        assert!(desc.verify(60));
        assert_eq!(desc.pq_commitment, id.pq_commitment());

        let uri = desc.to_uri();
        assert!(uri.starts_with(VB_V2_URI_PREFIX));
        let parsed = PeerDescriptorV2::from_uri(&uri).expect("v2 uri parse");
        assert_eq!(desc, parsed);
        assert!(parsed.verify(60));
        assert!(PeerDescriptor::from_uri(&uri).is_none());

        // Tampering any signed field invalidates signature
        let mut bad_caps = parsed.clone();
        bad_caps.capabilities ^= CAP_EXIT;
        assert!(!bad_caps.verify(60));

        let mut bad_port = parsed.clone();
        bad_port.mesh_port = 12345;
        assert!(!bad_port.verify(60));

        let mut bad_ice = parsed.clone();
        bad_ice.ice_offer = Some("tampered".to_string());
        assert!(!bad_ice.verify(60));

        let invite = NetworkInvite {
            network_name: "my-private-mesh".to_string(),
            swarm_secret: [0x7au8; 32],
            rendezvous_url: Some("https://blind.example.workers.dev".to_string()),
            bootstrap_peer: Some(desc),
        };
        let invite_uri = invite.to_uri();
        assert!(invite_uri.starts_with(VB_NET_URI_PREFIX));
        let decoded_invite = NetworkInvite::from_uri(&invite_uri).expect("invite uri parse");
        assert_eq!(invite, decoded_invite);
        assert!(decoded_invite.verify_bootstrap(60));
    }

    #[test]
    fn test_blind_mailbox_ephemeral_id_and_pow() {
        let eph1 = BlindMailboxClient::generate_ephemeral_id();
        let eph2 = BlindMailboxClient::generate_ephemeral_id();
        assert_eq!(eph1.len(), 32);
        assert_eq!(eph2.len(), 32);
        assert_ne!(eph1, eph2);
        assert!(eph1.chars().all(|c| c.is_ascii_hexdigit()));

        let slot_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let body = vec![0x42u8; BLIND_MAILBOX_WIRE_LEN];
        let nonce_hex = BlindMailboxClient::compute_pow_nonce(slot_hex, &eph1, &body);
        assert_eq!(nonce_hex.len(), 16);
        assert!(BlindMailboxClient::verify_pow_nonce(
            slot_hex, &eph1, &nonce_hex, &body
        ));

        // Bound to slot_hex, ephemeral_id, and body.
        assert!(!BlindMailboxClient::verify_pow_nonce(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &eph1,
            &nonce_hex,
            &body
        ));
        assert!(!BlindMailboxClient::verify_pow_nonce(
            slot_hex, &eph2, &nonce_hex, &body
        ));
        let mut tampered_body = body.clone();
        tampered_body[0] ^= 0x01;
        assert!(!BlindMailboxClient::verify_pow_nonce(
            slot_hex,
            &eph1,
            &nonce_hex,
            &tampered_body
        ));
        assert!(!BlindMailboxClient::verify_pow_nonce(
            slot_hex, &eph1, "not-hex", &body
        ));
    }

    #[test]
    fn test_genesis_fallback_policy_check() {
        assert!(validate_swarm_secret_policy(b"vantablack-genesis-v1", false).is_err());
        assert!(validate_swarm_secret_policy(b"vantablack-genesis-v1", true).is_ok());
        assert!(validate_swarm_secret_policy(b"private-swarm-secret-32bytes!", false).is_ok());
        assert!(validate_swarm_secret_policy(b"", true).is_err());
    }

    #[tokio::test]
    async fn test_omr_2_of_3_split_and_reconstruct_all_pairs() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct MemNostr(Arc<Mutex<HashMap<String, Vec<OmrNostrEvent>>>>);
        impl NostrRelayTransport for MemNostr {
            fn publish_event<'a>(
                &'a self,
                event: OmrNostrEvent,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
            {
                Box::pin(async move {
                    let slot = event.slot_hex().unwrap_or_default().to_string();
                    self.0.lock().unwrap().entry(slot).or_default().push(event);
                    Ok(())
                })
            }
            fn query_slot<'a>(
                &'a self,
                slot_hex: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<Vec<OmrNostrEvent>, String>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    Ok(self
                        .0
                        .lock()
                        .unwrap()
                        .get(slot_hex)
                        .cloned()
                        .unwrap_or_default())
                })
            }
        }

        #[derive(Clone, Default)]
        struct MemDoh(Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>);
        impl DohDhtTransport for MemDoh {
            fn put_record<'a>(
                &'a self,
                slot_hex: &'a str,
                record_bytes: &'a [u8],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
            {
                Box::pin(async move {
                    self.0
                        .lock()
                        .unwrap()
                        .entry(slot_hex.to_string())
                        .or_default()
                        .push(record_bytes.to_vec());
                    Ok(())
                })
            }
            fn get_records<'a>(
                &'a self,
                slot_hex: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<Vec<u8>>, String>> + Send + 'a>,
            > {
                Box::pin(async move {
                    Ok(self
                        .0
                        .lock()
                        .unwrap()
                        .get(slot_hex)
                        .cloned()
                        .unwrap_or_default())
                })
            }
        }

        #[derive(Clone, Default)]
        struct MemWorker(Arc<Mutex<HashMap<String, Vec<OmrShareEnvelope>>>>);
        impl OmrSubstrate for MemWorker {
            fn name(&self) -> &'static str {
                "mem-worker"
            }
            fn publish_share<'a>(
                &'a self,
                slot_hex: &'a str,
                envelope: &'a OmrShareEnvelope,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
            {
                Box::pin(async move {
                    self.0
                        .lock()
                        .unwrap()
                        .entry(slot_hex.to_string())
                        .or_default()
                        .push(envelope.clone());
                    Ok(())
                })
            }
            fn fetch_shares<'a>(
                &'a self,
                slot_hex: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<Vec<OmrShareEnvelope>, String>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    Ok(self
                        .0
                        .lock()
                        .unwrap()
                        .get(slot_hex)
                        .cloned()
                        .unwrap_or_default())
                })
            }
        }

        let s_worker = MemWorker::default();
        let s_nostr = MemNostr::default();
        let s_doh = MemDoh::default();

        let id = GhostIdentity::generate_fresh();
        let desc = PeerDescriptorV2::sign_new(
            &id,
            &[0x77u8; 1184],
            SocketAddr::from(([198, 51, 100, 42], 4433)),
            vec![],
            4433,
            NAT_CONE,
            CAP_QUIC,
            None,
        );

        let publisher = OmrPublisher::new(
            OmrSplitConfig::default(),
            vec![
                Box::new(s_worker.clone()),
                Box::new(NostrSlotSubstrate::new(
                    s_nostr.clone(),
                    "nostr_pk".to_string(),
                )),
                Box::new(DohDhtSubstrate::new(s_doh.clone())),
            ],
        );

        let secret = b"private-omr-swarm-secret-0123456";
        assert_eq!(publisher.publish(secret, &desc).await.unwrap(), 3);

        // Single substrate alone cannot reconstruct.
        let r_single =
            OmrResolver::new(OmrSplitConfig::default(), vec![Box::new(s_worker.clone())]);
        assert!(r_single.resolve(secret).await.unwrap().is_empty());

        // Any 2 of 3 substrates reconstruct the exact descriptor.
        let r_01 = OmrResolver::new(
            OmrSplitConfig::default(),
            vec![
                Box::new(s_worker.clone()),
                Box::new(NostrSlotSubstrate::new(
                    s_nostr.clone(),
                    "nostr_pk".to_string(),
                )),
            ],
        );
        assert_eq!(r_01.resolve(secret).await.unwrap(), vec![desc.clone()]);

        let r_02 = OmrResolver::new(
            OmrSplitConfig::default(),
            vec![
                Box::new(s_worker),
                Box::new(DohDhtSubstrate::new(s_doh.clone())),
            ],
        );
        assert_eq!(r_02.resolve(secret).await.unwrap(), vec![desc.clone()]);

        let r_12 = OmrResolver::new(
            OmrSplitConfig::default(),
            vec![
                Box::new(NostrSlotSubstrate::new(s_nostr, "nostr_pk".to_string())),
                Box::new(DohDhtSubstrate::new(s_doh)),
            ],
        );
        assert_eq!(r_12.resolve(secret).await.unwrap(), vec![desc]);
    }
}
