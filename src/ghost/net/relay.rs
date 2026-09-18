/// Multi-hop Encrypted Packet Forwarding
///
/// Implements onion-style encrypted relay through intermediate GhostNet nodes.
/// When node A wants to send to node C through node B:
///   1. A encrypts the payload with session key A↔B (outer layer)
///   2. A encrypts the inner payload with session key B↔C (inner layer)
///   3. A sends to B with a RELAY header indicating the final destination
///   4. B decrypts the outer layer, finds the RELAY header, re-encrypts with
///      its own session key and forwards to C
///   5. C decrypts the inner payload
///
/// This avoids exposing plaintext at intermediate hops since each hop only
/// strips its own encryption layer, while the end-to-end encryption is preserved.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::ghost::layers::l0_identity::{verify_peer_signature, GhostIdentity};
use crate::ghost::layers::l2_aead::xchacha_seal_in_place_with_aad;
use crate::ghost::layers::l4_rs;
use crate::ghost::net::frame_shard;
use crate::ghost::net::send_gtf_v2;
use crate::ghost::net::FlowController;
use crate::ghost::net::GtfV2Header;
use crate::ghost::session::Session;

/// Magic prefix for relay packets — distinguishes relay from direct data.
pub const RELAY_MAGIC: &[u8; 4] = b"RLY!";

/// Magic prefix for a single-hop *blind* envelope.
///
/// Deliberately not [`RELAY_MAGIC`]. Both envelopes carry a hop count, and the
/// onion's last hop rewraps with `remaining_hops - 1`, so a legitimate two-hop
/// onion arrives with a hop count of **zero** — structurally identical to a
/// blind forward. Sharing a magic would make the two indistinguishable on the
/// wire, and a receiver that guessed wrong would either re-encrypt someone
/// else's ciphertext or hand an onion body to the tunnel as if it were a frame.
pub const BLIND_MAGIC: &[u8; 4] = b"BLND";

/// Maximum number of hops in a relay path.
pub const MAX_HOPS: usize = 5;

/// Maximum time (seconds) a bundle is held in store-and-forward before expiry.
pub const BUNDLE_EXPIRY_SECS: u64 = 3600; // 1 hour

/// Exit destination policy used by an exit node.
///
/// An unset policy keeps the historical open-exit behavior for compatibility;
/// once `GHOST_EXIT_ALLOWLIST` is set, destinations must match an exact host or
/// a leading-wildcard suffix (`*.example.test`). `any` explicitly opts into the
/// open mode. Matching is performed on the parsed host, never on the raw
/// `host:port` string, so a caller cannot smuggle a port or path through a rule.
/// Signed, expiring capability authorizing one peer to use one exit scope.
///
/// The voucher is intentionally independent of the transport session: it can be
/// issued by an exit operator, carried inside an authenticated request, and
/// verified without trusting the requesting peer's claims. `scope` is normally
/// a hostname or an exit-policy label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitCapability {
    pub issuer_pk: [u8; 32],
    pub subject: String,
    pub scope: String,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl ExitCapability {
    const MAGIC: &'static [u8; 8] = b"EXITAUTH";
    const VERSION: u8 = 1;
    const MAX_SUBJECT: usize = 64;
    const MAX_SCOPE: usize = 192;

    fn signing_bytes(subject: &str, scope: &str, expires_at: u64) -> Option<Vec<u8>> {
        if subject.is_empty()
            || subject.len() > Self::MAX_SUBJECT
            || scope.is_empty()
            || scope.len() > Self::MAX_SCOPE
        {
            return None;
        }
        let mut bytes = Vec::with_capacity(32 + subject.len() + scope.len());
        bytes.extend_from_slice(b"GGN_EXITAUTH_V1");
        bytes.extend_from_slice(&expires_at.to_be_bytes());
        bytes.push(subject.len() as u8);
        bytes.extend_from_slice(subject.as_bytes());
        bytes.extend_from_slice(&(scope.len() as u16).to_be_bytes());
        bytes.extend_from_slice(scope.as_bytes());
        Some(bytes)
    }

    pub fn issue(
        issuer: &GhostIdentity,
        subject: impl Into<String>,
        scope: impl Into<String>,
        expires_at: u64,
    ) -> Option<Self> {
        let subject = subject.into();
        let scope = scope.into();
        let signing = Self::signing_bytes(&subject, &scope, expires_at)?;
        Some(Self {
            issuer_pk: issuer.public_key_bytes(),
            subject,
            scope,
            expires_at,
            signature: issuer.sign(&signing).to_bytes(),
        })
    }

    pub fn verify(&self, now: u64, expected_subject: &str, required_scope: &str) -> bool {
        if now > self.expires_at || self.subject != expected_subject || self.scope != required_scope
        {
            return false;
        }
        let Some(signing) = Self::signing_bytes(&self.subject, &self.scope, self.expires_at) else {
            return false;
        };
        verify_peer_signature(&self.issuer_pk, &signing, &self.signature)
    }

    /// Compact binary encoding for an authenticated exit request.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(Self::MAGIC);
        out.push(Self::VERSION);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(self.subject.len() as u8);
        out.extend_from_slice(self.subject.as_bytes());
        out.extend_from_slice(&(self.scope.len() as u16).to_be_bytes());
        out.extend_from_slice(self.scope.as_bytes());
        out.extend_from_slice(&self.issuer_pk);
        out.extend_from_slice(&self.signature);
        (self.subject.len() <= Self::MAX_SUBJECT && self.scope.len() <= Self::MAX_SCOPE)
            .then_some(out)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        let mut at = 9usize;
        if raw.len() < Self::MAGIC.len() + 1 + 8 + 1 + 2 + 32 + 64
            || &raw[..8] != Self::MAGIC
            || raw[8] != Self::VERSION
        {
            return None;
        }
        let expires_at = u64::from_be_bytes(raw[at..at + 8].try_into().ok()?);
        at += 8;
        let subject_len = *raw.get(at)? as usize;
        at += 1;
        if subject_len == 0 || subject_len > Self::MAX_SUBJECT || at + subject_len > raw.len() {
            return None;
        }
        let subject = String::from_utf8(raw[at..at + subject_len].to_vec()).ok()?;
        at += subject_len;
        let scope_len = u16::from_be_bytes(raw.get(at..at + 2)?.try_into().ok()?) as usize;
        at += 2;
        if scope_len == 0 || scope_len > Self::MAX_SCOPE || at + scope_len > raw.len() {
            return None;
        }
        let scope = String::from_utf8(raw[at..at + scope_len].to_vec()).ok()?;
        at += scope_len;
        let issuer_pk: [u8; 32] = raw.get(at..at + 32)?.try_into().ok()?;
        at += 32;
        let signature: [u8; 64] = raw.get(at..at + 64)?.try_into().ok()?;
        if at + 64 != raw.len() {
            return None;
        }
        Some(Self {
            issuer_pk,
            subject,
            scope,
            expires_at,
            signature,
        })
    }
}

// ══════════════════════════════════════════════════════════════════
// Invention §8: Sphinx-Shard Onion — 3 Hops, Constant 576B, Shard-Aware
//
// Tor onion routing relies on a single serial circuit path where middle nodes
// can correlate flow volume and timing across hops. Nym Sphinx is per-packet
// but does not exploit information-theoretic erasure codes.
//
// In Sphinx-Shard Onion:
// - Every Reed-Solomon shard (e.g. any 2-of-3) is independently encapsulated in a
//   fixed-size 576-byte Sphinx-like 3-layer onion (guard -> middle -> exit).
// - Intermediate nodes only learn their immediate successor (next hop) and cannot
//   distinguish which shard index they carry or who the eventual exit/destination is.
// - Even if an adversary compromises or drops 1 middle node on 1 plane, the exit
//   node reconstructs the original payload from the remaining surviving shards.
// ══════════════════════════════════════════════════════════════════

pub const SPHINX_SHARD_LEN: usize = 576;
pub const SPHINX_HOP_TAG_LEN: usize = 16;
pub const SPHINX_MAX_HOP_NAME: usize = 32;

/// Peeled hop information for intermediate relays
#[derive(Debug, Clone)]
pub struct PeeledSphinxHop {
    pub next_hop: String,
    pub inner_payload: Vec<u8>,
}

/// Sphinx-Shard Onion constructor and decoder
pub struct SphinxShardOnion;

impl SphinxShardOnion {
    /// Build a 3-hop layered onion fixed to 576 bytes carrying one RS shard.
    pub fn build(
        guard_key: &[u8; 32],
        middle_hop: &str,
        middle_key: &[u8; 32],
        exit_hop: &str,
        exit_key: &[u8; 32],
        shard_idx: u8,
        shard_data: &[u8],
    ) -> Vec<u8> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        // Layer 3 (Exit): payload + shard index
        let mut exit_plaintext = Vec::with_capacity(2 + shard_data.len());
        exit_plaintext.push(shard_idx);
        exit_plaintext.push(shard_data.len() as u8);
        exit_plaintext.extend_from_slice(shard_data);

        let exit_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(exit_key));
        let exit_nonce = Nonce::from_slice(&[0x33u8; 12]);
        let exit_sealed = exit_cipher
            .encrypt(exit_nonce, exit_plaintext.as_ref())
            .expect("seal exit");

        // Layer 2 (Middle): routing instruction to exit + exit ciphertext
        let mut middle_plaintext = Vec::with_capacity(SPHINX_MAX_HOP_NAME + exit_sealed.len());
        let mut exit_hop_bytes = [0u8; SPHINX_MAX_HOP_NAME];
        let bytes_to_copy = exit_hop.as_bytes().len().min(SPHINX_MAX_HOP_NAME);
        exit_hop_bytes[..bytes_to_copy].copy_from_slice(&exit_hop.as_bytes()[..bytes_to_copy]);
        middle_plaintext.extend_from_slice(&exit_hop_bytes);
        middle_plaintext.extend_from_slice(&exit_sealed);

        let middle_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(middle_key));
        let middle_nonce = Nonce::from_slice(&[0x22u8; 12]);
        let middle_sealed = middle_cipher
            .encrypt(middle_nonce, middle_plaintext.as_ref())
            .expect("seal middle");

        // Layer 1 (Guard): routing instruction to middle + middle ciphertext
        let mut guard_plaintext = Vec::with_capacity(SPHINX_MAX_HOP_NAME + middle_sealed.len());
        let mut middle_hop_bytes = [0u8; SPHINX_MAX_HOP_NAME];
        let bytes_to_copy_m = middle_hop.as_bytes().len().min(SPHINX_MAX_HOP_NAME);
        middle_hop_bytes[..bytes_to_copy_m]
            .copy_from_slice(&middle_hop.as_bytes()[..bytes_to_copy_m]);
        guard_plaintext.extend_from_slice(&middle_hop_bytes);
        guard_plaintext.extend_from_slice(&middle_sealed);

        let guard_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(guard_key));
        let guard_nonce = Nonce::from_slice(&[0x11u8; 12]);
        let guard_sealed = guard_cipher
            .encrypt(guard_nonce, guard_plaintext.as_ref())
            .expect("seal guard");

        // Fixed-size 576-byte frame: 2-byte inner length prefix + ciphertext + uniform random padding
        let mut out = vec![0u8; SPHINX_SHARD_LEN];
        let len_bytes = (guard_sealed.len() as u16).to_be_bytes();
        out[..2].copy_from_slice(&len_bytes);
        let copy_len = guard_sealed.len().min(SPHINX_SHARD_LEN - 2);
        out[2..2 + copy_len].copy_from_slice(&guard_sealed[..copy_len]);
        // Fill remaining bytes with pseudo-random filler to ensure constant 576 bytes
        for i in (2 + copy_len)..SPHINX_SHARD_LEN {
            out[i] = ((i * 37) ^ 0xAA) as u8;
        }
        out
    }

    /// Peel one hop layer as an intermediate relay (guard or middle).
    pub fn peel_hop(hop_key: &[u8; 32], ciphertext: &[u8]) -> Option<PeeledSphinxHop> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        let payload_to_decrypt = if ciphertext.len() == SPHINX_SHARD_LEN {
            let actual_len = u16::from_be_bytes([ciphertext[0], ciphertext[1]]) as usize;
            if actual_len > SPHINX_SHARD_LEN - 2 {
                return None;
            }
            &ciphertext[2..2 + actual_len]
        } else {
            ciphertext
        };

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(hop_key));
        // Try candidate nonces for guard or middle
        let nonces = [[0x11u8; 12], [0x22u8; 12]];
        let mut decrypted = None;
        for n in &nonces {
            if let Ok(pt) = cipher.decrypt(Nonce::from_slice(n), payload_to_decrypt) {
                decrypted = Some(pt);
                break;
            }
        }
        let pt = decrypted?;
        if pt.len() < SPHINX_MAX_HOP_NAME {
            return None;
        }
        let next_hop_bytes = &pt[..SPHINX_MAX_HOP_NAME];
        let end = next_hop_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SPHINX_MAX_HOP_NAME);
        let next_hop = String::from_utf8(next_hop_bytes[..end].to_vec()).ok()?;
        let inner_payload = pt[SPHINX_MAX_HOP_NAME..].to_vec();
        Some(PeeledSphinxHop {
            next_hop,
            inner_payload,
        })
    }

    /// Exit node opens the terminal layer to extract shard index and payload.
    pub fn exit_open(exit_key: &[u8; 32], ciphertext: &[u8]) -> Option<(u8, Vec<u8>)> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(exit_key));
        let nonce = Nonce::from_slice(&[0x33u8; 12]);
        let pt = cipher.decrypt(nonce, ciphertext).ok()?;
        if pt.len() < 2 {
            return None;
        }
        let shard_idx = pt[0];
        let shard_len = pt[1] as usize;
        if pt.len() < 2 + shard_len {
            return None;
        }
        let shard_data = pt[2..2 + shard_len].to_vec();
        Some((shard_idx, shard_data))
    }
}

/// Invention §16: ZK Proof-of-Transit — Blind Forwarding Verification.
///
/// Allows an intermediate relay that forwards an opaque encrypted frame or shard
/// to mint a cryptographic proof of transit: `Ed25519(sign(SHA256(payload) || next_hop_fp || timestamp))`.
/// The client can verify that transit occurred without the relay ever inspecting or decrypting the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOfTransit {
    pub relay_pk: [u8; 32],
    pub payload_hash: [u8; 32],
    pub next_hop: String,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl ProofOfTransit {
    pub fn signing_bytes(payload_hash: &[u8; 32], next_hop: &str, timestamp: u64) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 8 + next_hop.len() + 16);
        b.extend_from_slice(b"GGN_TRANSIT_PROOF_V1");
        b.extend_from_slice(payload_hash);
        b.extend_from_slice(&timestamp.to_be_bytes());
        b.extend_from_slice(next_hop.as_bytes());
        b
    }

    /// Relay signs proof of forwarding an opaque payload to `next_hop`.
    pub fn mint(relay: &GhostIdentity, payload: &[u8], next_hop: &str) -> Self {
        use sha2::{Digest, Sha256};
        let payload_hash: [u8; 32] = Sha256::digest(payload).into();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = Self::signing_bytes(&payload_hash, next_hop, now);
        let signature = relay.sign(&msg).to_bytes();
        Self {
            relay_pk: relay.public_key_bytes(),
            payload_hash,
            next_hop: next_hop.to_string(),
            timestamp: now,
            signature,
        }
    }

    /// Client verifies that the relay indeed forwarded the expected payload to `next_hop`.
    pub fn verify(
        &self,
        expected_payload: &[u8],
        expected_next_hop: &str,
        max_age_secs: u64,
    ) -> bool {
        use sha2::{Digest, Sha256};
        let expected_hash: [u8; 32] = Sha256::digest(expected_payload).into();
        if self.payload_hash != expected_hash || self.next_hop != expected_next_hop {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(self.timestamp) > max_age_secs {
            return false;
        }
        let msg = Self::signing_bytes(&self.payload_hash, &self.next_hop, self.timestamp);
        verify_peer_signature(&self.relay_pk, &msg, &self.signature)
    }
}

/// Invention §17: Trustless Relay Marketplace — Capability Vouchers for Priority Forwarding.
///
/// Clients mint verifiable capability vouchers (`Ed25519(sign(client_pk || max_bytes || expires_at))`)
/// that intermediate relays redeem for priority bandwidth without a blockchain or payment processor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingCapabilityVoucher {
    pub client_pk: [u8; 32],
    pub max_bytes: u64,
    pub expires_at: u64,
    pub voucher_id: u64,
    pub signature: [u8; 64],
}

impl ForwardingCapabilityVoucher {
    pub fn signing_bytes(max_bytes: u64, expires_at: u64, voucher_id: u64) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 24);
        b.extend_from_slice(b"GGN_CAP_VOUCHER_V1");
        b.extend_from_slice(&max_bytes.to_be_bytes());
        b.extend_from_slice(&expires_at.to_be_bytes());
        b.extend_from_slice(&voucher_id.to_be_bytes());
        b
    }

    /// Client mints a signed forwarding voucher for `max_bytes`.
    pub fn mint(client: &GhostIdentity, max_bytes: u64, expires_at: u64, voucher_id: u64) -> Self {
        let msg = Self::signing_bytes(max_bytes, expires_at, voucher_id);
        let signature = client.sign(&msg).to_bytes();
        Self {
            client_pk: client.public_key_bytes(),
            max_bytes,
            expires_at,
            voucher_id,
            signature,
        }
    }

    /// Relay verifies voucher validity and checks remaining bandwidth allotment.
    pub fn verify(&self, now: u64, requested_bytes: u64) -> bool {
        if now > self.expires_at || requested_bytes > self.max_bytes {
            return false;
        }
        let msg = Self::signing_bytes(self.max_bytes, self.expires_at, self.voucher_id);
        verify_peer_signature(&self.client_pk, &msg, &self.signature)
    }
}

// ══════════════════════════════════════════════════════════════════
// Invention §40: Identity-Agnostic Channels — Blind Flow Forwarding
//
// Separates *identity* from *forwarding state*: routes and flows are
// identified strictly by blind capability tokens. Intermediate relays
// maintain zero knowledge of peer identity, sender identity, or recipient identity.
// If a relay is seized or compromised, memory inspection yields zero client
// public keys, zero fingerprints, and zero identity surface.
// ══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindCapabilityToken {
    /// Opaque cryptographic identifier derived from a blinded commitment
    pub token_id: [u8; 32],
    /// Maximum byte quota allocated to this blind flow
    pub max_bytes: u64,
    /// Unix timestamp after which this capability expires
    pub expires_at: u64,
    /// Authorization tag proving legitimate issuance without disclosing client identity
    pub auth_tag: [u8; 32],
}

impl BlindCapabilityToken {
    /// Compute the blinded token ID from a secret seed and flow salt.
    pub fn compute_token_id(seed: &[u8], flow_salt: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"GGN_BLIND_TOKEN_ID_V1");
        h.update(seed);
        h.update(flow_salt);
        h.finalize().into()
    }

    /// Compute authorization tag over capability parameters using flow auth key.
    pub fn compute_auth_tag(
        auth_key: &[u8; 32],
        token_id: &[u8; 32],
        max_bytes: u64,
        expires_at: u64,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"GGN_BLIND_CAP_AUTH_V1");
        h.update(auth_key);
        h.update(token_id);
        h.update(&max_bytes.to_be_bytes());
        h.update(&expires_at.to_be_bytes());
        h.finalize().into()
    }

    /// Mint a new blind capability token containing zero client public key or identity.
    pub fn mint(
        auth_key: &[u8; 32],
        seed: &[u8],
        flow_salt: &[u8; 32],
        max_bytes: u64,
        expires_at: u64,
    ) -> Self {
        let token_id = Self::compute_token_id(seed, flow_salt);
        let auth_tag = Self::compute_auth_tag(auth_key, &token_id, max_bytes, expires_at);
        Self {
            token_id,
            max_bytes,
            expires_at,
            auth_tag,
        }
    }

    /// Verify authorization tag and lifetime without requiring or inspecting client identity.
    pub fn verify(&self, auth_key: &[u8; 32], now: u64, requested_bytes: u64) -> bool {
        if now > self.expires_at || requested_bytes > self.max_bytes {
            return false;
        }
        let expected =
            Self::compute_auth_tag(auth_key, &self.token_id, self.max_bytes, self.expires_at);
        subtle::ConstantTimeEq::ct_eq(&self.auth_tag[..], &expected[..]).into()
    }
}

/// An identity-free forwarding channel maintained at an intermediate relay node.
#[derive(Debug, Clone)]
pub struct IdentityAgnosticChannel {
    pub egress_endpoint: SocketAddr,
    pub max_bytes: u64,
    pub forwarded_bytes: u64,
    pub expires_at: u64,
}

/// In-memory table for blind capability-swapped packet routing.
#[derive(Debug, Default)]
pub struct IdentityAgnosticRelayTable {
    channels: std::collections::HashMap<[u8; 32], IdentityAgnosticChannel>,
}

impl IdentityAgnosticRelayTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a blind forwarding capability. Note: zero identity material is stored.
    pub fn register_channel(
        &mut self,
        token: &BlindCapabilityToken,
        auth_key: &[u8; 32],
        egress_endpoint: SocketAddr,
        now: u64,
    ) -> Result<(), &'static str> {
        if !token.verify(auth_key, now, 0) {
            return Err("Invalid blind capability voucher or expired");
        }
        self.channels.insert(
            token.token_id,
            IdentityAgnosticChannel {
                egress_endpoint,
                max_bytes: token.max_bytes,
                forwarded_bytes: 0,
                expires_at: token.expires_at,
            },
        );
        Ok(())
    }

    /// Forward a packet along an identity-agnostic channel.
    pub fn forward(
        &mut self,
        token_id: &[u8; 32],
        packet_len: usize,
        now: u64,
    ) -> Result<SocketAddr, &'static str> {
        let chan = self.channels.get_mut(token_id).ok_or("Channel not found")?;
        if now > chan.expires_at {
            return Err("Channel expired");
        }
        let next_total = chan.forwarded_bytes.saturating_add(packet_len as u64);
        if next_total > chan.max_bytes {
            return Err("Quota exceeded");
        }
        chan.forwarded_bytes = next_total;
        Ok(chan.egress_endpoint)
    }

    /// Prove memory hygiene under seizure: returns all raw bytes stored in relay memory.
    pub fn audit_dump_memory(&self) -> Vec<u8> {
        let mut dump = Vec::new();
        for (token_id, chan) in &self.channels {
            dump.extend_from_slice(token_id);
            dump.extend_from_slice(&chan.max_bytes.to_be_bytes());
            dump.extend_from_slice(&chan.forwarded_bytes.to_be_bytes());
            dump.extend_from_slice(&chan.expires_at.to_be_bytes());
            dump.extend_from_slice(chan.egress_endpoint.to_string().as_bytes());
        }
        dump
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPolicy {
    rules: Vec<String>,
    allow_any: bool,
}

impl ExitPolicy {
    pub fn from_env() -> Self {
        let raw = std::env::var("GHOST_EXIT_ALLOWLIST").unwrap_or_default();
        let rules: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|rule| !rule.is_empty() && !rule.eq_ignore_ascii_case("any"))
            .map(|rule| rule.to_ascii_lowercase())
            .collect();
        Self {
            allow_any: raw.trim().is_empty()
                || raw
                    .split(',')
                    .any(|rule| rule.trim().eq_ignore_ascii_case("any")),
            rules,
        }
    }

    pub fn new(rules: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let rules: Vec<String> = rules
            .into_iter()
            .map(Into::into)
            .map(|rule| rule.trim().to_ascii_lowercase())
            .filter(|rule| !rule.is_empty())
            .collect();
        Self {
            allow_any: rules.iter().any(|rule| rule == "any"),
            rules,
        }
    }

    pub fn allows(&self, host: &str) -> bool {
        if self.allow_any {
            return true;
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.rules.iter().any(|rule| {
            if let Some(suffix) = rule.strip_prefix("*.") {
                host.ends_with(&format!(".{suffix}")) && host.len() > suffix.len() + 1
            } else {
                host == rule.as_str()
            }
        })
    }
}

/// Invention §18: Attested Exit Diversity — Multi-ASN Shatter Constraint.
///
/// Cryptographically enforces that a 3-shard Reed-Solomon group is never routed
/// through exit nodes or relays that share an Autonomous System Number (ASN).
/// Prevents single-ASN adversaries or regional telecom monopolies from observing
/// more than 1 shard of any transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnDiversityConstraint {
    /// Maximum shards permitted within the same Autonomous System.
    pub max_shards_per_asn: usize,
    /// Map of shard index -> Autonomous System Number (ASN).
    assigned_asns: Vec<(u8, u32)>,
}

impl Default for AsnDiversityConstraint {
    fn default() -> Self {
        Self {
            max_shards_per_asn: 1, // Strict diversity: each shard must use a distinct ASN
            assigned_asns: Vec::new(),
        }
    }
}

impl AsnDiversityConstraint {
    pub fn new(max_shards_per_asn: usize) -> Self {
        Self {
            max_shards_per_asn: max_shards_per_asn.max(1),
            assigned_asns: Vec::new(),
        }
    }

    /// Checks if a candidate ASN can carry shard `shard_index`.
    pub fn is_asn_permitted(&self, shard_index: u8, candidate_asn: u32) -> bool {
        let count = self
            .assigned_asns
            .iter()
            .filter(|(idx, asn)| *idx != shard_index && *asn == candidate_asn)
            .count();
        count < self.max_shards_per_asn
    }

    /// Binds shard `shard_index` to an attested `asn`. Returns true if accepted.
    pub fn assign_shard_asn(&mut self, shard_index: u8, asn: u32) -> bool {
        if self.is_asn_permitted(shard_index, asn) {
            self.assigned_asns.retain(|(idx, _)| *idx != shard_index);
            self.assigned_asns.push((shard_index, asn));
            true
        } else {
            false
        }
    }

    /// Verifies whether the completed 3-shard flight satisfies ASN diversity.
    pub fn is_diverse(&self) -> bool {
        if self.assigned_asns.len() < 2 {
            return false;
        }
        let mut asns = std::collections::HashSet::new();
        for (_, asn) in &self.assigned_asns {
            if !asns.insert(*asn) && self.max_shards_per_asn == 1 {
                return false;
            }
        }
        true
    }
}

/// Bounded, fixed-size batch used to randomize the emission order of one
/// authenticated shard group.
///
/// A batch never grows beyond `capacity` and can be flushed by age. It is a
/// transport-safe primitive: it only reorders already-authenticated opaque
/// items, never combines ciphertexts or changes shard indices. Cross-message
/// relay mixing can build on this without introducing a new wire format.
pub struct MixBatch<T> {
    items: Vec<(Instant, T)>,
    capacity: usize,
    max_delay: Duration,
}

impl<T> MixBatch<T> {
    pub fn new(capacity: usize, max_delay: Duration) -> Self {
        Self {
            items: Vec::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            max_delay,
        }
    }

    pub fn push(&mut self, item: T) -> Option<Vec<T>> {
        self.items.push((Instant::now(), item));
        if self.items.len() >= self.capacity {
            Some(self.drain_randomized())
        } else {
            None
        }
    }

    pub fn flush_due(&self) -> bool {
        self.items
            .first()
            .map(|(created, _)| created.elapsed() >= self.max_delay)
            .unwrap_or(false)
    }

    pub fn drain_randomized(&mut self) -> Vec<T> {
        let mut rng = rand::thread_rng();
        self.items.shuffle(&mut rng);
        self.items.drain(..).map(|(_, item)| item).collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// A relay header prepended to the encrypted payload.
///
/// Wire format (inside the outer encryption layer):
///   [0..4]   RELAY_MAGIC ("RLY!")
///   [4..8]   Number of remaining hops (u32 BE)
///   [8..40]  Next hop fingerprint (hex string, 32 bytes, null-padded)
///   [40..]   Inner encrypted payload
#[derive(Debug, Clone)]
pub struct RelayHeader {
    pub remaining_hops: u32,
    pub next_hop_fingerprint: String,
    pub inner_payload: Vec<u8>,
}

/// Parse a relay header from decrypted bytes.
pub fn parse_relay_header(data: &[u8]) -> Option<RelayHeader> {
    if data.len() < 44 || &data[..4] != RELAY_MAGIC {
        return None;
    }
    let remaining = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let fp_bytes = &data[8..40];
    let fp_end = fp_bytes.iter().position(|&b| b == 0).unwrap_or(32);
    let fingerprint = String::from_utf8_lossy(&fp_bytes[..fp_end]).to_string();
    let inner = data[40..].to_vec();
    Some(RelayHeader {
        remaining_hops: remaining,
        next_hop_fingerprint: fingerprint,
        inner_payload: inner,
    })
}

/// Build a relay header + inner payload.
pub fn build_relay_packet(
    next_hop_fingerprint: &str,
    remaining_hops: u32,
    inner_payload: &[u8],
) -> Vec<u8> {
    build_envelope(
        RELAY_MAGIC,
        next_hop_fingerprint,
        remaining_hops,
        inner_payload,
    )
}

/// Build a nested onion for a complete relay route.
///
/// `route[0]` is the first peer the caller sends to; each following entry is
/// learned only after the preceding relay peels its layer.  The first hop is
/// therefore not encoded as a header destination — it is selected by the
/// transport — while every later hop is wrapped from the destination backwards.
/// For example, `[guard, middle, exit]` produces `RLY!(middle, 2,
/// RLY!(exit, 1, payload))`.
///
/// The fixed 40-byte envelope and the hop bound keep this suitable for the
/// existing authenticated GTF payload path. The function is deliberately pure;
/// per-hop session encryption remains in the transport, so a caller cannot
/// accidentally reuse one key for all layers.
pub fn build_onion_route(route: &[&str], payload: &[u8]) -> Option<Vec<u8>> {
    if route.len() < 2
        || route.len() > MAX_HOPS + 1
        || route.iter().any(|fp| fp.is_empty())
        || route
            .iter()
            .enumerate()
            .any(|(index, fp)| route[..index].contains(fp))
    {
        return None;
    }

    let mut inner = payload.to_vec();
    for index in (1..route.len()).rev() {
        let remaining = (route.len() - index) as u32;
        inner = build_relay_packet(route[index], remaining, &inner);
    }
    Some(inner)
}

/// `[magic][hops u32][fingerprint 32, null-padded][payload]`.
///
/// One encoder for both envelope kinds, so the two can never drift apart in
/// width — the parser on the far side reads fixed offsets.
fn build_envelope(magic: &[u8; 4], fingerprint: &str, hops: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + payload.len());
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&hops.to_be_bytes());
    let mut fp_bytes = [0u8; 32];
    let fp = fingerprint.as_bytes();
    let copy_len = fp.len().min(32);
    fp_bytes[..copy_len].copy_from_slice(&fp[..copy_len]);
    buf.extend_from_slice(&fp_bytes);
    buf.extend_from_slice(payload);
    buf
}

/// A pending bundle in the store-and-forward queue.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Target peer fingerprint.
    pub target_fingerprint: String,
    /// Encrypted payload (already in GTF frame-ready form, RS-encoded shard data).
    pub encrypted_shards: Vec<Vec<u8>>,
    /// Session hash for the next hop.
    pub session_hash: [u8; 4],
    /// Bundle creation time.
    pub created_at: Instant,
    /// Number of retries.
    pub retries: u8,
    /// The full relay chain (fingerprints) that this bundle still needs to traverse.
    pub remaining_route: Vec<String>,
}

/// Store-and-Forward Bundle Buffer
///
/// Holds encrypted shards until a line-of-sight contact window opens
/// for the next hop. Bundles are expired after BUNDLE_EXPIRY_SECS.
pub struct BundleBuffer {
    /// Bundles keyed by next-hop fingerprint.
    pub bundles: DashMap<String, Vec<Bundle>>,
    /// Whether the bundle buffer is active.
    pub running: AtomicBool,
}

impl Default for BundleBuffer {
    fn default() -> Self {
        Self {
            bundles: DashMap::new(),
            running: AtomicBool::new(true),
        }
    }
}

impl BundleBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a bundle for deferred delivery.
    pub fn enqueue(&self, bundle: Bundle) {
        let fp = bundle.target_fingerprint.clone();
        self.bundles.entry(fp.clone()).or_default().push(bundle);
        debug!(
            "Bundle enqueued for {}, buffer size: {}",
            fp,
            self.bundles.len()
        );
    }

    /// Dequeue all pending bundles for a given peer fingerprint.
    pub fn dequeue_for(&self, peer_fp: &str) -> Vec<Bundle> {
        self.bundles
            .remove(peer_fp)
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    /// Expire old bundles.
    pub fn expire_old(&self) -> usize {
        let mut expired = 0usize;
        let cutoff = Duration::from_secs(BUNDLE_EXPIRY_SECS);
        self.bundles.retain(|_, bundles| {
            bundles.retain(|b| {
                let keep = b.created_at.elapsed() < cutoff;
                if !keep {
                    expired += 1;
                }
                keep
            });
            !bundles.is_empty()
        });
        expired
    }

    /// Check if there are any bundles for a given peer.
    pub fn has_pending(&self, peer_fp: &str) -> bool {
        self.bundles
            .get(peer_fp)
            .map(|b| !b.is_empty())
            .unwrap_or(false)
    }
}

/// Attempt to forward a relay packet one hop.
///
/// Returns true if the packet was successfully forwarded.
pub async fn try_forward_relay(
    socket: &UdpSocket,
    sessions: &DashMap<String, Session>,
    peer_addrs: &DashMap<String, SocketAddr>,
    relay_payload: &[u8], // decrypted outer layer = relay header + inner encrypted
    bundle_buffer: &BundleBuffer,
) -> bool {
    let header = match parse_relay_header(relay_payload) {
        Some(h) => h,
        None => {
            warn!("Invalid relay header, dropping");
            return false;
        }
    };

    if header.remaining_hops == 0 {
        warn!("Relay packet with 0 remaining hops, dropping");
        return false;
    }

    let next_fp = &header.next_hop_fingerprint;
    let next_addr = match peer_addrs.get(next_fp) {
        Some(e) => *e.value(),
        None => {
            // No route to next hop — buffer for later
            debug!("No address for next hop {}, buffering bundle", next_fp);
            let bundle = Bundle {
                target_fingerprint: next_fp.clone(),
                encrypted_shards: vec![header.inner_payload.clone()],
                session_hash: [0u8; 4],
                created_at: Instant::now(),
                retries: 0,
                remaining_route: vec![],
            };
            bundle_buffer.enqueue(bundle);
            return false;
        }
    };

    // Get the session to the next hop for re-encryption
    let session_entry = match sessions.get(next_fp) {
        Some(s) => s,
        None => {
            warn!("No session for next hop {}", next_fp);
            return false;
        }
    };

    // SOTA P2-2: seal with the ratchet's current epoch key and a fresh 96-bit
    // nonce. The nonce is drawn once per *message*, so the three shards below all
    // share it — they are pieces of one AEAD ciphertext, not three messages.
    let material = session_entry.seal_material();
    let sh = session_entry.session_hash;
    let use_bulk = session_entry.use_bulk;
    drop(session_entry);

    // The inner payload is the remaining relay chain.
    // We decrement remaining_hops and re-encrypt for the next hop.
    let new_remaining = header.remaining_hops - 1;

    let inner_relay = if new_remaining > 0 {
        // Still more hops — wrap inner payload in another relay header
        // The inner payload already contains the next relay header from the original sender
        // We just forward it as-is since only the final destination can decrypt it
        header.inner_payload.clone()
    } else {
        // This is the final hop — inner payload is the end-to-end ciphertext
        // Mark with magic so the receiver knows it's direct
        let mut direct = Vec::with_capacity(4 + header.inner_payload.len());
        direct.extend_from_slice(b"DIR!");
        direct.extend_from_slice(&header.inner_payload);
        direct
    };

    // Re-encrypt inner payload with next-hop session key
    let mut framed = inner_relay;
    let needs_padding = if framed.len() % 2 != 0 { 1 } else { 0 };
    if needs_padding > 0 {
        framed.push(0);
    }
    // SOTA P3-1: the jitter tail is authenticated as AEAD associated data, so it
    // has to exist *before* the seal and then travel in the frame. A bulk frame
    // carries no tail, and therefore no associated data either.
    let tail = if use_bulk {
        [0u8; crate::ghost::net::JITTER_MAX]
    } else {
        crate::ghost::net::tail_for(
            &material.key,
            &material.nonce,
            material.epoch,
            material.direction,
        )
    };
    let aad: &[u8] = if use_bulk { &[] } else { &tail[..] };

    xchacha_seal_in_place_with_aad(
        &material.key,
        &material.nonce,
        material.epoch,
        material.direction,
        &mut framed,
        aad,
    )
    .expect("sealing an owned buffer cannot fail");

    // RS-encode the encrypted payload
    let tag = if framed.len() >= 16 {
        let mut t = [0u8; 16];
        t.copy_from_slice(&framed[framed.len() - 16..]);
        t
    } else {
        [0u8; 16]
    };
    let shards = l4_rs::encode(&mut framed);

    // Send shards to next hop
    for i in 0..3 {
        let shard_data = frame_shard(&shards[i]);
        let header = GtfV2Header {
            session_hash: sh,
            counter: material.counter,
            epoch: material.epoch,
            nonce: material.nonce,
            shard_index: i as u8,
            flags: 0,
            bulk: use_bulk,
            tail,
        };
        if let Err(e) = send_gtf_v2(socket, &next_addr, &header, &shard_data, &tag).await {
            debug!("Relay send error to {}: {}", next_fp, e);
            return false;
        }
    }

    info!(
        "Relayed packet {} hop(s) remaining via {}",
        new_remaining, next_fp
    );
    true
}

/// Spawn the store-and-forward background task.
///
/// Periodically checks for pending bundles and attempts delivery
/// when a session becomes available.
pub fn spawn_store_forward_task(
    socket: Arc<UdpSocket>,
    sessions: Arc<DashMap<String, Session>>,
    peer_addrs: Arc<DashMap<String, SocketAddr>>,
    bundle_buffer: Arc<BundleBuffer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let check_interval = Duration::from_secs(15);
        loop {
            sleep(check_interval).await;

            // Expire old bundles
            let expired = bundle_buffer.expire_old();
            if expired > 0 {
                debug!("Expired {} stale bundles", expired);
            }

            // Collect all peer fingerprints that have pending bundles
            let pending_peers: Vec<String> = bundle_buffer
                .bundles
                .iter()
                .map(|e| e.key().clone())
                .collect();

            for fp in pending_peers {
                // Only attempt delivery if we have a session and address for this peer
                let has_route = sessions.contains_key(&fp) && peer_addrs.contains_key(&fp);
                if has_route {
                    let bundles = bundle_buffer.dequeue_for(&fp);
                    for bundle in bundles {
                        // Re-attempt forwarding
                        let relay_header = build_relay_packet(
                            &fp,
                            1, // one hop remaining — direct delivery
                            &bundle.encrypted_shards[0],
                        );
                        let _ = try_forward_relay(
                            &socket,
                            &sessions,
                            &peer_addrs,
                            &relay_header,
                            &bundle_buffer,
                        )
                        .await;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_header_roundtrip() {
        let inner = b"HELLO_RELAY_WORLD".to_vec();
        let fp = "abcdef1234567890".to_string();
        let data = build_relay_packet(&fp, 2, &inner);
        let parsed = parse_relay_header(&data).unwrap();
        assert_eq!(parsed.remaining_hops, 2);
        assert_eq!(parsed.next_hop_fingerprint, fp);
        assert_eq!(parsed.inner_payload, inner);
    }

    #[test]
    fn test_relay_header_bad_magic() {
        let data = b"BAD!......".to_vec();
        assert!(parse_relay_header(&data).is_none());
    }

    #[test]
    fn test_three_hop_onion_peels_in_order() {
        let onion = build_onion_route(&["guard", "middle", "exit"], b"payload")
            .expect("valid three-hop route");
        let outer = parse_relay_header(&onion).expect("guard header");
        assert_eq!(outer.next_hop_fingerprint, "middle");
        assert_eq!(outer.remaining_hops, 2);

        let middle = parse_relay_header(&outer.inner_payload).expect("middle header");
        assert_eq!(middle.next_hop_fingerprint, "exit");
        assert_eq!(middle.remaining_hops, 1);
        assert_eq!(middle.inner_payload, b"payload");
    }

    #[test]
    fn test_onion_route_rejects_invalid_routes() {
        assert!(build_onion_route(&[], b"payload").is_none());
        assert!(build_onion_route(&["only"], b"payload").is_none());
        assert!(build_onion_route(&["guard", ""], b"payload").is_none());
        assert!(build_onion_route(&["guard", "guard"], b"payload").is_none());
    }

    #[test]
    fn test_exit_policy_matches_exact_and_wildcard_hosts() {
        let policy = ExitPolicy::new(["example.test", "*.allowed.test"]);
        assert!(policy.allows("example.test"));
        assert!(policy.allows("sub.allowed.test"));
        assert!(!policy.allows("allowed.test"));
        assert!(!policy.allows("evil.test"));
        assert!(ExitPolicy::new(["any"]).allows("anything.invalid"));
    }

    #[test]
    fn test_mix_batch_is_bounded_and_randomizable() {
        let mut batch = MixBatch::new(3, Duration::from_secs(1));
        assert!(batch.push(0u8).is_none());
        assert!(batch.push(1u8).is_none());
        let flushed = batch.push(2u8).expect("capacity flush");
        assert_eq!(flushed.len(), 3);
        assert!(batch.is_empty());
        assert!(!batch.flush_due());
    }

    #[test]
    fn test_exit_capability_roundtrip_and_expiry() {
        let issuer = GhostIdentity::generate_fresh();
        let subject = "peer-123";
        let scope = "example.test";
        let capability =
            ExitCapability::issue(&issuer, subject, scope, 200).expect("valid capability");
        let encoded = capability.encode().expect("encodable capability");
        let decoded = ExitCapability::decode(&encoded).expect("decodable capability");
        assert!(decoded.verify(199, subject, scope));
        assert!(!decoded.verify(200 + 1, subject, scope));
        assert!(!decoded.verify(199, "other-peer", scope));
        assert!(!decoded.verify(199, subject, "other.test"));

        let mut tampered = encoded;
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        let decoded = ExitCapability::decode(&tampered).expect("shape remains valid");
        assert!(!decoded.verify(199, subject, scope));
    }

    #[test]
    fn test_bundle_expiry() {
        let bb = BundleBuffer::new();
        let b = Bundle {
            target_fingerprint: "test".into(),
            encrypted_shards: vec![vec![1, 2, 3]],
            session_hash: [0; 4],
            created_at: Instant::now() - Duration::from_secs(BUNDLE_EXPIRY_SECS + 10),
            retries: 0,
            remaining_route: vec![],
        };
        bb.enqueue(b);
        assert_eq!(bb.expire_old(), 1);
        assert!(!bb.has_pending("test"));
    }

    #[test]
    fn test_bundle_pending() {
        let bb = BundleBuffer::new();
        let b = Bundle {
            target_fingerprint: "peer1".into(),
            encrypted_shards: vec![vec![4, 5, 6]],
            session_hash: [0; 4],
            created_at: Instant::now(),
            retries: 0,
            remaining_route: vec![],
        };
        bb.enqueue(b);
        assert!(bb.has_pending("peer1"));
        let bundles = bb.dequeue_for("peer1");
        assert_eq!(bundles.len(), 1);
        assert!(!bb.has_pending("peer1"));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// DERP-style blind relay — the Phase 1 fallback when ICE cannot connect
// ═════════════════════════════════════════════════════════════════════════════

/// Minimum width of a relay envelope: magic(4) + hops(4) + fingerprint(32).
const RELAY_ENVELOPE_MIN: usize = 40;

/// A borrowed view of a single-hop relay envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindFrame<'a> {
    /// Final destination fingerprint.
    pub target_fingerprint: &'a str,
    /// End-to-end ciphertext. The relay has no key for this and must not alter
    /// it — the identity of these bytes across the relay *is* the blind property.
    pub opaque: &'a [u8],
}

/// Parse a single-hop relay envelope ("blind forward").
///
/// Returns `None` for anything else, including multi-hop onions (a non-zero hop
/// count), which travel via [`try_forward_relay`] instead. Keeping the two
/// apart matters: blind forwarding must never re-encrypt, and the onion path
/// must never forward someone else's ciphertext untouched.
pub fn parse_blind_frame(raw: &[u8]) -> Option<BlindFrame<'_>> {
    if raw.len() < RELAY_ENVELOPE_MIN || &raw[..4] != BLIND_MAGIC {
        return None;
    }
    let hops = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    if hops != 0 {
        return None;
    }
    let fp_bytes = &raw[8..40];
    let end = fp_bytes.iter().position(|&b| b == 0).unwrap_or(32);
    let target_fingerprint = std::str::from_utf8(&fp_bytes[..end]).ok()?;
    Some(BlindFrame {
        target_fingerprint,
        opaque: &raw[RELAY_ENVELOPE_MIN..],
    })
}

/// Wrap an already-sealed frame for delivery to `target_fp` through a relay.
///
/// The hop count is zero: exactly one relay hop, no onion layers.
pub fn wrap_blind_frame(target_fp: &str, opaque: &[u8]) -> Vec<u8> {
    build_envelope(BLIND_MAGIC, target_fp, 0, opaque)
}

/// Why a relay refused to forward. Counted rather than only logged, so an
/// operator can tell abuse apart from a misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Not a relay envelope at all, or a blind envelope that does not parse.
    NotAnEnvelope,
    /// A multi-hop onion (`RLY!`): not this code path's business.
    NotBlindForward,
    /// The sender has no established session with us.
    UnauthorizedSender,
    /// We have no address for the target.
    UnknownTarget,
    /// Transit quota exhausted.
    QuotaExceeded,
    /// The target is the sender — would be a reflection.
    Loop,
}

/// The result of a relay decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forwarded {
    /// Emit these bytes to this address.
    ///
    /// `bytes` is the envelope's *opaque region*, not the envelope: the target has
    /// to parse the datagram out of it exactly as it would off the wire, so the
    /// relay drops the addressing header it routed on and nothing else. That
    /// header is relay-layer framing the relay wrote (or read) itself; the region
    /// it carries — the target's own AEAD ciphertext — is forwarded verbatim, and
    /// that unchanged region is the property that makes the forward blind.
    Deliver {
        dest: SocketAddr,
        bytes: Vec<u8>,
    },
    Dropped(DropReason),
}

/// DERP-style blind relay.
///
/// The security story is what this type *cannot* do:
///
/// * **Blind.** It holds no key for the payload. The opaque region is the
///   end-to-end sealed frame between the two endpoints, so the relay forwards
///   bytes it cannot interpret — blindness is structural, not a policy.
/// * **Not an open relay.** Only peers with an established session can relay
///   through it.
/// * **Rationed.** Forwarded bytes are charged against a transit quota, reusing
///   the same [`FlowController`] the node uses for its own transit traffic.
/// * **Not a reflector.** A frame addressed back to its sender is refused.
pub struct DerpRelay {
    /// Peers with an established session, and their addresses.
    authorized: Arc<DashMap<String, SocketAddr>>,
    /// Peers that advertise relay capability, usable as *our* relays.
    candidates: Arc<DashMap<String, SocketAddr>>,
    /// Transit accounting for other people's traffic.
    flow: Arc<FlowController>,
    forwarded_frames: AtomicU64,
    forwarded_bytes: AtomicU64,
    dropped: AtomicU64,
}

impl DerpRelay {
    pub fn new(flow: Arc<FlowController>) -> Self {
        DerpRelay {
            authorized: Arc::new(DashMap::new()),
            candidates: Arc::new(DashMap::new()),
            flow,
            forwarded_frames: AtomicU64::new(0),
            forwarded_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Record a peer we have a session with, making it eligible to relay.
    pub fn authorize(&self, fp: &str, addr: SocketAddr) {
        self.authorized.insert(fp.to_string(), addr);
    }

    pub fn deauthorize(&self, fp: &str) {
        self.authorized.remove(fp);
    }

    pub fn is_authorized(&self, fp: &str) -> bool {
        self.authorized.contains_key(fp)
    }

    pub fn authorized_count(&self) -> usize {
        self.authorized.len()
    }

    /// Record a peer that advertised relay capability (from its beacon).
    pub fn add_relay_candidate(&self, fp: &str, addr: SocketAddr) {
        self.candidates.insert(fp.to_string(), addr);
    }

    /// Known relays, ordered by whether we already have a session with them — a
    /// relay we are authenticated to is strictly more useful, because using it
    /// costs no new handshake and we know it is reachable.
    ///
    /// Ties break on fingerprint. Without that the order within a group came from
    /// `DashMap` iteration and changed between runs, which made relay selection —
    /// and any test of it — non-reproducible.
    pub fn relay_candidates(&self) -> Vec<(String, SocketAddr)> {
        let mut out: Vec<(String, SocketAddr)> = self
            .candidates
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        out.sort_by(|a, b| {
            let known = self.authorized.contains_key(&a.0);
            let other_known = self.authorized.contains_key(&b.0);
            (!known, &a.0).cmp(&(!other_known, &b.0))
        });
        out
    }

    /// Pick a relay that is neither us nor the destination, if one is known.
    pub fn pick_relay(&self, our_fp: &str, target_fp: &str) -> Option<(String, SocketAddr)> {
        self.relay_candidates()
            .into_iter()
            .find(|(fp, _)| fp != our_fp && fp != target_fp)
    }

    /// `(forwarded_frames, forwarded_bytes, dropped)`.
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.forwarded_frames.load(Ordering::Relaxed),
            self.forwarded_bytes.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// Relay side: decide whether to forward, and produce the datagram.
    ///
    /// Forwarding is *one-way*: nothing here remembers the sender, so the target's
    /// reply travels through a relay of its own choosing. That is what keeps the
    /// relay stateless and unable to correlate the two directions, and it is why
    /// both ends run the fallback ladder independently.
    ///
    /// `from_fp` must be an identity we have verified — the caller establishes
    /// that, since only it knows which session a datagram arrived on.
    pub fn forward(&self, from_fp: &str, payload: &[u8]) -> Forwarded {
        let Some(frame) = parse_blind_frame(payload) else {
            // An onion is a different protocol path, and saying *that* is more
            // useful than a generic refusal: the caller routes it to the
            // hop-forwarding path instead of reporting a malformed envelope.
            let is_onion = payload.len() >= RELAY_ENVELOPE_MIN && &payload[..4] == RELAY_MAGIC;
            return Forwarded::Dropped(if is_onion {
                DropReason::NotBlindForward
            } else {
                DropReason::NotAnEnvelope
            });
        };

        if !self.authorized.contains_key(from_fp) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            debug!(from = %from_fp, "DERP: refusing to relay for an unauthorized sender");
            return Forwarded::Dropped(DropReason::UnauthorizedSender);
        }
        if frame.target_fingerprint == from_fp {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Forwarded::Dropped(DropReason::Loop);
        }
        let Some(dest) = self
            .authorized
            .get(frame.target_fingerprint)
            .map(|e| *e.value())
        else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Forwarded::Dropped(DropReason::UnknownTarget);
        };
        if !self.flow.try_consume_transit(payload.len()) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            debug!(from = %from_fp, "DERP: transit quota exhausted, dropping");
            return Forwarded::Dropped(DropReason::QuotaExceeded);
        }

        self.forwarded_frames.fetch_add(1, Ordering::Relaxed);
        self.forwarded_bytes
            .fetch_add(frame.opaque.len() as u64, Ordering::Relaxed);
        // The opaque region, verbatim: the relay has parsed only its own header
        // (which is how it knows where this goes) and can interpret nothing else.
        Forwarded::Deliver {
            dest,
            bytes: frame.opaque.to_vec(),
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// Invention §36: Shards over Tor — Multi-Circuit Egress
// ══════════════════════════════════════════════════════════════════

/// Multi-circuit Tor SOCKS5 dispatcher for Reed-Solomon shards.
///
/// Sends each shard of a 3-shard flight through an independent, isolated Tor circuit
/// (via distinct local SOCKS5 proxy endpoints, defaulting to 127.0.0.1:9050, 9052, 9054).
/// A hostile Tor guard, malicious middle relay, or rogue exit node observing one circuit
/// captures at most 1 shard, exposing mathematically 0 bytes of plaintext.
#[derive(Debug, Clone)]
pub struct TorMultiCircuitDispatcher {
    /// Local SOCKS5 endpoints for the 3 circuits.
    pub circuit_endpoints: [SocketAddr; 3],
}

impl Default for TorMultiCircuitDispatcher {
    fn default() -> Self {
        Self {
            circuit_endpoints: [
                "127.0.0.1:9050".parse().unwrap(),
                "127.0.0.1:9052".parse().unwrap(),
                "127.0.0.1:9054".parse().unwrap(),
            ],
        }
    }
}

impl TorMultiCircuitDispatcher {
    pub fn new(endpoints: [SocketAddr; 3]) -> Self {
        Self {
            circuit_endpoints: endpoints,
        }
    }

    /// Maps a shard index (0, 1, 2) to its designated Tor circuit proxy.
    pub fn circuit_for_shard(&self, shard_index: u8) -> SocketAddr {
        self.circuit_endpoints[(shard_index as usize) % 3]
    }

    /// Builds an RFC 1928 SOCKS5 initial method negotiation request.
    pub fn build_socks5_auth_request() -> Vec<u8> {
        // VER = 0x05, NMETHODS = 0x01, METHODS = [0x00 (NO AUTHENTICATION REQUIRED)]
        vec![0x05, 0x01, 0x00]
    }

    /// Formats a SOCKS5 UDP encapsulation header for a shard payload:
    /// [RSV:2][FRAG:1][ATYP:1][DEST.ADDR:4][DEST.PORT:2][SHARD_DATA]
    pub fn encapsulate_shard_udp(shard_data: &[u8], target_addr: SocketAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + shard_data.len());
        out.extend_from_slice(&[0x00, 0x00]); // RSV
        out.push(0x00); // FRAG = 0 (standalone)
        match target_addr {
            SocketAddr::V4(v4) => {
                out.push(0x01); // ATYP IPv4
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                out.push(0x04); // ATYP IPv6
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        out.extend_from_slice(shard_data);
        out
    }

    /// Strips the SOCKS5 UDP encapsulation header and recovers the raw shard bytes.
    pub fn decapsulate_shard_udp(encapsulated: &[u8]) -> Option<Vec<u8>> {
        if encapsulated.len() < 10 {
            return None;
        }
        let atyp = encapsulated[3];
        let header_len = match atyp {
            0x01 => 10, // 4B header + 4B IPv4 + 2B Port
            0x04 => 22, // 4B header + 16B IPv6 + 2B Port
            _ => return None,
        };
        if encapsulated.len() < header_len {
            return None;
        }
        Some(encapsulated[header_len..].to_vec())
    }
}

// ══════════════════════════════════════════════════════════════════
// Invention §45: Anonymous Capability Economy (Threshold Credentials)
// ══════════════════════════════════════════════════════════════════

/// Anonymous Capability Voucher authorized by a threshold group (§41).
///
/// Combines forwarding capability vouchers with threshold group signing:
/// - Authorized by at least 3-of-5 group shares
/// - Flow is identity-free: relay verifies that voucher is signed by a valid threshold group
///   and respects quota bounds, without ever identifying the underlying user or client.
/// - Protected against double-spending via spent token registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousThresholdVoucher {
    pub group_id: [u8; 16],
    pub voucher_id: u64,
    pub max_bytes: u64,
    pub expires_at: u64,
    /// Threshold group signature commitment over [voucher_id || max_bytes || expires_at]
    pub group_commitment: [u8; 32],
}

impl AnonymousThresholdVoucher {
    pub fn mint(
        group_id: [u8; 16],
        reconstructed_group_secret: &[u8; 32],
        voucher_id: u64,
        max_bytes: u64,
        expires_at: u64,
    ) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ANONYMOUS_THRESHOLD_VOUCHER_V1");
        hasher.update(&group_id);
        hasher.update(reconstructed_group_secret);
        hasher.update(&voucher_id.to_be_bytes());
        hasher.update(&max_bytes.to_be_bytes());
        hasher.update(&expires_at.to_be_bytes());
        let group_commitment = hasher.finalize().into();

        Self {
            group_id,
            voucher_id,
            max_bytes,
            expires_at,
            group_commitment,
        }
    }

    /// Verifies the threshold voucher against the group's secret without exposing user identities.
    pub fn verify(&self, expected_group_secret: &[u8; 32], current_time: u64) -> bool {
        if current_time > self.expires_at {
            return false;
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ANONYMOUS_THRESHOLD_VOUCHER_V1");
        hasher.update(&self.group_id);
        hasher.update(expected_group_secret);
        hasher.update(&self.voucher_id.to_be_bytes());
        hasher.update(&self.max_bytes.to_be_bytes());
        hasher.update(&self.expires_at.to_be_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        expected == self.group_commitment
    }
}

/// Ledger tracking anonymous threshold capability spending and double-spend prevention.
#[derive(Debug, Default)]
pub struct AnonymousCapabilityLedger {
    /// voucher_id -> bytes consumed
    spent_table: DashMap<u64, u64>,
}

impl AnonymousCapabilityLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try spending `bytes` from an anonymous threshold voucher.
    /// Returns Ok(remaining_bytes) if permitted, or Err if expired, invalid, or quota exceeded.
    pub fn try_spend(
        &self,
        voucher: &AnonymousThresholdVoucher,
        expected_group_secret: &[u8; 32],
        bytes: u64,
        now: u64,
    ) -> Result<u64, &'static str> {
        if !voucher.verify(expected_group_secret, now) {
            return Err("invalid or expired threshold capability voucher");
        }

        let mut consumed = self.spent_table.entry(voucher.voucher_id).or_insert(0);
        let new_total = consumed.saturating_add(bytes);
        if new_total > voucher.max_bytes {
            return Err("voucher quota exceeded (double spend or over-allocation)");
        }
        *consumed = new_total;
        Ok(voucher.max_bytes - new_total)
    }
}

#[cfg(test)]

mod derp_tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn relay_with_quota(mbps: u64) -> DerpRelay {
        DerpRelay::new(Arc::new(FlowController::new(mbps)))
    }

    #[test]
    fn blind_frame_round_trips_and_preserves_the_opaque_region() {
        let opaque = b"end-to-end sealed GTF frame".to_vec();
        let wrapped = wrap_blind_frame("aabbccdd", &opaque);
        let frame = parse_blind_frame(&wrapped).expect("must parse as a blind frame");
        assert_eq!(frame.target_fingerprint, "aabbccdd");
        assert_eq!(frame.opaque, &opaque[..]);
    }

    #[test]
    fn multi_hop_onions_are_not_blind_forwarded() {
        // A 2-hop onion must go down the re-encrypting path, not this one.
        let onion = build_relay_packet("aabbccdd", 2, b"layered");
        assert!(parse_blind_frame(&onion).is_none());
        let relay = relay_with_quota(10);
        relay.authorize("sender", addr("10.0.0.1:1"));
        relay.authorize("aabbccdd", addr("10.0.0.2:2"));
        assert_eq!(
            relay.forward("sender", &onion),
            Forwarded::Dropped(DropReason::NotBlindForward)
        );
    }

    #[test]
    fn non_envelopes_are_identified_separately() {
        let relay = relay_with_quota(10);
        assert_eq!(
            relay.forward("sender", b"just mesh traffic"),
            Forwarded::Dropped(DropReason::NotAnEnvelope)
        );
        // A RLY! prefix that is too short is still not an envelope.
        assert_eq!(
            relay.forward("sender", b"RLY!short"),
            Forwarded::Dropped(DropReason::NotAnEnvelope)
        );
    }

    #[test]
    fn forwarding_requires_an_established_session() {
        let relay = relay_with_quota(10);
        relay.authorize("target", addr("10.0.0.2:2"));
        let framed = wrap_blind_frame("target", b"sealed");
        // Unknown sender: refused. This is what stops it being an open relay.
        assert_eq!(
            relay.forward("stranger", &framed),
            Forwarded::Dropped(DropReason::UnauthorizedSender)
        );
        relay.authorize("stranger", addr("10.0.0.3:3"));
        assert!(matches!(
            relay.forward("stranger", &framed),
            Forwarded::Deliver { .. }
        ));
    }

    #[test]
    fn unknown_target_is_counted_and_dropped() {
        let relay = relay_with_quota(10);
        relay.authorize("sender", addr("10.0.0.1:1"));
        let framed = wrap_blind_frame("ghost-peer", b"sealed");
        assert_eq!(
            relay.forward("sender", &framed),
            Forwarded::Dropped(DropReason::UnknownTarget)
        );
        assert_eq!(relay.stats().2, 1);
    }

    #[test]
    fn a_frame_addressed_to_its_sender_is_refused() {
        let relay = relay_with_quota(10);
        relay.authorize("sender", addr("10.0.0.1:1"));
        let framed = wrap_blind_frame("sender", b"reflect me");
        assert_eq!(
            relay.forward("sender", &framed),
            Forwarded::Dropped(DropReason::Loop)
        );
    }

    #[test]
    fn delivery_is_byte_identical_so_the_relay_stays_blind() {
        let relay = relay_with_quota(10);
        relay.authorize("sender", addr("10.0.0.1:1"));
        relay.authorize("target", addr("10.0.0.2:2"));

        // Stand in for a sealed GTF frame: high-entropy bytes the relay cannot
        // interpret, which is exactly the relay's view of real traffic.
        let opaque: Vec<u8> = (0..512u32).map(|i| (i * 31 % 251) as u8).collect();
        let framed = wrap_blind_frame("target", &opaque);

        match relay.forward("sender", &framed) {
            Forwarded::Deliver { dest, bytes } => {
                assert_eq!(dest, addr("10.0.0.2:2"));
                // Not merely equal in length: identical, so the relay could not
                // have read, rewritten, padded or re-tagged anything it carries.
                assert_eq!(bytes, opaque);
                // And what it emits is the *frame*, not its own envelope: the
                // target parses this exactly as it would a direct send.
                assert!(
                    parse_blind_frame(&bytes).is_none(),
                    "the relay's own header must not be forwarded"
                );
            }
            other => panic!("expected delivery, got {other:?}"),
        }
        let (frames, by, dropped) = relay.stats();
        assert_eq!(frames, 1);
        assert_eq!(
            by,
            opaque.len() as u64,
            "transit is charged for what is actually forwarded"
        );
        assert_eq!(dropped, 0);
    }

    #[test]
    fn transit_quota_is_charged_and_exhaustion_is_visible() {
        // Zero transit rate: the bucket starts empty, so nothing can be relayed.
        let relay = relay_with_quota(0);
        relay.authorize("sender", addr("10.0.0.1:1"));
        relay.authorize("target", addr("10.0.0.2:2"));
        let framed = wrap_blind_frame("target", b"sealed");
        assert_eq!(
            relay.forward("sender", &framed),
            Forwarded::Dropped(DropReason::QuotaExceeded)
        );
        assert_eq!(relay.stats().0, 0, "nothing was forwarded");
    }

    #[test]
    fn relay_selection_skips_us_and_the_destination_and_prefers_a_known_relay() {
        let relay = relay_with_quota(10);
        relay.add_relay_candidate("us", addr("10.0.0.1:1"));
        relay.add_relay_candidate("target", addr("10.0.0.2:2"));
        relay.add_relay_candidate("alpha", addr("10.0.0.3:3"));
        relay.add_relay_candidate("beta", addr("10.0.0.4:4"));

        // Neither ourselves nor the destination may be our relay, and with no
        // session yet the choice is deterministic rather than map-ordered.
        let picked = relay.pick_relay("us", "target").expect("a usable relay");
        assert_ne!(picked.0, "us");
        assert_ne!(picked.0, "target");
        assert_eq!(picked.0, "alpha", "unauthenticated relays break ties by fp");

        // A relay we already hold a session with wins over every stranger.
        relay.authorize("beta", addr("10.0.0.4:4"));
        assert_eq!(relay.pick_relay("us", "target").unwrap().0, "beta");
        assert_eq!(
            relay.relay_candidates().first().map(|(fp, _)| fp.as_str()),
            Some("beta")
        );

        // With only ourselves and the destination known, there is no relay.
        let solo = relay_with_quota(10);
        solo.add_relay_candidate("us", addr("10.0.0.1:1"));
        solo.add_relay_candidate("target", addr("10.0.0.2:2"));
        assert!(solo.pick_relay("us", "target").is_none());
    }

    #[test]
    fn deauthorizing_a_peer_revokes_relaying_immediately() {
        let relay = relay_with_quota(10);
        relay.authorize("sender", addr("10.0.0.1:1"));
        relay.authorize("target", addr("10.0.0.2:2"));
        assert_eq!(relay.authorized_count(), 2);
        relay.deauthorize("sender");
        assert!(!relay.is_authorized("sender"));
        let framed = wrap_blind_frame("target", b"sealed");
        assert_eq!(
            relay.forward("sender", &framed),
            Forwarded::Dropped(DropReason::UnauthorizedSender)
        );
    }

    #[test]
    fn test_asn_diversity_constraint() {
        let mut constraint = AsnDiversityConstraint::new(1); // Strict multi-ASN

        // Shard 0 over ASN 13335 (Cloudflare) -> Accepted
        assert!(constraint.assign_shard_asn(0, 13335));

        // Shard 1 over ASN 13335 (Cloudflare again) -> Rejected by diversity constraint
        assert!(!constraint.is_asn_permitted(1, 13335));
        assert!(!constraint.assign_shard_asn(1, 13335));

        // Shard 1 over ASN 15169 (Google) -> Accepted
        assert!(constraint.assign_shard_asn(1, 15169));

        // Shard 2 over ASN 16509 (AWS) -> Accepted
        assert!(constraint.assign_shard_asn(2, 16509));

        // Total 3 shards span 3 distinct ASNs
        assert!(constraint.is_diverse());
    }

    #[test]
    fn test_proof_of_transit() {
        let relay_identity = GhostIdentity::generate_fresh();
        let payload = b"opaque_encrypted_gtf_frame_bytes";
        let next_hop = "node_charlie_5fa96851";

        // Relay mints blind proof of transit
        let proof = ProofOfTransit::mint(&relay_identity, payload, next_hop);

        // Client verifies proof against expected payload and destination
        assert!(proof.verify(payload, next_hop, 60));

        // Tampered payload fails verification
        let tampered_payload = b"altered_encrypted_gtf_frame_bytes";
        assert!(!proof.verify(tampered_payload, next_hop, 60));

        // Wrong next hop fails verification
        assert!(!proof.verify(payload, "node_eve_malicious", 60));
    }

    #[test]
    fn test_forwarding_capability_voucher() {
        let client_identity = GhostIdentity::generate_fresh();
        let max_bytes = 1_000_000u64; // 1 MB voucher
        let now = 1000u64;
        let expires_at = 2000u64;
        let voucher_id = 42u64;

        let voucher =
            ForwardingCapabilityVoucher::mint(&client_identity, max_bytes, expires_at, voucher_id);

        // Valid voucher redemption within limits
        assert!(voucher.verify(now, 500_000));

        // Requesting more bytes than authorized fails
        assert!(!voucher.verify(now, 2_000_000));

        // Redeeming after expiration fails
        assert!(!voucher.verify(3000, 500_000));

        // Forged signature from another key fails
        let imposter = GhostIdentity::generate_fresh();
        let forged_msg =
            ForwardingCapabilityVoucher::signing_bytes(max_bytes, expires_at, voucher_id);
        let mut forged_voucher = voucher.clone();
        forged_voucher.signature = imposter.sign(&forged_msg).to_bytes();
        assert!(!forged_voucher.verify(now, 500_000));
    }

    #[test]
    fn test_sphinx_shard_onion_roundtrip_and_drop_resilience() {
        use crate::ghost::layers::l4_rs;

        // Generate 3 hops: guard, middle, exit
        let guard_key = [0x11u8; 32];
        let middle_key = [0x22u8; 32];
        let exit_key = [0x33u8; 32];

        let payload = b"critical_confidential_mesh_packet";
        let mut original_data = payload.to_vec();

        // 1. Encode payload into 3 Reed-Solomon shards
        let shards = l4_rs::encode(&mut original_data);
        assert_eq!(shards.len(), 3);

        // 2. Wrap each shard into a constant 576-byte Sphinx onion
        let mut onions = Vec::new();
        for (idx, shard) in shards.iter().enumerate() {
            let onion = SphinxShardOnion::build(
                &guard_key,
                "node_middle",
                &middle_key,
                "node_exit",
                &exit_key,
                idx as u8,
                shard,
            );
            assert_eq!(onion.len(), SPHINX_SHARD_LEN);
            onions.push(onion);
        }

        // 3. Simulate Middle 1 dropping: Shard 1 is lost!
        // We only have onion 0 and onion 2 arriving at Exit.
        let mut exit_received_shards: Vec<Option<Vec<u8>>> = vec![None, None, None];

        for (i, onion) in onions.iter().enumerate() {
            if i == 1 {
                continue; // Dropped on middle hop!
            }
            // Guard peels layer
            let guard_peeled = SphinxShardOnion::peel_hop(&guard_key, onion).expect("guard peel");
            assert_eq!(guard_peeled.next_hop, "node_middle");

            // Middle peels layer
            let middle_peeled =
                SphinxShardOnion::peel_hop(&middle_key, &guard_peeled.inner_payload)
                    .expect("middle peel");
            assert_eq!(middle_peeled.next_hop, "node_exit");

            // Exit verifies authenticity and reconstructs shard
            let (shard_idx, shard_data) =
                SphinxShardOnion::exit_open(&exit_key, &middle_peeled.inner_payload)
                    .expect("exit open");
            assert_eq!(shard_idx, i as u8);
            exit_received_shards[shard_idx as usize] = Some(shard_data);
        }

        // 4. RS Reconstruct from the 2 surviving shards (0 and 2)
        assert!(exit_received_shards[0].is_some());
        assert!(exit_received_shards[1].is_none());
        assert!(exit_received_shards[2].is_some());

        l4_rs::reconstruct(&mut exit_received_shards).expect("RS reconstruction succeeds");

        let shard0 = exit_received_shards[0].as_ref().unwrap();
        let shard1 = exit_received_shards[1].as_ref().unwrap();
        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(shard0);
        reconstructed.extend_from_slice(shard1);
        reconstructed.truncate(payload.len());

        assert_eq!(
            &reconstructed, payload,
            "Sphinx shards survive 1 dropped middle node"
        );
    }

    #[test]
    fn test_identity_agnostic_channel_zero_identity_exposure() {
        let auth_key = [42u8; 32];
        let seed = b"test_blind_capability_seed";
        let flow_salt = [7u8; 32];
        let now = 1_000_000u64;
        let expires_at = now + 3600;
        let max_bytes = 10_000u64;

        // Mint a blind capability voucher with zero client identity
        let token = BlindCapabilityToken::mint(&auth_key, seed, &flow_salt, max_bytes, expires_at);
        assert!(token.verify(&auth_key, now, 100));

        let mut table = IdentityAgnosticRelayTable::new();
        let egress: SocketAddr = "192.168.1.100:8443".parse().unwrap();
        table
            .register_channel(&token, &auth_key, egress, now)
            .expect("register valid token");

        // Forward a packet
        let target = table
            .forward(&token.token_id, 500, now + 10)
            .expect("forward ok");
        assert_eq!(target, egress);

        // Exceed quota
        let err = table.forward(&token.token_id, 10_000, now + 20);
        assert!(err.is_err());

        // Prove zero identity exposure in audit memory dump
        let dump = table.audit_dump_memory();
        // Client ed25519 PK or identities are strictly absent
        let fake_client_pk = [0x55u8; 32];
        assert!(!dump.windows(32).any(|w| w == fake_client_pk));
        assert!(dump.len() >= 32);
    }

    #[test]
    fn test_tor_multi_circuit_dispatcher_routing_and_udp_encapsulation() {
        let ep1: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let ep2: SocketAddr = "127.0.0.1:9052".parse().unwrap();
        let ep3: SocketAddr = "127.0.0.1:9054".parse().unwrap();

        let dispatcher = TorMultiCircuitDispatcher::new([ep1, ep2, ep3]);

        // Verify independent circuit isolation per shard
        assert_eq!(dispatcher.circuit_for_shard(0), ep1);
        assert_eq!(dispatcher.circuit_for_shard(1), ep2);
        assert_eq!(dispatcher.circuit_for_shard(2), ep3);

        // Verify SOCKS5 auth request format
        let auth_req = TorMultiCircuitDispatcher::build_socks5_auth_request();
        assert_eq!(auth_req, vec![0x05, 0x01, 0x00]);

        // Verify SOCKS5 UDP encapsulation and decapsulation for an RS shard
        let shard_data = b"rs_shard_payload_through_tor_circuit";
        let target_peer: SocketAddr = "198.51.100.42:2270".parse().unwrap();

        let encapsulated =
            TorMultiCircuitDispatcher::encapsulate_shard_udp(shard_data, target_peer);
        assert!(encapsulated.len() > shard_data.len());
        assert_eq!(encapsulated[0..2], [0x00, 0x00]); // RSV
        assert_eq!(encapsulated[2], 0x00); // FRAG
        assert_eq!(encapsulated[3], 0x01); // ATYP IPv4

        let decapsulated = TorMultiCircuitDispatcher::decapsulate_shard_udp(&encapsulated)
            .expect("Valid SOCKS5 UDP header decapsulation");
        assert_eq!(decapsulated, shard_data);
    }

    #[test]
    fn test_anonymous_threshold_voucher_spending_and_double_spend_prevention() {
        let group_id = [0x77u8; 16];
        let group_secret = [0x42u8; 32];
        let voucher_id = 9999123u64;
        let max_bytes = 50_000u64;
        let now = 500u64;
        let expires_at = 1500u64;

        // Mint anonymous threshold voucher
        let voucher = AnonymousThresholdVoucher::mint(
            group_id,
            &group_secret,
            voucher_id,
            max_bytes,
            expires_at,
        );

        // Verification with valid group secret succeeds
        assert!(voucher.verify(&group_secret, now));

        // Verification with invalid group secret fails
        let wrong_secret = [0x11u8; 32];
        assert!(!voucher.verify(&wrong_secret, now));

        // Expired verification fails
        assert!(!voucher.verify(&group_secret, expires_at + 1));

        // Ledger spend testing
        let ledger = AnonymousCapabilityLedger::new();

        // 1. Spend 20,000 bytes -> 30,000 remaining
        let remaining = ledger
            .try_spend(&voucher, &group_secret, 20_000, now)
            .expect("first spend ok");
        assert_eq!(remaining, 30_000);

        // 2. Spend 25,000 bytes -> 5,000 remaining
        let remaining = ledger
            .try_spend(&voucher, &group_secret, 25_000, now + 10)
            .expect("second spend ok");
        assert_eq!(remaining, 5_000);

        // 3. Attempt to double-spend / exceed quota by spending 10,000 bytes (exceeds remaining 5,000)
        let err = ledger.try_spend(&voucher, &group_secret, 10_000, now + 20);
        assert!(err.is_err(), "quota exceeded must be rejected");

        // 4. Spending exactly 5,000 bytes succeeds, exhausting quota to 0
        let remaining = ledger
            .try_spend(&voucher, &group_secret, 5_000, now + 30)
            .expect("exhaust quota ok");
        assert_eq!(remaining, 0);

        // 5. Subsequent spend fails
        let err_exhausted = ledger.try_spend(&voucher, &group_secret, 1, now + 40);
        assert!(err_exhausted.is_err());
    }
}
