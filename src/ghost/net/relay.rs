//! Multi-hop Encrypted Packet Forwarding.
//!
//! Implements onion-style encrypted relay through intermediate GhostNet nodes,
//! ensuring intermediate nodes strip only their outer session layer while preserving
//! end-to-end payload confidentiality and forward secrecy.

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

pub const RELAY_MAGIC: &[u8; 4] = b"RLY!";

pub const BLIND_MAGIC: &[u8; 4] = b"BLND";

pub const MAX_HOPS: usize = 5;

pub const BUNDLE_EXPIRY_SECS: u64 = 3600; // 1 hour

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

pub const SPHINX_SHARD_LEN: usize = 576;
pub const SPHINX_HOP_TAG_LEN: usize = 16;
pub const SPHINX_MAX_HOP_NAME: usize = 32;

#[derive(Debug, Clone)]
pub struct PeeledSphinxHop {
    pub next_hop: String,
    pub inner_payload: Vec<u8>,
}

pub struct SphinxShardOnion;

impl SphinxShardOnion {
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
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut exit_plaintext = Vec::with_capacity(2 + shard_data.len());
        exit_plaintext.push(shard_idx);
        exit_plaintext.push(shard_data.len() as u8);
        exit_plaintext.extend_from_slice(shard_data);

        let mut exit_nonce = [0u8; 12];
        rng.fill_bytes(&mut exit_nonce);
        let exit_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(exit_key));
        let exit_ct = exit_cipher
            .encrypt(Nonce::from_slice(&exit_nonce), exit_plaintext.as_ref())
            .expect("seal exit");
        let mut exit_sealed = Vec::with_capacity(12 + exit_ct.len());
        exit_sealed.extend_from_slice(&exit_nonce);
        exit_sealed.extend_from_slice(&exit_ct);

        let mut middle_plaintext = Vec::with_capacity(SPHINX_MAX_HOP_NAME + exit_sealed.len());
        let mut exit_hop_bytes = [0u8; SPHINX_MAX_HOP_NAME];
        let bytes_to_copy = exit_hop.len().min(SPHINX_MAX_HOP_NAME);
        exit_hop_bytes[..bytes_to_copy].copy_from_slice(&exit_hop.as_bytes()[..bytes_to_copy]);
        middle_plaintext.extend_from_slice(&exit_hop_bytes);
        middle_plaintext.extend_from_slice(&exit_sealed);

        let mut middle_nonce = [0u8; 12];
        rng.fill_bytes(&mut middle_nonce);
        let middle_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(middle_key));
        let middle_ct = middle_cipher
            .encrypt(Nonce::from_slice(&middle_nonce), middle_plaintext.as_ref())
            .expect("seal middle");
        let mut middle_sealed = Vec::with_capacity(12 + middle_ct.len());
        middle_sealed.extend_from_slice(&middle_nonce);
        middle_sealed.extend_from_slice(&middle_ct);

        let mut guard_plaintext = Vec::with_capacity(SPHINX_MAX_HOP_NAME + middle_sealed.len());
        let mut middle_hop_bytes = [0u8; SPHINX_MAX_HOP_NAME];
        let bytes_to_copy_m = middle_hop.len().min(SPHINX_MAX_HOP_NAME);
        middle_hop_bytes[..bytes_to_copy_m]
            .copy_from_slice(&middle_hop.as_bytes()[..bytes_to_copy_m]);
        guard_plaintext.extend_from_slice(&middle_hop_bytes);
        guard_plaintext.extend_from_slice(&middle_sealed);

        let mut guard_nonce = [0u8; 12];
        rng.fill_bytes(&mut guard_nonce);
        let guard_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(guard_key));
        let guard_ct = guard_cipher
            .encrypt(Nonce::from_slice(&guard_nonce), guard_plaintext.as_ref())
            .expect("seal guard");
        let mut guard_sealed = Vec::with_capacity(12 + guard_ct.len());
        guard_sealed.extend_from_slice(&guard_nonce);
        guard_sealed.extend_from_slice(&guard_ct);

        if guard_sealed.len() > SPHINX_SHARD_LEN - 2 {
            panic!(
                "Sphinx shard too large for 576-byte frame: {} > {}",
                guard_sealed.len(),
                SPHINX_SHARD_LEN - 2
            );
        }
        let mut out = vec![0u8; SPHINX_SHARD_LEN];
        let len_bytes = (guard_sealed.len() as u16).to_be_bytes();
        out[..2].copy_from_slice(&len_bytes);
        let copy_len = guard_sealed.len();
        out[2..2 + copy_len].copy_from_slice(&guard_sealed);
        rng.fill_bytes(&mut out[2 + copy_len..]);
        out
    }

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

        if payload_to_decrypt.len() < 12 {
            return None;
        }
        let nonce = Nonce::from_slice(&payload_to_decrypt[..12]);
        let ct = &payload_to_decrypt[12..];

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(hop_key));
        let pt = cipher.decrypt(nonce, ct).ok()?;
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

    pub fn exit_open(exit_key: &[u8; 32], ciphertext: &[u8]) -> Option<(u8, Vec<u8>)> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        if ciphertext.len() < 12 {
            return None;
        }
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let ct = &ciphertext[12..];

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(exit_key));
        let pt = cipher.decrypt(nonce, ct).ok()?;
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

    pub fn verify(&self, now: u64, requested_bytes: u64) -> bool {
        if now > self.expires_at || requested_bytes > self.max_bytes {
            return false;
        }
        let msg = Self::signing_bytes(self.max_bytes, self.expires_at, self.voucher_id);
        verify_peer_signature(&self.client_pk, &msg, &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindCapabilityToken {
    pub token_id: [u8; 32],
    pub max_bytes: u64,
    pub expires_at: u64,
    pub auth_tag: [u8; 32],
}

impl BlindCapabilityToken {
    pub fn compute_token_id(seed: &[u8], flow_salt: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"GGN_BLIND_TOKEN_ID_V1");
        h.update(seed);
        h.update(flow_salt);
        h.finalize().into()
    }

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
        h.update(max_bytes.to_be_bytes());
        h.update(expires_at.to_be_bytes());
        h.finalize().into()
    }

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

    pub fn verify(&self, auth_key: &[u8; 32], now: u64, requested_bytes: u64) -> bool {
        if now > self.expires_at || requested_bytes > self.max_bytes {
            return false;
        }
        let expected =
            Self::compute_auth_tag(auth_key, &self.token_id, self.max_bytes, self.expires_at);
        subtle::ConstantTimeEq::ct_eq(&self.auth_tag[..], &expected[..]).into()
    }
}

#[derive(Debug, Clone)]
pub struct IdentityAgnosticChannel {
    pub egress_endpoint: SocketAddr,
    pub max_bytes: u64,
    pub forwarded_bytes: u64,
    pub expires_at: u64,
}

#[derive(Debug, Default)]
pub struct IdentityAgnosticRelayTable {
    channels: std::collections::HashMap<[u8; 32], IdentityAgnosticChannel>,
}

impl IdentityAgnosticRelayTable {
    pub fn new() -> Self {
        Self::default()
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnDiversityConstraint {
    pub max_shards_per_asn: usize,
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

    pub fn is_asn_permitted(&self, shard_index: u8, candidate_asn: u32) -> bool {
        let count = self
            .assigned_asns
            .iter()
            .filter(|(idx, asn)| *idx != shard_index && *asn == candidate_asn)
            .count();
        count < self.max_shards_per_asn
    }

    pub fn assign_shard_asn(&mut self, shard_index: u8, asn: u32) -> bool {
        if self.is_asn_permitted(shard_index, asn) {
            self.assigned_asns.retain(|(idx, _)| *idx != shard_index);
            self.assigned_asns.push((shard_index, asn));
            true
        } else {
            false
        }
    }

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
        let deadline = if self.max_delay == Duration::ZERO {
            Duration::ZERO
        } else {
            Duration::from_millis(crate::ghost::net::mix_batch_delay_ms())
        };
        self.items
            .first()
            .map(|(created, _)| created.elapsed() >= deadline)
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

#[derive(Debug, Clone)]
pub struct RelayHeader {
    pub remaining_hops: u32,
    pub next_hop_fingerprint: String,
    pub inner_payload: Vec<u8>,
}

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

pub fn build_encrypted_onion_route(
    route: &[&str],
    hop_keys: &[[u8; 32]],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if route.len() != hop_keys.len()
        || route.len() < 2
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
        let rly = build_relay_packet(route[index], remaining, &inner);
        if index > 1 {
            let nonce = crate::ghost::layers::l2_aead::random_xnonce();
            let mut sealed = rly;
            crate::ghost::layers::l2_aead::xchacha_seal_in_place(
                &hop_keys[index - 1],
                &nonce,
                0,
                crate::ghost::layers::l2_aead::NonceDirection::InitiatorToResponder,
                &mut sealed,
            )
            .ok()?;
            let mut layer = Vec::with_capacity(ONION_SEAL_MAGIC.len() + 12 + sealed.len());
            layer.extend_from_slice(ONION_SEAL_MAGIC);
            layer.extend_from_slice(&nonce);
            layer.extend_from_slice(&sealed);
            inner = layer;
        } else {
            inner = rly;
        }
    }
    Some(inner)
}

pub const ONION_SEAL_MAGIC: &[u8; 4] = b"ONS1";

pub fn peel_encrypted_relay_layer(hop_key: &[u8; 32], encrypted_inner: &[u8]) -> Option<Vec<u8>> {
    let encrypted_inner = encrypted_inner
        .strip_prefix(ONION_SEAL_MAGIC)
        .unwrap_or(encrypted_inner);
    if encrypted_inner.len() < 12 + 16 {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&encrypted_inner[..12]);
    let mut ct = encrypted_inner[12..].to_vec();
    crate::ghost::layers::l2_aead::xchacha_open(
        hop_key,
        &nonce,
        0,
        crate::ghost::layers::l2_aead::NonceDirection::InitiatorToResponder,
        &mut ct,
    )
    .ok()
    .map(|pt| pt.to_vec())
}

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

#[derive(Debug, Clone)]
pub struct Bundle {
    pub target_fingerprint: String,
    pub encrypted_shards: Vec<Vec<u8>>,
    pub session_hash: [u8; 4],
    pub created_at: Instant,
    pub retries: u8,
    pub remaining_route: Vec<String>,
}

pub struct BundleBuffer {
    pub bundles: DashMap<String, Vec<Bundle>>,
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

    pub fn enqueue(&self, bundle: Bundle) {
        let fp = bundle.target_fingerprint.clone();
        self.bundles.entry(fp.clone()).or_default().push(bundle);
        debug!(
            "Bundle enqueued for {}, buffer size: {}",
            fp,
            self.bundles.len()
        );
    }

    pub fn dequeue_for(&self, peer_fp: &str) -> Vec<Bundle> {
        self.bundles
            .remove(peer_fp)
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    pub fn expire_old(&self) -> usize {
        let mut expired = 0usize;
        let cutoff = Duration::from_secs(BUNDLE_EXPIRY_SECS);
        self.bundles.retain(|_, bundles| {
            bundles.retain(|b| {
                let keep = b.created_at.elapsed() < cutoff;
                if !keep {
                    expired = expired.saturating_add(1);
                }
                keep
            });
            !bundles.is_empty()
        });
        expired
    }

    pub fn has_pending(&self, peer_fp: &str) -> bool {
        self.bundles
            .get(peer_fp)
            .map(|b| !b.is_empty())
            .unwrap_or(false)
    }
}

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

    let session_entry = match sessions.get(next_fp) {
        Some(s) => s,
        None => {
            warn!("No session for next hop {}", next_fp);
            return false;
        }
    };

    let material = session_entry.seal_material();
    let sh = session_entry.session_hash;
    let use_bulk = session_entry.use_bulk;
    drop(session_entry);

    let new_remaining = header.remaining_hops - 1;

    let inner_relay = if new_remaining > 0 {
        header.inner_payload.clone()
    } else {
        let mut direct = Vec::with_capacity(4 + header.inner_payload.len());
        direct.extend_from_slice(b"DIR!");
        direct.extend_from_slice(&header.inner_payload);
        direct
    };

    let mut framed = inner_relay;
    let needs_padding = if framed.len() % 2 != 0 { 1 } else { 0 };
    if needs_padding > 0 {
        framed.push(0);
    }
    let tail = if use_bulk {
        [0u8; crate::ghost::net::JITTER_MAX]
    } else {
        crate::ghost::net::random_tail()
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

    let tag = if framed.len() >= 16 {
        let mut t = [0u8; 16];
        if let Some(slice) = framed.get(framed.len().saturating_sub(16)..) {
            if slice.len() == 16 {
                t.copy_from_slice(slice);
            }
        }
        t
    } else {
        [0u8; 16]
    };
    let shards = l4_rs::encode(&mut framed);

    for (i, shard) in shards.iter().take(3).enumerate() {
        let shard_data = frame_shard(shard);
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

            let expired = bundle_buffer.expire_old();
            if expired > 0 {
                debug!("Expired {} stale bundles", expired);
            }

            let pending_peers: Vec<String> = bundle_buffer
                .bundles
                .iter()
                .map(|e| e.key().clone())
                .collect();

            for fp in pending_peers {
                let has_route = sessions.contains_key(&fp) && peer_addrs.contains_key(&fp);
                if has_route {
                    let bundles = bundle_buffer.dequeue_for(&fp);
                    for bundle in bundles {
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

#[derive(Debug, Clone)]
pub struct WanRateLimiter {
    buckets: Arc<DashMap<std::net::IpAddr, (f64, Instant)>>,
    capacity: f64,
    refill_per_sec: f64,
    max_entries: usize,
}

impl Default for WanRateLimiter {
    fn default() -> Self {
        Self::new(8.0, 2.0)
    }
}

impl WanRateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            capacity: capacity.max(1.0),
            refill_per_sec: refill_per_sec.max(0.1),
            max_entries: 4096,
        }
    }

    pub fn allow(
        &self,
        ip: std::net::IpAddr,
        pending_hs_len: usize,
        max_pending_hs: usize,
    ) -> bool {
        if pending_hs_len < max_pending_hs / 2 {
            return true;
        }
        self.allow_strict(ip)
    }

    pub fn allow_strict(&self, ip: std::net::IpAddr) -> bool {
        let now = Instant::now();
        if self.buckets.len() >= self.max_entries && !self.buckets.contains_key(&ip) {
            self.buckets
                .retain(|_, (_, last)| now.duration_since(*last) < Duration::from_secs(60));
            if self.buckets.len() >= self.max_entries {
                return false;
            }
        }
        let mut entry = self
            .buckets
            .entry(ip)
            .or_insert_with(|| (self.capacity, now));
        let (tokens, last) = entry.value_mut();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.capacity);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn issue_cookie(secret: &[u8; 32], ip: std::net::IpAddr, now_secs: u64) -> [u8; 16] {
        use sha2::{Digest, Sha256};
        let window = now_secs / 60;
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"GGN_HS_COOKIE_V1");
        hasher.update(window.to_be_bytes());
        match ip {
            std::net::IpAddr::V4(v4) => hasher.update(v4.octets()),
            std::net::IpAddr::V6(v6) => hasher.update(v6.octets()),
        };
        let hash = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&hash[..16]);
        out
    }

    pub fn verify_cookie(
        secret: &[u8; 32],
        ip: std::net::IpAddr,
        cookie: &[u8],
        now_secs: u64,
    ) -> bool {
        if cookie.len() != 16 {
            return false;
        }
        let current = Self::issue_cookie(secret, ip, now_secs);
        if cookie == current {
            return true;
        }
        if now_secs >= 60 {
            let prev = Self::issue_cookie(secret, ip, now_secs - 60);
            if cookie == prev {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(pub [u8; 16]);

impl CircuitId {
    pub fn random() -> Self {
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        Self(id)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry {
    pub next_hop: Option<String>,
    pub outgoing_circuit_id: CircuitId,
    pub hop_key: [u8; 32],
}

#[derive(Debug, Default)]
pub struct CircuitSwapTable {
    entries: DashMap<CircuitId, SwapEntry>,
}

impl CircuitSwapTable {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn insert(
        &self,
        in_id: CircuitId,
        next_hop: Option<String>,
        out_id: CircuitId,
        hop_key: [u8; 32],
    ) {
        self.entries.insert(
            in_id,
            SwapEntry {
                next_hop,
                outgoing_circuit_id: out_id,
                hop_key,
            },
        );
    }

    pub fn lookup(&self, in_id: &CircuitId) -> Option<SwapEntry> {
        self.entries.get(in_id).map(|e| e.value().clone())
    }

    pub fn remove(&self, in_id: &CircuitId) -> Option<SwapEntry> {
        self.entries.remove(in_id).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn swap_and_peel(
        &self,
        in_id: &CircuitId,
        sealed_cell: &[u8],
    ) -> Option<(Option<String>, CircuitId, Vec<u8>)> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        if sealed_cell.len() < 12 + 16 {
            return None;
        }
        let entry = self.entries.get(in_id)?;
        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&entry.hop_key));
        let nonce = Nonce::from_slice(&sealed_cell[..12]);
        let plaintext = cipher.decrypt(nonce, &sealed_cell[12..]).ok()?;
        Some((entry.next_hop.clone(), entry.outgoing_circuit_id, plaintext))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendPqCell {
    pub circuit_id: CircuitId,
    pub next_hop: Option<String>,
    pub client_x25519_pk: [u8; 32],
    pub ml_kem_ct: Vec<u8>,
}

impl ExtendPqCell {
    const MAGIC: &'static [u8; 4] = b"XPQ1";

    fn derive_hop_key(
        circuit_id: &CircuitId,
        x25519_ss: &[u8; 32],
        ml_kem_ss: &[u8],
    ) -> Option<[u8; 32]> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut ikm = Vec::with_capacity(32 + ml_kem_ss.len());
        ikm.extend_from_slice(x25519_ss);
        ikm.extend_from_slice(ml_kem_ss);

        let hk = Hkdf::<Sha256>::new(Some(circuit_id.as_bytes()), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"GGN_TELESCOPING_PQ_V1", &mut okm).ok()?;
        Some(okm)
    }

    pub fn initiate(
        circuit_id: CircuitId,
        next_hop: Option<String>,
        hop_x25519_pk: &[u8; 32],
        hop_ml_kem_ek: &[u8],
    ) -> Option<(Self, [u8; 32])> {
        use ml_kem::kem::{Encapsulate, TryKeyInit};
        use ml_kem::MlKem768;

        let esk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_x25519_pk = x25519_dalek::PublicKey::from(&esk).to_bytes();
        let x25519_ss = esk.diffie_hellman(&x25519_dalek::PublicKey::from(*hop_x25519_pk));

        let ek = ml_kem::EncapsulationKey::<MlKem768>::new_from_slice(hop_ml_kem_ek).ok()?;
        let (ct, ml_kem_ss) = ek.encapsulate();

        let hop_key =
            Self::derive_hop_key(&circuit_id, x25519_ss.as_bytes(), ml_kem_ss.as_slice())?;
        let cell = Self {
            circuit_id,
            next_hop,
            client_x25519_pk,
            ml_kem_ct: ct.as_slice().to_vec(),
        };
        Some((cell, hop_key))
    }

    pub fn accept(
        &self,
        hop_x25519_sk: &x25519_dalek::StaticSecret,
        hop_ml_kem_dk: &ml_kem::DecapsulationKey<ml_kem::MlKem768>,
    ) -> Option<[u8; 32]> {
        use ml_kem::kem::Decapsulate;
        use ml_kem::MlKem768;

        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(self.ml_kem_ct.as_slice()).ok()?;
        let ml_kem_ss = hop_ml_kem_dk.decapsulate(&ct);
        let x25519_ss =
            hop_x25519_sk.diffie_hellman(&x25519_dalek::PublicKey::from(self.client_x25519_pk));
        Self::derive_hop_key(&self.circuit_id, x25519_ss.as_bytes(), ml_kem_ss.as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let next_bytes = self.next_hop.as_deref().unwrap_or("").as_bytes();
        let mut out =
            Vec::with_capacity(4 + 16 + 2 + next_bytes.len() + 32 + 2 + self.ml_kem_ct.len());
        out.extend_from_slice(Self::MAGIC);
        out.extend_from_slice(self.circuit_id.as_bytes());
        out.extend_from_slice(&(next_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(next_bytes);
        out.extend_from_slice(&self.client_x25519_pk);
        out.extend_from_slice(&(self.ml_kem_ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ml_kem_ct);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 + 16 + 2 + 32 + 2 || &data[..4] != Self::MAGIC {
            return None;
        }
        let mut cid = [0u8; 16];
        cid.copy_from_slice(&data[4..20]);
        let next_len = u16::from_be_bytes([data[20], data[21]]) as usize;
        let mut idx = 22;
        if data.len() < idx + next_len + 32 + 2 {
            return None;
        }
        let next_hop = if next_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&data[idx..idx + next_len])
                    .ok()?
                    .to_string(),
            )
        };
        idx += next_len;
        let mut client_x25519_pk = [0u8; 32];
        client_x25519_pk.copy_from_slice(&data[idx..idx + 32]);
        idx += 32;
        let ct_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() != idx + ct_len {
            return None;
        }
        Some(Self {
            circuit_id: CircuitId(cid),
            next_hop,
            client_x25519_pk,
            ml_kem_ct: data[idx..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelescopingHop {
    pub peer_fp: String,
    pub circuit_id: CircuitId,
    pub hop_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TelescopingCircuit {
    entry_circuit_id: CircuitId,
    hops: Vec<TelescopingHop>,
}

impl TelescopingCircuit {
    pub fn new(entry_circuit_id: CircuitId) -> Self {
        Self {
            entry_circuit_id,
            hops: Vec::new(),
        }
    }

    pub fn extend_hop(&mut self, peer_fp: String, circuit_id: CircuitId, hop_key: [u8; 32]) {
        self.hops.push(TelescopingHop {
            peer_fp,
            circuit_id,
            hop_key,
        });
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn entry_id(&self) -> CircuitId {
        self.entry_circuit_id
    }

    pub fn seal_onion(&self, payload: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        if self.hops.is_empty() {
            return None;
        }
        let mut current = payload.to_vec();
        for hop in self.hops.iter().rev() {
            let mut nonce_bytes = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
            let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&hop.hop_key));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), current.as_slice())
                .ok()?;
            let mut layer = Vec::with_capacity(12 + ct.len());
            layer.extend_from_slice(&nonce_bytes);
            layer.extend_from_slice(&ct);
            current = layer;
        }
        Some(current)
    }
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

const RELAY_ENVELOPE_MIN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindFrame<'a> {
    pub target_fingerprint: &'a str,
    pub opaque: &'a [u8],
}

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

pub fn wrap_blind_frame(target_fp: &str, opaque: &[u8]) -> Vec<u8> {
    build_envelope(BLIND_MAGIC, target_fp, 0, opaque)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    NotAnEnvelope,
    NotBlindForward,
    UnauthorizedSender,
    UnknownTarget,
    QuotaExceeded,
    Loop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forwarded {
    Deliver { dest: SocketAddr, bytes: Vec<u8> },
    Dropped(DropReason),
}

pub struct DerpRelay {
    authorized: Arc<DashMap<String, SocketAddr>>,
    candidates: Arc<DashMap<String, SocketAddr>>,
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

    pub fn add_relay_candidate(&self, fp: &str, addr: SocketAddr) {
        self.candidates.insert(fp.to_string(), addr);
    }

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

    pub fn pick_relay(&self, our_fp: &str, target_fp: &str) -> Option<(String, SocketAddr)> {
        self.relay_candidates()
            .into_iter()
            .find(|(fp, _)| fp != our_fp && fp != target_fp)
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.forwarded_frames.load(Ordering::Relaxed),
            self.forwarded_bytes.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    pub fn forward(&self, from_fp: &str, payload: &[u8]) -> Forwarded {
        let Some(frame) = parse_blind_frame(payload) else {
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
        Forwarded::Deliver {
            dest,
            bytes: frame.opaque.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TorMultiCircuitDispatcher {
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

    pub fn circuit_for_shard(&self, shard_index: u8) -> SocketAddr {
        self.circuit_endpoints[(shard_index as usize) % 3]
    }

    pub fn build_socks5_auth_request() -> Vec<u8> {
        vec![0x05, 0x01, 0x00]
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousThresholdVoucher {
    pub group_id: [u8; 16],
    pub voucher_id: u64,
    pub max_bytes: u64,
    pub expires_at: u64,
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
        hasher.update(group_id);
        hasher.update(reconstructed_group_secret);
        hasher.update(voucher_id.to_be_bytes());
        hasher.update(max_bytes.to_be_bytes());
        hasher.update(expires_at.to_be_bytes());
        let group_commitment = hasher.finalize().into();

        Self {
            group_id,
            voucher_id,
            max_bytes,
            expires_at,
            group_commitment,
        }
    }

    pub fn verify(&self, expected_group_secret: &[u8; 32], current_time: u64) -> bool {
        if current_time > self.expires_at {
            return false;
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ANONYMOUS_THRESHOLD_VOUCHER_V1");
        hasher.update(self.group_id);
        hasher.update(expected_group_secret);
        hasher.update(self.voucher_id.to_be_bytes());
        hasher.update(self.max_bytes.to_be_bytes());
        hasher.update(self.expires_at.to_be_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        expected == self.group_commitment
    }
}

#[derive(Debug, Default)]
pub struct AnonymousCapabilityLedger {
    spent_table: DashMap<u64, u64>,
}

impl AnonymousCapabilityLedger {
    pub fn new() -> Self {
        Self::default()
    }

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

        let opaque: Vec<u8> = (0..512u32).map(|i| (i * 31 % 251) as u8).collect();
        let framed = wrap_blind_frame("target", &opaque);

        match relay.forward("sender", &framed) {
            Forwarded::Deliver { dest, bytes } => {
                assert_eq!(dest, addr("10.0.0.2:2"));
                assert_eq!(bytes, opaque);
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

        let picked = relay.pick_relay("us", "target").expect("a usable relay");
        assert_ne!(picked.0, "us");
        assert_ne!(picked.0, "target");
        assert_eq!(picked.0, "alpha", "unauthenticated relays break ties by fp");

        relay.authorize("beta", addr("10.0.0.4:4"));
        assert_eq!(relay.pick_relay("us", "target").unwrap().0, "beta");
        assert_eq!(
            relay.relay_candidates().first().map(|(fp, _)| fp.as_str()),
            Some("beta")
        );

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

        assert!(constraint.assign_shard_asn(0, 13335));

        assert!(!constraint.is_asn_permitted(1, 13335));
        assert!(!constraint.assign_shard_asn(1, 13335));

        assert!(constraint.assign_shard_asn(1, 15169));

        assert!(constraint.assign_shard_asn(2, 16509));

        assert!(constraint.is_diverse());
    }

    #[test]
    fn test_proof_of_transit() {
        let relay_identity = GhostIdentity::generate_fresh();
        let payload = b"opaque_encrypted_gtf_frame_bytes";
        let next_hop = "node_charlie_5fa96851";

        let proof = ProofOfTransit::mint(&relay_identity, payload, next_hop);

        assert!(proof.verify(payload, next_hop, 60));

        let tampered_payload = b"altered_encrypted_gtf_frame_bytes";
        assert!(!proof.verify(tampered_payload, next_hop, 60));

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

        assert!(voucher.verify(now, 500_000));

        assert!(!voucher.verify(now, 2_000_000));

        assert!(!voucher.verify(3000, 500_000));

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

        let guard_key = [0x11u8; 32];
        let middle_key = [0x22u8; 32];
        let exit_key = [0x33u8; 32];

        let payload = b"critical_confidential_mesh_packet";
        let mut original_data = payload.to_vec();

        let shards = l4_rs::encode(&mut original_data);
        assert_eq!(shards.len(), 3);

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

        let mut exit_received_shards: Vec<Option<Vec<u8>>> = vec![None, None, None];

        for (i, onion) in onions.iter().enumerate() {
            if i == 1 {
                continue; // Dropped on middle hop!
            }
            let guard_peeled = SphinxShardOnion::peel_hop(&guard_key, onion).expect("guard peel");
            assert_eq!(guard_peeled.next_hop, "node_middle");

            let middle_peeled =
                SphinxShardOnion::peel_hop(&middle_key, &guard_peeled.inner_payload)
                    .expect("middle peel");
            assert_eq!(middle_peeled.next_hop, "node_exit");

            let (shard_idx, shard_data) =
                SphinxShardOnion::exit_open(&exit_key, &middle_peeled.inner_payload)
                    .expect("exit open");
            assert_eq!(shard_idx, i as u8);
            exit_received_shards[shard_idx as usize] = Some(shard_data);
        }

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

        let token = BlindCapabilityToken::mint(&auth_key, seed, &flow_salt, max_bytes, expires_at);
        assert!(token.verify(&auth_key, now, 100));

        let mut table = IdentityAgnosticRelayTable::new();
        let egress: SocketAddr = "192.168.1.100:8443".parse().unwrap();
        table
            .register_channel(&token, &auth_key, egress, now)
            .expect("register valid token");

        let target = table
            .forward(&token.token_id, 500, now + 10)
            .expect("forward ok");
        assert_eq!(target, egress);

        let err = table.forward(&token.token_id, 10_000, now + 20);
        assert!(err.is_err());

        let dump = table.audit_dump_memory();
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

        assert_eq!(dispatcher.circuit_for_shard(0), ep1);
        assert_eq!(dispatcher.circuit_for_shard(1), ep2);
        assert_eq!(dispatcher.circuit_for_shard(2), ep3);

        let auth_req = TorMultiCircuitDispatcher::build_socks5_auth_request();
        assert_eq!(auth_req, vec![0x05, 0x01, 0x00]);

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

        let voucher = AnonymousThresholdVoucher::mint(
            group_id,
            &group_secret,
            voucher_id,
            max_bytes,
            expires_at,
        );

        assert!(voucher.verify(&group_secret, now));

        let wrong_secret = [0x11u8; 32];
        assert!(!voucher.verify(&wrong_secret, now));

        assert!(!voucher.verify(&group_secret, expires_at + 1));

        let ledger = AnonymousCapabilityLedger::new();

        let remaining = ledger
            .try_spend(&voucher, &group_secret, 20_000, now)
            .expect("first spend ok");
        assert_eq!(remaining, 30_000);

        let remaining = ledger
            .try_spend(&voucher, &group_secret, 25_000, now + 10)
            .expect("second spend ok");
        assert_eq!(remaining, 5_000);

        let err = ledger.try_spend(&voucher, &group_secret, 10_000, now + 20);
        assert!(err.is_err(), "quota exceeded must be rejected");

        let remaining = ledger
            .try_spend(&voucher, &group_secret, 5_000, now + 30)
            .expect("exhaust quota ok");
        assert_eq!(remaining, 0);

        let err_exhausted = ledger.try_spend(&voucher, &group_secret, 1, now + 40);
        assert!(err_exhausted.is_err());
    }

    #[test]
    fn test_telescoping_pq_circuit_isolation_and_swap() {
        use ml_kem::kem::{Kem, KeyExport};
        use ml_kem::MlKem768;

        let gen_hop_keys = || {
            let x_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let x_pk = x25519_dalek::PublicKey::from(&x_sk).to_bytes();
            let (dk, ek) = MlKem768::generate_keypair();
            let ek_bytes = ek.to_bytes().as_slice().to_vec();
            (x_sk, x_pk, dk, ek_bytes)
        };

        let (g_xsk, g_xpk, g_dk, g_ek) = gen_hop_keys();
        let (m_xsk, m_xpk, m_dk, m_ek) = gen_hop_keys();
        let (e_xsk, e_xpk, e_dk, e_ek) = gen_hop_keys();

        let cid_cg = CircuitId::random();
        let cid_gm = CircuitId::random();
        let cid_me = CircuitId::random();

        let (cell_g, key_g_client) =
            ExtendPqCell::initiate(cid_cg, Some("middle_fp".into()), &g_xpk, &g_ek)
                .expect("guard extend");
        let parsed_g = ExtendPqCell::from_bytes(&cell_g.to_bytes()).expect("parse guard cell");
        let key_g_relay = parsed_g.accept(&g_xsk, &g_dk).expect("guard accept");
        assert_eq!(key_g_client, key_g_relay);

        let (cell_m, key_m_client) =
            ExtendPqCell::initiate(cid_gm, Some("exit_fp".into()), &m_xpk, &m_ek)
                .expect("middle extend");
        let key_m_relay = cell_m.accept(&m_xsk, &m_dk).expect("middle accept");
        assert_eq!(key_m_client, key_m_relay);

        let (cell_e, key_e_client) =
            ExtendPqCell::initiate(cid_me, None, &e_xpk, &e_ek).expect("exit extend");
        let key_e_relay = cell_e.accept(&e_xsk, &e_dk).expect("exit accept");
        assert_eq!(key_e_client, key_e_relay);

        let guard_table = CircuitSwapTable::new();
        guard_table.insert(cid_cg, Some("middle_fp".into()), cid_gm, key_g_relay);

        let middle_table = CircuitSwapTable::new();
        middle_table.insert(cid_gm, Some("exit_fp".into()), cid_me, key_m_relay);

        let exit_table = CircuitSwapTable::new();
        exit_table.insert(cid_me, None, cid_me, key_e_relay);

        let mut circuit = TelescopingCircuit::new(cid_cg);
        circuit.extend_hop("guard_fp".into(), cid_cg, key_g_client);
        circuit.extend_hop("middle_fp".into(), cid_gm, key_m_client);
        circuit.extend_hop("exit_fp".into(), cid_me, key_e_client);
        assert_eq!(circuit.hop_count(), 3);

        let payload = b"secret_telescoping_pq_payload";
        let onion = circuit.seal_onion(payload).expect("seal onion");

        let (next1, out_id1, body1) = guard_table
            .swap_and_peel(&cid_cg, &onion)
            .expect("guard peel");
        assert_eq!(next1.as_deref(), Some("middle_fp"));
        assert_eq!(out_id1, cid_gm);
        assert!(guard_table.lookup(&cid_me).is_none());

        let (next2, out_id2, body2) = middle_table
            .swap_and_peel(&out_id1, &body1)
            .expect("middle peel");
        assert_eq!(next2.as_deref(), Some("exit_fp"));
        assert_eq!(out_id2, cid_me);
        assert!(middle_table.lookup(&cid_cg).is_none());

        let (next3, _out_id3, plaintext) = exit_table
            .swap_and_peel(&out_id2, &body2)
            .expect("exit peel");
        assert!(next3.is_none());
        assert_eq!(plaintext.as_slice(), payload);
    }
}
