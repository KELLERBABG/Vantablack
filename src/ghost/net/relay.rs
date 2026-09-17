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
        if now > self.expires_at
            || self.subject != expected_subject
            || self.scope != required_scope
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
        Some(Self { issuer_pk, subject, scope, expires_at, signature })
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
        let capability = ExitCapability::issue(&issuer, subject, scope, 200)
            .expect("valid capability");
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
}
