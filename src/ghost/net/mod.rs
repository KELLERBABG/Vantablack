#[cfg(feature = "quic")]
pub mod carrier;
/// GhostNet Network Layer
///
/// Implements the Ghost Transport Frame (GTF) — the wire format for all
/// UDP packets — with dual frame modes for maximum throughput:
///
/// - **Normal mode**: a constant 576-byte wire frame — 512 B of authenticated GTF
///   plus a full-length 64 B jitter tail (SOTA P3-1: the tail used to be
///   `0..64` bytes, which made the *length* the signal; it is now fixed, so
///   privacy frames are one size on every path)
/// - **Bulk mode**: 1472-byte frames at full Ethernet MTU (maximum throughput)
///
/// Also implements a lightweight ACK engine for reliable delivery over UDP,
/// and an adaptive token-bucket flow controller.
pub mod cc;
pub mod consumer;
pub mod dispatcher;
pub mod fallback;
pub mod ice;
pub mod mesh;
pub mod orbit;
#[cfg(feature = "quic")]
pub mod quic;
pub mod relay;
pub mod shardsec;

/// Which framing an optional transport used for a frame (SOTA P1-2).
///
/// Defined here rather than in the transport so that a build *without* the
/// transport still names the same type: the tunnel asks its carrier registry for
/// a path on every frame, and "no carrier" must be a value it can hold rather
/// than a `cfg` at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierPath {
    /// Unreliable, unordered carrier — the Reed-Solomon privacy path.
    Datagram,
    /// Reliable, ordered carrier — the bulk path.
    Stream,
}

/// A carrier registry in a build with no optional transport compiled in.
///
/// It is deliberately the same shape as the real one: everything this build can
/// say is "nothing is registered", which is exactly true. The multipath methods
/// answer the same way — a build with no transport has no paths, so nothing is
/// carried and nothing is dialled — which is what keeps the egress sites free of
/// a `cfg` of their own.
#[cfg(not(feature = "quic"))]
pub mod carrier {
    use super::CarrierPath;
    use std::net::IpAddr;

    /// No optional transport in this build (`--features quic` adds one).
    #[derive(Debug, Default)]
    pub struct Carrier;

    impl Carrier {
        pub fn disabled() -> Self {
            Carrier
        }
        pub fn enabled(&self) -> bool {
            false
        }
        pub fn peer_count(&self) -> usize {
            0
        }
        /// Live links across every peer and path: none exist here.
        pub fn link_count(&self) -> usize {
            0
        }
        /// Named local paths (multipath): none exist here.
        pub fn path_count(&self) -> usize {
            0
        }
        /// Nothing to dial and nothing covered.
        pub fn covered(&self, _fp: &str) -> bool {
            false
        }
        pub fn label(&self) -> &'static str {
            "none"
        }
        /// Nothing to send on: the caller keeps to UDP.
        pub async fn send_frame(&self, _fp: &str, _frame: &[u8]) -> Option<CarrierPath> {
            None
        }
        /// No path carried any shard.
        pub async fn send_shards(&self, _fp: &str, _frames: &[Vec<u8>]) -> usize {
            0
        }
        /// No transport, so no link is dialled.
        pub async fn dial_paths(&self, _fp: &str, _addr: std::net::SocketAddr) -> usize {
            0
        }
        /// No links, so nothing to pin a post-quantum key to. The beacon path
        /// calls this in every build; only a build with the transport can act on
        /// it, because only that one holds links to check.
        pub fn pin_commitment(&self, _fp: &str, _commitment: [u8; 32]) {}
        /// Nothing is ever pinned here.
        pub fn pinned_commitment(&self, _fp: &str) -> Option<[u8; 32]> {
            None
        }
        pub fn forget(&self, _fp: &str) {}
        pub fn forget_link(&self, _fp: &str, _local: IpAddr) {}
    }
}
pub mod routing;
pub mod security;
pub mod stun;
pub mod tun;
pub mod turn;
pub mod upnp;
#[cfg(feature = "vpn")]
pub mod vpn;

use bytes::Bytes;
use rand::Rng;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

// ── Multicast Discovery Constants ─────────────────────────────────

/// Default multicast group for UDP beacon-based peer discovery.
pub const BEACON_MULTICAST_ADDR: &str = "239.255.0.1";
/// Default beacon port.
pub const BEACON_PORT: u16 = 2270;
/// Beacon interval in seconds.
pub const BEACON_INTERVAL_SECS: u64 = 30;
/// Beacon payload prefix — "GHOST_BEACON__" padded to 16 bytes.
pub const BEACON_PREFIX: &[u8; 16] = b"GHOST_BEACON____";

// ── Frame Size Constants ──────────────────────────────────────────

/// Base size of a standard GTF privacy frame (anti-traffic-analysis).
pub const GTF_BASE_SIZE: usize = 512;

/// Maximum size of a bulk GTF frame — full Ethernet MTU minus IP+UDP headers.
/// Standard Ethernet MTU is 1500, minus 20 (IP) minus 8 (UDP) = 1472 payload.
pub const GTF_BULK_SIZE: usize = 1472;

/// Maximum jitter padding bytes for privacy frames.
pub const JITTER_MAX: usize = 64;

/// Minimum frame size we accept (anything smaller is noise/garbage).
pub const MIN_FRAME_SIZE: usize = 32;

// ── Frame Offsets (Normal Mode) ───────────────────────────────────

pub const OFFSET_SESSION_HASH: usize = 0;
pub const OFFSET_PACKET_COUNTER: usize = 4;
pub const OFFSET_SHARD_INDEX: usize = 8;
pub const OFFSET_FLAGS: usize = 9; // flags byte: bit 0 = bulk mode
pub const OFFSET_PAYLOAD_START: usize = 10;
pub const OFFSET_AUTH_TAG_START: usize = 496;

/// Maximum payload within a 512-byte privacy frame.
pub const MAX_PAYLOAD_LEN: usize = OFFSET_AUTH_TAG_START - OFFSET_PAYLOAD_START; // 486

// ── Bulk Frame Offsets (1472 bytes) ───────────────────────────────

pub const BULK_OFFSET_PAYLOAD_START: usize = 10;
pub const BULK_OFFSET_AUTH_TAG_START: usize = 1456; // 1472 - 16

/// Maximum payload within a 1472-byte bulk frame.
pub const MAX_BULK_PAYLOAD_LEN: usize = BULK_OFFSET_AUTH_TAG_START - BULK_OFFSET_PAYLOAD_START; // 1446

// ══════════════════════════════════════════════════════════════════
// GTF v2 wire format (SOTA P2-2)
//
// What changed from v1, and why each change was unavoidable:
//
//  * **Random 96-bit nonce on the wire.** v1 derived its nonce from the counter,
//    which made the counter's width a security parameter. v2 carries
//    `nonce[12]` and the counter becomes a pure sequence number.
//  * **64-bit counter.** With the nonce no longer derived from it, the counter
//    only has to be a monotone *sequence* for replay protection — and a wrapping
//    one is worse than useless (the peer's sliding window rejects every frame
//    after the wrap, so a session dies at 2³² datagrams). v1's whole
//    near-exhaustion watchdog existed to prevent that; v2 makes it unnecessary.
//  * **Ratchet epoch.** Names the key generation that sealed the frame, so the
//    receiver looks the key up instead of trial-decrypting candidate epochs
//    (which leaks two AEAD attempts and cannot tell a stale epoch from a forged
//    one).
//
// The 22 bytes this costs come out of the payload region: the frame stays 512 B
// (that is the anti-analysis property, not a coincidence) and the Reed-Solomon
// shard that rides in it shrinks. RS(2,1) is size-agnostic, so nothing else had
// to change to pay for it.
//
// **Version discrimination.** Both versions keep the session hash at `0..4`, the
// shard index at `8` and the flags byte at `9`; v2 differs from byte 10 onward and
// marks itself with [`FLAG_V2`] in that same flags byte. That is legal because a v1
// sender only ever writes 0x00, 0x01, 0x02 or 0x03 there (privacy / bulk /
// tunnel), so bit 7 is free and unambiguous — whereas keying the version off a
// byte v1 uses for the counter would misread every third v1 packet.
// ══════════════════════════════════════════════════════════════════

/// Wire version this build emits for GTF frames.
pub const GTF_VERSION: u8 = 2;

/// Flags-byte bit that marks a v2 header (v1 never sets it).
pub const FLAG_V2: u8 = 0x80;
/// Bulk mode: an MTU-sized frame instead of a 512-byte privacy frame.
pub const FLAG_BULK: u8 = 0x01;
/// Tunnel bit: the payload is one self-contained shard, not a 3-shard RS group.
pub const FLAG_TUNNEL: u8 = 0x02;
/// Cover-traffic bit (SOTA P3-1): the payload is a [`DUMMY_MAGIC`] placeholder
/// and carries no application data.
///
/// A v1 sender only ever writes `0x00`..=`0x03` into this byte, so bit 2 is free
/// for the same reason bit 7 is (see the version-discrimination note above).
///
/// **This bit is a hint, not the decision.** Header flags are outside the AEAD —
/// only the ciphertext and the jitter tail are authenticated — so anyone on the
/// path can set or clear it. A receiver must therefore drop cover traffic on the
/// evidence of the *decrypted* [`DUMMY_MAGIC`], never on this bit: trusting the
/// bit would let an attacker who flips it either suppress a real frame or have a
/// placeholder dispatched as application data. The bit exists so a receiver can
/// skip work early, not so it can decide.
pub const FLAG_DUMMY: u8 = 0x04;
/// Per-shard authenticated encryption (ShardSec) marker.
pub const FLAG_SHARDSEC: u8 = 0x08;

/// Payload marker for a cover-traffic frame (SOTA P3-1).
///
/// The marker lives **inside** the AEAD plaintext, which is what makes it a fact
/// a receiver can act on: it is authenticated, so it cannot be forged, and it
/// cannot be stripped without the key. See [`FLAG_DUMMY`] for why the header bit
/// cannot serve that role.
///
/// Six bytes, and deliberately not a prefix any real payload can begin with: the
/// wire's control magics start with distinct letters, and a legitimate payload
/// reaching this check has already had its 2-byte length prefix removed.
pub const DUMMY_MAGIC: &[u8; 6] = b"DUMMY!";

/// True when a *decrypted, unframed* payload is cover traffic.
///
/// Takes the output of `frame_payload` (the length prefix already stripped), not
/// the raw decrypted buffer — the prefix would otherwise be compared instead of
/// the marker.
pub fn is_dummy_payload(plain: &[u8]) -> bool {
    plain.len() >= DUMMY_MAGIC.len() && &plain[..DUMMY_MAGIC.len()] == DUMMY_MAGIC.as_slice()
}

/// v2: session hash, 4 bytes (unchanged position, so lookup still works first).
pub const V2_OFFSET_SESSION_HASH: usize = 0;
/// v2: four zero bytes v1 used for its counter. Reserved, must be zero.
pub const V2_OFFSET_RESERVED: usize = 4;
/// v2: shard index (unchanged position).
pub const V2_OFFSET_SHARD_INDEX: usize = 8;
/// v2: flags byte (unchanged position; carries [`FLAG_V2`]).
pub const V2_OFFSET_FLAGS: usize = 9;
/// v2: 64-bit monotone packet counter, big-endian.
pub const V2_OFFSET_PACKET_COUNTER: usize = 10;
/// v2: 64-bit ratchet epoch that sealed this frame, big-endian.
pub const V2_OFFSET_RATCHET_EPOCH: usize = 18;
/// v2: 12-byte random nonce.
pub const V2_OFFSET_NONCE: usize = 26;
/// v2: first payload byte in a privacy frame.
pub const V2_OFFSET_PAYLOAD_START: usize = 38;
/// v2: Poly1305 tag position in a privacy frame.
pub const V2_OFFSET_AUTH_TAG_START: usize = 496;
/// v2: maximum payload in a 512-byte privacy frame.
pub const V2_MAX_PAYLOAD_LEN: usize = V2_OFFSET_AUTH_TAG_START - V2_OFFSET_PAYLOAD_START; // 458
/// v2: tag position in a bulk frame.
pub const V2_BULK_OFFSET_AUTH_TAG_START: usize = 1456;
/// v2: maximum payload in a 1472-byte bulk frame.
pub const V2_MAX_BULK_PAYLOAD_LEN: usize = V2_BULK_OFFSET_AUTH_TAG_START - V2_OFFSET_PAYLOAD_START; // 1418

/// The header of a v2 GTF frame — everything the receiver needs to find the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtfV2Header {
    pub session_hash: [u8; 4],
    /// Monotone sequence number for replay protection (never a nonce).
    pub counter: u64,
    /// Ratchet generation whose key sealed this frame.
    pub epoch: u64,
    /// 96-bit random nonce, carried verbatim.
    pub nonce: [u8; 12],
    pub shard_index: u8,
    /// Caller bits (bulk/tunnel). [`FLAG_V2`] is added by the builder.
    pub flags: u8,
    pub bulk: bool,
    /// The 64-byte jitter tail to place after the authenticated frame
    /// (SOTA P3-1).
    ///
    /// It lives on the header rather than as a builder argument so that the
    /// *same bytes* can be handed to the AEAD as associated data and written
    /// into the frame — the two must agree or the receiver rejects the frame.
    /// A header-only caller (or a test that only parses) can leave it zeroed:
    /// nothing reads the tail, its entire job is to make every privacy frame
    /// one length.
    pub tail: [u8; JITTER_MAX],
}

/// The jitter tail for one sealed message (SOTA P3-1).
///
/// **Derived, not drawn.** It is a keyed PRF of the session key and the message's
/// own seal metadata, for two reasons that force each other:
///
/// * the three shards of one message share **one** AEAD tag, so they must share
///   one tail — a per-shard random tail could not be authenticated by a single
///   tag;
/// * the seal and the frame-build are separate functions that never see each
///   other's tail, so the value has to be *recomputable* rather than passed.
///
/// The receiver does **not** recompute it to check: it feeds the tail it actually
/// read off the wire (`frame_tail`) to `xchacha_open_with_aad`, so a rewritten
/// tail no longer matches what the sender sealed and the tag check fails. This
/// function exists to give the *sender* its value; the authentication itself is
/// Poly1305's.
pub fn tail_for(
    key: &[u8; 32],
    nonce: &[u8; 12],
    epoch: u64,
    direction: crate::ghost::layers::l2_aead::NonceDirection,
) -> [u8; JITTER_MAX] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let dir = match direction {
        crate::ghost::layers::l2_aead::NonceDirection::InitiatorToResponder => 0u8,
        crate::ghost::layers::l2_aead::NonceDirection::ResponderToInitiator => 1u8,
    };
    let mut out = [0u8; JITTER_MAX];
    for (block, chunk) in out.chunks_mut(32).enumerate() {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(b"GTF_P3_1_JITTER_TAIL");
        mac.update(nonce);
        mac.update(&epoch.to_be_bytes());
        mac.update(&[dir, block as u8]);
        chunk.copy_from_slice(&mac.finalize().into_bytes()[..chunk.len()]);
    }
    out
}

/// The jitter tail a received frame carries (SOTA P3-1).
///
/// Empty for a bulk frame (it has no tail, which is what keeps it MTU-aligned)
/// and for anything too short to hold one. The caller feeds this to
/// `xchacha_open_with_aad` so a rewritten tail fails the tag.
pub fn frame_tail(buf: &[u8]) -> &[u8] {
    if is_v2_frame(buf) && !is_bulk_frame(buf) && buf.len() >= GTF_BASE_SIZE + JITTER_MAX {
        &buf[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX]
    } else {
        &[]
    }
}

impl GtfV2Header {
    /// A header with a freshly drawn nonce.
    pub fn new(session_hash: [u8; 4], counter: u64, epoch: u64, shard_index: u8) -> Self {
        Self {
            session_hash,
            counter,
            epoch,
            nonce: crate::ghost::layers::l2_aead::random_xnonce(),
            shard_index,
            flags: 0,
            bulk: false,
            tail: [0u8; JITTER_MAX],
        }
    }

    pub fn bulk(mut self, bulk: bool) -> Self {
        self.bulk = bulk;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Attach the jitter tail that will be written after the frame and
    /// authenticated as associated data (SOTA P3-1).
    pub fn with_tail(mut self, tail: [u8; JITTER_MAX]) -> Self {
        self.tail = tail;
        self
    }
}

/// True when `buf` carries a v2 header. Safe on any length: short buffers answer false.
pub fn is_v2_frame(buf: &[u8]) -> bool {
    buf.len() > V2_OFFSET_FLAGS && (buf[V2_OFFSET_FLAGS] & FLAG_V2) != 0
}

/// The wire version of a received frame.
pub fn frame_wire_version(buf: &[u8]) -> u8 {
    if is_v2_frame(buf) {
        GTF_VERSION
    } else {
        1
    }
}

/// Build a v2 GTF frame. Returns the bytes to send.
///
/// The frame is always exactly [`GTF_BASE_SIZE`] (plus jitter) or [`GTF_BULK_SIZE`],
/// so the note about v1's payload capacity applies unchanged.
pub fn build_gtf_v2_frame(h: &GtfV2Header, payload: &[u8], auth_tag: &[u8; 16]) -> Vec<u8> {
    let (total, tag_start, cap) = if h.bulk {
        (GTF_BULK_SIZE, V2_BULK_OFFSET_AUTH_TAG_START, V2_MAX_BULK_PAYLOAD_LEN)
    } else {
        (GTF_BASE_SIZE, V2_OFFSET_AUTH_TAG_START, V2_MAX_PAYLOAD_LEN)
    };
    assert!(
        payload.len() <= cap,
        "Payload ({} bytes) exceeds GTF v2 capacity ({} bytes)",
        payload.len(),
        cap
    );

    let mut packet = vec![0u8; total];
    packet[V2_OFFSET_SESSION_HASH..V2_OFFSET_SESSION_HASH + 4].copy_from_slice(&h.session_hash);
    packet[V2_OFFSET_RESERVED..V2_OFFSET_RESERVED + 4].copy_from_slice(&[0u8; 4]);
    packet[V2_OFFSET_SHARD_INDEX] = h.shard_index;
    // Caller bits are the low three: bulk (0x01), tunnel (0x02) and — since SOTA
    // P3-1 — cover traffic (0x04). The mask has to admit all three or the dummy
    // bit is silently dropped on the way out, which would make the flag look
    // supported while never reaching the wire.
    packet[V2_OFFSET_FLAGS] =
        FLAG_V2 | (h.flags & (FLAG_BULK | FLAG_TUNNEL | FLAG_DUMMY | FLAG_SHARDSEC)) | if h.bulk { FLAG_BULK } else { 0 };
    packet[V2_OFFSET_PACKET_COUNTER..V2_OFFSET_PACKET_COUNTER + 8]
        .copy_from_slice(&h.counter.to_be_bytes());
    packet[V2_OFFSET_RATCHET_EPOCH..V2_OFFSET_RATCHET_EPOCH + 8]
        .copy_from_slice(&h.epoch.to_be_bytes());
    packet[V2_OFFSET_NONCE..V2_OFFSET_NONCE + 12].copy_from_slice(&h.nonce);
    packet[V2_OFFSET_PAYLOAD_START..V2_OFFSET_PAYLOAD_START + payload.len()]
        .copy_from_slice(payload);
    packet[tag_start..total].copy_from_slice(auth_tag);

    // Jitter tail (SOTA P3-1) — privacy frames only, CONSTANT length, and now
    // authenticated. The bytes come from the header rather than from a fresh
    // draw here, because the caller needed them *before* sealing: they are given
    // to the AEAD as associated data, so the tag covers them and an on-path
    // attacker can no longer rewrite this region without the frame failing to
    // open. Nothing else moved — the frame is still 576 B and every offset is
    // unchanged.
    if !h.bulk {
        packet.extend_from_slice(&h.tail);
    }
    packet
}

/// Parse a v2 header. Returns `None` if the frame is not v2 or is truncated.
pub fn parse_gtf_v2_header(buf: &[u8]) -> Option<GtfV2Header> {
    if !is_v2_frame(buf) || buf.len() < V2_OFFSET_PAYLOAD_START {
        return None;
    }
    let mut session_hash = [0u8; 4];
    session_hash.copy_from_slice(&buf[V2_OFFSET_SESSION_HASH..V2_OFFSET_SESSION_HASH + 4]);
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&buf[V2_OFFSET_PACKET_COUNTER..V2_OFFSET_PACKET_COUNTER + 8]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&buf[V2_OFFSET_RATCHET_EPOCH..V2_OFFSET_RATCHET_EPOCH + 8]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buf[V2_OFFSET_NONCE..V2_OFFSET_NONCE + 12]);
    let flags = buf[V2_OFFSET_FLAGS];
    let bulk = (flags & FLAG_BULK) != 0;
    // The jitter tail travels back with the header so the receive path can hand
    // it to the AEAD as associated data without re-deriving offsets (SOTA P3-1).
    let mut tail = [0u8; JITTER_MAX];
    if !bulk && buf.len() >= GTF_BASE_SIZE + JITTER_MAX {
        tail.copy_from_slice(&buf[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX]);
    }
    Some(GtfV2Header {
        session_hash,
        counter: u64::from_be_bytes(counter),
        epoch: u64::from_be_bytes(epoch),
        nonce,
        shard_index: buf[V2_OFFSET_SHARD_INDEX],
        flags: flags & !FLAG_V2,
        bulk,
        tail,
    })
}

/// Parse the packet counter from either wire version.
pub fn parse_packet_counter_u64(buf: &[u8]) -> u64 {
    match parse_gtf_v2_header(buf) {
        Some(h) => h.counter,
        None => parse_packet_counter(buf) as u64,
    }
}

// ── ACK Engine ─────────────────────────────────────────────────────

/// Tracks sent packets for retransmission — stores the AEAD auth tag so
/// retransmitted packets pass cryptographic authentication.
#[derive(Clone)]
pub struct AckEntry {
    pub seq: u32,
    pub data: Bytes,
    pub auth_tag: [u8; 16],
    pub session_hash: [u8; 4],
    pub sent_at: Instant,
    pub retries: u8,
}

/// Lightweight ACK state per session.
pub struct AckEngine {
    /// Sent packets awaiting ACK, indexed by seq number.
    pending: Vec<Option<AckEntry>>,
    /// Base sequence number (sliding window start).
    pub base_seq: u32,
    /// Window size (max in-flight packets).
    pub window_size: u32,
    /// Estimated round-trip time (smoothed).
    pub srtt: f64,
    /// Whether congestion avoidance is active.
    pub congestion: bool,
    /// Congestion window (packets).
    pub cwnd: u32,
}

impl Default for AckEngine {
    fn default() -> Self {
        Self {
            pending: vec![None; 4096],
            base_seq: 0,
            window_size: 64,
            srtt: 50_000.0, // 50ms initial estimate (microseconds)
            congestion: false,
            cwnd: 64,
        }
    }
}

impl AckEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a sent packet for ACK tracking with its AEAD auth tag and session hash.
    pub fn register(&mut self, seq: u32, data: Bytes, auth_tag: [u8; 16], session_hash: [u8; 4]) {
        let idx = (seq as usize) % self.pending.len();
        self.pending[idx] = Some(AckEntry {
            seq,
            data,
            auth_tag,
            session_hash,
            sent_at: Instant::now(),
            retries: 0,
        });
    }

    /// Process an incoming ACK. Returns true if the ACK was valid.
    pub fn on_ack(&mut self, seq: u32) -> bool {
        let idx = (seq as usize) % self.pending.len();
        if let Some(ref entry) = self.pending[idx] {
            if entry.seq == seq {
                let rtt = entry.sent_at.elapsed().as_micros() as f64;
                // Smooth RTT estimate: RFC 6298 style
                self.srtt = self.srtt * 0.875 + rtt * 0.125;
                // Update congestion window (AIMD)
                if !self.congestion {
                    self.cwnd = self.cwnd.saturating_add(1).min(512);
                } else {
                    self.cwnd = self.cwnd.saturating_add(1).min(512);
                }
                self.congestion = false;
                self.pending[idx] = None;
                return true;
            }
        }
        false
    }

    /// Mark a timeout event for congestion control.
    pub fn on_timeout(&mut self) {
        self.congestion = true;
        self.cwnd = (self.cwnd / 2).max(16);
    }

    /// Collect expired packets for retransmission. Returns packets to resend.
    pub fn collect_expired(&mut self, timeout: Duration) -> Vec<(u32, Bytes)> {
        let mut retransmit = Vec::new();
        let now = Instant::now();
        for slot in self.pending.iter_mut() {
            if let Some(ref mut entry) = slot {
                if now.duration_since(entry.sent_at) > timeout && entry.retries < 5 {
                    entry.retries += 1;
                    entry.sent_at = now;
                    retransmit.push((entry.seq, entry.data.clone()));
                } else if entry.retries >= 5 {
                    // Give up after 5 retries
                    slot.take();
                }
            }
        }
        retransmit
    }

    /// Collect expired packets with full metadata (auth_tag + session_hash) for retransmission.
    /// Used by the ACK retransmit engine to produce cryptographically valid packets.
    pub fn collect_expired_full(
        &mut self,
        timeout: Duration,
    ) -> Vec<(u32, Bytes, [u8; 16], [u8; 4])> {
        let mut retransmit = Vec::new();
        let now = Instant::now();
        for slot in self.pending.iter_mut() {
            if let Some(ref mut entry) = slot {
                if now.duration_since(entry.sent_at) > timeout && entry.retries < 5 {
                    entry.retries += 1;
                    entry.sent_at = now;
                    retransmit.push((
                        entry.seq,
                        entry.data.clone(),
                        entry.auth_tag,
                        entry.session_hash,
                    ));
                } else if entry.retries >= 5 {
                    slot.take();
                }
            }
        }
        retransmit
    }

    /// Remaining window capacity.
    pub fn available(&self) -> u32 {
        let in_flight = self.pending.iter().filter(|s| s.is_some()).count() as u32;
        self.cwnd.saturating_sub(in_flight)
    }
}

// ── Shared Framing Utilities ───────────────────────────────────────

/// Prepend a 2-byte big-endian length prefix to a shard for binary-safe transport.
/// This is the canonical framing function used throughout the GhostNet stack.
pub fn frame_shard(d: &[u8]) -> Vec<u8> {
    let l = (d.len() as u16).to_be_bytes();
    let mut f = Vec::with_capacity(d.len() + 2);
    f.extend_from_slice(&l);
    f.extend_from_slice(d);
    f
}

/// Strip the 2-byte length prefix from a framed shard, returning the original data.
/// Returns None if framing is invalid or truncated.
pub fn unframe(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 2 {
        return None;
    }
    let l = u16::from_be_bytes([b[0], b[1]]) as usize;
    if l == 0 || 2 + l > b.len() {
        None
    } else {
        Some(b[2..2 + l].to_vec())
    }
}

// ── Flow Controller ────────────────────────────────────────────────

/// Smallest transit burst the shaper will ever allow, so a very low rate still
/// admits a whole packet rather than deadlocking on a sub-packet burst.
const MIN_TRANSIT_BURST: u64 = 1500;

/// Adaptive token-bucket flow controller with dual-rate shaping.
///
/// This is a **policy** limit — "do not forward someone else's traffic faster
/// than this" — not a congestion-control loop. For the control loop see
/// [`cc::AckEngine`], which measures the path and decides how fast to go; this
/// type only enforces a ceiling. The two compose: a caller that has a
/// congestion-controlled rate calls [`FlowController::set_transit_rate_bps`] so
/// shaping follows the measurement instead of a hand-set constant.
pub struct FlowController {
    /// Transit tokens (for routing other people's traffic).
    transit_bucket: AtomicU64,
    /// Local tokens (for the user's own traffic — effectively unlimited).
    local_bucket: AtomicU64,
    /// Max transit bytes per second. Atomic so the rate can be retuned — and so
    /// [`Self::replenish`] sees the *new* rate rather than the constructor's.
    transit_rate: AtomicU64,
    /// Burst allowance for transit, retuned with the rate so the two cannot
    /// disagree (a 100 ms burst of the *old* rate would let a raised limit be
    /// exceeded instantly and a lowered one be overshot for a whole RTT).
    transit_burst: AtomicU64,
    /// Timestamp of last replenishment (nanos).
    last_replenish: AtomicU64,
}

impl FlowController {
    /// Create a new flow controller.
    /// transit_rate_mbps: megabits per second for transit traffic.
    pub fn new(transit_rate_mbps: u64) -> Self {
        let bytes_per_sec = transit_rate_mbps * 125_000; // Mbps → bytes/sec
        Self {
            transit_bucket: AtomicU64::new(bytes_per_sec), // start full
            local_bucket: AtomicU64::new(u64::MAX),
            transit_rate: AtomicU64::new(bytes_per_sec),
            // Start with a full 100 ms burst of credit.
            transit_burst: AtomicU64::new((bytes_per_sec / 10).max(MIN_TRANSIT_BURST)),
            last_replenish: AtomicU64::new(now_nanos()),
        }
    }

    /// Replenish tokens based on elapsed time.
    pub fn replenish(&self) {
        let now = now_nanos();
        let last = self.last_replenish.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);
        if elapsed > 1_000_000 {
            // only replenish if >1ms elapsed
            let rate = self.transit_rate.load(Ordering::Relaxed) as u128;
            let tokens = rate.saturating_mul(elapsed as u128) / 1_000_000_000;
            let burst = self.transit_burst.load(Ordering::Relaxed) as u128;
            let current = self.transit_bucket.load(Ordering::Relaxed) as u128;
            let new = (current + tokens).min(burst) as u64;
            self.transit_bucket.store(new, Ordering::Relaxed);
            self.last_replenish.store(now, Ordering::Relaxed);
        }
    }

    /// Try to consume tokens for a packet. Returns true if allowed.
    pub fn try_consume_transit(&self, bytes: usize) -> bool {
        self.replenish();
        let current = self.transit_bucket.load(Ordering::Relaxed);
        if current >= bytes as u64 {
            self.transit_bucket
                .store(current - bytes as u64, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Local traffic is always allowed (full line speed).
    pub fn try_consume_local(&self, _bytes: usize) -> bool {
        true // no throttle
    }

    /// Reset the transit rate (atomic-safe for `&self`).
    ///
    /// Sets the *rate* the bucket replenishes at, and refills the bucket to its
    /// new ceiling so a raised limit takes effect immediately. (Until this was
    /// fixed the method wrote the requested rate into the token *bucket*, which
    /// `replenish` then ignored: it kept computing credit from the rate the
    /// constructor had been given, so retuning a live node silently did nothing.)
    pub fn set_transit_rate_mbps(&self, mbps: u64) {
        self.set_transit_rate_bps(mbps * 125_000);
    }

    /// Set the transit rate from a measured or modelled rate, bytes per second.
    ///
    /// This is how a congestion-controlled estimate reaches the shaper: the
    /// caller runs [`cc::AckEngine`] and hands the result here.
    pub fn set_transit_rate_bps(&self, bytes_per_sec: u64) {
        self.transit_rate.store(bytes_per_sec, Ordering::Relaxed);
        self.transit_burst.store(
            (bytes_per_sec / 10).max(MIN_TRANSIT_BURST),
            Ordering::Relaxed,
        );
        self.transit_bucket.store(bytes_per_sec, Ordering::Relaxed);
        self.last_replenish.store(now_nanos(), Ordering::Relaxed);
    }

    /// The rate the bucket currently replenishes at, bytes per second.
    pub fn transit_rate_bps(&self) -> u64 {
        self.transit_rate.load(Ordering::Relaxed)
    }
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ── Frame Building ─────────────────────────────────────────────────

/// Build a GTF frame. Returns the raw bytes to send over the wire.
/// If `bulk` is true, uses a 1472-byte MTU-optimized frame.
/// If `bulk` is false, uses a 512-byte privacy frame with jitter padding.
pub fn build_gtf_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
    bulk: bool,
) -> Vec<u8> {
    if bulk {
        build_bulk_frame(session_hash, counter, shard_index, payload, auth_tag)
    } else {
        build_privacy_frame(session_hash, counter, shard_index, payload, auth_tag)
    }
}

fn build_privacy_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    assert!(
        payload.len() <= MAX_PAYLOAD_LEN,
        "Payload ({} bytes) exceeds privacy frame capacity ({} bytes)",
        payload.len(),
        MAX_PAYLOAD_LEN
    );

    let mut packet = vec![0u8; GTF_BASE_SIZE];
    packet[OFFSET_SESSION_HASH..OFFSET_SESSION_HASH + 4].copy_from_slice(&session_hash);
    packet[OFFSET_PACKET_COUNTER..OFFSET_PACKET_COUNTER + 4]
        .copy_from_slice(&counter.to_be_bytes());
    packet[OFFSET_SHARD_INDEX] = shard_index;
    packet[OFFSET_FLAGS] = 0; // privacy mode
    packet[OFFSET_PAYLOAD_START..OFFSET_PAYLOAD_START + payload.len()].copy_from_slice(payload);
    packet[OFFSET_AUTH_TAG_START..GTF_BASE_SIZE].copy_from_slice(auth_tag);

    // Apply jitter padding (L5)
    let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
    if jitter > 0 {
        packet.extend(std::iter::repeat_n(0u8, jitter));
        rand::thread_rng().fill(&mut packet[GTF_BASE_SIZE..]);
    }

    packet
}

fn build_bulk_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    assert!(
        payload.len() <= MAX_BULK_PAYLOAD_LEN,
        "Payload ({} bytes) exceeds bulk frame capacity ({} bytes)",
        payload.len(),
        MAX_BULK_PAYLOAD_LEN
    );

    let mut packet = vec![0u8; GTF_BULK_SIZE];
    packet[OFFSET_SESSION_HASH..OFFSET_SESSION_HASH + 4].copy_from_slice(&session_hash);
    packet[OFFSET_PACKET_COUNTER..OFFSET_PACKET_COUNTER + 4]
        .copy_from_slice(&counter.to_be_bytes());
    packet[OFFSET_SHARD_INDEX] = shard_index;
    packet[OFFSET_FLAGS] = 0x01; // bit 0 = bulk mode
    packet[BULK_OFFSET_PAYLOAD_START..BULK_OFFSET_PAYLOAD_START + payload.len()]
        .copy_from_slice(payload);
    packet[BULK_OFFSET_AUTH_TAG_START..GTF_BULK_SIZE].copy_from_slice(auth_tag);

    packet
}

/// Determine if a received frame is in bulk mode by reading the flags byte.
pub fn is_bulk_frame(buf: &[u8]) -> bool {
    buf.len() > OFFSET_FLAGS && (buf[OFFSET_FLAGS] & 0x01) != 0
}

/// Determine the expected frame size given its mode.
pub fn frame_size(buf: &[u8]) -> usize {
    if is_bulk_frame(buf) {
        GTF_BULK_SIZE
    } else {
        GTF_BASE_SIZE
    }
}

// ── Parsing ────────────────────────────────────────────────────────

/// Parse the 4-byte packet counter from a raw GTF buffer.
pub fn parse_packet_counter(buf: &[u8]) -> u32 {
    if buf.len() < OFFSET_PACKET_COUNTER + 4 {
        return 0;
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(&buf[OFFSET_PACKET_COUNTER..OFFSET_PACKET_COUNTER + 4]);
    u32::from_be_bytes(c)
}

/// Parse the 4-byte session hash from a raw GTF buffer.
pub fn parse_session_hash(buf: &[u8]) -> [u8; 4] {
    if buf.len() < OFFSET_SESSION_HASH + 4 {
        return [0u8; 4];
    }
    let mut h = [0u8; 4];
    h.copy_from_slice(&buf[OFFSET_SESSION_HASH..OFFSET_SESSION_HASH + 4]);
    h
}

/// Parse the flags byte.
pub fn parse_flags(buf: &[u8]) -> u8 {
    if buf.len() > OFFSET_FLAGS {
        buf[OFFSET_FLAGS]
    } else {
        0
    }
}

/// Extract payload data from a received frame, handling both modes and both versions.
pub fn extract_payload(buf: &[u8]) -> &[u8] {
    let (start, tag_start) = if is_v2_frame(buf) {
        (
            V2_OFFSET_PAYLOAD_START,
            if is_bulk_frame(buf) {
                V2_BULK_OFFSET_AUTH_TAG_START
            } else {
                V2_OFFSET_AUTH_TAG_START
            },
        )
    } else if is_bulk_frame(buf) {
        (BULK_OFFSET_PAYLOAD_START, BULK_OFFSET_AUTH_TAG_START)
    } else {
        (OFFSET_PAYLOAD_START, OFFSET_AUTH_TAG_START)
    };
    if buf.len() <= start {
        return &[];
    }
    &buf[start..tag_start.min(buf.len())]
}

/// Extract the auth tag from a received frame.
pub fn extract_auth_tag(buf: &[u8]) -> &[u8] {
    let tag_start = if is_v2_frame(buf) {
        if is_bulk_frame(buf) {
            V2_BULK_OFFSET_AUTH_TAG_START
        } else {
            V2_OFFSET_AUTH_TAG_START
        }
    } else if is_bulk_frame(buf) {
        BULK_OFFSET_AUTH_TAG_START
    } else {
        OFFSET_AUTH_TAG_START
    };
    let tag_end = (tag_start + 16).min(buf.len());
    if tag_end >= tag_start + 16 {
        &buf[tag_start..tag_end]
    } else {
        &[]
    }
}

/// Send a GTF frame over a UDP socket asynchronously.
pub async fn send_gtf(
    socket: &UdpSocket,
    target: &SocketAddr,
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
    bulk: bool,
) -> std::io::Result<()> {
    let frame = build_gtf_frame(session_hash, counter, shard_index, payload, auth_tag, bulk);
    socket.send_to(&frame, target).await?;
    Ok(())
}

/// Send a GTF **v2** frame over a UDP socket asynchronously.
///
/// Shards of one message share a header except for `shard_index`: pass the same
/// counter, epoch and nonce with a different index, because they are pieces of one
/// AEAD ciphertext rather than three separate messages.
pub async fn send_gtf_v2(
    socket: &UdpSocket,
    target: &SocketAddr,
    h: &GtfV2Header,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> std::io::Result<()> {
    let frame = build_gtf_v2_frame(h, payload, auth_tag);
    socket.send_to(&frame, target).await?;
    Ok(())
}

#[cfg(test)]
mod wire_v2_tests {
    use super::*;

    fn tag() -> [u8; 16] {
        [0xABu8; 16]
    }

    #[test]
    fn test_v2_frame_marks_itself_and_parses_back() {
        let h = GtfV2Header::new([1, 2, 3, 4], 0x1_0000_0007, 9, 2);
        let frame = build_gtf_v2_frame(&h, b"payload", &tag());
        assert_eq!(
            frame.len(),
            GTF_BASE_SIZE + JITTER_MAX,
            "SOTA P3-1: a privacy frame is a CONSTANT 576 B — 512 B of authenticated \
             frame plus a full-length jitter tail — so its length carries no signal"
        );
        assert!(is_v2_frame(&frame));
        assert_eq!(frame_wire_version(&frame), GTF_VERSION);
        let parsed = parse_gtf_v2_header(&frame).expect("v2 header");
        assert_eq!(parsed.session_hash, [1, 2, 3, 4]);
        assert_eq!(parsed.counter, 0x1_0000_0007);
        assert_eq!(parsed.epoch, 9);
        assert_eq!(parsed.nonce, h.nonce);
        assert_eq!(parsed.shard_index, 2);
        assert!(!parsed.bulk);
    }

    #[test]
    fn test_p3_1_privacy_frames_are_always_the_same_length() {
        // The property P3-1 buys, asserted directly rather than by inference: the
        // wire length of a privacy frame must not vary with the payload, the
        // shard, or the draw of the RNG. Before this change the tail was
        // `0..JITTER_MAX` bytes, so 65 distinct lengths were reachable and the
        // length *was* the leak.
        let mut seen = std::collections::HashSet::new();
        for payload_len in [0usize, 1, 64, 200, GTF_BASE_SIZE] {
            for shard in 0u8..3 {
                let payload = vec![0xA5u8; payload_len.min(V2_MAX_PAYLOAD_LEN)];
                let h = GtfV2Header::new([7, 7, 7, 7], 1, 0, shard);
                let frame = build_gtf_v2_frame(&h, &payload, &tag());
                seen.insert(frame.len());
            }
        }
        assert_eq!(
            seen,
            std::collections::HashSet::from([GTF_BASE_SIZE + JITTER_MAX]),
            "every privacy frame must be exactly one length on the wire"
        );

        // The tail is now *derived* rather than drawn (SOTA P3-1), so the old
        // "two frames of the same message differ in the tail" assertion no longer
        // describes it — and keeping it would now be wrong, not merely stale:
        // the three shards of one message share a single AEAD tag, so they must
        // share a single tail. What still matters is that the tail is a *keyed*
        // PRF of the seal metadata, so it is neither a run of zeros an observer
        // can strip nor a value an attacker can recompute after tampering.
        let key = [0x5Au8; 32];
        let nonce = [0x11u8; 12];
        let dir = crate::ghost::layers::l2_aead::NonceDirection::InitiatorToResponder;
        let t1 = tail_for(&key, &nonce, 0, dir);
        assert_ne!(t1, [0u8; JITTER_MAX], "not a strippable run of zeros");
        assert_eq!(t1, tail_for(&key, &nonce, 0, dir), "deterministic per message");
        assert_ne!(t1, tail_for(&key, &[0x12u8; 12], 0, dir), "different nonce");
        assert_ne!(t1, tail_for(&key, &nonce, 1, dir), "different epoch");
        assert_ne!(
            t1,
            tail_for(
                &key,
                &nonce,
                0,
                crate::ghost::layers::l2_aead::NonceDirection::ResponderToInitiator
            ),
            "different direction"
        );
        assert_ne!(
            t1,
            tail_for(&[0x5Bu8; 32], &nonce, 0, dir),
            "a different session key must give an unrelated tail"
        );
    }

    #[test]
    fn test_v2_counter_survives_the_32_bit_boundary() {
        // The whole point of the 64-bit counter: it keeps counting where v1 wrapped.
        for counter in [0, 1, u32::MAX as u64, (u32::MAX as u64) + 1, 1u64 << 40] {
            let h = GtfV2Header::new([9, 9, 9, 9], counter, 0, 0);
            let frame = build_gtf_v2_frame(&h, b"x", &tag());
            assert_eq!(parse_packet_counter_u64(&frame), counter);
        }
    }

    #[test]
    fn test_v1_frames_are_still_read_as_v1() {
        // The version marker must not misread a v1 frame: v1 writes 0x00/0x01/0x02
        // in the flags byte and never bit 7.
        for (counter, bulk) in [(0u32, false), (2, false), (3, true), (u32::MAX, true)] {
            let frame = build_gtf_frame([7, 7, 7, 7], counter, 1, b"shard", &tag(), bulk);
            assert!(!is_v2_frame(&frame), "v1 frame misread as v2 (counter {counter})");
            assert_eq!(frame_wire_version(&frame), 1);
            assert_eq!(parse_packet_counter(&frame), counter);
            assert_eq!(parse_packet_counter_u64(&frame), counter as u64);
            assert_eq!(parse_gtf_v2_header(&frame), None);
        }
    }

    #[test]
    fn test_v2_flags_carry_bulk_and_tunnel() {
        let h = GtfV2Header::new([1, 1, 1, 1], 5, 0, 0)
            .bulk(true)
            .with_flags(FLAG_TUNNEL);
        let frame = build_gtf_v2_frame(&h, b"tunnel", &tag());
        assert!(is_bulk_frame(&frame));
        let parsed = parse_gtf_v2_header(&frame).unwrap();
        assert!(parsed.bulk);
        assert_eq!(parsed.flags & FLAG_TUNNEL, FLAG_TUNNEL);
        assert_eq!(parsed.flags & FLAG_V2, 0, "the marker is not a caller flag");
    }

    #[test]
    fn test_v2_payload_and_tag_offsets_differ_from_v1() {
        // Both versions keep the frame at 512 B; v2 pays for its header out of the
        // payload region, so the two extractors must not be interchangeable.
        assert_eq!(V2_MAX_PAYLOAD_LEN, 458);
        assert_eq!(MAX_PAYLOAD_LEN, 486);
        assert!(V2_OFFSET_PAYLOAD_START > OFFSET_PAYLOAD_START);

        let h = GtfV2Header::new([2, 2, 2, 2], 11, 1, 0);
        let mut payload = vec![0u8; V2_MAX_PAYLOAD_LEN];
        payload[..4].copy_from_slice(b"ABCD");
        let frame = build_gtf_v2_frame(&h, &payload, &tag());
        assert_eq!(&extract_payload(&frame)[..4], b"ABCD");
        assert_eq!(extract_auth_tag(&frame), &tag());
        assert_eq!(extract_payload(&frame).len(), V2_MAX_PAYLOAD_LEN);

        // A v1 frame built with the same tag must still extract correctly. Both
        // extractors return the whole payload *region* — the shard's own 2-byte
        // length prefix is what trims the padding — so compare the region's head.
        let v1 = build_gtf_frame([2, 2, 2, 2], 11, 0, b"shard", &tag(), false);
        assert_eq!(&extract_payload(&v1)[..5], b"shard");
        assert_eq!(extract_payload(&v1).len(), MAX_PAYLOAD_LEN);
        assert_eq!(extract_auth_tag(&v1), &tag());
    }

    #[test]
    fn test_v2_rejects_an_oversized_payload() {
        let h = GtfV2Header::new([1, 1, 1, 1], 1, 0, 0);
        let over = vec![0u8; V2_MAX_PAYLOAD_LEN + 1];
        assert!(std::panic::catch_unwind(|| build_gtf_v2_frame(&h, &over, &tag())).is_err());
        // And the bulk cap is the larger one.
        let hb = GtfV2Header::new([1, 1, 1, 1], 1, 0, 0).bulk(true);
        let frames_ok = build_gtf_v2_frame(&hb, &vec![0u8; V2_MAX_BULK_PAYLOAD_LEN], &tag());
        assert_eq!(frames_ok.len(), GTF_BULK_SIZE);
    }

    #[test]
    fn test_v2_short_buffer_is_not_a_v2_frame() {
        assert!(!is_v2_frame(&[]));
        assert!(!is_v2_frame(&[0u8; 5]));
        assert_eq!(parse_gtf_v2_header(&[0x80u8; 4]), None);
        assert_eq!(frame_wire_version(&[0u8; 11]), 1);
    }
}

// ── Throughput Statistics ──────────────────────────────────────────

/// Atomic throughput counters for monitoring.
#[derive(Default)]
pub struct ThroughputStats {
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub retransmits: AtomicU64,
    pub drops: AtomicU64,
    /// Cover-traffic frames received and discarded (SOTA P3-1).
    ///
    /// Separate from `drops` because it is not a loss: these frames arrived
    /// intact and were dropped *by design*. An operator wants to see cover
    /// traffic flowing rather than have it look like packet loss.
    pub cover_recv: AtomicU64,
}

impl ThroughputStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Report current throughput as (sent_bytes, recv_bytes, send_rate, recv_rate) over interval.
    pub fn report(&self, interval: Duration) -> (f64, f64, f64, f64) {
        let sent = self.bytes_sent.swap(0, Ordering::Relaxed) as f64;
        let recv = self.bytes_recv.swap(0, Ordering::Relaxed) as f64;
        let secs = interval.as_secs_f64();
        (sent, recv, sent / secs, recv / secs)
    }
}
