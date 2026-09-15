#[cfg(feature = "quic")]
pub mod carrier;
/// GhostNet Network Layer
///
/// Implements the Ghost Transport Frame (GTF) — the wire format for all
/// UDP packets — with dual frame modes for maximum throughput:
///
/// - **Normal mode**: 512-byte frames with jitter padding (anti-traffic-analysis)
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
/// say is "nothing is registered", which is exactly true.
#[cfg(not(feature = "quic"))]
pub mod carrier {
    use super::CarrierPath;

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
        pub fn label(&self) -> &'static str {
            "none"
        }
        /// Nothing to send on: the caller keeps to UDP.
        pub async fn send_frame(&self, _fp: &str, _frame: &[u8]) -> Option<CarrierPath> {
            None
        }
        pub fn forget(&self, _fp: &str) {}
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

/// Extract payload data from a received frame, handling both modes.
pub fn extract_payload(buf: &[u8]) -> &[u8] {
    if is_bulk_frame(buf) {
        let payload_end = BULK_OFFSET_AUTH_TAG_START.min(buf.len());
        &buf[BULK_OFFSET_PAYLOAD_START..payload_end]
    } else {
        let payload_end = OFFSET_AUTH_TAG_START.min(buf.len());
        &buf[OFFSET_PAYLOAD_START..payload_end]
    }
}

/// Extract the auth tag from a received frame.
pub fn extract_auth_tag(buf: &[u8]) -> &[u8] {
    let tag_start = if is_bulk_frame(buf) {
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
