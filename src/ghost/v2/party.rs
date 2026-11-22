//! `ggn party` — a LAN bridge for games.
//!
//! Two kinds of lag ruin a LAN game over a WAN link:
//!
//! 1. **Path lag.** The game's UDP packets take the same single route everyone
//!    else's traffic does, so one dropped packet is one missed frame.
//! 2. **Head-of-line lag.** Packets arrive out of order and the game either
//!    discards them or stalls waiting for a gap that will never fill.
//!
//! This bridge addresses both without touching the game. It carries each
//! datagram as a sequenced [`PartyFrame`], optionally transmits it twice so a
//! single packet loss cannot end a frame, drops duplicates with a 1024-sequence
//! window, and re-orders into a small jitter buffer whose delay is configurable
//! (0 for twitch shooters, 30–60 ms for a lossy path).
//!
//! The honest limits:
//!
//! * **Duplication is not free.** Each duplicate costs bandwidth; `--copies 2` is
//!   the useful default, `3` only on a path that loses >5 %.
//! * **The jitter buffer adds latency by design.** It exists to convert jitter
//!   into a constant delay, which is what games are actually tuned for.
//! * **This is a bridge, not a tunnel.** It does not encrypt. Run it over the
//!   mesh (`--peer` pointing at a mesh peer's address) if the path needs it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Wire magic. A party frame on the wrong port is discarded, not guessed at.
pub const PARTY_MAGIC: &[u8; 4] = b"GPY1";
/// Header: magic + 8-byte sequence + 2-byte length.
pub const PARTY_HEADER_LEN: usize = 14;
/// Largest datagram this bridge will carry (keeps under a 1500-byte MTU).
pub const PARTY_MAX_PAYLOAD: usize = 1400;
/// Dedupe window, in sequences.
pub const SEQ_WINDOW: u64 = 1024;

/// One game datagram, sequenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyFrame {
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl PartyFrame {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.payload.len() > PARTY_MAX_PAYLOAD {
            return None;
        }
        let mut out = Vec::with_capacity(PARTY_HEADER_LEN + self.payload.len());
        out.extend_from_slice(PARTY_MAGIC);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PARTY_HEADER_LEN || &bytes[0..4] != PARTY_MAGIC {
            return None;
        }
        let seq = u64::from_be_bytes(bytes[4..12].try_into().ok()?);
        let len = u16::from_be_bytes([bytes[12], bytes[13]]) as usize;
        if len > PARTY_MAX_PAYLOAD || bytes.len() < PARTY_HEADER_LEN + len {
            return None;
        }
        Some(Self {
            seq,
            payload: bytes[PARTY_HEADER_LEN..PARTY_HEADER_LEN + len].to_vec(),
        })
    }
}

/// A sliding bitmap of recently seen sequences.
#[derive(Debug, Clone)]
pub struct SeqWindow {
    highest: u64,
    seen: [u64; 16],
}

impl Default for SeqWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SeqWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            seen: [0u64; 16],
        }
    }

    fn bit(seq: u64) -> (usize, u64) {
        let slot = (seq % SEQ_WINDOW) as usize;
        (slot / 64, 1u64 << (slot % 64))
    }

    /// `true` when this sequence is new (and records it).
    pub fn accept(&mut self, seq: u64) -> bool {
        if seq > self.highest {
            let delta = seq - self.highest;
            if delta >= SEQ_WINDOW {
                self.seen = [0u64; 16];
            } else {
                // Bit positions are absolute (`seq % WINDOW`), so the window does
                // not slide: each newly-covered position is cleared before it is
                // used. Without this, the slot for seq N still held the bit for
                // seq N-WINDOW and a fresh packet would be mistaken for a
                // duplicate — or, worse, an old one would be let through.
                for s in (self.highest + 1)..=seq {
                    let (w, m) = Self::bit(s);
                    self.seen[w] &= !m;
                }
            }
            self.highest = seq;
            let (w, m) = Self::bit(seq);
            self.seen[w] |= m;
            return true;
        }

        let behind = self.highest - seq;
        if behind >= SEQ_WINDOW {
            return false;
        }
        let (w, m) = Self::bit(seq);
        if self.seen[w] & m != 0 {
            return false;
        }
        self.seen[w] |= m;
        true
    }
}

/// Re-orders datagrams into a fixed small delay.
#[derive(Debug)]
pub struct JitterBuffer {
    next: Option<u64>,
    target_delay: Duration,
    pending: BTreeMap<u64, (Vec<u8>, Instant)>,
}

impl JitterBuffer {
    pub fn new(target_delay: Duration) -> Self {
        Self {
            next: None,
            target_delay,
            pending: BTreeMap::new(),
        }
    }

    /// Insert a datagram. Returns anything now deliverable, in order.
    pub fn push(&mut self, seq: u64, payload: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        let next = *self.next.get_or_insert(seq);
        if seq < next {
            return Vec::new();
        }
        // Bound the buffer: a game cannot use more than a second of packets and a
        // hostile peer could otherwise grow it without limit.
        if self.pending.len() >= 4096 {
            return Vec::new();
        }
        self.pending.entry(seq).or_insert((payload, now));
        self.drain(now, false)
    }

    /// Release what the delay allows even if a gap remains: waiting longer than
    /// the target for a packet that is not coming is exactly the lag this buffer
    /// exists to prevent.
    pub fn tick(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.drain(now, true)
    }

    fn drain(&mut self, now: Instant, force: bool) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(next) = self.next {
            if let Some((payload, _)) = self.pending.remove(&next) {
                out.push(payload);
                self.next = Some(next.wrapping_add(1));
                continue;
            }
            let Some((&first_seq, (_, arrived))) = self.pending.iter().next() else {
                break;
            };
            let waited = now.saturating_duration_since(*arrived);
            if force && waited >= self.target_delay {
                // Skip the gap: deliver from the oldest pending sequence.
                self.next = Some(first_seq);
                continue;
            }
            break;
        }
        out
    }

    pub fn depth(&self) -> usize {
        self.pending.len()
    }
}

/// Counters exposed to the CLI and dashboard.
#[derive(Debug, Default)]
pub struct PartyStats {
    pub received: AtomicU64,
    pub forwarded: AtomicU64,
    pub duplicates: AtomicU64,
    pub malformed: AtomicU64,
    pub dropped_gap: AtomicU64,
}

impl PartyStats {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "received": self.received.load(Ordering::Relaxed),
            "forwarded": self.forwarded.load(Ordering::Relaxed),
            "duplicates": self.duplicates.load(Ordering::Relaxed),
            "malformed": self.malformed.load(Ordering::Relaxed),
            "dropped_gap": self.dropped_gap.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PartyConfig {
    /// The address the game (or console) sends to.
    pub listen: String,
    /// Where the peer's `ggn party` listens. `None` makes this a local echo
    /// bridge, useful for checking a path without a second node.
    pub peer: Option<String>,
    /// The address this bridge accepts peer frames on. Defaults to the game
    /// port + 1 on the same host; a two-machine run must give this address to
    /// the other player's `--peer`.
    pub peer_listen: Option<String>,
    /// Number of copies per datagram. Clamped to 1..=3.
    pub copies: usize,
    /// Jitter buffer delay in milliseconds.
    pub jitter_ms: u64,
}

impl PartyConfig {
    pub fn new(listen: &str, peer: Option<&str>) -> Self {
        Self {
            listen: listen.to_string(),
            peer: peer.map(str::to_string),
            peer_listen: None,
            copies: 2,
            jitter_ms: 0,
        }
    }

    /// The peer-facing bind address. Derived from `listen` when unset so the
    /// game side and the peer side never share a socket.
    pub fn peer_listen_addr(&self) -> String {
        if let Some(addr) = &self.peer_listen {
            return addr.clone();
        }
        match self.listen.parse::<SocketAddr>() {
            Ok(mut addr) => {
                addr.set_port(addr.port().saturating_add(1));
                addr.to_string()
            }
            Err(_) => "0.0.0.0:47078".to_string(),
        }
    }

    pub fn copies(&self) -> usize {
        self.copies.clamp(1, 3)
    }
}

/// Run the bridge until the process exits.
pub async fn run(cfg: PartyConfig) -> anyhow::Result<()> {
    let local = UdpSocket::bind(&cfg.listen)
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", cfg.listen))?;
    let local = Arc::new(local);
    let peer_addr: Option<SocketAddr> = match &cfg.peer {
        Some(p) => {
            let mut last = None;
            for a in tokio::net::lookup_host(p).await? {
                last = Some(a);
            }
            Some(last.ok_or_else(|| anyhow::anyhow!("cannot resolve peer {p}"))?)
        }
        None => None,
    };

    // The peer-facing socket is separate so the game's address is never used as
    // the source for peer traffic (a NAT would rewrite it anyway). It binds a
    // *known* address: an ephemeral port would leave the other machine with
    // nothing to point `--peer` at.
    let peer_bind = cfg.peer_listen_addr();
    let uplink = Arc::new(UdpSocket::bind(&peer_bind).await.map_err(|e| {
        anyhow::anyhow!("cannot listen for peers on {peer_bind}: {e}")
    })?);
    let game_sender: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));
    let stats = Arc::new(PartyStats::default());
    let copies = cfg.copies();
    let jitter = Duration::from_millis(cfg.jitter_ms);

    println!("Vantablack party");
    println!("  game  -> {}", local.local_addr()?);
    println!("  peers -> {}", uplink.local_addr()?);
    if let Some(p) = peer_addr {
        println!("  peer  -> {p}");
    } else {
        println!("  peer  -> (none; local echo mode)");
    }
    println!("  copies {}, jitter {} ms", copies, cfg.jitter_ms);
    println!("Point the game at the game address and the other player at this node's peer address.");
    println!("Ctrl+C to stop.");

    // ── Game → peer ────────────────────────────────────────────────────
    let up_local = Arc::clone(&local);
    let up_sock = Arc::clone(&uplink);
    let up_stats = Arc::clone(&stats);
    let up_sender = Arc::clone(&game_sender);
    tokio::spawn(async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = up_local.recv_from(&mut buf).await else {
                continue;
            };
            up_stats.received.fetch_add(1, Ordering::Relaxed);
            // Remember the local game endpoint; peer frames are delivered here,
            // never back to the other bridge.
            if let Ok(mut slot) = up_sender.lock() {
                *slot = Some(from);
            }
            let frame = PartyFrame {
                seq,
                payload: buf[..n].to_vec(),
            };
            seq = seq.wrapping_add(1);
            let Some(encoded) = frame.encode() else {
                up_stats.malformed.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            match peer_addr {
                Some(peer) => {
                    for _ in 0..copies {
                        let _ = up_sock.send_to(&encoded, peer).await;
                    }
                }
                None => {
                    // Echo mode: hand it straight back so a single machine can
                    // verify the path through the mesh.
                    let _ = up_local.send_to(&frame.payload, from).await;
                }
            }
        }
    });

    // ── Peer → game ────────────────────────────────────────────────────
    let down_sock = Arc::clone(&uplink);
    let down_local = Arc::clone(&local);
    let down_stats = Arc::clone(&stats);
    let down_sender = Arc::clone(&game_sender);
    tokio::spawn(async move {
        let mut window = SeqWindow::new();
        let mut buffer = JitterBuffer::new(jitter);
        let mut buf = vec![0u8; 2048];
        loop {
            let wait = if buffer.depth() > 0 { Duration::from_millis(5) } else { Duration::from_secs(1) };
            match tokio::time::timeout(wait, down_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _from))) => {
                    match PartyFrame::decode(&buf[..n]) {
                        Some(frame) => {
                            down_stats.received.fetch_add(1, Ordering::Relaxed);
                            if !window.accept(frame.seq) {
                                down_stats.duplicates.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            for payload in buffer.push(frame.seq, frame.payload, Instant::now()) {
                                let addr = down_sender
                                    .lock()
                                    .ok()
                                    .and_then(|slot| *slot)
                                    .or(peer_addr);
                                if let Some(addr) = addr {
                                    let _ = down_local.send_to(&payload, addr).await;
                                    down_stats.forwarded.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        None => {
                            down_stats.malformed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    for payload in buffer.tick(Instant::now()) {
                        let addr = down_sender
                            .lock()
                            .ok()
                            .and_then(|slot| *slot)
                            .or(peer_addr);
                        if let Some(addr) = addr {
                            let _ = down_local.send_to(&payload, addr).await;
                            down_stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    });

    tokio::signal::ctrl_c().await.ok();
    println!("Party stopped. {}", stats.snapshot());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_reject_garbage() {
        let frame = PartyFrame {
            seq: 42,
            payload: b"player position".to_vec(),
        };
        let wire = frame.encode().unwrap();
        assert_eq!(PartyFrame::decode(&wire), Some(frame));

        assert!(PartyFrame::decode(b"XXXX").is_none());
        assert!(PartyFrame::decode(&wire[..wire.len() - 1]).is_none());
        let too_big = PartyFrame {
            seq: 1,
            payload: vec![0u8; PARTY_MAX_PAYLOAD + 1],
        };
        assert!(too_big.encode().is_none());
    }

    #[test]
    fn duplicates_are_suppressed_inside_the_window() {
        let mut w = SeqWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(1), "duplicate");
        assert!(!w.accept(2), "duplicate");
        assert!(w.accept(3));
        assert!(w.accept(10), "gap is fine, order is not required here");
        assert!(!w.accept(10));
    }

    #[test]
    fn very_old_sequences_fall_out_of_the_window() {
        let mut w = SeqWindow::new();
        assert!(w.accept(5_000));
        assert!(!w.accept(5_000 - SEQ_WINDOW), "too old to judge, drop");
        assert!(!w.accept(1));
        assert!(w.accept(5_001));
    }

    #[test]
    fn bitmap_shifts_correctly_across_word_boundaries() {
        let mut w = SeqWindow::new();
        for seq in 0..200u64 {
            assert!(w.accept(seq), "seq {seq}");
        }
        // Every one of them is still a duplicate.
        for seq in 0..200u64 {
            assert!(!w.accept(seq), "seq {seq} should be remembered");
        }
        // A jump of exactly one word must not resurrect old entries.
        assert!(w.accept(200 + 64 - 1));
        assert!(!w.accept(200 + 64 - 1));
    }

    #[test]
    fn jitter_buffer_orders_within_a_stream() {
        let t0 = Instant::now();
        let mut b = JitterBuffer::new(Duration::from_millis(20));
        // The first datagram of a stream is the baseline: there is no reason to
        // wait for a sequence number that may pre-date the session.
        assert_eq!(b.push(0, b"zero".to_vec(), t0), vec![b"zero".to_vec()]);
        assert!(b.push(2, b"two".to_vec(), t0).is_empty(), "waiting for 1");
        assert_eq!(
            b.push(1, b"one".to_vec(), t0),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(b.depth(), 0);
    }

    #[test]
    fn jitter_buffer_does_not_wait_forever_for_a_lost_packet() {
        let t0 = Instant::now();
        let mut b = JitterBuffer::new(Duration::from_millis(20));
        assert_eq!(b.push(0, b"zero".to_vec(), t0), vec![b"zero".to_vec()]);
        assert!(b.push(2, b"two".to_vec(), t0).is_empty());
        assert!(b.tick(t0 + Duration::from_millis(5)).is_empty(), "still inside the delay");
        assert_eq!(b.tick(t0 + Duration::from_millis(25)), vec![b"two".to_vec()]);
    }

    #[test]
    fn frames_older_than_the_next_expected_are_dropped() {
        let t0 = Instant::now();
        let mut b = JitterBuffer::new(Duration::ZERO);
        assert_eq!(b.push(10, b"a".to_vec(), t0), vec![b"a".to_vec()]);
        assert!(b.push(9, b"old".to_vec(), t0).is_empty());
        assert_eq!(b.depth(), 0);
    }
}
