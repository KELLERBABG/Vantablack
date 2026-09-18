//! VPN client pump: TUN ⇄ mesh with UNRELIABLE tunnel datagrams.
//!
//! Implements PROTOTYPE.md rule 1: packets from the TUN are sealed
//! (`seal_datagram`, own counter space + epoch) and handed to the caller's
//! mesh sender — never registered with AckEngine, never retransmitted, never
//! reordered. Inbound datagrams go through `VpnIngress` (auth + replay only)
//! and are written to the TUN immediately: no head-of-line blocking.
//!
//! The mesh transport itself is abstracted behind [`MeshSender`] /
//! [`MeshReceiver`] so tests run against in-memory queues (and the
//! LossyVirtualLink in `virtual_net.rs`).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Arc;

use parking_lot::Mutex;

use super::{seal_datagram, OpenOutcome, VpnIngress, TUNNEL_HDR_LEN};

/// What the client uses to push sealed datagrams into the mesh.
pub trait MeshSender: Send + Sync {
    fn send_datagram(&self, wire: Vec<u8>);
}

/// What the client uses to receive sealed datagrams from the mesh.
pub trait MeshReceiver: Send {
    /// Next tunnel datagram from the hub (blocking is allowed).
    fn recv_datagram(&mut self) -> Option<Vec<u8>>;
}

/// Per-epoch client TX state: one monotonic counter per epoch.
pub struct ClientState {
    pub fingerprint: String,
    pub epoch: AtomicU32,
    /// Widened from AtomicU32 to eliminate 32-bit counter exhaustion.
    tx_counter: AtomicU64,
    key: Mutex<[u8; 32]>,
    ingress: VpnIngress,
    /// Resilience loop state (see resilience::TunnelWatchdog).
    pub watchdog: Mutex<resilience::TunnelWatchdog>,
    /// Millis clock of the last authenticated inbound datagram.
    last_inbound_ms: AtomicU64,
}

impl ClientState {
    pub fn new(fingerprint: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            epoch: AtomicU32::new(1),
            tx_counter: AtomicU64::new(1),
            key: Mutex::new(key),
            ingress: VpnIngress::new(),
            watchdog: Mutex::new(resilience::TunnelWatchdog::new()),
            last_inbound_ms: AtomicU64::new(0),
        }
    }

    pub fn set_key(&self, k: [u8; 32]) {
        *self.key.lock() = k;
    }

    pub fn key(&self) -> [u8; 32] {
        *self.key.lock()
    }

    /// Fresh handshake completed: rotate epoch (clears counters + windows).
    pub fn rotate_epoch(&self) -> u32 {
        self.tx_counter.store(1, Ordering::Relaxed);
        let e = self.epoch.fetch_add(1, Ordering::Relaxed) + 1;
        self.ingress.evict(&self.fingerprint);
        e
    }

    /// Watchdog feed: record an authenticated inbound datagram.
    pub fn note_inbound(&self) {
        self.last_inbound_ms.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            Ordering::Relaxed,
        );
    }

    /// Millis clock of the last authenticated inbound datagram.
    pub fn last_inbound_ms(&self) -> u64 {
        self.last_inbound_ms.load(Ordering::Relaxed)
    }

    pub fn current_epoch(&self) -> u32 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Current TX counter (diagnostics/tests).
    pub fn tx_counter(&self) -> u64 {
        self.tx_counter.load(Ordering::Relaxed)
    }
}

/// Errors from the pump.
#[derive(Debug)]
pub enum PumpError {
    Tun(std::io::Error),
    PacketTooBig(usize),
}

/// Max inner IP packet that fits the tunnel datagram budget.
pub const MAX_IP_PACKET: usize = super::TUNNEL_MAX_PAYLOAD - 16 - TUNNEL_HDR_LEN;

/// Seal one TUN packet for the wire. Returns None for oversized packets.
pub fn seal_from_tun(state: &ClientState, ip_packet: &[u8]) -> Option<Vec<u8>> {
    if ip_packet.len() > MAX_IP_PACKET {
        return None;
    }
    let e = state.current_epoch();
    // counter space is per-epoch: high 0 bits + epoch already in header,
    // so a plain per-epoch counter is enough.
    let ctr = state.tx_counter.fetch_add(1, Ordering::Relaxed);
    Some(seal_datagram(&state.key(), e, ctr, ip_packet))
}

/// Open one wire datagram and, if fresh, write it into the TUN.
/// Returns (accepted, advanced) for the caller's re-anchor logic.
pub fn open_to_tun(
    state: &ClientState,
    wire: &[u8],
    tun: &dyn crate::ghost::net::vpn::tun::TunDevice,
) -> (bool, bool) {
    let e = state.current_epoch();
    match state
        .ingress
        .open(&state.key(), &state.fingerprint, e, wire)
    {
        OpenOutcome::Accepted {
            ip_packet,
            advanced,
        } => {
            state.note_inbound();
            match tun.write_packet(&ip_packet) {
                Ok(_) => (true, advanced),
                Err(_) => (false, advanced),
            }
        }
        _ => (false, false),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::net::vpn::tun::FakeTun;

    /// In-memory mesh pair with configurable loss/reorder — the LossyVirtualLink
    /// lives in virtual_net.rs; here we use a perfect link for roundtrip checks.
    struct ChanSender(std::sync::mpsc::Sender<Vec<u8>>);
    struct ChanReceiver(std::sync::mpsc::Receiver<Vec<u8>>);

    impl MeshSender for ChanSender {
        fn send_datagram(&self, wire: Vec<u8>) {
            let _ = self.0.send(wire);
        }
    }
    impl MeshReceiver for ChanReceiver {
        fn recv_datagram(&mut self) -> Option<Vec<u8>> {
            self.0.recv().ok()
        }
    }

    #[test]
    fn client_roundtrip_perfect_link() {
        // "phone" and "hub" states sharing one key
        let key = [9u8; 32];
        let phone = Arc::new(ClientState::new("phone", key));
        let hub_ing = VpnIngress::new();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let sender = ChanSender(tx);
        let mut recv = ChanReceiver(rx);

        // TUN produces a packet → seal → "mesh" → hub opens
        let mut tun = FakeTun::new();
        tun.push_inbound(vec![0x45u8; 40]);
        let mut rbuf = [0u8; 1400];
        let n = crate::ghost::net::vpn::tun::TunDevice::read_packet(&mut tun, &mut rbuf).unwrap();
        let wire = seal_from_tun(&phone, &rbuf[..n]).unwrap();
        sender.send_datagram(wire);
        let wire = recv.recv_datagram().unwrap();
        let hub_epoch = 1;
        match hub_ing.open(&key, "phone", hub_epoch, &wire) {
            OpenOutcome::Accepted {
                ip_packet,
                advanced,
            } => {
                assert_eq!(ip_packet, vec![0x45u8; 40]);
                assert!(advanced);
            }
            _ => panic!("hub must accept first packet"),
        }

        // hub replies → client opens → TUN receives
        let reply = seal_datagram(&key, hub_epoch, 1, &[0x45u8; 60]);
        let (accepted, _adv) = open_to_tun(&phone, &reply, &tun);
        assert!(accepted);
        let out = tun.drain_outbound();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![0x45u8; 60]);
    }

    #[test]
    fn epoch_rotation_resets_counters_and_windows() {
        let key = [5u8; 32];
        let c = ClientState::new("c", key);
        let w1 = seal_from_tun(&c, &[1u8; 20]).unwrap();
        let w2 = seal_from_tun(&c, &[2u8; 20]).unwrap();
        // rotate (simulates reconnect): old wire must fail epoch check
        let new_epoch = c.rotate_epoch();
        assert_eq!(new_epoch, 2);
        let ing = VpnIngress::new();
        assert!(matches!(ing.open(&key, "c", 2, &w1), OpenOutcome::AuthFail));
        // new-epoch packet opens
        let w3 = seal_from_tun(&c, &[3u8; 20]).unwrap();
        assert!(matches!(
            ing.open(&key, "c", 2, &w3),
            OpenOutcome::Accepted { .. }
        ));
        // and w2 (old epoch) never opens under the new epoch
        assert!(matches!(ing.open(&key, "c", 2, &w2), OpenOutcome::AuthFail));
    }

    #[test]
    fn oversized_packets_are_refused() {
        let c = ClientState::new("c", [1u8; 32]);
        assert!(seal_from_tun(&c, &vec![0u8; MAX_IP_PACKET + 1]).is_none());
        assert!(seal_from_tun(&c, &vec![0u8; MAX_IP_PACKET]).is_some());
    }
}

// ── Client resilience: tunnel watchdog + keepalive ──────────────────

pub mod resilience {
    //! Decides WHEN the tunnel looks dead and drives recovery: an ICMP echo
    //! keepalive to the hub's overlay IP (the hub already answers it —
    //! `answer_icmp`), then a fresh handshake with exponential backoff. Pure
    //! state machine: callers inject `Instant`s, so every transition is
    //! unit-testable without a runtime.
    //!
    //! Cadence: one 28-byte probe per ≥10 s of idle; dead after 30 s of total
    //! inbound silence; recovery via mesh-level handshake (gated 2→30 s).
    //! After `MAX_ATTEMPTS` the machine stops dialing but any inbound datagram
    //! (e.g. user traffic once the hub returns) still heals it instantly.

    use std::time::{Duration, Instant};

    /// Idle tunnel: send a keepalive echo after this much silence.
    pub const KEEPALIVE_AFTER: Duration = Duration::from_secs(10);
    /// No inbound traffic for this long (keepalive unanswered) → tunnel dead,
    /// re-handshake. Must exceed KEEPALIVE_AFTER so one probe round fits.
    pub const SILENCE_SECS: u64 = 30;
    /// Backoff before attempt n: BACKOFF_BASE * 2^(n-1), capped.
    pub const BACKOFF_BASE: Duration = Duration::from_secs(2);
    pub const BACKOFF_CAP: Duration = Duration::from_secs(30);
    /// Give up dialing after this many consecutive dead-tunnel re-handshakes
    /// (stay probing; the next inbound datagram still heals).
    pub const MAX_ATTEMPTS: u32 = 6;

    /// What the caller should do now.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Action {
        Nothing,
        /// Send the keepalive echo (then wait up to SILENCE for a reply).
        SendKeepalive,
        /// Run a fresh handshake to the hub (n-th consecutive attempt).
        Rehandshake {
            attempt: u32,
        },
    }

    /// Tunnel liveness state machine. All times are injected for tests.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Phase {
        Healthy,
        Probing,
        Dead,
    }

    #[derive(Debug)]
    pub struct TunnelWatchdog {
        phase: Phase,
        /// Last observed inbound tunnel traffic.
        last_inbound: Instant,
        /// Consecutive dead-tunnel re-handshake attempts.
        attempts: u32,
        /// When the last re-handshake was kicked (backoff gate).
        last_attempt: Option<Instant>,
    }

    impl Default for TunnelWatchdog {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TunnelWatchdog {
        pub fn new() -> Self {
            Self::new_at(Instant::now())
        }

        pub fn new_at(now: Instant) -> Self {
            Self {
                phase: Phase::Healthy,
                last_inbound: now,
                attempts: 0,
                last_attempt: None,
            }
        }

        /// Any authenticated inbound tunnel datagram (keepalive reply counts).
        pub fn on_inbound(&mut self, now: Instant) {
            self.phase = Phase::Healthy;
            self.last_inbound = now;
            self.attempts = 0;
            self.last_attempt = None;
        }

        /// Drive the machine. Cheap; call from the client pump tick.
        pub fn poll(&mut self, now: Instant) -> Action {
            let idle = now.saturating_duration_since(self.last_inbound);
            match self.phase {
                Phase::Healthy => {
                    if idle >= KEEPALIVE_AFTER {
                        self.phase = Phase::Probing;
                        Action::SendKeepalive
                    } else {
                        Action::Nothing
                    }
                }
                Phase::Probing => {
                    if idle >= Duration::from_secs(SILENCE_SECS) {
                        self.phase = Phase::Dead;
                    }
                    Action::Nothing
                }
                Phase::Dead => {
                    if self.attempts >= MAX_ATTEMPTS {
                        return Action::Nothing;
                    }
                    let due = self.last_attempt.map(|t| t + self.backoff()).unwrap_or(now);
                    if now >= due {
                        self.attempts += 1;
                        self.last_attempt = Some(now);
                        Action::Rehandshake {
                            attempt: self.attempts,
                        }
                    } else {
                        Action::Nothing
                    }
                }
            }
        }

        /// Drive the machine *and* honour the tunnel-counter headroom.
        ///
        /// PROTOTYPE.md flaw #1: the tunnel counter is per-epoch and the peer's
        /// replay window is monotonic — once a counter wraps, every later frame is
        /// rejected forever. A spent counter is therefore as fatal as a dead
        /// tunnel, and the same recovery vehicle fixes it (fresh handshake → epoch
        /// rotation → both counters reset). Checked *before* the liveness machine
        /// so exhaustion takes precedence over a merely idle link.
        pub fn poll_with_counter(&mut self, now: Instant, tx_counter: u64) -> Action {
            // Re-key well before the wrap. The margin wants to exceed the worst-case
            // RTT + handshake time at the client's peak frame rate.
            const COUNTER_REKEY_AT: u64 = u64::MAX - 10_000_000;
            if tx_counter < COUNTER_REKEY_AT {
                return self.poll(now);
            }
            if self.attempts >= MAX_ATTEMPTS {
                return Action::Nothing;
            }
            let due = self.last_attempt.map(|t| t + self.backoff()).unwrap_or(now);
            if now < due {
                return Action::Nothing;
            }
            self.attempts += 1;
            self.last_attempt = Some(now);
            Action::Rehandshake {
                attempt: self.attempts,
            }
        }

        fn backoff(&self) -> Duration {
            let exp = self.attempts.saturating_sub(1).min(5);
            BACKOFF_BASE.saturating_mul(1u32 << exp).min(BACKOFF_CAP)
        }

        /// Diagnostics (VPN STATUS).
        pub fn is_dead(&self) -> bool {
            self.phase == Phase::Dead
        }
        pub fn attempts(&self) -> u32 {
            self.attempts
        }
    }

    /// ICMP echo request to the hub's overlay IP (28 bytes, valid IP checksum).
    /// The hub's `answer_icmp` replies to echoes addressed to its overlay IP,
    /// so a successful round trip proves the tunnel is bidirectionally alive
    /// with zero hub-side changes.
    pub fn build_keepalive(
        hub_overlay: std::net::Ipv4Addr,
        client_ip: std::net::Ipv4Addr,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&client_ip.octets());
        pkt[16..20].copy_from_slice(&hub_overlay.octets());
        pkt[20] = 8; // echo request
        pkt[22..24].copy_from_slice(&0x4B1Du16.to_be_bytes()); // marker id
        pkt[24..26].copy_from_slice(&1u16.to_be_bytes()); // seq
        let sum = super::super::hub::internet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        pkt
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn at(secs: u64) -> Instant {
            Instant::now() + Duration::from_secs(secs)
        }

        #[test]
        fn watchdog_transitions_idle_probe_dead_rehandshake() {
            let t0 = at(0);
            let mut w = TunnelWatchdog::new_at(t0);
            // Fresh tunnel: quiet until KEEPALIVE_AFTER.
            assert_eq!(w.poll(at(5)), Action::Nothing);
            assert_eq!(w.poll(at(10)), Action::SendKeepalive, "idle → probe");
            // Probe answered: healthy again.
            w.on_inbound(at(11));
            assert_eq!(w.poll(at(25)), Action::SendKeepalive, "idle again → probe");
            // Probe NOT answered: dead at SILENCE_SECS since last inbound (26+30=56).
            // Note: on_inbound started a NEW silence window, so a fresh probe
            // fires once idle re-passes KEEPALIVE_AFTER — one probe per window.
            w.on_inbound(at(26));
            assert_eq!(w.poll(at(50)), Action::SendKeepalive, "new window's probe");
            assert_eq!(w.poll(at(55)), Action::Nothing, "idle 29 < 30");
            assert_eq!(w.poll(at(56)), Action::Nothing, "dead transition poll");
            // Dead → rehandshake immediately, then backoff 2 s, 4 s.
            assert_eq!(w.poll(at(57)), Action::Rehandshake { attempt: 1 });
            assert_eq!(w.poll(at(58)), Action::Nothing, "inside 2 s backoff");
            assert_eq!(w.poll(at(59)), Action::Rehandshake { attempt: 2 });
            assert_eq!(w.poll(at(61)), Action::Nothing, "inside 4 s backoff");
            assert_eq!(w.poll(at(63)), Action::Rehandshake { attempt: 3 });
            // Inbound heals everything.
            w.on_inbound(at(64));
            assert!(!w.is_dead());
            assert_eq!(w.attempts(), 0);
        }

        #[test]
        fn watchdog_backoff_caps_and_gives_up() {
            let t0 = at(0);
            let mut w = TunnelWatchdog::new_at(t0);
            let _ = w.poll(at(10)); // probe
            let _ = w.poll(at(30)); // dead transition
            let mut last = 30u64;
            for n in 1..=MAX_ATTEMPTS {
                let mut s = last;
                loop {
                    s += 1;
                    if let Action::Rehandshake { attempt } = w.poll(at(s)) {
                        assert_eq!(attempt, n);
                        break;
                    }
                }
                last = s;
            }
            // MAX_ATTEMPTS reached: never again, even far in the future.
            assert_eq!(w.poll(at(last + 3600)), Action::Nothing);
            // But one inbound datagram revives the machine fully.
            w.on_inbound(at(last + 3601));
            assert_eq!(w.poll(at(last + 3611)), Action::SendKeepalive);
        }

        #[test]
        fn counter_exhaustion_triggers_rehandshake_before_wrap() {
            // PROTOTYPE.md flaw #1: once the tunnel counter wraps, the peer's
            // monotonic replay window rejects every later frame *forever*. The
            // watchdog must therefore demand a fresh epoch before that point,
            // reusing the same recovery vehicle as a dead link.
            const BELOW: u64 = u64::MAX - 20_000_000; // under the re-key margin
            const ABOVE: u64 = u64::MAX - 100_000; // past the re-key margin

            // Headroom: the counter must never override the liveness machine.
            let t0 = at(0);
            let mut w = TunnelWatchdog::new_at(t0);
            assert_eq!(w.poll_with_counter(at(1), BELOW), Action::Nothing);
            assert_eq!(
                w.poll_with_counter(at(10), BELOW),
                Action::SendKeepalive,
                "counter headroom must not mask the normal idle probe"
            );

            // Past the margin: re-handshake at once, then honour the backoff gate.
            let mut w = TunnelWatchdog::new_at(t0);
            assert_eq!(
                w.poll_with_counter(at(1), ABOVE),
                Action::Rehandshake { attempt: 1 }
            );
            assert_eq!(
                w.poll_with_counter(at(2), ABOVE),
                Action::Nothing,
                "inside backoff"
            );
            assert_eq!(
                w.poll_with_counter(at(3), ABOVE),
                Action::Rehandshake { attempt: 2 }
            );

            // A healthy inbound datagram (post-rotation, low counter) resets it.
            w.on_inbound(at(4));
            assert_eq!(w.poll_with_counter(at(5), 7), Action::Nothing);
            assert_eq!(w.attempts(), 0);
            assert!(!w.is_dead());
        }

        #[test]
        fn keepalive_packet_is_a_valid_echo_request() {
            use super::super::super::hub::internet_checksum;
            let pkt = build_keepalive(
                std::net::Ipv4Addr::new(10, 66, 0, 1),
                std::net::Ipv4Addr::new(10, 66, 0, 10),
            );
            assert_eq!(pkt.len(), 28);
            assert_eq!(pkt[9], 1, "ICMP");
            assert_eq!(&pkt[16..20], &[10, 66, 0, 1], "dst = hub overlay");
            assert_eq!(&pkt[12..16], &[10, 66, 0, 10], "src = client overlay");
            assert_eq!(pkt[20], 8, "echo request");
            assert_eq!(internet_checksum(&pkt[..20]), 0, "IP checksum valid");
        }
    }
}

pub use resilience::{build_keepalive, Action, TunnelWatchdog};
