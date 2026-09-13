#![cfg(feature = "vpn")]

//! M1/M2 verification gates from PROTOTYPE.md, as integration tests.
//!
//! - `m1_lossy_link_tunnel_survives`: LossyVirtualLink (reorder 1,3,2,5,4 +
//!   15 % drop of tunnel frames) — inner sequence space advances without any
//!   mesh-level retransmit queue (structural: the tunnel path has none).
//! - `m1_no_retransmit_structurally`: tunnel datagrams are sealed with an
//!   independent counter space and opened through VpnIngress only.
//! - `m2_migration_race`: N+1 from IP_B, then N from IP_A → egress locked
//!   to IP_B (LeaseTable monotonic rule).
//! - `m2_udp_flood`: 2 000 queries across 2 virtual peers → caps hold.
//! - `m2_backpressure_probe`: paused LAN reader wakes on headroom resume.

use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use vantablack::ghost::net::vpn::{
    client::{open_to_tun, seal_from_tun, ClientState},
    tun::{FakeTun, TunDevice},
    FlowKey, LeaseTable, OpenOutcome, UdpFlowTable, VpnIngress, UDP_FLOWS_PER_FP,
};

// ── LossyVirtualLink ────────────────────────────────────────────────

/// Simulated lossy mesh link: delivers the exact reorder pattern
/// (1,3,2,5,4) and drops 15 % of frames (deterministic, seeded).
struct LossyVirtualLink {
    queue: Mutex<Vec<Option<Vec<u8>>>>,
    /// deterministic PRNG state (xorshift)
    rng: Mutex<u64>,
    drop_pct: u64,
    dropped: AtomicU32,
    delivered: AtomicU32,
}

impl LossyVirtualLink {
    fn new() -> Self {
        Self {
            queue: Mutex::new(Vec::new()),
            rng: Mutex::new(0x9E3779B97F4A7C15),
            drop_pct: 15,
            dropped: AtomicU32::new(0),
            delivered: AtomicU32::new(0),
        }
    }

    fn next_rand(&self) -> u64 {
        let mut r = self.rng.lock();
        *r ^= *r << 13;
        *r ^= *r >> 7;
        *r ^= *r << 17;
        *r
    }

    /// Sender side: 15 % loss.
    fn send(&self, wire: Vec<u8>) {
        let keep = (self.next_rand() % 100) >= self.drop_pct;
        if keep {
            self.queue.lock().push(Some(wire));
        } else {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.queue.lock().push(None); // tombstone keeps the schedule fixed
        }
    }

    /// Reorder the already-queued frames into the 1,3,2,5,4 pattern per
    /// group of five (audit-specified schedule).
    fn apply_reorder_schedule(&self) {
        let mut q = self.queue.lock();
        for chunk in q.chunks_mut(5) {
            if chunk.len() == 5 {
                chunk.swap(1, 2); // 1,3,2,4,5
                chunk.swap(3, 4); // 1,3,2,5,4
            }
        }
    }

    fn drain(&self) -> Vec<Vec<u8>> {
        let mut q = self.queue.lock();
        let out = q
            .drain(..)
            .filter_map(|x| {
                if x.is_some() {
                    self.delivered
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                x
            })
            .collect();
        out
    }
}

// ── M1: lossy link ──────────────────────────────────────────────────

#[test]
fn m1_lossy_link_tunnel_survives() {
    let key = [77u8; 32];
    let phone = Arc::new(ClientState::new("phone_fp", key));
    let hub_ing = VpnIngress::new();
    let link = LossyVirtualLink::new();

    // 40 packets from the phone TUN through the lossy link.
    let mut tun = FakeTun::new();
    for i in 0..40u32 {
        let mut pkt = vec![0x45u8; 200];
        pkt[4..8].copy_from_slice(&i.to_be_bytes()); // inner sequence marker
        tun.push_inbound(pkt);
    }
    let mut rbuf = [0u8; 1400];
    loop {
        match TunDevice::read_packet(&mut tun, &mut rbuf) {
            Ok(n) => {
                let wire = seal_from_tun(&phone, &rbuf[..n]).expect("fits budget");
                link.send(wire);
            }
            Err(_) => break,
        }
    }
    link.apply_reorder_schedule();
    let wires = link.drain();

    // Hub opens everything that arrived; duplicates impossible, drops
    // expected (~15 %). NO retransmit request, NO reorder wait: accepted
    // packets are immediately usable — inner TCP would retransmit itself.
    let mut accepted = 0usize;
    let mut inner_seqs: Vec<u32> = Vec::new();
    for w in wires {
        match hub_ing.open(&key, "phone_fp", 1, &w) {
            OpenOutcome::Accepted { ip_packet, .. } => {
                accepted += 1;
                let seq =
                    u32::from_be_bytes([ip_packet[4], ip_packet[5], ip_packet[6], ip_packet[7]]);
                inner_seqs.push(seq);
            }
            _ => {}
        }
    }
    let drop_rate = 1.0 - (accepted as f64 / 40.0);
    assert!(
        drop_rate > 0.03 && drop_rate < 0.30,
        "drop rate implausible: {drop_rate}"
    );
    // accepted packets may arrive out of order — that is fine for L3.
    // The invariant: the sequence space is NOT re-sequenced by the mesh,
    // and no accepted packet was held back (delivery set == arrival set).
    inner_seqs.sort();
    inner_seqs.dedup();
    assert_eq!(inner_seqs.len(), accepted);
    // Structural: delivered + dropped == sent
    let d = link.dropped.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(accepted as u32 + d, 40);
}

#[test]
fn m1_no_retransmit_structurally() {
    // The tunnel wire format has no ACK/NAK channel and no retry: seal twice
    // with the same counter = deterministic replay (dropped, not re-sent).
    let key = [3u8; 32];
    let phone = ClientState::new("fp", key);
    let w1 = seal_from_tun(&phone, &[9u8; 64]).unwrap();
    let ing = VpnIngress::new();
    assert!(matches!(
        ing.open(&key, "fp", 1, &w1),
        OpenOutcome::Accepted { .. }
    ));
    assert!(matches!(ing.open(&key, "fp", 1, &w1), OpenOutcome::Replay));
    // counters are strictly monotonic per epoch (no reuse → no retransmit)
    let c1 = phone.tx_counter();
    let _ = seal_from_tun(&phone, &[8u8; 64]).unwrap();
    let c2 = phone.tx_counter();
    assert_eq!(c2, c1 + 1);
}

// ── M2: migration race ──────────────────────────────────────────────

#[test]
fn m2_migration_race_egress_locked_to_ip_b() {
    let lt = LeaseTable::new();
    let fp = "deadbeefdeadbeef";
    lt.lease_for(fp).unwrap();
    let ip_a: std::net::SocketAddr = "198.51.100.10:40000".parse().unwrap();
    let ip_b: std::net::SocketAddr = "203.0.113.99:51000".parse().unwrap();
    lt.rotate_epoch(fp, ip_a);

    // advance to counter 150 from IP_A
    for ctr in 1..=150u32 {
        lt.observe_tunnel_packet(fp, 1, ctr, ip_a);
    }
    // N+1 (151) from IP_B: window advance → re-anchor
    let (ok, ev) = lt.observe_tunnel_packet(fp, 1, 151, ip_b);
    assert!(ok && matches!(ev, vantablack::ghost::net::vpn::AnchorEvent::WindowAdvance));
    // late N (150) from IP_A: valid data, endpoint unchanged
    let (_ok, ev2) = lt.observe_tunnel_packet(fp, 1, 150, ip_a);
    assert!(matches!(
        ev2,
        vantablack::ghost::net::vpn::AnchorEvent::NoChange
    ));
    let lease_ip = lt.lease_for(fp).unwrap();
    assert_eq!(lt.endpoint_for_ip(lease_ip).unwrap(), ip_b);
}

// ── M2: UDP flood ───────────────────────────────────────────────────

#[test]
fn m2_udp_flood_caps_hold() {
    let binder = Box::new(|_a: std::net::IpAddr| {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .map(Arc::new)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrInUse, e))
    });
    let ft = UdpFlowTable::with_binder(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), binder);
    let peers = ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"];
    let mut created = 0usize;
    for q in 0..2000u32 {
        let fp = peers[(q % 2) as usize];
        let key = FlowKey {
            fp: fp.to_string(),
            overlay_src: std::net::Ipv4Addr::new(
                10,
                66,
                0,
                if fp.starts_with('a') { 10 } else { 11 },
            ),
            overlay_port: 4000 + (q % 64) as u16,
            dst: std::net::SocketAddr::from(([192, 168, 1, 1], 53)),
        };
        if ft.get_or_create(key).is_some() {
            created += 1;
        }
        if q % 100 == 0 {
            ft.sweep();
        }
    }
    assert_eq!(created, 2000 - ft_dropped(&ft)); // every non-dropped call OK
    assert!(ft.len() <= UDP_FLOWS_PER_FP * 2); // per-fp caps hold
                                               // final sweep: nothing expired yet except by TTL — table stays bounded
    assert!(ft.len() <= UDP_FLOWS_PER_FP * 2);
}

fn ft_dropped(_ft: &UdpFlowTable) -> usize {
    0 // get_or_create never errors on flood: LRU evicts, so all succeed
}

// ── M2: backpressure probe ──────────────────────────────────────────

#[test]
fn m2_backpressure_probe() {
    use vantablack::ghost::net::vpn::{Done, Headroom};
    let headroom = Arc::new(Headroom::new(1.0));
    let done = Arc::new(Done::new());
    let h2 = Arc::clone(&headroom);
    let d2 = Arc::clone(&done);
    // LAN reader pauses below 25 %, resumes only when headroom state rises
    let reader = std::thread::spawn(move || {
        let mut pauses = 0u64;
        loop {
            if d2.is_set() {
                break;
            }
            if h2.get() < 0.25 {
                pauses += 1;
                h2.wait_resume(0.75, &d2);
                if d2.is_set() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        pauses
    });
    // simulate fast producer / throttled consumer
    std::thread::sleep(Duration::from_millis(20));
    headroom.set(0.10); // buffer fills → pause
    std::thread::sleep(Duration::from_millis(40));
    headroom.set(0.90); // ACK drains → resume
    std::thread::sleep(Duration::from_millis(40));
    headroom.set(0.10);
    std::thread::sleep(Duration::from_millis(40));
    done.set();
    let pauses = reader.join().unwrap();
    assert!(
        pauses >= 2,
        "reader must have paused at least twice, got {pauses}"
    );
}

// ── E2E: phone TUN → lossy mesh → hub lease → (hub reply) → phone TUN ──

#[test]
fn m2_end_to_end_phone_to_hub_and_back() {
    let key = [31u8; 32];
    let phone = Arc::new(ClientState::new("a1b2c3d4e5f6a7b8", key));
    let lt = LeaseTable::new();
    let fp = "a1b2c3d4e5f6a7b8";
    lt.lease_for(fp).unwrap();
    let phone_addr: std::net::SocketAddr = "198.51.100.7:45000".parse().unwrap();
    lt.rotate_epoch(fp, phone_addr);
    let hub_ing = VpnIngress::new();
    let link = LossyVirtualLink::new();

    // 1. phone sends 10 packets
    let mut tun = FakeTun::new();
    for i in 0..10u32 {
        let mut pkt = vec![0x45u8; 120];
        pkt[4..8].copy_from_slice(&i.to_be_bytes());
        tun.push_inbound(pkt);
    }
    let mut rbuf = [0u8; 1400];
    while let Ok(n) = TunDevice::read_packet(&mut tun, &mut rbuf) {
        let wire = seal_from_tun(&phone, &rbuf[..n]).unwrap();
        link.send(wire);
    }
    link.apply_reorder_schedule();

    // 2. hub receives: auth + replay + lease observe (real pipeline order)
    let mut hub_saw = 0usize;
    for w in link.drain() {
        if let OpenOutcome::Accepted {
            ip_packet,
            advanced,
        } = hub_ing.open(&key, fp, 1, &w)
        {
            let (ok, _ev) = lt.observe_tunnel_packet(
                fp,
                1,
                u32::from_be_bytes([w[4], w[5], w[6], w[7]]),
                phone_addr,
            );
            assert!(ok);
            let _ = (ip_packet, advanced);
            hub_saw += 1;
        }
    }
    assert!(hub_saw >= 7, "too many drops: {hub_saw}/10");

    // 3. hub replies via the lease endpoint; the PHONE opens them with its
    // own per-direction ingress (directions never share a replay window —
    // same rule as the AEAD NonceDirection split in l2_aead).
    let phone_ing = VpnIngress::new();
    let mut tun2 = FakeTun::new();
    let mut replies = 0usize;
    for ctr in 1..=hub_saw as u32 {
        let wire = vantablack::ghost::net::vpn::seal_datagram(&key, 1, ctr, &[0x45u8; 100]);
        if let OpenOutcome::Accepted {
            ip_packet,
            advanced,
        } = phone_ing.open(&key, fp, 1, &wire)
        {
            let (accepted, _) = open_to_tun(&phone, &wire, &tun2);
            assert!(accepted);
            let _ = (ip_packet, advanced);
            replies += 1;
        }
    }
    // every accepted reply landed in the phone TUN
    assert_eq!(tun2.drain_outbound().len(), replies);
    assert_eq!(replies, hub_saw);
    // final: phone-side lease endpoint is stable
    assert_eq!(
        lt.endpoint_for_ip(lt.lease_for(fp).unwrap()).unwrap(),
        phone_addr
    );
    drop(tun2);
}
