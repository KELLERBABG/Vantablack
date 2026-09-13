#![cfg(feature = "vpn")]

//! Literal M2 backpressure gate (PROTOTYPE.md / audit round 2):
//! a fast producer (a real LAN TcpStream writing 10 MB into the hub's proxy)
//! and a throttled consumer (the test drains netstack egress at 1 packet per
//! 5 ms for the throttle phase, then flat-out).
//!
//! Assertions:
//! - all 10 MB arrive byte-exact (the no-drop invariant on stack→LAN … i.e.
//!   LAN→stack→mesh here) despite the consumer stalling,
//! - the stall actually happened (elapsed >= throttle phase),
//! - the flow tears down cleanly and aggregates its byte counters.

use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::time::{Duration, Instant};

use vantablack::ghost::net::vpn::netstack::Netstack;

// ── raw IPv4+TCP packet helpers (valid checksums; smoltcp enforces them) ──

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a client→hub TCP segment: src 10.66.0.10:52000 → dst `dst`.
/// `payload` may be empty; flags: 0x02 SYN, 0x10 ACK, 0x08 FIN.
fn tcp_packet(
    dst: (Ipv4Addr, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ihl = 20;
    let mut pkt = vec![0u8; ihl + 20 + payload.len()];
    pkt[0] = 0x45;
    let total = (ihl + 20 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 66, 0, 10]);
    pkt[16..20].copy_from_slice(&dst.0.octets());
    pkt[ihl..ihl + 2].copy_from_slice(&52000u16.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&dst.1.to_be_bytes());
    pkt[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[ihl + 8..ihl + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[ihl + 12] = 0x50; // data offset 5
    pkt[ihl + 13] = flags;
    pkt[ihl + 14..ihl + 16].copy_from_slice(&window.to_be_bytes());
    pkt[ihl + 20..].copy_from_slice(payload);

    // TCP checksum with pseudo-header
    let mut pseudo = Vec::with_capacity(12 + 20 + payload.len());
    pseudo.extend_from_slice(&[10, 66, 0, 10]);
    pseudo.extend_from_slice(&dst.0.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[ihl..ihl + 20 + payload.len()]);
    let sum = internet_checksum(&pseudo);
    pkt[ihl + 16..ihl + 18].copy_from_slice(&sum.to_be_bytes());

    // IPv4 header checksum
    let sum = internet_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&sum.to_be_bytes());
    pkt
}

/// Extract (payload, seq, ack, flags, src_port) from a stack→client packet
/// (src 10.200.0.1:L, dst 10.200.0.2:52000).
fn parse_stack_pkt(pkt: &[u8]) -> Option<(Vec<u8>, u32, u32, u8)> {
    if pkt.len() < 40 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total > pkt.len() {
        return None;
    }
    let seq = u32::from_be_bytes(pkt[ihl + 4..ihl + 8].try_into().ok()?);
    let ack = u32::from_be_bytes(pkt[ihl + 8..ihl + 12].try_into().ok()?);
    let flags = pkt[ihl + 13];
    // data offset nibble: SYN/SYN-ACK segments carry options (MSS etc.)
    let doff = ((pkt[ihl + 12] >> 4) as usize) * 4;
    if doff < 20 || ihl + doff > total {
        return None;
    }
    let payload = pkt[ihl + doff..total].to_vec();
    Some((payload, seq, ack, flags))
}

const TOTAL: usize = 10 * 1024 * 1024;
const CLIENT_ISN: u32 = 900;
const CLIENT_PORT: u16 = 52000;

#[test]
fn m2_backpressure_10mb_fast_producer_throttled_consumer_zero_loss() {
    let ns = Netstack::start();

    // "NAS": real loopback listener. Writes 10 MB of a deterministic pattern.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let nas_port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_nodelay(true).ok();
        let mut written = 0usize;
        let mut ctr = 0u32;
        while written < TOTAL {
            let chunk = TOTAL - written;
            let n = chunk.min(8192);
            let mut buf = vec![0u8; n];
            for i in (0..n).step_by(4) {
                let end = (i + 4).min(n);
                buf[i..end].copy_from_slice(&ctr.to_be_bytes()[..end - i]);
                if end - i == 4 {
                    ctr = ctr.wrapping_add(1);
                }
            }
            if conn.write_all(&buf).is_err() {
                break;
            }
            written += n;
        }
        // Keep the connection open (no FIN) until the test asserts; a clean
        // FIN would race the client's data path.
        written
    });

    // 1. SYN → SYN-ACK → ACK (dst = the NAS tuple; the netstack NATs it).
    let dst = (Ipv4Addr::new(127, 0, 0, 1), nas_port);
    let syn = tcp_packet(dst, CLIENT_ISN, 0, 0x02, 65535, &[]);
    ns.try_feed(syn).unwrap();

    let mut server_isn = 0u32;
    let deadline = Instant::now() + Duration::from_secs(5);
    while server_isn == 0 && Instant::now() < deadline {
        if let Some(pkt) = ns.poll_outgoing() {
            if let Some((p, seq, _ack, flags)) = parse_stack_pkt(&pkt) {
                if flags & 0x12 == 0x12 {
                    // SYN-ACK
                    server_isn = seq;
                    assert!(p.is_empty());
                }
            }
        }
    }
    assert_ne!(server_isn, 0, "no SYN-ACK");
    let ack = tcp_packet(dst, CLIENT_ISN + 1, server_isn + 1, 0x10, 65535, &[]);
    ns.try_feed(ack).unwrap();

    // 2. Pump: drain egress (throttled at first), ACK everything received.
    let mut received: Vec<u8> = Vec::with_capacity(TOTAL);
    let mut next_ack = server_isn + 1;
    let mut drained = 0usize;
    let start = Instant::now();
    let throttle_until = start + Duration::from_secs(2); // consumer stalls here
    let hard_deadline = start + Duration::from_secs(90);
    let mut last_progress = Instant::now();
    while received.len() < TOTAL && Instant::now() < hard_deadline {
        let mut progressed = false;
        while let Some(pkt) = ns.poll_outgoing() {
            drained += 1;
            progressed = true;
            if let Some((p, seq, _ack, flags)) = parse_stack_pkt(&pkt) {
                if !p.is_empty() && seq == next_ack {
                    received.extend_from_slice(&p);
                    next_ack = next_ack.wrapping_add(p.len() as u32);
                }
                if flags & 0x01 != 0 {
                    // FIN from the stack (server closed) — stop after this.
                }
            }
            // ACK the data so the window stays open; the ONLY throttle is
            // this drain rate.
            let a = tcp_packet(dst, CLIENT_ISN + 1, next_ack, 0x10, 65535, &[]);
            let _ = ns.try_feed(a);
        }
        if Instant::now() < throttle_until {
            std::thread::sleep(Duration::from_millis(5)); // 1 packet / 5 ms
        }
        if progressed {
            last_progress = Instant::now();
        } else if last_progress.elapsed() > Duration::from_secs(10) {
            panic!("no progress for 10 s — stalled past the throttle phase");
        }
    }
    let elapsed = start.elapsed();

    let written = server.join().unwrap();
    assert_eq!(written, TOTAL, "NAS wrote all bytes");

    // 3. Zero loss: byte-exact stream despite the 2 s consumer stall.
    assert_eq!(received.len(), TOTAL, "all 10 MB must arrive");
    let mut ctr = 0u32;
    for (i, chunk) in received.chunks(8192).enumerate() {
        let _ = i;
        for b in chunk.chunks(4) {
            let expect = &ctr.to_be_bytes()[..b.len()];
            assert_eq!(
                b,
                expect,
                "stream corruption at offset {}",
                (b.as_ptr() as usize) - (received.as_ptr() as usize)
            );
            if b.len() == 4 {
                ctr = ctr.wrapping_add(1);
            }
        }
    }

    // 4. The stall happened: throttled drain adds its full duration.
    assert!(drained > 1000, "must have drained a real stream: {drained}");
    assert!(
        elapsed >= Duration::from_secs(2),
        "consumer stall must slow the transfer, took {elapsed:?}"
    );

    // 5. Clean teardown & counters: after idle teardown (FLOW_IDLE + GC),
    //    tcp_flows must be 0 and the aggregated bytes_s2c (counted at
    //    sock.recv_slice = what the client actually received) must equal
    //    TOTAL exactly — no drops, no duplicates anywhere in the pipeline.
    let teardown_deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let st = ns.stats();
        if st.tcp_flows == 0 || Instant::now() > teardown_deadline {
            assert_eq!(st.tcp_flows, 0, "flow must tear down cleanly");
            // Driver naming: the LAN→client direction (our 10 MB) is counted
            // in bytes_c2s; bytes_s2c counts client→LAN payload (ACKs only).
            assert_eq!(
                st.bytes_c2s, TOTAL as u64,
                "aggregated LAN→client bytes must equal the delivered stream"
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
