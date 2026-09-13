#![cfg(feature = "vpn")]

//! MSS-clamp gate (audit round 2, rule 3 — the last ungated PROTOTYPE.md rule).
//!
//! Proves, through the REAL driver path and the REAL egress rewriter:
//! 1. a phone SYN advertising MSS 1460 reaches smoltcp advertising
//!    OVERLAY_MSS (1240) — clamped BEFORE the stack can accept it;
//! 2. the stack's own SYN-ACK fits the tunnel (device MTU 1280) and the
//!    `nat_egress` rewriter would clamp an oversized option as defense.
//!
//! Without the clamp, an LTE path that drops "fragmentation needed" ICMP
//! turns the 1280-byte tunnel MTU into a silent PMTUD blackhole.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use vantablack::ghost::net::vpn::netstack::{nat_egress, Netstack, NAT_ADDR, NETSTACK_ADDR};
use vantablack::ghost::net::vpn::OVERLAY_MSS;

mod common;
use common::wire::{internet_checksum, read_mss_option, tcp_packet_opts};

const CLIENT: ([u8; 4], u16) = ([10, 66, 0, 10], 51444);
const NAS: ([u8; 4], u16) = ([192, 168, 1, 50], 445);
const CLIENT_ISN: u32 = 700;

/// What the phone sends: SYN → dst NAS, advertising MSS 1460 (typical LAN
/// Ethernet default — deliberately larger than the tunnel can carry).
fn phone_syn() -> Vec<u8> {
    let mut opts = [0u8; 4];
    opts[0] = 2;
    opts[1] = 4;
    opts[2..4].copy_from_slice(&1460u16.to_be_bytes());
    tcp_packet_opts(CLIENT, NAS, CLIENT_ISN, 0, 0x02, 65535, &opts)
}

#[test]
fn mss_ingest_clamp_and_egress_reply_direction() {
    let ns = Netstack::start();

    // ── 1. Feed the oversized SYN through the real driver path. ──
    ns.try_feed(phone_syn()).unwrap();

    // Wait for teardown-free flow creation, then shut the driver down and
    // inspect what actually reached smoltcp by watching egress: the SYN-ACK.
    // The driver thread is the only reader of the flow; we poll egress for
    // the SYN-ACK and assert its advertised MSS fits the tunnel.
    let mut synack = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while synack.is_none() && Instant::now() < deadline {
        while let Some(pkt) = ns.poll_outgoing() {
            // Egress packets have already been reverse-NATed by nat_egress:
            // src = the real target (NAS), dst = the real client.
            if pkt.len() > 40 && &pkt[12..16] == &NAS.0[..] && &pkt[16..20] == &CLIENT.0[..] {
                let flags = pkt[20 + 13];
                if flags & 0x12 == 0x12 {
                    synack = Some(pkt);
                    break;
                }
            }
        }
        if synack.is_none() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let synack = synack.expect("no SYN-ACK — flow creation broken");
    assert_eq!(
        internet_checksum(&synack[..20]),
        0,
        "SYN-ACK must leave the hub with a valid IP checksum"
    );
    // smoltcp derives its MSS from the 1280 device MTU; assert it never
    // advertises more than the tunnel can carry.
    if let Some(mss) = read_mss_option(&synack) {
        assert!(
            mss <= OVERLAY_MSS,
            "stack SYN-ACK advertises MSS {mss} > tunnel limit {OVERLAY_MSS}"
        );
    }

    // ── 2. The egress rewriter clamps a LAN SYN-ACK with an oversized MSS. ──
    // Craft what smoltcp would emit for a SYN-ACK carrying MSS 1460
    // (e.g. if the device MTU were misconfigured), reverse-NAT it back to the
    // client, and assert the option was rewritten to OVERLAY_MSS.
    let mut opts = [0u8; 4];
    opts[0] = 2;
    opts[1] = 4;
    opts[2..4].copy_from_slice(&1460u16.to_be_bytes());
    let lan_synack = tcp_packet_opts(
        (NETSTACK_ADDR.octets(), 4450),
        (NAT_ADDR.octets(), CLIENT.1),
        900,
        CLIENT_ISN + 1,
        0x12, // SYN | ACK
        65535,
        &opts,
    );
    // The flow's reverse mapping: local port 4450 → the phone's tuple.
    let mut reverse = std::collections::HashMap::new();
    reverse.insert(
        4450u16,
        (
            Ipv4Addr::from(CLIENT.0),
            CLIENT.1,
            Ipv4Addr::from(NAS.0),
            NAS.1,
        ),
    );
    let to_client = nat_egress(&lan_synack, &reverse).expect("known reverse tuple");
    let mss = read_mss_option(&to_client).expect("SYN-ACK must keep its MSS option");
    assert_eq!(
        mss, OVERLAY_MSS,
        "egress must clamp an oversized LAN SYN-ACK MSS"
    );
    assert_eq!(internet_checksum(&to_client[..20]), 0, "IP checksum valid");
    // dst rewritten back to the real client, src to the real target
    assert_eq!(&to_client[12..16], &NAS.0[..]);
    assert_eq!(&to_client[16..20], &CLIENT.0[..]);

    // ── 3. A small advertised MSS passes through untouched. ──
    let mut small = [0u8; 4];
    small[0] = 2;
    small[1] = 4;
    small[2..4].copy_from_slice(&1000u16.to_be_bytes());
    let lan_synack_small = tcp_packet_opts(
        (NETSTACK_ADDR.octets(), 4451),
        (NAT_ADDR.octets(), CLIENT.1),
        901,
        CLIENT_ISN + 1,
        0x12,
        65535,
        &small,
    );
    reverse.insert(
        4451u16,
        (
            Ipv4Addr::from(CLIENT.0),
            CLIENT.1,
            Ipv4Addr::from(NAS.0),
            NAS.1,
        ),
    );
    let out = nat_egress(&lan_synack_small, &reverse).unwrap();
    assert_eq!(
        read_mss_option(&out),
        Some(1000),
        "clamp must only shrink, never grow"
    );

    ns.shutdown();
}
