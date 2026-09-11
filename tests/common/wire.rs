//! Shared IPv4/TCP/UDP wire helpers for VPN gate tests.
//!
//! Usage: `mod common; use common::wire::*;`

/// Standard Internet checksum (RFC 1071).
pub fn internet_checksum(data: &[u8]) -> u16 {
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

/// Recompute the IPv4 header checksum of `pkt` in place.
pub fn fix_ip_checksum(pkt: &mut [u8], ihl: usize) {
    pkt[10] = 0;
    pkt[11] = 0;
    let sum = internet_checksum(&pkt[..ihl]);
    pkt[10] = (sum >> 8) as u8;
    pkt[11] = (sum & 0xFF) as u8;
}

/// Recompute the TCP checksum (with pseudo-header) in place.
pub fn fix_tcp_checksum(pkt: &mut [u8], ihl: usize) {
    let csum_off = ihl + 16;
    pkt[csum_off] = 0;
    pkt[csum_off + 1] = 0;
    let l4_len = pkt.len() - ihl;
    let mut buf = Vec::with_capacity(12 + l4_len);
    buf.extend_from_slice(&pkt[12..20]);
    buf.push(0);
    buf.push(6);
    buf.extend_from_slice(&(l4_len as u16).to_be_bytes());
    buf.extend_from_slice(&pkt[ihl..]);
    let sum = internet_checksum(&buf);
    pkt[csum_off] = (sum >> 8) as u8;
    pkt[csum_off + 1] = (sum & 0xFF) as u8;
}

/// Build a raw IPv4+TCP packet with arbitrary TCP options.
/// `options` is the raw option bytes (must be a multiple of 4, ≤ 40).
#[allow(clippy::too_many_arguments)]
pub fn tcp_packet_opts(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
) -> Vec<u8> {
    let ihl = 20usize;
    let doff = 20 + options.len();
    let mut pkt = vec![0u8; ihl + doff];
    pkt[0] = 0x45;
    let total = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.0);
    pkt[16..20].copy_from_slice(&dst.0);
    pkt[ihl..ihl + 2].copy_from_slice(&src.1.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&dst.1.to_be_bytes());
    pkt[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[ihl + 8..ihl + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[ihl + 12] = ((doff / 4) as u8) << 4;
    pkt[ihl + 13] = flags;
    pkt[ihl + 14..ihl + 16].copy_from_slice(&window.to_be_bytes());
    pkt[ihl + 20..ihl + doff].copy_from_slice(options);
    fix_ip_checksum(&mut pkt, ihl);
    fix_tcp_checksum(&mut pkt, ihl);
    pkt
}

/// Walk a packet's TCP option list; return the MSS option value if present.
pub fn read_mss_option(pkt: &[u8]) -> Option<u16> {
    if pkt.len() < 24 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let doff = ((pkt[ihl + 12] >> 4) as usize) * 4;
    if doff < 20 || pkt.len() < ihl + doff {
        return None;
    }
    let mut off = ihl + 20;
    let end = ihl + doff;
    while off + 1 < end {
        let kind = pkt[off];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            off += 1;
            continue;
        }
        let len = pkt[off + 1] as usize;
        if len < 2 || off + len > end {
            break;
        }
        if kind == 2 && len == 4 {
            return Some(u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]));
        }
        off += len;
    }
    None
}

// ── UDP + DNS (vpn_dns gate) ────────────────────────────────────────────────

/// Parse a raw IPv4+UDP packet into (src (ip, port), dst (ip, port), payload).
pub fn parse_udp(pkt: &[u8]) -> Option<(([u8; 4], u16), ([u8; 4], u16), &[u8])> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    let src = (
        [pkt[12], pkt[13], pkt[14], pkt[15]],
        u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
    );
    let dst = (
        [pkt[16], pkt[17], pkt[18], pkt[19]],
        u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
    );
    Some((src, dst, &pkt[ihl + 8..]))
}

/// Minimal valid DNS A query for `name` (e.g. "nas.home").
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT = 1
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE = A, QCLASS = IN
    m
}

/// Minimal DNS response for `dns_query`: same question, one A record `ip`
/// (answer name via compression pointer to offset 12).
pub fn dns_response(id: u16, name: &str, ip: [u8; 4]) -> Vec<u8> {
    let mut m = dns_query(id, name);
    m[2] = 0x81; // QR + RD
    m[3] = 0x80; // RA
    m[6..8].copy_from_slice(&[0, 1]); // ANCOUNT = 1
    m.extend_from_slice(&[0xC0, 0x0C]); // pointer to QNAME
    m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    m.extend_from_slice(&60u32.to_be_bytes()); // TTL
    m.extend_from_slice(&[0, 4]); // RDLENGTH
    m.extend_from_slice(&ip); // RDATA
    m
}
