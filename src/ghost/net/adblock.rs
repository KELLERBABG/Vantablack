//! Built-in DNS & SOCKS5 Ad / Tracker Blocker.
//!
//! Works both when exited through a mesh `VpnHub` / `SOCKS5` proxy AND standalone
//! on Android (`Local Ad-Shield DNS` mode) or Desktop SOCKS5 even when zero mesh
//! peers are connected.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ADBLOCK_ENABLED: AtomicBool = AtomicBool::new(true);
static ADBLOCK_BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Curated list of ad networks, mobile interstitial SDKs, and telemetry trackers.
/// Matched by exact domain or subdomain suffix (e.g. `foo.doubleclick.net` matches `doubleclick.net`).
const BLOCKED_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "googletagservices.com",
    "googletagmanager.com",
    "google-analytics.com",
    "adservice.google.com",
    "ads.google.com",
    "pagead2.googlesyndication.com",
    "app-measurement.com",
    "firebase-settings.crashlytics.com",
    "crashlyticsreports-pa.googleapis.com",
    "facebook.net",
    "connect.facebook.net",
    "an.facebook.com",
    "ads.facebook.com",
    "graph.instagram.com",
    "applovin.com",
    "applvn.com",
    "unityads.unity3d.com",
    "cdp.cloud.unity3d.com",
    "vungle.com",
    "ironsrc.com",
    "is.com",
    "mopub.com",
    "adcolony.com",
    "chartboost.com",
    "inmobi.com",
    "taboola.com",
    "outbrain.com",
    "criteo.com",
    "criteo.net",
    "pubmatic.com",
    "rubiconproject.com",
    "openx.net",
    "casalemedia.com",
    "adnxs.com",
    "adsrvr.org",
    "demdex.net",
    "omtrdc.net",
    "scorecardresearch.com",
    "quantserve.com",
    "branch.io",
    "app.link",
    "adjust.com",
    "appsflyer.com",
    "appsflyersdk.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "segment.com",
    "hotjar.com",
    "fullstory.com",
    "sentry.io",
    "bugsnag.com",
    "amazon-adsystem.com",
    "aax-us-east.amazon-adsystem.com",
    "ads.msn.com",
    "bat.bing.com",
    "ads.tiktok.com",
    "analytics.tiktok.com",
    "ads-api.twitter.com",
    "ads.twitter.com",
    "ads.linkedin.com",
    "px.ads.linkedin.com",
    "ads.reddit.com",
    "events.reddit.com",
    "ads.pinterest.com",
    "ct.pinterest.com",
    "ads.yahoo.com",
    "gemini.yahoo.com",
    "smaato.net",
    "tapjoy.com",
    "fyber.com",
    "liftoff.io",
    "pangle.io",
    "mintegral.com",
    "startappservice.com",
    "yandexadexchange.net",
    "adform.net",
    "smartadserver.com",
    "bidswitch.net",
    "sharethrough.com",
    "triplelift.com",
    "33across.com",
    "media.net",
    "revcontent.com",
    "mgid.com",
    "teads.tv",
    "spotxchange.com",
    "springserve.com",
    "connatix.com",
];

pub fn is_enabled() -> bool {
    ADBLOCK_ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(enabled: bool) {
    ADBLOCK_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn blocked_count() -> u64 {
    ADBLOCK_BLOCKED_COUNT.load(Ordering::Relaxed)
}

pub fn record_blocked() -> u64 {
    ADBLOCK_BLOCKED_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1)
}

/// Check if `domain` (case-insensitive, optional trailing dot) is blocked when adblock is enabled.
pub fn is_blocked_domain(domain: &str) -> bool {
    if !is_enabled() {
        return false;
    }
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    for &pattern in BLOCKED_DOMAINS {
        if clean == pattern {
            return true;
        }
        if clean.len() > pattern.len()
            && clean.ends_with(pattern)
            && clean.as_bytes()[clean.len() - pattern.len() - 1] == b'.'
        {
            return true;
        }
    }
    false
}

/// Extract the QNAME from a standard DNS query payload (UDP port 53).
pub fn extract_dns_qname(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    // QR bit == 0 (standard query) and QDCOUNT >= 1
    if (payload[2] & 0x80) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut labels = Vec::new();
    let mut idx: usize = 12;
    let mut total: usize = 0;
    while idx < payload.len() {
        let len = *payload.get(idx)? as usize;
        idx = idx.checked_add(1)?;
        if len == 0 {
            break;
        }
        if (len & 0xC0) != 0 || len > 63 {
            return None;
        }
        let end = idx.checked_add(len)?;
        let label_bytes = payload.get(idx..end)?;
        total = total.saturating_add(len).saturating_add(1);
        if total > 255 {
            return None;
        }
        let label = std::str::from_utf8(label_bytes).ok()?;
        labels.push(label.to_ascii_lowercase());
        idx = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Build an RFC 1035 NXDOMAIN (RCODE=3) response for a blocked DNS query.
pub fn build_dns_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    let rd = query[2] & 0x01;
    // QR=1 (0x80), preserve RD, RA=1 (0x80), RCODE=3 (NXDOMAIN, 0x03)
    resp[2] = 0x80 | rd;
    resp[3] = 0x83;
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;

    let mut idx: usize = 12;
    while idx < resp.len() {
        let len = resp[idx] as usize;
        if len == 0 {
            idx = idx.saturating_add(1);
            break;
        }
        if (len & 0xC0) == 0xC0 {
            idx = idx.saturating_add(2);
            break;
        }
        idx = idx.saturating_add(1).saturating_add(len);
    }
    let end = idx.checked_add(4)?;
    if end <= resp.len() {
        resp.truncate(end);
        Some(resp)
    } else {
        None
    }
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in hdr.as_chunks::<2>().0 {
        sum = sum.saturating_add(u16::from_be_bytes(*chunk) as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF).saturating_add(sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum = sum.saturating_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32);
    sum = sum.saturating_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32);
    sum = sum.saturating_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32);
    sum = sum.saturating_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32);
    sum = sum.saturating_add(17u32); // UDP proto
    sum = sum.saturating_add(udp_segment.len() as u32);

    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum = sum.saturating_add(u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32);
        i += 2;
    }
    if i < udp_segment.len() {
        sum = sum.saturating_add((udp_segment[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF).saturating_add(sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 {
        0xFFFF
    } else {
        res
    }
}

/// Synthesize a complete IPv4+UDP DNS reply packet swapping src/dst of `req_pkt`.
pub fn synthesize_ipv4_udp_reply(req_pkt: &[u8], dns_resp: &[u8]) -> Option<Vec<u8>> {
    if req_pkt.len() < 28 || (req_pkt[0] >> 4) != 4 || req_pkt[9] != 17 {
        return None;
    }
    let ihl = ((req_pkt[0] & 0x0F) as usize) * 4;
    if ihl < 20 || req_pkt.len() < ihl + 8 {
        return None;
    }
    let udp_len = 8usize.checked_add(dns_resp.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    if total_len > u16::MAX as usize {
        return None;
    }

    let req_src = [req_pkt[12], req_pkt[13], req_pkt[14], req_pkt[15]];
    let req_dst = [req_pkt[16], req_pkt[17], req_pkt[18], req_pkt[19]];
    let sport = u16::from_be_bytes([req_pkt[ihl], req_pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([req_pkt[ihl + 2], req_pkt[ihl + 3]]);

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&[0x12, 0x34]);
    pkt[6] = 0x40; // DF
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&req_dst);
    pkt[16..20].copy_from_slice(&req_src);
    let ip_csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&dport.to_be_bytes());
    pkt[22..24].copy_from_slice(&sport.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(dns_resp);

    let u_csum = udp_checksum(req_dst, req_src, &pkt[20..]);
    pkt[26..28].copy_from_slice(&u_csum.to_be_bytes());
    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_exact_and_subdomain_matches() {
        set_enabled(true);
        assert!(is_blocked_domain("doubleclick.net"));
        assert!(is_blocked_domain("ad.doubleclick.net."));
        assert!(is_blocked_domain("PAGEAD2.GOOGLESYNDICATION.COM"));
        assert!(!is_blocked_domain("example.com"));
        assert!(!is_blocked_domain("notdoubleclick.net"));
    }

    #[test]
    fn extracts_qname_and_builds_nxdomain() {
        let mut q = vec![
            0xAA, 0xBB, 0x01, 0x00, // ID, flags (RD=1)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QD=1
        ];
        q.extend_from_slice(&[
            3, b'a', b'd', b's', 6, b'v', b'u', b'n', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        assert_eq!(extract_dns_qname(&q).as_deref(), Some("ads.vungle.com"));
        let resp = build_dns_nxdomain_response(&q).unwrap();
        assert_eq!(resp[0..2], [0xAA, 0xBB]);
        assert_eq!(resp[3] & 0x0F, 3); // NXDOMAIN
    }

    #[test]
    fn synthesizes_valid_ipv4_udp_reply() {
        let mut req = vec![0u8; 28 + 12];
        req[0] = 0x45;
        req[9] = 17;
        req[12..16].copy_from_slice(&[10, 66, 0, 10]);
        req[16..20].copy_from_slice(&[10, 66, 0, 1]);
        req[20..22].copy_from_slice(&12345u16.to_be_bytes());
        req[22..24].copy_from_slice(&53u16.to_be_bytes());
        let reply = synthesize_ipv4_udp_reply(&req, &[1, 2, 3, 4]).unwrap();
        assert_eq!(&reply[12..16], &[10, 66, 0, 1]);
        assert_eq!(&reply[16..20], &[10, 66, 0, 10]);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 53);
        assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 12345);
        assert_eq!(&reply[28..], &[1, 2, 3, 4]);
    }
}
