//! Built-in DNS & SOCKS5 Ad / Tracker Blocker.
//!
//! Works both when exited through a mesh `VpnHub` / `SOCKS5` proxy AND standalone
//! on Android (`Local Ad-Shield DNS` mode) or Desktop SOCKS5 even when zero mesh
//! peers are connected.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ADBLOCK_ENABLED: AtomicBool = AtomicBool::new(true);
static ADBLOCK_DOH_GUARD: AtomicBool = AtomicBool::new(true);
static ADBLOCK_BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);

const DOH_RESOLVERS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "doh.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
];

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
    "safedk.com",
    "admob.com",
    "admob.googleapis.com",
    "imasdk.googleapis.com",
    "googleadsserving.cn",
    "supersonicads.com",
    "supersonic.com",
    "ssacdn.com",
    "isprog.com",
    "rayjump.com",
    "mobvista.com",
    "pangleglobal.com",
    "byteoversea.com",
    "isnssdk.com",
    "snssdk.com",
    "pglstatp-toutiao.com",
    "tobsdk.com",
    "vungle.io",
    "liftoff.com",
    "bidmachine.io",
    "appodeal.com",
    "appodealx.com",
    "moloco.com",
    "molocoads.com",
    "bigossp.com",
    "bigoads.com",
    "inner-active.mobi",
    "mydas.mobi",
    "digitalturbine.com",
    "hyprmx.com",
    "smaato.com",
    "adsdk.yandex.ru",
    "an.yandex.ru",
    "mobile.yandexadexchange.net",
    "startappexchange.com",
    "startappnetwork.com",
    "ogury.com",
    "ogury.io",
    "presage.io",
    "pubnative.net",
    "pubnative.io",
    "verve.com",
    "inmobi.cn",
    "inmobicdn.net",
    "dtscout.com",
    "kidoz.net",
    "analytics.unity3d.com",
    "events.mz.unity3d.com",
    "unityads.com",
    "2mdn.net",
    "adtrafficquality.google",
    "fundingchoicesmessages.google.com",
    "adsafeprotected.com",
    "moatads.com",
    "doubleverify.com",
    "integralads.com",
    "innovid.com",
    "flashtalking.com",
    "singular.net",
    "kochava.com",
    "tenjin.com",
    "tenjin.io",
    "ironsrc.mobi",
    "adtiming.com",
    "aarki.net",
    "indexww.com",
    "3lift.com",
    "spotx.tv",
    "lkqd.net",
    "kargo.com",
    "yieldmo.com",
    "gumgum.com",
    "sonobi.com",
    "lijit.com",
    "undertone.com",
    "adtelligent.com",
    "kwai-ads.com",
    "analytics.google.com",
    "app-analytics-services.com",
    "adwords.google.com",
    "adsense.com",
    "adsensecustomsearchads.com",
    "crashlytics.com",
    "assoc-amazon.com",
    "bat.bing.net",
    "c.bing.com",
    "ads.microsoft.com",
    "clarity.ms",
    "magnite.com",
    "xandr.com",
    "sovrn.com",
    "advertising.com",
    "oath.com",
    "yieldlab.net",
    "emxdgt.com",
    "1rx.io",
    "tremorhub.com",
    "unrulymedia.com",
    "kontextua.com",
    "equativ.com",
    "adition.com",
    "emetriq.com",
    "nugg.ad",
    "semasio.net",
    "zeotap.com",
    "id5-sync.com",
    "liadm.com",
    "sitescout.com",
    "adhigh.net",
    "freewheel.tv",
    "smartclip.net",
    "stickyads.tv",
    "yume.com",
    "adapex.io",
    "snigelweb.com",
    "quantcast.com",
    "comscore.com",
    "imrworldwide.com",
    "crwdcntrl.net",
    "lotame.com",
    "permutive.com",
    "rlcdn.com",
    "agkn.com",
    "bluekai.com",
    "exelator.com",
    "krxd.net",
    "tapad.com",
    "adsymptotic.com",
    "mathtag.com",
    "turn.com",
    "serving-sys.com",
    "adroll.com",
    "zedo.com",
    "fastclick.net",
    "adbutler.com",
    "addthis.com",
    "sharethis.com",
    "zemanta.com",
    "nativo.com",
    "dianomi.com",
    "plista.com",
    "ligatus.com",
    "exoclick.com",
    "juicyads.com",
    "trafficjunky.net",
    "popads.net",
    "popcash.net",
    "propellerads.com",
    "adcash.com",
    "hilltopads.net",
    "clickadu.com",
    "midtownads.com",
    "heyzap.com",
    "adincube.com",
    "tapresearch.com",
    "pollfish.com",
    "adgatemedia.com",
    "adjoe.io",
    "adpopcorn.com",
    "igaworks.com",
    "cauly.net",
    "taptica.com",
    "vungle.net",
    "conviva.com",
    "appmetrica.yandex.com",
    "appmetrica.yandex.net",
    "smartlook.com",
    "mouseflow.com",
    "luckyorange.com",
    "inspectlet.com",
    "logrocket.com",
    "heapanalytics.com",
    "heap.io",
    "statcounter.com",
    "clicky.com",
    "getclicky.com",
    "matomo.cloud",
    "chartbeat.com",
    "parsely.com",
    "nr-data.net",
    "datadoghq-browser-agent.com",
    "shareasale.com",
    "awin1.com",
    "commission-junction.com",
    "impactradius.com",
    "tradedoubler.com",
    "linksynergy.com",
    "rakutenadvertising.com",
    "viglink.com",
    "skimlinks.com",
    "mc.yandex.ru",
    "ad.mail.ru",
    "top-fwz1.mail.ru",
    "adriver.ru",
    "begun.ru",
    "umeng.com",
    "umengcloud.com",
    "cnzz.com",
    "growingio.com",
    "talkingdata.com",
    "tanx.com",
    "alimama.com",
    "mmstat.com",
    "pos.baidu.com",
    "cpro.baidu.com",
    "hm.baidu.com",
];

pub fn is_enabled() -> bool {
    ADBLOCK_ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(enabled: bool) {
    ADBLOCK_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_doh_guard_enabled() -> bool {
    ADBLOCK_DOH_GUARD.load(Ordering::Relaxed)
}

pub fn set_doh_guard_enabled(enabled: bool) {
    ADBLOCK_DOH_GUARD.store(enabled, Ordering::Relaxed);
}

pub fn blocked_count() -> u64 {
    ADBLOCK_BLOCKED_COUNT.load(Ordering::Relaxed)
}

pub fn record_blocked() -> u64 {
    ADBLOCK_BLOCKED_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1)
}

fn matches_domain_list(domain: &str, list: &[&str]) -> bool {
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    for &pattern in list {
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

pub fn is_blocked_domain(domain: &str) -> bool {
    is_enabled() && matches_domain_list(domain, BLOCKED_DOMAINS)
}

pub fn is_doh_blocked_domain(domain: &str) -> bool {
    is_enabled() && is_doh_guard_enabled() && matches_domain_list(domain, DOH_RESOLVERS)
}

pub fn is_blocked_target(domain: &str) -> bool {
    is_blocked_domain(domain) || is_doh_blocked_domain(domain)
}

pub fn is_shielded_target(host: &str) -> bool {
    if is_blocked_target(host) {
        return true;
    }
    if let Ok(ip) = host.trim().parse::<std::net::IpAddr>() {
        return crate::ghost::net::threat_shield::blocks_ip(ip);
    }
    crate::ghost::net::threat_shield::blocks_domain(host)
}

pub enum PacketShieldVerdict {
    Allow,
    Block(Option<Vec<u8>>),
}

pub fn inspect_outbound_ipv4_packet(pkt: &[u8]) -> PacketShieldVerdict {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return PacketShieldVerdict::Allow;
    }
    let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if crate::ghost::net::threat_shield::blocks_ip(std::net::IpAddr::V4(dst)) {
        record_blocked();
        return PacketShieldVerdict::Block(None);
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return PacketShieldVerdict::Allow;
    }
    match pkt[9] {
        17 if pkt.len() >= ihl + 8 => {
            let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            if is_blocked_port(dport) {
                record_blocked();
                return PacketShieldVerdict::Block(None);
            }
            if dport == 53 {
                let dns_payload = &pkt[ihl + 8..];
                if let Some(qname) = extract_dns_qname(dns_payload) {
                    if is_shielded_target(&qname) {
                        record_blocked();
                        let reply = build_dns_nxdomain_response(dns_payload)
                            .and_then(|nx| synthesize_ipv4_udp_reply(pkt, &nx));
                        return PacketShieldVerdict::Block(reply);
                    }
                }
            }
        }
        6 if pkt.len() >= ihl + 20 => {
            let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            if is_blocked_port(dport) {
                record_blocked();
                return PacketShieldVerdict::Block(None);
            }
            let data_off = (((pkt[ihl + 12] >> 4) as usize) * 4).max(20);
            if pkt.len() > ihl + data_off {
                if let Some(sni) = extract_tls_sni(&pkt[ihl + data_off..]) {
                    if is_shielded_target(&sni) {
                        record_blocked();
                        return PacketShieldVerdict::Block(None);
                    }
                }
            }
        }
        _ => {}
    }
    PacketShieldVerdict::Allow
}

pub fn is_blocked_port(port: u16) -> bool {
    port == 853 && is_enabled() && is_doh_guard_enabled()
}

pub fn extract_dns_qname(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
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

pub fn build_dns_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    let rd = query[2] & 0x01;
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

fn read_dns_name(msg: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut end_pos = 0;
    let mut jumps = 0u8;

    loop {
        let len = *msg.get(pos)?;
        if (len & 0xC0) == 0xC0 {
            let b2 = *msg.get(pos + 1)?;
            let ptr = (((len & 0x3F) as usize) << 8) | (b2 as usize);
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > 16 || ptr >= msg.len() {
                return None;
            }
            pos = ptr;
        } else if (len & 0xC0) != 0 {
            return None;
        } else if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else {
            let l = len as usize;
            let start = pos + 1;
            let end = start.checked_add(l)?;
            let label = std::str::from_utf8(msg.get(start..end)?).ok()?;
            labels.push(label.to_string());
            pos = end;
        }
    }
    Some((labels.join("."), end_pos))
}

pub fn extract_dns_cnames(response: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if response.len() < 12 || (response[2] & 0x80) == 0 {
        return out;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut pos = 12usize;

    for _ in 0..qdcount {
        let Some((_, next)) = read_dns_name(response, pos) else {
            return out;
        };
        pos = next.saturating_add(4);
        if pos > response.len() {
            return out;
        }
    }

    for _ in 0..ancount {
        let Some((_, after_name)) = read_dns_name(response, pos) else {
            break;
        };
        if after_name + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[after_name], response[after_name + 1]]);
        let rdlen =
            u16::from_be_bytes([response[after_name + 8], response[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let Some(rdata_end) = rdata_start.checked_add(rdlen) else {
            break;
        };
        if rdata_end > response.len() {
            break;
        }
        if rtype == 5 {
            if let Some((cname, _)) = read_dns_name(response, rdata_start) {
                if !cname.is_empty() {
                    out.push(cname);
                }
            }
        }
        pos = rdata_end;
    }
    out
}

pub fn filter_dns_response(response: &[u8]) -> Option<Vec<u8>> {
    if !is_enabled() {
        return None;
    }
    let cnames = extract_dns_cnames(response);
    if !cnames.iter().any(|c| is_shielded_target(c)) {
        return None;
    }
    record_blocked();
    build_dns_nxdomain_response(response)
}

pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 43 || payload[0] != 0x16 {
        return None;
    }
    if payload[5] != 0x01 {
        return None;
    }
    let mut pos = 43usize;
    let sid_len = *payload.get(pos)? as usize;
    pos = pos.checked_add(1 + sid_len)?;

    let cs_len = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2 + cs_len)?;

    let comp_len = *payload.get(pos)? as usize;
    pos = pos.checked_add(1 + comp_len)?;

    let ext_total = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?.min(payload.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        let next_ext = pos.checked_add(ext_len)?;
        if next_ext > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            let name_type = payload[pos + 2];
            let name_len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
            if name_type == 0x00 && pos + 5 + name_len <= next_ext {
                let sni = std::str::from_utf8(&payload[pos + 5..pos + 5 + name_len]).ok()?;
                return Some(sni.to_string());
            }
        }
        pos = next_ext;
    }
    None
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

    #[test]
    fn doh_guard_blocks_known_resolvers_and_port_853() {
        set_enabled(true);
        set_doh_guard_enabled(true);
        assert!(is_doh_blocked_domain("dns.google"));
        assert!(is_doh_blocked_domain("cloudflare-dns.com"));
        assert!(is_blocked_target("dns.quad9.net"));
        assert!(is_blocked_port(853));
        assert!(!is_blocked_port(443));
        set_doh_guard_enabled(false);
        assert!(!is_doh_blocked_domain("dns.google"));
        assert!(!is_blocked_port(853));
        set_doh_guard_enabled(true);
    }

    #[test]
    fn uncloaks_blocked_cname_into_nxdomain() {
        set_enabled(true);
        let qname = [
            7, b'm', b'e', b't', b'r', b'i', b'c', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 3, b'c', b'o', b'm', 0,
        ];
        let cname = [
            7, b't', b'r', b'a', b'c', b'k', b'e', b'r', 11, b'd', b'o', b'u', b'b', b'l', b'e',
            b'c', b'l', b'i', b'c', b'k', 3, b'n', b'e', b't', 0,
        ];
        let mut resp = vec![
            0x12, 0x34, 0x81, 0x80, // ID, standard response
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // QD=1, AN=1
        ];
        resp.extend_from_slice(&qname);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, IN
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]); // TYPE=CNAME, IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        resp.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        resp.extend_from_slice(&cname);

        let cnames = extract_dns_cnames(&resp);
        assert_eq!(cnames, vec!["tracker.doubleclick.net".to_string()]);
        let nx = filter_dns_response(&resp).expect("blocked CNAME should yield NXDOMAIN");
        assert_eq!(nx[3] & 0x0F, 3);
    }

    #[test]
    fn extracts_sni_from_tls_client_hello() {
        let host = b"ads.vungle.com";
        let sni_ext_len = 2 + 1 + 2 + host.len();
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        ext.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes());
        ext.push(0x00); // host_name
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id len
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]); // cipher suite
        hello.push(1);
        hello.push(0); // compression
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        let mut pkt = vec![0x16, 0x03, 0x01];
        pkt.extend_from_slice(&((4 + hello.len()) as u16).to_be_bytes());
        pkt.push(0x01); // ClientHello
        let hl = hello.len() as u32;
        pkt.extend_from_slice(&hl.to_be_bytes()[1..4]);
        pkt.extend_from_slice(&hello);

        assert_eq!(extract_tls_sni(&pkt).as_deref(), Some("ads.vungle.com"));
    }
}
