//! Control center and telemetry HTTP server for Vantablack.
//!
//! Provides the REST API (/api/status, /api/peers, /api/peers/add,
//! /api/peers/disconnect, /api/topology, /api/mode, /api/connect,
//! /api/settings, /api/scan, /api/pipeline_probe), /proxy.pac, Prometheus
//! /metrics, and the embedded HTML dashboard.

use super::*;
use crate::vpn::daemon::{vpn_export, VpnMode};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vantablack::ghost::layers::l10_qel::{self, QelAnchorState, QuantumRouteResult};
use vantablack::ghost::net::consumer::{self, ConsumerSettings};
use vantablack::ghost::net::discovery::{
    LocalPeerCache, NetworkInvite, PeerDescriptor, PeerDescriptorV2, CAP_EXIT, CAP_HOME_EXIT,
    CAP_QUIC, CAP_RELAY, CAP_VPN_HUB, NAT_CONE, NAT_DIRECT, NAT_RESTRICTED, NAT_SYMMETRIC,
    NAT_UNKNOWN, VB_NET_URI_PREFIX, VB_URI_PREFIX, VB_V2_URI_PREFIX,
};
use vantablack::ghost::net::mesh::{
    local_node_offer, peer_telemetry_snapshot, remove_peer_telemetry, update_peer_telemetry,
    wan_telemetry_snapshot, NatType,
};
use vantablack::ghost::v2;
use vantablack::ghost::v2::{api as v2api, regime as v2regime};
use vantablack::ghost::GhostNode;

/// Port the HTTP control center listens on (`GHOST_WEB_PORT`, else the legacy
/// `GHOST_METRICS_PORT`, else 2270). Shared by the node and the desktop window.
pub fn control_port_from_env() -> u16 {
    std::env::var("GHOST_WEB_PORT")
        .or_else(|_| std::env::var("GHOST_METRICS_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2270)
}

/// Parse the JSON body out of an HTTP request, ignoring headers.
pub fn json_body(req: &str) -> serde_json::Value {
    let body_str = req.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    serde_json::from_str(body_str.trim()).unwrap_or(serde_json::Value::Null)
}

/// Extract and validate the `Origin` header against permitted localhost origins.
pub fn is_origin_allowed(req: &str, port: u16) -> bool {
    let origin = req.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("origin") {
            Some(value.trim())
        } else {
            None
        }
    });

    match origin {
        None => true, // direct curl, desktop webview, or native process
        Some(o) => {
            o == format!("http://127.0.0.1:{}", port) || o == format!("http://localhost:{}", port)
        }
    }
}

/// Extract the `X-Pin` header from an incoming HTTP request.
pub fn header_pin(req: &str) -> Option<&str> {
    req.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("x-pin") {
            Some(value.trim())
        } else {
            None
        }
    })
}

/// Constant-time PIN check. The length difference is folded into the result, so
/// the compare neither short-circuits on a mismatched byte nor on a mismatched
/// length, either of which would time the configured PIN out to the caller.
pub fn pin_matches(expected: &str, supplied: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    let supplied = supplied.unwrap_or("");
    let n = expected.len().max(supplied.len());
    let mut a = vec![0u8; n];
    let mut b = vec![0u8; n];
    a[..expected.len()].copy_from_slice(expected.as_bytes());
    b[..supplied.len()].copy_from_slice(supplied.as_bytes());
    let same_len = (expected.len() as u64).ct_eq(&(supplied.len() as u64));
    bool::from(a.as_slice().ct_eq(b.as_slice()) & same_len)
}

/// Round to `places` decimals for stable JSON output.
pub fn round(value: f64, places: i32) -> f64 {
    let factor = 10f64.powi(places);
    (value * factor).round() / factor
}

/// Nearest-rank percentile of an unsorted sample set.
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub fn mean(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / samples.len() as f64
    }
}

/// Benchmark the live in-process crypto pipeline:
/// - XChaCha20-Poly1305 authenticated encryption
/// - 2-of-3 Reed-Solomon erasure coding
/// - Memory scrubbing / allocation
pub fn run_pipeline_probe(total_bytes: usize) -> serde_json::Value {
    let chunk_size = 900;
    let iterations = (total_bytes / chunk_size).max(10);
    let mut payload = vec![0u8; chunk_size];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payload);

    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
    let dummy_ctx = SealCtx {
        key,
        epoch: 1,
        counter: 100,
        nonce: [0x42; 12],
        direction: NonceDirection::InitiatorToResponder,
        session_hash: [0x11, 0x22, 0x33, 0x44],
        ratchet_due: false,
    };

    let start = std::time::Instant::now();
    let mut latencies_us = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t0 = std::time::Instant::now();
        let (shards, tag) = enc_split(&dummy_ctx, &payload);
        let elapsed_us = t0.elapsed().as_micros() as f64;
        latencies_us.push(elapsed_us);
        std::hint::black_box((shards, tag));
    }

    let total_duration = start.elapsed();
    let total_processed = chunk_size * iterations;
    let mbps = (total_processed as f64 * 8.0) / total_duration.as_secs_f64() / 1_000_000.0;

    serde_json::json!({
        "status": "completed",
        "total_bytes": total_processed,
        "iterations": iterations,
        "duration_ms": round(total_duration.as_secs_f64() * 1000.0, 2),
        "throughput_mbps": round(mbps, 2),
        "latency_us": {
            "min": round(*latencies_us.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap_or(&0.0), 1),
            "mean": round(mean(&latencies_us), 1),
            "p50": round(percentile(&latencies_us, 0.50), 1),
            "p95": round(percentile(&latencies_us, 0.95), 1),
            "p99": round(percentile(&latencies_us, 0.99), 1),
            "max": round(*latencies_us.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap_or(&0.0), 1),
        }
    })
}

/// Round-trip time to the public internet, from the fastest of three TCP
/// connects.
#[allow(dead_code)]
pub async fn isp_rtt_ms() -> Option<f64> {
    let mut best: Option<f64> = None;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let attempt = tokio::time::timeout(
            Duration::from_millis(700),
            tokio::net::TcpStream::connect("1.1.1.1:443"),
        )
        .await;
        match attempt {
            Ok(Ok(_stream)) => {
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                best = Some(best.map_or(ms, |b: f64| b.min(ms)));
            }
            _ => break,
        }
    }
    best.map(|v| round(v, 1))
}

/// One peer entry for `/api/status` and `/api/peers`, with the consumer-facing
/// fields the dashboard renders: friendly name, platform, presence.
pub fn peer_entry(
    nc: &GhostNode,
    settings: &ConsumerSettings,
    fingerprint: &str,
    addr: &SocketAddr,
) -> serde_json::Value {
    let has_session = nc.sessions.contains_key(fingerprint);
    serde_json::json!({
        "fingerprint": fingerprint,
        "name": settings.device_name(fingerprint),
        "custom_name": settings.has_custom_name(fingerprint),
        "os": settings.device_os(fingerprint),
        "address": addr.to_string(),
        "scope": classify_addr_scope(addr),
        "connected": has_session,
        "status": consumer::peer_status(has_session, true),
        "role": if has_session { "Active Mesh Peer" } else { "Discovered Peer" },
        "latency_ms": serde_json::Value::Null,
    })
}

/// Optional self-node telemetry override for `/api/topology`, allowing `wan-core`
/// to supply live STUN/NAT/relay measurements without breaking the JSON schema.
#[derive(Debug, Clone, Default)]
pub struct TopologySelfHint {
    pub public_addr: Option<String>,
    pub nat_type: Option<String>,
    pub rtt_ms: Option<f64>,
    pub via_relay_fp: Option<String>,
    pub transport: Option<String>,
}

/// Optional per-peer telemetry override for `/api/topology`.
#[derive(Debug, Clone, Default)]
pub struct TopologyPeerHint {
    pub rtt_ms: Option<f64>,
    pub via_relay_fp: Option<String>,
    pub transport: Option<String>,
    pub is_exit: bool,
}

/// Classify a socket address as `"lan"` (RFC1918, loopback, link-local, or ULA)
/// or `"wan"` (globally routable).
pub fn classify_addr_scope(addr: &SocketAddr) -> &'static str {
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                "lan"
            } else {
                "wan"
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            let is_ula = (first & 0xfe00) == 0xfc00;
            let is_ll = (first & 0xffc0) == 0xfe80;
            if v6.is_loopback() || v6.is_unspecified() || is_ula || is_ll {
                "lan"
            } else {
                "wan"
            }
        }
    }
}

/// Determine active roles advertised for the local node in `/api/topology`.
pub fn local_node_roles(socks_listening: bool, vpn_role: &str) -> Vec<&'static str> {
    let mut roles = vec!["mesh"];
    if socks_listening {
        roles.push("socks5");
    }
    let env_true = |key: &str| {
        std::env::var(key)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    };
    if vpn_role == "hub" || env_true("GHOST_EXIT") {
        roles.push("exit");
    }
    if env_true("GHOST_RELAY") {
        roles.push("relay");
    }
    match vpn_role {
        "hub" => roles.push("vpn_hub"),
        "client" => roles.push("vpn_client"),
        _ => {}
    }
    roles
}

/// Build the `/api/topology` JSON document with optional `wan-core` telemetry hints.
pub fn build_topology_json(
    nc: &GhostNode,
    addrs: &DashMap<String, SocketAddr>,
    settings: &ConsumerSettings,
    lan_host: &str,
    mode: &str,
    socks_listening: bool,
    socks_port: u16,
    vpn_role: &str,
    vpn_available: bool,
    carrier: &net::carrier::Carrier,
    lan_discovery_ok: bool,
    self_hint: &TopologySelfHint,
    peer_hints: &std::collections::HashMap<String, TopologyPeerHint>,
) -> serde_json::Value {
    let self_fp = nc.fingerprint();
    let sessions_count = nc.sessions.len();
    let socks_ports = [
        socks_port,
        socks_port.saturating_add(1),
        socks_port.saturating_add(2),
        socks_port.saturating_add(3),
    ];

    let peers: Vec<serde_json::Value> = addrs
        .iter()
        .map(|entry| {
            let fp = entry.key();
            let addr = entry.value();
            let scope = classify_addr_scope(addr);
            let has_session = nc.sessions.contains_key(fp);
            let hint = peer_hints.get(fp);
            let transport = hint
                .and_then(|h| h.transport.as_deref())
                .unwrap_or_else(|| {
                    if hint.and_then(|h| h.via_relay_fp.as_ref()).is_some() {
                        "relayed"
                    } else if carrier.covered(fp) {
                        "carrier_quic"
                    } else if scope == "lan" {
                        "direct_lan"
                    } else {
                        "direct_wan"
                    }
                });
            serde_json::json!({
                "fingerprint": fp,
                "name": settings.device_name(fp),
                "os": settings.device_os(fp),
                "address": addr.to_string(),
                "scope": scope,
                "transport": transport,
                "connected": has_session,
                "role": if has_session { "Active Mesh Peer" } else { "Discovered Peer" },
                "rtt_ms": hint.and_then(|h| h.rtt_ms),
                "is_exit": hint.map(|h| h.is_exit).unwrap_or(false),
                "via_relay_fp": hint.and_then(|h| h.via_relay_fp.clone()),
            })
        })
        .collect();

    let swarm_hops_available = sessions_count.min(3);
    let wan_snap = wan_telemetry_snapshot();
    let self_transport = self_hint
        .transport
        .as_deref()
        .unwrap_or(if carrier.enabled() {
            "carrier_quic"
        } else {
            "udp"
        });

    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "self": {
            "fingerprint": self_fp,
            "name": settings.device_name(&self_fp),
            "os": consumer::local_os(),
            "host": lan_host,
            "mode": mode,
            "roles": local_node_roles(socks_listening, vpn_role),
            "socks_listening": socks_listening,
            "socks_port": socks_port,
            "socks_ports": socks_ports,
            "vpn_role": vpn_role,
            "carrier_enabled": carrier.enabled(),
            "nat_type": self_hint.nat_type.as_deref().unwrap_or("Detecting"),
            "public_addr": self_hint.public_addr,
            "rtt_ms": self_hint.rtt_ms,
            "via_relay_fp": self_hint.via_relay_fp,
            "transport": self_transport,
        },
        "peers": peers,
        "wan_readiness": {
            "socket_ok": nc.running.load(Ordering::Relaxed),
            "lan_discovery_ok": lan_discovery_ok,
            "socks_ok": socks_listening,
            "vpn_available": vpn_available,
            "carrier_enabled": carrier.enabled(),
            "stun_ok": wan_snap.stun_server.is_some(),
            "upnp_ok": wan_snap.upnp_mapped,
            "relay_count": wan_snap.relay_count,
            "relayed_peer_count": wan_snap.relayed_peer_count,
            "peer_count": addrs.len(),
            "active_sessions": sessions_count,
            "swarm_hops_available": swarm_hops_available,
        },
    })
}

/// Build a `proxy.pac` script routing RFC1918 and localhost traffic `DIRECT`
/// and all remaining traffic through `SOCKS5 127.0.0.1:<socks_port>; DIRECT`.
pub fn build_proxy_pac(socks_port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{\n\
         \x20 if (isPlainHostName(host) ||\n\
         \x20     dnsDomainIs(host, \".local\") ||\n\
         \x20     localHostOrDomainIs(host, \"localhost\") ||\n\
         \x20     host === \"::1\" ||\n\
         \x20     isInNet(host, \"127.0.0.0\", \"255.0.0.0\") ||\n\
         \x20     isInNet(host, \"10.0.0.0\", \"255.0.0.0\") ||\n\
         \x20     isInNet(host, \"172.16.0.0\", \"255.240.0.0\") ||\n\
         \x20     isInNet(host, \"192.168.0.0\", \"255.255.0.0\") ||\n\
         \x20     isInNet(host, \"169.254.0.0\", \"255.255.0.0\")) {{\n\
         \x20   return \"DIRECT\";\n\
         \x20 }}\n\
         \x20 return \"SOCKS5 127.0.0.1:{socks_port}; DIRECT\";\n\
         }}\n"
    )
}

/// Map [`NatType`] into the wire byte used by [`PeerDescriptorV2`].
fn nat_type_to_code(nt: NatType) -> u8 {
    match nt {
        NatType::Direct => NAT_DIRECT,
        NatType::Cone => NAT_CONE,
        NatType::Restricted => NAT_RESTRICTED,
        NatType::Symmetric => NAT_SYMMETRIC,
        NatType::Unknown => NAT_UNKNOWN,
    }
}

/// Human-readable NAT label for `/api/topology` and `/api/status`.
fn nat_type_label(nt: NatType) -> &'static str {
    match nt {
        NatType::Unknown => "Detecting",
        other => other.as_str(),
    }
}

/// Compute advertised [`PeerDescriptorV2`] capability bitflags for this node.
fn local_capability_flags(vpn_role: &str) -> u8 {
    let env_true = |key: &str| {
        std::env::var(key)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    };
    let mut caps = 0u8;
    if env_true("GHOST_RELAY") {
        caps |= CAP_RELAY;
    }
    if vpn_role == "hub" || env_true("GHOST_EXIT") {
        caps |= CAP_EXIT;
        if env_true("GHOST_HOME_EXIT") {
            caps |= CAP_HOME_EXIT;
        }
    }
    if vpn_role == "hub" {
        caps |= CAP_VPN_HUB;
    }
    if cfg!(feature = "quic") {
        caps |= CAP_QUIC;
    }
    caps
}

/// Upsert a verified [`PeerDescriptorV2`] into Tier-1 disk cache (`peers.bin`).
fn record_peer_cache_v2_entry(desc: PeerDescriptorV2) {
    let peers_bin = vantablack::ghost::paths::data_file("peers.bin");
    let mut list = LocalPeerCache::load_v2(&peers_bin).unwrap_or_default();
    if let Some(existing) = list.iter_mut().find(|d| d.ed25519_pk == desc.ed25519_pk) {
        if desc.timestamp >= existing.timestamp {
            *existing = desc;
        }
    } else {
        list.push(desc);
    }
    let _ = LocalPeerCache::save_v2(&peers_bin, &list);
}

/// Append a peer endpoint to `peers.cache` if not already present.
fn record_peer_cache_entry(addr_str: &str) {
    let peers_cache = vantablack::ghost::paths::data_file("peers.cache");
    if let Ok(mut current) = std::fs::read_to_string(&peers_cache) {
        if !current.contains(addr_str) {
            if !current.ends_with('\n') && !current.is_empty() {
                current.push('\n');
            }
            current.push_str(addr_str);
            current.push('\n');
            let _ = std::fs::write(&peers_cache, current);
        }
    } else {
        let _ = std::fs::write(&peers_cache, format!("{}\n", addr_str));
    }
}

/// Extract an optional `?port=<u16>` query parameter from a `/proxy.pac` request line,
/// clamped to the node's own multi-port SOCKS5 range (`socks_port..=socks_port+3`).
fn pac_port_from_request(req: &str, socks_port: u16) -> u16 {
    let first_line = req.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    if let Some((_, query)) = path.split_once('?') {
        for pair in query.split('&') {
            if let Some(("port", val)) = pair.split_once('=') {
                if let Ok(p) = val.parse::<u16>() {
                    if p >= socks_port && p <= socks_port.saturating_add(3) {
                        return p;
                    }
                }
            }
        }
    }
    socks_port
}

/// Spawns the Ghost Web Control Center and Telemetry HTTP service.
pub fn spawn_control_center(
    metrics_port: u16,
    nc: Arc<GhostNode>,
    addrs: Arc<DashMap<String, SocketAddr>>,
    consumer_connected: Arc<AtomicBool>,
    consumer_mode: Arc<parking_lot::RwLock<String>>,
    consumer_pin: Arc<parking_lot::RwLock<Option<String>>>,
    consumer_settings: Arc<parking_lot::RwLock<ConsumerSettings>>,
    consumer_config: String,
    lan_host: String,
    pair_uri: String,
    socks_listening: bool,
    socks_port: u16,
    vpn_mode: Option<VpnMode>,
    carrier: Arc<net::carrier::Carrier>,
    pending_hs: PendingHandshakes,
    scan_notify: Arc<tokio::sync::Notify>,
    scan_interval_secs: Arc<AtomicU32>,
    qel_state_ref: Arc<parking_lot::RwLock<QelAnchorState>>,
    qel_last_route: Arc<parking_lot::RwLock<Option<QuantumRouteResult>>>,
) {
    let nc_m = Arc::clone(&nc);
    let addrs_m = Arc::clone(&addrs);
    let c_conn_m = Arc::clone(&consumer_connected);
    let c_mode_m = Arc::clone(&consumer_mode);
    let c_pin_m = Arc::clone(&consumer_pin);
    let c_settings_m = Arc::clone(&consumer_settings);
    c_settings_m.read().sync_experimental_flags();
    let c_path_m = consumer_config;
    let lan_host_m = lan_host;
    let pair_uri_m = pair_uri;
    let vpn_m = vpn_mode;
    let mp = metrics_port;
    let carrier_m = Arc::clone(&carrier);
    let phs_m = Arc::clone(&pending_hs);
    let scan_notify_m = Arc::clone(&scan_notify);
    let scan_interval_m = Arc::clone(&scan_interval_secs);
    let qel_state_m = Arc::clone(&qel_state_ref);
    let qel_route_m = Arc::clone(&qel_last_route);

    tokio::spawn(async move {
        let bind_host =
            std::env::var("GHOST_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let bind_addr = format!("{}:{}", bind_host, mp);
        match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(listener) => {
                tracing::info!(
                    "Ghost Web Control Center & Telemetry listening on http://{}:{}",
                    bind_host,
                    mp
                );
                if std::env::var("GHOST_OPEN_BROWSER")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
                        let url = format!("http://127.0.0.1:{}", mp);
                        #[cfg(target_os = "windows")]
                        let _ = std::process::Command::new("cmd")
                            .args(["/C", "start", &url])
                            .spawn();
                        #[cfg(target_os = "macos")]
                        let _ = std::process::Command::new("open").arg(&url).spawn();
                        #[cfg(target_os = "linux")]
                        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
                    });
                }
                loop {
                    match listener.accept().await {
                        Ok((mut stream, _)) => {
                            let nc_ref = Arc::clone(&nc_m);
                            let addrs_ref = Arc::clone(&addrs_m);
                            let vpn_ref = vpn_m.clone();
                            let conn_ref = Arc::clone(&c_conn_m);
                            let mode_ref = Arc::clone(&c_mode_m);
                            let pin_ref = Arc::clone(&c_pin_m);
                            let cs_ref = Arc::clone(&c_settings_m);
                            let cp_ref = c_path_m.clone();
                            let lan_host_ref = lan_host_m.clone();
                            let pair_uri_ref = pair_uri_m.clone();
                            let carrier_ref = Arc::clone(&carrier_m);
                            let phs_ref = Arc::clone(&phs_m);
                            let scan_notify_ref = Arc::clone(&scan_notify_m);
                            let scan_interval_ref = Arc::clone(&scan_interval_m);
                            let qel_state_ref = Arc::clone(&qel_state_m);
                            let qel_last_route = Arc::clone(&qel_route_m);
                            tokio::spawn(async move {
                                // Read the whole request. A single `read` races the client's
                                // TCP segmentation: a POST whose body lands in a later segment
                                // would be parsed as body-less and rejected. Clients here do
                                // NOT half-close their write side before reading the response
                                // (every browser does the same), so we cannot read to EOF;
                                // instead read until the headers are complete and then until
                                // `Content-Length` body bytes have arrived (bounded).
                                let mut buf: Vec<u8> = Vec::with_capacity(4096);
                                {
                                    let mut chunk = [0u8; 4096];
                                    let _guard = tokio::time::timeout(
                                        tokio::time::Duration::from_secs(10),
                                        async {
                                            loop {
                                                // Headers complete?
                                                let header_end =
                                                    buf.windows(4).position(|w| w == b"\r\n\r\n");
                                                let need_body = match header_end {
                                                    Some(h) => {
                                                        let headers =
                                                            String::from_utf8_lossy(&buf[..h]);
                                                        headers
                                                            .lines()
                                                            .find_map(|l| {
                                                                let (k, v) = l.split_once(':')?;
                                                                k.trim()
                                                                    .eq_ignore_ascii_case(
                                                                        "content-length",
                                                                    )
                                                                    .then(|| {
                                                                        v.trim()
                                                                            .parse::<usize>()
                                                                            .ok()
                                                                    })
                                                                    .flatten()
                                                            })
                                                            .unwrap_or(0)
                                                    }
                                                    None => usize::MAX, // keep reading headers
                                                };
                                                let have = buf.len()
                                                    - header_end.map(|h| h + 4).unwrap_or(0);
                                                if header_end.is_some() && have >= need_body {
                                                    break;
                                                }
                                                match stream.read(&mut chunk).await {
                                                    Ok(0) | Err(_) => break,
                                                    Ok(n) => {
                                                        buf.extend_from_slice(&chunk[..n]);
                                                        if buf.len() > 1_048_576 {
                                                            break; // request size cap
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                    )
                                    .await;
                                }
                                if !buf.is_empty() {
                                    let req = String::from_utf8_lossy(&buf);
                                    let (vpn_role, vpn_prom, vpn_json) = vpn_export(&vpn_ref);
                                    tracing::debug!(
                                        first = %req.lines().next().unwrap_or(""),
                                        bytes = buf.len(),
                                        "control: request received"
                                    );
                                    let vpn_available = vpn_ref.is_some();
                                    let configured_pin = pin_ref.read().clone();
                                    // `true` here means the caller may see identity and
                                    // pairing material: either no PIN is configured, or it
                                    // was supplied correctly.
                                    let pin_ok = match configured_pin.as_deref() {
                                        None => true,
                                        Some(expected) => pin_matches(expected, header_pin(&req)),
                                    };
                                    let is_mutation = req.starts_with("POST ");
                                    let origin_allowed = is_origin_allowed(&req, mp);

                                    if is_mutation && !origin_allowed {
                                        let resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nCross-Origin Forbidden\n";
                                        let _ = stream.write_all(resp.as_bytes()).await;
                                        return;
                                    }

                                    let cors_header = if origin_allowed {
                                        format!(
                                            "Access-Control-Allow-Origin: http://127.0.0.1:{}\r\n",
                                            mp
                                        )
                                    } else {
                                        String::new()
                                    };

                                    if req.starts_with("OPTIONS ") {
                                        let resp = format!(
                                        "HTTP/1.1 204 No Content\r\n{}Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Pin\r\nConnection: close\r\n\r\n",
                                        cors_header
                                    );
                                        let _ = stream.write_all(resp.as_bytes()).await;
                                        let _ = stream.flush().await;
                                        let _ = stream.shutdown().await;
                                        return;
                                    }

                                    let (status_line, body, content_type) = if is_mutation
                                        && !pin_ok
                                    {
                                        (
                                            "HTTP/1.1 401 Unauthorized",
                                            serde_json::json!({
                                                "success": false,
                                                "error": "PIN required",
                                                "pin_required": true
                                            })
                                            .to_string(),
                                            "application/json",
                                        )
                                    } else if !pin_ok
                                        && (req.starts_with("GET /api/peers")
                                            || req.starts_with("GET /api/wan_telemetry")
                                            || req.starts_with("GET /api/topology")
                                            || req.starts_with("GET /api/invite"))
                                    {
                                        // These reads carry peer or node fingerprints and
                                        // have no liveness role, so a missing PIN denies
                                        // them outright. /api/status stays readable and
                                        // redacts its identity fields instead.
                                        let body = serde_json::json!({
                                            "success": false,
                                            "error": "PIN required",
                                            "pin_required": true
                                        })
                                        .to_string();
                                        ("HTTP/1.1 401 Unauthorized", body, "application/json")
                                    } else if req.starts_with("POST /api/v2/btcr/issue") {
                                        let body = json_body(&req);
                                        match v2api::btcr_issue(
                                            &body,
                                            &nc_ref.identity.long_term_signing.to_bytes(),
                                        ) {
                                            Ok(value) => (
                                                "HTTP/1.1 200 OK",
                                                value.to_string(),
                                                "application/json",
                                            ),
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({"success": false, "error": e})
                                                    .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("POST /api/v2/btcr/spend") {
                                        let body = json_body(&req);
                                        match v2api::btcr_spend(
                                            &body,
                                            &nc_ref.identity.long_term_signing.to_bytes(),
                                        ) {
                                            Ok(value) => (
                                                "HTTP/1.1 200 OK",
                                                value.to_string(),
                                                "application/json",
                                            ),
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({"success": false, "error": e})
                                                    .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("POST /api/v2/home-exit/select") {
                                        let body = json_body(&req);
                                        let fp = body
                                            .get("fingerprint")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .trim()
                                            .to_string();
                                        match v2::boomerang::select(&fp) {
                                            Ok(peer) => {
                                                let connected = nc_ref.sessions.contains_key(&fp);
                                                (
                                                    "HTTP/1.1 200 OK",
                                                    serde_json::json!({
                                                        "success": true,
                                                        "selected": peer.fingerprint,
                                                        "endpoint": peer.endpoint,
                                                        "connected": connected,
                                                        "note": if connected {
                                                            "SOCKS5 exit traffic is pinned to this home exit."
                                                        } else {
                                                            "Selected, but no session is live yet; SOCKS5 refuses until it is."
                                                        }
                                                    })
                                                    .to_string(),
                                                    "application/json",
                                                )
                                            }
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({
                                                    "success": false,
                                                    "error": e
                                                })
                                                .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("POST /api/v2/home-exit/clear") {
                                        let previous = v2::boomerang::clear_selection();
                                        (
                                            "HTTP/1.1 200 OK",
                                            serde_json::json!({
                                                "success": true,
                                                "cleared": previous
                                            })
                                            .to_string(),
                                            "application/json",
                                        )
                                    } else if req.starts_with("POST /api/v2/regime") {
                                        let body = json_body(&req);
                                        match v2api::apply_regime(&body) {
                                            Ok(value) => (
                                                "HTTP/1.1 200 OK",
                                                value.to_string(),
                                                "application/json",
                                            ),
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({
                                                    "success": false,
                                                    "error": e
                                                })
                                                .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("POST /api/v2/fleet/invite") {
                                        let body = json_body(&req);
                                        match v2api::fleet_invite_qr(&body) {
                                            Ok(value) => (
                                                "HTTP/1.1 200 OK",
                                                value.to_string(),
                                                "application/json",
                                            ),
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({
                                                    "success": false,
                                                    "error": e
                                                })
                                                .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("POST /api/v2/fleet/revoke") {
                                        let body = json_body(&req);
                                        match v2api::fleet_revoke(&body) {
                                            Ok(value) => (
                                                "HTTP/1.1 200 OK",
                                                value.to_string(),
                                                "application/json",
                                            ),
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({
                                                    "success": false,
                                                    "error": e
                                                })
                                                .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("GET /api/v2/") {
                                        let peers = nc_ref.sessions.len();
                                        // A regime listener is already the final port;
                                        // the API derives offsets, so give it the base.
                                        let regime_active = v2regime::active().ok();
                                        let api_socks_base = if regime_active.is_some() {
                                            1080
                                        } else {
                                            socks_port
                                        };
                                        let (relay_population, relay_domains) =
                                            v2::xray::relay_population();
                                        let state = v2api::ApiState {
                                            peers,
                                            regime: regime_active
                                                .unwrap_or(v2regime::Regime::Ghost),
                                            socks_port: api_socks_base,
                                            transport: (peers > 0).then(|| "udp".to_string()),
                                            exit_ip: None,
                                            node_fingerprint: nc_ref.fingerprint(),
                                            witnesses: v2api::Witnesses {
                                                // A relay count is only evidence once
                                                // the descriptor signature checked out;
                                                // `accept_descriptor` records those.
                                                relay_population: Some(relay_population),
                                                relay_domains: Some(relay_domains),
                                                cap_relay_verified: Some(relay_population),
                                                circuit_hops: v2::boomerang::last_circuit_hops(),
                                                cover_tx: Some(v2::racs::cover_packets_emitted()),
                                                nonce_echo_hops: v2::xray::last_nonce_echo_hops(),
                                                ..Default::default()
                                            },
                                            identity_seed: Some(v2api::NodeSecret::new(
                                                nc_ref.identity.long_term_signing.to_bytes(),
                                            )),
                                        };
                                        match v2api::handle(&state, &req) {
                                            Some(value) => (
                                                "HTTP/1.1 200 OK",
                                                value.to_string(),
                                                "application/json",
                                            ),
                                            None => (
                                                "HTTP/1.1 404 Not Found",
                                                serde_json::json!({
                                                    "success": false,
                                                    "error": "unknown v2 endpoint"
                                                })
                                                .to_string(),
                                                "application/json",
                                            ),
                                        }
                                    } else if req.starts_with("GET /api/topology") {
                                        let current_mode = mode_ref.read().clone();
                                        let settings_now = cs_ref.read().clone();
                                        let lan_discovery_ok =
                                            nc_ref.beacon_enabled.load(Ordering::Relaxed);
                                        let wan_snap = wan_telemetry_snapshot();
                                        let self_hint = TopologySelfHint {
                                            public_addr: wan_snap
                                                .public_addr
                                                .map(|a| a.to_string()),
                                            nat_type: Some(
                                                nat_type_label(wan_snap.nat_type).to_string(),
                                            ),
                                            ..TopologySelfHint::default()
                                        };
                                        let peer_hints: std::collections::HashMap<
                                            String,
                                            TopologyPeerHint,
                                        > = peer_telemetry_snapshot()
                                            .into_iter()
                                            .map(|(fp, t)| {
                                                (
                                                    fp,
                                                    TopologyPeerHint {
                                                        rtt_ms: t.rtt_ms,
                                                        via_relay_fp: t.via_relay_fp,
                                                        transport: t.transport,
                                                        is_exit: t.is_exit,
                                                    },
                                                )
                                            })
                                            .collect();
                                        let body = build_topology_json(
                                            &nc_ref,
                                            &addrs_ref,
                                            &settings_now,
                                            &lan_host_ref,
                                            &current_mode,
                                            socks_listening,
                                            socks_port,
                                            vpn_role,
                                            vpn_available,
                                            &carrier_ref,
                                            lan_discovery_ok,
                                            &self_hint,
                                            &peer_hints,
                                        )
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /api/invite") {
                                        let wan_snap = wan_telemetry_snapshot();
                                        let (offer_port, ice_offer) = local_node_offer();
                                        let mesh_port = if offer_port != 0 {
                                            offer_port
                                        } else {
                                            nc_ref
                                                .socket
                                                .local_addr()
                                                .map(|a| a.port())
                                                .unwrap_or(55225)
                                        };
                                        let lan_sa = lan_host_ref.parse::<SocketAddr>().ok();
                                        // Same operator override as the descriptor
                                        // builder: a manually forwarded endpoint wins
                                        // over STUN, and then it is the only candidate.
                                        let advertised_override =
                                            std::env::var("GHOST_ADVERTISE_ADDR").ok().and_then(
                                                |raw| raw.trim().parse::<SocketAddr>().ok(),
                                            );
                                        let endpoint = advertised_override
                                            .or(wan_snap.public_addr)
                                            .or(lan_sa)
                                            .unwrap_or_else(|| {
                                                SocketAddr::from(([127, 0, 0, 1], mesh_port))
                                            });
                                        let lan_endpoints: Vec<SocketAddr> =
                                            if advertised_override.is_some() {
                                                vec![endpoint]
                                            } else {
                                                lan_sa.into_iter().collect()
                                            };
                                        let caps = local_capability_flags(vpn_role);
                                        let nat_code = nat_type_to_code(wan_snap.nat_type);
                                        let desc = PeerDescriptorV2::sign_new(
                                            &nc_ref.identity,
                                            &nc_ref.identity.pq_public_key_bytes(),
                                            endpoint,
                                            lan_endpoints,
                                            mesh_port,
                                            nat_code,
                                            caps,
                                            ice_offer,
                                        );
                                        let vb_uri = desc.to_uri();
                                        let qr_svg =
                                            vantablack::ghost::v2::fleet::render_qr_svg(&vb_uri)
                                                .ok();
                                        let body = serde_json::json!({
                                            "success": true,
                                            "vb_uri": vb_uri,
                                            "qr_svg": qr_svg,
                                            "fingerprint": desc.fingerprint(),
                                            "endpoint": desc.endpoint.to_string(),
                                            "mesh_port": desc.mesh_port,
                                            "nat_type": nat_type_label(wan_snap.nat_type),
                                            "capabilities": desc.capabilities,
                                            "has_ice_offer": desc.ice_offer.is_some(),
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /proxy.pac ")
                                        || req.starts_with("GET /proxy.pac?")
                                    {
                                        let pac_port = pac_port_from_request(&req, socks_port);
                                        let pac = build_proxy_pac(pac_port);
                                        (
                                            "HTTP/1.1 200 OK",
                                            pac,
                                            "application/x-ns-proxy-autoconfig",
                                        )
                                    } else if req.starts_with("GET /api/status") {
                                        let is_conn = conn_ref.load(Ordering::Relaxed);
                                        let current_mode = mode_ref.read().clone();
                                        let has_pin = pin_ref.read().is_some();
                                        let sent_bytes =
                                            nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                        let recv_bytes =
                                            nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                        let sent_pkts =
                                            nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                        let recv_pkts =
                                            nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                        let uptime = nc_ref.created_at.elapsed().as_secs();
                                        let peers_count = addrs_ref.len();
                                        let sessions_count = nc_ref.sessions.len();

                                        let settings_now = cs_ref.read().clone();
                                        let peer_entries: Vec<serde_json::Value> = addrs_ref
                                            .iter()
                                            .map(|entry| {
                                                peer_entry(
                                                    &nc_ref,
                                                    &settings_now,
                                                    entry.key(),
                                                    entry.value(),
                                                )
                                            })
                                            .collect();

                                        let wan_snap = wan_telemetry_snapshot();
                                        let route_mode_active =
                                            match settings_now.route_mode.as_str() {
                                                consumer::ROUTE_MODE_SYSTEM_VPN => vpn_available,
                                                _ => socks_listening,
                                            };
                                        let mut body_val = serde_json::json!({
                                            "version": env!("CARGO_PKG_VERSION"),
                                            "connected": is_conn,
                                            "mode": current_mode,
                                            "nat_type": nat_type_label(wan_snap.nat_type),
                                            "public_addr": if pin_ok { wan_snap.public_addr.map(|a| serde_json::json!(a.to_string())).unwrap_or(serde_json::Value::Null) } else { serde_json::Value::Null },
                                            "stun_ok": wan_snap.stun_server.is_some(),
                                            "upnp_ok": wan_snap.upnp_mapped,
                                            "relay_count": wan_snap.relay_count,
                                            "network_id": if pin_ok { serde_json::json!(nc_ref.fingerprint()) } else { serde_json::Value::Null },
                                            "device_name": if pin_ok { serde_json::json!(settings_now.device_name(&nc_ref.fingerprint())) } else { serde_json::Value::Null },
                                            "device_os": consumer::local_os(),
                                            "host": lan_host_ref,
                                            "multicast_addr": format!("{}:{}", vantablack::ghost::net::BEACON_MULTICAST_ADDR, vantablack::ghost::net::BEACON_PORT),
                                            "pair_uri": if pin_ok { serde_json::json!(pair_uri_ref) } else { serde_json::Value::Null },
                                            "route_mode": settings_now.route_mode,
                                            "route_mode_active": route_mode_active,
                                            "bypass_count": settings_now.bypass.len(),
                                            "socks_listening": socks_listening,
                                            "socks_port": socks_port,
                                            "socks_ports": [
                                                socks_port,
                                                socks_port.saturating_add(1),
                                                socks_port.saturating_add(2),
                                                socks_port.saturating_add(3),
                                            ],
                                            "vpn_available": vpn_available,
                                            "pin_protected": has_pin,
                                            "pin_required": has_pin && !pin_ok,
                                            "uptime_seconds": uptime,
                                            "peers_count": peers_count,
                                            "active_sessions": sessions_count,
                                            "private_mesh": {
                                                "active_nodes": if sessions_count > 0 { 1 + sessions_count } else { 1 },
                                                "autonomous_local": (sessions_count + 1) >= 5,
                                                "mode": if (sessions_count + 1) >= 5 { "autonomous_local" } else { "wan_mesh_assisted" },
                                                "scan_interval_secs": scan_interval_ref.load(Ordering::Relaxed),
                                            },
                                            "latency_ms": serde_json::Value::Null,
                                            "active_carrier_paths": if is_conn {
                                                std::cmp::min(3, 1 + nc_ref.sessions.len().min(2))
                                            } else {
                                                0
                                            },
                                            "carrier": serde_json::json!({
                                                "enabled": carrier_ref.enabled(),
                                                "label": carrier_ref.label(),
                                                "path_count": carrier_ref.path_count(),
                                                "peer_count": carrier_ref.peer_count(),
                                                "link_count": carrier_ref.link_count(),
                                            }),
                                            "skywave": serde_json::json!({
                                                "enabled": cfg!(feature = "sdr"),
                                                "carrier": "ABOS (Atmospheric Broadcast OS)",
                                                "band": "2-10 MHz NVIS HF",
                                                "propagation": "Near-Vertical Incidence Skywave (Zero Skip Zone)",
                                            }),
                                            "traffic": {
                                                "bytes_sent": sent_bytes,
                                                "bytes_recv": recv_bytes,
                                                "packets_sent": sent_pkts,
                                                "packets_recv": recv_pkts,
                                                "cover_traffic_rate_hz": 2.0,
                                                "cover_traffic_active": sessions_count > 0,
                                            },
                                            "throughput": {
                                                "bytes_sent": sent_bytes,
                                                "bytes_recv": recv_bytes,
                                                "packets_sent": sent_pkts,
                                                "packets_recv": recv_pkts,
                                            },
                                            "low_latency": vantablack::ghost::net::is_low_latency(),
                                            "mix_batch_ms": vantablack::ghost::net::mix_batch_delay_ms(),
                                            "zero_admin": vantablack::ghost::net::is_zero_admin(),
                                            "vpn": vpn_role,
                                            "vpn_stats": vpn_json,
                                            "exit_node": vpn_role == "hub",
                                            "peers": if pin_ok { serde_json::json!(peer_entries) } else { serde_json::json!([]) },
                                        });
                                        if let Some(obj) = body_val.as_object_mut() {
                                            obj.insert(
                                                "adblock_enabled".to_string(),
                                                serde_json::json!(
                                                    vantablack::ghost::net::adblock::is_enabled()
                                                ),
                                            );
                                            obj.insert(
                                                "ads_blocked".to_string(),
                                                serde_json::json!(
                                                    vantablack::ghost::net::adblock::blocked_count(
                                                    )
                                                ),
                                            );
                                        }
                                        let body = body_val.to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/peers/add") {
                                        let val = json_body(&req);
                                        let addr_str = val
                                            .get("address")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .trim();
                                        if addr_str.starts_with(VB_V2_URI_PREFIX) {
                                            match PeerDescriptorV2::from_uri(addr_str) {
                                                Some(desc) if desc.verify(86400 * 7) => {
                                                    let target_addr = desc.endpoint;
                                                    let fp = desc.fingerprint();
                                                    let is_exit =
                                                        (desc.capabilities & CAP_EXIT) != 0;
                                                    initiate_handshake(
                                                        &nc_ref,
                                                        &nc_ref.socket,
                                                        target_addr,
                                                        &phs_ref,
                                                    )
                                                    .await;
                                                    for lan_ep in &desc.lan_endpoints {
                                                        if *lan_ep != target_addr {
                                                            initiate_handshake(
                                                                &nc_ref,
                                                                &nc_ref.socket,
                                                                *lan_ep,
                                                                &phs_ref,
                                                            )
                                                            .await;
                                                        }
                                                    }
                                                    let endpoint_str = target_addr.to_string();
                                                    record_peer_cache_entry(&endpoint_str);
                                                    let caps = desc.capabilities;
                                                    record_peer_cache_v2_entry(desc);
                                                    update_peer_telemetry(&fp, |t| {
                                                        t.is_exit = is_exit;
                                                    });
                                                    // A `vb://2.` invite carries the
                                                    // descriptor's signature, so it is
                                                    // enough to register a home-exit
                                                    // candidate before any session exists.
                                                    v2::boomerang::note_peer(
                                                        &fp,
                                                        caps,
                                                        &endpoint_str,
                                                    );
                                                    let body = serde_json::json!({
                                                        "success": true,
                                                        "address": endpoint_str,
                                                        "fingerprint": fp,
                                                        "uri_parsed": true,
                                                        "version": 2,
                                                        "message": format!("Handshake initiated with {} (verified vb://2. descriptor)", target_addr)
                                                    })
                                                    .to_string();
                                                    ("HTTP/1.1 200 OK", body, "application/json")
                                                }
                                                Some(_) => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": "Peer descriptor v2 signature or timestamp verification failed"
                                                    })
                                                    .to_string();
                                                    (
                                                        "HTTP/1.1 400 Bad Request",
                                                        body,
                                                        "application/json",
                                                    )
                                                }
                                                None => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": "Invalid vb://2. peer descriptor URI"
                                                    })
                                                    .to_string();
                                                    (
                                                        "HTTP/1.1 400 Bad Request",
                                                        body,
                                                        "application/json",
                                                    )
                                                }
                                            }
                                        } else if addr_str.starts_with(VB_NET_URI_PREFIX) {
                                            match NetworkInvite::from_uri(addr_str) {
                                                Some(invite) => {
                                                    if !invite.verify_bootstrap(86400 * 7) {
                                                        let body = serde_json::json!({
                                                            "success": false,
                                                            "error": "Network invite bootstrap descriptor verification failed"
                                                        })
                                                        .to_string();
                                                        (
                                                            "HTTP/1.1 400 Bad Request",
                                                            body,
                                                            "application/json",
                                                        )
                                                    } else {
                                                        let mut target_ep: Option<String> = None;
                                                        let mut peer_fp: Option<String> = None;
                                                        if let Some(bp) = invite.bootstrap_peer {
                                                            let ep = bp.endpoint;
                                                            let fp = bp.fingerprint();
                                                            let is_exit =
                                                                (bp.capabilities & CAP_EXIT) != 0;
                                                            initiate_handshake(
                                                                &nc_ref,
                                                                &nc_ref.socket,
                                                                ep,
                                                                &phs_ref,
                                                            )
                                                            .await;
                                                            let ep_str = ep.to_string();
                                                            record_peer_cache_entry(&ep_str);
                                                            let caps = bp.capabilities;
                                                            record_peer_cache_v2_entry(bp);
                                                            update_peer_telemetry(&fp, |t| {
                                                                t.is_exit = is_exit;
                                                            });
                                                            v2::boomerang::note_peer(
                                                                &fp, caps, &ep_str,
                                                            );
                                                            target_ep = Some(ep_str);
                                                            peer_fp = Some(fp);
                                                        }
                                                        let body = serde_json::json!({
                                                            "success": true,
                                                            "uri_parsed": true,
                                                            "invite": true,
                                                            "network_name": invite.network_name,
                                                            "rendezvous_url": invite.rendezvous_url,
                                                            "address": target_ep,
                                                            "fingerprint": peer_fp,
                                                            "message": "Network invite accepted"
                                                        })
                                                        .to_string();
                                                        (
                                                            "HTTP/1.1 200 OK",
                                                            body,
                                                            "application/json",
                                                        )
                                                    }
                                                }
                                                None => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": "Invalid vb-net:// network invite URI"
                                                    })
                                                    .to_string();
                                                    (
                                                        "HTTP/1.1 400 Bad Request",
                                                        body,
                                                        "application/json",
                                                    )
                                                }
                                            }
                                        } else if addr_str.starts_with(VB_URI_PREFIX) {
                                            match PeerDescriptor::from_uri(addr_str) {
                                                Some(desc) if desc.verify(86400 * 7) => {
                                                    let target_addr = desc.endpoint;
                                                    initiate_handshake(
                                                        &nc_ref,
                                                        &nc_ref.socket,
                                                        target_addr,
                                                        &phs_ref,
                                                    )
                                                    .await;
                                                    let endpoint_str = target_addr.to_string();
                                                    record_peer_cache_entry(&endpoint_str);
                                                    let body = serde_json::json!({
                                                        "success": true,
                                                        "address": endpoint_str,
                                                        "uri_parsed": true,
                                                        "message": format!("Handshake initiated with {} (verified vb:// descriptor)", target_addr)
                                                    })
                                                    .to_string();
                                                    ("HTTP/1.1 200 OK", body, "application/json")
                                                }
                                                Some(_) => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": "Peer descriptor signature or timestamp verification failed"
                                                    })
                                                    .to_string();
                                                    (
                                                        "HTTP/1.1 400 Bad Request",
                                                        body,
                                                        "application/json",
                                                    )
                                                }
                                                None => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": "Invalid vb:// peer descriptor URI"
                                                    })
                                                    .to_string();
                                                    (
                                                        "HTTP/1.1 400 Bad Request",
                                                        body,
                                                        "application/json",
                                                    )
                                                }
                                            }
                                        } else {
                                            match addr_str.parse::<SocketAddr>() {
                                                Ok(target_addr) => {
                                                    initiate_handshake(
                                                        &nc_ref,
                                                        &nc_ref.socket,
                                                        target_addr,
                                                        &phs_ref,
                                                    )
                                                    .await;
                                                    record_peer_cache_entry(addr_str);
                                                    let body = serde_json::json!({
                                                        "success": true,
                                                        "address": addr_str,
                                                        "message": format!("Handshake initiated with {}", target_addr)
                                                    })
                                                    .to_string();
                                                    ("HTTP/1.1 200 OK", body, "application/json")
                                                }
                                                Err(e) => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": format!("Invalid address format '{}': {}", addr_str, e)
                                                    })
                                                    .to_string();
                                                    (
                                                        "HTTP/1.1 400 Bad Request",
                                                        body,
                                                        "application/json",
                                                    )
                                                }
                                            }
                                        }
                                    } else if req.starts_with("POST /api/peers/disconnect") {
                                        let val = json_body(&req);
                                        let fp = val
                                            .get("fingerprint")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .trim();
                                        if fp.is_empty() {
                                            let body = serde_json::json!({
                                                "success": false,
                                                "error": "Missing 'fingerprint'"
                                            })
                                            .to_string();
                                            ("HTTP/1.1 400 Bad Request", body, "application/json")
                                        } else {
                                            let endpoint = addrs_ref.get(fp).map(|e| *e.value());
                                            let mut bye_sent = false;
                                            if let Some(sess) = nc_ref.sessions.get(fp) {
                                                if !sess.is_v1_wire() {
                                                    if let Some(ep) = endpoint {
                                                        let ctx = SealCtx::from_session(&sess);
                                                        let frame =
                                                            seal_single(&ctx, GHOST_BYE_MAGIC);
                                                        let _ =
                                                            nc_ref.socket.try_send_to(&frame, ep);
                                                        bye_sent = true;
                                                    }
                                                }
                                            }
                                            let had_session = nc_ref.sessions.remove(fp).is_some();
                                            let had_addr = addrs_ref.remove(fp).is_some();
                                            carrier_ref.forget(fp);
                                            remove_peer_telemetry(fp);
                                            if let Some(ep) = endpoint {
                                                phs_ref.remove(&ep.to_string());
                                            }
                                            let body = serde_json::json!({
                                                "success": true,
                                                "fingerprint": fp,
                                                "evicted": had_session || had_addr,
                                                "bye_sent": bye_sent,
                                            })
                                            .to_string();
                                            ("HTTP/1.1 200 OK", body, "application/json")
                                        }
                                    } else if req.starts_with("GET /api/peers") {
                                        let settings_now = cs_ref.read().clone();
                                        let peer_entries: Vec<serde_json::Value> = addrs_ref
                                            .iter()
                                            .map(|entry| {
                                                peer_entry(
                                                    &nc_ref,
                                                    &settings_now,
                                                    entry.key(),
                                                    entry.value(),
                                                )
                                            })
                                            .collect();
                                        let body = serde_json::json!({
                                            "peers": peer_entries,
                                            "count": peer_entries.len()
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/connect") {
                                        let val = json_body(&req);
                                        let prev = conn_ref.load(Ordering::Relaxed);
                                        let next = val
                                            .get("connected")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(!prev);
                                        conn_ref.store(next, Ordering::Relaxed);
                                        nc_ref.beacon_enabled.store(next, Ordering::Relaxed);
                                        if !next {
                                            phs_ref.clear();
                                            broadcast_goodbye(&nc_ref, &addrs_ref);
                                            tracing::info!(
                                            "Mesh deactivated via control center — broadcasted GHOST_BYE to all peers"
                                        );
                                        } else if !prev {
                                            scan_notify_ref.notify_waiters();
                                            tracing::info!(
                                            "Mesh reactivated via control center — triggering immediate LAN discovery"
                                        );
                                        }
                                        let body = serde_json::json!({
                                            "success": true,
                                            "connected": next
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/mode") {
                                        let val = json_body(&req);
                                        if let Some(m) = val.get("mode").and_then(|v| v.as_str()) {
                                            *mode_ref.write() = m.to_string();
                                        }
                                        let current_mode = mode_ref.read().clone();
                                        let body = serde_json::json!({
                                            "success": true,
                                            "mode": current_mode
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/exit/voucher") {
                                        let val = json_body(&req);
                                        let peer_fp = val
                                            .get("peer_fingerprint")
                                            .and_then(|v| v.as_str())
                                            .map(str::trim)
                                            .filter(|s| !s.is_empty());
                                        if let Some(peer_fp) = peer_fp {
                                            let allowed_host = val
                                                .get("allowed_host")
                                                .and_then(|v| v.as_str())
                                                .map(str::trim)
                                                .filter(|s| !s.is_empty())
                                                .unwrap_or("*");
                                            let ttl_secs = val
                                                .get("ttl_secs")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(86400)
                                                .clamp(60, 30 * 86400);
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_secs())
                                                .unwrap_or(0);
                                            let expires_at = now.saturating_add(ttl_secs);
                                            match vantablack::ghost::net::relay::ExitCapability::issue(
                                                &nc_ref.identity,
                                                peer_fp,
                                                allowed_host,
                                                expires_at,
                                            )
                                            .and_then(|cap| cap.encode())
                                            {
                                                Some(raw) => {
                                                    let body = serde_json::json!({
                                                        "success": true,
                                                        "voucher_hex": hex::encode(raw),
                                                        "expires_at": expires_at,
                                                        "allowed_host": allowed_host,
                                                        "peer_fingerprint": peer_fp,
                                                    })
                                                    .to_string();
                                                    ("HTTP/1.1 200 OK", body, "application/json")
                                                }
                                                None => {
                                                    let body = serde_json::json!({
                                                        "success": false,
                                                        "error": "Invalid peer_fingerprint or allowed_host"
                                                    })
                                                    .to_string();
                                                    ("HTTP/1.1 400 Bad Request", body, "application/json")
                                                }
                                            }
                                        } else {
                                            let body = serde_json::json!({
                                                "success": false,
                                                "error": "peer_fingerprint is required"
                                            })
                                            .to_string();
                                            ("HTTP/1.1 400 Bad Request", body, "application/json")
                                        }
                                    } else if req.starts_with("POST /api/scan")
                                        || req.starts_with("POST /api/mesh/scan")
                                    {
                                        scan_notify_ref.notify_waiters();
                                        let body = serde_json::json!({
                                            "success": true,
                                            "message": "LAN discovery sweep triggered immediately"
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/pipeline_probe") {
                                        let val = json_body(&req);
                                        let total_bytes = val
                                            .get("total_bytes")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(2_000_000)
                                            as usize;
                                        let probe_res = run_pipeline_probe(total_bytes);
                                        (
                                            "HTTP/1.1 200 OK",
                                            probe_res.to_string(),
                                            "application/json",
                                        )
                                    } else if req.starts_with("GET /api/settings") {
                                        handle_get_settings(&cs_ref, &scan_interval_ref)
                                    } else if req.starts_with("POST /api/settings")
                                        || req.starts_with("POST /api/mesh/config")
                                    {
                                        handle_post_settings(
                                            &req,
                                            &cs_ref,
                                            &scan_interval_ref,
                                            &cp_ref,
                                        )
                                    } else if req.starts_with("GET /api/wan_telemetry") {
                                        let sent_bytes =
                                            nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                        let recv_bytes =
                                            nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                        let sent_pkts =
                                            nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                        let recv_pkts =
                                            nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                        let retrans =
                                            nc_ref.stats.retransmits.load(Ordering::Relaxed);
                                        let drops = nc_ref.stats.drops.load(Ordering::Relaxed);
                                        let body = serde_json::json!({
                                        "node_fingerprint": nc_ref.fingerprint(),
                                        "active_sessions": nc_ref.sessions.len(),
                                        "known_peers": addrs_ref.len(),
                                        "uptime_seconds": nc_ref.created_at.elapsed().as_secs(),
                                        "packets_sent": sent_pkts,
                                        "packets_recv": recv_pkts,
                                        "bytes_sent": sent_bytes,
                                        "bytes_recv": recv_bytes,
                                        "retransmits": retrans,
                                        "drops": drops,
                                        "vpn": vpn_role,
                                        "vpn_stats": vpn_json,
                                        "frame_standard": "GTF 512B Privacy / 1472B Bulk + L5 Jitter",
                                        "handshake_status": "ML-KEM-512 + X25519 Post-Quantum Hybrid",
                                        "discovery_source": "DNS Seed + Multicast Beacon + peers.cache"
                                    }).to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /api/v1/anchors/status") {
                                        // Physical anchors (experimental, in-simulation):
                                        // ABOS skywave carrier + QEL quantum anchor.
                                        let sky = net::sdr_bridge::SkywaveBridge::global()
                                            .map(|b| b.telemetry());
                                        let qel_state = *qel_state_ref.read();
                                        let body = serde_json::json!({
                                        "abos_skywave": match sky {
                                            Some(t) => serde_json::json!({
                                                "status": if t.sdr_active { "online" } else { "standby" },
                                                "synthetic": !cfg!(feature = "sdr"),
                                                "carrier_freq_hz": t.carrier_freq_hz,
                                                "estimated_f0f2_hz": t.estimated_f0f2_hz,
                                                "dsss_processing_gain_db": t.dsss_processing_gain_db,
                                                "tx_packets": t.tx_packet_count,
                                                "rx_packets": t.rx_packet_count,
                                                "tx_dsp_bytes": t.tx_dsp_bytes,
                                                "meteor_burst_window_open": t.meteor_burst_window_open,
                                                "virtual_carrier": t.virtual_carrier,
                                                "virtual_carrier_peer": t.virtual_carrier_peer,
                                            }),
                                            None => serde_json::json!({ "status": "offline" }),
                                        },
                                        "qel_quantum": {
                                            "status": qel_state.as_str(),
                                            "last_route": qel_last_route
                                                .read()
                                                .clone()
                                                .map(|r| serde_json::json!({
                                                    "path": r.path,
                                                    "end_to_end_fidelity": r.end_to_end_fidelity,
                                                    "key_fidelity": r.key_fidelity,
                                                    "distillation_rounds": r.distillation_rounds,
                                                    "swap_nodes": r.swap_nodes,
                                                    "key_derived": r.qkd_key_hex.is_some(),
                                                })),
                                            // Which key-delivery backend this node runs, and
                                            // whether it is a simulation or an appliance.
                                            // Carries no key material and no token: this
                                            // document is fetched over loopback HTTP.
                                            "backend": l10_qel::shared_controller().backend_report(),
                                            "routes_over_topology":
                                                l10_qel::shared_controller().routes_over_topology(),
                                            "note": "experimental — see docs/ANCHORS_CODEBASE_INTEGRATION.md §8 for what is and is not claimed",
                                        },
                                    })
                                    .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/v1/anchors/qel/route") {
                                        tracing::debug!("control: qel route endpoint entered");
                                        // Trigger a real QEL route computation between two
                                        // live peer fingerprints: {"from": "<fp>", "to": "<fp>"}.
                                        // PIN-gated like every mutation above.
                                        let parsed: Option<(String, String)> = req
                                            .split_once("\r\n\r\n")
                                            .and_then(|(_, body)| {
                                                serde_json::from_str(body.trim()).ok()
                                            })
                                            .and_then(|v: serde_json::Value| {
                                                let from = v.get("from")?.as_str()?.to_string();
                                                let to = v.get("to")?.as_str()?.to_string();
                                                Some((from, to))
                                            });
                                        let Some((from_fp, to_fp)) = parsed else {
                                            let body = serde_json::json!({
                                            "success": false,
                                            "error": "body must be JSON: {\"from\": \"<fingerprint>\", \"to\": \"<fingerprint>\"}"
                                        })
                                        .to_string();
                                            let resp = format!(
                                            "HTTP/1.1 400 Bad Request\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            cors_header,
                                            body.len(),
                                            body
                                        );
                                            let _ = stream.write_all(resp.as_bytes()).await;
                                            let _ = stream.flush().await;
                                            let _ = stream.shutdown().await;
                                            return;
                                        };
                                        let topo_path = std::env::var("GHOST_QEL_TOPOLOGY")
                                            .unwrap_or_else(|_| {
                                                vantablack::ghost::paths::data_file_string(
                                                    "ghost-topology.json",
                                                )
                                            });
                                        let ctrl =
                                            vantablack::ghost::layers::l10_qel::shared_controller();
                                        let outcome = ctrl
                                            .establish_quantum_link(
                                                Path::new(&topo_path),
                                                &from_fp,
                                                &to_fp,
                                            )
                                            .await;
                                        if let Some(route) = &outcome.route {
                                            if route.success {
                                                *qel_last_route.write() = Some(route.clone());
                                            }
                                        }
                                        *qel_state_ref.write() = outcome.anchor_state;
                                        let body = serde_json::json!({
                                        "anchor_state": outcome.anchor_state.as_str(),
                                        "success": outcome.route.as_ref().map(|r| r.success).unwrap_or(false),
                                        "route": outcome.route,
                                        "key_derived": outcome.key.is_some(),
                                        "error": outcome.error,
                                    })
                                    .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /api/threat_shield") {
                                        handle_get_threat_shield(&cs_ref)
                                    } else if req.starts_with("GET /api/update/check") {
                                        let body = match check_github_update().await {
                                            Ok(val) => val.to_string(),
                                            Err(e) => serde_json::json!({
                                                "error": e,
                                                "update_available": false,
                                                "current_version": env!("CARGO_PKG_VERSION")
                                            })
                                            .to_string(),
                                        };
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/update/download") {
                                        let (status, body) = match download_github_update().await {
                                            Ok(msg) => (
                                                "HTTP/1.1 200 OK",
                                                serde_json::json!({ "success": true, "message": msg }).to_string(),
                                            ),
                                            Err(e) => (
                                                "HTTP/1.1 500 Internal Server Error",
                                                serde_json::json!({ "success": false, "error": e }).to_string(),
                                            ),
                                        };
                                        (status, body, "application/json")
                                    } else if req.starts_with("POST /api/update/apply") {
                                        let (status, body) = match apply_github_update().await {
                                        Ok(msg) => (
                                            "HTTP/1.1 200 OK",
                                            serde_json::json!({ "success": true, "message": msg }).to_string(),
                                        ),
                                        Err(e) => (
                                            "HTTP/1.1 500 Internal Server Error",
                                            serde_json::json!({ "success": false, "error": e }).to_string(),
                                        ),
                                    };
                                        (status, body, "application/json")
                                    } else if req.starts_with("GET /dashboard")
                                        || req.starts_with("GET / ")
                                        || req.starts_with("GET /?")
                                    {
                                        let html = include_str!("../assets/wan_dashboard.html")
                                            .replace(
                                                "v0.7.5",
                                                &format!("v{}", env!("CARGO_PKG_VERSION")),
                                            )
                                            .replace("{{VERSION}}", env!("CARGO_PKG_VERSION"));
                                        ("HTTP/1.1 200 OK", html, "text/html; charset=utf-8")
                                    } else if req.starts_with("GET /metrics") {
                                        let sessions = nc_ref.sessions.len();
                                        let peers = addrs_ref.len();
                                        let uptime = nc_ref.created_at.elapsed().as_secs();
                                        let sent_bytes =
                                            nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                        let recv_bytes =
                                            nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                        let sent_pkts =
                                            nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                        let recv_pkts =
                                            nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                        let retrans =
                                            nc_ref.stats.retransmits.load(Ordering::Relaxed);
                                        let drops = nc_ref.stats.drops.load(Ordering::Relaxed);
                                        let body = format!(
                                        "# HELP ghost_sessions_total Active peer-to-peer sessions\n# TYPE ghost_sessions_total gauge\nghost_sessions_total {}\n# HELP ghost_known_peers_total Discovered mesh peers\n# TYPE ghost_known_peers_total gauge\nghost_known_peers_total {}\n# HELP ghost_uptime_seconds Process uptime in seconds\n# TYPE ghost_uptime_seconds counter\nghost_uptime_seconds {}\n# HELP ghost_bytes_sent_total Total bytes transmitted\n# TYPE ghost_bytes_sent_total counter\nghost_bytes_sent_total {}\n# HELP ghost_bytes_recv_total Total bytes received\n# TYPE ghost_bytes_recv_total counter\nghost_bytes_recv_total {}\n# HELP ghost_packets_sent_total Total packets sent\n# TYPE ghost_packets_sent_total counter\nghost_packets_sent_total {}\n# HELP ghost_packets_recv_total Total packets received\n# TYPE ghost_packets_recv_total counter\nghost_packets_recv_total {}\n# HELP ghost_retransmits_total Total retransmissions triggered\n# TYPE ghost_retransmits_total counter\nghost_retransmits_total {}\n# HELP ghost_drops_total Total dropped or replay-rejected frames\n# TYPE ghost_drops_total counter\nghost_drops_total {}\n# HELP ghost_cover_traffic_rate_hz Nominal cover traffic emission rate in Hz\n# TYPE ghost_cover_traffic_rate_hz gauge\nghost_cover_traffic_rate_hz 2.0\n",
                                        sessions, peers, uptime, sent_bytes, recv_bytes, sent_pkts, recv_pkts, retrans, drops
                                    );
                                        (
                                            "HTTP/1.1 200 OK",
                                            body,
                                            "text/plain; version=0.0.4; charset=utf-8",
                                        )
                                    } else {
                                        (
                                            "HTTP/1.1 404 Not Found",
                                            "Not Found".to_string(),
                                            "text/plain",
                                        )
                                    };

                                    let body = if req.starts_with("GET /metrics") {
                                        format!("{body}{vpn_prom}")
                                    } else {
                                        body
                                    };
                                    let resp = format!(
                                    "{}\r\n{}Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Pin\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    status_line, cors_header, content_type, body.len(), body
                                );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.flush().await;
                                    let _ = stream.shutdown().await;
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Control center accept error: {e}");
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to bind metrics HTTP endpoint on port {}: {}", mp, e);
            }
        }
    });
}

/// Where the consumer settings document lives (device names, egress mode,
/// split-tunnel list).
pub fn consumer_config_path() -> String {
    std::env::var("GHOST_CONSUMER_CONFIG")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| vantablack::ghost::paths::data_file_string("ghost-consumer.json"))
}

/// Load consumer settings. Returns `None` when the file is absent, so the
/// caller can fall back to env-derived defaults.
pub fn load_consumer_settings(path: &str) -> Option<ConsumerSettings> {
    let data = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<ConsumerSettings>(&data) {
        Ok(settings) => Some(settings),
        Err(e) => {
            tracing::warn!("Ignoring unreadable consumer config {path}: {e}");
            None
        }
    }
}

/// Persist consumer settings via a temp file + rename, so a crash mid-write
/// cannot leave a truncated document behind.
pub fn save_consumer_settings(path: &str, settings: &ConsumerSettings) {
    let Ok(json) = serde_json::to_string_pretty(settings) else {
        return;
    };
    let tmp = format!("{path}.tmp");
    if std::fs::write(&tmp, json).is_err() {
        tracing::warn!("Could not write {tmp}");
        return;
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!("Could not replace {path}");
    }
}

/// Compare two semver-like version strings (e.g. "v0.8.18" vs "0.8.17").
pub fn is_newer_version(latest: &str, current: &str) -> bool {
    let parse_parts = |s: &str| -> Vec<u32> {
        s.trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse::<u32>().ok())
            .collect()
    };
    let l_parts = parse_parts(latest);
    let c_parts = parse_parts(current);
    let len = l_parts.len().max(c_parts.len());
    for i in 0..len {
        let l = l_parts.get(i).copied().unwrap_or(0);
        let c = c_parts.get(i).copied().unwrap_or(0);
        if l > c {
            return true;
        }
        if l < c {
            return false;
        }
    }
    false
}

/// Query the latest release info from the official GitHub repository.
pub async fn check_github_update() -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .user_agent("Vantablack-Updater/0.8")
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;

    let res = client
        .get("https://api.github.com/repos/KELLERBABG/Vantablack/releases/latest")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !res.status().is_success() {
        return Err(format!("GitHub API returned HTTP {}", res.status()));
    }

    let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let current = env!("CARGO_PKG_VERSION");
    let has_update = is_newer_version(&tag, current);

    let mut exe_url = String::new();
    let mut zip_url = String::new();
    let mut apk_url = String::new();

    if let Some(assets) = json.get("assets").and_then(|a| a.as_array()) {
        for asset in assets {
            if let (Some(name), Some(url)) = (
                asset.get("name").and_then(|n| n.as_str()),
                asset.get("browser_download_url").and_then(|u| u.as_str()),
            ) {
                if name.ends_with(".exe") && (name.contains("setup") || name.starts_with("ggn-")) {
                    exe_url = url.to_string();
                } else if name.ends_with(".zip") && name.contains("windows") {
                    zip_url = url.to_string();
                } else if name.ends_with(".apk") {
                    apk_url = url.to_string();
                }
            }
        }
    }

    Ok(serde_json::json!({
        "current_version": current,
        "latest_version": tag.trim_start_matches('v'),
        "tag_name": tag,
        "update_available": has_update,
        "html_url": json.get("html_url").and_then(|u| u.as_str()).unwrap_or(""),
        "release_notes": json.get("body").and_then(|b| b.as_str()).unwrap_or(""),
        "published_at": json.get("published_at").and_then(|p| p.as_str()).unwrap_or(""),
        "windows_setup_url": exe_url,
        "windows_zip_url": zip_url,
        "android_apk_url": apk_url,
    }))
}

/// Download the latest Windows release installer to temp without launching it yet.
pub async fn download_github_update() -> Result<String, String> {
    let update_info = check_github_update().await?;
    let setup_url = update_info
        .get("windows_setup_url")
        .and_then(|u| u.as_str())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "No Windows installer (.exe) found in release".to_string())?;

    let client = reqwest::Client::builder()
        .user_agent("Vantablack-Updater/0.8")
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(setup_url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Download failed: HTTP {}", resp.status()));
    }

    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let temp_installer = std::env::temp_dir().join("vantablack-latest-setup.exe");
    std::fs::write(&temp_installer, &bytes).map_err(|e| e.to_string())?;
    Ok("Update downloaded and ready to install".to_string())
}

/// Download (if not already staged) and execute the latest Windows release installer.
pub async fn apply_github_update() -> Result<String, String> {
    let temp_installer = std::env::temp_dir().join("vantablack-latest-setup.exe");
    if !temp_installer
        .metadata()
        .map(|m| m.len() >= 100_000)
        .unwrap_or(false)
    {
        let _ = download_github_update().await?;
    }

    #[cfg(windows)]
    {
        let installer_path = temp_installer.to_string_lossy().to_string();
        let current_exe = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let ps_script = format!(
            "$ErrorActionPreference = 'SilentlyContinue'; \
             Start-Sleep -Milliseconds 900; \
             $inst = '{installer}'; \
             $cur = '{current}'; \
             $installed = Join-Path $env:LOCALAPPDATA 'Programs\\GlobalGhostNet\\ggn.exe'; \
             Start-Process -FilePath $inst -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CLOSEAPPLICATIONS' -Wait; \
             if ((Test-Path -LiteralPath $installed) -and $cur -and ($cur -ne $installed)) {{ \
                 Copy-Item -LiteralPath $installed -Destination $cur -Force; \
             }}; \
             $target = if ($cur -and (Test-Path -LiteralPath $cur)) {{ $cur }} elseif (Test-Path -LiteralPath $installed) {{ $installed }} else {{ $null }}; \
             if ($target) {{ Start-Process -FilePath $target }}",
            installer = installer_path.replace('\'', "''"),
            current = current_exe.replace('\'', "''"),
        );

        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps_script,
            ])
            .spawn()
            .map_err(|e| e.to_string())?;

        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(450)).await;
            std::process::exit(0);
        });
    }

    #[cfg(not(windows))]
    {
        Err("Silent self-update is currently supported on Windows".to_string())
    }

    #[cfg(windows)]
    Ok("Installer launched silently. Vantablack is restarting...".to_string())
}

fn handle_get_settings(
    cs_ref: &Arc<parking_lot::RwLock<ConsumerSettings>>,
    scan_interval_ref: &Arc<AtomicU32>,
) -> (&'static str, String, &'static str) {
    let s = cs_ref.read().clone();
    let body = serde_json::json!({
        "success": true,
        "route_mode": s.route_mode,
        "device_names": s.device_names,
        "device_os": s.device_os,
        "bypass": s.bypass,
        "bypass_count": s.bypass.len(),
        "private_mesh_scan_interval_secs": scan_interval_ref.load(Ordering::Relaxed),
        "low_latency": vantablack::ghost::net::is_low_latency(),
        "mix_batch_ms": vantablack::ghost::net::mix_batch_delay_ms(),
        "zero_admin": vantablack::ghost::net::is_zero_admin(),
        "stego_carrier_mode": s.stego_carrier_mode,
        "energy_ledger_enabled": s.energy_ledger_enabled,
        "jurisdiction_tag": s.jurisdiction_tag,
        "abos_skywave_enabled": s.abos_skywave_enabled,
        "qel_enabled": s.qel_enabled,
        "exp_pow_shield": s.exp_pow_shield,
        "exp_dtn_reconcile": s.exp_dtn_reconcile,
        "exp_universal_tunnel": s.exp_universal_tunnel,
        "exp_collective_defense": s.exp_collective_defense,
        "exp_rendezvous": s.exp_rendezvous,
        "exp_diffusion": s.exp_diffusion,
        "adblock_enabled": vantablack::ghost::net::adblock::is_enabled(),
        "ads_blocked": vantablack::ghost::net::adblock::blocked_count(),
        "threat_shield_enabled": s.threat_shield_enabled,
        "threat_shield_blocked": vantablack::ghost::net::threat_shield::blocked_total(),
        "threat_shield_allowlist": s.threat_shield_allowlist,
    })
    .to_string();
    ("HTTP/1.1 200 OK", body, "application/json")
}

fn handle_post_settings(
    req: &str,
    cs_ref: &Arc<parking_lot::RwLock<ConsumerSettings>>,
    scan_interval_ref: &Arc<AtomicU32>,
    cp_ref: &str,
) -> (&'static str, String, &'static str) {
    let val = json_body(req);
    let mut s = cs_ref.write();
    if let Some(r) = val.get("route_mode").and_then(|v| v.as_str()) {
        s.set_route_mode(r);
    }
    if let Some(ll) = val.get("low_latency").and_then(|v| v.as_bool()) {
        vantablack::ghost::net::set_low_latency(ll);
    }
    if let Some(ab) = val.get("adblock_enabled").and_then(|v| v.as_bool()) {
        vantablack::ghost::net::adblock::set_enabled(ab);
    }
    if let Some(ms) = val.get("mix_batch_ms").and_then(|v| v.as_u64()) {
        vantablack::ghost::net::set_mix_batch_delay_ms(ms);
    }
    if let Some(za) = val.get("zero_admin").and_then(|v| v.as_bool()) {
        vantablack::ghost::net::set_zero_admin(za);
    }
    let mut bypass_err: Option<String> = None;
    if let Some(add) = val.get("bypass_add").and_then(|v| v.as_str()) {
        if let Err(e) = s.add_bypass(add) {
            bypass_err = Some(e);
        }
    }
    if let Some(rem) = val.get("bypass_remove").and_then(|v| v.as_str()) {
        s.remove_bypass(rem);
    }
    if let Some(secs) = val
        .get("private_mesh_scan_interval_secs")
        .or_else(|| val.get("scan_interval_secs"))
        .and_then(|v| v.as_u64())
    {
        scan_interval_ref.store(secs as u32, Ordering::Relaxed);
    }
    if let Some(names) = val
        .get("set_device_name")
        .or_else(|| val.get("set_peer_name"))
        .and_then(|v| v.as_object())
    {
        for (k, v) in names {
            if let Some(name_str) = v.as_str() {
                let _ = s.set_device_name(k, name_str);
            }
        }
    }
    if let Some(stego) = val.get("stego_carrier_mode").and_then(|v| v.as_bool()) {
        s.stego_carrier_mode = stego;
    }
    if let Some(energy) = val.get("energy_ledger_enabled").and_then(|v| v.as_bool()) {
        s.energy_ledger_enabled = energy;
    }
    if let Some(juris) = val.get("jurisdiction_tag").and_then(|v| v.as_str()) {
        s.set_jurisdiction_tag(juris);
    }
    if let Some(abos) = val.get("abos_skywave_enabled").and_then(|v| v.as_bool()) {
        s.abos_skywave_enabled = abos;
    }
    if let Some(qel) = val.get("qel_enabled").and_then(|v| v.as_bool()) {
        s.qel_enabled = qel;
    }
    if let Some(v) = val.get("exp_pow_shield").and_then(|v| v.as_bool()) {
        s.exp_pow_shield = v;
        vantablack::ghost::net::pow::set_enabled(v);
    }
    if let Some(v) = val.get("exp_dtn_reconcile").and_then(|v| v.as_bool()) {
        s.exp_dtn_reconcile = v;
        vantablack::ghost::net::dtn_reconcile::set_enabled(v);
    }
    if let Some(v) = val.get("exp_universal_tunnel").and_then(|v| v.as_bool()) {
        s.exp_universal_tunnel = v;
        vantablack::ghost::net::universal_tunnel::set_enabled(v);
    }
    if let Some(v) = val.get("exp_collective_defense").and_then(|v| v.as_bool()) {
        s.exp_collective_defense = v;
        vantablack::ghost::net::collective_defense::set_enabled(v);
    }
    if let Some(v) = val.get("exp_rendezvous").and_then(|v| v.as_bool()) {
        s.exp_rendezvous = v;
        vantablack::ghost::net::rendezvous::set_enabled(v);
    }
    if let Some(v) = val.get("exp_diffusion").and_then(|v| v.as_bool()) {
        s.exp_diffusion = v;
        vantablack::ghost::net::diffusion::set_enabled(v);
    }
    if let Some(v) = val.get("threat_shield_enabled").and_then(|v| v.as_bool()) {
        s.threat_shield_enabled = v;
        vantablack::ghost::net::threat_shield::set_enabled(v);
    }
    if let Some(add) = val.get("threat_shield_allow_add").and_then(|v| v.as_str()) {
        let clean = add.trim().trim_end_matches('.').to_ascii_lowercase();
        if !clean.is_empty() && !s.threat_shield_allowlist.iter().any(|d| d == &clean) {
            s.threat_shield_allowlist.push(clean);
            s.sync_threat_shield();
        }
    }
    if let Some(rem) = val
        .get("threat_shield_allow_remove")
        .and_then(|v| v.as_str())
    {
        let clean = rem.trim().trim_end_matches('.').to_ascii_lowercase();
        s.threat_shield_allowlist.retain(|d| d != &clean);
        s.sync_threat_shield();
    }
    if !cp_ref.is_empty() && bypass_err.is_none() {
        save_consumer_settings(cp_ref, &s);
    }
    if let Some(err_msg) = bypass_err {
        let body = serde_json::json!({
            "success": false,
            "error": err_msg,
            "bypass": s.bypass,
            "bypass_count": s.bypass.len(),
        })
        .to_string();
        ("HTTP/1.1 400 Bad Request", body, "application/json")
    } else {
        let body = serde_json::json!({
            "success": true,
            "route_mode": s.route_mode,
            "bypass": s.bypass,
            "bypass_count": s.bypass.len(),
            "private_mesh_scan_interval_secs": scan_interval_ref.load(Ordering::Relaxed),
            "stego_carrier_mode": s.stego_carrier_mode,
            "energy_ledger_enabled": s.energy_ledger_enabled,
            "jurisdiction_tag": s.jurisdiction_tag,
            "abos_skywave_enabled": s.abos_skywave_enabled,
            "qel_enabled": s.qel_enabled,
            "exp_pow_shield": s.exp_pow_shield,
            "exp_dtn_reconcile": s.exp_dtn_reconcile,
            "exp_universal_tunnel": s.exp_universal_tunnel,
            "exp_collective_defense": s.exp_collective_defense,
            "exp_rendezvous": s.exp_rendezvous,
            "exp_diffusion": s.exp_diffusion,
            "threat_shield_enabled": s.threat_shield_enabled,
            "threat_shield_blocked": vantablack::ghost::net::threat_shield::blocked_total(),
            "threat_shield_allowlist": s.threat_shield_allowlist,
        })
        .to_string();
        ("HTTP/1.1 200 OK", body, "application/json")
    }
}

fn handle_get_threat_shield(
    cs_ref: &Arc<parking_lot::RwLock<ConsumerSettings>>,
) -> (&'static str, String, &'static str) {
    let allowlist = cs_ref.read().threat_shield_allowlist.clone();
    let (domains, cidrs, allowlist_len) = vantablack::ghost::net::threat_shield::with_shield(|s| {
        (s.domain_count(), s.cidr_count(), s.allowlist_len())
    });
    let recent: Vec<serde_json::Value> = vantablack::ghost::net::threat_shield::recent_blocks(32)
        .into_iter()
        .map(|ev| {
            serde_json::json!({
                "value": ev.value,
                "kind": ev.kind.as_str(),
                "at": ev.at,
            })
        })
        .collect();
    let body = serde_json::json!({
        "enabled": vantablack::ghost::net::threat_shield::is_enabled(),
        "blocked_total": vantablack::ghost::net::threat_shield::blocked_total(),
        "domains": domains,
        "cidrs": cidrs,
        "allowlist_len": allowlist_len,
        "allowlist": allowlist,
        "last_install_at": vantablack::ghost::net::threat_feed::last_install_at(),
        "recent_blocks": recent,
    })
    .to_string();
    ("HTTP/1.1 200 OK", body, "application/json")
}
