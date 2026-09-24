//! Control center and telemetry HTTP server for Vantablack.
//!
//! Provides the REST API (/api/status, /api/peers, /api/mode, /api/connect,
//! /api/settings, /api/scan, /api/pipeline_probe), Prometheus /metrics,
//! and the embedded HTML dashboard.

use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vantablack::ghost::net::consumer::{self, ConsumerSettings};
use vantablack::ghost::GhostNode;
use crate::vpn::daemon::{vpn_export, VpnMode};

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
        "connected": has_session,
        "status": consumer::peer_status(has_session, true),
        "role": if has_session { "Active Mesh Peer" } else { "Discovered Peer" },
        "latency_ms": serde_json::Value::Null,
    })
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
) {
    let nc_m = Arc::clone(&nc);
    let addrs_m = Arc::clone(&addrs);
    let c_conn_m = Arc::clone(&consumer_connected);
    let c_mode_m = Arc::clone(&consumer_mode);
    let c_pin_m = Arc::clone(&consumer_pin);
    let c_settings_m = Arc::clone(&consumer_settings);
    let c_path_m = consumer_config;
    let lan_host_m = lan_host;
    let pair_uri_m = pair_uri;
    let vpn_m = vpn_mode;
    let mp = metrics_port;
    let carrier_m = Arc::clone(&carrier);
    let phs_m = Arc::clone(&pending_hs);
    let scan_notify_m = Arc::clone(&scan_notify);
    let scan_interval_m = Arc::clone(&scan_interval_secs);

    tokio::spawn(async move {
        let bind_addr = format!("0.0.0.0:{}", mp);
        match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(listener) => {
                tracing::info!(
                    "Ghost Web Control Center & Telemetry listening on http://127.0.0.1:{} (LAN: http://0.0.0.0:{})",
                    mp,
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
                    if let Ok((mut stream, _)) = listener.accept().await {
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
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            if let Ok(n) = stream.read(&mut buf).await {
                                let req = String::from_utf8_lossy(&buf[..n]);
                                let (vpn_role, vpn_prom, vpn_json) = vpn_export(&vpn_ref);
                                let vpn_available = vpn_ref.is_some();
                                let configured_pin = pin_ref.read().clone();
                                let pin_ok = match configured_pin.as_deref() {
                                    None => true,
                                    Some(expected) => header_pin(&req) == Some(expected),
                                };
                                let is_mutation = req.starts_with("POST ");

                                if req.starts_with("OPTIONS ") {
                                    let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Pin\r\nConnection: close\r\n\r\n";
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    return;
                                }

                                let (status_line, body, content_type) = if is_mutation && !pin_ok {
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
                                } else if req.starts_with("GET /api/status") {
                                    let is_conn = conn_ref.load(Ordering::Relaxed);
                                    let current_mode = mode_ref.read().clone();
                                    let has_pin = pin_ref.read().is_some();
                                    let sent_bytes = nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                    let recv_bytes = nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                    let sent_pkts = nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                    let recv_pkts = nc_ref.stats.packets_recv.load(Ordering::Relaxed);
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

                                    let route_mode_active = match settings_now.route_mode.as_str() {
                                        consumer::ROUTE_MODE_SYSTEM_VPN => vpn_available,
                                        _ => socks_listening,
                                    };
                                    let body = serde_json::json!({
                                        "connected": is_conn,
                                        "mode": current_mode,
                                        "network_id": nc_ref.fingerprint(),
                                        "device_name": settings_now.device_name(&nc_ref.fingerprint()),
                                        "device_os": consumer::local_os(),
                                        "host": lan_host_ref,
                                        "pair_uri": pair_uri_ref,
                                        "route_mode": settings_now.route_mode,
                                        "route_mode_active": route_mode_active,
                                        "bypass_count": settings_now.bypass.len(),
                                        "socks_listening": socks_listening,
                                        "socks_port": socks_port,
                                        "vpn_available": vpn_available,
                                        "pin_protected": has_pin,
                                        "uptime_seconds": uptime,
                                        "peers_count": peers_count,
                                        "active_sessions": sessions_count,
                                        "private_mesh": {
                                            "active_nodes": sessions_count,
                                            "autonomous_local": sessions_count >= 5,
                                            "mode": if sessions_count >= 5 { "autonomous_local" } else { "wan_mesh_assisted" },
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
                                        "traffic": {
                                            "bytes_sent": sent_bytes,
                                            "bytes_recv": recv_bytes,
                                            "packets_sent": sent_pkts,
                                            "packets_recv": recv_pkts,
                                            "cover_traffic_rate_hz": 2.0,
                                            "cover_traffic_active": sessions_count > 0,
                                        },
                                        "vpn": vpn_role,
                                        "vpn_stats": vpn_json,
                                        "peers": peer_entries,
                                    })
                                    .to_string();
                                    ("HTTP/1.1 200 OK", body, "application/json")
                                } else if req.starts_with("POST /api/peers/add") {
                                    let val = json_body(&req);
                                    let addr_str = val
                                        .get("address")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .trim();
                                    match addr_str.parse::<SocketAddr>() {
                                        Ok(target_addr) => {
                                            initiate_handshake(
                                                &nc_ref,
                                                &nc_ref.socket,
                                                target_addr,
                                                &phs_ref,
                                            )
                                            .await;
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
                                            ("HTTP/1.1 400 Bad Request", body, "application/json")
                                        }
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
                                    let next = val
                                        .get("connected")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or_else(|| !conn_ref.load(Ordering::Relaxed));
                                    conn_ref.store(next, Ordering::Relaxed);
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
                                } else if req.starts_with("POST /api/scan") {
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
                                        .unwrap_or(2_000_000) as usize;
                                    let probe_res = run_pipeline_probe(total_bytes);
                                    ("HTTP/1.1 200 OK", probe_res.to_string(), "application/json")
                                } else if req.starts_with("GET /api/settings") {
                                    let s = cs_ref.read().clone();
                                    let body = serde_json::json!({
                                        "success": true,
                                        "route_mode": s.route_mode,
                                        "device_names": s.device_names,
                                        "device_os": s.device_os,
                                        "bypass": s.bypass,
                                        "bypass_count": s.bypass.len(),
                                        "private_mesh_scan_interval_secs": scan_interval_ref.load(Ordering::Relaxed),
                                    })
                                    .to_string();
                                    ("HTTP/1.1 200 OK", body, "application/json")
                                } else if req.starts_with("POST /api/settings") {
                                    let val = json_body(&req);
                                    let mut s = cs_ref.write();
                                    if let Some(r) = val.get("route_mode").and_then(|v| v.as_str()) {
                                        s.set_route_mode(r);
                                    }
                                    if let Some(add) = val.get("bypass_add").and_then(|v| v.as_str()) {
                                        let _ = s.add_bypass(add);
                                    }
                                    if let Some(rem) = val.get("bypass_remove").and_then(|v| v.as_str()) {
                                        s.remove_bypass(rem);
                                    }
                                    if let Some(secs) = val.get("private_mesh_scan_interval_secs").and_then(|v| v.as_u64()) {
                                        scan_interval_ref.store(secs as u32, Ordering::Relaxed);
                                    }
                                    if let Some(names) = val.get("set_device_name").or_else(|| val.get("set_peer_name")).and_then(|v| v.as_object()) {
                                        for (k, v) in names {
                                            if let Some(name_str) = v.as_str() {
                                                let _ = s.set_device_name(k, name_str);
                                            }
                                        }
                                    }
                                    if !cp_ref.is_empty() {
                                        save_consumer_settings(&cp_ref, &s);
                                    }
                                    let body = serde_json::json!({
                                        "success": true,
                                        "route_mode": s.route_mode,
                                        "bypass_count": s.bypass.len(),
                                        "private_mesh_scan_interval_secs": scan_interval_ref.load(Ordering::Relaxed),
                                    })
                                    .to_string();
                                    ("HTTP/1.1 200 OK", body, "application/json")
                                } else if req.starts_with("GET /api/wan_telemetry") {
                                    let sent_bytes = nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                    let recv_bytes = nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                    let sent_pkts = nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                    let recv_pkts = nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                    let retrans = nc_ref.stats.retransmits.load(Ordering::Relaxed);
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
                                } else if req.starts_with("GET /dashboard")
                                    || req.starts_with("GET / ")
                                    || req.starts_with("GET /?")
                                {
                                    let html = include_str!("../assets/wan_dashboard.html");
                                    (
                                        "HTTP/1.1 200 OK",
                                        html.to_string(),
                                        "text/html; charset=utf-8",
                                    )
                                } else if req.starts_with("GET /metrics") {
                                    let sessions = nc_ref.sessions.len();
                                    let peers = addrs_ref.len();
                                    let uptime = nc_ref.created_at.elapsed().as_secs();
                                    let sent_bytes = nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                    let recv_bytes = nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                    let sent_pkts = nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                    let recv_pkts = nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                    let retrans = nc_ref.stats.retransmits.load(Ordering::Relaxed);
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
                                    "{}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Pin\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    status_line, content_type, body.len(), body
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                        });
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
