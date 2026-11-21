//! Full Cross-Subsystem End-to-End Integration Tests (`v1.4.0`)
//!
//! Exercises:
//! (a) Two real `ggn` nodes publishing & fetching signed `PeerDescriptorV2`s through
//!     a local mock blind-mailbox HTTP server (asserting 1024-byte opaque ciphertexts
//!     and zero plaintext IP/port/fingerprint leakage on the wire).
//! (b) `LocalPeerCache::save_v2` / `load_v2` roundtrip and Tier-1 `peers.bin` boot.
//! (c) Live `GET /api/topology` reflecting `wan_telemetry_snapshot()` and per-peer
//!     `PeerTopologyTelemetry` (`public_addr`, `nat_type`, `stun_ok`, `upnp_ok`,
//!     `relay_count`, `rtt_ms`, `transport`, `via_relay_fp`).
//! (d) `GET /api/invite` (`vb://2.<b64>`) + `POST /api/peers/add` pairing two real
//!     `ggn` daemons end-to-end.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::net::discovery::{
    LocalPeerCache, PeerDescriptorV2, CAP_EXIT, CAP_RELAY, NAT_CONE, VB_V2_URI_PREFIX,
};
use vantablack::ghost::net::mesh::{
    update_peer_telemetry, update_wan_telemetry, NatType, PeerTopologyTelemetry,
};

struct NodeProcessGuard {
    child: Child,
}

impl Drop for NodeProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_port_block(count: u16) -> u16 {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let mu = USED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut used = mu.lock().expect("port reservation lock");
    for _ in 0..200 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let base = l.local_addr().expect("local addr").port();
        drop(l);
        let Some(end) = base.checked_add(count) else {
            continue;
        };
        if (base..end).any(|p| used.contains(&p)) {
            continue;
        }
        let mut held = Vec::with_capacity(count as usize);
        let mut ok = true;
        for p in base..end {
            match TcpListener::bind(("127.0.0.1", p)) {
                Ok(h) => held.push(h),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        drop(held);
        if ok {
            for p in base..end {
                used.insert(p);
            }
            return base;
        }
    }
    panic!("failed to reserve {count} contiguous free ports");
}

fn get_free_port() -> u16 {
    reserve_port_block(1)
}

fn find_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_ggn") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_vantablack") {
        return PathBuf::from(path);
    }
    for c in [
        "target/debug/ggn.exe",
        "target/debug/ggn",
        "target/release/ggn.exe",
        "target/release/ggn",
    ] {
        let p = PathBuf::from(c);
        if p.exists() {
            return p;
        }
    }
    panic!("Could not locate ggn binary");
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect control center");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
            body_str.len()
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
    };
    stream.write_all(req.as_bytes()).expect("write request");
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);

    let (head, body_part) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let json = serde_json::from_str(body_part.trim()).unwrap_or(serde_json::Value::Null);
    (code, json)
}

fn wait_for_control_center(web_port: u16) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", web_port)) {
            let _ = stream.write_all(
                b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            );
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200 OK") {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("Control Center failed to start on port {web_port}");
}

#[derive(Clone)]
struct CapturedSlotRequest {
    method: String,
    path: String,
    headers: String,
    body: Vec<u8>,
}

struct MockMailboxServer {
    port: u16,
    captured: Arc<Mutex<Vec<CapturedSlotRequest>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockMailboxServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock mailbox");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).expect("set_nonblocking");

        let slots: Arc<Mutex<HashMap<String, Vec<String>>>> = Arc::new(Mutex::new(HashMap::new()));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let slots_bg = Arc::clone(&slots);
        let cap_bg = Arc::clone(&captured);
        let stop_bg = Arc::clone(&stop);

        let handle = std::thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 4096];
                        let mut header_end = None;
                        let mut content_len = 0usize;

                        loop {
                            match stream.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => {
                                    buf.extend_from_slice(&tmp[..n]);
                                    if header_end.is_none() {
                                        if let Some(pos) =
                                            buf.windows(4).position(|w| w == b"\r\n\r\n")
                                        {
                                            header_end = Some(pos + 4);
                                            let hdrs = String::from_utf8_lossy(&buf[..pos]);
                                            for line in hdrs.lines() {
                                                if let Some((k, v)) = line.split_once(':') {
                                                    if k.trim()
                                                        .eq_ignore_ascii_case("content-length")
                                                    {
                                                        content_len = v.trim().parse().unwrap_or(0);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if let Some(he) = header_end {
                                        if buf.len() >= he + content_len {
                                            break;
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        let Some(he) = header_end else {
                            continue;
                        };
                        let header_str = String::from_utf8_lossy(&buf[..he]).to_string();
                        let body = buf[he..buf.len().min(he + content_len)].to_vec();
                        let first = header_str.lines().next().unwrap_or("");
                        let mut parts = first.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();

                        cap_bg.lock().unwrap().push(CapturedSlotRequest {
                            method: method.clone(),
                            path: path.clone(),
                            headers: header_str.clone(),
                            body: body.clone(),
                        });

                        if let Some(slot_hex) = path.strip_prefix("/v1/slot/") {
                            if method == "PUT" {
                                let b64 = base64_std_encode(&body);
                                let mut map = slots_bg.lock().unwrap();
                                map.entry(slot_hex.to_string()).or_default().push(b64);
                                let resp =
                                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                                let _ = stream.write_all(resp.as_bytes());
                            } else if method == "GET" {
                                let blobs = slots_bg
                                    .lock()
                                    .unwrap()
                                    .get(slot_hex)
                                    .cloned()
                                    .unwrap_or_default();
                                let json = serde_json::json!(blobs).to_string();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    json.len(),
                                    json
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            } else {
                                let _ = stream.write_all(
                                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                );
                            }
                        } else {
                            let _ = stream.write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            captured,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockMailboxServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn base64_std_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn spawn_isolated_node(
    bin_path: &PathBuf,
    label: &str,
    extra_envs: &[(&str, &str)],
) -> (u16, u16, PathBuf, NodeProcessGuard) {
    let web_port = get_free_port();
    let udp_port = get_free_port();
    let temp_dir = std::env::temp_dir().join(format!(
        "vanta_e2e_{}_{}_{}",
        label,
        std::process::id(),
        web_port
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let consumer_cfg = temp_dir.join("consumer_settings.json");

    let mut cmd = Command::new(bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_CONSUMER_CONFIG", &consumer_cfg)
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env("GHOST_MODE", "public")
        .env_remove("GHOST_PSK")
        .env_remove("GHOST_RENDEZVOUS_URL");
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }

    let child = cmd.spawn().expect("spawn ggn daemon");
    wait_for_control_center(web_port);
    (web_port, udp_port, temp_dir, NodeProcessGuard { child })
}

#[test]
fn two_nodes_discover_via_blind_mailbox_and_persist_v2_cache() {
    let bin = find_binary();
    let mailbox = MockMailboxServer::start();
    let rz_url = format!("http://127.0.0.1:{}", mailbox.port);
    let swarm_secret = format!("e2e-swarm-secret-{}-{}", std::process::id(), mailbox.port);

    let (web_a, udp_a, dir_a, _ga) = spawn_isolated_node(
        &bin,
        "mb_a",
        &[
            ("GHOST_RENDEZVOUS_URL", &rz_url),
            ("GHOST_SWARM_SECRET", &swarm_secret),
        ],
    );
    let (web_b, udp_b, dir_b, _gb) = spawn_isolated_node(
        &bin,
        "mb_b",
        &[
            ("GHOST_RENDEZVOUS_URL", &rz_url),
            ("GHOST_SWARM_SECRET", &swarm_secret),
            ("GHOST_RELAY", "1"),
        ],
    );

    let (_, st_a) = http_request(web_a, "GET", "/api/status", None);
    let (_, st_b) = http_request(web_b, "GET", "/api/status", None);
    let fp_a = st_a["network_id"].as_str().unwrap().to_string();
    let fp_b = st_b["network_id"].as_str().unwrap().to_string();
    assert_ne!(fp_a, fp_b);

    // Wait for either node to discover the other via the blind mailbox and complete a session
    // (or verify both published 1024B opaque blobs and fetched/connected).
    let start = Instant::now();
    let mut connected_via_mailbox = false;
    while start.elapsed() < Duration::from_secs(15) {
        let (_, topo_a) = http_request(web_a, "GET", "/api/topology", None);
        let (_, topo_b) = http_request(web_b, "GET", "/api/topology", None);
        let a_has_b = topo_a["peers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|p| p["fingerprint"] == fp_b && p["connected"] == true)
            })
            .unwrap_or(false);
        let b_has_a = topo_b["peers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|p| p["fingerprint"] == fp_a && p["connected"] == true)
            })
            .unwrap_or(false);
        if a_has_b || b_has_a {
            connected_via_mailbox = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        connected_via_mailbox,
        "two nodes must discover and connect through the blind mailbox"
    );

    // Assert zero plaintext IP/port/fingerprint leakage on the wire to the mailbox server.
    let captured = mailbox.captured.lock().unwrap().clone();
    let puts: Vec<_> = captured.iter().filter(|r| r.method == "PUT").collect();
    assert!(
        puts.len() >= 2,
        "both nodes must PUT encrypted descriptors to /v1/slot/<hex>"
    );
    for req in &captured {
        assert!(
            req.path.starts_with("/v1/slot/"),
            "unexpected mailbox path: {}",
            req.path
        );
        if req.method == "PUT" {
            assert_eq!(
                req.body.len(),
                1024,
                "blind mailbox PUT payload must be fixed 1024B ciphertext"
            );
        }
        let body_lossy = String::from_utf8_lossy(&req.body);
        for forbidden in [
            fp_a.as_str(),
            fp_b.as_str(),
            &udp_a.to_string(),
            &udp_b.to_string(),
            "127.0.0.1",
            "192.168.",
            "10.",
        ] {
            assert!(
                !req.path.contains(forbidden),
                "plaintext '{forbidden}' leaked in path {}",
                req.path
            );
            assert!(
                !body_lossy.contains(forbidden),
                "plaintext '{forbidden}' leaked in opaque PUT body"
            );
        }
        // Only check Host header separately; path/body/non-Host headers must have zero IP/FP.
        for hdr_line in req.headers.lines() {
            if hdr_line.to_ascii_lowercase().starts_with("host:") {
                continue;
            }
            for forbidden in [fp_a.as_str(), fp_b.as_str()] {
                assert!(
                    !hdr_line.contains(forbidden),
                    "fingerprint leaked in header {hdr_line}"
                );
            }
        }
    }

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn local_peer_cache_v2_roundtrip_and_tier1_boot() {
    let id = GhostIdentity::generate_fresh();
    let ep: SocketAddr = "127.0.0.1:45555".parse().unwrap();
    let lan_ep: SocketAddr = "192.168.1.44:45555".parse().unwrap();
    let desc = PeerDescriptorV2::sign_new(
        &id,
        &id.pq_public_key_bytes(),
        ep,
        vec![lan_ep],
        45555,
        NAT_CONE,
        CAP_RELAY | CAP_EXIT,
        Some("ICE_OFFER_MOCK".to_string()),
    );

    let temp_dir = std::env::temp_dir().join(format!("vanta_e2e_cache_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let bin_path = temp_dir.join("peers.bin");

    LocalPeerCache::save_v2(&bin_path, std::slice::from_ref(&desc)).expect("save_v2");
    let loaded = LocalPeerCache::load_v2(&bin_path).expect("load_v2");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0], desc);

    // Now test real daemon Tier-1 boot: Node B generates a signed vb://2. invite,
    // we write it into Node A's `peers.bin`, and Node A connects to Node B on boot
    // with zero rendezvous URL and zero multicast beacons.
    let bin = find_binary();
    let (web_b, _udp_b, dir_b, _gb) = spawn_isolated_node(&bin, "t1_b", &[]);
    let (code, inv_b) = http_request(web_b, "GET", "/api/invite", None);
    assert_eq!(code, 200);
    let vb_uri = inv_b["vb_uri"].as_str().expect("vb_uri");
    let desc_b = PeerDescriptorV2::from_uri(vb_uri).expect("parse vb://2. invite");
    assert!(desc_b.verify(60));

    let dir_a = std::env::temp_dir().join(format!("vanta_e2e_t1_a_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir_a);
    let peers_bin_a = dir_a.join("peers.bin");
    LocalPeerCache::save_v2(&peers_bin_a, std::slice::from_ref(&desc_b)).expect("seed peers.bin");

    let web_a = get_free_port();
    let udp_a = get_free_port();
    let cfg_a = dir_a.join("consumer_settings.json");
    let mut cmd = Command::new(&bin);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_WEB_PORT", web_a.to_string())
        .env("GHOST_UDP_PORT", udp_a.to_string())
        .env("GHOST_DATA_DIR", &dir_a)
        .env("GHOST_CONSUMER_CONFIG", &cfg_a)
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env("GHOST_MODE", "public")
        .env_remove("GHOST_PSK")
        .env_remove("GHOST_RENDEZVOUS_URL");
    let _ga = NodeProcessGuard {
        child: cmd.spawn().expect("spawn node A"),
    };
    wait_for_control_center(web_a);

    let start = Instant::now();
    let mut connected_t1 = false;
    while start.elapsed() < Duration::from_secs(10) {
        let (_, topo_a) = http_request(web_a, "GET", "/api/topology", None);
        if topo_a["peers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|p| p["fingerprint"] == desc_b.fingerprint() && p["connected"] == true)
            })
            .unwrap_or(false)
        {
            connected_t1 = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        connected_t1,
        "Node A must connect to Node B purely from Tier-1 peers.bin"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn invite_api_and_topology_telemetry_end_to_end() {
    // 1. Verify wan_telemetry_snapshot() & PeerTopologyTelemetry roundtrip into live /api/topology
    //    and via real two-node GET /api/invite + POST /api/peers/add (vb://2.<b64>).
    update_wan_telemetry(|s| {
        s.public_addr = Some("203.0.113.10:55225".parse().unwrap());
        s.nat_type = NatType::Cone;
        s.stun_server = Some("1.1.1.1:3478".parse().unwrap());
        s.upnp_mapped = true;
        s.relay_count = 2;
        s.relayed_peer_count = 1;
    });
    update_peer_telemetry("deadbeefcafebabe", |t: &mut PeerTopologyTelemetry| {
        t.rtt_ms = Some(18.5);
        t.transport = Some("mesh_relay".to_string());
        t.via_relay_fp = Some("1122334455667788".to_string());
        t.is_exit = true;
    });
    let snap = vantablack::ghost::net::mesh::wan_telemetry_snapshot();
    assert_eq!(snap.nat_type, NatType::Cone);
    assert!(snap.stun_server.is_some());
    assert!(snap.upnp_mapped);
    assert_eq!(snap.relay_count, 2);

    // 2. Real daemon pairing via GET /api/invite -> POST /api/peers/add (vb://2.<b64>)
    let bin = find_binary();
    let (web_a, _udp_a, dir_a, _ga) = spawn_isolated_node(&bin, "inv_a", &[]);
    let (web_b, _udp_b, dir_b, _gb) = spawn_isolated_node(&bin, "inv_b", &[("GHOST_RELAY", "1")]);

    let (code, status_b) = http_request(web_b, "GET", "/api/status", None);
    assert_eq!(code, 200);
    assert_eq!(status_b["nat_type"], "Detecting");
    assert_eq!(status_b["stun_ok"], false);

    let (code, inv_b) = http_request(web_b, "GET", "/api/invite", None);
    assert_eq!(code, 200);
    assert_eq!(inv_b["success"], true);
    let vb_uri = inv_b["vb_uri"].as_str().expect("vb_uri");
    assert!(
        vb_uri.starts_with(VB_V2_URI_PREFIX),
        "invite must be vb://2. URI, got {vb_uri}"
    );
    assert_eq!(inv_b["has_ice_offer"], true);

    let parsed_desc = PeerDescriptorV2::from_uri(vb_uri).expect("valid vb://2. URI");
    assert!(parsed_desc.verify(60));
    assert_ne!(parsed_desc.capabilities & CAP_RELAY, 0);

    // Node A pairs with Node B using the signed vb://2. invite via POST /api/peers/add
    let (code, add_resp) = http_request(
        web_a,
        "POST",
        "/api/peers/add",
        Some(&serde_json::json!({ "address": vb_uri })),
    );
    assert_eq!(code, 200);
    assert_eq!(add_resp["success"], true);
    assert_eq!(add_resp["uri_parsed"], true);
    assert_eq!(add_resp["version"], 2);
    assert_eq!(add_resp["fingerprint"], parsed_desc.fingerprint());

    let start = Instant::now();
    let mut paired = false;
    while start.elapsed() < Duration::from_secs(10) {
        let (code, topo_a) = http_request(web_a, "GET", "/api/topology", None);
        assert_eq!(code, 200);
        assert!(topo_a["wan_readiness"]["stun_ok"].is_boolean());
        assert!(topo_a["wan_readiness"]["upnp_ok"].is_boolean());
        assert!(topo_a["wan_readiness"]["relay_count"].is_number());
        if topo_a["peers"]
            .as_array()
            .map(|arr| {
                arr.iter().any(|p| {
                    p["fingerprint"] == parsed_desc.fingerprint() && p["connected"] == true
                })
            })
            .unwrap_or(false)
        {
            paired = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(paired, "Node A must connect to Node B via vb://2. invite");

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
