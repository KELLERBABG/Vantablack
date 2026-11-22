//! Product Surface — Control Center API & SOCKS5 End-to-End Integration Tests
//!
//! Exercises:
//! 1. Headless daemon startup (`GHOST_NO_GUI=1`).
//! 2. `GET /api/status` endpoint (status, device info, session counters, uptime).
//! 3. `GET /api/peers` endpoint (peer list, count).
//! 4. `POST /api/mode` endpoint (operation mode mutation).
//! 5. `POST /api/connect` endpoint (connect / disconnect toggle).
//! 6. `GET /api/settings` & `POST /api/settings` (split-tunnel bypass add, disk persistence, remove).
//! 7. Live SOCKS5 proxy RFC 1928 handshake and byte forwarding through split-tunnel bypass.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

struct NodeProcessGuard {
    child: Child,
}

impl Drop for NodeProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Find a contiguous block of `count` free TCP ports, ensuring concurrent tests
/// in this binary never overlap on multi-port SOCKS5 ranges (`base..base+4`).
fn reserve_port_block(count: u16) -> u16 {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let mu = USED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut used = mu.lock().expect("port reservation lock");
    for _ in 0..200 {
        let base_listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let base = base_listener.local_addr().expect("local addr").port();
        drop(base_listener);
        let Some(end) = base.checked_add(count) else {
            continue;
        };
        if (base..end).any(|p| used.contains(&p)) {
            continue;
        }
        let mut listeners = Vec::with_capacity(count as usize);
        let mut all_free = true;
        for p in base..end {
            match TcpListener::bind(("127.0.0.1", p)) {
                Ok(l) => listeners.push(l),
                Err(_) => {
                    all_free = false;
                    break;
                }
            }
        }
        drop(listeners);
        if all_free {
            for p in base..end {
                used.insert(p);
            }
            return base;
        }
    }
    panic!("failed to reserve {count} contiguous free TCP ports");
}

/// Find a free ephemeral TCP port.
fn get_free_port() -> u16 {
    reserve_port_block(1)
}

/// Locate the vantablack binary compiled by cargo.
fn find_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_vantablack") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_ggn") {
        return PathBuf::from(path);
    }

    // Fallback: check target directories
    let candidates = [
        "target/debug/vantablack.exe",
        "target/debug/vantablack",
        "target/release/vantablack.exe",
        "target/release/vantablack",
        "C:/target/debug/vantablack.exe",
        "C:/target/debug/vantablack",
    ];

    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return p;
        }
    }

    panic!("Could not locate vantablack binary. Ensure it is built before running tests.");
}

/// Send an HTTP/1.1 request and parse the status code and JSON response body.
fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> (u16, serde_json::Value) {
    http_request_timeout(port, method, path, body, Duration::from_secs(5))
}

/// True once `buf` holds a whole HTTP response: the headers, plus the number
/// of body bytes its `Content-Length` promised.
fn http_response_complete(buf: &[u8]) -> bool {
    let Some(headers_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..headers_end]);
    let declared: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    buf.len() - (headers_end + 4) >= declared
}

/// Send an HTTP/1.1 request with optional extra headers and return `(status, headers, body)`.
fn http_request_raw(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to control center");
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.set_write_timeout(Some(timeout)).unwrap();

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let content_len = body_str.len();
    let mut extra = String::new();
    for (k, v) in extra_headers {
        extra.push_str(&format!("{k}: {v}\r\n"));
    }

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}Content-Type: application/json\r\nContent-Length: {content_len}\r\nConnection: close\r\n\r\n{body_str}"
    );

    stream.write_all(req.as_bytes()).expect("write request");

    // Read until the response is complete rather than until EOF: a handler
    // that takes seconds (the QEL anchor spawns a real subprocess) can make
    // Windows deliver a connection reset when the server closes right after
    // writing, and `read_to_end` would surface that as a failure even though
    // every response byte arrived.
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if http_response_complete(&response) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => panic!("read response: {e}"),
        }
    }
    assert!(!response.is_empty(), "server closed without a response");
    let resp_str = String::from_utf8_lossy(&response);

    let mut lines = resp_str.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("parse status code");

    let body_start = resp_str.find("\r\n\r\n").expect("body delimiter");
    let headers_part = resp_str[..body_start].to_string();
    let body_part = resp_str[body_start + 4..].to_string();
    (status_code, headers_part, body_part)
}

/// Same as [`http_request`] with an explicit socket timeout — needed for
/// endpoints that run a real subprocess (the QEL bridge spawns Python).
fn http_request_timeout(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    timeout: Duration,
) -> (u16, serde_json::Value) {
    let (status_code, _, body_part) = http_request_raw(port, method, path, body, &[], timeout);
    let json_val = serde_json::from_str(body_part.trim()).unwrap_or(serde_json::Value::Null);
    (status_code, json_val)
}

#[test]
fn test_product_surface_control_center_api_and_socks5_e2e() {
    let bin_path = find_binary();
    println!("Testing binary: {}", bin_path.display());

    let web_port = get_free_port();
    let socks_port = reserve_port_block(4);
    let udp_port = get_free_port();

    let temp_dir = std::env::temp_dir().join(format!("vanta_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let consumer_config = temp_dir.join("consumer_settings.json");

    let mut cmd = Command::new(&bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_SOCKS5", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_SOCKS5_PORT", socks_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_CONSUMER_CONFIG", &consumer_config)
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env_remove("GHOST_PSK")
        .env("GHOST_MODE", "public");

    let child = cmd.spawn().expect("failed to spawn daemon");
    let _guard = NodeProcessGuard { child };

    // 1. Wait for Control Center API to become healthy (poll up to 10s)
    let start_wait = Instant::now();
    let mut healthy = false;
    while start_wait.elapsed() < Duration::from_secs(12) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", web_port)) {
            let req = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req);
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200 OK") {
                    healthy = true;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    assert!(
        healthy,
        "Control Center HTTP API failed to start within 12s on port {web_port}"
    );
    println!("Control Center API is healthy on port {web_port}");

    // ── Test 1: GET /api/status ───────────────────────────────────────────
    let (code, status) = http_request(web_port, "GET", "/api/status", None);
    assert_eq!(code, 200, "status code must be 200");
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["mode"], "public");
    assert!(status["connected"].is_boolean());
    assert!(status["network_id"].is_string());
    assert_eq!(status["network_id"].as_str().unwrap().len(), 16);
    assert_eq!(status["socks_listening"], true);
    assert_eq!(status["socks_port"], socks_port);
    assert_eq!(status["multicast_addr"], "239.255.0.1:2270");
    assert_eq!(
        status["socks_ports"],
        serde_json::json!([socks_port, socks_port + 1, socks_port + 2, socks_port + 3])
    );
    assert!(status["uptime_seconds"].as_u64().is_some());
    println!(
        "PASS: GET /api/status validated: network_id={}, version={}",
        status["network_id"], status["version"]
    );

    // ── Test 2: GET /api/peers ────────────────────────────────────────────
    let (code, peers) = http_request(web_port, "GET", "/api/peers", None);
    assert_eq!(code, 200);
    assert!(peers["peers"].is_array());
    assert_eq!(peers["count"], 0);
    println!("PASS: GET /api/peers validated: count=0");

    // ── Test 3: POST /api/mode ────────────────────────────────────────────
    let mode_payload = serde_json::json!({ "mode": "stealth" });
    let (code, mode_resp) = http_request(web_port, "POST", "/api/mode", Some(&mode_payload));
    assert_eq!(code, 200);
    assert_eq!(mode_resp["success"], true);
    assert_eq!(mode_resp["mode"], "stealth");

    // Verify mode is reflected in status
    let (_, status_after_mode) = http_request(web_port, "GET", "/api/status", None);
    assert_eq!(status_after_mode["mode"], "stealth");
    println!("PASS: POST /api/mode mutated mode to 'stealth'");

    // ── Test 4: POST /api/connect (Toggle / Disconnect) ────────────────────
    let disc_payload = serde_json::json!({ "connected": false });
    let (code, conn_resp) = http_request(web_port, "POST", "/api/connect", Some(&disc_payload));
    assert_eq!(code, 200);
    assert_eq!(conn_resp["success"], true);
    assert_eq!(conn_resp["connected"], false);

    let (_, status_after_disc) = http_request(web_port, "GET", "/api/status", None);
    assert_eq!(status_after_disc["connected"], false);

    // Re-connect
    let conn_payload = serde_json::json!({ "connected": true });
    let (code, reconn_resp) = http_request(web_port, "POST", "/api/connect", Some(&conn_payload));
    assert_eq!(code, 200);
    assert_eq!(reconn_resp["connected"], true);
    println!("PASS: POST /api/connect disconnect and reconnect toggle verified");

    // ── Test 5: Split-Tunnel Config Cycle (GET / POST /api/settings) ───────
    let (code, initial_settings) = http_request(web_port, "GET", "/api/settings", None);
    assert_eq!(code, 200);
    assert!(initial_settings["bypass"].is_array());
    let initial_bypass_count = initial_settings["bypass_count"].as_u64().unwrap();

    // Add a split-tunnel bypass rule
    let target_bypass_rule = "bank.corp.internal";
    let add_payload = serde_json::json!({ "bypass_add": target_bypass_rule });
    let (code, add_resp) = http_request(web_port, "POST", "/api/settings", Some(&add_payload));
    assert_eq!(code, 200);
    assert_eq!(add_resp["success"], true);

    // Verify settings updated via GET
    let (code, updated_settings) = http_request(web_port, "GET", "/api/settings", None);
    assert_eq!(code, 200);
    let bypass_arr: Vec<String> = updated_settings["bypass"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        bypass_arr.contains(&target_bypass_rule.to_string()),
        "settings bypass must contain added rule"
    );
    assert_eq!(
        updated_settings["bypass_count"].as_u64().unwrap(),
        initial_bypass_count + 1
    );

    // Verify disk persistence: the config file on disk must reflect the changes
    assert!(
        consumer_config.exists(),
        "consumer config file must be written to disk: {}",
        consumer_config.display()
    );
    let disk_content = std::fs::read_to_string(&consumer_config).expect("read consumer config");
    assert!(
        disk_content.contains(target_bypass_rule),
        "disk config must persist '{target_bypass_rule}'"
    );

    // Remove the split-tunnel bypass rule
    let rem_payload = serde_json::json!({ "bypass_remove": target_bypass_rule });
    let (code, rem_resp) = http_request(web_port, "POST", "/api/settings", Some(&rem_payload));
    assert_eq!(code, 200);
    assert_eq!(rem_resp["success"], true);

    // Verify removal
    let (_, final_settings) = http_request(web_port, "GET", "/api/settings", None);
    let final_bypass: Vec<String> = final_settings["bypass"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(!final_bypass.contains(&target_bypass_rule.to_string()));
    println!("PASS: Split-tunnel config write/read/persist/remove cycle verified");

    // ── Test 5b: Research Settings API ───────────────────────
    let research_payload = serde_json::json!({
        "stego_carrier_mode": true,
        "energy_ledger_enabled": true,
        "jurisdiction_tag": "eu",
        "abos_skywave_enabled": true
    });
    let (code, r_resp) = http_request(web_port, "POST", "/api/settings", Some(&research_payload));
    assert_eq!(code, 200);
    assert_eq!(r_resp["stego_carrier_mode"], true);
    assert_eq!(r_resp["energy_ledger_enabled"], true);
    assert_eq!(r_resp["jurisdiction_tag"], "eu");
    assert_eq!(r_resp["abos_skywave_enabled"], true);
    println!("PASS: Research Settings API verified");

    // ── Test 6: SOCKS5 End-to-End Live Proxy Data Flow ────────────────────
    // Add 127.0.0.1 to split-tunnel bypass so the SOCKS5 proxy relays directly locally
    let bypass_localhost = serde_json::json!({ "bypass_add": "127.0.0.1" });
    let (code, _) = http_request(web_port, "POST", "/api/settings", Some(&bypass_localhost));
    assert_eq!(code, 200);

    // Start a mock TCP echo server
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo listener");
    let echo_port = echo_listener.local_addr().unwrap().port();

    let echo_handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = echo_listener.accept() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        }
    });

    // Connect to SOCKS5 proxy on 127.0.0.1:socks_port
    let mut socks_client =
        TcpStream::connect(("127.0.0.1", socks_port)).expect("connect to SOCKS5 proxy port");
    socks_client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socks_client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // 1. SOCKS5 Greeting: [VER=5, NMETHODS=1, METHOD=0 (No Auth)]
    socks_client
        .write_all(&[0x05, 0x01, 0x00])
        .expect("send greeting");
    let mut greeting_resp = [0u8; 2];
    socks_client
        .read_exact(&mut greeting_resp)
        .expect("read greeting response");
    assert_eq!(
        greeting_resp,
        [0x05, 0x00],
        "SOCKS5 authentication negotiation must succeed"
    );

    // 2. SOCKS5 Connect to 127.0.0.1:echo_port
    // Format: [VER=5, CMD=1 (CONNECT), RSV=0, ATYP=1 (IPv4), DST.ADDR (4 bytes), DST.PORT (2 bytes)]
    let mut connect_cmd = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_cmd.extend_from_slice(&echo_port.to_be_bytes());
    socks_client
        .write_all(&connect_cmd)
        .expect("send SOCKS5 connect");

    // 3. Read SOCKS5 Connect Reply
    let mut connect_resp = [0u8; 10];
    socks_client
        .read_exact(&mut connect_resp)
        .expect("read connect reply");
    assert_eq!(connect_resp[0], 0x05, "reply version");
    assert_eq!(
        connect_resp[1], 0x00,
        "reply status must be 0x00 (success / granted)"
    );

    // 4. Send application bytes through the established SOCKS5 tunnel
    let test_data = b"VANTABLACK_SOCKS5_END_TO_END_VERIFIED_12345";
    socks_client
        .write_all(test_data)
        .expect("write through proxy");

    // 5. Read back echoed response
    let mut echo_back = vec![0u8; test_data.len()];
    socks_client
        .read_exact(&mut echo_back)
        .expect("read echoed bytes");
    assert_eq!(
        &echo_back[..],
        test_data,
        "Echoed bytes must match exactly through proxy"
    );

    echo_handle.join().expect("echo server join");
    println!("PASS: SOCKS5 end-to-end data flow verified successfully");

    // Cleanup temp dir
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Physical anchors surface: `GET /api/v1/anchors/status` reports both anchors
/// (skywave telemetry + QEL state), and `POST /api/v1/anchors/qel/route`
/// degrades honestly to an error JSON (never a 5xx) when the anchor cannot run.
#[test]
fn test_anchors_api_surface() {
    let bin_path = find_binary();
    let web_port = get_free_port();
    let udp_port = get_free_port();

    let temp_dir = std::env::temp_dir().join(format!("vanta_anchors_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mut cmd = Command::new(&bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_SKYWAVE", "1")
        .env("GHOST_QUANTUM", "1")
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env_remove("GHOST_PSK")
        .env("GHOST_MODE", "public");

    let child = cmd.spawn().expect("failed to spawn daemon");
    let _guard = NodeProcessGuard { child };

    // Wait for the API to come up.
    let start_wait = Instant::now();
    let mut healthy = false;
    while start_wait.elapsed() < Duration::from_secs(12) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", web_port)) {
            let req = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req);
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200 OK") {
                    healthy = true;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(healthy, "control center failed to start on port {web_port}");

    // ── Anchors status: both anchors present with honest states ──────────
    let (code, anchors) = http_request(web_port, "GET", "/api/v1/anchors/status", None);
    assert_eq!(code, 200);

    let sky = &anchors["abos_skywave"];
    assert!(sky.is_object(), "skywave anchor must be reported");
    assert_eq!(
        sky["status"], "online",
        "opted-in synthetic carrier is online"
    );
    assert_eq!(
        sky["synthetic"],
        !cfg!(feature = "sdr"),
        "the carrier must report as synthetic only when compiled without --features sdr"
    );
    assert_eq!(sky["carrier_freq_hz"], 5_350_000);

    let qel = &anchors["qel_quantum"];
    assert!(qel.is_object(), "qel anchor must be reported");
    let qel_status = qel["status"].as_str().expect("qel status string");
    assert!(
        ["available", "degraded", "unavailable"].contains(&qel_status),
        "probed anchor state, got {qel_status}"
    );
    println!("PASS: GET /api/v1/anchors/status — skywave online (synthetic), qel={qel_status}");

    // ── QEL route endpoint: degrades to a JSON error, never a 5xx ────────
    // No topology export exists in this temp data dir, so the anchor answers
    // from its preflight without spawning python at all.
    let payload = serde_json::json!({ "from": "deadbeefdeadbeef", "to": "0000000000000000" });
    let (code, route) = http_request_timeout(
        web_port,
        "POST",
        "/api/v1/anchors/qel/route",
        Some(&payload),
        Duration::from_secs(30),
    );
    assert_eq!(code, 200, "degraded QEL results are 200 with success=false");
    assert_eq!(route["success"], false, "no such fingerprints: no route");
    assert!(route["error"].is_string() || route["route"].is_object());

    // A malformed body is a clean 400.
    let (code, _) = http_request(web_port, "POST", "/api/v1/anchors/qel/route", None);
    assert_eq!(code, 400, "missing body must be rejected");

    println!("PASS: POST /api/v1/anchors/qel/route degrades honestly");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// The QEL anchor's *success* path through the daemon: a real route over a real
/// mesh export, distilled far enough to yield key material, with the distilled
/// fidelity — not the route's — naming the key.
///
/// This is the contract the live session mix depends on, so it is checked where
/// the daemon actually parses it rather than only in the Python test suite: the
/// two new fields must round-trip, and `key_fidelity` must be the figure above
/// the BB84 cutoff while `end_to_end_fidelity` is below it.
#[test]
fn test_qel_anchor_routes_a_real_key_over_a_mesh_export() {
    let bin_path = find_binary();
    let web_port = get_free_port();
    let udp_port = get_free_port();

    let temp_dir = std::env::temp_dir().join(format!("vanta_qel_key_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // Two nodes one 10 km hop apart, with the length the quantum layer needs to
    // derive a link's attenuation. Fingerprints are arbitrary here: the
    // endpoint routes between whatever pair it is given.
    let topology = temp_dir.join("qel-topology.json");
    std::fs::write(
        &topology,
        r#"{
          "schema_version": 1,
          "generator": "vantablack",
          "exported_at": 0,
          "nodes": [
            {"fingerprint": "qelfrom00000000", "addr": "10.0.0.1:2270"},
            {"fingerprint": "qelto0000000000", "addr": "10.0.0.2:2270"}
          ],
          "links": [{"a": "qelfrom00000000", "b": "qelto0000000000", "length_km": 10.0}]
        }"#,
    )
    .expect("write topology export");

    let mut cmd = Command::new(&bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_QEL_TOPOLOGY", &topology)
        .env("GHOST_QUANTUM", "1")
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env_remove("GHOST_PSK")
        .env("GHOST_MODE", "public");

    let child = cmd.spawn().expect("failed to spawn daemon");
    let _guard = NodeProcessGuard { child };

    let start_wait = Instant::now();
    let mut healthy = false;
    while start_wait.elapsed() < Duration::from_secs(12) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", web_port)) {
            let req = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req);
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200 OK") {
                    healthy = true;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(healthy, "control center failed to start on port {web_port}");

    let (_, anchors) = http_request(web_port, "GET", "/api/v1/anchors/status", None);
    let qel_status = anchors["qel_quantum"]["status"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    if qel_status != "available" {
        // No python or no quantumnet package here. The anchor says so, which is
        // the honest answer, and the Python suite covers this path directly.
        println!("SKIP: qel anchor is {qel_status} — install with pip install -e \"Quantum Entanglement Link\"");
        let _ = std::fs::remove_dir_all(&temp_dir);
        return;
    }

    let payload = serde_json::json!({"from": "qelfrom00000000", "to": "qelto0000000000"});
    let (code, resp) = http_request_timeout(
        web_port,
        "POST",
        "/api/v1/anchors/qel/route",
        Some(&payload),
        Duration::from_secs(60),
    );
    assert_eq!(code, 200);
    assert_eq!(
        resp["success"], true,
        "a two-node export with a length routes"
    );
    assert_eq!(
        resp["key_derived"], true,
        "distillation must carry the route over the BB84 cutoff: {resp}"
    );

    let route = &resp["route"];
    let route_fid = route["end_to_end_fidelity"]
        .as_f64()
        .expect("route fidelity");
    let key_fid = route["key_fidelity"].as_f64().expect("key fidelity");
    assert!(
        route_fid < 0.88,
        "the route's own fidelity is below the cutoff ({route_fid}) — that is why distillation exists"
    );
    assert!(
        key_fid >= 0.88 && key_fid > route_fid,
        "the key is derived at the distilled fidelity ({key_fid} vs route {route_fid})"
    );
    assert!(
        route["distillation_rounds"].as_u64().unwrap_or(0) >= 1,
        "reaching the cutoff took at least one round"
    );
    let key_hex = route["qkd_key_hex"].as_str().expect("key material");
    assert_eq!(key_hex.len(), 64, "32 bytes of key material as hex");

    println!(
        "PASS: QEL anchor routed a key — route_fid={route_fid:.4}, key_fid={key_fid:.4}, rounds={}",
        route["distillation_rounds"]
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Wait until the Control Center HTTP endpoint answers 200 on `GET /api/status`.
fn wait_for_control_center(web_port: u16) {
    let start_wait = Instant::now();
    while start_wait.elapsed() < Duration::from_secs(12) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", web_port)) {
            let req = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req);
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200 OK") {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("Control Center HTTP API failed to start within 12s on port {web_port}");
}

#[test]
fn test_mesh_ui_endpoints_topology_pac_aliases_vb_uri_and_disconnect() {
    let bin_path = find_binary();
    let web_port = get_free_port();
    let socks_port = reserve_port_block(4);
    let udp_port = get_free_port();

    let temp_dir = std::env::temp_dir().join(format!("vanta_mesh_ui_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let consumer_config = temp_dir.join("consumer_settings.json");

    let mut cmd = Command::new(&bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_SOCKS5", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_SOCKS5_PORT", socks_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_CONSUMER_CONFIG", &consumer_config)
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env_remove("GHOST_PSK")
        .env("GHOST_MODE", "public");

    let child = cmd.spawn().expect("failed to spawn daemon");
    let _guard = NodeProcessGuard { child };
    wait_for_control_center(web_port);

    // 1. GET /api/topology
    let (code, topo) = http_request(web_port, "GET", "/api/topology", None);
    assert_eq!(code, 200);
    assert_eq!(topo["version"], env!("CARGO_PKG_VERSION"));
    assert!(topo["self"]["fingerprint"].is_string());
    assert_eq!(topo["self"]["socks_listening"], true);
    assert_eq!(topo["self"]["socks_port"], socks_port);
    assert_eq!(
        topo["self"]["socks_ports"],
        serde_json::json!([socks_port, socks_port + 1, socks_port + 2, socks_port + 3])
    );
    assert_eq!(topo["self"]["nat_type"], "Detecting");
    assert!(topo["self"]["roles"].is_array());
    assert!(topo["peers"].is_array());
    assert_eq!(topo["wan_readiness"]["socket_ok"], true);
    assert_eq!(topo["wan_readiness"]["socks_ok"], true);
    assert_eq!(topo["wan_readiness"]["swarm_hops_available"], 0);

    // 2. GET /proxy.pac
    let (code, headers, pac_body) = http_request_raw(
        web_port,
        "GET",
        "/proxy.pac",
        None,
        &[],
        Duration::from_secs(5),
    );
    assert_eq!(code, 200);
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("application/x-ns-proxy-autoconfig"),
        "PAC content-type missing: {headers}"
    );
    assert!(pac_body.contains("function FindProxyForURL(url, host)"));
    assert!(pac_body.contains("return \"DIRECT\";"));
    assert!(pac_body.contains(&format!("SOCKS5 127.0.0.1:{socks_port}; DIRECT")));

    // 3. GET / dashboard HTML sanity
    let (code, _, html) = http_request_raw(web_port, "GET", "/", None, &[], Duration::from_secs(5));
    assert_eq!(code, 200);
    assert!(html.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
    assert!(html.contains("239.255.0.1:2270"));
    assert!(html.contains("tab-mesh"));
    assert!(!html.contains("v0.8.21"), "hardcoded v0.8.21 must be gone");
    assert!(
        !html.contains("Verbindung mit Android-App"),
        "German copy must be removed"
    );
    assert!(
        !html.contains("/api/mesh/scan"),
        "broken /api/mesh/scan call must be removed from dashboard JS"
    );

    // 4. Backwards-compatible aliases: POST /api/mesh/scan & POST /api/mesh/config
    let (code, scan_resp) = http_request(web_port, "POST", "/api/mesh/scan", None);
    assert_eq!(code, 200);
    assert_eq!(scan_resp["success"], true);

    let cfg_payload = serde_json::json!({ "scan_interval_secs": 1800 });
    let (code, cfg_resp) = http_request(web_port, "POST", "/api/mesh/config", Some(&cfg_payload));
    assert_eq!(code, 200);
    assert_eq!(cfg_resp["success"], true);
    assert_eq!(cfg_resp["private_mesh_scan_interval_secs"], 1800);

    // 5. POST /api/peers/add with signed vb:// URI (and tampered vb:// rejection)
    let peer_id = vantablack::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
    let kem_pk = [0x55u8; 1184];
    let target_ep: std::net::SocketAddr = format!("127.0.0.1:{}", get_free_port()).parse().unwrap();
    let desc = vantablack::ghost::net::discovery::PeerDescriptor::sign_new(
        &peer_id,
        &kem_pk,
        target_ep,
        vantablack::ghost::net::discovery::NAT_DIRECT,
    );
    let vb_uri = desc.to_uri();
    let add_uri_payload = serde_json::json!({ "address": vb_uri });
    let (code, add_uri_resp) =
        http_request(web_port, "POST", "/api/peers/add", Some(&add_uri_payload));
    assert_eq!(code, 200);
    assert_eq!(add_uri_resp["success"], true);
    assert_eq!(add_uri_resp["uri_parsed"], true);
    assert_eq!(add_uri_resp["address"], target_ep.to_string());

    // Tampered vb:// URI must fail signature verification cleanly with 400
    let mut bad_desc = desc.clone();
    bad_desc.signature[0] ^= 0xFF;
    let bad_payload = serde_json::json!({ "address": bad_desc.to_uri() });
    let (code, bad_resp) = http_request(web_port, "POST", "/api/peers/add", Some(&bad_payload));
    assert_eq!(code, 400);
    assert_eq!(bad_resp["success"], false);

    // 6. POST /api/peers/disconnect
    let (code, bad_disc) = http_request(
        web_port,
        "POST",
        "/api/peers/disconnect",
        Some(&serde_json::json!({})),
    );
    assert_eq!(code, 400);
    assert_eq!(bad_disc["success"], false);

    let (code, disc_resp) = http_request(
        web_port,
        "POST",
        "/api/peers/disconnect",
        Some(&serde_json::json!({ "fingerprint": peer_id.fingerprint() })),
    );
    assert_eq!(code, 200);
    assert_eq!(disc_resp["success"], true);
    assert_eq!(disc_resp["fingerprint"], peer_id.fingerprint());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_topology_and_disconnect_enforce_ghost_pin() {
    let bin_path = find_binary();
    let web_port = get_free_port();
    let udp_port = get_free_port();

    let temp_dir = std::env::temp_dir().join(format!("vanta_pin_topo_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mut cmd = Command::new(&bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_PIN", "secret-pin-42")
        .env("GHOST_ZK_DISCOVERY", "1")
        .env("GHOST_STUN", "off")
        .env_remove("GHOST_PSK")
        .env("GHOST_MODE", "public");

    let child = cmd.spawn().expect("failed to spawn daemon");
    let _guard = NodeProcessGuard { child };
    wait_for_control_center(web_port);

    // Unauthenticated GET /api/topology -> 401
    let (code, unauth) = http_request(web_port, "GET", "/api/topology", None);
    assert_eq!(code, 401);
    assert_eq!(unauth["pin_required"], true);

    // Authenticated GET /api/topology -> 200
    let (code, _, body) = http_request_raw(
        web_port,
        "GET",
        "/api/topology",
        None,
        &[("X-Pin", "secret-pin-42")],
        Duration::from_secs(5),
    );
    assert_eq!(code, 200);
    let topo: serde_json::Value = serde_json::from_str(&body).expect("valid topology json");
    assert!(topo["self"]["fingerprint"].is_string());

    // Unauthenticated POST /api/peers/disconnect -> 401
    let (code, _) = http_request(
        web_port,
        "POST",
        "/api/peers/disconnect",
        Some(&serde_json::json!({ "fingerprint": "deadbeef12345678" })),
    );
    assert_eq!(code, 401);

    // Authenticated POST /api/peers/disconnect -> 200
    let (code, _, disc_body) = http_request_raw(
        web_port,
        "POST",
        "/api/peers/disconnect",
        Some(&serde_json::json!({ "fingerprint": "deadbeef12345678" })),
        &[("X-Pin", "secret-pin-42")],
        Duration::from_secs(5),
    );
    assert_eq!(code, 200);
    let disc: serde_json::Value = serde_json::from_str(&disc_body).expect("valid disconnect json");
    assert_eq!(disc["success"], true);

    // GET /proxy.pac remains reachable without X-Pin for browser PAC fetch
    let (code, _, _) = http_request_raw(
        web_port,
        "GET",
        "/proxy.pac",
        None,
        &[],
        Duration::from_secs(5),
    );
    assert_eq!(code, 200);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_exit_voucher_enforces_ghost_pin_and_mints_valid_capability() {
    let bin_path = find_binary();
    let web_port = get_free_port();
    let udp_port = get_free_port();

    let temp_dir = std::env::temp_dir().join(format!("vanta_exit_voucher_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mut cmd = Command::new(&bin_path);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_WEB_PORT", web_port.to_string())
        .env("GHOST_UDP_PORT", udp_port.to_string())
        .env("GHOST_DATA_DIR", &temp_dir)
        .env("GHOST_PIN", "secret-pin-42")
        .env("GHOST_STUN", "off")
        .env_remove("GHOST_PSK")
        .env("GHOST_MODE", "public");

    let child = cmd.spawn().expect("failed to spawn daemon");
    let _guard = NodeProcessGuard { child };
    wait_for_control_center(web_port);

    let payload = serde_json::json!({
        "peer_fingerprint": "deadbeef12345678",
        "allowed_host": "*.example.test",
        "ttl_secs": 3600
    });

    // Unauthenticated POST /api/exit/voucher -> 401
    let (code, unauth) = http_request(web_port, "POST", "/api/exit/voucher", Some(&payload));
    assert_eq!(code, 401);
    assert_eq!(unauth["pin_required"], true);

    // Authenticated POST /api/exit/voucher -> 200 with valid decodable ExitCapability
    let (code, _, body) = http_request_raw(
        web_port,
        "POST",
        "/api/exit/voucher",
        Some(&payload),
        &[("X-Pin", "secret-pin-42")],
        Duration::from_secs(5),
    );
    assert_eq!(code, 200);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid voucher json");
    assert_eq!(resp["success"], true);
    assert_eq!(resp["peer_fingerprint"], "deadbeef12345678");
    assert_eq!(resp["allowed_host"], "*.example.test");
    let voucher_hex = resp["voucher_hex"].as_str().expect("voucher_hex string");
    let raw = hex::decode(voucher_hex).expect("valid hex");
    let cap =
        vantablack::ghost::net::relay::ExitCapability::decode(&raw).expect("valid ExitCapability");
    assert_eq!(cap.subject, "deadbeef12345678");
    assert_eq!(cap.scope, "*.example.test");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(cap.verify(now, "deadbeef12345678", "*.example.test"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
