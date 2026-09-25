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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
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

/// Find a free ephemeral TCP port.
fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
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
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to control center");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let content_len = body_str.len();

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {content_len}\r\nConnection: close\r\n\r\n{body_str}"
    );

    stream.write_all(req.as_bytes()).expect("write request");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
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
    let body_part = &resp_str[body_start + 4..];

    let json_val = serde_json::from_str(body_part.trim()).unwrap_or(serde_json::Value::Null);

    (status_code, json_val)
}

#[test]
fn test_product_surface_control_center_api_and_socks5_e2e() {
    let bin_path = find_binary();
    println!("Testing binary: {}", bin_path.display());

    let web_port = get_free_port();
    let socks_port = get_free_port();
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
    assert_eq!(status["mode"], "public");
    assert!(status["connected"].is_boolean());
    assert!(status["network_id"].is_string());
    assert_eq!(status["network_id"].as_str().unwrap().len(), 16);
    assert_eq!(status["socks_listening"], true);
    assert_eq!(status["socks_port"], socks_port);
    assert!(status["uptime_seconds"].as_u64().is_some());
    println!(
        "PASS: GET /api/status validated: network_id={}",
        status["network_id"]
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
