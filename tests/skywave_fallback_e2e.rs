//! End-to-end: a frame crosses the *skywave* fallback rung between two live
//! daemons, with both physical anchors enabled.
//!
//! Two real `vantablack` processes are started, each with `GHOST_SKYWAVE=1` (the
//! ABOS carrier) and `GHOST_QUANTUM=1` (the QEL anchor). They discover each other
//! over IP, complete a hybrid handshake and hold a real session — and then every
//! terrestrial rung of the fallback ladder is out of action:
//!
//! * **direct** — each node declares the other *radio-only*
//!   (`GHOST_SKYWAVE_ONLY`, see `docs/ANCHORS_CODEBASE_INTEGRATION.md` §8), so no
//!   candidate pair is ever checked and no later measurement may supersede the
//!   declaration. The declaration is resolved through the same ladder a failed
//!   check walks, with the terrestrial rungs withheld, so it can only pre-empt the
//!   ladder's answer and never invent a route.
//! * **mesh relay** — neither node runs with `GHOST_RELAY=1`, so no peer
//!   advertises relay capability and the ladder is offered no relay candidate.
//! * **TURN** — neither node is configured with `GHOST_TURN_*`, so it holds no
//!   allocation and the ladder can never select a TURN route.
//!
//! What the assertions prove, and why each one is load-bearing:
//!
//! * the far node prints the decrypted marker — the payload arrived and
//!   authenticated under the session's AEAD;
//! * the *skywave* counters move by at least the three RS shards — and cover
//!   traffic cannot move them, because cover rides the mesh socket directly; the
//!   only writers are the fallback rungs;
//! * both logs carry the per-shard skywave routing line, and never the direct-path
//!   or relay-fallback lines — so the radio is what carried the frame, and the
//!   rungs that would have been measured first were never even tried;
//! * the boot log shows both declarations landing, so the pin is in force rather
//!   than silently rejected (an unarmed carrier refuses the pin out loud).
//!
//! The chat path short-circuits on the route table, so a mesh delivery and a radio
//! delivery are mutually exclusive: if the pin had not taken effect there would be
//! no route at all, and the counters would not move.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use vantablack::ghost::layers::l0_identity::GhostIdentity;

/// The multicast port every daemon binds for discovery. Handing it to a node as
/// its mesh or carrier port would collide with that node's own beacon socket.
const BEACON_PORT: u16 = 2270;

/// The skywave message the router logs once per shard it hands to the carrier.
const SKYWAVE_ROUTE_LOG: &str = "routing datagram across Skywave NVIS carrier";
/// The declaration landing, as the boot log reports it.
const PIN_LOG: &str = "pinned to the skywave carrier";
/// The two lines that would mean a terrestrial rung carried (or was tried for)
/// the frame. Neither may appear: the declaration replaces the direct check, and
/// no relay or TURN route exists to fall back to.
const DIRECT_PATH_LOG: &str = "ICE: direct path established";
const RELAY_FALLBACK_LOG: &str = "falling back to a relay";

// ── process harness ─────────────────────────────────────────────────────

/// Locate the vantablack binary compiled by cargo.
fn find_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_vantablack") {
        return PathBuf::from(path);
    }
    for candidate in [
        "target/debug/vantablack.exe",
        "target/debug/vantablack",
        "target/release/vantablack.exe",
        "target/release/vantablack",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!("could not locate the vantablack binary — build it before running tests");
}

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral tcp port");
    listener.local_addr().expect("local addr").port()
}

fn free_udp_port() -> u16 {
    loop {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp port");
        let port = sock.local_addr().expect("local addr").port();
        drop(sock);
        if port != BEACON_PORT {
            return port;
        }
    }
}

/// A daemon under test: its control plane, its console and its captured log.
struct Daemon {
    name: &'static str,
    child: Child,
    stdin: ChildStdin,
    web: u16,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn trace(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn status(&self) -> serde_json::Value {
        let (code, value) = http_json(self.web, "GET", "/api/status", None);
        assert_eq!(code, 200, "{}: GET /api/status", self.name);
        value
    }

    fn anchors(&self) -> serde_json::Value {
        let (code, value) = http_json(self.web, "GET", "/api/v1/anchors/status", None);
        assert_eq!(code, 200, "{}: GET /api/v1/anchors/status", self.name);
        value
    }

    fn sessions(&self) -> u64 {
        self.status()["active_sessions"].as_u64().unwrap_or(0)
    }

    /// `(tx_packets, rx_packets, tx_dsp_bytes)` of the skywave carrier.
    fn skywave(&self) -> (u64, u64, u64) {
        let anchors = self.anchors();
        let sky = &anchors["abos_skywave"];
        (
            sky["tx_packets"].as_u64().unwrap_or(0),
            sky["rx_packets"].as_u64().unwrap_or(0),
            sky["tx_dsp_bytes"].as_u64().unwrap_or(0),
        )
    }

    fn run(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").expect("write console command");
        self.stdin.flush().expect("flush console command");
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_daemon(
    bin: &Path,
    name: &'static str,
    dir: &Path,
    web: u16,
    mesh: u16,
    carrier: u16,
    peer_carrier: u16,
    identity: &Path,
    radio_only: &str,
) -> Daemon {
    std::fs::create_dir_all(dir).expect("create node data dir");
    let log = dir.join("test.log");
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .expect("open log");
    let err = out.try_clone().expect("clone log handle");

    let mut cmd = Command::new(bin);
    cmd.env("GHOST_NO_GUI", "1")
        .env("GHOST_MODE", "public")
        .env("GHOST_WEB_PORT", web.to_string())
        .env("GHOST_BIND", format!("127.0.0.1:{mesh}"))
        .env("GHOST_DATA_DIR", dir)
        .env("GHOST_IDENTITY_FILE", identity)
        .env("GHOST_LOG", dir.join("ghost.log"))
        // Both anchors on: the ABOS carrier, and the QEL quantum anchor.
        .env("GHOST_SKYWAVE", "1")
        .env("GHOST_QUANTUM", "1")
        .env(
            "GHOST_SKYWAVE_UDP",
            format!("127.0.0.1:{carrier}|127.0.0.1:{peer_carrier}"),
        )
        // The whole point: every IP rung of the ladder is out of action.
        .env("GHOST_SKYWAVE_ONLY", radio_only)
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    // The client of this test may run under a shell that exports these; the
    // premise of the test is that none of them is configured, so they are
    // removed rather than assumed absent.
    for var in [
        "GHOST_RELAY",
        "GHOST_TURN_SERVER",
        "GHOST_TURN_USER",
        "GHOST_TURN_PASS",
        "GHOST_PSK",
        "GHOST_AMNESIA",
        "GHOST_ZK_DISCOVERY",
        "GHOST_VPN",
        "GHOST_SOCKS5",
        "GHOST_LDPC_FEC",
    ] {
        cmd.env_remove(var);
    }

    let mut child = cmd.spawn().expect("spawn daemon");
    let stdin = child.stdin.take().expect("daemon stdin");
    Daemon {
        name,
        child,
        stdin,
        web,
        log,
    }
}

// ── HTTP + waiting ──────────────────────────────────────────────────────

/// True once `buf` holds a whole HTTP response: headers plus the body its
/// `Content-Length` promised.
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

fn http_json(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> (u16, serde_json::Value) {
    try_http_json(port, method, path, body).expect("connect to control center")
}

/// [`http_json`] for a caller that polls: `None` means the control center is not
/// listening yet, which is a state and not a failure.
fn try_http_json(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Option<(u16, serde_json::Value)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let timeout = Duration::from_secs(10);
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.set_write_timeout(Some(timeout)).unwrap();

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");

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
    let text = String::from_utf8_lossy(&response);
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body_part = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    Some((
        status,
        serde_json::from_str(body_part.trim()).unwrap_or(serde_json::Value::Null),
    ))
}

/// Report both logs and fail: a two-process test that only says "timed out" is
/// useless to whoever has to debug it.
fn fail_with_logs(a: &Daemon, b: &Daemon, message: String) -> ! {
    println!(
        "--- {} (log {}) ---\n{}",
        a.name,
        a.log.display(),
        a.trace()
    );
    println!(
        "--- {} (log {}) ---\n{}",
        b.name,
        b.log.display(),
        b.trace()
    );
    panic!("{message}");
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// ── the test ────────────────────────────────────────────────────────────

#[test]
fn a_frame_crosses_the_skywave_rung_when_every_ip_rung_is_unusable() {
    let bin = find_binary();
    println!("Testing binary: {}", bin.display());

    let root = std::env::temp_dir().join(format!("vanta_skywave_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // Identities are generated before boot because a radio-only declaration names
    // a *fingerprint*, and the daemons have to be told about it at startup.
    let id_a = root.join("a").join("identity.key");
    let id_b = root.join("b").join("identity.key");
    std::fs::create_dir_all(id_a.parent().unwrap()).unwrap();
    std::fs::create_dir_all(id_b.parent().unwrap()).unwrap();
    let fp_a = GhostIdentity::load_or_generate_opts(id_a.to_str().unwrap(), false).fingerprint();
    let fp_b = GhostIdentity::load_or_generate_opts(id_b.to_str().unwrap(), false).fingerprint();
    assert_ne!(fp_a, fp_b, "two nodes must not share an identity");
    println!("Node A fingerprint {fp_a} / node B fingerprint {fp_b}");

    let web_a = free_tcp_port();
    let web_b = free_tcp_port();
    let mesh_a = free_udp_port();
    let mesh_b = free_udp_port();
    let carrier_a = free_udp_port();
    let carrier_b = free_udp_port();

    let mut a = spawn_daemon(
        &bin,
        "A",
        &root.join("a"),
        web_a,
        mesh_a,
        carrier_a,
        carrier_b,
        &id_a,
        &fp_b,
    );
    let mut b = spawn_daemon(
        &bin,
        "B",
        &root.join("b"),
        web_b,
        mesh_b,
        carrier_b,
        carrier_a,
        &id_b,
        &fp_a,
    );

    // ── 1. Both control centers answer, with the identities the pins name ──
    let start = Instant::now();
    let mut healthy = false;
    while start.elapsed() < Duration::from_secs(30) {
        let up_a = try_http_json(web_a, "GET", "/api/status", None).is_some_and(|(c, _)| c == 200);
        let up_b = try_http_json(web_b, "GET", "/api/status", None).is_some_and(|(c, _)| c == 200);
        if up_a && up_b {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    if !healthy {
        fail_with_logs(
            &a,
            &b,
            "both control centers must answer /api/status within 30s".into(),
        );
    }
    let status_a = a.status();
    let status_b = b.status();
    assert_eq!(
        status_a["network_id"].as_str(),
        Some(fp_a.as_str()),
        "node A must run the identity the radio-only declaration names"
    );
    assert_eq!(
        status_b["network_id"].as_str(),
        Some(fp_b.as_str()),
        "node B must run the identity the radio-only declaration names"
    );

    // ── 2. Both anchors are enabled, and the pin landed rather than being refused ──
    for node in [&a, &b] {
        let anchors = node.anchors();
        assert_eq!(
            anchors["abos_skywave"]["status"], "online",
            "{}: the ABOS carrier must be armed (GHOST_SKYWAVE=1)",
            node.name
        );
        assert_eq!(
            anchors["abos_skywave"]["carrier_freq_hz"], 5_350_000,
            "{}: the carrier runs on the 60 m NVIS band",
            node.name
        );
        assert_eq!(
            anchors["qel_quantum"]["backend"]["engine"], "quantumnet (simulated)",
            "{}: the QEL anchor must be enabled with its backend selected",
            node.name
        );
        let trace = node.trace();
        assert!(
            trace.contains(PIN_LOG),
            "{}: the radio-only declaration must have been applied, not refused",
            node.name
        );
        assert!(
            !trace.contains("no route pinned"),
            "{}: the declaration was refused — the carrier must be armed before it is applied",
            node.name
        );
    }
    println!("Both anchors are online on both nodes, and both declarations are in force");

    // ── 3. A real session, over IP (the handshake is not what is under test) ──
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let _ = http_json(
            web_a,
            "POST",
            "/api/peers/add",
            Some(&serde_json::json!({ "address": format!("127.0.0.1:{mesh_b}") })),
        );
        if a.sessions() >= 1 && b.sessions() >= 1 {
            break;
        }
        if Instant::now() >= deadline {
            fail_with_logs(&a, &b, "no session formed between the two daemons".into());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    println!("Session established on both nodes");

    // Let the session settle before the baseline is taken: the QEL anchor mixes a
    // key on connect (over the radio, since that is this peer's only route), and a
    // baseline drawn before that would let its shards be mistaken for the frame
    // under test.
    std::thread::sleep(Duration::from_secs(6));

    // ── 4. A -> B over the radio ──
    let (tx_a0, _, bytes_a0) = a.skywave();
    let (_, rx_b0, _) = b.skywave();
    let marker_ab = "nvis-fallback-marker-one";
    a.run(&format!("CHAT {fp_b} {marker_ab}"));

    let expected_ab = format!("[Chat from {}] {marker_ab}", &fp_a[..8]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if b.trace().contains(&expected_ab) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !b.trace().contains(&expected_ab) {
        fail_with_logs(
            &a,
            &b,
            format!("{marker_ab} never arrived at B: the radio did not carry the frame"),
        );
    }

    let (tx_a1, rx_a1, bytes_a1) = a.skywave();
    let (tx_b1, rx_b1, _) = b.skywave();

    // Every RS group is three shards, and the route short-circuits the mesh send —
    // so shards on the carrier is exactly what "the frame crossed the rung" means.
    assert!(
        tx_a1 >= tx_a0 + 3,
        "A transmitted {} skywave frame(s), expected at least 3 for the chat's shards",
        tx_a1 - tx_a0
    );
    assert!(
        bytes_a1 > bytes_a0,
        "the carrier must report the DSP bytes it handled"
    );
    assert!(
        rx_b1 >= rx_b0 + 3,
        "B received {} skywave frame(s), expected at least 3",
        rx_b1 - rx_b0
    );

    assert!(
        count(&a.trace(), SKYWAVE_ROUTE_LOG) >= 3,
        "node A must log the skywave route once per shard it handed to the carrier"
    );
    println!("A -> B crossed the skywave rung: {marker_ab}");

    // ── 5. B -> A, the other direction ──
    let marker_ba = "nvis-fallback-marker-two";
    b.run(&format!("CHAT {fp_a} {marker_ba}"));
    let expected_ba = format!("[Chat from {}] {marker_ba}", &fp_b[..8]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if a.trace().contains(&expected_ba) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !a.trace().contains(&expected_ba) {
        fail_with_logs(
            &a,
            &b,
            format!("{marker_ba} never arrived at A: the return path did not cross the rung"),
        );
    }
    let (_, rx_a2, _) = a.skywave();
    let (tx_b2, _, _) = b.skywave();
    assert!(
        tx_b2 >= tx_b1 + 3,
        "B transmitted {} skywave frame(s) for the reply, expected at least 3",
        tx_b2 - tx_b1
    );
    assert!(
        rx_a2 >= rx_a1 + 3,
        "A received {} skywave frame(s) for the reply, expected at least 3",
        rx_a2 - rx_a1
    );
    assert!(
        count(&b.trace(), SKYWAVE_ROUTE_LOG) >= 3,
        "node B must log the skywave route once per shard of its reply"
    );
    println!("B -> A crossed the skywave rung: {marker_ba}");

    // ── 6. The rungs that were declared out of action were never used ──
    for (node, trace) in [(&a, a.trace()), (&b, b.trace())] {
        assert!(
            !trace.contains(DIRECT_PATH_LOG),
            "{}: a direct path was established — the frame may not have crossed the radio",
            node.name
        );
        assert!(
            !trace.contains(RELAY_FALLBACK_LOG),
            "{}: the ladder fell back to a relay, so the radio is not what carried the frame",
            node.name
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
