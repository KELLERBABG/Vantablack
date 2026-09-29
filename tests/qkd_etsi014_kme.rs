//! The ETSI GS QKD 014 backend, driven against a **mock KME appliance**.
//!
//! The unit tests in `ghost::layers::l10_qel_etsi` pin the pieces — URL
//! normalisation, the path layout, base64, the epoch-key derivation, the
//! origin-form request line. What none of them can catch is the thing an operator
//! actually cares about: that two nodes which each talk to a real appliance come
//! away with the *same* epoch key, over a real socket, using the standard's request
//! and response shapes.
//!
//! So this file runs a small KME: it holds a pool of key material (standing in for
//! what the quantum channel generated), hands a key out on `enc_keys`, and serves
//! the same key back on `dec_keys` when it is named. Two controllers — a "master"
//! SAE and a "slave" SAE, with different SAE IDs, as two sites would be — are then
//! pointed at it, exactly as two daemons configured with the `GHOST_QKD_*`
//! environment would be.
//!
//! # What is deliberately simulated, and what is not
//!
//! Not simulated: the rest of the path. The HTTP/1.1 transport, the URL and request
//! line the client builds, the `key_ID`/`key` envelope, the chunked framing a
//! gateway puts in front of an appliance, the TLS handshake, and mutual certificate
//! authentication — all asserted against a real socket. A mock is the only honest
//! way to test the client at all, because the real counterpart is an appliance with
//! a quantum channel attached. The one thing this cannot show is that the
//! appliance's keys came from photons: that is a claim about *deployment*, and the
//! documentation makes it only about deployment.
//!
//! The mutual-TLS tests are behind `--features qkd-tls`, the build a real
//! deployment needs. Without it the client refuses an `https://` URL instead of
//! sending key material in the clear, which
//! `an_https_url_without_tls_is_refused_instead_of_downgraded` pins.

#![allow(clippy::needless_range_loop)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use vantablack::ghost::layers::l10_qel::{QelAnchorState, QuantumAnchorController};
use vantablack::ghost::layers::l10_qel_etsi::{Etsi014Client, Etsi014Config, Etsi014Error};

// ── The mock appliance ──────────────────────────────────────────────────────

/// What the appliance is holding and what it has served.
struct KmeState {
    /// `(key_ID, material)` still available: the pool the quantum channel filled.
    pool: Vec<(String, Vec<u8>)>,
    /// IDs already handed out by `enc_keys`, which `dec_keys` must serve back. The
    /// standard's whole point: the master consumes, the slave redeems.
    issued: Vec<(String, Vec<u8>)>,
    /// `"{method} {sae}/{op}"` for every request served — the assertions about
    /// *which* SAE a call names read this.
    log: Vec<String>,
    /// Advertised key-size range, so a test can make the appliance refuse the
    /// client's request while remaining reachable.
    min_bits: u32,
    max_bits: u32,
    /// Served in `status` as `source_KME_ID`, so a test can tell two appliances
    /// apart.
    kme_id: String,
    /// Frame `dec_keys` responses as chunked, as a gateway in front of an
    /// appliance does.
    chunk_dec_keys: bool,
}

impl KmeState {
    fn new(n: usize) -> Self {
        let mut s = Self {
            pool: Vec::new(),
            issued: Vec::new(),
            log: Vec::new(),
            min_bits: 64,
            max_bits: 1024,
            kme_id: "kme-mock".to_string(),
            chunk_dec_keys: false,
        };
        for i in 0..n {
            s.pool.push((
                format!("key-{i:04}"),
                (0..32).map(|b| b ^ i as u8).collect(),
            ));
        }
        s
    }
}

struct MockKme {
    addr: SocketAddr,
    state: Arc<Mutex<KmeState>>,
}

impl MockKme {
    /// Start the appliance with `n` 256-bit keys in its pool, over plaintext HTTP
    /// on a loopback port.
    async fn start(n: usize) -> Self {
        Self::start_with(n, |_| {}).await
    }

    async fn start_with(n: usize, tweak: impl FnOnce(&mut KmeState)) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let mut state = KmeState::new(n);
        tweak(&mut state);
        let state = Arc::new(Mutex::new(state));
        spawn_plain(listener, Arc::clone(&state));
        Self { addr, state }
    }

    fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }

    fn pool_len(&self) -> usize {
        self.state.lock().unwrap().pool.len()
    }

    /// Forget every issued ID: the wrong-appliance, rotated-pool case.
    fn forget_issued(&self) {
        self.state.lock().unwrap().issued.clear();
    }
}

fn spawn_plain(listener: TcpListener, state: Arc<Mutex<KmeState>>) {
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Some(resp) = serve(&mut sock, &state).await {
                    let _ = sock.write_all(&resp).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
}

/// Serve one request over any byte stream, plaintext or TLS.
async fn serve<S>(sock: &mut S, state: &Arc<Mutex<KmeState>>) -> Option<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let header_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        let mut chunk = [0u8; 1024];
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let content_length: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut rest = buf[header_end + 4..].to_vec();
    while rest.len() < content_length {
        let mut chunk = [0u8; 1024];
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => rest.extend_from_slice(&chunk[..n]),
        }
    }
    rest.truncate(content_length);

    // Origin-form only: `/api/v1/keys/{sae}/{op}`. An absolute-form line means the
    // client regressed to sending the whole URL, which is exactly the bug this
    // framing catches.
    if target.starts_with("http://") || target.starts_with("https://") {
        return Some(response(
            400,
            "{\"message\":\"absolute-form request target\"}",
            false,
        ));
    }
    let path = target.split('?').next().unwrap_or("");
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (sae, op) = match segs.as_slice() {
        ["api", "v1", "keys", sae, op] => (*sae, *op),
        _ => return Some(response(404, "{\"message\":\"unknown path\"}", false)),
    };
    state
        .lock()
        .unwrap()
        .log
        .push(format!("{method} {sae}/{op}"));

    match (method.as_str(), op) {
        ("GET", "status") => {
            let (min, max, stored, id) = {
                let s = state.lock().unwrap();
                (s.min_bits, s.max_bits, s.pool.len(), s.kme_id.clone())
            };
            let body = format!(
                "{{\"source_KME_ID\":\"{id}\",\"target_KME_ID\":\"{id}\",\
                  \"master_SAE_ID\":\"sae-master\",\"slave_SAE_ID\":\"sae-slave\",\
                  \"key_size\":256,\"stored_key_count\":{stored},\"max_key_count\":100000,\
                  \"max_key_per_request\":128,\"max_key_size\":{max},\"min_key_size\":{min},\
                  \"max_SAE_ID_count\":0}}"
            );
            Some(response(200, &body, false))
        }
        ("GET", "enc_keys") => {
            let taken = {
                let mut s = state.lock().unwrap();
                if s.pool.is_empty() {
                    None
                } else {
                    let k = s.pool.remove(0);
                    s.issued.push(k.clone());
                    Some(k)
                }
            };
            match taken {
                // The standard's answer for an empty pool.
                None => Some(response(503, "{\"message\":\"no keys available\"}", false)),
                Some((id, material)) => Some(key_envelope(&id, &material, false)),
            }
        }
        ("POST", "dec_keys") => {
            let body: serde_json::Value =
                serde_json::from_slice(&rest).unwrap_or(serde_json::Value::Null);
            let wanted = body
                .get("key_IDs")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|e| e.get("key_ID"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let (found, chunked) = {
                let s = state.lock().unwrap();
                (
                    s.issued.iter().find(|(id, _)| *id == wanted).cloned(),
                    s.chunk_dec_keys,
                )
            };
            match found {
                None => Some(response(404, "{\"message\":\"key not found\"}", false)),
                Some((id, material)) => Some(key_envelope(&id, &material, chunked)),
            }
        }
        _ => Some(response(405, "{\"message\":\"not allowed\"}", false)),
    }
}

fn key_envelope(id: &str, material: &[u8], chunked: bool) -> Vec<u8> {
    response(
        200,
        &format!(
            "{{\"keys\":[{{\"key_ID\":\"{id}\",\"key\":\"{}\"}}]}}",
            b64(material)
        ),
        chunked,
    )
}

fn response(status: u16, body: &str, chunked: bool) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    if chunked {
        // One data chunk then the terminator, which is what nginx emits for a
        // small response over HTTP/1.1.
        return format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
        .into_bytes();
    }
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A tiny encoder for the fixture's key material. The client only decodes, so the
/// test supplies the other direction rather than the library growing one.
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ── Two nodes, one appliance ────────────────────────────────────────────────

fn config_for(kme: &MockKme, our_sae: &str, peer_sae: &str) -> Etsi014Config {
    Etsi014Config {
        base_url: format!("http://{}/api/v1/keys", kme.addr),
        our_sae_id: our_sae.into(),
        default_peer_sae_id: Some(peer_sae.into()),
        sae_map: HashMap::new(),
        key_bits: 256,
        timeout: Duration::from_secs(5),
        ca_pem: None,
        client_cert: None,
        client_key: None,
        insecure: false,
    }
}

fn controller(kme: &MockKme, our_sae: &str, peer_sae: &str) -> QuantumAnchorController {
    QuantumAnchorController::with_etsi_client(Etsi014Client::new(config_for(
        kme, our_sae, peer_sae,
    )))
}

fn unreachable_config(addr: SocketAddr) -> Etsi014Config {
    Etsi014Config {
        base_url: format!("http://{addr}/api/v1/keys"),
        our_sae_id: "sae-a".into(),
        default_peer_sae_id: Some("sae-b".into()),
        sae_map: HashMap::new(),
        key_bits: 256,
        timeout: Duration::from_millis(400),
        ca_pem: None,
        client_cert: None,
        client_key: None,
        insecure: false,
    }
}

/// The whole point of the backend, end to end: the master takes a key, the slave
/// gets the *same* key back from the ID alone, and neither one sent it.
#[tokio::test]
async fn both_nodes_derive_one_epoch_key_from_a_key_id() {
    let kme = MockKme::start(4).await;
    // Two sites, two SAE IDs, one appliance — the deployment shape this backend
    // exists for.
    let master = controller(&kme, "sae-a", "sae-b");
    let slave = controller(&kme, "sae-b", "sae-a");

    assert_eq!(master.state().await, QelAnchorState::Available);
    assert_eq!(master.backend_name(), "etsi014");

    let acquired = master
        .acquire_key(Path::new("unused-topology.json"), "fp-a", "fp-b")
        .await;
    let key = acquired.key.expect("the master takes a key");
    let label = acquired.label.expect("and the label naming it");
    assert!(
        acquired.error.is_none(),
        "no error on a served request: {:?}",
        acquired.error
    );

    let redeemed = slave.redeem_key("fp-a", &label).await;
    let same = redeemed.key.expect("the slave redeems the same ID");
    assert_eq!(
        key, same,
        "both sides must hold the same bytes, or the mix would be refused"
    );
    assert_eq!(
        redeemed.label.as_deref(),
        Some(label.as_str()),
        "the label round-trips unchanged"
    );

    assert_eq!(kme.pool_len(), 3, "exactly one key was consumed");
    let log = kme.requests();
    assert!(
        log.contains(&"GET sae-b/enc_keys".to_string()),
        "enc_keys must name the *peer's* SAE: {log:?}"
    );
    assert!(
        log.contains(&"POST sae-a/dec_keys".to_string()),
        "dec_keys must name the *peer's* SAE too: {log:?}"
    );
}

/// A key ID, not key material, is what travels between the nodes — so a second
/// request must never hand out the same key, or two sessions would share one.
#[tokio::test]
async fn each_acquire_consumes_a_different_key() {
    let kme = MockKme::start(3).await;
    let ctrl = controller(&kme, "sae-a", "sae-b");
    let mut seen = Vec::new();
    for peer in ["fp-1", "fp-2", "fp-3"] {
        let o = ctrl
            .acquire_key(Path::new("unused.json"), "fp-us", peer)
            .await;
        seen.push((o.label.expect("a label"), o.key.expect("a key")));
    }
    assert_eq!(kme.pool_len(), 0, "three acquires, three keys consumed");
    for i in 0..seen.len() {
        for j in (i + 1)..seen.len() {
            assert_ne!(seen[i].0, seen[j].0, "labels must be distinct");
            assert_ne!(seen[i].1, seen[j].1, "and so must the material");
        }
    }

    // An exhausted pool is a degraded answer carrying the appliance's own reason,
    // not a panic and not a fabricated key.
    let empty = ctrl
        .acquire_key(Path::new("unused.json"), "fp-us", "fp-4")
        .await;
    assert!(empty.key.is_none());
    let err = empty.error.expect("a reason");
    assert!(err.contains("503"), "the status must be reported: {err}");
    assert!(
        err.contains("no keys available"),
        "and so must the appliance's own message: {err}"
    );
}

/// The status document's size range is the appliance's word about what it can
/// serve. A mismatch is a configuration problem an operator can fix, so it is
/// reported as `Degraded` — reachable and refusing — rather than as unreachable.
#[tokio::test]
async fn an_appliance_that_cannot_serve_our_key_size_is_degraded() {
    let kme = MockKme::start_with(4, |s| s.max_bits = 128).await;
    let ctrl = controller(&kme, "sae-a", "sae-b");
    assert_eq!(
        ctrl.state().await,
        QelAnchorState::Degraded,
        "asking 256 bits of a pool that caps at 128 is the operator's to fix"
    );
    let report = ctrl.backend_report();
    assert_eq!(report["name"], "etsi014");
    assert_eq!(report["last_status"]["max_key_size"], 128);
    assert_eq!(report["key_bits"], 256);
    assert_eq!(report["sae_id"], "sae-a");
    assert_eq!(report["engine"], "ETSI GS QKD 014 key delivery");
}

/// Nothing answering: the appliance is down, which no node-side action fixes. A
/// firewall that silently drops the packets is the same situation, which is why a
/// connect that never completes is classified as unreachable rather than as a
/// timeout.
#[tokio::test]
async fn an_unreachable_appliance_is_unavailable() {
    // TEST-NET-1 (RFC 5737): guaranteed not to be a real reachable host, so this
    // cannot be answered by another test's listener on a reused loopback port.
    let dead: SocketAddr = "192.0.2.1:8443".parse().unwrap();
    let ctrl =
        QuantumAnchorController::with_etsi_client(Etsi014Client::new(unreachable_config(dead)));
    assert_eq!(ctrl.state().await, QelAnchorState::Unavailable);
    let outcome = ctrl
        .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
        .await;
    assert!(outcome.key.is_none());
    assert!(outcome.label.is_none());
    assert_eq!(outcome.anchor_state, QelAnchorState::Unavailable);
    assert!(
        outcome.error.as_deref().unwrap().contains("192.0.2.1"),
        "the reason must name the appliance that did not answer: {:?}",
        outcome.error
    );
}

/// The appliance has no key pool for a peer we cannot name. That is a missing
/// mapping, not a fault, and — importantly — the client must not guess an SAE ID
/// and address some other peer's pool.
#[tokio::test]
async fn a_peer_with_no_sae_mapping_is_refused_without_touching_the_appliance() {
    let kme = MockKme::start(2).await;
    let mut cfg = config_for(&kme, "sae-a", "sae-b");
    cfg.default_peer_sae_id = None;
    let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));

    let outcome = ctrl
        .acquire_key(Path::new("unused.json"), "fp-a", "fp-unknown")
        .await;
    assert!(outcome.key.is_none());
    let err = outcome.error.expect("a reason");
    assert!(
        err.contains("SAE ID") || err.contains("GHOST_QKD_PEER_SAE_ID"),
        "the reason must name what is missing: {err}"
    );
    assert!(
        kme.requests().is_empty(),
        "no request may be sent for an unnameable peer: {:?}",
        kme.requests()
    );
    assert_eq!(
        kme.pool_len(),
        2,
        "and no key may be consumed while finding that out"
    );
}

/// A refusal from the appliance is surfaced with its status and its own words.
#[tokio::test]
async fn an_unknown_key_id_is_a_readable_refusal() {
    let kme = MockKme::start(2).await;
    let ctrl = controller(&kme, "sae-b", "sae-a");
    let outcome = ctrl.redeem_key("fp-a", "not-a-real-key-id").await;
    assert!(outcome.key.is_none());
    let err = outcome.error.expect("a reason");
    assert!(err.contains("404"), "{err}");
    assert!(err.contains("key not found"), "{err}");
    // Refused, but reachable — the appliance answered us.
    assert_eq!(outcome.anchor_state, QelAnchorState::Degraded);
}

/// A key ID from an appliance that does not hold it: the pool was rotated, the two
/// nodes point at different KMEs, or a replayed PDU names a key that is gone. The
/// answer must be an error, never a substitute key.
#[tokio::test]
async fn an_id_the_appliance_never_issued_is_not_substituted() {
    let kme = MockKme::start(2).await;
    let master = controller(&kme, "sae-a", "sae-b");
    let acquired = master
        .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
        .await;
    let label = acquired.label.expect("a label");

    kme.forget_issued();
    let slave = controller(&kme, "sae-b", "sae-a");
    let redeemed = slave.redeem_key("fp-a", &label).await;
    assert!(
        redeemed.key.is_none(),
        "an appliance that has forgotten the ID must refuse, not invent a key"
    );
    assert!(redeemed.error.as_deref().is_some_and(|e| e.contains("404")));
}

/// A response the appliance frames as chunked — which is what any KME behind a
/// gateway does — must decode the same as a `Content-Length` one.
#[tokio::test]
async fn a_chunked_key_response_is_decoded() {
    let kme = MockKme::start_with(2, |s| s.chunk_dec_keys = true).await;
    let master = controller(&kme, "sae-a", "sae-b");
    let acquired = master
        .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
        .await;
    let key = acquired.key.expect("a key");
    let label = acquired.label.expect("a label");

    let slave = controller(&kme, "sae-b", "sae-a");
    let redeemed = slave.redeem_key("fp-a", &label).await;
    assert_eq!(
        redeemed.key,
        Some(key),
        "the chunked framing must be transparent to the caller"
    );
}

/// Two different peers must be addressable on one appliance: the map, not the
/// single default, picks the pool.
#[tokio::test]
async fn a_peer_map_addresses_a_pool_per_peer() {
    let kme = MockKme::start(2).await;
    let mut cfg = config_for(&kme, "sae-a", "sae-b");
    cfg.default_peer_sae_id = None;
    cfg.sae_map.insert("fp-alpha".into(), "sae-alpha".into());
    cfg.sae_map.insert("fp-beta".into(), "sae-beta".into());
    let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));

    assert!(ctrl
        .acquire_key(Path::new("unused.json"), "fp-us", "fp-alpha")
        .await
        .key
        .is_some());
    assert!(ctrl
        .acquire_key(Path::new("unused.json"), "fp-us", "fp-beta")
        .await
        .key
        .is_some());
    let log = kme.requests();
    assert!(
        log.contains(&"GET sae-alpha/enc_keys".to_string()),
        "{log:?}"
    );
    assert!(
        log.contains(&"GET sae-beta/enc_keys".to_string()),
        "{log:?}"
    );
}

/// Without `qkd-tls`, an `https://` appliance is refused outright.
///
/// The worst possible failure mode for this layer is quietly delivering key
/// material in the clear, so the refusal is asserted rather than assumed — and the
/// pool is checked to prove no key was spent reaching the conclusion.
#[cfg(not(feature = "qkd-tls"))]
#[tokio::test]
async fn an_https_url_without_tls_is_refused_instead_of_downgraded() {
    let kme = MockKme::start(1).await;
    let mut cfg = config_for(&kme, "sae-a", "sae-b");
    // Same address, https scheme: reachable, but no TLS stack in this build.
    cfg.base_url = cfg.base_url.replace("http://", "https://");
    let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));
    let outcome = ctrl
        .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
        .await;
    assert!(outcome.key.is_none(), "no key may arrive over plaintext");
    let err = outcome.error.expect("a reason");
    assert!(
        err.contains("qkd-tls"),
        "the reason must name the feature to rebuild with: {err}"
    );
    assert_eq!(outcome.anchor_state, QelAnchorState::Unavailable);
    assert_eq!(
        kme.pool_len(),
        1,
        "and the plaintext pool was never touched"
    );
}

// ── Transport security (qkd-tls) ────────────────────────────────────────────

#[cfg(feature = "qkd-tls")]
mod tls {
    use super::*;
    use std::sync::Arc;

    use tokio_rustls::rustls;

    /// A CA, an appliance certificate signed by it, and a client certificate
    /// signed by the same CA — the layout a real QKD deployment has.
    struct Pki {
        dir: std::path::PathBuf,
        ca_pem: std::path::PathBuf,
        /// A *second* CA that did not sign the appliance, so the client can be
        /// pointed at the wrong trust anchor and must refuse.
        other_ca_pem: std::path::PathBuf,
        leaf_der: Vec<u8>,
        leaf_key_pem: std::path::PathBuf,
        client_cert_pem: std::path::PathBuf,
        client_key_pem: std::path::PathBuf,
    }

    impl Pki {
        fn generate() -> Self {
            // Unique *per instance*, not per process: these tests share a process
            // and run concurrently, so a process-wide name would let one test's
            // cleanup delete the PEMs another is halfway through reading.
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "vanta_kme_pki_{}_{}",
                std::process::id(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("pki dir");
            let write = |name: &str, body: &str| {
                let p = dir.join(name);
                std::fs::write(&p, body).expect("write pem");
                p
            };

            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "vantablack test KME CA");
            let ca = ca_params.self_signed(&ca_key).unwrap();

            let other_ca_key = rcgen::KeyPair::generate().unwrap();
            let mut other_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            other_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "some other CA");
            let other_ca = other_params.self_signed(&other_ca_key).unwrap();

            // The SAN must cover the name the client dials, or verification fails
            // for a reason that has nothing to do with what the test checks.
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let mut leaf_params =
                rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            leaf_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "kme.site-a.example");
            let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

            let client_key = rcgen::KeyPair::generate().unwrap();
            let mut client_params =
                rcgen::CertificateParams::new(vec!["sae-a".to_string()]).unwrap();
            client_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "sae-a");
            let client = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();

            Pki {
                ca_pem: write("ca.pem", &ca.pem()),
                other_ca_pem: write("other_ca.pem", &other_ca.pem()),
                client_cert_pem: write("client.pem", &client.pem()),
                client_key_pem: write("client.key", &client_key.serialize_pem()),
                leaf_key_pem: write("kme.key", &leaf_key.serialize_pem()),
                leaf_der: leaf.der().to_vec(),
                dir,
            }
        }

        /// A server config that requires and verifies a client certificate, which
        /// is what an ETSI-compliant appliance does.
        fn server_config(&self, require_client_cert: bool) -> Arc<rustls::ServerConfig> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let certs = vec![rustls::pki_types::CertificateDer::from(
                self.leaf_der.clone(),
            )];
            let key = {
                let pem = std::fs::read(&self.leaf_key_pem).expect("read the leaf key");
                let mut reader = std::io::BufReader::new(&pem[..]);
                rustls_pemfile::private_key(&mut reader)
                    .expect("parse the leaf key")
                    .expect("a private key")
            };
            let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap();
            let config = if require_client_cert {
                let mut roots = rustls::RootCertStore::empty();
                let pem = std::fs::read(&self.ca_pem).unwrap();
                let mut reader = std::io::BufReader::new(&pem[..]);
                for c in rustls_pemfile::certs(&mut reader) {
                    roots.add(c.unwrap()).unwrap();
                }
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap();
                builder
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .unwrap()
            } else {
                builder
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap()
            };
            Arc::new(config)
        }
    }

    impl Drop for Pki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The mock appliance again, over TLS, reusing the same request handling.
    async fn start_tls(pki: &Pki, require_client_cert: bool, keys: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();
        let mut state = KmeState::new(keys);
        state.kme_id = "kme-tls".to_string();
        let state = Arc::new(Mutex::new(state));
        let acceptor = tokio_rustls::TlsAcceptor::from(pki.server_config(require_client_cert));
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    // A rejected handshake is the expected outcome in the negative
                    // tests: the connection ends there, and no key is served.
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    if let Some(resp) = serve(&mut tls, &state).await {
                        let _ = tls.write_all(&resp).await;
                    }
                    let _ = tls.shutdown().await;
                });
            }
        });
        addr
    }

    fn tls_config(pki: &Pki, addr: SocketAddr, with_client_cert: bool) -> Etsi014Config {
        Etsi014Config {
            base_url: format!("https://localhost:{}/api/v1/keys", addr.port()),
            our_sae_id: "sae-a".into(),
            default_peer_sae_id: Some("sae-b".into()),
            sae_map: HashMap::new(),
            key_bits: 256,
            timeout: Duration::from_secs(10),
            ca_pem: Some(pki.ca_pem.clone()),
            client_cert: with_client_cert.then(|| pki.client_cert_pem.clone()),
            client_key: with_client_cert.then(|| pki.client_key_pem.clone()),
            insecure: false,
        }
    }

    /// The standard's deployment shape: HTTPS, the appliance's certificate
    /// verified against the private CA, and a client certificate for mutual
    /// authentication. The key still arrives.
    #[tokio::test]
    async fn a_mutual_tls_appliance_delivers_a_key() {
        let pki = Pki::generate();
        let addr = start_tls(&pki, true, 1).await;
        let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(tls_config(
            &pki, addr, true,
        )));
        assert_eq!(ctrl.state().await, QelAnchorState::Available);
        let outcome = ctrl
            .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
            .await;
        assert!(
            outcome.key.is_some(),
            "a verified mutual-TLS appliance must deliver: {:?}",
            outcome.error
        );
        assert_eq!(outcome.label.as_deref(), Some("key-0000"));
    }

    /// Mutual authentication is the appliance's requirement, and this client
    /// cannot satisfy it without a certificate. The failure must be reported, not
    /// worked around by disabling verification.
    #[tokio::test]
    async fn an_appliance_that_requires_a_client_certificate_refuses_one_without_it() {
        let pki = Pki::generate();
        let addr = start_tls(&pki, true, 1).await;
        let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(tls_config(
            &pki, addr, false,
        )));
        let outcome = ctrl
            .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
            .await;
        assert!(
            outcome.key.is_none(),
            "no key may arrive on a handshake the appliance refused"
        );
        assert!(outcome.error.is_some(), "and the refusal is reported");
    }

    /// A certificate signed by a CA we do not trust must be refused. This is the
    /// test that would fail if the client ever grew a silent "accept anything"
    /// path — which is why `GHOST_QKD_INSECURE` is an explicit, logged,
    /// control-plane-visible setting rather than a default.
    #[tokio::test]
    async fn a_certificate_from_an_untrusted_ca_is_refused() {
        let pki = Pki::generate();
        let addr = start_tls(&pki, false, 1).await;
        let mut cfg = tls_config(&pki, addr, false);
        cfg.ca_pem = Some(pki.other_ca_pem.clone());
        let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));
        let outcome = ctrl
            .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
            .await;
        assert!(
            outcome.key.is_none(),
            "an untrusted chain must not deliver key material"
        );
        assert_eq!(
            outcome.anchor_state,
            QelAnchorState::Unavailable,
            "a TLS failure is unreachable-from-here, not a fixable misconfiguration"
        );
    }

    /// `GHOST_QKD_INSECURE` is the lab escape hatch. It is exercised here so the
    /// code path is known to work, and asserted to be *reported* so it can never be
    /// enabled unnoticed.
    #[tokio::test]
    async fn the_insecure_flag_works_and_says_so_in_the_report() {
        let pki = Pki::generate();
        let addr = start_tls(&pki, false, 1).await;
        let mut cfg = tls_config(&pki, addr, false);
        cfg.ca_pem = Some(pki.other_ca_pem.clone());
        cfg.insecure = true;
        let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));
        assert!(
            ctrl.acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
                .await
                .key
                .is_some(),
            "with verification explicitly off, the key arrives"
        );
        let report = ctrl.backend_report();
        assert!(
            report["certificate_verification"]
                .as_str()
                .unwrap()
                .contains("disabled"),
            "the status document must admit this: {report}"
        );
        assert_eq!(report["tls"], true);
        assert_eq!(report["client_certificate"], serde_json::Value::Null);
    }

    /// The report is fetched over loopback HTTP by anything that can reach the
    /// control port, so it must not carry key material or a token.
    #[tokio::test]
    async fn the_backend_report_carries_no_secrets() {
        let pki = Pki::generate();
        let addr = start_tls(&pki, false, 1).await;
        let mut cfg = tls_config(&pki, addr, false);
        cfg.sae_map
            .insert("fp-a".to_string(), "sae-slave".to_string());
        let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));
        let _ = ctrl.probe().await;
        let report = ctrl.backend_report();
        let text = report.to_string();
        assert!(text.contains("localhost"), "the URL is reported: {text}");
        assert!(text.contains("sae-a"), "and the SAE ID: {text}");
        assert!(
            !text.contains("PRIVATE KEY"),
            "no key material may appear: {text}"
        );
        assert!(
            !text.to_lowercase().contains("\"key\""),
            "and no single-key field either: {text}"
        );
        assert_eq!(report["peer_sae_map"], 1);
    }

    /// An appliance asked for and not configured must not become a simulation: the
    /// two make different claims about the entropy a session then mixes in.
    #[tokio::test]
    async fn a_missing_kme_url_is_misconfigured_not_a_simulator() {
        // This test binary is a separate process from the lib's own tests, so the
        // process-wide environment cannot race with them. Stated rather than
        // assumed, because both would otherwise touch the same variables.
        let previous_url = std::env::var(vantablack::ghost::layers::l10_qel_etsi::ENV_KME_URL).ok();
        std::env::set_var(
            vantablack::ghost::layers::l10_qel_etsi::ENV_BACKEND,
            "etsi014",
        );
        std::env::remove_var(vantablack::ghost::layers::l10_qel_etsi::ENV_KME_URL);
        let ctrl = QuantumAnchorController::from_env();
        assert_eq!(
            ctrl.backend_name(),
            "misconfigured",
            "an appliance asked for and not configured must not become a simulation"
        );
        let outcome = ctrl
            .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
            .await;
        assert!(outcome.key.is_none());
        assert!(outcome
            .error
            .as_deref()
            .unwrap()
            .contains("GHOST_QKD_KME_URL"));
        if let Some(v) = previous_url {
            std::env::set_var(vantablack::ghost::layers::l10_qel_etsi::ENV_KME_URL, v);
        }
        std::env::remove_var(vantablack::ghost::layers::l10_qel_etsi::ENV_BACKEND);
    }

    /// The client never retries `enc_keys`. A retry after a timeout silently burns
    /// a key the appliance may never reproduce and orphans the ID the peer is
    /// trying to redeem — so the timeout must *say* that rather than look like a
    /// clean failure.
    #[tokio::test]
    async fn a_timed_out_key_request_warns_that_a_key_may_have_been_consumed() {
        // A server that accepts and then says nothing: the client's own response
        // timeout is the only way out, and it cannot know whether the appliance
        // took the key.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock); // never answer
            }
        });
        let mut cfg = unreachable_config(addr);
        cfg.timeout = Duration::from_millis(400);
        let ctrl = QuantumAnchorController::with_etsi_client(Etsi014Client::new(cfg));
        let outcome = ctrl
            .acquire_key(Path::new("unused.json"), "fp-a", "fp-b")
            .await;
        assert!(outcome.key.is_none());
        let err = outcome.error.expect("a reason");
        assert!(
            err.contains("consumed"),
            "a timed-out enc_keys must not read as a clean failure: {err}"
        );
    }
}

// ── The taxonomy the controller maps onto anchor states ─────────────────────

/// Pinned here because the mapping is the whole difference between "the appliance
/// is down" and "your configuration is wrong", and an operator has to be able to
/// tell those apart from the control plane alone.
#[test]
fn the_error_taxonomy_splits_unreachable_from_refused() {
    assert!(Etsi014Error::Transport("x".into()).is_transport());
    assert!(Etsi014Error::TlsNotCompiled.is_transport());
    assert!(!Etsi014Error::Http {
        status: 404,
        message: "no".into()
    }
    .is_transport());
    assert!(!Etsi014Error::Config("bad".into()).is_transport());
    assert!(Etsi014Error::NoPeerSaeId {
        peer: "p".into(),
        env: "E"
    }
    .is_config());
}

/// A build without `qkd-tls` must still understand the scheme it was given, so the
/// refusal names the real problem rather than a parse failure.
#[test]
fn an_https_url_parses_even_without_the_tls_feature() {
    let mut cfg = Etsi014Config {
        base_url: "https://kme.example:8443/api/v1/keys".into(),
        our_sae_id: "sae-a".into(),
        default_peer_sae_id: Some("sae-b".into()),
        sae_map: HashMap::new(),
        key_bits: 256,
        timeout: Duration::from_secs(5),
        ca_pem: None,
        client_cert: None,
        client_key: None,
        insecure: false,
    };
    assert!(cfg.is_https());
    assert_eq!(cfg.authority(), "kme.example:8443");
    cfg.base_url = "http://kme.example:8080/api/v1/keys".into();
    assert!(!cfg.is_https());
}
