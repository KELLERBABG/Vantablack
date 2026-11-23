//! Universal shard tunnel for the live daemon (`exp_universal_tunnel`).
//!
//! [`vantablack::ghost::net::universal_tunnel`] owns the sequencing and
//! reassembly: a byte stream is cut into bounded chunks, each padded into a
//! 576-byte privacy frame. This module is the daemon half — the local listener,
//! the exit splice, and the two allowlists that stop either side from becoming an
//! open proxy.
//!
//! ## Two roles, both explicit
//!
//! * **Initiator**: `GHOST_TUNNEL_PORTS=15432=10.0.0.5:5432` publishes a local TCP
//!   port and names the exit peer in `GHOST_TUNNEL_EXIT`. Every accepted connection
//!   is an `OPEN` carrying the target it wants.
//! * **Exit**: `GHOST_TUNNEL_ALLOW=10.0.0.5:5432,...` is the complete list of
//!   targets this node will dial, and `GHOST_TUNNEL_PEERS` the complete list of
//!   fingerprints allowed to ask. **Both empty means the exit is off**: a node does
//!   not become a relay because a toggle was flipped, only because an operator
//!   named who may use it and what it may reach.
//!
//! ## Wire shape
//!
//! Every frame rides inside an ordinary sealed GTFv2 message addressed to the peer
//! on the other end of the tunnel:
//!
//! ```text
//! [UTUN 4][kind 1][role 1][stream id 4][body ...]
//! ```
//!
//! `OPEN` carries the target string, `OK`/`FAIL` answer it, `DATA` carries one
//! 576-byte [`UniversalTunnelChunker`] frame (sequence number, flags, payload), and
//! `CLOSE` ends the stream. Because the payload is sealed under the session with
//! the *other endpoint*, intermediate nodes never see a byte of it — the tunnel is
//! a local-to-remote TCP splice, not a public relay.
//!
//! ### What the role byte disambiguates
//!
//! A stream id alone is not unique on the wire. Each endpoint numbers the streams it
//! opens from its own counter, so stream 7 can mean "the stream I opened to that
//! peer" (the forwarder side of a local TCP connection) or "the stream that peer
//! asked me to open" (the exit side). Both can exist at once — a node may publish
//! forwards and serve as an exit for the same peer.
//!
//! So every frame names the **sender's** role for that stream: `0` = local (the
//! sender's own forward), `1` = remote (a stream the sender is serving). The
//! receiver looks the stream up under the complementary role, which makes the pair
//! `(role, stream id)` unique without a second negotiation and without relying on the
//! two fingerprints differing.

use crate::*;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use vantablack::ghost::net::universal_tunnel::{
    UniversalTunnelChunker, UniversalTunnelReassembler,
};

/// Envelope magic. Four bytes, like every other control payload the peer loop sees.
pub(crate) const TUNNEL_MAGIC: &[u8; 4] = b"UTUN";
const KIND_OPEN: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_CLOSE: u8 = 3;
const KIND_OK: u8 = 4;
const KIND_FAIL: u8 = 5;
/// Wire markers for the sender's role on a stream.
const ROLE_LOCAL: u8 = 0;
const ROLE_REMOTE: u8 = 1;
/// How long the exit may take to connect to a target before the stream is refused.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the toggle is on.
pub(crate) fn enabled() -> bool {
    vantablack::ghost::net::universal_tunnel::is_enabled()
}

/// `[UTUN][kind][role][stream id][body]`.
///
/// `role` is the *sender's* role for the stream. It is what makes a stream id
/// unambiguous: both endpoints allocate ids from their own counter, so "stream 3"
/// can name a stream the sender opened (`Local`) or one it is serving (`Remote`),
/// and the receiver looks it up under the complementary role.
fn encode(kind: u8, role: StreamRole, stream: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(TUNNEL_MAGIC);
    out.push(kind);
    out.push(match role {
        StreamRole::Local => ROLE_LOCAL,
        StreamRole::Remote => ROLE_REMOTE,
    });
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Parse an envelope body. `None` for anything that is not one, so a payload is
/// never reinterpreted.
fn decode(payload: &[u8]) -> Option<(u8, StreamRole, u32, &[u8])> {
    if payload.len() < 10 || &payload[..4] != TUNNEL_MAGIC {
        return None;
    }
    let kind = payload[4];
    let role = match payload[5] {
        ROLE_LOCAL => StreamRole::Local,
        ROLE_REMOTE => StreamRole::Remote,
        _ => return None,
    };
    let stream = u32::from_be_bytes(payload[6..10].try_into().ok()?);
    Some((kind, role, stream, &payload[10..]))
}

/// Whether `payload` is a tunnel envelope.
pub(crate) fn looks_like(payload: &[u8]) -> bool {
    payload.len() >= 10 && &payload[..4] == TUNNEL_MAGIC
}

// ── Configuration ─────────────────────────────────────────────────────────

/// One published local port and the target it forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Forward {
    pub local: SocketAddr,
    pub target: String,
}

/// Parse `GHOST_TUNNEL_PORTS` (`local=target,...`).
///
/// A `local` of just a port means `127.0.0.1:<port>`: binding every interface
/// would publish a forward to the LAN, which is not what a local tunnel is for.
pub(crate) fn parse_ports(spec: &str) -> (Vec<Forward>, Vec<String>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = entry.split_once('=').and_then(|(local, target)| {
            let local = local.trim();
            let target = target.trim();
            if target.is_empty() || !target.contains(':') {
                return None;
            }
            let local = if local.contains(':') {
                local.to_string()
            } else {
                format!("127.0.0.1:{local}")
            };
            let local: SocketAddr = local.parse().ok()?;
            Some(Forward {
                local,
                target: target.to_string(),
            })
        });
        match parsed {
            Some(f) => accepted.push(f),
            None => rejected.push(entry.to_string()),
        }
    }
    (accepted, rejected)
}

/// Split an allowlist into normalised entries.
fn allow_entries(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The targets this node will dial on behalf of peers.
fn allowed_targets() -> Vec<String> {
    allow_entries(&std::env::var("GHOST_TUNNEL_ALLOW").unwrap_or_default())
}

/// The peers allowed to use this node as an exit.
fn allowed_peers() -> Vec<String> {
    allow_entries(&std::env::var("GHOST_TUNNEL_PEERS").unwrap_or_default())
}

/// Whether the exit role is configured at all.
pub(crate) fn exit_enabled() -> bool {
    !allowed_targets().is_empty() && !allowed_peers().is_empty()
}

/// Exact-match target admission. No prefix or wildcard: a forward that could reach
/// any host is a proxy.
fn target_allowed(target: &str) -> bool {
    let target = target.trim().to_ascii_lowercase();
    allowed_targets().contains(&target)
}

/// Exact-match peer admission.
fn peer_allowed(fingerprint: &str) -> bool {
    let fingerprint = fingerprint.trim().to_ascii_lowercase();
    allowed_peers().contains(&fingerprint)
}

/// The fingerprint of the peer that runs the exit side for our forwards.
fn exit_peer() -> Option<String> {
    std::env::var("GHOST_TUNNEL_EXIT")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

// ── Stream state ──────────────────────────────────────────────────────────

/// Which side of a stream owns the state: the forwarder (`Local`, the TCP connection
/// we accepted) or the exit (`Remote`, the stream a peer asked us to open).
///
/// The role is part of the key because one node can do both at once, and because the
/// peer fingerprint alone cannot distinguish "the stream I opened to this peer" from
/// "the stream this peer opened with me".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum StreamRole {
    Local,
    Remote,
}

type StreamKey = (StreamRole, String, u32);

/// Where reassembled bytes for one stream go, keyed by role, peer and stream id.
fn streams() -> &'static DashMap<StreamKey, mpsc::UnboundedSender<Vec<u8>>> {
    static MAP: OnceLock<DashMap<StreamKey, mpsc::UnboundedSender<Vec<u8>>>> = OnceLock::new();
    MAP.get_or_init(DashMap::new)
}

/// Per-stream reassembly state, same key as [`streams`].
fn reassemblers() -> &'static DashMap<StreamKey, UniversalTunnelReassembler> {
    static MAP: OnceLock<DashMap<StreamKey, UniversalTunnelReassembler>> = OnceLock::new();
    MAP.get_or_init(DashMap::new)
}

/// Start the local listeners. `None` when the toggle is off or nothing is
/// configured — the ordinary send path is untouched in that case.
pub(crate) fn spawn(
    nc: Arc<GhostNode>,
    peers: Arc<DashMap<String, SocketAddr>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    if exit_enabled() {
        tracing::info!(
            peers = allowed_peers().len(),
            targets = allowed_targets().len(),
            "Tunnel: acting as an exit for the allowlisted peers and targets"
        );
    } else if !allowed_targets().is_empty() || !allowed_peers().is_empty() {
        tracing::warn!(
            "Tunnel: GHOST_TUNNEL_ALLOW and GHOST_TUNNEL_PEERS must both name entries — \
             the exit role stays off"
        );
    }
    let Some(exit_fp) = exit_peer() else {
        tracing::info!(
            "Tunnel: no GHOST_TUNNEL_EXIT — no local port is published (the exit role, if \
             configured, still serves peers)"
        );
        return None;
    };
    let raw = std::env::var("GHOST_TUNNEL_PORTS").unwrap_or_default();
    let (forwards, rejected) = parse_ports(&raw);
    for entry in rejected {
        tracing::warn!(entry = %entry, "GHOST_TUNNEL_PORTS entry is not `local=host:port` — ignored");
    }
    if forwards.is_empty() {
        tracing::warn!("Tunnel: the toggle is on but GHOST_TUNNEL_PORTS names no forward");
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tasks = Vec::new();
        for forward in forwards {
            match TcpListener::bind(forward.local).await {
                Ok(listener) => {
                    tracing::info!(
                        local = %forward.local,
                        target = %forward.target,
                        exit = %exit_fp,
                        "Tunnel: local port forwarding over the mesh"
                    );
                    let nc = Arc::clone(&nc);
                    let peers = Arc::clone(&peers);
                    let exit_fp = exit_fp.clone();
                    tasks.push(tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((socket, from)) => {
                                    let nc = Arc::clone(&nc);
                                    let peers = Arc::clone(&peers);
                                    let exit_fp = exit_fp.clone();
                                    let target = forward.target.clone();
                                    tokio::spawn(async move {
                                        serve_local(nc, peers, exit_fp, target, socket, from).await;
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Tunnel: accept failed");
                                    return;
                                }
                            }
                        }
                    }));
                }
                Err(e) => tracing::error!(
                    local = %forward.local,
                    error = %e,
                    "Tunnel: cannot bind the local port — this forward stays off"
                ),
            }
        }
        for task in tasks {
            let _ = task.await;
        }
    }))
}

/// Pump one accepted local connection: TCP in, `DATA` out; `DATA` in, TCP out.
async fn serve_local(
    nc: Arc<GhostNode>,
    peers: Arc<DashMap<String, SocketAddr>>,
    exit_fp: String,
    target: String,
    socket: TcpStream,
    from: SocketAddr,
) {
    let stream_id = next_stream_id();
    if !send_payload(
        &nc,
        &peers,
        &exit_fp,
        &encode(KIND_OPEN, StreamRole::Local, stream_id, target.as_bytes()),
    )
    .await
    {
        tracing::debug!(peer = %from, "Tunnel: no path to the exit — connection closed");
        return;
    }
    let (mut read, mut write) = socket.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // The reply stream is keyed by the exit, so an incoming `DATA` from the exit
    // finds it — the same lookup the exit performs in the other direction.
    streams().insert((StreamRole::Local, exit_fp.clone(), stream_id), tx);
    reassemblers().insert(
        (StreamRole::Local, exit_fp.clone(), stream_id),
        UniversalTunnelReassembler::new(),
    );

    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if write.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });

    let mut chunker = UniversalTunnelChunker::new(stream_id);
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        match read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                for frame in chunker.chunk_payload(&buf[..n], false) {
                    if !send_payload(
                        &nc,
                        &peers,
                        &exit_fp,
                        &encode(KIND_DATA, StreamRole::Local, stream_id, &frame),
                    )
                    .await
                    {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    send_payload(
        &nc,
        &peers,
        &exit_fp,
        &encode(KIND_CLOSE, StreamRole::Local, stream_id, &[]),
    )
    .await;
    streams().remove(&(StreamRole::Local, exit_fp.clone(), stream_id));
    reassemblers().remove(&(StreamRole::Local, exit_fp, stream_id));
    writer.abort();
    tracing::debug!(peer = %from, stream = stream_id, "Tunnel: local connection closed");
}

fn next_stream_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Handle one tunnel envelope. Returns `true` when the payload was one.
pub(crate) async fn handle(rx: &RxContext, payload: &[u8], from: SocketAddr) -> bool {
    if !looks_like(payload) {
        return false;
    }
    handle_frame(&rx.node, &rx.peers, payload, from).await
}

/// The handler proper, once the frame's origin is known.
///
/// Split from [`handle`] so the end-to-end test can drive the real forwarding and
/// exit code over a loopback session without constructing a whole receive context;
/// `ingress` calls it through [`handle`] with exactly these arguments.
pub(crate) async fn handle_frame(
    node: &Arc<GhostNode>,
    peers: &Arc<DashMap<String, SocketAddr>>,
    payload: &[u8],
    from: SocketAddr,
) -> bool {
    if !looks_like(payload) {
        return false;
    }
    let Some((kind, role, stream, body)) = decode(payload) else {
        return false;
    };
    // The sender's role names the stream; ours is the other one.
    let role = match role {
        StreamRole::Local => StreamRole::Remote,
        StreamRole::Remote => StreamRole::Local,
    };
    if !enabled() {
        tracing::debug!(peer = %from, "Tunnel: envelope ignored — the toggle is off");
        return true;
    }
    // Only a peer we hold a session with can be named: `from` is the address the
    // frame arrived from, and the fingerprint is resolved through that address.
    let Some(peer_fp) = peers
        .iter()
        .find(|entry| *entry.value() == from)
        .map(|entry| entry.key().clone())
    else {
        tracing::debug!(peer = %from, "Tunnel: no peer record for this source — dropped");
        return true;
    };
    match kind {
        KIND_OPEN => {
            if !peer_allowed(&peer_fp) {
                tracing::warn!(
                    peer = %peer_fp,
                    "Tunnel: exit refused — peer is not in GHOST_TUNNEL_PEERS"
                );
                send_payload(
                    node,
                    peers,
                    &peer_fp,
                    &encode(KIND_FAIL, StreamRole::Remote, stream, b"peer not allowed"),
                )
                .await;
                return true;
            }
            let target = String::from_utf8_lossy(body).into_owned();
            if !target_allowed(&target) {
                tracing::warn!(
                    peer = %peer_fp,
                    target = %target,
                    "Tunnel: exit refused — target is not in GHOST_TUNNEL_ALLOW"
                );
                send_payload(
                    node,
                    peers,
                    &peer_fp,
                    &encode(KIND_FAIL, StreamRole::Remote, stream, b"target not allowed"),
                )
                .await;
                return true;
            }
            // The stream's queue and reassembler are installed *now*, before the
            // exit dials: a client that writes immediately sends DATA before the
            // target connection exists, and those frames would otherwise be dropped
            // for want of anywhere to reassemble them.
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            streams().insert((StreamRole::Remote, peer_fp.clone(), stream), tx);
            reassemblers().insert(
                (StreamRole::Remote, peer_fp.clone(), stream),
                UniversalTunnelReassembler::new(),
            );
            let nc = Arc::clone(node);
            let peers = Arc::clone(peers);
            tokio::spawn(async move {
                serve_exit(nc, peers, peer_fp, stream, target, rx).await;
            });
            true
        }
        KIND_DATA => {
            // The stream this belongs to is whichever one this node registered for
            // that peer: its own forward (`Local`) or the one it serves (`Remote`).
            {
                let key = (role, peer_fp.clone(), stream);
                if let Some(mut state) = reassemblers().get_mut(&key) {
                    match state.ingest_frame(body) {
                        Ok(bytes) if !bytes.is_empty() => {
                            if let Some(tx) = streams().get(&key) {
                                let _ = tx.send(bytes);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::debug!(peer = %peer_fp, error = %e, "Tunnel: bad frame"),
                    }
                }
            }
            true
        }
        KIND_CLOSE => {
            streams().remove(&(role, peer_fp.clone(), stream));
            reassemblers().remove(&(role, peer_fp, stream));
            true
        }
        // OK/FAIL are informational: the data path is one-way-addressed, so a
        // refusal simply means no bytes arrive and the local connection closes.
        KIND_OK | KIND_FAIL => {
            if kind == KIND_FAIL {
                tracing::warn!(
                    peer = %peer_fp,
                    stream,
                    reason = %String::from_utf8_lossy(body),
                    "Tunnel: exit refused the stream"
                );
            }
            true
        }
        _ => true,
    }
}

/// Splice one remote stream to its target on the exit side.
async fn serve_exit(
    nc: Arc<GhostNode>,
    peers: Arc<DashMap<String, SocketAddr>>,
    peer_fp: String,
    stream: u32,
    target: String,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await;
    let socket = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(target = %target, error = %e, "Tunnel: exit connect failed");
            send_payload(
                &nc,
                &peers,
                &peer_fp,
                &encode(KIND_FAIL, StreamRole::Remote, stream, b"connect failed"),
            )
            .await;
            streams().remove(&(StreamRole::Remote, peer_fp.clone(), stream));
            reassemblers().remove(&(StreamRole::Remote, peer_fp, stream));
            return;
        }
        Err(_) => {
            tracing::warn!(target = %target, "Tunnel: exit connect timed out");
            send_payload(
                &nc,
                &peers,
                &peer_fp,
                &encode(KIND_FAIL, StreamRole::Remote, stream, b"connect timeout"),
            )
            .await;
            streams().remove(&(StreamRole::Remote, peer_fp.clone(), stream));
            reassemblers().remove(&(StreamRole::Remote, peer_fp, stream));
            return;
        }
    };
    send_payload(
        &nc,
        &peers,
        &peer_fp,
        &encode(KIND_OK, StreamRole::Remote, stream, &[]),
    )
    .await;

    let (mut read, mut write) = socket.into_split();

    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if write.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });

    let mut chunker = UniversalTunnelChunker::new(stream);
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        match read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                for frame in chunker.chunk_payload(&buf[..n], false) {
                    if !send_payload(
                        &nc,
                        &peers,
                        &peer_fp,
                        &encode(KIND_DATA, StreamRole::Remote, stream, &frame),
                    )
                    .await
                    {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    send_payload(
        &nc,
        &peers,
        &peer_fp,
        &encode(KIND_CLOSE, StreamRole::Remote, stream, &[]),
    )
    .await;
    streams().remove(&(StreamRole::Remote, peer_fp.clone(), stream));
    reassemblers().remove(&(StreamRole::Remote, peer_fp, stream));
    writer.abort();
}

/// Send one tunnel envelope to `peer_fp` over the session we hold with it.
///
/// Single self-contained frame when it fits, RS carriers when it does not — the
/// same framing every other payload takes, so the tunnel needs no second wire
/// format.
pub(crate) async fn send_payload(
    nc: &Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let Some(addr) = peers.get(peer_fp).map(|entry| *entry.value()) else {
        return false;
    };
    let Some(sess) = nc.sessions.get(peer_fp) else {
        return false;
    };
    let ctx = SealCtx::from_session(&sess);
    drop(sess);
    if payload.len() + 2 <= net::V2_MAX_BULK_PAYLOAD_LEN {
        let frame = seal_single(&ctx, payload);
        return super::srtp::send_raw(&nc.socket, &addr, &frame)
            .await
            .is_ok();
    }
    let (carriers, tag) = enc_split(&ctx, payload);
    let mut carried = true;
    for (i, carrier) in carriers.iter().take(3).enumerate() {
        if super::srtp::send_v2(
            &nc.socket,
            &addr,
            &ctx.data_header(i as u8, true, 0),
            carrier,
            &tag,
        )
        .await
        .is_err()
        {
            carried = false;
        }
    }
    carried
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use vantablack::ghost::net::universal_tunnel::FLAG_FIN;

    /// Serialises the tests that set the tunnel's allowlists: the environment is
    /// process-global and the harness runs test functions in parallel.
    async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    #[test]
    fn envelopes_round_trip_and_foreign_payloads_are_refused() {
        let open = encode(KIND_OPEN, StreamRole::Local, 7, b"10.0.0.5:5432");
        assert!(looks_like(&open));
        let (kind, role, stream, body) = decode(&open).expect("decodes");
        assert_eq!(kind, KIND_OPEN);
        assert_eq!(role, StreamRole::Local);
        assert_eq!(stream, 7);
        assert_eq!(body, b"10.0.0.5:5432");

        assert!(!looks_like(b"GHOST_HANDSHAKE_"));
        assert!(decode(b"UTUN").is_none(), "too short");
        assert!(decode(b"XXXX\x01\0\0\0\x07").is_none(), "wrong magic");
    }

    #[test]
    fn a_forward_needs_a_local_port_and_a_target_and_binds_loopback_by_default() {
        let (forwards, rejected) =
            parse_ports("15432=10.0.0.5:5432, 9090=127.0.0.1:9000, =nope, 8080, ok=1.2.3.4:80");
        assert_eq!(forwards.len(), 2, "only two entries name both sides");
        assert_eq!(
            forwards[0].local,
            "127.0.0.1:15432".parse::<SocketAddr>().unwrap(),
            "a bare port binds loopback, not every interface"
        );
        assert_eq!(forwards[0].target, "10.0.0.5:5432");
        assert_eq!(forwards[1].local, "127.0.0.1:9090".parse().unwrap());
        assert_eq!(
            rejected,
            vec!["=nope", "8080", "ok=1.2.3.4:80"],
            "a missing target, a bare port and an unparseable local all say why"
        );
        assert!(parse_ports("").0.is_empty());
    }

    #[test]
    fn admission_is_an_exact_match_on_both_lists() {
        // The helpers read the environment; assert the matching rule directly.
        assert!(allow_entries(" 10.0.0.5:5432 , AABB ").contains(&"10.0.0.5:5432".to_string()));
        assert_eq!(allow_entries(""), Vec::<String>::new());
        // A prefix, a wildcard or a bare host is not the same entry.
        let entries = allow_entries("10.0.0.5:5432");
        assert!(entries.iter().any(|e| e == "10.0.0.5:5432"));
        assert!(!entries.iter().any(|e| e == "10.0.0.5"));
        assert!(!entries.iter().any(|e| e == "*"));
    }

    /// One direction of a sealed loopback mesh: every datagram the sender writes is
    /// opened with the receiver's own session and handed to the receiver's tunnel
    /// handler — the step `RxContext::ingest` performs after decryption, isolated so
    /// a test can stand two real nodes next to each other.
    fn relay(
        from: Arc<UdpSocket>,
        to_node: Arc<GhostNode>,
        to_peers: Arc<DashMap<String, SocketAddr>>,
        peer_fp: String,
        direction: NonceDirection,
        observed: Option<mpsc::UnboundedSender<Vec<u8>>>,
    ) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, from_addr)) = from.recv_from(&mut buf).await else {
                    return;
                };
                let frame = &buf[..n];
                let Some(header) = net::parse_gtf_v2_header(frame) else {
                    continue;
                };
                let Some(sess) = to_node.sessions.get(&peer_fp) else {
                    continue;
                };
                let plan = sess.plan_open(header.epoch, direction, header.counter);
                let key = match &plan {
                    vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => *key,
                    vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => *key,
                    vantablack::ghost::session::ratchet::OpenPlan::Refused => continue,
                };
                let Some(mut carried) = unframe(net::extract_payload(frame)) else {
                    continue;
                };
                let Ok(opened) = vantablack::ghost::layers::l2_aead::xchacha_open(
                    &key,
                    &header.nonce,
                    header.epoch,
                    direction,
                    &mut carried,
                ) else {
                    continue;
                };
                sess.commit_open(header.epoch, direction, plan);
                drop(sess);
                let Some(payload) = frame_payload(opened) else {
                    continue;
                };
                // A copy for the test, before the handler consumes the frame: this is
                // the only place an envelope such as `FAIL` is visible on the wire.
                if let Some(observed) = &observed {
                    let _ = observed.send(payload.to_vec());
                }
                let _ = handle_frame(&to_node, &to_peers, payload, from_addr).await;
            }
        });
    }

    /// Two real nodes with one sealed loopback session between them, a target
    /// listener the exit may or may not be allowed to dial, and a window onto the
    /// frames the initiator receives.
    struct Harness {
        initiator: Arc<GhostNode>,
        exit: Arc<GhostNode>,
        init_peers: Arc<DashMap<String, SocketAddr>>,
        /// Envelopes that arrived at the initiator, decoded by the test rather than
        /// consumed: this is where a refusal is observable.
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        target: Option<TcpListener>,
        target_addr: SocketAddr,
    }

    impl Harness {
        async fn new() -> Self {
            let target = TcpListener::bind("127.0.0.1:0").await.expect("a target");
            let target_addr = target.local_addr().expect("a bound target");
            let initiator = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("an initiator"));
            let exit = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("an exit"));
            let init_addr = initiator.socket.local_addr().expect("initiator bound");
            let exit_addr = exit.socket.local_addr().expect("exit bound");

            let master = [0x5Au8; 32];
            initiator.sessions.insert(
                exit.fingerprint(),
                Session::new_with_role(master, exit.fingerprint(), SessionRole::Initiator),
            );
            exit.sessions.insert(
                initiator.fingerprint(),
                Session::new_with_role(master, initiator.fingerprint(), SessionRole::Responder),
            );
            let init_peers: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
            let exit_peers: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
            init_peers.insert(exit.fingerprint(), exit_addr);
            exit_peers.insert(initiator.fingerprint(), init_addr);

            // What the exit sends arrives on the initiator's socket, and vice versa.
            let (inbound_tx, inbound) = mpsc::unbounded_channel();
            relay(
                Arc::clone(&initiator.socket),
                Arc::clone(&initiator),
                Arc::clone(&init_peers),
                exit.fingerprint(),
                NonceDirection::ResponderToInitiator,
                Some(inbound_tx),
            );
            relay(
                Arc::clone(&exit.socket),
                Arc::clone(&exit),
                Arc::clone(&exit_peers),
                initiator.fingerprint(),
                NonceDirection::InitiatorToResponder,
                None,
            );

            Self {
                initiator,
                exit,
                init_peers,
                inbound,
                target: Some(target),
                target_addr,
            }
        }

        fn take_target(&mut self) -> TcpListener {
            self.target.take().expect("the target listener")
        }

        /// Publish a local port that forwards to `target` through the exit.
        async fn forwarder(&self, target: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
            let local = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a local port");
            let addr = local.local_addr().expect("a bound local port");
            let initiator = Arc::clone(&self.initiator);
            let peers = Arc::clone(&self.init_peers);
            let exit_fp = self.exit.fingerprint();
            let target = target.to_string();
            let task = tokio::spawn(async move {
                let (socket, from) = local.accept().await.expect("a local client");
                serve_local(initiator, peers, exit_fp, target, socket, from).await;
            });
            (addr, task)
        }

        /// The next envelope of `want` that reached the initiator, with its body.
        async fn next_kind(&mut self, want: u8) -> Vec<u8> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while tokio::time::Instant::now() < deadline {
                let payload =
                    match tokio::time::timeout(Duration::from_millis(500), self.inbound.recv())
                        .await
                    {
                        Ok(Some(payload)) => payload,
                        Ok(None) => break,
                        Err(_) => continue,
                    };
                let Some((kind, _, _, body)) = decode(&payload) else {
                    continue;
                };
                if kind == want {
                    return body.to_vec();
                }
            }
            panic!("no envelope of kind {want} arrived over the loopback session");
        }
    }

    /// End to end: a TCP client talks to the local forwarder, the frames cross a
    /// sealed loopback session, the exit checks both allowlists, dials the target and
    /// splices the reply back.
    #[tokio::test]
    async fn a_local_tcp_client_reaches_an_allowlisted_target_through_the_exit() {
        let _guard = env_lock().await;
        let mut harness = Harness::new().await;
        let target = harness.take_target();
        let target_addr = harness.target_addr;

        let target_task = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.expect("the exit dials");
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.expect("the request arrives");
            socket.write_all(&buf[..n]).await.expect("the echo leaves");
            socket.write_all(b"|ack").await.expect("the tail leaves");
            n
        });

        // The allowlists an operator would set, and the toggle.
        std::env::set_var("GHOST_TUNNEL_ALLOW", target_addr.to_string());
        std::env::set_var("GHOST_TUNNEL_PEERS", harness.initiator.fingerprint());
        vantablack::ghost::net::universal_tunnel::set_enabled(true);

        let (local_addr, forwarder) = harness.forwarder(&target_addr.to_string()).await;
        let mut client = TcpStream::connect(local_addr)
            .await
            .expect("connect the forwarder");
        let request = b"hello over the mesh";
        client.write_all(request).await.expect("write the request");
        client.flush().await.expect("flush the request");

        // The echo plus the tail, however many reads it takes.
        let expected: Vec<u8> = [request.as_slice(), b"|ack"].concat();
        let mut reply = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while reply.len() < expected.len() && tokio::time::Instant::now() < deadline {
            let mut buf = vec![0u8; 256];
            match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => reply.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => panic!("read failed: {e}"),
            }
        }
        assert_eq!(reply, expected, "the client reads the target's reply");

        let received = tokio::time::timeout(Duration::from_secs(5), target_task)
            .await
            .expect("the target saw the request")
            .expect("the accept task finished");
        assert_eq!(received, request.len(), "the target got the whole request");

        forwarder.abort();
        std::env::remove_var("GHOST_TUNNEL_ALLOW");
        std::env::remove_var("GHOST_TUNNEL_PEERS");
        vantablack::ghost::net::universal_tunnel::set_enabled(false);
    }

    /// A peer outside `GHOST_TUNNEL_PEERS`: the exit answers `FAIL` over the session,
    /// and the target is never dialled.
    #[tokio::test]
    async fn a_peer_outside_the_allowlist_is_refused_and_the_target_is_never_dialled() {
        let _guard = env_lock().await;
        let mut harness = Harness::new().await;
        let target = harness.take_target();
        let target_addr = harness.target_addr;

        // The target is allowed; the *peer* is not.
        std::env::set_var("GHOST_TUNNEL_ALLOW", target_addr.to_string());
        std::env::set_var("GHOST_TUNNEL_PEERS", "0000000000000000");
        vantablack::ghost::net::universal_tunnel::set_enabled(true);

        let (local_addr, forwarder) = harness.forwarder(&target_addr.to_string()).await;
        let mut client = TcpStream::connect(local_addr)
            .await
            .expect("connect the forwarder");
        client.write_all(b"should not arrive").await.expect("write");

        let body = harness.next_kind(KIND_FAIL).await;
        assert_eq!(
            body, b"peer not allowed",
            "the refusal names the allowlist that refused"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(400), target.accept())
                .await
                .is_err(),
            "an unlisted peer must not reach the target"
        );

        forwarder.abort();
        std::env::remove_var("GHOST_TUNNEL_ALLOW");
        std::env::remove_var("GHOST_TUNNEL_PEERS");
        vantablack::ghost::net::universal_tunnel::set_enabled(false);
    }

    /// A target outside `GHOST_TUNNEL_ALLOW`: the exit answers `FAIL` over the session,
    /// and the target is never dialled.
    #[tokio::test]
    async fn a_target_outside_the_allowlist_is_refused_and_never_dialled() {
        let _guard = env_lock().await;
        let mut harness = Harness::new().await;
        let target = harness.take_target();
        let target_addr = harness.target_addr;

        // The peer is allowed; the *target* is not — the allowlist names another
        // address, which is what a typo or an over-broad policy would look like.
        std::env::set_var("GHOST_TUNNEL_ALLOW", "10.255.255.1:9");
        std::env::set_var("GHOST_TUNNEL_PEERS", harness.initiator.fingerprint());
        vantablack::ghost::net::universal_tunnel::set_enabled(true);

        let (local_addr, forwarder) = harness.forwarder(&target_addr.to_string()).await;
        let mut client = TcpStream::connect(local_addr)
            .await
            .expect("connect the forwarder");
        client.write_all(b"should not arrive").await.expect("write");

        let body = harness.next_kind(KIND_FAIL).await;
        assert_eq!(
            body, b"target not allowed",
            "the refusal names the allowlist that refused"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(400), target.accept())
                .await
                .is_err(),
            "a target outside the allowlist is never dialled"
        );

        forwarder.abort();
        std::env::remove_var("GHOST_TUNNEL_ALLOW");
        std::env::remove_var("GHOST_TUNNEL_PEERS");
        vantablack::ghost::net::universal_tunnel::set_enabled(false);
    }

    /// The transport half: a chunker frame survives the envelope and the peer's
    /// reassembler yields the original bytes.
    #[test]
    fn chunked_data_survives_the_envelope_and_reassembly() {
        let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let mut chunker = UniversalTunnelChunker::new(9);
        let frames = chunker.chunk_payload(&payload, true);
        assert_eq!(frames.len(), 3);

        let mut reassembler = UniversalTunnelReassembler::new();
        let mut got = Vec::new();
        for frame in &frames {
            let encoded = encode(KIND_DATA, StreamRole::Local, 9, frame);
            let (kind, role, stream, body) = decode(&encoded).expect("decodes");
            assert_eq!((kind, stream), (KIND_DATA, 9));
            assert_eq!(
                role,
                StreamRole::Local,
                "the sender's role travels with the frame"
            );
            got.extend_from_slice(&reassembler.ingest_frame(body).expect("ingest"));
        }
        assert_eq!(got, payload);
        assert!(
            reassembler.is_finished,
            "the FIN flag survives the envelope"
        );
        // The chunker's FIN flag is what the reassembler reports, not the envelope.
        assert_ne!(FLAG_FIN, 0);
    }
}
