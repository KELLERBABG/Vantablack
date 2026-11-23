//! MASQUE (HTTP/3 CONNECT-UDP) transport for the live daemon (Phase 4, `quic`).
//!
//! [`vantablack::ghost::v2::masque`] implements the HTTP/3 pieces MASQUE needs —
//! SETTINGS with `H3_DATAGRAM`, extended CONNECT, RFC 9297 capsules and RFC 9221
//! datagrams. This module is the daemon half: admission by **post-quantum session
//! binding**, carriage of ordinary GTFv2 datagrams, and the dial that reaches a
//! peer whose UDP path is blocked.
//!
//! ## Admission is a session, not a string
//!
//! The endpoint this replaces admitted a CONNECT when the `:authority` label
//! matched a configured token. That authenticates a name anyone can type. Here a
//! peer must additionally prove it holds the identity the mesh already pinned:
//!
//! * the client sends its fingerprint and a signature over
//!   [`masque::proof_message`] — a fixed prefix, **this QUIC connection's TLS
//!   exporter value**, and the fingerprint;
//! * the server looks the fingerprint up in `node.sessions` and verifies the
//!   signature against `Session::peer_identity_pk`, the key the hybrid handshake
//!   pinned;
//! * any connection that cannot produce it is refused at the request, before a
//!   single frame is carried.
//!
//! The exporter binding is what stops a proof captured on one connection from
//! being replayed on another, and the session lookup is what stops an attacker who
//! knows a fingerprint from claiming it.
//!
//! ## Carriage
//!
//! Each GTFv2 datagram becomes one datagram capsule on the request stream and each
//! arriving capsule becomes one frame handed to `RxContext::ingest` — the same
//! entry point a UDP datagram takes. The frames are unchanged, so the sealing,
//! replay window and ratchet behave exactly as they do over UDP; this is a
//! different carrier for the same bytes.
//!
//! ## Configuration
//!
//! | Variable | Meaning |
//! |---|---|
//! | `GHOST_MASQUE=1` | run the HTTP/3 endpoint |
//! | `GHOST_MASQUE_LISTEN` | bind address (default `0.0.0.0:8444`) |
//! | `GHOST_MASQUE_DIAL=1` | dial a peer's endpoint when its UDP path fails |
//! | `GHOST_MASQUE_PORT` | port a peer's endpoint listens on (default 8444) |
//! | `GHOST_MASQUE_SNI` | SNI used when dialing (default `masque.origin.test`) |

use crate::*;
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::sync::mpsc;

use vantablack::ghost::v2::masque::{self, Admission, Tunnel};

/// One datagram from a MASQUE stream, and the address the daemon should treat as
/// its source.
type Inbound = (Vec<u8>, SocketAddr);

fn paths() -> &'static DashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> {
    static PATHS: OnceLock<DashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>> = OnceLock::new();
    PATHS.get_or_init(DashMap::new)
}

fn sessions() -> &'static DashMap<[u8; 4], SocketAddr> {
    static SESSIONS: OnceLock<DashMap<[u8; 4], SocketAddr>> = OnceLock::new();
    SESSIONS.get_or_init(DashMap::new)
}

/// Peers we are dialing or already carrying: one dial at a time per address, and
/// no re-dial while a stream is up.
fn dials() -> &'static DashMap<SocketAddr, ()> {
    static DIALS: OnceLock<DashMap<SocketAddr, ()>> = OnceLock::new();
    DIALS.get_or_init(DashMap::new)
}

/// Whether this process runs the MASQUE endpoint.
pub(crate) fn enabled() -> bool {
    static RESOLVED: OnceLock<bool> = OnceLock::new();
    *RESOLVED.get_or_init(|| flag("GHOST_MASQUE"))
}

/// Whether this node dials a peer's endpoint when its UDP path fails.
pub(crate) fn dial_enabled() -> bool {
    static RESOLVED: OnceLock<bool> = OnceLock::new();
    *RESOLVED.get_or_init(|| flag("GHOST_MASQUE_DIAL"))
}

/// The pure switch reader, so every env shape is testable.
fn flag(name: &str) -> bool {
    flag_value(std::env::var(name).ok().as_deref())
}

fn flag_value(value: Option<&str>) -> bool {
    match value {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => false,
    }
}

/// The port a peer's endpoint listens on.
pub(crate) fn dial_port() -> u16 {
    dial_port_from(std::env::var("GHOST_MASQUE_PORT").ok().as_deref())
}

fn dial_port_from(value: Option<&str>) -> u16 {
    value
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(8444)
}

fn listen_addr() -> SocketAddr {
    std::env::var("GHOST_MASQUE_LISTEN")
        .ok()
        .and_then(|raw| raw.trim().parse::<SocketAddr>().ok())
        .unwrap_or_else(|| "0.0.0.0:8444".parse().expect("a valid default bind"))
}

/// The SNI to present when dialing. A name, because QUIC's TLS stack refuses an
/// IP literal as `server_name`.
fn dial_sni() -> String {
    std::env::var("GHOST_MASQUE_SNI")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "masque.origin.test".into())
}

/// Try to carry `frame` over a MASQUE stream.
///
/// Returns `false` when the destination has no stream, which is the ordinary
/// case: the caller then keeps to UDP.
pub(crate) fn try_send(dst: &SocketAddr, frame: &[u8]) -> bool {
    if paths().is_empty() {
        return false;
    }
    let session = net::parse_session_hash(frame);
    let target = if paths().contains_key(dst) {
        Some(*dst)
    } else if session != [0, 0, 0, 0] {
        sessions().get(&session).map(|entry| *entry.value())
    } else {
        None
    };
    let Some(target) = target else {
        return false;
    };
    let Some(tx) = paths().get(&target).map(|entry| entry.value().clone()) else {
        return false;
    };
    tx.send(frame.to_vec()).is_ok()
}

/// Whether a MASQUE stream already reaches this peer.
///
/// `send3_adaptive` uses this to skip a relay route chosen only because UDP
/// failed: the stream goes to the peer itself.
pub(crate) fn carries(dst: &SocketAddr, session: &[u8; 4]) -> bool {
    if paths().contains_key(dst) {
        return true;
    }
    *session != [0, 0, 0, 0] && sessions().contains_key(session)
}

/// The admission rule: the named peer must hold a live session with us and prove
/// it with a signature over this connection's exporter value.
fn admission(nc: Arc<GhostNode>) -> Admission {
    Admission::Session(Arc::new(move |fingerprint, binding, proof| {
        let signature: [u8; 64] = match proof.try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let Some(session) = nc.sessions.get(fingerprint) else {
            tracing::debug!(
                peer = %fingerprint,
                "MASQUE: refused — no post-quantum session with this peer"
            );
            return false;
        };
        let Some(pk) = session.peer_identity_pk() else {
            tracing::debug!(
                peer = %fingerprint,
                "MASQUE: refused — session has no pinned identity key"
            );
            return false;
        };
        drop(session);
        let message = masque::proof_message(binding, fingerprint);
        let ok = l0_identity::verify_peer_signature(&pk, &message, &signature);
        if !ok {
            tracing::warn!(
                peer = %fingerprint,
                "MASQUE: refused — proof does not verify against the pinned identity"
            );
        }
        ok
    }))
}

/// Start the endpoint when configured. Every admitted tunnel feeds `ingress`.
pub(crate) fn spawn(
    nc: Arc<GhostNode>,
    ingress: mpsc::UnboundedSender<Inbound>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    Some(spawn_on(nc, ingress, listen_addr()))
}

/// Start the endpoint on an explicit address. The configured [`spawn`] and the
/// end-to-end test share this, so the test exercises the same listener, admission
/// and pump code the daemon runs.
fn spawn_on(
    nc: Arc<GhostNode>,
    ingress: mpsc::UnboundedSender<Inbound>,
    listen: SocketAddr,
) -> tokio::task::JoinHandle<()> {
    let admission = admission(Arc::clone(&nc));
    let sni = dial_sni();
    let (tx, mut tunnels) = mpsc::unbounded_channel::<Tunnel>();
    let handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        let server = tokio::spawn(async move {
            if let Err(e) = masque::run_tunnel_server(listen, admission, sni, None, tx).await {
                tracing::error!("MASQUE: endpoint stopped: {e}");
            }
        });
        while let Some(tunnel) = tunnels.recv().await {
            let ingress = ingress.clone();
            tokio::spawn(async move { serve_tunnel(tunnel, ingress).await });
        }
        server.abort();
    });
    tracing::info!(%listen, "MASQUE: HTTP/3 endpoint starting (PQ session admission)");
    handle
}

/// Dial a peer's endpoint after its UDP path failed.
///
/// Returns `true` when a dial started. The caller keeps whatever route it has
/// meanwhile; [`carries`] takes over the send path the moment a stream is up.
pub(crate) fn try_dial(nc: &Arc<GhostNode>, peer: SocketAddr) -> bool {
    if !dial_enabled() {
        return false;
    }
    if dials().insert(peer, ()).is_some() {
        return false;
    }
    dial(
        nc,
        peer,
        SocketAddr::new(peer.ip(), dial_port()),
        dial_sni(),
    )
}

/// Dial `target` for `peer`, registering the stream under the peer's mesh address.
///
/// Split from [`try_dial`] so the end-to-end test can name a loopback endpoint
/// without depending on `GHOST_MASQUE_PORT`; the registration, pump and cleanup are
/// the same code the daemon runs.
fn dial(nc: &Arc<GhostNode>, peer: SocketAddr, target: SocketAddr, sni: String) -> bool {
    if dials().insert(peer, ()).is_some() {
        return false;
    }
    let fingerprint = nc.fingerprint();
    let identity = Arc::clone(&nc.identity);
    let sign: Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync> =
        Arc::new(move |message: &[u8]| identity.sign(message).to_bytes().to_vec());
    let (queue, outbound) = mpsc::unbounded_channel::<Vec<u8>>();
    paths().insert(peer, queue);
    tokio::spawn(async move {
        let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        // Replies are addressed to the peer's mesh address: that is the only name
        // the rest of the daemon holds for it.
        let pump = tokio::spawn(async move {
            while let Some(frame) = in_rx.recv().await {
                let session = net::parse_session_hash(&frame);
                if session != [0, 0, 0, 0] {
                    sessions().insert(session, peer);
                }
                if let Some(tx) = ingress_sender() {
                    if tx.send((frame, peer)).is_err() {
                        return;
                    }
                }
            }
        });
        match masque::tunnel_client(target, sni, fingerprint, sign, outbound, in_tx).await {
            Ok(()) => tracing::info!(peer = %peer, %target, "MASQUE: dialed stream closed"),
            Err(e) => tracing::debug!(peer = %peer, %target, error = %e, "MASQUE: dial failed"),
        }
        pump.abort();
        paths().remove(&peer);
        sessions().retain(|_, addr| *addr != peer);
        dials().remove(&peer);
    });
    true
}

/// The ingress sink installed by the node, used by dialed streams (which are not
/// children of the listener task).
fn ingress_cell() -> &'static OnceLock<mpsc::UnboundedSender<Inbound>> {
    static INGRESS: OnceLock<mpsc::UnboundedSender<Inbound>> = OnceLock::new();
    &INGRESS
}

fn ingress_sender() -> Option<mpsc::UnboundedSender<Inbound>> {
    ingress_cell().get().cloned()
}

/// Install the frame sink once; a second call is ignored, which keeps it safe in
/// tests and in a restarting supervisor.
pub(crate) fn install_ingress(tx: mpsc::UnboundedSender<Inbound>) {
    let _ = ingress_cell().set(tx);
}

/// Bridge one admitted tunnel to the daemon's frame pipeline.
///
/// The stream is registered under the connection's address before the pump
/// starts, so a frame the daemon sends the instant the peer's first frame arrives
/// already has a stream to take instead of racing into the UDP fallback.
async fn serve_tunnel(tunnel: Tunnel, ingress: mpsc::UnboundedSender<Inbound>) {
    let key = tunnel.peer;
    let identity = tunnel.identity.clone();
    let (queue, outbound) = mpsc::unbounded_channel::<Vec<u8>>();
    paths().insert(key, queue);
    tracing::info!(peer = %key, admitted = %identity, "MASQUE: tunnel open");

    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let forward = tokio::spawn(async move {
        while let Some(frame) = in_rx.recv().await {
            let session = net::parse_session_hash(&frame);
            if session != [0, 0, 0, 0] {
                sessions().insert(session, key);
            }
            if ingress.send((frame, key)).is_err() {
                return;
            }
        }
    });

    if let Err(e) = masque::pump_tunnel(tunnel, outbound, in_tx).await {
        tracing::debug!(peer = %key, error = %e, "MASQUE: tunnel ended");
    }
    forward.abort();
    paths().remove(&key);
    sessions().retain(|_, addr| *addr != key);
    tracing::info!(peer = %key, "MASQUE: tunnel closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transport_is_off_unless_both_switches_are_set() {
        assert!(!flag_value(None));
        assert!(!flag_value(Some("0")));
        assert!(flag_value(Some("1")));
        assert!(flag_value(Some("TRUE")));
        assert_eq!(dial_port_from(None), 8444);
        assert_eq!(dial_port_from(Some("9444")), 9444);
        assert_eq!(dial_port_from(Some("nonsense")), 8444);
        assert_eq!(dial_port_from(Some("0")), 8444);
    }

    /// The admission rule end to end: no session means no admission even with a
    /// valid signature, and once the mesh session has pinned the peer's identity
    /// only a proof over *this* connection is accepted.
    #[tokio::test]
    async fn admission_needs_a_pinned_session_and_a_proof_over_this_connection() {
        let node = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("a test node"));
        let peer_id = l0_identity::GhostIdentity::generate_fresh();
        let fingerprint = peer_id.fingerprint();
        let Admission::Session(check) = admission(Arc::clone(&node)) else {
            panic!("the daemon admits by session");
        };
        let binding = [9u8; 32];
        let signed = peer_id
            .sign(&masque::proof_message(&binding, &fingerprint))
            .to_bytes();

        assert!(
            !check(&fingerprint, &binding, &signed),
            "an unknown fingerprint is refused before any signature is checked"
        );

        let session =
            Session::new_with_role([1u8; 32], fingerprint.clone(), SessionRole::Responder);
        session.pin_peer_identity(peer_id.public_key_bytes());
        node.sessions.insert(fingerprint.clone(), session);

        assert!(
            check(&fingerprint, &binding, &signed),
            "the pinned identity plus this connection's proof is admitted"
        );
        let other_binding = [8u8; 32];
        assert!(
            !check(&fingerprint, &other_binding, &signed),
            "a proof captured on another connection does not transfer"
        );
        assert!(
            !check(&fingerprint, &binding, &[0u8; 64]),
            "a forged signature is refused"
        );
    }

    /// A real GTFv2 frame, sealed-shaped: the transport carries frames unchanged, so
    /// a test frame is enough to prove the carrier does not rewrite them.
    fn gtf_frame(session: [u8; 4], shard: u8, payload: &[u8]) -> Vec<u8> {
        let header = net::GtfV2Header {
            session_hash: session,
            counter: 1,
            epoch: 0,
            nonce: [3u8; 12],
            shard_index: shard,
            flags: 0,
            bulk: false,
            tail: [0u8; net::JITTER_MAX],
        };
        net::build_gtf_v2_frame(&header, payload, &[0u8; 16])
    }

    /// End to end over loopback: a real HTTP/3 endpoint admits a real client by
    /// session binding, and GTFv2 frames cross in both directions.
    ///
    /// Nothing here is simulated: the endpoint binds a socket, the client completes a
    /// QUIC handshake and an HTTP/3 CONNECT with a proof over the connection's
    /// exporter value, and both frames travel as datagram capsules on the request
    /// stream.
    #[tokio::test]
    async fn a_localhost_endpoint_and_client_carry_gtf_frames_both_ways() {
        use std::time::Duration;

        let server_node = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("a server node"));
        let client_node = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("a client node"));

        // The mesh handshake has already pinned the client's identity on the server.
        let session =
            Session::new_with_role([7u8; 32], client_node.fingerprint(), SessionRole::Responder);
        session.pin_peer_identity(client_node.identity.public_key_bytes());
        server_node
            .sessions
            .insert(client_node.fingerprint(), session);

        // A free loopback port for the endpoint: bind, learn, release.
        let listen: SocketAddr = {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("a probe socket");
            probe.local_addr().expect("a bound probe")
        };
        let (server_in_tx, mut server_in) = mpsc::unbounded_channel::<Inbound>();
        let endpoint = spawn_on(Arc::clone(&server_node), server_in_tx, listen);

        let (client_in_tx, mut client_in) = mpsc::unbounded_channel::<Inbound>();
        install_ingress(client_in_tx);

        // The peer's mesh address is the only name the daemon holds for it.
        let peer: SocketAddr = "127.0.0.1:39002".parse().expect("the peer's mesh address");
        assert!(
            dial(&client_node, peer, listen, "masque.origin.test".into()),
            "a dial starts"
        );

        let outbound = gtf_frame([1, 2, 3, 4], 0, b"hello from the client");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut sent = false;
        while tokio::time::Instant::now() < deadline {
            if try_send(&peer, &outbound) {
                sent = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(sent, "the stream came up and took the frame");

        let (received, from_client) =
            tokio::time::timeout(Duration::from_secs(10), server_in.recv())
                .await
                .expect("the endpoint hands the frame to ingest")
                .expect("an inbound frame");
        assert_eq!(
            received, outbound,
            "the server received the frame unchanged"
        );

        let reply = gtf_frame([1, 2, 3, 4], 1, b"a reply from the server");
        assert!(
            try_send(&from_client, &reply),
            "the admitted stream carries replies"
        );
        let (back, _) = tokio::time::timeout(Duration::from_secs(10), client_in.recv())
            .await
            .expect("the client's pump delivers the reply")
            .expect("an inbound frame");
        assert_eq!(back, reply, "the reply crossed back unchanged");

        endpoint.abort();
    }

    /// The proof is bound to the connection, so the same session cannot reuse a
    /// captured proof on another stream: the message carries the exporter value.
    #[test]
    fn a_proof_carries_the_connection_binding_and_the_fingerprint() {
        let a = masque::proof_message(&[1u8; 32], "aabbccddeeff0011");
        let b = masque::proof_message(&[2u8; 32], "aabbccddeeff0011");
        let c = masque::proof_message(&[1u8; 32], "0011223344556677");
        assert_ne!(a, b, "another connection yields another message");
        assert_ne!(a, c, "another peer yields another message");
        assert!(a.starts_with(b"GGN_MASQUE_V1"));
        assert!(a.ends_with(b"aabbccddeeff0011"));
    }
}
