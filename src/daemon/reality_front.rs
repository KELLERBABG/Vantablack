//! REALITY front transport for the live daemon (Phase 3, `reality-front` feature).
//!
//! The front presents a real TLS 1.3 listener that splices every unauthenticated
//! probe to a borrowed origin (see `ghost::v2::front`). This module is the daemon
//! half: it admits a knocked connection — or dials a peer's front itself — and
//! carries **ordinary GTF datagrams** over it in both directions, framed as
//! `[u32 length][frame]`.
//!
//! Bidirectional carriage is keyed two ways, because the daemon's send path knows
//! different things at different moments:
//!
//! * **By peer address.** During a handshake the frame's session hash is
//!   `[0,0,0,0]`, so the only identity is the address the rest of the daemon
//!   replies to: the connection's own remote address for an admitted stream, the
//!   peer's UDP address for a dialed one. Registering the stream under that
//!   address lets the handshake answer itself over TLS.
//! * **By session hash.** Once a session exists, replies may be built from a
//!   different code path that holds only the peer's UDP address. Every GTF frame
//!   carries its session hash at offset 0, so [`try_send`] can find the stream
//!   that session arrived on without the caller knowing anything about TLS.
//!
//! Frames that have no front path fall through to the ordinary UDP send, so this
//! transport is additive: a node with the front disabled, or a peer that does not
//! use it, keeps exactly the UDP path it had.
//!
//! ## When the daemon dials
//!
//! A node whose UDP path to a peer is blocked performs ICE checks and reports the
//! failure; before handing the peer to the relay ladder the daemon calls
//! [`try_dial`], because a TLS stream to the peer itself is a *direct* path and
//! costs no third party. The route table entry the ladder installs stays put
//! (a dial can fail), and once a stream is up [`carries`] makes
//! `send3_adaptive` skip the relay for that peer.
//!
//! Dialing needs the remote front's **label** admission: the hidden knock lives
//! in the ClientHello random, which the TLS stack generates itself and offers no
//! seam to replace, so a knock-only front is not dialed from here (a stream that
//! cannot authenticate would be spliced to the borrowed origin, and writing frames
//! into it would be traffic aimed at a third party). [`try_dial`] refuses when no
//! label is configured, rather than dialing into a splice.
//!
//! That asymmetry is advertised, not only logged: a front whose admission is
//! knock-only sets `CAP_REALITY_FRONT_KNOCK` beside `CAP_REALITY_FRONT` in its
//! descriptor, so a peer sees there is no dialable front before it tries one. The
//! same node warns at startup when `GHOST_REALITY_FRONT_DIAL` is set without a
//! label, because then none of its blocked peers can be reached over a front.
//!
//! Configuration (environment, since the daemon has no config file for this):
//!
//! | Variable | Meaning |
//! |---|---|
//! | `GHOST_REALITY_FRONT=1` | enable the listener |
//! | `GHOST_REALITY_FRONT_LISTEN` | bind address (default `0.0.0.0:8443`) |
//! | `GHOST_REALITY_ORIGIN` | borrowed origin, `host[:port]` (default `www.cloudflare.com`) |
//! | `GHOST_REALITY_TOKEN` | label admission: listener token, and the dial SNI label (required for dialing) |
//! | `GHOST_REALITY_KNOCK_PSK` | 32-byte hex PSK for hidden-knock admission (preferred for listening, **not dialable**) |
//! | `GHOST_REALITY_FRONT_DIAL=1` | dial a peer's front when its UDP path fails |
//! | `GHOST_REALITY_FRONT_PORT` | port the peer's front listens on (default `8443`) |

use crate::*;
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use vantablack::ghost::v2::front::{
    self as front, Admission, Admitted, FrontConfig, FrontListener,
};
use vantablack::ghost::v2::reality::{BorrowedOrigin, RealityKnock};

/// One datagram from a front stream, and the address the daemon should treat as
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

/// Where every front stream — admitted or dialed — hands its frames.
///
/// A channel rather than a captured `RxContext`: a failed punch can start a dial
/// before the receive pipeline is assembled, so the sink is installed once and
/// drained by a single forwarder into `ingest`.
fn ingress_cell() -> &'static OnceLock<mpsc::UnboundedSender<Inbound>> {
    static INGRESS: OnceLock<mpsc::UnboundedSender<Inbound>> = OnceLock::new();
    &INGRESS
}

fn ingress() -> Option<mpsc::UnboundedSender<Inbound>> {
    ingress_cell().get().cloned()
}

/// Install the frame sink. Called once by the node orchestrator; a second call is
/// ignored, which keeps it safe in tests and in a restarting supervisor.
pub(crate) fn install_ingress(tx: mpsc::UnboundedSender<Inbound>) {
    let _ = ingress_cell().set(tx);
}

/// Whether the front listener is configured for this process.
pub(crate) fn enabled() -> bool {
    std::env::var("GHOST_REALITY_FRONT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Whether this node dials a peer's front when UDP fails.
pub(crate) fn dial_enabled() -> bool {
    dial_enabled_for(std::env::var("GHOST_REALITY_FRONT_DIAL").ok().as_deref())
}

/// The pure decision behind [`dial_enabled`].
fn dial_enabled_for(value: Option<&str>) -> bool {
    match value {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => false,
    }
}

/// The port a peer's front listens on: the peer's IP, this port.
pub(crate) fn dial_port() -> u16 {
    dial_port_from(std::env::var("GHOST_REALITY_FRONT_PORT").ok().as_deref())
}

/// The pure decision behind [`dial_port`].
fn dial_port_from(value: Option<&str>) -> u16 {
    value
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(8443)
}

/// The SNI to dial with: `<token>.<borrowed origin>`, which is exactly what the
/// label-admission listener splits on.
fn dial_sni(token: &str, origin_sni: &str) -> String {
    format!("{token}.{origin_sni}")
}

/// The configured label, when this node has one.
fn label_token() -> Option<String> {
    std::env::var("GHOST_REALITY_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

/// Peers we are dialing or already carrying over a front stream: one dial at a
/// time per address, and no re-dial while a stream is up.
fn dials() -> &'static DashMap<SocketAddr, ()> {
    static DIALS: OnceLock<DashMap<SocketAddr, ()>> = OnceLock::new();
    DIALS.get_or_init(DashMap::new)
}

/// Try to carry `frame` over a front stream.
///
/// Returns `false` when the destination has no front path, which is the ordinary
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

/// Whether a front stream already reaches this peer.
///
/// `send3_adaptive` uses this to skip a relay route that was chosen only because
/// UDP failed: the stream goes to the peer itself, so relaying would add a third
/// party to a path that does not need one.
pub(crate) fn carries(dst: &SocketAddr, session: &[u8; 4]) -> bool {
    if paths().contains_key(dst) {
        return true;
    }
    *session != [0, 0, 0, 0] && sessions().contains_key(session)
}

fn listen_addr() -> SocketAddr {
    std::env::var("GHOST_REALITY_FRONT_LISTEN")
        .ok()
        .and_then(|raw| match raw.trim().parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                tracing::warn!(value = %raw, error = %e, "GHOST_REALITY_FRONT_LISTEN is not a socket address; using the default");
                None
            }
        })
        .unwrap_or_else(|| "0.0.0.0:8443".parse().expect("a valid default bind"))
}

fn origin() -> BorrowedOrigin {
    let raw = std::env::var("GHOST_REALITY_ORIGIN").unwrap_or_else(|_| "www.cloudflare.com".into());
    match raw.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => BorrowedOrigin {
            host: host.to_string(),
            port: port.parse().unwrap_or(443),
            sni: host.to_string(),
        },
        _ => BorrowedOrigin::new(&raw),
    }
}

/// Admission mode: a knock PSK wins when present, otherwise the legacy label.
fn admission() -> Option<Admission> {
    admission_from(
        std::env::var("GHOST_REALITY_KNOCK_PSK").ok().as_deref(),
        label_token().as_deref(),
    )
}

/// The pure decision behind [`admission`].
///
/// A malformed PSK falls back to the label, with a warning, rather than leaving
/// the front with no admission at all.
fn admission_from(psk: Option<&str>, label: Option<&str>) -> Option<Admission> {
    let Some(raw) = psk else {
        return label.map(|token| Admission::SniLabel(token.to_string()));
    };
    match parse_knock_psk(raw) {
        Some(key) => Some(Admission::Knock(RealityKnock::new(key))),
        None => {
            tracing::warn!(
                len = raw.trim().len(),
                "GHOST_REALITY_KNOCK_PSK must be 64 hex characters (32 bytes); \
                 falling back to label admission"
            );
            label.map(|token| Admission::SniLabel(token.to_string()))
        }
    }
}

/// Parse a knock PSK: exactly 32 bytes, hex encoded.
fn parse_knock_psk(raw: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).ok()?;
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(key)
}

/// Whether this node's front admits knocks only, i.e. a peer that dials by SNI
/// label cannot reach it.
///
/// Read where the node advertises its front capability, so the mode travels with
/// the bits instead of being discovered from a refused handshake.
pub(crate) fn knock_only() -> bool {
    matches!(admission(), Some(Admission::Knock(_)))
}

/// Start the listener when configured. Returns the supervisor task handle.
pub(crate) fn spawn() -> Option<tokio::task::JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    let Some(admission) = admission() else {
        tracing::error!(
            "REALITY front: GHOST_REALITY_FRONT is set but neither \
             GHOST_REALITY_KNOCK_PSK nor GHOST_REALITY_TOKEN is configured — \
             every probe would be spliced, so the listener stays off"
        );
        return None;
    };
    // Say it once at startup rather than at the first failed punch: without a
    // label no peer front can be dialed, so a blocked UDP path stays on the relay.
    if dial_enabled() && label_token().is_none() {
        tracing::warn!(
            "REALITY front: GHOST_REALITY_FRONT_DIAL is set but GHOST_REALITY_TOKEN is \
             not — only label admission can be dialed, so a front carries nothing to \
             peers whose UDP path fails"
        );
    }
    let cfg = FrontConfig {
        listen: listen_addr(),
        origin: origin(),
        admission: admission.clone(),
    };
    Some(tokio::spawn(async move {
        let listener = match FrontListener::bind(cfg).await {
            Ok(listener) => listener,
            Err(e) => {
                tracing::error!("REALITY front: cannot bind: {e}");
                return;
            }
        };
        match listener.local_addr() {
            Ok(addr) => tracing::info!(
                %addr,
                admission = listener.admission_label(),
                dialable = !matches!(admission, Admission::Knock(_)),
                "REALITY front: listening (TLS 1.3, borrowed-origin splice)"
            ),
            Err(e) => tracing::warn!("REALITY front: local address unavailable: {e}"),
        }
        let (tx, mut admitted) = mpsc::channel::<Admitted>(64);
        tokio::spawn(async move {
            if let Err(e) = listener.run(tx).await {
                tracing::error!("REALITY front: listener stopped: {e}");
            }
        });
        while let Some(conn) = admitted.recv().await {
            tokio::spawn(async move { serve_connection(conn).await });
        }
    }))
}

/// Dial a peer's front after its UDP path failed.
///
/// Returns `true` when a dial was started. The caller keeps whatever route it has
/// meanwhile (the dial may fail); [`carries`] takes over the send path the moment
/// the stream is up. A peer that is already dialing, or already carried, is left
/// alone: a second stream to the same peer would only duplicate every frame.
pub(crate) fn try_dial(peer: SocketAddr) -> bool {
    if !dial_enabled() {
        return false;
    }
    let Some(token) = label_token() else {
        tracing::info!(
            peer = %peer,
            "REALITY front: dial requested but no GHOST_REALITY_TOKEN is set — the \
             hidden knock lives in the ClientHello random, which this TLS stack \
             generates itself, so only label admission can be dialed"
        );
        return false;
    };
    if dials().insert(peer, ()).is_some() {
        return false;
    }
    let sni = dial_sni(&token, &origin().sni);
    let target = SocketAddr::new(peer.ip(), dial_port());
    tokio::spawn(async move {
        match front::dial(target, &sni).await {
            Ok(stream) => {
                tracing::info!(peer = %peer, front = %target, "REALITY front: dialed, carrying frames over TLS");
                serve_dialed(peer, stream).await;
            }
            Err(e) => tracing::debug!(
                peer = %peer,
                front = %target,
                error = %e,
                "REALITY front: dial failed"
            ),
        }
        dials().remove(&peer);
    });
    true
}

/// Bridge one admitted TLS stream to the daemon's frame pipeline.
async fn serve_connection(conn: Admitted) {
    let Some(inbound) = ingress() else {
        tracing::error!("REALITY front: no ingest sink installed — dropping the stream");
        return;
    };
    let peer = conn.peer;
    tracing::info!(%peer, sni = %conn.sni, "REALITY front: tunnel open");
    let (_, queue) = path_channel(peer);
    carry(conn.stream, peer, queue, inbound).await;
    tracing::info!(%peer, "REALITY front: tunnel closed");
}

/// Bridge a stream this node dialed, keyed by the peer's UDP address.
///
/// That address is what every caller on this side already holds for the peer, so
/// replies reach the stream without the rest of the daemon learning that a TCP
/// connection exists at all.
async fn serve_dialed<S>(peer: SocketAddr, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(inbound) = ingress() else {
        tracing::error!("REALITY front: no ingest sink installed — dropping the dialed stream");
        return;
    };
    let (_, queue) = path_channel(peer);
    carry(stream, peer, queue, inbound).await;
    tracing::info!(%peer, "REALITY front: dialed tunnel closed");
}

/// Claim this side's name for the peer in the send path, returning the queue the
/// stream's writer drains.
///
/// Registration is synchronous and happens before the pump starts, so a frame sent
/// the instant a dial returns already has a front path to take instead of racing
/// the writer task into the UDP fallback.
fn path_channel(
    key: SocketAddr,
) -> (
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (tx, queue) = mpsc::unbounded_channel::<Vec<u8>>();
    paths().insert(key, tx.clone());
    (tx, queue)
}

/// Pump frames in both directions for one stream.
///
/// `key` is this side's name for the peer (see the module docs); `queue` is the
/// frame queue registered by [`path_channel`]; `inbound` is where received frames
/// go. Split out from the two callers so the carriage itself can be driven — and
/// tested — without a listener, a node or a `RxContext`.
async fn carry<S>(
    stream: S,
    key: SocketAddr,
    mut queue: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound: mpsc::UnboundedSender<Inbound>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = queue.recv().await {
            if let Err(e) = front::write_frame(&mut writer, &frame).await {
                tracing::debug!(peer = %key, error = %e, "REALITY front: write failed");
                return;
            }
        }
    });

    loop {
        match front::read_frame(&mut reader).await {
            Ok(Some(frame)) => {
                // Learn the mapping before handing the frame on: the dispatcher
                // runs on its own task and may reply as soon as it has the frame.
                let session = net::parse_session_hash(&frame);
                if session != [0, 0, 0, 0] {
                    sessions().insert(session, key);
                }
                if inbound.send((frame, key)).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(peer = %key, error = %e, "REALITY front: read failed");
                break;
            }
        }
    }

    paths().remove(&key);
    sessions().retain(|_, addr| *addr != key);
    writer_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A front whose borrowed origin is a closed local port: an unauthenticated
    /// probe is spliced to it, the splice fails at once, and no DNS lookup is
    /// involved. The certificate is generated for that name.
    fn test_front() -> FrontConfig {
        FrontConfig {
            listen: "127.0.0.1:0".parse().expect("bind address"),
            origin: BorrowedOrigin {
                host: "127.0.0.1".into(),
                port: 9,
                sni: "127.0.0.1".into(),
            },
            admission: Admission::SniLabel("tok".into()),
        }
    }

    async fn serve_one(cfg: FrontConfig) -> (SocketAddr, mpsc::Receiver<Admitted>) {
        let listener = FrontListener::bind(cfg).await.expect("the front binds");
        let addr = listener.local_addr().expect("a local address");
        let (tx, rx) = mpsc::channel::<Admitted>(4);
        tokio::spawn(async move {
            let _ = listener.run(tx).await;
        });
        (addr, rx)
    }

    #[test]
    fn dialing_is_opt_in_and_defaults_to_the_documented_port() {
        assert!(!dial_enabled_for(None));
        assert!(!dial_enabled_for(Some("0")));
        assert!(dial_enabled_for(Some("1")));
        assert!(dial_enabled_for(Some("TRUE")));
        assert_eq!(dial_port_from(None), 8443);
        assert_eq!(dial_port_from(Some("9443")), 9443);
        assert_eq!(
            dial_port_from(Some("nonsense")),
            8443,
            "a bad value is not port 0"
        );
        assert_eq!(dial_port_from(Some("0")), 8443);
        assert_eq!(dial_sni("tok", "origin.example"), "tok.origin.example");
    }

    /// A knock PSK admits without a label, which is exactly why a peer's dialer
    /// cannot reach such a front: the mode that it advertises must reflect that.
    #[test]
    fn a_knock_psk_is_knock_only_and_a_bad_one_falls_back_to_the_label() {
        let psk = "5a".repeat(32);
        assert!(matches!(
            admission_from(Some(&psk), Some("tok")),
            Some(Admission::Knock(_))
        ));
        assert_eq!(parse_knock_psk(&psk), Some([0x5A; 32]));

        // Broken keys never leave the front unauthenticated: the label is used.
        for bad in ["", "not-hex", "5a", &"5a".repeat(31)] {
            assert_eq!(parse_knock_psk(bad), None, "{bad:?} is not a 32-byte key");
            assert!(matches!(
                admission_from(Some(bad), Some("tok")),
                Some(Admission::SniLabel(t)) if t == "tok"
            ));
            assert!(admission_from(Some(bad), None).is_none());
        }

        assert!(matches!(
            admission_from(None, Some("tok")),
            Some(Admission::SniLabel(_))
        ));
        assert!(admission_from(None, None).is_none());
    }

    /// The whole outbound half against real TLS: a label-admitted front accepts a
    /// dial, and frames cross in both directions over the stream — address-keyed
    /// one way, session-hash-keyed the other, exactly as `srtp::send_v2` sends.
    #[tokio::test]
    async fn a_dialed_front_admits_real_tls_and_carries_frames_both_ways() {
        let (addr, mut admitted) = serve_one(test_front()).await;

        // A DNS name, as a real front's borrowed origin is: `dial` refuses a
        // syntactically invalid SNI, and the label check would never be reached.
        let dialed = tokio::time::timeout(
            Duration::from_secs(15),
            front::dial(addr, &dial_sni("tok", "origin.test")),
        )
        .await
        .expect("the dial must not hang")
        .expect("the label admits the dial");
        let conn = tokio::time::timeout(Duration::from_secs(15), admitted.recv())
            .await
            .expect("a stream is admitted")
            .expect("the channel stays open");

        // The daemon's name for each side: the peer's UDP address on the dialing
        // side, the connection's remote address on the listening side.
        let peer_udp: SocketAddr = "127.0.0.1:55225".parse().expect("peer address");
        let session = [0xA1u8, 0xB2, 0xC3, 0xD4];
        let (server_tx, mut server_in) = mpsc::unbounded_channel::<Inbound>();
        let (client_tx, mut client_in) = mpsc::unbounded_channel::<Inbound>();
        let (_, server_queue) = path_channel(conn.peer);
        let (_, client_queue) = path_channel(peer_udp);
        let server = tokio::spawn(carry(conn.stream, conn.peer, server_queue, server_tx));
        let client = tokio::spawn(carry(dialed, peer_udp, client_queue, client_tx));

        // A frame shaped like a GTFv2 datagram: session hash at offset 0.
        let mut frame = vec![0u8; 96];
        frame[..4].copy_from_slice(&session);
        frame[4..].fill(0x5A);

        // Address-keyed: the send path holds only the peer's UDP address.
        assert!(
            try_send(&peer_udp, &frame),
            "the dialed stream is the path for this peer"
        );
        let (arrived, src) = tokio::time::timeout(Duration::from_secs(10), server_in.recv())
            .await
            .expect("the frame crosses the TLS stream")
            .expect("the sink stays open");
        assert_eq!(arrived, frame, "bytes are carried unchanged");
        assert_eq!(
            src, conn.peer,
            "the listener names the dialer by the connection it accepted"
        );

        // Hash-keyed: the listening side replies knowing only the session hash.
        let elsewhere: SocketAddr = "203.0.113.9:55225".parse().expect("unrelated address");
        assert!(
            !paths().contains_key(&elsewhere),
            "the reply address is not a registered path"
        );
        assert!(carries(&elsewhere, &session), "the session is carried");
        assert!(
            try_send(&elsewhere, &frame),
            "the session hash finds the stream"
        );
        let (answered, answered_src) =
            tokio::time::timeout(Duration::from_secs(10), client_in.recv())
                .await
                .expect("the reply crosses back")
                .expect("the sink stays open");
        assert_eq!(answered, frame);
        assert_eq!(
            answered_src, peer_udp,
            "the dialer names the listener by the peer's UDP address"
        );

        // `carries` gates the relay bypass in `send3_adaptive`: with no stream for
        // this peer it must stay false, so a relay is still used where one is needed.
        assert!(!carries(&elsewhere, &[0, 0, 0, 0]));
        assert!(!carries(
            &"198.51.100.7:55225".parse().expect("addr"),
            &[9, 9, 9, 9]
        ));

        server.abort();
        client.abort();
        paths().remove(&peer_udp);
        paths().remove(&conn.peer);
        sessions().remove(&session);
    }

    /// A probe without the label is spliced to the borrowed origin, never admitted:
    /// the dialer's handshake therefore fails and nothing reaches the tunnel.
    #[tokio::test]
    async fn an_unlabelled_dial_is_spliced_not_admitted() {
        let (addr, mut admitted) = serve_one(test_front()).await;
        let attempt = tokio::time::timeout(
            Duration::from_secs(15),
            front::dial(addr, &dial_sni("wrong", "origin.test")),
        )
        .await
        .expect("the dial must not hang");
        assert!(attempt.is_err(), "no TLS session with a spliced connection");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), admitted.recv())
                .await
                .is_err(),
            "the front admits nothing without the label"
        );
    }
}
