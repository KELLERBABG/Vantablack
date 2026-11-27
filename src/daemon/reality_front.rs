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

type Inbound = (Vec<u8>, SocketAddr);

fn paths() -> &'static DashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> {
    static PATHS: OnceLock<DashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>> = OnceLock::new();
    PATHS.get_or_init(DashMap::new)
}

fn sessions() -> &'static DashMap<[u8; 4], SocketAddr> {
    static SESSIONS: OnceLock<DashMap<[u8; 4], SocketAddr>> = OnceLock::new();
    SESSIONS.get_or_init(DashMap::new)
}

fn ingress_cell() -> &'static OnceLock<mpsc::UnboundedSender<Inbound>> {
    static INGRESS: OnceLock<mpsc::UnboundedSender<Inbound>> = OnceLock::new();
    &INGRESS
}

fn ingress() -> Option<mpsc::UnboundedSender<Inbound>> {
    ingress_cell().get().cloned()
}

pub(crate) fn install_ingress(tx: mpsc::UnboundedSender<Inbound>) {
    let _ = ingress_cell().set(tx);
}

pub(crate) fn enabled() -> bool {
    std::env::var("GHOST_REALITY_FRONT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub(crate) fn dial_enabled() -> bool {
    dial_enabled_for(std::env::var("GHOST_REALITY_FRONT_DIAL").ok().as_deref())
}

fn dial_enabled_for(value: Option<&str>) -> bool {
    match value {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => false,
    }
}

pub(crate) fn dial_port() -> u16 {
    dial_port_from(std::env::var("GHOST_REALITY_FRONT_PORT").ok().as_deref())
}

fn dial_port_from(value: Option<&str>) -> u16 {
    value
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(8443)
}

fn dial_sni(token: &str, origin_sni: &str) -> String {
    format!("{token}.{origin_sni}")
}

fn label_token() -> Option<String> {
    std::env::var("GHOST_REALITY_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

fn dials() -> &'static DashMap<SocketAddr, ()> {
    static DIALS: OnceLock<DashMap<SocketAddr, ()>> = OnceLock::new();
    DIALS.get_or_init(DashMap::new)
}

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

fn admission() -> Option<Admission> {
    admission_from(
        std::env::var("GHOST_REALITY_KNOCK_PSK").ok().as_deref(),
        label_token().as_deref(),
    )
}

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

fn parse_knock_psk(raw: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).ok()?;
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(key)
}

pub(crate) fn knock_only() -> bool {
    matches!(admission(), Some(Admission::Knock(_)))
}

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

    #[test]
    fn a_knock_psk_is_knock_only_and_a_bad_one_falls_back_to_the_label() {
        let psk = "5a".repeat(32);
        assert!(matches!(
            admission_from(Some(&psk), Some("tok")),
            Some(Admission::Knock(_))
        ));
        assert_eq!(parse_knock_psk(&psk), Some([0x5A; 32]));

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

    #[tokio::test]
    async fn a_dialed_front_admits_real_tls_and_carries_frames_both_ways() {
        let (addr, mut admitted) = serve_one(test_front()).await;

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

        let peer_udp: SocketAddr = "127.0.0.1:55225".parse().expect("peer address");
        let session = [0xA1u8, 0xB2, 0xC3, 0xD4];
        let (server_tx, mut server_in) = mpsc::unbounded_channel::<Inbound>();
        let (client_tx, mut client_in) = mpsc::unbounded_channel::<Inbound>();
        let (_, server_queue) = path_channel(conn.peer);
        let (_, client_queue) = path_channel(peer_udp);
        let server = tokio::spawn(carry(conn.stream, conn.peer, server_queue, server_tx));
        let client = tokio::spawn(carry(dialed, peer_udp, client_queue, client_tx));

        let mut frame = vec![0u8; 96];
        frame[..4].copy_from_slice(&session);
        frame[4..].fill(0x5A);

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
