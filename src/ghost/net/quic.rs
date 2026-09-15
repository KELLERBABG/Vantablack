//! QUIC as an optional transport under GTF (SOTA P1-2).
//!
//! GTF stays exactly what it is on this path: the frames are the same sealed
//! privacy/bulk frames the UDP path carries, and the session layer's
//! authentication is unchanged. QUIC replaces only the *transport* — which is
//! what matters on a lossy or censored path, because QUIC's congestion control
//! and loss recovery are implemented over streams rather than inferred from a
//! packet counter, and its own encryption defeats a middlebox that inspects the
//! UDP payload.
//!
//! ## Two ways to carry a frame, chosen by size
//!
//! * **Datagrams** (RFC 9221) for the privacy path. They are unreliable and
//!   unordered by design, which is exactly right: the privacy path already
//!   tolerates a lost shard because it is (2,1) Reed-Solomon coded, and a
//!   retransmission would only add latency to bytes a peer can reconstruct.
//! * **Unidirectional streams** for the bulk path. A GTF bulk frame is 1472
//!   bytes and QUIC's datagram limit is MTU-bounded (≈1200 in practice), so a
//!   bulk frame *cannot* ride a datagram. Streams have no such limit and give
//!   the bulk path the reliable, in-order delivery it wants.
//!
//! `send_frame` picks between them and reports which, so a caller — and a
//! benchmark — can see the split rather than guess at it.
//!
//! ## What authenticates what
//!
//! The certificate is **self-signed and is deliberately not the trust anchor**.
//! Both ends run under a rustls verifier that accepts a self-signed chain,
//! because there is no PKI in a mesh and inventing one to carry traffic the mesh
//! already authenticates would be theatre. What actually binds the connection to
//! an identity is a **channel binding**:
//!
//! 1. Both ends derive keying material from the TLS session itself
//!    (`Connection::export_keying_material`, RFC 5705).
//! 2. Each end sends `[Ed25519 public key][signature over that keying material]`
//!    on a stream the peer reads before any data flows.
//! 3. Each end checks the signature *and* that the key belongs to the fingerprint
//!    the mesh layer already authenticated.
//!
//! A man in the middle who terminates TLS on both sides gets a *different*
//! channel binding on each side, so the two signatures cannot both be valid —
//! which is precisely the property a self-signed certificate alone cannot give.
//! Accepting the certificate therefore skips X.509 trust, not authentication.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use quinn::rustls::SignatureScheme;
use quinn::{Connection, Endpoint, TransportConfig};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::ghost::layers::l0_identity::{verify_peer_signature, GhostIdentity};

/// ALPN protocol identifier. A peer that does not offer it is not one of ours.
pub const QUIC_ALPN: &[u8] = b"ggn-quic-1";
/// Default UDP port for the QUIC transport (the mesh uses 2270).
pub const QUIC_DEFAULT_PORT: u16 = 2271;
/// Label for the identity channel binding (RFC 5705).
pub const ID_BINDING_LABEL: &[u8] = b"ggn-quic-identity-binding";
/// A binding message is an Ed25519 public key plus its signature.
pub const BINDING_LEN: usize = 96;
/// Largest frame accepted on a stream. Bounded so a hostile peer cannot make us
/// allocate without limit before any decryption has happened.
pub const MAX_STREAM_FRAME: usize = 64 * 1024;
/// How many received frames may queue before the ingress side drops. Dropping is
/// the right failure for the datagram path (the RS code recovers); the stream
/// path waits instead of dropping, because it promised delivery.
pub const INGRESS_QUEUE: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("QUIC TLS setup error: {0}")]
    Tls(#[from] quinn::rustls::Error),
    #[error("QUIC crypto setup error: {0}")]
    Crypto(String),
    #[error("QUIC stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("QUIC datagram send error: {0}")]
    Datagram(quinn::SendDatagramError),
    #[error("no room to send a {0}-byte frame within the congestion wait")]
    Congested(usize),
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate generation failed: {0}")]
    Certificate(String),
    #[error("channel binding failed: {0}")]
    Binding(String),
    #[error("the peer identified as {got}, not {expected}")]
    WrongIdentity { expected: String, got: String },
    #[error("the peer did not prove possession of its identity key")]
    UnprovenIdentity,
    #[error("the peer's identity is not one we know: {0}")]
    UnknownPeer(String),
    #[error("frame of {0} bytes exceeds the {1}-byte stream limit")]
    FrameTooLarge(usize, usize),
    #[error("the link is closed")]
    Closed,
}

impl QuicError {
    /// A datagram failure is only ever a connection failure underneath; saying so
    /// keeps the caller's retry decision meaningful.
    fn from_datagram(e: quinn::SendDatagramError) -> Self {
        match e {
            quinn::SendDatagramError::ConnectionLost(c) => QuicError::Connection(c),
            other => QuicError::Datagram(other),
        }
    }
}

/// How long a datagram may wait for room before the frame is reported as not
/// carried. Short on purpose: this is the privacy path's budget for one shard.
const DATAGRAM_ROOM_TIMEOUT: Duration = Duration::from_millis(50);

/// Which framing a frame actually left by.
///
/// The tunnel's own name for this decision (`net::CarrierPath`) is reused rather
/// than shadowed, so a caller can hold one value type whether or not this
/// transport is compiled in.
pub use super::CarrierPath as FramePath;

/// Per-link counters an operator (or a benchmark) can read.
#[derive(Debug, Default)]
pub struct LinkStats {
    pub datagrams_sent: AtomicU64,
    pub datagrams_recv: AtomicU64,
    pub stream_frames_sent: AtomicU64,
    pub stream_frames_recv: AtomicU64,
    pub datagrams_dropped: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
}

impl LinkStats {
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.datagrams_sent.load(Ordering::Relaxed),
            self.datagrams_recv.load(Ordering::Relaxed),
            self.stream_frames_sent.load(Ordering::Relaxed),
            self.stream_frames_recv.load(Ordering::Relaxed),
            self.datagrams_dropped.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_recv.load(Ordering::Relaxed),
        )
    }
}

/// A self-signed certificate built from the node's Ed25519 identity.
///
/// The key is the identity's own, so the certificate's subject key *is* the
/// fingerprint the mesh knows — which is what lets the binding below be checked
/// against it, and what makes the certificate a name rather than a secret.
pub fn identity_certificate(
    identity: &GhostIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), QuicError> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    // PKCS#8 v1 for Ed25519 is a fixed 48-byte wrapper around the 32-byte seed.
    let seed: [u8; 32] = identity.long_term_signing.to_bytes();
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend_from_slice(&seed);
    let key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.clone()),
        &PKCS_ED25519,
    )
    .map_err(|e| QuicError::Certificate(e.to_string()))?;

    let params = CertificateParams::new(vec![identity.fingerprint()])
        .map_err(|e| QuicError::Certificate(e.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| QuicError::Certificate(e.to_string()))?;
    Ok((
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
    ))
}

/// The message each end signs to bind its identity to this TLS session.
pub fn identity_binding(identity: &GhostIdentity, channel_binding: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BINDING_LEN);
    msg.extend_from_slice(&identity.public_key_bytes());
    msg.extend_from_slice(&identity.sign(channel_binding).to_bytes());
    msg
}

/// Verify a peer's binding against the fingerprint we expect.
pub fn verify_identity_binding(
    expected_fp: &str,
    binding: &[u8],
    channel_binding: &[u8],
) -> Result<String, QuicError> {
    if binding.len() != BINDING_LEN {
        return Err(QuicError::UnprovenIdentity);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&binding[..32]);
    let sig = &binding[32..];
    let got = hex::encode(&pk[..8]);
    if got != expected_fp {
        return Err(QuicError::WrongIdentity {
            expected: expected_fp.to_string(),
            got,
        });
    }
    let Ok(sig) = <&[u8; 64]>::try_from(sig) else {
        return Err(QuicError::UnprovenIdentity);
    };
    if !verify_peer_signature(&pk, channel_binding, sig) {
        return Err(QuicError::UnprovenIdentity);
    }
    Ok(got)
}

/// A rustls verifier that accepts a self-signed chain.
///
/// Documented rather than hidden: X.509 is not the trust anchor here (there is no
/// PKI in a mesh), and the identity is proven by the channel binding instead. The
/// signature *algorithms* are still verified normally, so a peer cannot negotiate
/// a scheme it cannot actually use.
#[derive(Debug)]
struct SelfSignedAccepted;

impl quinn::rustls::client::danger::ServerCertVerifier for SelfSignedAccepted {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<quinn::rustls::client::danger::ServerCertVerified, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        quinn::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &quinn::rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        quinn::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &quinn::rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        quinn::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    // Datagrams are unreliable by contract; make the buffers deep enough that a
    // burst is not dropped for want of room before the RS pool can use it.
    t.datagram_send_buffer_size(4 * INGRESS_QUEUE * 64)
        .datagram_receive_buffer_size(Some(4 * INGRESS_QUEUE * 64))
        // Idle: the mesh keeps sessions alive with its own keepalives, so a
        // QUIC connection that has gone quiet is genuinely gone.
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap_or_default()))
        .keep_alive_interval(Some(Duration::from_secs(15)));
    Arc::new(t)
}

/// A QUIC endpoint: the listening side, the dialling side, or both.
pub struct QuicTransport {
    endpoint: Endpoint,
    identity: Arc<GhostIdentity>,
}

impl QuicTransport {
    /// Listen for inbound QUIC connections.
    pub fn listen(bind: SocketAddr, identity: Arc<GhostIdentity>) -> Result<Self, QuicError> {
        let (chain, key) = identity_certificate(&identity)?;
        let mut tls = quinn::rustls::ServerConfig::builder_with_provider(Arc::new(
            quinn::rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
        tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| QuicError::Crypto(e.to_string()))?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport_config());
        let endpoint = Endpoint::server(config, bind)?;
        info!(local = %endpoint.local_addr()?, "QUIC: listening");
        Ok(QuicTransport { endpoint, identity })
    }
    /// A client endpoint, bound to an ephemeral local port.
    pub fn client(identity: Arc<GhostIdentity>) -> Result<Self, QuicError> {
        Self::client_bound("0.0.0.0:0".parse().expect("valid bind"), identity)
    }

    /// A client endpoint bound to a **specific local address**.
    ///
    /// This is what makes more than one path possible from one host: a Wi-Fi
    /// address and an LTE address each get their own endpoint, and therefore their
    /// own QUIC connection to the same peer. QUIC will not migrate a connection
    /// between them on its own — that is `multipath` in the transport's own terms,
    /// and what this crate does instead is open two connections and spread the
    /// Reed-Solomon shards across them, which is the same trick the shard router
    /// already plays across peers.
    pub fn client_bound(bind: SocketAddr, identity: Arc<GhostIdentity>) -> Result<Self, QuicError> {
        let mut tls = quinn::rustls::ClientConfig::builder_with_provider(Arc::new(
            quinn::rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SelfSignedAccepted))
        .with_no_client_auth();
        tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| QuicError::Crypto(e.to_string()))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport_config());
        let mut endpoint = Endpoint::client(bind)?;
        endpoint.set_default_client_config(config);
        Ok(QuicTransport { endpoint, identity })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn local_fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Dial a peer and prove both identities over the new session.
    pub async fn connect(
        &self,
        peer: SocketAddr,
        expected_fp: &str,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let conn = self
            .endpoint
            .connect(peer, "ggn")?
            .await
            .map_err(QuicError::Connection)?;
        QuicLink::establish(conn, Arc::clone(&self.identity), Some(expected_fp)).await
    }

    /// Accept one connection, refusing an identity the caller does not know.
    ///
    /// `is_known` is the caller's admission decision — in `main.rs` it is
    /// "a peer whose signed beacon we have verified", the same rule the relay
    /// uses, so a stranger cannot open a QUIC session just by reaching the port.
    pub async fn accept_one(
        &self,
        is_known: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| QuicError::Certificate("endpoint closed".into()))?;
        let conn = incoming.await.map_err(QuicError::Connection)?;
        let link = QuicLink::establish_accepted(
            conn,
            Arc::clone(&self.identity),
            Box::new(is_known),
            // The predicate arrives as one value to keep the call site simple.
        )
        .await?;
        Ok(link)
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

/// One established, identity-bound QUIC link.
///
/// Debug is hand-written because the useful facts about a link are its peer and
/// its datagram budget, not the internals of a live connection.
pub struct QuicLink {
    conn: Connection,
    peer_fp: String,
    max_datagram: usize,
    stats: Arc<LinkStats>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Kept so the stream reader can keep feeding `inbound`.
    _reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for QuicLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicLink")
            .field("peer", &self.peer_fp)
            .field("max_datagram", &self.max_datagram)
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl QuicLink {
    /// Dialled side: send our binding, check the peer's against `expected_fp`.
    async fn establish(
        conn: Connection,
        identity: Arc<GhostIdentity>,
        expected_fp: Option<&str>,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let binding = channel_binding(&conn)?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&identity_binding(&identity, &binding))
            .await?;
        send.finish()?;
        let peer = recv
            .read_to_end(BINDING_LEN + 1)
            .await
            .map_err(|e| QuicError::Binding(e.to_string()))?;
        let expected = expected_fp.ok_or(QuicError::UnprovenIdentity)?;
        let peer_fp = verify_identity_binding(expected, &peer, &binding)?;
        debug!(peer = %peer_fp, "QUIC: identity bound to the TLS session");
        Self::finish(conn, peer_fp).await
    }

    /// Accepted side: same exchange, with the caller's admission rule.
    async fn establish_accepted(
        conn: Connection,
        identity: Arc<GhostIdentity>,
        is_known: Box<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let binding = channel_binding(&conn)?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let peer = recv
            .read_to_end(BINDING_LEN + 1)
            .await
            .map_err(|e| QuicError::Binding(e.to_string()))?;
        if peer.len() != BINDING_LEN {
            return Err(QuicError::UnprovenIdentity);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&peer[..32]);
        let peer_fp = hex::encode(&pk[..8]);
        let Ok(sig) = <&[u8; 64]>::try_from(&peer[32..]) else {
            return Err(QuicError::UnprovenIdentity);
        };
        if !verify_peer_signature(&pk, &binding, sig) {
            return Err(QuicError::UnprovenIdentity);
        }
        if !is_known(&peer_fp) {
            warn!(peer = %peer_fp, "QUIC: refusing a connection from an unknown identity");
            return Err(QuicError::UnknownPeer(peer_fp));
        }
        send.write_all(&identity_binding(&identity, &binding))
            .await?;
        send.finish()?;
        debug!(peer = %peer_fp, "QUIC: identity bound to the TLS session (accepted)");
        Self::finish(conn, peer_fp).await
    }

    async fn finish(conn: Connection, peer_fp: String) -> Result<Arc<QuicLink>, QuicError> {
        let max_datagram = conn.max_datagram_size().unwrap_or(0);
        let (tx, rx) = mpsc::channel(INGRESS_QUEUE);
        let stats = Arc::new(LinkStats::default());
        let reader = spawn_reader(conn.clone(), tx, Arc::clone(&stats));
        Ok(Arc::new(QuicLink {
            conn,
            peer_fp,
            max_datagram,
            stats,
            inbound: tokio::sync::Mutex::new(rx),
            _reader: reader,
        }))
    }

    pub fn peer_fingerprint(&self) -> &str {
        &self.peer_fp
    }

    /// The peer's address as QUIC sees it. Data ingress keys tunnel state on an
    /// address, and the only honest one to offer is where the frames came from.
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Largest frame QUIC will carry as a datagram right now.
    pub fn max_datagram(&self) -> usize {
        self.max_datagram
    }

    pub fn stats(&self) -> &Arc<LinkStats> {
        &self.stats
    }

    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    /// Send one GTF frame, choosing the framing by size.
    ///
    /// A frame that fits a datagram goes as one: the privacy path is Reed-Solomon
    /// coded, so an unreliable carrier is what it expects. Anything larger goes
    /// on its own unidirectional stream, where delivery is ordered and reliable.
    /// A caller that wants a specific framing calls `send_frame_as`.
    pub async fn send_frame(&self, frame: &[u8]) -> Result<FramePath, QuicError> {
        let path = if frame.len() <= self.max_datagram && self.max_datagram > 0 {
            FramePath::Datagram
        } else {
            FramePath::Stream
        };
        self.send_frame_as(frame, path).await
    }

    /// Send one frame with the framing held fixed.
    ///
    /// `send_frame` picks by size, which is the right default. A caller with an
    /// opinion needs the lever too: a bulk transfer may want reliability even for
    /// a frame that would fit a datagram, and a benchmark has to hold the framing
    /// still to compare two carriers on equal terms.
    pub async fn send_frame_as(
        &self,
        frame: &[u8],
        path: FramePath,
    ) -> Result<FramePath, QuicError> {
        if path == FramePath::Datagram {
            if frame.len() > self.max_datagram || self.max_datagram == 0 {
                return Err(QuicError::FrameTooLarge(frame.len(), self.max_datagram));
            }
            // `send_datagram` never blocks: it makes room by discarding the
            // oldest *queued* datagrams, which would silently turn this carrier
            // back into the lossy one it was chosen to improve on. `wait`
            // prioritises the frames already queued instead — bounded, because a
            // frame that cannot go promptly is a frame the peer's pool is waiting
            // on, and the UDP path is right there.
            let bytes = bytes::Bytes::copy_from_slice(frame);
            match tokio::time::timeout(DATAGRAM_ROOM_TIMEOUT, self.conn.send_datagram_wait(bytes))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(QuicError::from_datagram(e)),
                Err(_elapsed) => return Err(QuicError::Congested(frame.len())),
            }
            self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
            return Ok(FramePath::Datagram);
        }
        if frame.len() > MAX_STREAM_FRAME {
            return Err(QuicError::FrameTooLarge(frame.len(), MAX_STREAM_FRAME));
        }
        // One frame per stream: a stream boundary is the frame boundary, so a
        // truncated frame can never be mistaken for a short one.
        let mut send = self.conn.open_uni().await?;
        send.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        send.write_all(frame).await?;
        send.finish()?;
        self.stats
            .stream_frames_sent
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        Ok(FramePath::Stream)
    }

    /// The next frame the peer sent, datagram or stream.
    pub async fn recv_frame(&self) -> Option<Vec<u8>> {
        // A closed link is not an error the caller can act on — the tunnel simply
        // stops receiving from it, exactly as it would from a dead UDP path.
        self.inbound.lock().await.recv().await
    }

    /// Wait until the peer closes the connection.
    pub async fn closed(&self) {
        self.conn.closed().await;
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
    }
}

/// Derive the channel binding both ends will see identically.
fn channel_binding(conn: &Connection) -> Result<[u8; 32], QuicError> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, ID_BINDING_LABEL, &[])
        .map_err(|_| QuicError::Binding("the session has no exportable keying material".into()))?;
    Ok(out)
}

/// Read datagrams and stream frames into one queue.
///
/// Both sources share a queue because the receive path does not care which
/// carrier a frame arrived on — the GTF header is the same either way — and
/// because ordering between the two is meaningless: a datagram may be lost and a
/// stream frame may be late, which the RS pool and the replay window already
/// handle.
fn spawn_reader(
    conn: Connection,
    tx: mpsc::Sender<Vec<u8>>,
    stats: Arc<LinkStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                d = conn.read_datagram() => match d {
                    Ok(d) => {
                        stats.datagrams_recv.fetch_add(1, Ordering::Relaxed);
                        stats.bytes_recv.fetch_add(d.len() as u64, Ordering::Relaxed);
                        // Datagrams may be dropped under pressure: the RS pool is
                        // what makes that safe, and blocking here would stall the
                        // streams sharing this task.
                        if tx.try_send(d.to_vec()).is_err() {
                            stats.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        debug!("QUIC: datagram read ended: {e}");
                        return;
                    }
                },
                uni = conn.accept_uni() => match uni {
                    Ok(mut recv) => {
                        let tx = tx.clone();
                        let stats = Arc::clone(&stats);
                        tokio::spawn(async move {
                            while let Ok(Some(frame)) = read_stream_frame(&mut recv).await {
                                stats.stream_frames_recv.fetch_add(1, Ordering::Relaxed);
                                stats.bytes_recv.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                // Streams promised delivery, so wait rather than
                                // drop: the queue is bounded and the sender is
                                // already flow-controlled by QUIC.
                                if tx.send(frame).await.is_err() {
                                    return;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        debug!("QUIC: stream accept ended: {e}");
                        return;
                    }
                },
                _ = conn.closed() => return,
            }
        }
    })
}

/// Read one length-prefixed frame from a stream.
async fn read_stream_frame(recv: &mut quinn::RecvStream) -> Result<Option<Vec<u8>>, QuicError> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
        Err(quinn::ReadExactError::ReadError(e)) => return Err(QuicError::Read(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_STREAM_FRAME {
        return Err(QuicError::FrameTooLarge(len, MAX_STREAM_FRAME));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => QuicError::Closed,
        quinn::ReadExactError::ReadError(e) => QuicError::Read(e),
    })?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_is_built_from_the_identity_key() {
        // The subject key IS the identity, which is what makes the binding
        // checkable against a fingerprint the mesh already knows.
        let identity = GhostIdentity::generate_fresh();
        let (chain, _key) = identity_certificate(&identity).expect("a certificate");
        assert_eq!(chain.len(), 1);
        assert!(chain[0].len() > 64, "a real DER certificate");
        // The 32-byte public key appears verbatim inside the DER (as the SPKI).
        let pk = identity.public_key_bytes();
        assert!(
            chain[0].windows(32).any(|w| w == pk),
            "the certificate must carry the identity's public key"
        );
    }

    #[test]
    fn a_binding_proves_possession_of_the_identity_key() {
        let identity = GhostIdentity::generate_fresh();
        let fp = identity.fingerprint();
        let binding = identity_binding(&identity, b"session-binding");
        assert_eq!(binding.len(), BINDING_LEN);
        assert_eq!(
            verify_identity_binding(&fp, &binding, b"session-binding").unwrap(),
            fp
        );

        // A signature over a different session is refused: this is the property
        // that makes a self-signed certificate safe to accept, because a MITM
        // terminating TLS on both sides cannot produce it.
        assert!(matches!(
            verify_identity_binding(&fp, &binding, b"another-session"),
            Err(QuicError::UnprovenIdentity)
        ));
        // So is someone else's identity.
        let other = GhostIdentity::generate_fresh();
        assert!(matches!(
            verify_identity_binding(&other.fingerprint(), &binding, b"session-binding"),
            Err(QuicError::WrongIdentity { .. })
        ));
        // And so is a truncated or absent proof.
        assert!(matches!(
            verify_identity_binding(&fp, &binding[..40], b"session-binding"),
            Err(QuicError::UnprovenIdentity)
        ));
    }
}
