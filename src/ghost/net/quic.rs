//! QUIC as an optional transport under GTF.
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

use crate::ghost::layers::l0_identity::{
    pq_commitment, verify_peer_signature, verify_pq_signature, GhostIdentity, ED25519_SIG_LEN,
    ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN,
};

pub const QUIC_ALPN: &[u8] = b"h3";
pub const QUIC_DEFAULT_PORT: u16 = 2271;
pub const ID_BINDING_LABEL: &[u8] = b"ggn-quic-identity-binding";
pub const BINDING_VERSION_HYBRID: u8 = 2;
pub const BINDING_LEN_V1: usize = 96;
pub const BINDING_LEN_V2: usize = 1 + 32 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;
pub const MAX_STREAM_FRAME: usize = 64 * 1024;
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
    #[error("the peer proved only its classical identity (a v1 binding)")]
    ClassicalOnlyBinding,
    #[error("the peer's identity is not one we know: {0}")]
    UnknownPeer(String),
    #[error("frame of {0} bytes exceeds the {1}-byte stream limit")]
    FrameTooLarge(usize, usize),
    #[error("the link is closed")]
    Closed,
}

impl QuicError {
    fn from_datagram(e: quinn::SendDatagramError) -> Self {
        match e {
            quinn::SendDatagramError::ConnectionLost(c) => QuicError::Connection(c),
            other => QuicError::Datagram(other),
        }
    }
}

const DATAGRAM_ROOM_TIMEOUT: Duration = Duration::from_millis(50);

pub use super::CarrierPath as FramePath;

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

pub fn identity_certificate(
    identity: &GhostIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), QuicError> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

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

fn binding_material(channel_binding: &[u8], pq_pk: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(channel_binding.len() + pq_pk.len());
    msg.extend_from_slice(channel_binding);
    msg.extend_from_slice(pq_pk);
    msg
}

pub fn identity_binding(identity: &GhostIdentity, channel_binding: &[u8]) -> Vec<u8> {
    let pq_pk = identity.pq_public_key_bytes();
    let sig = identity.sign_hybrid(&binding_material(channel_binding, &pq_pk));
    let mut msg = Vec::with_capacity(BINDING_LEN_V2);
    msg.push(BINDING_VERSION_HYBRID);
    msg.extend_from_slice(&identity.public_key_bytes());
    msg.extend_from_slice(&pq_pk);
    msg.extend_from_slice(&sig.ed25519);
    msg.extend_from_slice(&sig.pq);
    msg
}

fn verify_binding(binding: &[u8], channel_binding: &[u8]) -> Result<(String, [u8; 32]), QuicError> {
    if binding.len() == BINDING_LEN_V1 {
        return Err(QuicError::ClassicalOnlyBinding);
    }
    if binding.len() != BINDING_LEN_V2 || binding[0] != BINDING_VERSION_HYBRID {
        return Err(QuicError::UnprovenIdentity);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&binding[1..33]);
    let pq_pk = &binding[33..33 + ML_DSA_65_PK_LEN];
    let ed_sig = &binding[33 + ML_DSA_65_PK_LEN..33 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN];
    let pq_sig = &binding[33 + ML_DSA_65_PK_LEN + ED25519_SIG_LEN..];

    let Ok(ed_sig) = <&[u8; ED25519_SIG_LEN]>::try_from(ed_sig) else {
        return Err(QuicError::UnprovenIdentity);
    };
    let msg = binding_material(channel_binding, pq_pk);
    if !verify_peer_signature(&pk, &msg, ed_sig) {
        return Err(QuicError::UnprovenIdentity);
    }
    if !verify_pq_signature(pq_pk, &msg, pq_sig) {
        return Err(QuicError::UnprovenIdentity);
    }
    Ok((hex::encode(&pk[..8]), pq_commitment(pq_pk)))
}

pub fn verify_identity_binding(
    expected_fp: &str,
    binding: &[u8],
    channel_binding: &[u8],
) -> Result<String, QuicError> {
    let (got, _) = verify_binding(binding, channel_binding)?;
    if got != expected_fp {
        return Err(QuicError::WrongIdentity {
            expected: expected_fp.to_string(),
            got,
        });
    }
    Ok(got)
}

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
    t.datagram_send_buffer_size(4 * INGRESS_QUEUE * 64)
        .datagram_receive_buffer_size(Some(4 * INGRESS_QUEUE * 64))
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap_or_default()))
        .keep_alive_interval(Some(Duration::from_secs(15)));
    Arc::new(t)
}

pub struct QuicTransport {
    endpoint: Endpoint,
    identity: Arc<GhostIdentity>,
}

impl QuicTransport {
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
    pub fn client(identity: Arc<GhostIdentity>) -> Result<Self, QuicError> {
        Self::client_bound("0.0.0.0:0".parse().expect("valid bind"), identity)
    }

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

    pub fn identity(&self) -> &Arc<GhostIdentity> {
        &self.identity
    }

    pub fn is_named_path(&self) -> bool {
        self.endpoint
            .local_addr()
            .map(|a| !a.ip().is_unspecified())
            .unwrap_or(false)
    }

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
        let path = endpoint_path(&self.endpoint);
        QuicLink::establish(conn, Arc::clone(&self.identity), Some(expected_fp), path).await
    }

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
            endpoint_path(&self.endpoint),
        )
        .await?;
        Ok(link)
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

pub struct QuicLink {
    conn: Connection,
    peer_fp: String,
    peer_pq_commitment: [u8; 32],
    local: std::net::IpAddr,
    max_datagram: usize,
    stats: Arc<LinkStats>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    _reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for QuicLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicLink")
            .field("peer", &self.peer_fp)
            .field("local", &self.local)
            .field("max_datagram", &self.max_datagram)
            .field("closed", &self.is_closed())
            .finish()
    }
}

fn endpoint_path(endpoint: &Endpoint) -> Option<std::net::IpAddr> {
    endpoint
        .local_addr()
        .ok()
        .map(|a| a.ip())
        .filter(|ip| !ip.is_unspecified())
}

impl QuicLink {
    async fn establish(
        conn: Connection,
        identity: Arc<GhostIdentity>,
        expected_fp: Option<&str>,
        path: Option<std::net::IpAddr>,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let binding = channel_binding(&conn)?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&identity_binding(&identity, &binding))
            .await?;
        send.finish()?;
        let peer = recv
            .read_to_end(BINDING_LEN_V2 + 1)
            .await
            .map_err(|e| QuicError::Binding(e.to_string()))?;
        let expected = expected_fp.ok_or(QuicError::UnprovenIdentity)?;
        let (peer_fp, peer_pq_commitment) = verify_binding(&peer, &binding)?;
        if peer_fp != expected {
            return Err(QuicError::WrongIdentity {
                expected: expected.to_string(),
                got: peer_fp,
            });
        }
        debug!(peer = %peer_fp, "QUIC: identity bound to the TLS session");
        Self::finish(conn, peer_fp, peer_pq_commitment, path).await
    }

    async fn establish_accepted(
        conn: Connection,
        identity: Arc<GhostIdentity>,
        is_known: Box<dyn Fn(&str) -> bool + Send + Sync>,
        path: Option<std::net::IpAddr>,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let binding = channel_binding(&conn)?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let peer = recv
            .read_to_end(BINDING_LEN_V2 + 1)
            .await
            .map_err(|e| QuicError::Binding(e.to_string()))?;
        let (peer_fp, peer_pq_commitment) = verify_binding(&peer, &binding)?;
        if !is_known(&peer_fp) {
            warn!(peer = %peer_fp, "QUIC: refusing a connection from an unknown identity");
            return Err(QuicError::UnknownPeer(peer_fp));
        }
        send.write_all(&identity_binding(&identity, &binding))
            .await?;
        send.finish()?;
        debug!(peer = %peer_fp, "QUIC: identity bound to the TLS session (accepted)");
        Self::finish(conn, peer_fp, peer_pq_commitment, path).await
    }

    async fn finish(
        conn: Connection,
        peer_fp: String,
        peer_pq_commitment: [u8; 32],
        path: Option<std::net::IpAddr>,
    ) -> Result<Arc<QuicLink>, QuicError> {
        let local = path
            .or_else(|| conn.local_ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let max_datagram = conn.max_datagram_size().unwrap_or(0);
        let (tx, rx) = mpsc::channel(INGRESS_QUEUE);
        let stats = Arc::new(LinkStats::default());
        let reader = spawn_reader(conn.clone(), tx, Arc::clone(&stats));
        Ok(Arc::new(QuicLink {
            conn,
            peer_fp,
            peer_pq_commitment,
            local,
            max_datagram,
            stats,
            inbound: tokio::sync::Mutex::new(rx),
            _reader: reader,
        }))
    }

    pub fn peer_fingerprint(&self) -> &str {
        &self.peer_fp
    }

    pub fn peer_pq_commitment(&self) -> [u8; 32] {
        self.peer_pq_commitment
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    pub fn local_addr(&self) -> std::net::IpAddr {
        self.local
    }

    pub fn max_datagram(&self) -> usize {
        self.max_datagram
    }

    pub fn stats(&self) -> &Arc<LinkStats> {
        &self.stats
    }

    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    pub async fn send_frame(&self, frame: &[u8]) -> Result<FramePath, QuicError> {
        let path = if frame.len() <= self.max_datagram && self.max_datagram > 0 {
            FramePath::Datagram
        } else {
            FramePath::Stream
        };
        self.send_frame_as(frame, path).await
    }

    pub async fn send_frame_as(
        &self,
        frame: &[u8],
        path: FramePath,
    ) -> Result<FramePath, QuicError> {
        if path == FramePath::Datagram {
            if frame.len() > self.max_datagram || self.max_datagram == 0 {
                return Err(QuicError::FrameTooLarge(frame.len(), self.max_datagram));
            }
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

    pub async fn recv_frame(&self) -> Option<Vec<u8>> {
        self.inbound.lock().await.recv().await
    }

    pub async fn closed(&self) {
        self.conn.closed().await;
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
    }
}

fn channel_binding(conn: &Connection) -> Result<[u8; 32], QuicError> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, ID_BINDING_LABEL, &[])
        .map_err(|_| QuicError::Binding("the session has no exportable keying material".into()))?;
    Ok(out)
}

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

pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;
pub const CONNECT_UDP_CONTEXT_ID_PAYLOAD: u64 = 0x00;
const QUIC_VARINT_MAX: u64 = (1 << 62) - 1;

pub fn encode_quic_varint(val: u64, out: &mut Vec<u8>) -> Result<(), QuicError> {
    if val > QUIC_VARINT_MAX {
        return Err(QuicError::Crypto(format!(
            "QUIC varint {val} exceeds 2^62 - 1"
        )));
    }
    if val < (1 << 6) {
        out.push(val as u8);
    } else if val < (1 << 14) {
        out.extend_from_slice(&((val as u16) | 0x4000).to_be_bytes());
    } else if val < (1 << 30) {
        out.extend_from_slice(&((val as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(val | 0xC000_0000_0000_0000).to_be_bytes());
    }
    Ok(())
}

pub fn decode_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3F) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | (b as u64);
    }
    Some((val, len))
}

pub fn encode_connect_udp_capsule(payload: &[u8]) -> Result<Vec<u8>, QuicError> {
    let mut context_id = Vec::with_capacity(1);
    encode_quic_varint(CONNECT_UDP_CONTEXT_ID_PAYLOAD, &mut context_id)?;
    let capsule_len = context_id.len() + payload.len();

    let mut out = Vec::with_capacity(2 + 4 + capsule_len);
    encode_quic_varint(CAPSULE_TYPE_DATAGRAM, &mut out)?;
    encode_quic_varint(capsule_len as u64, &mut out)?;
    out.extend_from_slice(&context_id);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_connect_udp_capsule(buf: &[u8]) -> Option<(&[u8], usize)> {
    let (capsule_type, type_len) = decode_quic_varint(buf)?;
    if capsule_type != CAPSULE_TYPE_DATAGRAM {
        return None;
    }
    let (capsule_len, len_len) = decode_quic_varint(&buf[type_len..])?;
    let header_len = type_len + len_len;
    let total_len = header_len.checked_add(usize::try_from(capsule_len).ok()?)?;
    if buf.len() < total_len {
        return None;
    }
    let capsule_val = &buf[header_len..total_len];
    let (context_id, ctx_len) = decode_quic_varint(capsule_val)?;
    if context_id != CONNECT_UDP_CONTEXT_ID_PAYLOAD {
        return None;
    }
    Some((&capsule_val[ctx_len..], total_len))
}

#[derive(Debug, Clone)]
pub struct RealityKnockConfig {
    pub server_public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub cover_origin: String,
    pub max_clock_skew_secs: u64,
}

impl Default for RealityKnockConfig {
    fn default() -> Self {
        Self {
            server_public_key: [0u8; 32],
            short_id: [0u8; 8],
            cover_origin: "www.cloudflare.com:443".to_string(),
            max_clock_skew_secs: 120,
        }
    }
}

fn derive_reality_knock_key(shared_secret: &[u8; 32], short_id: &[u8; 8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(short_id), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"ggn-reality-knock-v1", &mut key)
        .expect("32-byte HKDF-SHA256 output is valid");
    key
}

pub fn build_reality_knock(
    client_ephemeral_secret: &x25519_dalek::StaticSecret,
    server_public_key: &[u8; 32],
    short_id: &[u8; 8],
    timestamp_secs: u64,
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let server_pub = x25519_dalek::PublicKey::from(*server_public_key);
    let shared = client_ephemeral_secret.diffie_hellman(&server_pub);
    let knock_key = derive_reality_knock_key(shared.as_bytes(), short_id);

    let ts_bytes = timestamp_secs.to_be_bytes();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&knock_key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(&ts_bytes);
    mac.update(short_id);
    let tag = mac.finalize().into_bytes();

    let mut knock = [0u8; 32];
    for i in 0..8 {
        knock[i] = ts_bytes[i] ^ knock_key[i];
    }
    knock[8..32].copy_from_slice(&tag[..24]);
    knock
}

pub fn verify_reality_knock(
    server_secret: &x25519_dalek::StaticSecret,
    client_ephemeral_pub: &[u8; 32],
    legacy_session_id: &[u8; 32],
    short_id: &[u8; 8],
    now_secs: u64,
    max_skew_secs: u64,
) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    let client_pub = x25519_dalek::PublicKey::from(*client_ephemeral_pub);
    let shared = server_secret.diffie_hellman(&client_pub);
    let knock_key = derive_reality_knock_key(shared.as_bytes(), short_id);

    let mut ts_bytes = [0u8; 8];
    for i in 0..8 {
        ts_bytes[i] = legacy_session_id[i] ^ knock_key[i];
    }
    let ts = u64::from_be_bytes(ts_bytes);
    if now_secs.abs_diff(ts) > max_skew_secs {
        return false;
    }

    let mut mac =
        Hmac::<Sha256>::new_from_slice(&knock_key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(&ts_bytes);
    mac.update(short_id);
    let expected_tag = mac.finalize().into_bytes();

    legacy_session_id[8..32].ct_eq(&expected_tag[..24]).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_is_built_from_the_identity_key() {
        let identity = GhostIdentity::generate_fresh();
        let (chain, _key) = identity_certificate(&identity).expect("a certificate");
        assert_eq!(chain.len(), 1);
        assert!(chain[0].len() > 64, "a real DER certificate");
        let pk = identity.public_key_bytes();
        assert!(
            chain[0].windows(32).any(|w| w == pk),
            "the certificate must carry the identity's public key"
        );
    }

    #[test]
    fn a_binding_proves_possession_of_both_identity_keys() {
        let identity = GhostIdentity::generate_fresh();
        let fp = identity.fingerprint();
        let binding = identity_binding(&identity, b"session-binding");
        assert_eq!(binding.len(), BINDING_LEN_V2);
        assert_eq!(binding[0], BINDING_VERSION_HYBRID);
        assert_eq!(
            verify_identity_binding(&fp, &binding, b"session-binding").unwrap(),
            fp
        );

        assert!(matches!(
            verify_identity_binding(&fp, &binding, b"another-session"),
            Err(QuicError::UnprovenIdentity)
        ));
        let other = GhostIdentity::generate_fresh();
        assert!(matches!(
            verify_identity_binding(&other.fingerprint(), &binding, b"session-binding"),
            Err(QuicError::WrongIdentity { .. })
        ));
        assert!(matches!(
            verify_identity_binding(&fp, &binding[..40], b"session-binding"),
            Err(QuicError::UnprovenIdentity)
        ));
        let mut swapped_pq = binding.clone();
        let foreign = other.pq_public_key_bytes();
        swapped_pq[33..33 + ML_DSA_65_PK_LEN].copy_from_slice(&foreign);
        assert!(matches!(
            verify_identity_binding(&fp, &swapped_pq, b"session-binding"),
            Err(QuicError::UnprovenIdentity)
        ));
        let mut bad_pq_sig = binding.clone();
        let last = bad_pq_sig.len() - 1;
        bad_pq_sig[last] ^= 0x01;
        assert!(matches!(
            verify_identity_binding(&fp, &bad_pq_sig, b"session-binding"),
            Err(QuicError::UnprovenIdentity)
        ));
        let mut bad_ed_sig = binding.clone();
        let ed_off = 33 + ML_DSA_65_PK_LEN;
        bad_ed_sig[ed_off] ^= 0x01;
        assert!(matches!(
            verify_identity_binding(&fp, &bad_ed_sig, b"session-binding"),
            Err(QuicError::UnprovenIdentity)
        ));
    }

    #[test]
    fn a_classical_only_binding_is_refused() {
        let identity = GhostIdentity::generate_fresh();
        let fp = identity.fingerprint();
        let mut v1 = Vec::with_capacity(BINDING_LEN_V1);
        v1.extend_from_slice(&identity.public_key_bytes());
        v1.extend_from_slice(&identity.sign(b"session-binding").to_bytes());
        assert_eq!(v1.len(), BINDING_LEN_V1);
        assert!(matches!(
            verify_identity_binding(&fp, &v1, b"session-binding"),
            Err(QuicError::ClassicalOnlyBinding)
        ));
    }

    #[test]
    fn alpn_is_standard_h3() {
        assert_eq!(QUIC_ALPN, b"h3");
    }

    #[test]
    fn connect_udp_capsule_roundtrip() {
        let payload = b"gtf-v3-encrypted-frame-payload";
        let capsule = encode_connect_udp_capsule(payload).expect("encode capsule");
        let (decoded, consumed) = decode_connect_udp_capsule(&capsule).expect("decode capsule");
        assert_eq!(consumed, capsule.len());
        assert_eq!(decoded, payload);
        assert!(decode_connect_udp_capsule(&capsule[..capsule.len() - 1]).is_none());
    }

    #[test]
    fn reality_knock_verifies_and_rejects_probes() {
        let server_secret = x25519_dalek::StaticSecret::from([7u8; 32]);
        let server_pub = x25519_dalek::PublicKey::from(&server_secret);
        let client_secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let client_pub = x25519_dalek::PublicKey::from(&client_secret);
        let short_id = *b"ggn-test";
        let now = 1_700_000_000u64;

        let knock = build_reality_knock(&client_secret, server_pub.as_bytes(), &short_id, now);
        assert!(verify_reality_knock(
            &server_secret,
            client_pub.as_bytes(),
            &knock,
            &short_id,
            now + 5,
            120,
        ));
        assert!(!verify_reality_knock(
            &server_secret,
            client_pub.as_bytes(),
            &knock,
            &short_id,
            now + 300,
            120,
        ));
        let mut probe = knock;
        probe[15] ^= 0xFF;
        assert!(!verify_reality_knock(
            &server_secret,
            client_pub.as_bytes(),
            &probe,
            &short_id,
            now,
            120,
        ));
    }
}
