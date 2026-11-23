//! REALITY front: a real TLS 1.3 listener with a borrowed-origin splice.
//!
//! This is the transport `reality.rs` describes but deliberately did not
//! contain. The first bytes of every connection are a TLS ClientHello; the SNI
//! label is the knock:
//!
//! * `<token>.<origin>` — authenticated. The connection is terminated here with
//!   TLS 1.3 and carried into the tunnel (HTTP page, echo, or a MASQUE datagram
//!   capsule).
//! * anything else — spliced byte-for-byte to the borrowed origin, so an active
//!   prober completes a real TLS handshake with the real site and sees its real
//!   certificate. The listener never sends an alert or RST at the front door.
//!
//! The token travels in the SNI, which is visible on the wire exactly like any
//! other SNI; it is an admission label, not a confidentiality boundary. What
//! the tunnel carries is protected by the TLS 1.3 session itself.

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::ghost::v2::reality::{BorrowedOrigin, RealityKnock};

/// What the first ClientHello told us.
#[derive(Debug, Clone)]
pub struct HelloInfo {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub random: [u8; 32],
}

/// Parse the first TLS record far enough to read SNI, ALPN and the random.
pub fn parse_client_hello(buf: &[u8]) -> Option<HelloInfo> {
    if buf.len() < 6 || buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let hs = &buf[5..5 + record_len];
    if hs.first() != Some(&0x01) || hs.len() < 4 + 34 {
        return None;
    }
    let body = &hs[4..];
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[2..34]);
    let mut p = 34usize;
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs_len;
    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_total).min(body.len());
    let mut sni = None;
    let mut alpn = Vec::new();
    while p + 4 <= end {
        let kind = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let data = body.get(p + 4..p + 4 + len)?;
        match kind {
            0x0000 => {
                // server_name_list: u16 length, then entries.
                if data.len() >= 5 && data[2] == 0 {
                    let n = u16::from_be_bytes([data[3], data[4]]) as usize;
                    if let Some(name) = data.get(5..5 + n) {
                        sni = String::from_utf8(name.to_vec()).ok();
                    }
                }
            }
            0x0010 if data.len() >= 2 => {
                let mut q = 2usize;
                let list_end =
                    (2 + u16::from_be_bytes([data[0], data[1]]) as usize).min(data.len());
                while q < list_end {
                    let n = data[q] as usize;
                    q += 1;
                    if let Some(proto) = data.get(q..q + n) {
                        alpn.push(String::from_utf8_lossy(proto).into_owned());
                    }
                    q += n;
                }
            }
            _ => {}
        }
        p += 4 + len;
    }
    Some(HelloInfo { sni, alpn, random })
}

/// Read (without consuming) until a full ClientHello record is buffered.
async fn peek_hello(stream: &TcpStream) -> Option<HelloInfo> {
    let mut buf = vec![0u8; 16_384];
    for _ in 0..200 {
        let n = stream.peek(&mut buf).await.ok()?;
        if n >= 5 {
            let need = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if n >= need {
                if let Some(info) = parse_client_hello(&buf[..n]) {
                    return Some(info);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "pq-tls")]
    {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }
    #[cfg(not(feature = "pq-tls"))]
    {
        Arc::new(rustls::crypto::ring::default_provider())
    }
}

fn build_tls_config(origin_sni: &str) -> Result<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec![origin_sni.to_string()])
        .map_err(|e| anyhow!("certificate generation failed: {e}"))?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 1.3 config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|e| anyhow!("server certificate: {e}"))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

fn http_page(sni: &str, version: &str, cipher: &str) -> String {
    let body = format!(
        "<!doctype html><title>Vantablack REALITY tunnel</title>\
         <h1>REALITY tunnel</h1><p>SNI: {sni}</p><p>Protocol: {version}</p><p>Cipher: {cipher}</p>"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

async fn serve_tunnel(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    sni: &str,
) -> Result<()> {
    let (version, cipher) = {
        let (_, session) = tls.get_ref();
        let version = session
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "none".into());
        let cipher = session
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_else(|| "none".into());
        (version, cipher)
    };
    println!("REALITY tunnel  sni={sni} version={version} cipher={cipher}");

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .context("tunnel read timed out")??;
    let request = &buf[..n];
    let reply: Vec<u8> = if request.starts_with(b"GET ")
        || request.starts_with(b"POST ")
        || request.starts_with(b"HEAD ")
    {
        http_page(sni, &version, &cipher).into_bytes()
    } else if let Some(hex) = request.strip_prefix(b"CAPSULE ") {
        // RFC 9297 datagram capsule: decode, prove the payload crossed, wrap the
        // answer in a capsule of the same framing.
        let hex = String::from_utf8_lossy(hex).trim().to_string();
        let raw = hex::decode(&hex).unwrap_or_default();
        match crate::ghost::v2::reality::decode_datagram_capsule(&raw) {
            Some(payload) => {
                let mut answer = b"CAPSULE-ECHO:".to_vec();
                answer.extend_from_slice(payload);
                crate::ghost::v2::reality::encode_datagram_capsule(&answer).unwrap_or_default()
            }
            None => b"CAPSULE-BAD".to_vec(),
        }
    } else {
        let mut echo = b"FRONT-ECHO:".to_vec();
        echo.extend_from_slice(request);
        echo
    };
    tls.write_all(&reply).await?;
    tls.flush().await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// A TLS connection the front admitted to the tunnel.
///
/// The listener does not decide what an admitted stream carries: it hands the
/// established TLS session to whoever consumes the channel. `run_cli` serves the
/// demo page/echo; the daemon bridges GTFv2 frames (see `daemon::reality_front`).
pub struct Admitted {
    pub stream: tokio_rustls::server::TlsStream<TcpStream>,
    pub sni: String,
    pub peer: SocketAddr,
}

/// How the front decides whether a probe is a peer.
#[derive(Clone)]
pub enum Admission {
    /// Legacy: the first SNI label is the shared token in cleartext.
    SniLabel(String),
    /// Hidden knock: the token rides in the ClientHello random field.
    Knock(RealityKnock),
}

/// Everything a front listener needs.
pub struct FrontConfig {
    pub listen: SocketAddr,
    pub origin: BorrowedOrigin,
    pub admission: Admission,
}

/// Build the TLS 1.3 acceptor the front presents.
pub fn tls_acceptor(origin_sni: &str) -> Result<TlsAcceptor> {
    let cfg = Arc::new(build_tls_config(origin_sni)?);
    Ok(TlsAcceptor::from(cfg))
}

/// Derive the 32-byte value a hidden knock is bound to.
///
/// The ClientHello random field is 32 bytes, and the knock blob is 24, so the
/// client picks the **last 8 bytes** freely, derives the token over those (plus
/// the SNI and the timestamp), and then writes the 24-byte token over the first
/// 24 bytes — which leaves the tail it was bound to untouched and recoverable on
/// the receiving side. Without that rule a token placed inside the random would
/// be bound to itself and could never verify.
pub fn knock_binding(random: &[u8; 32]) -> [u8; 32] {
    let mut bound = [0u8; 32];
    for i in 0..4 {
        bound[i * 8..i * 8 + 8].copy_from_slice(&random[24..32]);
    }
    bound
}

/// The 24-byte hidden knock for this hello.
pub fn knock_token(knock: &RealityKnock, sni: &str, random: &[u8; 32], now: u64) -> [u8; 24] {
    knock.token(sni, &knock_binding(random), now)
}

/// Whether a hello's random field carries a valid hidden knock.
pub fn knock_admits(knock: &RealityKnock, sni: &str, random: &[u8; 32], now: u64) -> bool {
    knock.verify(sni, &knock_binding(random), &random[..24], now)
}

impl Admission {
    /// Whether the picked-apart hello is a peer.
    fn admits(&self, hello: &HelloInfo, now: u64) -> bool {
        match self {
            Admission::SniLabel(token) => hello
                .sni
                .as_deref()
                .and_then(|sni| sni.split('.').next())
                .map(|label| label == token.as_str())
                .unwrap_or(false),
            Admission::Knock(knock) => hello
                .sni
                .as_deref()
                .map(|sni| knock_admits(knock, sni, &hello.random, now))
                .unwrap_or(false),
        }
    }
}

/// Parse `host[:port]` into a borrowed origin (port 443 when omitted).
fn origin_from_addr(raw: &str) -> BorrowedOrigin {
    match raw.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => BorrowedOrigin {
            host: host.to_string(),
            port: port.parse().unwrap_or(443),
            sni: host.to_string(),
        },
        _ => BorrowedOrigin::new(raw),
    }
}

/// A bound REALITY front listener.
pub struct FrontListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    peer: &'static str,
    origin_host: String,
    origin_port: u16,
    admission: Admission,
}

impl FrontListener {
    /// Bind the listener. The TLS certificate is issued for the borrowed origin's
    /// SNI, so a prober sees the certificate of the site it asked for.
    pub async fn bind(cfg: FrontConfig) -> Result<Self> {
        let acceptor = tls_acceptor(&cfg.origin.sni)?;
        let listener = TcpListener::bind(cfg.listen)
            .await
            .with_context(|| format!("cannot bind REALITY front on {}", cfg.listen))?;
        let admission = cfg.admission;
        let peer = if matches!(admission, Admission::Knock(_)) {
            "hidden knock"
        } else {
            "SNI label"
        };
        Ok(Self {
            listener,
            acceptor,
            peer,
            origin_host: cfg.origin.host,
            origin_port: cfg.origin.port,
            admission,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn admission_label(&self) -> &'static str {
        self.peer
    }

    /// Accept forever, handing each admitted TLS stream to `admitted`.
    ///
    /// Every connection that does not authenticate is spliced byte-for-byte to
    /// the borrowed origin — never answered, never reset, because a refusal is
    /// the fingerprint this front exists to avoid.
    pub async fn run(self, admitted: mpsc::Sender<Admitted>) -> Result<()> {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    println!("REALITY accept error: {e}");
                    continue;
                }
            };
            let acceptor = self.acceptor.clone();
            let origin_host = self.origin_host.clone();
            let origin_port = self.origin_port;
            let admission = self.admission.clone();
            let admitted = admitted.clone();
            tokio::spawn(async move {
                let Some(hello) = peek_hello(&stream).await else {
                    println!("REALITY {peer}: no ClientHello, splicing");
                    let _ = splice_to_origin(stream, &origin_host, origin_port).await;
                    return;
                };
                let sni = hello.sni.clone().unwrap_or_default();
                if !admission.admits(&hello, crate::ghost::v2::reality::now_secs()) {
                    println!(
                        "REALITY {peer}: splice sni={sni} alpn={:?} (no valid knock)",
                        hello.alpn
                    );
                    if let Err(e) = splice_to_origin(stream, &origin_host, origin_port).await {
                        println!("REALITY {peer}: splice failed: {e}");
                    }
                    return;
                }
                println!(
                    "REALITY {peer}: authenticated sni={sni} alpn={:?}, TLS 1.3 handshake",
                    hello.alpn
                );
                match acceptor.accept(stream).await {
                    Ok(tls) => {
                        if admitted
                            .send(Admitted {
                                stream: tls,
                                sni,
                                peer,
                            })
                            .await
                            .is_err()
                        {
                            println!("REALITY {peer}: admitted but nobody is listening");
                        }
                    }
                    Err(e) => println!("REALITY {peer}: handshake failed: {e}"),
                }
            });
        }
    }
}

/// Run the TLS front. Returns only on listener failure or Ctrl-C.
pub async fn run_cli(listen: String, origin: String, token: String) -> Result<()> {
    let origin = origin_from_addr(&origin);
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid --listen address {listen}"))?;
    let front = FrontListener::bind(FrontConfig {
        listen: addr,
        origin: origin.clone(),
        admission: Admission::SniLabel(token.clone()),
    })
    .await?;
    println!(
        "REALITY front listening on {} -> borrowed origin {}:{} (TLS 1.3)",
        front.local_addr()?,
        origin.host,
        origin.port
    );
    println!("Authenticated SNI label: {token}.{}", origin.sni);

    let (tx, mut rx) = mpsc::channel::<Admitted>(64);
    tokio::spawn(async move {
        if let Err(e) = front.run(tx).await {
            println!("REALITY front stopped: {e}");
        }
    });
    while let Some(admitted) = rx.recv().await {
        let sni = admitted.sni.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_tunnel(admitted.stream, &sni).await {
                println!("REALITY {}: tunnel ended: {e}", admitted.peer);
            }
        });
    }
    Ok(())
}

/// Dial the front as a client.
///
/// The certificate is not verified here on purpose: the front presents the
/// borrowed origin's certificate, which this side has no chain for, and the
/// identity that matters — the peer's post-quantum fingerprint — is bound at the
/// GTF session layer inside the tunnel, exactly as `net::quic` does it.
pub async fn dial(
    addr: SocketAddr,
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let provider = crypto_provider();
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 1.3 client config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| anyhow!("invalid SNI {sni}: {e}"))?;
    Ok(connector.connect(name, tcp).await?)
}

/// Certificate verifier for the dialer: the tunnel authenticates at the frame
/// layer, so the TLS certificate is a cover artefact, not a trust anchor.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Frames on the front stream: `[u32 big-endian length][bytes]`.
///
/// The daemon's unit on this carrier is one GTF datagram, so the bridge preserves
/// datagram boundaries instead of re-framing the tunnel.
pub const FRONT_FRAME_MAX: usize = 64 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> Result<()> {
    if frame.len() > FRONT_FRAME_MAX {
        return Err(anyhow!("front frame too large: {} bytes", frame.len()));
    }
    writer
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame. `Ok(None)` means the peer closed on a frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("front frame length"),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > FRONT_FRAME_MAX {
        return Err(anyhow!("front frame length out of range: {len}"));
    }
    let mut frame = vec![0u8; len];
    reader
        .read_exact(&mut frame)
        .await
        .context("front frame body")?;
    Ok(Some(frame))
}

async fn splice_to_origin(mut client: TcpStream, host: &str, port: u16) -> Result<()> {
    let mut upstream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("borrowed origin {host}:{port} unreachable"))?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_with(sni: &str, alpn: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut alpn_body = vec![alpn.len() as u8];
        alpn_body.extend_from_slice(alpn.as_bytes());
        let mut alpn_ext = Vec::new();
        alpn_ext.extend_from_slice(&((alpn_body.len() + 2) as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&alpn_body);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn_ext);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0); // no session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![1, 0, 0, 0];
        let len = body.len() as u32;
        hs[1] = (len >> 16) as u8;
        hs[2] = (len >> 8) as u8;
        hs[3] = len as u8;
        hs.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn parses_sni_alpn_and_random() {
        let h = parse_client_hello(&hello_with("s3cret.example.com", "http/1.1")).unwrap();
        assert_eq!(h.sni.as_deref(), Some("s3cret.example.com"));
        assert_eq!(h.alpn, vec!["http/1.1"]);
        assert_eq!(h.random, [0x11; 32]);
    }

    #[test]
    fn truncated_hello_is_not_trusted() {
        assert!(parse_client_hello(b"").is_none());
        let h = hello_with("a.example", "h2");
        assert!(parse_client_hello(&h[..h.len() - 5]).is_none());
    }

    /// The hidden knock as a client builds it: the tail of the random is fixed
    /// first, the token is derived over it, then the token overwrites the head.
    fn hello_with_knock(knock: &RealityKnock, sni: &str, now: u64) -> ([u8; 32], Vec<u8>) {
        let mut random = [0x33u8; 32];
        random[24..32].copy_from_slice(&[0x7A, 1, 2, 3, 4, 5, 6, 7]);
        let token = knock_token(knock, sni, &random, now);
        random[..24].copy_from_slice(&token);
        (random, hello_with(sni, "http/1.1"))
    }

    #[test]
    fn a_hidden_knock_admits_without_exposing_the_token_in_the_sni() {
        let knock = RealityKnock::new([0x5Au8; 32]);
        let sni = "cdn.example";
        let (random, _) = hello_with_knock(&knock, sni, 1_000);
        assert!(knock_admits(&knock, sni, &random, 1_000));
        // The SNI is the borrowed origin's name; nothing about the token is in it.
        assert!(!sni.contains("token"));
        // Bound to the hello: another SNI, another tail, another timestamp all fail.
        assert!(!knock_admits(&knock, "evil.example", &random, 1_000));
        let mut other = random;
        other[31] ^= 0xFF;
        assert!(!knock_admits(&knock, sni, &other, 1_000));
        assert!(!knock_admits(&knock, sni, &random, 9_999));
        // And a plain hello (no token in the random) never admits.
        let plain = [0u8; 32];
        assert!(!knock_admits(&knock, sni, &plain, 1_000));
    }

    #[test]
    fn admission_modes_disagree_only_on_how_the_token_travels() {
        let knock = RealityKnock::new([0x11u8; 32]);
        let now = 2_000;
        let (random, _) = hello_with_knock(&knock, "cdn.example", now);
        let hidden = Admission::Knock(knock);
        let legacy = Admission::SniLabel("token".to_string());
        let knock_hello = HelloInfo {
            sni: Some("cdn.example".into()),
            alpn: vec!["http/1.1".into()],
            random,
        };
        assert!(hidden.admits(&knock_hello, now));
        assert!(!legacy.admits(&knock_hello, now));

        let label_hello = HelloInfo {
            sni: Some("token.cdn.example".into()),
            alpn: vec![],
            random: [0u8; 32],
        };
        assert!(legacy.admits(&label_hello, now));
        assert!(!hidden.admits(&label_hello, now));
    }

    #[tokio::test]
    async fn frames_cross_the_bridge_intact_and_eof_is_clean() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_frame(&mut client, b"first").await.unwrap();
        write_frame(&mut client, &[0xAB; 1200]).await.unwrap();
        assert_eq!(read_frame(&mut server).await.unwrap().unwrap(), b"first");
        assert_eq!(
            read_frame(&mut server).await.unwrap().unwrap(),
            vec![0xAB; 1200]
        );
        client.shutdown().await.unwrap();
        assert!(read_frame(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_on_both_ends() {
        let (mut client, _server) = tokio::io::duplex(8);
        let huge = vec![0u8; FRONT_FRAME_MAX + 1];
        assert!(write_frame(&mut client, &huge).await.is_err());
    }
}
