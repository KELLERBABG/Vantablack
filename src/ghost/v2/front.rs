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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

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

/// Run the TLS front. Returns only on listener failure or Ctrl-C.
pub async fn run_cli(listen: String, origin: String, token: String) -> Result<()> {
    let (origin_host, origin_port) = match origin.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (origin.clone(), 443),
    };
    let origin_sni = origin_host.clone();
    let cfg = Arc::new(build_tls_config(&origin_sni)?);
    let acceptor = TlsAcceptor::from(cfg);
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid --listen address {listen}"))?;
    let listener = TcpListener::bind(addr).await?;
    println!(
        "REALITY front listening on {} -> borrowed origin {}:{} (TLS 1.3)",
        listener.local_addr()?,
        origin_host,
        origin_port
    );
    println!("Authenticated SNI label: {token}.{origin_sni}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                println!("REALITY accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let origin_host = origin_host.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let Some(hello) = peek_hello(&stream).await else {
                println!("REALITY {peer}: no ClientHello, splicing");
                let _ = splice_to_origin(stream, &origin_host, origin_port).await;
                return;
            };
            let sni = hello.sni.clone().unwrap_or_default();
            let authenticated = sni
                .split('.')
                .next()
                .map(|label| label == token.as_str())
                .unwrap_or(false);
            if !authenticated {
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
                    if let Err(e) = serve_tunnel(tls, &sni).await {
                        println!("REALITY {peer}: tunnel ended: {e}");
                    }
                }
                Err(e) => println!("REALITY {peer}: handshake failed: {e}"),
            }
        });
    }
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
}
