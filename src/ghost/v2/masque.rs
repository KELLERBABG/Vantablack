//! HTTP/3 MASQUE endpoint: ALPN `h3`, extended CONNECT, capsules and datagrams.
//!
//! This is the HTTP/3 counterpart of [`super::front`], built directly on quinn.
//! It implements the part of HTTP/3 that MASQUE needs:
//!
//! * control streams with SETTINGS (including `SETTINGS_H3_DATAGRAM` and
//!   `SETTINGS_ENABLE_CONNECT_PROTOCOL`) and the QPACK encoder/decoder streams;
//! * request streams carrying HEADERS frames, with a QPACK field-section decoder
//!   (static table + Huffman) and encoder;
//! * extended CONNECT (RFC 9220) with `:protocol = connect-udp` and
//!   `capsule-protocol: ?1`;
//! * RFC 9297 capsules on the request stream and RFC 9221 QUIC datagrams in
//!   both directions, framed with the HTTP Datagram quarter-stream-id prefix.
//!
//! It also answers a plain `GET` with an HTML page, so a browser that trusts the
//! certificate can verify full HTTP/3 request/response framing, not just the
//! CONNECT path.

use anyhow::{anyhow, Context, Result};
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use quinn::rustls::SignatureScheme;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::ghost::v2::reality::{decode_datagram_capsule, decode_varint, encode_datagram_capsule};

mod huffman {
    include!("hpack_huffman.rs");
}

const ALPN: &[u8] = b"h3";

fn crypto_provider() -> Arc<quinn::rustls::crypto::CryptoProvider> {
    #[cfg(feature = "pq-tls")]
    {
        Arc::new(quinn::rustls::crypto::aws_lc_rs::default_provider())
    }
    #[cfg(not(feature = "pq-tls"))]
    {
        Arc::new(quinn::rustls::crypto::ring::default_provider())
    }
}

// HTTP/3 frame and stream types.
const DATA_FRAME: u64 = 0x00;
const HEADERS_FRAME: u64 = 0x01;
const SETTINGS_FRAME: u64 = 0x04;
const CONTROL_STREAM: u64 = 0x00;
const QPACK_ENCODER_STREAM: u64 = 0x02;
const QPACK_DECODER_STREAM: u64 = 0x03;

// HTTP/3 settings.
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// QPACK static table (RFC 9204 Appendix A).
const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    if let Some(bytes) = crate::ghost::v2::reality::encode_varint(value) {
        out.extend_from_slice(&bytes);
        return;
    }
    let mut buf = [0u8; 8];
    for byte in buf.iter_mut().rev() {
        *byte = (value & 0xff) as u8;
        value >>= 8;
    }
    out.extend_from_slice(&buf);
}

async fn read_varint(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0u8; 1];
    if recv.read(&mut first).await?.is_none() {
        return Err(anyhow!("stream closed"));
    }
    let len = 1usize << (first[0] >> 6);
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut b = [0u8; 1];
        if recv.read(&mut b).await?.is_none() {
            return Err(anyhow!("truncated varint"));
        }
        value = (value << 8) | b[0] as u64;
    }
    Ok(value)
}

async fn read_exact(recv: &mut quinn::RecvStream, out: &mut [u8]) -> Result<()> {
    let mut got = 0;
    while got < out.len() {
        match recv.read(&mut out[got..]).await? {
            Some(0) | None => return Err(anyhow!("stream ended mid-frame")),
            Some(n) => got += n,
        }
    }
    Ok(())
}

async fn read_frame(recv: &mut quinn::RecvStream) -> Result<(u64, Vec<u8>)> {
    let kind = read_varint(recv).await?;
    let len = read_varint(recv).await? as usize;
    if len > 1 << 20 {
        return Err(anyhow!("frame too large"));
    }
    let mut body = vec![0u8; len];
    read_exact(recv, &mut body).await?;
    Ok((kind, body))
}

async fn send_frame(send: &mut quinn::SendStream, kind: u64, body: &[u8]) -> Result<()> {
    let mut head = Vec::new();
    put_varint(&mut head, kind);
    put_varint(&mut head, body.len() as u64);
    send.write_all(&head).await?;
    send.write_all(body).await?;
    Ok(())
}

fn settings_frame() -> Vec<u8> {
    let mut payload = Vec::new();
    for (id, value) in [
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
    ] {
        put_varint(&mut payload, id);
        put_varint(&mut payload, value);
    }
    let mut out = Vec::new();
    put_varint(&mut out, SETTINGS_FRAME);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

// ── QPACK ─────────────────────────────────────────────────────────────────

fn decode_int(buf: &[u8], pos: &mut usize, prefix: u8) -> Option<u64> {
    let mask = (1u64 << prefix) - 1;
    let first = *buf.get(*pos)?;
    *pos += 1;
    let mut value = (first as u64) & mask;
    if value < mask {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        value = value.wrapping_add(((b & 0x7f) as u64) << shift);
        shift += 7;
        if b & 0x80 == 0 {
            return Some(value);
        }
        if shift > 63 {
            return None;
        }
    }
}

fn huffman_decode(data: &[u8]) -> Option<String> {
    let mut out = Vec::new();
    let mut code = 0u32;
    let mut len = 0u8;
    for byte in data {
        for bit in (0..8).rev() {
            code = (code << 1) | ((byte >> bit) & 1) as u32;
            len += 1;
            let mut matched = false;
            for (sym, &code_len) in huffman::LENGTHS.iter().enumerate() {
                if code_len == len && huffman::CODES[sym] == code {
                    if sym == 256 {
                        return Some(String::from_utf8_lossy(&out).into_owned());
                    }
                    out.push(sym as u8);
                    code = 0;
                    len = 0;
                    matched = true;
                    break;
                }
            }
            if !matched && len > 30 {
                return None;
            }
        }
    }
    if len > 0 && code != (1u32 << len) - 1 {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn decode_string(buf: &[u8], pos: &mut usize) -> Option<String> {
    let huffman = buf.get(*pos)? & 0x80 != 0;
    let len = decode_int(buf, pos, 7)? as usize;
    let bytes = buf.get(*pos..*pos + len)?;
    *pos += len;
    if huffman {
        huffman_decode(bytes)
    } else {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn qpack_decode(buf: &[u8]) -> Option<Vec<(String, String)>> {
    let mut pos = 0usize;
    let _required = decode_int(buf, &mut pos, 8)?;
    let _base = decode_int(buf, &mut pos, 7)?;
    let mut fields = Vec::new();
    while pos < buf.len() {
        let b = buf[pos];
        if b & 0x80 != 0 {
            let static_ref = b & 0x40 != 0;
            let index = decode_int(buf, &mut pos, 6)?;
            if !static_ref {
                return None;
            }
            let (name, value) = STATIC_TABLE.get(index as usize)?;
            fields.push((name.to_string(), value.to_string()));
        } else if b & 0x40 != 0 {
            let static_ref = b & 0x10 != 0;
            if !static_ref {
                return None;
            }
            let index = decode_int(buf, &mut pos, 4)?;
            let (name, _) = STATIC_TABLE.get(index as usize)?;
            let value = decode_string(buf, &mut pos)?;
            fields.push((name.to_string(), value));
        } else if b & 0x20 != 0 {
            let huffman = b & 0x08 != 0;
            let name_len = decode_int(buf, &mut pos, 3)? as usize;
            let name_bytes = buf.get(pos..pos + name_len)?;
            pos += name_len;
            let name = if huffman {
                huffman_decode(name_bytes)?
            } else {
                String::from_utf8_lossy(name_bytes).into_owned()
            };
            let value = decode_string(buf, &mut pos)?;
            fields.push((name, value));
        } else {
            return None;
        }
    }
    Some(fields)
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    if bytes.len() < 127 {
        out.push(bytes.len() as u8);
    } else {
        out.push(0x7f);
        let mut v = bytes.len() as u64;
        while v >= 128 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    out.extend_from_slice(bytes);
}

/// Literal field lines with literal names (never indexed), no Huffman.
fn qpack_encode_fields(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0u8, 0u8];
    for (name, value) in fields {
        let bytes = name.as_bytes();
        if bytes.len() < 7 {
            out.push(0x20 | bytes.len() as u8);
        } else {
            out.push(0x27);
            let mut v = bytes.len() as u64 - 7;
            while v >= 128 {
                out.push((v as u8 & 0x7f) | 0x80);
                v >>= 7;
            }
            out.push(v as u8);
        }
        out.extend_from_slice(bytes);
        put_string(&mut out, value);
    }
    out
}

/// `:status 200`, plus the static `text/html; charset=utf-8` entry and a
/// content-length literal when a body follows.
fn qpack_response(body_len: Option<usize>) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0xD9]; // :status 200 (static index 25)
    if let Some(len) = body_len {
        out.push(0xF4); // content-type: text/html; charset=utf-8 (index 52)
        out.push(0x54); // literal with name ref, static index 4 (content-length)
        put_string(&mut out, &len.to_string());
    }
    out
}

// ── QUIC server ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct AcceptAnyCert;

impl quinn::rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
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

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.datagram_send_buffer_size(256 * 1024)
        .datagram_receive_buffer_size(Some(256 * 1024))
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap_or_default()));
    // Chronos: quinn has no hook for our own ACK scheduling, but it can ask the
    // peer to delay the ACKs it sends for our data, which is the direction a
    // guard can control with the ACK_FREQUENCY extension.
    if let Ok(ms) = std::env::var("GHOST_CHRONOS_ACK_DELAY_MS") {
        if let Ok(ms) = ms.parse::<u64>() {
            if ms > 0 {
                let mut afc = quinn::AckFrequencyConfig::default();
                afc.max_ack_delay(Some(Duration::from_millis(ms)));
                t.ack_frequency_config(Some(afc));
            }
        }
    }
    Arc::new(t)
}

fn server_config(sni: &str, cert_out: Option<&str>) -> Result<quinn::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec![
        sni.to_string(),
        format!("*.{sni}"),
    ])
    .map_err(|e| anyhow!("certificate generation failed: {e}"))?;
    if let Some(path) = cert_out {
        std::fs::write(path, certified.cert.pem()).context("write certificate PEM")?;
    }
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let mut rustls_cfg = quinn::rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 1.3 config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|e| anyhow!("TLS config: {e}"))?;
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| anyhow!("QUIC server crypto: {e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport());
    Ok(cfg)
}

fn client_config() -> Result<quinn::ClientConfig> {
    let mut rustls_cfg = quinn::rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 1.3 config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .map_err(|e| anyhow!("QUIC client crypto: {e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport());
    Ok(cfg)
}

fn handshake(conn: &quinn::Connection) -> (String, String) {
    match conn.handshake_data() {
        Some(data) => match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
            Ok(hs) => (
                hs.server_name.unwrap_or_else(|| "-".into()),
                hs.protocol
                    .map(|p| String::from_utf8_lossy(&p).into_owned())
                    .unwrap_or_else(|| "-".into()),
            ),
            Err(_) => ("-".into(), "-".into()),
        },
        None => ("-".into(), "-".into()),
    }
}

pub async fn run_server(
    listen: SocketAddr,
    token: String,
    sni: String,
    cert_out: Option<String>,
) -> Result<()> {
    let endpoint = quinn::Endpoint::server(server_config(&sni, cert_out.as_deref())?, listen)?;
    println!(
        "MASQUE HTTP/3 endpoint listening on {} alpn=h3 sni={sni} (token label {token})",
        endpoint.local_addr()?
    );
    if let Ok(ms) = std::env::var("GHOST_CHRONOS_ACK_DELAY_MS") {
        println!(
            "Chronos QUIC: requesting peer ACK delay {ms} ms (ACK_FREQUENCY; our own ACK timing remains quinn-owned)"
        );
    }
    while let Some(incoming) = endpoint.accept().await {
        let token = token.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    println!("MASQUE handshake failed: {e}");
                    return;
                }
            };
            let (peer_sni, alpn) = handshake(&conn);
            let admitted = peer_sni
                .split('.')
                .next()
                .map(|label| label == token.as_str())
                .unwrap_or(false);
            println!(
                "MASQUE QUIC handshake from {} sni={peer_sni} alpn={alpn} admitted={admitted}",
                conn.remote_address()
            );
            if !admitted {
                conn.close(0u32.into(), b"unknown token");
                return;
            }
            if let Err(e) = serve_connection(conn, token).await {
                println!("MASQUE connection ended: {e}");
            }
        });
    }
    Ok(())
}

async fn serve_connection(conn: quinn::Connection, token: String) -> Result<()> {
    let mut control = conn.open_uni().await?;
    let mut head = Vec::new();
    put_varint(&mut head, CONTROL_STREAM);
    control.write_all(&head).await?;
    control.write_all(&settings_frame()).await?;
    let mut qpack_enc = conn.open_uni().await?;
    qpack_enc.write_all(&[QPACK_ENCODER_STREAM as u8]).await?;
    let mut qpack_dec = conn.open_uni().await?;
    qpack_dec.write_all(&[QPACK_DECODER_STREAM as u8]).await?;

    // Drain the peer's control/QPACK streams so their flow control never blocks.
    // Each stream is kept open by a reader task; dropping a RecvStream early
    // would reset a critical stream and close the whole connection.
    let drain_conn = conn.clone();
    tokio::spawn(async move {
        while let Ok(mut uni) = drain_conn.accept_uni().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(Some(_)) = uni.read(&mut buf).await {}
            });
        }
    });

    while let Ok((send, recv)) = conn.accept_bi().await {
        let conn = conn.clone();
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(conn, send, recv, token).await {
                println!("MASQUE request ended: {e}");
            }
        });
    }
    let _keep = (control, qpack_enc, qpack_dec);
    Ok(())
}

async fn handle_request(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    token: String,
) -> Result<()> {
    let (kind, body) = read_frame(&mut recv).await?;
    if kind != HEADERS_FRAME {
        return Err(anyhow!("first request frame was {kind}, not HEADERS"));
    }
    let fields = qpack_decode(&body).ok_or_else(|| anyhow!("QPACK decode failed"))?;
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    println!(
        "MASQUE HTTP/3 request stream={} method={} protocol={} path={}",
        recv.id().index(),
        get(":method").unwrap_or("-"),
        get(":protocol").unwrap_or("-"),
        get(":path").unwrap_or("-")
    );
    if get(":method") == Some("CONNECT") {
        if get(":protocol") != Some("connect-udp") || get("capsule-protocol") != Some("?1") {
            send_frame(&mut send, HEADERS_FRAME, &[0x00, 0x00, 0xC0 | 67]).await?;
            let _ = send.finish();
            return Ok(());
        }
        if get(":authority").map(|a| a.split('.').next()) != Some(Some(token.as_str())) {
            send_frame(&mut send, HEADERS_FRAME, &[0x00, 0x00, 0xC0 | 67]).await?;
            let _ = send.finish();
            return Ok(());
        }
        let capsule_protocol = get("capsule-protocol").unwrap_or("?0");
        println!("MASQUE extended CONNECT established capsule-protocol={capsule_protocol}");
        send_frame(&mut send, HEADERS_FRAME, &qpack_response(None)).await?;

        let qsid = recv.id().index() / 4;
        let dgram_conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(data) = dgram_conn.read_datagram().await {
                let Some((id, n)) = decode_varint(&data) else { continue };
                let payload = &data[n..];
                let mut reply = Vec::new();
                put_varint(&mut reply, id);
                reply.extend_from_slice(b"DGRAM-ECHO:");
                reply.extend_from_slice(payload);
                let _ = dgram_conn.send_datagram(reply.into());
                println!("MASQUE HTTP datagram {} bytes", payload.len());
            }
        });
        let mut pending = Vec::new();
        while let Ok((kind, body)) = read_frame(&mut recv).await {
            if kind != DATA_FRAME {
                continue;
            }
            pending.extend_from_slice(&body);
            while let Some(capsule) = take_capsule(&mut pending) {
                if let Some(payload) = decode_datagram_capsule(&capsule) {
                    let mut answer = b"CAPSULE-ECHO:".to_vec();
                    answer.extend_from_slice(payload);
                    if let Some(echo) = encode_datagram_capsule(&answer) {
                        send_frame(&mut send, DATA_FRAME, &echo).await?;
                        println!("MASQUE capsule {} bytes echoed (qsid={qsid})", payload.len());
                    }
                }
            }
        }
        let _ = send.finish();
        return Ok(());
    }

    if get(":method") == Some("GET") {
        let body = format!(
            "<!doctype html><title>Vantablack HTTP/3</title><h1>HTTP/3 MASQUE endpoint</h1>\
             <p>ALPN h3, QUIC, TLS 1.3.</p><p>Path: {}</p><p>User-Agent: {}</p>",
            get(":path").unwrap_or("/"),
            get("user-agent").unwrap_or("-")
        );
        send_frame(&mut send, HEADERS_FRAME, &qpack_response(Some(body.len()))).await?;
        send_frame(&mut send, DATA_FRAME, body.as_bytes()).await?;
        send.finish()?;
        return Ok(());
    }

    send_frame(&mut send, HEADERS_FRAME, &[0x00, 0x00, 0xC0 | 67]).await?;
    let _ = send.finish();
    Ok(())
}

fn take_capsule(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let (_, n) = decode_varint(buf)?;
    let (len, m) = decode_varint(&buf[n..])?;
    let total = n + m + len as usize;
    if buf.len() < total {
        return None;
    }
    let capsule = buf[..total].to_vec();
    buf.drain(..total);
    Some(capsule)
}

// ── HTTP/3 client (used by `ggn masque --client`) ─────────────────────────

pub async fn run_client(connect: SocketAddr, token: String, sni: String) -> Result<()> {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config()?);
    let server_name = format!("{token}.{sni}");
    let conn = endpoint
        .connect(connect, &server_name)
        .with_context(|| format!("connect {connect}"))?
        .await
        .context("QUIC handshake")?;
    let (peer_sni, alpn) = handshake(&conn);
    println!(
        "MASQUE client connected: sni={peer_sni} alpn={alpn} remote={}",
        conn.remote_address()
    );

    let mut control = conn.open_uni().await?;
    let mut head = Vec::new();
    put_varint(&mut head, CONTROL_STREAM);
    control.write_all(&head).await?;
    control.write_all(&settings_frame()).await?;
    let mut enc = conn.open_uni().await?;
    enc.write_all(&[QPACK_ENCODER_STREAM as u8]).await?;
    let mut dec = conn.open_uni().await?;
    dec.write_all(&[QPACK_DECODER_STREAM as u8]).await?;

    let (mut send, mut recv) = conn.open_bi().await?;
    let request = qpack_encode_fields(&[
        (":method", "CONNECT"),
        (":scheme", "https"),
        (":authority", &server_name),
        (":path", "/"),
        (":protocol", "connect-udp"),
        ("capsule-protocol", "?1"),
    ]);
    send_frame(&mut send, HEADERS_FRAME, &request).await?;
    let (kind, body) = read_frame(&mut recv).await?;
    if kind != HEADERS_FRAME {
        return Err(anyhow!("response was not HEADERS"));
    }
    let fields = qpack_decode(&body).ok_or_else(|| anyhow!("response QPACK decode failed"))?;
    let status = fields
        .iter()
        .find(|(n, _)| n == ":status")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "-".into());
    println!("MASQUE client response status={status}");

    let payload = b"hello-http3";
    let capsule = encode_datagram_capsule(payload).ok_or_else(|| anyhow!("capsule encode"))?;
    send_frame(&mut send, DATA_FRAME, &capsule).await?;
    let (kind, body) = read_frame(&mut recv).await?;
    if kind == DATA_FRAME {
        if let Some(payload) = decode_datagram_capsule(&body) {
            println!(
                "MASQUE client capsule echo: {}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    let qsid = send.id().index() / 4;
    let mut dgram = Vec::new();
    put_varint(&mut dgram, qsid);
    dgram.extend_from_slice(b"ping-datagram-42");
    conn.send_datagram(dgram.into())?;
    let got = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await?
        .context("datagram read")?;
    let (_, n) = decode_varint(&got).ok_or_else(|| anyhow!("bad datagram qsid"))?;
    println!(
        "MASQUE client datagram echo: {}",
        String::from_utf8_lossy(&got[n..])
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http3_settings_advertise_connect_and_datagrams() {
        let frame = settings_frame();
        assert_eq!(frame[0], SETTINGS_FRAME as u8);
        let (kind, payload) = (frame[0], &frame[2..]);
        assert_eq!(kind, 4);
        assert!(payload.windows(2).any(|w| w == [0x08, 0x01]));
        assert!(payload.windows(2).any(|w| w == [0x33, 0x01]));
    }

    #[test]
    fn qpack_round_trips_literal_headers() {
        let fields = [
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            ("capsule-protocol", "?1"),
        ];
        let encoded = qpack_encode_fields(&fields);
        let decoded = qpack_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert!(decoded.iter().any(|(n, v)| n == ":protocol" && v == "connect-udp"));
        assert!(decoded
            .iter()
            .any(|(n, v)| n == "capsule-protocol" && v == "?1"));
    }

    #[test]
    fn qpack_decodes_static_and_huffman_values() {
        // `:method GET` from static index 17.
        assert_eq!(qpack_decode(&[0, 0, 0xC0 | 17]).unwrap()[0].1, "GET");
        // Huffman for "www.example.com" (RFC 7541 C.4.1).
        let encoded = [
            0u8, 0, 0x50, 0x80 | 12, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let decoded = qpack_decode(&encoded).unwrap();
        assert_eq!(decoded[0], (":authority".into(), "www.example.com".into()));
    }
}
