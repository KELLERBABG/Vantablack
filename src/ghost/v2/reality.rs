//! P2P-REALITY, MASQUE and SRTP shaping.
//!
//! Three carriers, one idea: an observer should not be able to tell this traffic
//! from what the surrounding network already carries.
//!
//! * **REALITY knock.** A probe to the listening port presents a normal TLS
//!   ClientHello with an authentication tag hidden in its random field. Without a
//!   valid tag the port behaves like a reverse proxy to a *borrowed* popular
//!   origin, so an active prober sees a real certificate for a real site and
//!   learns nothing — no RST, no fingerprint, no "something is here".
//! * **MASQUE.** Valid clients are carried as HTTP/3 `CONNECT-UDP` datagrams
//!   (RFC 9297/9298), i.e. as a QUIC stream of capsules rather than a bespoke UDP
//!   protocol on a strange port.
//! * **SRTP.** Where UDP is filtered but WebRTC is not, frames ride inside
//!   RTP-looking packets (12-byte header, Opus payload type, 20 ms timestamps)
//!   with padding to a media-like size distribution.
//!
//! Scope, stated plainly: this module implements the **authentication and framing**
//! layers that make those carriers work, and the decision to splice rather than
//! reject. It does not contain a TLS stack or a QUIC implementation — the project
//! deliberately has no TLS server, and adding one to satisfy a roadmap line would
//! be a security regression. [`RealityFront`] therefore takes an already-accepted
//! byte stream and either hands it to the mesh or copies it to the borrowed
//! origin verbatim; the shape functions are what a transport (including the
//! existing `quic` feature) uses to look like the borrowed protocol.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Bytes that mark a frame as a REALITY knock, carried ahead of the ClientHello
/// body inside the random field.
pub const KNOCK_MAGIC: &[u8; 4] = b"GNK!";

/// Default acceptance window for a knock timestamp, in seconds. A knock is
/// replayable inside the window, which is harmless: it only authenticates a
/// handshake that then performs a full post-quantum key exchange.
pub const KNOCK_WINDOW_SECS: u64 = 60;

type HmacSha256 = Hmac<Sha256>;

/// Computes and checks REALITY knocks.
#[derive(Clone)]
pub struct RealityKnock {
    key: [u8; 32],
    window: Duration,
}

impl RealityKnock {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            window: Duration::from_secs(KNOCK_WINDOW_SECS),
        }
    }

    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    fn mac(&self, sni: &str, client_random: &[u8; 32], timestamp: u64) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC-SHA256 accepts keys of any length");
        mac.update(b"VB-REALITY-KNOCK-V1");
        mac.update(&(sni.len() as u16).to_be_bytes());
        mac.update(sni.as_bytes());
        mac.update(client_random);
        mac.update(&timestamp.to_be_bytes());
        let out = mac.finalize().into_bytes();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&out);
        mac_bytes
    }

    /// The 24-byte knock blob to place in a ClientHello: magic, 8-byte
    /// timestamp, 12 bytes of MAC.
    pub fn token(&self, sni: &str, client_random: &[u8; 32], now: u64) -> [u8; 24] {
        let full = self.mac(sni, client_random, now);
        let mut out = [0u8; 24];
        out[0..4].copy_from_slice(KNOCK_MAGIC);
        out[4..12].copy_from_slice(&now.to_be_bytes());
        out[12..24].copy_from_slice(&full[..12]);
        out
    }

    /// Verify a knock against the SNI and ClientHello random it is bound to.
    pub fn verify(&self, sni: &str, client_random: &[u8; 32], token: &[u8], now: u64) -> bool {
        if token.len() != 24 || &token[0..4] != KNOCK_MAGIC {
            return false;
        }
        let ts = u64::from_be_bytes(token[4..12].try_into().unwrap_or([0u8; 8]));
        let skew = now.abs_diff(ts);
        if skew > self.window.as_secs() {
            return false;
        }
        let expected = self.mac(sni, client_random, ts);
        // Constant-time compare of the truncated MAC.
        let mut diff = 0u8;
        for (a, b) in expected[..12].iter().zip(&token[12..24]) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// What arrived on the listening port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// A TLS record whose random carried a valid knock.
    RealityKnock,
    /// TLS that did not authenticate. Splice it; do not answer it.
    TlsClientHello,
    /// Plain HTTP — a browser, a scanner, or a censorship middlebox.
    Http,
    /// Anything else.
    Unknown,
}

/// What the listener should do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceAction {
    /// Authenticated: carry this connection into the mesh.
    OpenTunnel,
    /// Unauthenticated: relay to the borrowed origin so the prober sees a real
    /// site. This is the whole point of REALITY — a refusal is a fingerprint.
    SpliceToOrigin,
}

/// Classify the first bytes of a connection.
pub fn classify(first: &[u8]) -> ProbeKind {
    if first.len() >= 3 && first[0] == 0x16 && first[1] == 0x03 && (0x01..=0x04).contains(&first[2])
    {
        // A complete TLS record whose body carries the knock magic in its first
        // bytes is the authenticated case. The full check happens against the
        // parsed SNI and random in `RealityKnock::verify`.
        if first.len() >= 15 && &first[11..15] == KNOCK_MAGIC {
            return ProbeKind::RealityKnock;
        }
        return ProbeKind::TlsClientHello;
    }
    let text = &first[..first.len().min(8)];
    if text.starts_with(b"GET ") || text.starts_with(b"POST ") || text.starts_with(b"HEAD ") {
        return ProbeKind::Http;
    }
    ProbeKind::Unknown
}

/// Decide the action. Anything that is not an authenticated knock is spliced —
/// including HTTP and garbage. There is deliberately no `Reject` variant: an RST
/// or a 403 is the signal a censor is looking for.
pub fn decide(kind: ProbeKind) -> SpliceAction {
    match kind {
        ProbeKind::RealityKnock => SpliceAction::OpenTunnel,
        _ => SpliceAction::SpliceToOrigin,
    }
}

/// A borrowed origin: where unauthenticated probes are sent, and the SNI the
/// node presents. Should be a popular site reachable from the censored region,
/// not something the operator controls — otherwise the certificate is a tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BorrowedOrigin {
    pub host: String,
    pub port: u16,
    pub sni: String,
}

impl BorrowedOrigin {
    pub fn new(sni: &str) -> Self {
        Self {
            host: sni.to_string(),
            port: 443,
            sni: sni.to_string(),
        }
    }

    pub fn connect_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// The routing decision plus what to do with the first bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontDecision {
    pub action: SpliceAction,
    pub origin: String,
    pub note: &'static str,
}

pub struct RealityFront {
    knock: RealityKnock,
    origin: BorrowedOrigin,
}

impl RealityFront {
    pub fn new(knock: RealityKnock, origin: BorrowedOrigin) -> Self {
        Self { knock, origin }
    }

    pub fn origin(&self) -> &BorrowedOrigin {
        &self.origin
    }

    /// Inspect a connection's first bytes. `sni`/`random` are only available when
    /// the caller parsed the ClientHello; without them a knock cannot verify and
    /// the connection is spliced, which is the safe default.
    pub fn inspect(
        &self,
        first: &[u8],
        parsed: Option<(&str, &[u8; 32])>,
        now: u64,
    ) -> FrontDecision {
        let kind = classify(first);
        if kind == ProbeKind::RealityKnock {
            if let Some((sni, random)) = parsed {
                let token = &first[11..first.len().min(35)];
                if self.knock.verify(sni, random, token, now) {
                    return FrontDecision {
                        action: SpliceAction::OpenTunnel,
                        origin: self.origin.connect_addr(),
                        note: "authenticated knock",
                    };
                }
            }
            return FrontDecision {
                action: SpliceAction::SpliceToOrigin,
                origin: self.origin.connect_addr(),
                note: "knock marker without a valid tag",
            };
        }
        FrontDecision {
            action: decide(kind),
            origin: self.origin.connect_addr(),
            note: "probe spliced to borrowed origin",
        }
    }
}

// ── MASQUE / CONNECT-UDP capsules (RFC 9297) ──────────────────────────────

/// Capsule type for a QUIC DATAGRAM payload inside CONNECT-UDP.
pub const CAPSULE_DATAGRAM: u64 = 0x00;
/// Capsule type for a compressed `CLOSE` — unused here but named so the parser
/// can identify and skip it rather than mistaking it for a datagram.
pub const CAPSULE_CLOSE: u64 = 0x02;

/// Encode a QUIC variable-length integer.
pub fn encode_varint(value: u64) -> Option<Vec<u8>> {
    if value < 64 {
        Some(vec![value as u8])
    } else if value < 16_384 {
        Some(((value as u16) | 0x4000).to_be_bytes().to_vec())
    } else if value < 1_073_741_824 {
        Some(((value as u32) | 0x8000_0000).to_be_bytes().to_vec())
    } else if value < 4_611_686_018_427_387_904 {
        Some((value | 0xC000_0000_0000_0000).to_be_bytes().to_vec())
    } else {
        None
    }
}

/// Decode a QUIC variable-length integer; returns `(value, bytes_consumed)`.
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for b in &buf[1..len] {
        value = (value << 8) | *b as u64;
    }
    Some((value, len))
}

/// Wrap a payload as `[type=0x00][length][payload]`.
pub fn encode_datagram_capsule(payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = encode_varint(CAPSULE_DATAGRAM)?;
    out.extend_from_slice(&encode_varint(payload.len() as u64)?);
    out.extend_from_slice(payload);
    Some(out)
}

/// Pull the payload out of one datagram capsule.
pub fn decode_datagram_capsule(buf: &[u8]) -> Option<&[u8]> {
    let (kind, n) = decode_varint(buf)?;
    if kind != CAPSULE_DATAGRAM {
        return None;
    }
    let (len, m) = decode_varint(buf.get(n..)?)?;
    let start = n + m;
    let end = start.checked_add(len as usize)?;
    buf.get(start..end)
}

// ── SRTP / RTP shaping ────────────────────────────────────────────────────

/// Opus dynamic payload type used by Chrome's WebRTC stack.
pub const RTP_PT_OPUS: u8 = 111;
/// RTP header length with no CSRC and no extension.
pub const RTP_HEADER_LEN: usize = 12;

/// Wrap a frame in an RTP-looking header.
///
/// `seq` and `timestamp` come from the caller's media clock: at 48 kHz with 20 ms
/// packets, `timestamp` advances by 960 per packet and `seq` by 1, which is what
/// makes the stream look like a call rather than a tunnel. Padding is appended so
/// the total is a multiple of four, as RTP requires.
pub fn srtp_shape(payload: &[u8], seq: u16, timestamp: u32, ssrc: u32) -> Vec<u8> {
    let pad = (4 - ((RTP_HEADER_LEN + payload.len()) % 4)) % 4;
    let total = RTP_HEADER_LEN + payload.len() + pad;
    let mut out = Vec::with_capacity(total);
    out.push(0x80); // version 2, no padding bit (padding is explicit in length)
    out.push(RTP_PT_OPUS & 0x7F);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(total, 0);
    out
}

/// Remove the RTP header and padding, returning the frame.
pub fn srtp_unshape(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < RTP_HEADER_LEN || frame[0] >> 6 != 2 {
        return None;
    }
    // The shaper pads with zeros and records no padding length, so the receiver
    // recovers the frame from its own length prefix rather than from RTP's
    // padding-count field. Return everything after the header; the tunnel's
    // 2-byte length prefix decides where the frame actually ends.
    Some(&frame[RTP_HEADER_LEN..])
}

/// Timestamp advance for a 20 ms Opus packet at 48 kHz.
pub const RTP_TS_STEP_20MS: u32 = 960;

/// Current Unix time, for knock timestamps.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x5Au8; 32]
    }

    #[test]
    fn knock_verifies_only_for_its_own_hello() {
        let rk = RealityKnock::new(key());
        let random = [0x11u8; 32];
        let token = rk.token("cdn.example", &random, 1_000);
        assert!(rk.verify("cdn.example", &random, &token, 1_000));
        assert!(
            rk.verify("cdn.example", &random, &token, 1_050),
            "inside window"
        );
        assert!(!rk.verify("cdn.example", &random, &token, 2_000), "expired");
        assert!(
            !rk.verify("other.example", &random, &token, 1_000),
            "replayed elsewhere"
        );
        assert!(
            !rk.verify("cdn.example", &[0x22u8; 32], &token, 1_000),
            "other hello"
        );
    }

    #[test]
    fn knock_is_bound_to_the_magic_and_length() {
        let rk = RealityKnock::new(key());
        let random = [0u8; 32];
        let mut token = rk.token("a.example", &random, 10);
        token[0] ^= 1;
        assert!(!rk.verify("a.example", &random, &token, 10));
        assert!(!rk.verify("a.example", &random, &token[..20], 10));
    }

    #[test]
    fn unauthenticated_probes_are_spliced_never_refused() {
        let tls = [0x16u8, 0x03, 0x01, 0x00, 0x40, 0x01, 0, 0, 0, 0, 0, 0xAA];
        assert_eq!(classify(&tls), ProbeKind::TlsClientHello);
        assert_eq!(
            decide(ProbeKind::TlsClientHello),
            SpliceAction::SpliceToOrigin
        );
        assert_eq!(
            decide(classify(b"GET / HTTP/1.1\r\n")),
            SpliceAction::SpliceToOrigin
        );
        assert_eq!(
            decide(classify(b"\x00\xff\x00")),
            SpliceAction::SpliceToOrigin
        );
        assert_eq!(decide(ProbeKind::RealityKnock), SpliceAction::OpenTunnel);
    }

    #[test]
    fn front_opens_a_tunnel_only_for_a_valid_knock() {
        let rk = RealityKnock::new(key());
        let front = RealityFront::new(rk.clone(), BorrowedOrigin::new("cdn.example"));
        let random = [3u8; 32];
        let token = rk.token("cdn.example", &random, 500);

        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0, 0, 0, 0, 0];
        hello.extend_from_slice(&token);
        hello.extend_from_slice(&[0u8; 16]);

        let d = front.inspect(&hello, Some(("cdn.example", &random)), 500);
        assert_eq!(d.action, SpliceAction::OpenTunnel);
        assert_eq!(d.origin, "cdn.example:443");

        // Same bytes, wrong SNI: spliced.
        let d = front.inspect(&hello, Some(("evil.example", &random)), 500);
        assert_eq!(d.action, SpliceAction::SpliceToOrigin);
        // No parsed hello: spliced, never trusted.
        let d = front.inspect(&hello, None, 500);
        assert_eq!(d.action, SpliceAction::SpliceToOrigin);
    }

    #[test]
    fn masque_capsules_round_trip_across_varint_sizes() {
        for size in [0usize, 1, 63, 64, 300, 16_000, 1_100_000] {
            let payload = vec![0xABu8; size];
            let encoded = encode_datagram_capsule(&payload).unwrap();
            let decoded = decode_datagram_capsule(&encoded).unwrap();
            assert_eq!(decoded.len(), size);
            assert!(decoded.iter().all(|b| *b == 0xAB));
        }
        // A truncated capsule is refused rather than read out of bounds.
        let enc = encode_datagram_capsule(b"hello").unwrap();
        assert!(decode_datagram_capsule(&enc[..enc.len() - 1]).is_none());
    }

    #[test]
    fn varint_round_trips_at_boundaries() {
        for v in [
            0u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            4_611_686_018_427_387_903,
        ] {
            let enc = encode_varint(v).unwrap();
            assert_eq!(decode_varint(&enc), Some((v, enc.len())));
        }
        assert!(encode_varint(u64::MAX).is_none());
    }

    #[test]
    fn srtp_frames_look_like_media_and_recover() {
        let frame = b"tunnel frame payload";
        let shaped = srtp_shape(frame, 7, 960, 0xDEAD_BEEF);
        assert_eq!(shaped.len() % 4, 0);
        assert_eq!(shaped[0] >> 6, 2, "RTP version 2");
        assert_eq!(shaped[1], RTP_PT_OPUS);
        assert_eq!(u16::from_be_bytes([shaped[2], shaped[3]]), 7);
        assert_eq!(srtp_unshape(&shaped).unwrap(), frame);
        assert!(srtp_unshape(&[0u8; 4]).is_none());
    }
}
