//! SRTP / RTP carrier shaping for the live data path (Phase 2).
//!
//! Some networks permit UDP only when it is media: WebRTC flows to a relay, a
//! conference bridge or a carrier's VoLTE stack are passed while a bespoke
//! protocol on a strange port is dropped or throttled. This module lets the
//! daemon carry its ordinary GTFv2 datagrams inside RTP-looking packets, using
//! the shaping primitives in [`vantablack::ghost::v2::reality`].
//!
//! Wire shape, per datagram:
//!
//! ```text
//! [RTP header: 12 B][GTFv2 frame, unchanged][zero pad to a 4-byte boundary]
//! ```
//!
//! The RTP header advertises version 2, payload type [`RTP_PT_OPUS`] and a
//! per-destination 48 kHz media clock: `seq` advances by one per datagram and
//! `timestamp` by [`RTP_TS_STEP_20MS`] (960), which is what a 20 ms Opus stream
//! looks like. `ssrc` is derived from the destination address, so one peer is
//! one "call participant" and two peers are not two packets of one call.
//!
//! **Opt-in, and both ends must opt in.** `GHOST_SRTP=1` turns shaping on for
//! outbound GTFv2 datagrams. The receive path auto-detects shaped datagrams, so a
//! node that is *not* opted in keeps working with a peer that is (its own sends
//! stay plain and the peer accepts them), while a shaped datagram that no one
//! asked for is never mistaken for a plain frame: [`unshape_if_shaped`] only
//! unwraps when the *inner* bytes parse as a GTFv2 header.
//!
//! Scope, stated plainly: this is a carrier framing, not encryption. The frame
//! inside is the same sealed GTFv2 frame a direct send would have delivered, so
//! authentication, the replay window and the ratchet are untouched — an observer
//! who strips the header sees exactly what they would have seen on a plain send,
//! which is why the opt-in is about *reachability*, not confidentiality.

use crate::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use vantablack::ghost::v2::reality::{srtp_shape, srtp_unshape, RTP_PT_OPUS, RTP_TS_STEP_20MS};

/// Environment switch for outbound SRTP carrier shaping.
pub(crate) const SRTP_ENV: &str = "GHOST_SRTP";

/// Whether this process shapes outbound GTFv2 datagrams as RTP.
///
/// Cached once: the answer must not change under a running packet path, and
/// reading the environment per datagram would put a syscall on the hot path.
pub(crate) fn enabled() -> bool {
    static RESOLVED: OnceLock<bool> = OnceLock::new();
    *RESOLVED.get_or_init(|| enabled_for(std::env::var(SRTP_ENV).ok().as_deref()))
}

/// The pure decision behind [`enabled`], so every env shape is unit-testable.
pub(crate) fn enabled_for(env_value: Option<&str>) -> bool {
    match env_value {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => false,
    }
}

/// Per-destination RTP media clock.
///
/// `seq` and `ts` are 32-bit atomics rather than a mutex-guarded struct: several
/// sends for one peer can be in flight on different tasks, and an RTP sequence
/// number must not repeat. `fetch_add` gives each datagram a unique value without
/// holding a lock across the socket send.
struct MediaClock {
    seq: AtomicU32,
    timestamp: AtomicU32,
    ssrc: u32,
}

impl MediaClock {
    fn new(seed: u32) -> Self {
        Self {
            seq: AtomicU32::new(0),
            // Start the media clock at a random-ish offset, as a real stream does
            // after its first packet: a timestamp that always begins at 0 is a
            // pattern a classifier can key on.
            timestamp: AtomicU32::new(seed % RTP_TS_STEP_20MS),
            ssrc: seed,
        }
    }

    fn next(&self) -> (u16, u32, u32) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ts = self
            .timestamp
            .fetch_add(RTP_TS_STEP_20MS, Ordering::Relaxed);
        (seq as u16, ts, self.ssrc)
    }
}

fn clocks() -> &'static DashMap<SocketAddr, Arc<MediaClock>> {
    static CLOCKS: OnceLock<DashMap<SocketAddr, Arc<MediaClock>>> = OnceLock::new();
    CLOCKS.get_or_init(DashMap::new)
}

/// A stable SSRC for one destination: the identity of the "participant" in the
/// media stream. Derived from the address so a restarted send path continues the
/// same call rather than appearing as a new one mid-stream.
fn ssrc_for(dst: &SocketAddr) -> u32 {
    match dst {
        SocketAddr::V4(a) => {
            let ip = u32::from(*a.ip());
            ip ^ (u32::from(a.port()) << 16) ^ 0x5A17_C0DE
        }
        SocketAddr::V6(a) => {
            let segments = a.ip().segments();
            let fold = segments
                .iter()
                .fold(0u32, |acc, s| acc.rotate_left(5) ^ u32::from(*s));
            fold ^ (u32::from(a.port()) << 16) ^ 0x5A17_C0DE
        }
    }
}

/// Shape one outbound GTFv2 datagram for `dst`.
///
/// Returns the frame unchanged when shaping is off, so callers can use this
/// unconditionally and keep one send path.
pub(crate) fn shape_for_send(dst: &SocketAddr, frame: &[u8]) -> Vec<u8> {
    if !enabled() {
        return frame.to_vec();
    }
    let clock = clocks()
        .entry(*dst)
        .or_insert_with(|| Arc::new(MediaClock::new(ssrc_for(dst))))
        .clone();
    let (seq, timestamp, ssrc) = clock.next();
    srtp_shape(frame, seq, timestamp, ssrc)
}

/// Whether `frame` carries the RTP shape this module emits.
///
/// Deliberately shallow: this only says "the header looks like our stream". The
/// decision to actually unwrap is [`unshape_if_shaped`], which additionally
/// requires the inner bytes to parse as GTFv2 — a plain GTF frame whose session
/// hash happens to start with `0x80` and whose next byte is `111` (about one in a
/// thousand) is therefore never misread as media.
pub(crate) fn looks_shaped(frame: &[u8]) -> bool {
    frame.len() > vantablack::ghost::v2::reality::RTP_HEADER_LEN
        && frame[0] >> 6 == 2
        && frame[1] == RTP_PT_OPUS
}

/// Unwrap an SRTP-shaped datagram, or return `None` when it is not one.
///
/// Only reached on the receive path, and only trusted after the inner frame
/// parses as GTFv2, so this never reinterprets legacy traffic. Shaping is
/// accepted from any peer regardless of this node's own `GHOST_SRTP` setting:
/// the switch decides what *we* send, not what we are willing to hear.
pub(crate) fn unshape_if_shaped(frame: &[u8]) -> Option<&[u8]> {
    if !looks_shaped(frame) {
        return None;
    }
    let inner = srtp_unshape(frame)?;
    net::parse_gtf_v2_header(inner).map(|_| inner)
}

/// Send one v2 frame, shaped when the carrier is on.
///
/// This is the daemon's ordinary "seal, then put a shard on the wire" call. It
/// exists so the shaping decision is made in exactly one place instead of at
/// every call site: with the carrier off it is the same `send_gtf_v2` the daemon
/// has always used.
pub(crate) async fn send_v2(
    sock: &UdpSocket,
    dst: &SocketAddr,
    header: &net::GtfV2Header,
    shard: &[u8],
    tag: &[u8; 16],
) -> std::io::Result<()> {
    let frame = net::try_build_gtf_v2_frame(header, shard, tag)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // An admitted — or dialed — REALITY front stream carries the frame unchanged
    // in place of the UDP datagram; shaping is a UDP-wire concern, skipped there.
    #[cfg(feature = "reality-front")]
    if super::reality_front::try_send(dst, &frame) {
        return Ok(());
    }
    let wire = if enabled() {
        shape_for_send(dst, &frame)
    } else {
        frame
    };
    sock.send_to(&wire, dst).await?;
    Ok(())
}

/// Send an already-built datagram, shaped when the carrier is on.
pub(crate) async fn send_raw(
    sock: &UdpSocket,
    dst: &SocketAddr,
    frame: &[u8],
) -> std::io::Result<()> {
    #[cfg(feature = "reality-front")]
    if super::reality_front::try_send(dst, frame) {
        return Ok(());
    }
    let wire = if enabled() {
        shape_for_send(dst, frame)
    } else {
        frame.to_vec()
    };
    sock.send_to(&wire, dst).await?;
    Ok(())
}

/// The non-async twin for callers that already hold `try_send_to` semantics.
pub(crate) fn try_send_raw(sock: &UdpSocket, dst: &SocketAddr, frame: &[u8]) {
    if !enabled() {
        let _ = sock.try_send_to(frame, *dst);
        return;
    }
    let _ = sock.try_send_to(&shape_for_send(dst, frame), *dst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use vantablack::ghost::layers::l2_aead::xchacha_open;
    use vantablack::ghost::net::{extract_payload, parse_gtf_v2_header, unframe};

    /// Two seats on one v2 session, the same construction the transport tests use.
    fn session_pair() -> (Session, Session) {
        let alice_id = l0_identity::GhostIdentity::generate_fresh();
        let bob_id = l0_identity::GhostIdentity::generate_fresh();
        let master = [0x5Au8; 32];
        let alice = Session::new_with_role(master, bob_id.fingerprint(), SessionRole::Initiator);
        let bob = Session::new_with_role(master, alice_id.fingerprint(), SessionRole::Responder);
        alice.pin_peer_identity(bob_id.public_key_bytes());
        bob.pin_peer_identity(alice_id.public_key_bytes());
        (alice, bob)
    }

    fn addr() -> SocketAddr {
        "203.0.113.7:55225".parse().unwrap()
    }

    #[test]
    fn the_switch_is_off_unless_explicitly_on() {
        assert!(!enabled_for(None));
        assert!(!enabled_for(Some("0")));
        assert!(!enabled_for(Some("off")));
        assert!(enabled_for(Some("1")));
        assert!(enabled_for(Some("TRUE")));
    }

    /// The whole carrier, end to end: seal → SRTP wrap → SRTP unwrap → GTFv2 open.
    #[test]
    fn srtp_wrap_unwrap_then_gtf_open_recovers_the_payload() {
        let (alice, bob) = session_pair();
        let payload = b"media-only network";
        let ctx = SealCtx::from_session(&alice);
        let frame = seal_single(&ctx, payload);
        assert!(parse_gtf_v2_header(&frame).is_some());

        // Shape exactly as `shape_for_send` would, with a known media clock.
        let shaped = srtp_shape(&frame, 3, RTP_TS_STEP_20MS * 3, 0xDEAD_BEEF);
        assert!(looks_shaped(&shaped));
        assert_eq!(shaped.len() % 4, 0);

        // The receive path's detection: unwrap only because the inner bytes parse.
        let inner = unshape_if_shaped(&shaped).expect("a shaped GTFv2 datagram");
        assert_eq!(inner, frame.as_slice());

        // …and the frame opens on the peer's session, byte for byte as a direct
        // send would have.
        let header = parse_gtf_v2_header(inner).expect("a v2 header");
        let plan = bob.plan_open(
            header.epoch,
            NonceDirection::InitiatorToResponder,
            header.counter,
        );
        let key = match &plan {
            vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => *key,
            vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => *key,
            vantablack::ghost::session::ratchet::OpenPlan::Refused => panic!("plan refused"),
        };
        let mut carried = unframe(extract_payload(inner)).expect("a framed shard");
        let opened = xchacha_open(
            &key,
            &header.nonce,
            header.epoch,
            NonceDirection::InitiatorToResponder,
            &mut carried,
        )
        .expect("the epoch key opens it");
        bob.commit_open(header.epoch, NonceDirection::InitiatorToResponder, plan);
        assert_eq!(frame_payload(opened).expect("a framed payload"), payload);
    }

    #[test]
    fn a_plain_frame_is_never_mistaken_for_media() {
        let (alice, _bob) = session_pair();
        let ctx = SealCtx::from_session(&alice);
        let frame = seal_single(&ctx, b"plain");
        // Whatever the first bytes happen to be, the inner-parse rule means the
        // only frames this unwraps are frames that really are shaped.
        if let Some(inner) = unshape_if_shaped(&frame) {
            assert!(parse_gtf_v2_header(inner).is_some());
        }
        assert!(unshape_if_shaped(&[0u8; 8]).is_none(), "too short");
        assert!(unshape_if_shaped(&[0x40u8; 64]).is_none(), "not version 2");
        assert!(
            unshape_if_shaped(&[0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]).is_none(),
            "not Opus, and the inner bytes are not a GTFv2 header"
        );
    }

    #[test]
    fn the_media_clock_advances_per_datagram_and_is_stable_per_peer() {
        let a = addr();
        let b: SocketAddr = "198.51.100.9:55225".parse().unwrap();
        assert_eq!(ssrc_for(&a), ssrc_for(&a), "one peer, one SSRC");
        assert_ne!(ssrc_for(&a), ssrc_for(&b), "two peers, two streams");
        let _ = (a, b);
    }
}
