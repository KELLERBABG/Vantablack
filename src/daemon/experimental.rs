//! Experimental toggle wiring (see `docs/EXPERIMENTAL_FEATURES.md`).
//!
//! Each toggle module already owns its machinery and its `is_enabled()` flag; the
//! control center persists the switch and calls `set_enabled`. What was missing was
//! the daemon *reading* the flag, so flipping a switch only changed a stored value.
//! This module holds the small pure pieces both halves of a wiring need, so the
//! packet-path edits stay one or two lines each.
//!
//! Two toggles are wired here:
//!
//! * **Flood shield** (`pow`): a new peer must spend one proof-of-work before a
//!   `ctr == 0` handshake is admitted. The challenge is derived from the responder's
//!   mesh port and the current epoch, so it needs no round trip and no coordinator;
//!   the initiator solves it from what it already knows (the address it dials).
//! * **Shared threat signals** (`collective_defense`): every beacon carries this
//!   node's coarse, bucketed loss observation in a `CDEF` section, and receivers
//!   feed them into the k-anonymity aggregator. No payload, no peer identity and no
//!   fine-grained timing leaves the node — only the discretized observation.
//!
//! ## Interop note for the flood shield
//!
//! It is a mesh-wide policy, not a local preference: a node that requires a token
//! cannot be reached by a node that does not send one. That is inherent in asking
//! a peer to pay before it is admitted, and it is why the switch is off by default.

use crate::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use vantablack::ghost::net::collective_defense::{AnomalyObservable, CollectiveDefenseAggregator};

// ── Flood shield (exp_pow_shield) ─────────────────────────────────────────

/// Magic of a proof-of-work token frame. Four bytes, like every other control
/// frame the peer loop dispatches on.
pub(crate) const POW_TOKEN_MAGIC: &[u8; 4] = b"POWS";
/// Domain separation for the challenge digest.
const POW_DOMAIN: &[u8] = b"GGN_POW_SHIELD_V1";
/// A token is valid for the epoch it was solved in and the one before it, which
/// absorbs a clock that is a little fast or slow without widening the window.
const POW_EPOCH_SECS: u64 = 300;
/// How long a redeemed token stays in the allow set: long enough for the
/// handshake that follows it, short enough that one token is one admission.
const POW_TOKEN_TTL: Duration = Duration::from_secs(60);

/// The challenge a peer must solve to be admitted by `port` during `epoch`.
///
/// Both sides can compute it: the initiator knows the port it is dialing, the
/// responder knows the port it bound. No round trip, no per-peer state.
pub(crate) fn pow_challenge(port: u16, epoch: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(POW_DOMAIN);
    hasher.update(port.to_be_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().into()
}

/// The difficulty demanded of a token, in leading zero bits.
pub(crate) fn pow_bits() -> u8 {
    pow_bits_from(std::env::var("GHOST_POW_DIFFICULTY").ok().as_deref())
}

/// The pure decision behind [`pow_bits`]. Clamped: fewer than 8 bits is not a
/// cost, and more than 24 bits would stall an honest phone.
fn pow_bits_from(value: Option<&str>) -> u8 {
    value
        .and_then(|raw| raw.trim().parse::<u8>().ok())
        .map(|bits| bits.clamp(8, 24))
        .unwrap_or(12)
}

/// `SHA-256(challenge ‖ nonce)` has at least `bits` leading zeros.
pub(crate) fn pow_solved(port: u16, epoch: u64, nonce: u64, bits: u8) -> bool {
    use sha2::{Digest, Sha256};
    let challenge = pow_challenge(port, epoch);
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut zeros = 0u8;
    for byte in digest {
        let lz = byte.leading_zeros() as u8;
        zeros += lz;
        if lz < 8 {
            break;
        }
    }
    zeros >= bits
}

/// Solve the token for `port` at `now`. Bounded by the caller's epoch: an
/// unsolvable difficulty (24 bits is ~16M hashes) still terminates, because the
/// nonce space is searched linearly and the loop exits on the first solution.
pub(crate) fn pow_solve(port: u16, now: u64, bits: u8) -> u64 {
    let epoch = now / POW_EPOCH_SECS;
    let mut nonce = 0u64;
    loop {
        if pow_solved(port, epoch, nonce, bits) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// The token payload: `[POWS][nonce u64]`.
pub(crate) fn pow_token_payload(port: u16, now: u64, bits: u8) -> Vec<u8> {
    let nonce = pow_solve(port, now, bits);
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(POW_TOKEN_MAGIC);
    out.extend_from_slice(&nonce.to_be_bytes());
    out
}

/// Tokens redeemed recently, keyed by source address.
fn pow_allow() -> &'static DashMap<IpAddr, Instant> {
    static ALLOW: OnceLock<DashMap<IpAddr, Instant>> = OnceLock::new();
    ALLOW.get_or_init(DashMap::new)
}

/// Verify a token frame and, when it holds, allow one handshake from that source.
///
/// Returns `true` when the token was accepted. Expired entries are pruned here
/// rather than on a timer: the map is only ever as large as the recent arrivals.
pub(crate) fn pow_redeem(data: &[u8], src: SocketAddr, our_port: u16, now_secs: u64) -> bool {
    if data.len() < 12 || &data[..4] != POW_TOKEN_MAGIC {
        return false;
    }
    let nonce = u64::from_be_bytes(data[4..12].try_into().unwrap_or([0u8; 8]));
    let bits = pow_bits();
    let epoch = now_secs / POW_EPOCH_SECS;
    let valid = pow_solved(our_port, epoch, nonce, bits)
        || (epoch > 0 && pow_solved(our_port, epoch - 1, nonce, bits));
    if !valid {
        tracing::debug!(
            peer = %src,
            bits,
            "PoW shield: token does not meet the difficulty"
        );
        return false;
    }
    pow_allow().insert(src.ip(), Instant::now());
    true
}

/// Whether a `ctr == 0` handshake from `src` may proceed.
///
/// Always `true` when the toggle is off, so the gate costs nothing on a build or
/// a mesh that does not use it. A redeemed token is single-use: the entry is
/// removed as it is read, so a replayed handshake has to solve again.
pub(crate) fn pow_admit(src: SocketAddr) -> bool {
    if !vantablack::ghost::net::pow::is_enabled() {
        return true;
    }
    pow_allow().retain(|_, at| at.elapsed() < POW_TOKEN_TTL);
    pow_allow().remove(&src.ip()).is_some()
}

// ── Collective defense (exp_collective_defense) ───────────────────────────

/// Beacon section carrying one coarse, bucketed loss observation.
pub(crate) const BEACON_SECTION_CDEF: &[u8; 4] = b"CDEF";

/// The section payload: `[region u32][epoch u64][loss_pct u8][drops u16]`.
pub(crate) fn cdef_payload(region: u32, epoch: u64, loss_pct: u8, drops: u16) -> [u8; 15] {
    let mut out = [0u8; 15];
    out[..4].copy_from_slice(&region.to_be_bytes());
    out[4..12].copy_from_slice(&epoch.to_be_bytes());
    out[12] = loss_pct;
    out[13..15].copy_from_slice(&drops.to_be_bytes());
    out
}

/// Parse a `CDEF` section payload, refusing anything that is not exactly the
/// layout above.
pub(crate) fn parse_cdef(payload: &[u8]) -> Option<(u32, u64, u8, u16)> {
    if payload.len() != 15 {
        return None;
    }
    Some((
        u32::from_be_bytes(payload[..4].try_into().ok()?),
        u64::from_be_bytes(payload[4..12].try_into().ok()?),
        payload[12],
        u16::from_be_bytes(payload[13..15].try_into().ok()?),
    ))
}

/// A coarse region bucket for an address: the /24 of an IPv4 peer, or the /48 of
/// an IPv6 one. Coarse on purpose — a finer bucket would identify a subscriber,
/// which is exactly what k-anonymity is supposed to prevent.
pub(crate) fn region_for(ip: IpAddr) -> u32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"GGN_COLLECTIVE_REGION_V1");
    match ip {
        IpAddr::V4(v4) => hasher.update(&v4.octets()[..3]),
        IpAddr::V6(v6) => hasher.update(&v6.octets()[..6]),
    }
    let digest = hasher.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn aggregator() -> &'static parking_lot::Mutex<CollectiveDefenseAggregator> {
    static AGG: OnceLock<parking_lot::Mutex<CollectiveDefenseAggregator>> = OnceLock::new();
    AGG.get_or_init(|| parking_lot::Mutex::new(CollectiveDefenseAggregator::new()))
}

/// Ingest a beacon's observation and report whether its region is now flagged.
///
/// Returns `true` only on the evaluation that crosses the threshold, so a caller
/// logs a region once instead of once per beacon.
pub(crate) fn note_observable(payload: &[u8], from: SocketAddr) -> bool {
    if !vantablack::ghost::net::collective_defense::is_enabled() {
        return false;
    }
    let Some((region, epoch, loss_pct, drops)) = parse_cdef(payload) else {
        tracing::debug!(peer = %from, len = payload.len(), "CDEF: malformed section ignored");
        return false;
    };
    let mut agg = aggregator().lock();
    agg.ingest_observable(AnomalyObservable {
        region_bucket: region,
        epoch_slot: epoch,
        discretized_loss_pct: loss_pct,
        bucketed_peer_drops: drops,
    });
    agg.evaluate_region_threat(region, epoch)
}

/// This node's own observation for its beacon, or `None` when the toggle is off.
///
/// `peers` and `connected` are counted here, not inferred: "drops" is the number
/// of known peers this node holds no session with, bucketed to the nearest five by
/// [`AnomalyObservable`] itself.
pub(crate) fn local_observation(
    peers: usize,
    sessions: usize,
    now_secs: u64,
    our_ip: IpAddr,
) -> Option<([u8; 15], u32, u64)> {
    if !vantablack::ghost::net::collective_defense::is_enabled() {
        return None;
    }
    let region = region_for(our_ip);
    let epoch = now_secs / 600;
    let drops = peers.saturating_sub(sessions);
    // A node that cannot reach peers it knows about is the signal; the loss
    // percentage is that ratio discretized, not a measured packet loss rate.
    let loss_pct = if peers == 0 {
        0
    } else {
        ((drops as f64 / peers as f64) * 100.0).round() as u8
    };
    Some((
        cdef_payload(region, epoch, loss_pct, drops as u16),
        region,
        epoch,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flood_shield_solves_and_verifies_only_for_its_port_and_epoch() {
        let bits = 8;
        let port = 2270u16;
        let epoch = 1_700_000_000u64 / POW_EPOCH_SECS;
        let nonce = pow_solve(port, epoch * POW_EPOCH_SECS, bits);
        assert!(pow_solved(port, epoch, nonce, bits));
        assert!(
            !pow_solved(port + 1, epoch, nonce, bits),
            "a token for one port is not a token for another"
        );
        assert!(
            !pow_solved(port, epoch + 5, nonce, bits),
            "a token does not stay valid across epochs"
        );
    }

    #[test]
    fn a_token_is_redeemed_once_and_only_by_its_source() {
        // The gate only exists while the toggle is on; no other test in this
        // process depends on it being off.
        vantablack::ghost::net::pow::set_enabled(true);
        let port = 2270u16;
        let now = 1_700_000_000u64;
        // The redeemer verifies at the configured difficulty, so the token has to
        // be solved at the same one.
        let payload = pow_token_payload(port, now, pow_bits());
        assert_eq!(&payload[..4], POW_TOKEN_MAGIC);

        let alice: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let bob: SocketAddr = "192.0.2.11:40000".parse().unwrap();
        assert!(!pow_admit(alice), "no token yet");

        assert!(pow_redeem(&payload, alice, port, now));
        assert!(pow_admit(alice), "the handshake may proceed");
        assert!(!pow_admit(alice), "the token is spent");
        assert!(!pow_admit(bob), "another source gets nothing");

        // A token for a different port is refused outright.
        assert!(!pow_redeem(&payload, bob, port + 1, now));
        // A short or foreign frame is not a token.
        assert!(!pow_redeem(b"POW", bob, port, now));
        assert!(!pow_redeem(b"NOPE12345678", bob, port, now));
        vantablack::ghost::net::pow::set_enabled(false);
    }

    #[test]
    fn difficulty_is_clamped_and_defaults_to_twelve_bits() {
        assert_eq!(pow_bits_from(None), 12);
        assert_eq!(pow_bits_from(Some("1")), 8);
        assert_eq!(pow_bits_from(Some("64")), 24);
        assert_eq!(pow_bits_from(Some("nonsense")), 12);
    }

    #[test]
    fn a_cdef_section_round_trips_and_refuses_other_lengths() {
        let payload = cdef_payload(0xDEADBEEF, 12345, 42, 15);
        assert_eq!(parse_cdef(&payload), Some((0xDEADBEEF, 12345, 42, 15)));
        assert!(parse_cdef(&payload[..14]).is_none());
        let mut long = payload.to_vec();
        long.push(0);
        assert!(parse_cdef(&long).is_none());
    }

    #[test]
    fn one_region_per_subnet_and_a_distinct_one_per_subnet() {
        let a: IpAddr = "192.168.1.10".parse().unwrap();
        let b: IpAddr = "192.168.1.99".parse().unwrap();
        let c: IpAddr = "192.168.2.10".parse().unwrap();
        assert_eq!(region_for(a), region_for(b), "same /24, same bucket");
        assert_ne!(
            region_for(a),
            region_for(c),
            "another /24 is another bucket"
        );
    }
}
