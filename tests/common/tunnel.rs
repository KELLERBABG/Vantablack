//! Shared VPN tunnel framing helpers for gate tests.
//!
//! These reproduce `main.rs`'s wire path byte-for-byte:
//! `tunnel_frame` = `send_tunnel_frame` (without the async UDP send),
//! `receiver_open` = the receive loop's tunnel-bulk branch (unframe →
//! session-decrypt → strip magic).
//!
//! Usage: `mod common; use common::tunnel::{receiver_open, tunnel_frame};`

use vantablack::ghost::layers::l2_aead::{
    decrypt_in_place_with_context, encrypt_in_place_with_context, NonceDirection,
};
use vantablack::ghost::net;

pub const MAGIC: &[u8; 5] = vantablack::ghost::net::vpn::hub::VPN_PAYLOAD_MAGIC;

/// Reproduces main.rs::frame_shard: [len u16][bytes].
pub fn frame_shard(d: &[u8]) -> Vec<u8> {
    let l = (d.len() as u16).to_be_bytes();
    let mut f = Vec::with_capacity(d.len() + 2);
    f.extend_from_slice(&l);
    f.extend_from_slice(d);
    f
}

/// Exactly what `main.rs::send_tunnel_frame` does: session-encrypt
/// `[len u16][GVPN1][tunnel wire]`, wrap in a real bulk GTF frame, set the
/// tunnel flag bit. (Only the async UDP `send_to` is not under test.)
pub fn tunnel_frame(
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
    dir: NonceDirection,
    wire: &[u8],
) -> Vec<u8> {
    let mut payload = MAGIC.to_vec();
    payload.extend_from_slice(wire);
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    encrypt_in_place_with_context(key, ctr, &sh, dir, &mut framed);
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    // The bulk payload region holds a [len u16][bytes] shard — what
    // frame_shard produces and the receive path's unframe() consumes.
    let framed = frame_shard(&framed);
    let frame = net::build_gtf_frame(sh, ctr, 0, &framed, &tag, true);
    let mut frame = frame;
    frame[net::OFFSET_FLAGS] |= 0x02; // tunnel bit — receiver-side bypass marker
    frame
}

/// Exactly what the `main.rs` receive loop does for a tunnel-bulk frame:
/// extract `[2-byte len][ct||tag]` from the bulk payload region and decrypt
/// (both AEAD directions tried, as in `handle_pkt`), then strip the inner
/// length prefix and the GVPN1 magic. Returns the bare tunnel datagram.
pub fn receiver_open(
    frame: &[u8],
    amt: usize,
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
) -> Option<Vec<u8>> {
    let pe = net::BULK_OFFSET_AUTH_TAG_START.min(amt);
    if pe <= net::BULK_OFFSET_PAYLOAD_START {
        return None;
    }
    let b = &frame[net::BULK_OFFSET_PAYLOAD_START..pe];
    if b.len() < 2 {
        return None;
    }
    let l = u16::from_be_bytes([b[0], b[1]]) as usize;
    if l == 0 || 2 + l > b.len() {
        return None;
    }
    let mut msg = b[2..2 + l].to_vec();
    let ok = decrypt_in_place_with_context(
        key,
        ctr,
        &sh,
        NonceDirection::InitiatorToResponder,
        &mut msg,
    )
    .is_ok()
        || decrypt_in_place_with_context(
            key,
            ctr,
            &sh,
            NonceDirection::ResponderToInitiator,
            &mut msg,
        )
        .is_ok();
    if !ok {
        return None;
    }
    let n = u16::from_be_bytes([msg[0], msg[1]]) as usize;
    let payload = msg.get(2..2 + n)?;
    if payload.len() > MAGIC.len() && &payload[..5] == MAGIC {
        Some(payload[5..].to_vec())
    } else {
        None
    }
}
