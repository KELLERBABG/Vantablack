//! L2 — ChaCha20-Poly1305 AEAD Layer
//!
//! Authenticated Encryption with Associated Data (AEAD) using the
//! ChaCha20 stream cipher and Poly1305 message authentication code.
//!
//! - ChaCha20 provides 256-bit stream cipher security
//! - Poly1305 provides 128-bit authentication tag integrity
//! - Any single-bit modification to ciphertext causes authentication failure
//!
//! Nonce derivation: 12-byte nonce = [2 bytes session_hash[0..2] | 1 byte direction | 1 byte reserved | 8 byte counter BE]
//!   - session_hash[0..2]: first 2 bytes of the 4-byte session hash, so nonces stay unique across sessions
//!   - direction: 0x00 for initiator to responder, 0x01 for responder to initiator, so counters cannot mirror across directions
//!   - reserved: 0x00 (future use)
//!   - counter[4..12]: 64-bit monotonic packet counter, big-endian. `nonce_from_counter_u64` fills all 8 bytes;
//!     `nonce_from_counter` writes the low 4 bytes and leaves the high 4 zero.
//!
//! This ensures unique nonces even if directional counters align across different sessions
//! under the same master key, and prevents nonce reuse after session re-keying.

use chacha20poly1305::aead::{AeadInPlace, Error as AeadError};

use chacha20poly1305::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceDirection {
    InitiatorToResponder = 0x00,
    ResponderToInitiator = 0x01,
}

impl NonceDirection {
    pub fn peer_direction(self) -> Self {
        match self {
            Self::InitiatorToResponder => Self::ResponderToInitiator,
            Self::ResponderToInitiator => Self::InitiatorToResponder,
        }
    }
}

pub fn nonce_from_counter_u64(
    counter: u64,
    session_hash: &[u8; 4],
    direction: NonceDirection,
) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..2].copy_from_slice(&session_hash[0..2]);
    nonce[2] = direction as u8;
    nonce[3] = 0x00; // reserved
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn nonce_from_counter(
    counter: u32,
    session_hash: &[u8; 4],
    direction: NonceDirection,
) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..2].copy_from_slice(&session_hash[0..2]);
    nonce[2] = direction as u8;
    nonce[3] = 0x00; // reserved
    nonce[4..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn encrypt_in_place(key: &[u8; 32], counter: u32, data: &mut Vec<u8>) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let sh = [0u8; 4];
    cipher
        .encrypt_in_place(
            Nonce::from_slice(&nonce_from_counter(
                counter,
                &sh,
                NonceDirection::InitiatorToResponder,
            )),
            &[],
            data,
        )
        .unwrap();
}

pub fn encrypt_in_place_with_context(
    key: &[u8; 32],
    counter: u32,
    session_hash: &[u8; 4],
    direction: NonceDirection,
    data: &mut Vec<u8>,
) {
    debug_assert!(key != &[0u8; 32], "AEAD encryption called with zero key");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt_in_place(
            Nonce::from_slice(&nonce_from_counter(counter, session_hash, direction)),
            &[],
            data,
        )
        .unwrap();
}

#[allow(clippy::needless_lifetimes)]
pub fn decrypt_in_place<'a>(
    key: &[u8; 32],
    counter: u32,
    data: &'a mut Vec<u8>,
) -> Result<&'a [u8], AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let sh = [0u8; 4];
    cipher.decrypt_in_place(
        Nonce::from_slice(&nonce_from_counter(
            counter,
            &sh,
            NonceDirection::InitiatorToResponder,
        )),
        &[],
        data,
    )?;
    Ok(data as &[u8])
}

#[allow(clippy::needless_lifetimes)]
pub fn decrypt_in_place_with_context<'a>(
    key: &[u8; 32],
    counter: u32,
    session_hash: &[u8; 4],
    direction: NonceDirection,
    data: &'a mut Vec<u8>,
) -> Result<&'a [u8], AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt_in_place(
        Nonce::from_slice(&nonce_from_counter(counter, session_hash, direction)),
        &[],
        data,
    )?;
    Ok(data as &[u8])
}

pub const WIRE_NONCE_LEN: usize = 12;

pub const XCHACHA_NONCE_LEN: usize = 24;

pub fn xnonce(
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
) -> [u8; XCHACHA_NONCE_LEN] {
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    nonce[0..12].copy_from_slice(wire);
    nonce[12..20].copy_from_slice(&epoch.to_be_bytes());
    nonce[20] = direction as u8;
    nonce
}

pub fn random_xnonce() -> [u8; WIRE_NONCE_LEN] {
    let mut n = [0u8; WIRE_NONCE_LEN];
    rand::thread_rng().fill(&mut n[..]);
    n
}

pub fn xchacha_seal(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    xchacha_seal_with_aad(key, wire, epoch, direction, plaintext, &[])
}

pub fn xchacha_seal_with_aad(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut out = plaintext.to_vec();
    xchacha_seal_in_place_with_aad(key, wire, epoch, direction, &mut out, aad)?;
    Ok(out)
}

pub fn xchacha_seal_in_place(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    data: &mut Vec<u8>,
) -> Result<(), AeadError> {
    xchacha_seal_in_place_with_aad(key, wire, epoch, direction, data, &[])
}

pub fn xchacha_seal_in_place_with_aad(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    data: &mut Vec<u8>,
    aad: &[u8],
) -> Result<(), AeadError> {
    debug_assert!(key != &[0u8; 32], "AEAD encryption called with zero key");
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt_in_place(
            XNonce::from_slice(&xnonce(wire, epoch, direction)),
            aad,
            data,
        )
        .map_err(|_| AeadError)
}

#[allow(clippy::needless_lifetimes)]
pub fn xchacha_open<'a>(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    data: &'a mut Vec<u8>,
) -> Result<&'a [u8], AeadError> {
    xchacha_open_with_aad(key, wire, epoch, direction, data, &[])
}

#[allow(clippy::needless_lifetimes)]
pub fn xchacha_open_with_aad<'a>(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    data: &'a mut Vec<u8>,
    aad: &[u8],
) -> Result<&'a [u8], AeadError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt_in_place(
        XNonce::from_slice(&xnonce(wire, epoch, direction)),
        aad,
        data,
    )?;
    Ok(data as &[u8])
}

pub const SUBLIMINAL_TAIL_LEN: usize = 64;
pub const SUBLIMINAL_PAYLOAD_LEN: usize = SUBLIMINAL_TAIL_LEN - 16;

fn subliminal_xnonce(
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
) -> [u8; XCHACHA_NONCE_LEN] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VB-SUBLIMINAL-TAIL-V1");
    h.update(wire);
    h.update(epoch.to_be_bytes());
    h.update([direction as u8]);
    let digest = h.finalize();
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    nonce.copy_from_slice(&digest[..XCHACHA_NONCE_LEN]);
    nonce
}

pub fn subliminal_tail_seal(
    k_true: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    payload: &[u8; SUBLIMINAL_PAYLOAD_LEN],
) -> [u8; SUBLIMINAL_TAIL_LEN] {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(k_true));
    let mut buf = payload.to_vec();
    cipher
        .encrypt_in_place(
            XNonce::from_slice(&subliminal_xnonce(wire, epoch, direction)),
            b"GTF-SUBLIMINAL-TAIL",
            &mut buf,
        )
        .expect("sealing a 48-byte buffer cannot fail");
    debug_assert_eq!(buf.len(), SUBLIMINAL_TAIL_LEN);
    let mut out = [0u8; SUBLIMINAL_TAIL_LEN];
    out.copy_from_slice(&buf);
    out
}

pub fn subliminal_tail_open(
    k_true: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    tail: &[u8; SUBLIMINAL_TAIL_LEN],
) -> Option<[u8; SUBLIMINAL_PAYLOAD_LEN]> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(k_true));
    let mut buf = tail.to_vec();
    cipher
        .decrypt_in_place(
            XNonce::from_slice(&subliminal_xnonce(wire, epoch, direction)),
            b"GTF-SUBLIMINAL-TAIL",
            &mut buf,
        )
        .ok()?;
    if buf.len() != SUBLIMINAL_PAYLOAD_LEN {
        return None;
    }
    let mut out = [0u8; SUBLIMINAL_PAYLOAD_LEN];
    out.copy_from_slice(&buf);
    Some(out)
}

pub const MAX_SAFE_COUNTER: u32 = u32::MAX - 1000;

pub fn needs_rekey(counter: u32) -> bool {
    counter >= MAX_SAFE_COUNTER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_direction_difference() {
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let nonce_init = nonce_from_counter(42, &sh, NonceDirection::InitiatorToResponder);
        let nonce_resp = nonce_from_counter(42, &sh, NonceDirection::ResponderToInitiator);
        assert_ne!(
            nonce_init, nonce_resp,
            "Direction should produce different nonces"
        );
        assert_eq!(nonce_init[2], 0x00);
        assert_eq!(nonce_resp[2], 0x01);
    }

    #[test]
    fn test_nonce_session_hash_difference() {
        let sh1 = [0xDE, 0xAD, 0xBE, 0xEF];
        let sh2 = [0xCA, 0xFE, 0xBA, 0xBE];
        let nonce1 = nonce_from_counter(42, &sh1, NonceDirection::InitiatorToResponder);
        let nonce2 = nonce_from_counter(42, &sh2, NonceDirection::InitiatorToResponder);
        assert_ne!(
            nonce1, nonce2,
            "Different session hashes should produce different nonces"
        );
    }

    #[test]
    fn test_nonce_counter_difference() {
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let nonce1 = nonce_from_counter(42, &sh, NonceDirection::InitiatorToResponder);
        let nonce2 = nonce_from_counter(43, &sh, NonceDirection::InitiatorToResponder);
        assert_ne!(
            nonce1, nonce2,
            "Different counters should produce different nonces"
        );
    }

    #[test]
    fn test_nonce_full_uniqueness() {
        let sh_a = [0xAA, 0xBB, 0xCC, 0xDD];
        let sh_b = [0x11, 0x22, 0x33, 0x44];
        let counter: u32 = 5;
        let nonces: std::collections::HashSet<[u8; 12]> = [
            nonce_from_counter(counter, &sh_a, NonceDirection::InitiatorToResponder),
            nonce_from_counter(counter, &sh_a, NonceDirection::ResponderToInitiator),
            nonce_from_counter(counter, &sh_b, NonceDirection::InitiatorToResponder),
            nonce_from_counter(counter, &sh_b, NonceDirection::ResponderToInitiator),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            nonces.len(),
            4,
            "All four combinations should produce unique nonces"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_context() {
        let key = [0x42u8; 32];
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut data = b"HELLO GHOSTNET".to_vec();
        let original = data.clone();
        encrypt_in_place_with_context(
            &key,
            0,
            &sh,
            NonceDirection::InitiatorToResponder,
            &mut data,
        );
        assert_ne!(data, original, "Ciphertext should differ from plaintext");
        let pt = decrypt_in_place_with_context(
            &key,
            0,
            &sh,
            NonceDirection::InitiatorToResponder,
            &mut data,
        )
        .expect("Decryption should succeed");
        assert_eq!(pt, original.as_slice(), "Roundtrip should recover original");
    }

    #[test]
    fn test_encrypt_decrypt_wrong_direction_fails() {
        let key = [0x42u8; 32];
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut data = b"HELLO GHOSTNET".to_vec();
        encrypt_in_place_with_context(
            &key,
            0,
            &sh,
            NonceDirection::InitiatorToResponder,
            &mut data,
        );
        let result = decrypt_in_place_with_context(
            &key,
            0,
            &sh,
            NonceDirection::ResponderToInitiator,
            &mut data,
        );
        assert!(
            result.is_err(),
            "Decryption with wrong direction should fail"
        );
    }

    #[test]
    fn test_needs_rekey_threshold() {
        assert!(!needs_rekey(0));
        assert!(!needs_rekey(u32::MAX - 2000));
        assert!(needs_rekey(u32::MAX - 500));
        assert!(needs_rekey(u32::MAX));
    }

    #[test]
    fn test_xnonce_is_24_bytes_and_binds_epoch_and_direction() {
        let wire = [0xAAu8; WIRE_NONCE_LEN];
        let a = xnonce(&wire, 0, NonceDirection::InitiatorToResponder);
        assert_eq!(a.len(), XCHACHA_NONCE_LEN);
        assert_eq!(&a[0..12], &wire[..], "the wire half must ride verbatim");
        assert_eq!(&a[12..20], &0u64.to_be_bytes());

        assert_ne!(a, xnonce(&wire, 1, NonceDirection::InitiatorToResponder));
        assert_ne!(a, xnonce(&wire, 0, NonceDirection::ResponderToInitiator));
        assert_eq!(a, xnonce(&wire, 0, NonceDirection::InitiatorToResponder));
    }

    #[test]
    fn test_xchacha_seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let wire = random_xnonce();
        let ct = xchacha_seal(
            &key,
            &wire,
            7,
            NonceDirection::InitiatorToResponder,
            b"GHOST P2-2",
        )
        .expect("seal");
        assert_ne!(ct.as_slice(), b"GHOST P2-2");
        assert_eq!(ct.len(), b"GHOST P2-2".len() + 16);

        let mut buf = ct;
        let pt = xchacha_open(
            &key,
            &wire,
            7,
            NonceDirection::InitiatorToResponder,
            &mut buf,
        )
        .expect("open");
        assert_eq!(pt, b"GHOST P2-2");
    }

    #[test]
    fn test_xchacha_rejects_wrong_epoch_direction_key_and_tamper() {
        let key = [0x42u8; 32];
        let wire = random_xnonce();
        let ct = xchacha_seal(
            &key,
            &wire,
            3,
            NonceDirection::InitiatorToResponder,
            b"secret",
        )
        .expect("seal");

        let mut b = ct.clone();
        assert!(
            xchacha_open(&key, &wire, 4, NonceDirection::InitiatorToResponder, &mut b).is_err()
        );
        let mut b = ct.clone();
        assert!(
            xchacha_open(&key, &wire, 3, NonceDirection::ResponderToInitiator, &mut b).is_err()
        );
        let mut b = ct.clone();
        let mut other = wire;
        other[0] ^= 0x01;
        assert!(xchacha_open(
            &key,
            &other,
            3,
            NonceDirection::InitiatorToResponder,
            &mut b
        )
        .is_err());
        let mut b = ct.clone();
        assert!(xchacha_open(
            &[0x43u8; 32],
            &wire,
            3,
            NonceDirection::InitiatorToResponder,
            &mut b
        )
        .is_err());
        let mut b = ct.clone();
        b[0] ^= 0x80;
        assert!(
            xchacha_open(&key, &wire, 3, NonceDirection::InitiatorToResponder, &mut b).is_err()
        );
        let mut b = ct;
        let last = b.len() - 1;
        b[last] ^= 0x01;
        assert!(
            xchacha_open(&key, &wire, 3, NonceDirection::InitiatorToResponder, &mut b).is_err()
        );
    }

    #[test]
    fn test_random_xnonces_do_not_repeat() {
        let set: std::collections::HashSet<[u8; WIRE_NONCE_LEN]> =
            (0..4096).map(|_| random_xnonce()).collect();
        assert_eq!(set.len(), 4096);
    }

    #[test]
    fn test_same_plaintext_seals_differently_under_distinct_nonces() {
        let key = [0x42u8; 32];
        let a = xchacha_seal(
            &key,
            &random_xnonce(),
            0,
            NonceDirection::InitiatorToResponder,
            b"identical",
        )
        .unwrap();
        let b = xchacha_seal(
            &key,
            &random_xnonce(),
            0,
            NonceDirection::InitiatorToResponder,
            b"identical",
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_v2_and_v1_layers_are_not_interchangeable() {
        let key = [0x42u8; 32];
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut v1 = b"GHOST v1".to_vec();
        encrypt_in_place_with_context(&key, 5, &sh, NonceDirection::InitiatorToResponder, &mut v1);
        let wire = random_xnonce();
        assert!(xchacha_open(
            &key,
            &wire,
            5,
            NonceDirection::InitiatorToResponder,
            &mut v1
        )
        .is_err());
    }

    #[cfg(feature = "vpn")]
    #[test]
    fn test_vpn_egress_and_receiver_open_roundtrip() {
        use crate::ghost::net::vpn::client::{open_to_tun, ClientState};
        use crate::ghost::net::vpn::seal_datagram;
        use crate::ghost::net::vpn::tun::FakeTun;
        use crate::ghost::net::{
            build_gtf_frame, frame_shard, BULK_OFFSET_AUTH_TAG_START, BULK_OFFSET_PAYLOAD_START,
        };

        let key = [0x42u8; 32];
        let sh = [0x11, 0x22, 0x33, 0x44];
        let ctr = 6u32;
        let dir = NonceDirection::ResponderToInitiator;
        let ip_packet = vec![0x45; 60];
        let epoch = 2u32;
        let slot = 1u64;
        let tunnel_wire = seal_datagram(&key, epoch, slot, &ip_packet);
        let magic = crate::ghost::net::vpn::hub::VPN_PAYLOAD_MAGIC;

        let mut payload = magic.to_vec();
        payload.extend_from_slice(&tunnel_wire);
        let mut framed = Vec::with_capacity(2 + payload.len() + 1 + 16);
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(&payload);
        if framed.len() % 2 != 0 {
            framed.push(0);
        }
        encrypt_in_place_with_context(&key, ctr, &sh, dir, &mut framed);
        let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
        let framed = frame_shard(&framed);
        let mut frame = build_gtf_frame(sh, ctr, 0, &framed, &tag, true);
        frame[crate::ghost::net::OFFSET_FLAGS] |= 0x02;

        let amt = frame.len();
        let pe = BULK_OFFSET_AUTH_TAG_START.min(amt);
        assert!(pe > BULK_OFFSET_PAYLOAD_START);
        let b = &frame[BULK_OFFSET_PAYLOAD_START..pe];
        assert!(b.len() >= 2);
        let l = u16::from_be_bytes([b[0], b[1]]) as usize;
        assert!(l > 0 && 2 + l <= b.len());
        let msg = b[2..2 + l].to_vec();
        let mut decrypted = None;
        for d in [
            NonceDirection::ResponderToInitiator,
            NonceDirection::InitiatorToResponder,
        ] {
            let mut trial = msg.clone();
            if decrypt_in_place_with_context(&key, ctr, &sh, d, &mut trial).is_ok() {
                decrypted = Some(trial);
                break;
            }
        }
        assert!(
            decrypted.is_some(),
            "decrypt_in_place_with_context must succeed"
        );
        let decrypted_msg = decrypted.unwrap();
        assert!(decrypted_msg.len() >= 2);
        let n = u16::from_be_bytes([decrypted_msg[0], decrypted_msg[1]]) as usize;
        let decrypted_payload = decrypted_msg.get(2..2 + n).unwrap();
        assert_eq!(&decrypted_payload[..magic.len()], magic.as_slice());
        let wire = &decrypted_payload[magic.len()..];
        assert_eq!(wire, tunnel_wire.as_slice());

        let phone_state = ClientState::new("client_fp", key);
        let new_epoch = phone_state.rotate_epoch();
        assert_eq!(new_epoch, 2);
        let tun = FakeTun::new();
        let (accepted, adv) = open_to_tun(&phone_state, wire, &tun);
        assert!(accepted, "open_to_tun must accept packet!");
        assert!(adv);
        let out = tun.drain_outbound();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], ip_packet);
    }

    #[test]
    fn test_ipv4_mapped_ipv6_inequality() {
        let v4: std::net::SocketAddr = "192.168.178.27:55225".parse().unwrap();
        let v6: std::net::SocketAddr = "[::ffff:192.168.178.27]:55225".parse().unwrap();
        assert_ne!(v4, v6);
        assert_ne!(v4.ip(), v6.ip());
    }
}

#[cfg(test)]
mod subliminal_tests {
    use super::*;

    fn wire() -> [u8; WIRE_NONCE_LEN] {
        [0x7Au8; WIRE_NONCE_LEN]
    }

    #[test]
    fn the_hidden_plane_round_trips_and_is_exactly_one_tail_long() {
        let k_true = [0x42u8; 32];
        let payload = [0x5Au8; SUBLIMINAL_PAYLOAD_LEN];
        let tail = subliminal_tail_seal(
            &k_true,
            &wire(),
            9,
            NonceDirection::InitiatorToResponder,
            &payload,
        );
        assert_eq!(tail.len(), SUBLIMINAL_TAIL_LEN);
        assert_ne!(&tail[..], &payload[..], "the payload is not in the clear");
        let opened = subliminal_tail_open(
            &k_true,
            &wire(),
            9,
            NonceDirection::InitiatorToResponder,
            &tail,
        )
        .expect("hidden plane opens with its key");
        assert_eq!(opened, payload);
    }

    #[test]
    fn a_random_tail_opens_no_hidden_plane_and_neither_does_a_tampered_one() {
        let tail = random_xnonce();
        let mut innocent = [0u8; SUBLIMINAL_TAIL_LEN];
        innocent[..WIRE_NONCE_LEN].copy_from_slice(&tail);
        assert!(
            subliminal_tail_open(
                &[0x42u8; 32],
                &wire(),
                9,
                NonceDirection::InitiatorToResponder,
                &innocent
            )
            .is_none(),
            "an unused random tail must look like no hidden plane"
        );

        let k_true = [0x42u8; 32];
        let payload = [0x11u8; SUBLIMINAL_PAYLOAD_LEN];
        let mut sealed = subliminal_tail_seal(
            &k_true,
            &wire(),
            9,
            NonceDirection::InitiatorToResponder,
            &payload,
        );
        sealed[0] ^= 0x01;
        assert!(
            subliminal_tail_open(
                &k_true,
                &wire(),
                9,
                NonceDirection::InitiatorToResponder,
                &sealed
            )
            .is_none(),
            "a rewritten tail fails the tag"
        );
    }

    #[test]
    fn the_hidden_plane_is_bound_to_epoch_direction_and_frame_nonce() {
        let k_true = [0x33u8; 32];
        let payload = [0x77u8; SUBLIMINAL_PAYLOAD_LEN];
        let tail = subliminal_tail_seal(
            &k_true,
            &wire(),
            1,
            NonceDirection::InitiatorToResponder,
            &payload,
        );
        for (nonce, epoch, direction) in [
            (
                [0x7Bu8; WIRE_NONCE_LEN],
                1,
                NonceDirection::InitiatorToResponder,
            ),
            (wire(), 2, NonceDirection::InitiatorToResponder),
            (wire(), 1, NonceDirection::ResponderToInitiator),
        ] {
            assert!(
                subliminal_tail_open(&k_true, &nonce, epoch, direction, &tail).is_none(),
                "a tail must not open outside the frame metadata it was sealed for"
            );
        }
    }
}
