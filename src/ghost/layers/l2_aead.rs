/// L2 — ChaCha20-Poly1305 AEAD Layer
///
/// Authenticated Encryption with Associated Data (AEAD) using the
/// ChaCha20 stream cipher and Poly1305 message authentication code.
///
/// - ChaCha20 provides 256-bit stream cipher security
/// - Poly1305 provides 128-bit authentication tag integrity
/// - Any single-bit modification to ciphertext causes authentication failure
///
/// Nonce derivation (v2): 12-byte nonce = [2 bytes session_hash[0..2] | 1 byte direction | 1 byte reserved | 4 bytes counter BE]
///   - session_hash[0..2]: First 2 bytes of the 4-byte session hash — guarantees nonce uniqueness across sessions
///   - direction: 0x00 for initiator→responder, 0x01 for responder→initiator — prevents directional counter mirroring
///   - reserved: 0x00 (future use)
///   - counter[0..4]: 4-byte monotonic packet counter (big-endian)
///
/// This ensures unique nonces even if directional counters align across different sessions
/// under the same master key, and prevents nonce reuse after session re-keying.
use chacha20poly1305::aead::{AeadInPlace, Error as AeadError};
use chacha20poly1305::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use rand::Rng;

/// Direction indicator — XOR'd into the nonce to prevent directional nonce collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceDirection {
    /// Packets sent from session initiator to responder.
    InitiatorToResponder = 0x00,
    /// Packets sent from session responder to initiator.
    ResponderToInitiator = 0x01,
}

impl NonceDirection {
    /// The other direction — what the *peer* seals in, given what we seal in.
    pub fn peer_direction(self) -> Self {
        match self {
            Self::InitiatorToResponder => Self::ResponderToInitiator,
            Self::ResponderToInitiator => Self::InitiatorToResponder,
        }
    }
}

/// Build a 12-byte nonce from a 64-bit counter value, session hash, and direction.
///
/// Layout: [session_hash[0..2]:2 | direction:1 | reserved:1 | counter:8 BE]
///
/// This design guarantees uniqueness across sessions (via session hash prefix),
/// across directions (via direction byte), and across time (via full 64-bit monotonic counter).
/// Spanning the full remaining 8 bytes eliminates counter exhaustion on high-throughput links.
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

/// Build a 12-byte nonce from the counter value, session hash, and direction.
///
/// Layout: [session_hash[0..2]:2 | direction:1 | reserved:1 | counter:4 BE | zero:4]
///
/// This design guarantees uniqueness across sessions (via session hash prefix),
/// across directions (via direction byte), and across time (via monotonic counter).
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

/// Legacy nonce builder — 12-byte nonce = [4 bytes counter (big-endian) | 8 zero bytes]
/// DEPRECATED: Use `nonce_from_counter` with session_hash and direction instead.
pub fn nonce_from_counter_legacy(counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Encrypt data in-place and append the 16-byte Poly1305 authentication tag.
///
/// Uses the v2 nonce scheme incorporating session hash and direction for
/// uniqueness guarantees across sessions and directions.
pub fn encrypt_in_place(key: &[u8; 32], counter: u32, data: &mut Vec<u8>) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    // Use session_hash = [0u8; 4] and direction = Initiator as fallback
    // (backward-compatible callers should use the full-param version)
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

/// Encrypt data with explicit session hash and direction for guaranteed nonce uniqueness.
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

/// Decrypt data in-place. The 16-byte authentication tag must be appended
/// to `data` (as produced by encrypt_in_place). Returns the plaintext slice.
///
/// Uses the v2 nonce scheme with session hash and direction.
#[allow(clippy::needless_lifetimes)]
pub fn decrypt_in_place<'a>(
    key: &[u8; 32],
    counter: u32,
    data: &'a mut Vec<u8>,
) -> Result<&'a [u8], AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    // Use session_hash = [0u8; 4] and direction = Initiator as fallback
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

/// Decrypt data with explicit session hash and direction.
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

// ── P2-2: XChaCha20-Poly1305 with a transmitted 96-bit nonce ────────
//
// The v1 scheme derives its nonce (`session_hash ‖ direction ‖ counter`), so
// nonce uniqueness is a *consequence* of the counter, and the counter's width is
// therefore a security parameter: exhaust 2³² counters under one key and the
// nonce repeats, which in ChaCha20-Poly1305 is catastrophic (the keystream XOR
// recovers plaintext and the Poly1305 one-time key becomes recoverable). The v2
// scheme moves uniqueness onto a random 96-bit nonce that travels with the frame,
// so the counter is free to be a pure sequence number (8 bytes of anti-replay
// space) and the key is bound by the ratchet's epoch instead.

/// Length of the random nonce carried on the wire, in bytes (96 bits).
pub const WIRE_NONCE_LEN: usize = 12;

/// Length of the nonce XChaCha20-Poly1305 actually takes (192 bits).
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Assemble the 24-byte XChaCha nonce: `[12 transmitted random | 8 epoch BE | 1 direction | 3 reserved]`.
///
/// The transmitted half is what makes nonces unique within an epoch; the derived
/// half is what makes them unique *across* epochs and directions without depending
/// on the random half at all. Binding the epoch this way means a frame's epoch
/// field cannot be rewritten by an intermediary into another epoch's namespace
/// and still authenticate — the nonce would change with it.
///
/// XChaCha20 is chosen because HChaCha20 mixes the first 16 nonce bytes into the
/// key, so a random nonce is safe here in a way the 12-byte-nonce ChaCha20-Poly1305
/// is not (RFC 8439 §4 wants a *guaranteed*-unique 96-bit nonce, not a random one).
pub fn xnonce(
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
) -> [u8; XCHACHA_NONCE_LEN] {
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    nonce[0..12].copy_from_slice(wire);
    nonce[12..20].copy_from_slice(&epoch.to_be_bytes());
    nonce[20] = direction as u8;
    // nonce[21..24] stays reserved (zero) for a future key-generation field.
    nonce
}

/// Draw a fresh 96-bit nonce from the OS CSPRNG.
///
/// This is the only source of nonce uniqueness in v2, so it must be a real CSPRNG
/// (`getrandom`), not a counter and not a seeded PRNG: a repeated or predictable
/// nonce under one key destroys both confidentiality and authenticity.
pub fn random_xnonce() -> [u8; WIRE_NONCE_LEN] {
    let mut n = [0u8; WIRE_NONCE_LEN];
    rand::thread_rng().fill(&mut n[..]);
    n
}

/// Seal `plaintext`, returning `ciphertext ‖ 16-byte tag`.
pub fn xchacha_seal(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    xchacha_seal_with_aad(key, wire, epoch, direction, plaintext, &[])
}

/// Seal `plaintext` with associated data, returning `ciphertext ‖ 16-byte tag`.
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

/// Seal in place, appending the 16-byte tag.
pub fn xchacha_seal_in_place(
    key: &[u8; 32],
    wire: &[u8; WIRE_NONCE_LEN],
    epoch: u64,
    direction: NonceDirection,
    data: &mut Vec<u8>,
) -> Result<(), AeadError> {
    xchacha_seal_in_place_with_aad(key, wire, epoch, direction, data, &[])
}

/// `xchacha_seal_in_place` with associated data.
///
/// The GTF privacy frame's 64-byte jitter tail sits *outside* the payload region
/// and so was outside the tag: an on-path attacker could rewrite it — and, before
/// the frame size was pinned, vary its length — with no AEAD failure to show for
/// it. It now rides as **associated data**, which Poly1305 authenticates without
/// encrypting, which is exactly what a padding region that no one ever reads
/// needs. Nothing else about the frame moves: it is still 576 B and every offset
/// is unchanged, so this changes the tag's *input*, not the layout, and needs no
/// new version marker.
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

/// Open in place: verifies the tag and truncates `data` to the plaintext.
///
/// The epoch and direction are inputs rather than derivable from `data` on
/// purpose — they must come from the authenticated frame header, so a frame can
/// only ever be attributed to the epoch the sender sealed it under.
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

/// `xchacha_open` with associated data — the receiving half of
/// [`xchacha_seal_in_place_with_aad`].
///
/// A frame whose jitter tail was altered fails here, because the tag was
/// computed over it. That is the property the tail lacked: it is still
/// unread filler, but it is no longer a field an attacker can move.
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

/// Maximum safe counter value before forced session re-keying.
/// We force re-key at u32::MAX - 1000 to leave a safety margin.
pub const MAX_SAFE_COUNTER: u32 = u32::MAX - 1000;

/// Check if a session counter is approaching the wraparound threshold.
/// Returns true if the counter is within 1000 of u32::MAX, indicating
/// that session re-keying should be triggered.
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
        // Nonces should differ in the direction byte
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
        // Even if counters match across different sessions and directions,
        // the nonces should be unique due to session_hash + direction mixing
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
        // Decrypt with wrong direction — should fail
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

        // Same wire nonce, different epoch or direction: different nonce. This is
        // the property that stops a replayed frame from being re-attributed.
        assert_ne!(a, xnonce(&wire, 1, NonceDirection::InitiatorToResponder));
        assert_ne!(a, xnonce(&wire, 0, NonceDirection::ResponderToInitiator));
        // And it is a pure function of its inputs.
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

        // Wrong epoch: same key, different nonce.
        let mut b = ct.clone();
        assert!(
            xchacha_open(&key, &wire, 4, NonceDirection::InitiatorToResponder, &mut b).is_err()
        );
        // Wrong direction.
        let mut b = ct.clone();
        assert!(
            xchacha_open(&key, &wire, 3, NonceDirection::ResponderToInitiator, &mut b).is_err()
        );
        // Wrong wire nonce.
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
        // Wrong key.
        let mut b = ct.clone();
        assert!(xchacha_open(
            &[0x43u8; 32],
            &wire,
            3,
            NonceDirection::InitiatorToResponder,
            &mut b
        )
        .is_err());
        // Tampered ciphertext.
        let mut b = ct.clone();
        b[0] ^= 0x80;
        assert!(
            xchacha_open(&key, &wire, 3, NonceDirection::InitiatorToResponder, &mut b).is_err()
        );
        // Tampered tag.
        let mut b = ct;
        let last = b.len() - 1;
        b[last] ^= 0x01;
        assert!(
            xchacha_open(&key, &wire, 3, NonceDirection::InitiatorToResponder, &mut b).is_err()
        );
    }

    #[test]
    fn test_random_xnonces_do_not_repeat() {
        // 96 random bits: a repeat in 4096 draws would mean the RNG, not luck.
        let set: std::collections::HashSet<[u8; WIRE_NONCE_LEN]> =
            (0..4096).map(|_| random_xnonce()).collect();
        assert_eq!(set.len(), 4096);
    }

    #[test]
    fn test_same_plaintext_seals_differently_under_distinct_nonces() {
        // With a random nonce, two frames carrying identical plaintext must not
        // look identical on the wire: that is the traffic-analysis property the
        // nonce change buys on top of the security one.
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
        // A v1 frame opened as v2 (or the reverse) must fail rather than produce
        // plaintext: the two schemes must not silently interoperate.
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
}
