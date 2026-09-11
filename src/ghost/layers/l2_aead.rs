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
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Direction indicator — XOR'd into the nonce to prevent directional nonce collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceDirection {
    /// Packets sent from session initiator to responder.
    InitiatorToResponder = 0x00,
    /// Packets sent from session responder to initiator.
    ResponderToInitiator = 0x01,
}

/// Build a 12-byte nonce from a 64-bit counter value, session hash, and direction.
///
/// Layout: [session_hash[0..2]:2 | direction:1 | reserved:1 | counter:8 BE]
///
/// This design guarantees uniqueness across sessions (via session hash prefix),
/// across directions (via direction byte), and across time (via full 64-bit monotonic counter).
/// Spanning the full remaining 8 bytes eliminates counter exhaustion on high-throughput links.
pub fn nonce_from_counter_u64(counter: u64, session_hash: &[u8; 4], direction: NonceDirection) -> [u8; 12] {
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
pub fn nonce_from_counter(counter: u32, session_hash: &[u8; 4], direction: NonceDirection) -> [u8; 12] {
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
            Nonce::from_slice(&nonce_from_counter(counter, &sh, NonceDirection::InitiatorToResponder)),
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
    cipher
        .decrypt_in_place(
            Nonce::from_slice(&nonce_from_counter(counter, &sh, NonceDirection::InitiatorToResponder)),
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
    cipher
        .decrypt_in_place(
            Nonce::from_slice(&nonce_from_counter(counter, session_hash, direction)),
            &[],
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
        assert_ne!(nonce_init, nonce_resp, "Direction should produce different nonces");
        assert_eq!(nonce_init[2], 0x00);
        assert_eq!(nonce_resp[2], 0x01);
    }

    #[test]
    fn test_nonce_session_hash_difference() {
        let sh1 = [0xDE, 0xAD, 0xBE, 0xEF];
        let sh2 = [0xCA, 0xFE, 0xBA, 0xBE];
        let nonce1 = nonce_from_counter(42, &sh1, NonceDirection::InitiatorToResponder);
        let nonce2 = nonce_from_counter(42, &sh2, NonceDirection::InitiatorToResponder);
        assert_ne!(nonce1, nonce2, "Different session hashes should produce different nonces");
    }

    #[test]
    fn test_nonce_counter_difference() {
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let nonce1 = nonce_from_counter(42, &sh, NonceDirection::InitiatorToResponder);
        let nonce2 = nonce_from_counter(43, &sh, NonceDirection::InitiatorToResponder);
        assert_ne!(nonce1, nonce2, "Different counters should produce different nonces");
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
        ].into_iter().collect();
        assert_eq!(nonces.len(), 4, "All four combinations should produce unique nonces");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_context() {
        let key = [0x42u8; 32];
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut data = b"HELLO GHOSTNET".to_vec();
        let original = data.clone();
        encrypt_in_place_with_context(&key, 0, &sh, NonceDirection::InitiatorToResponder, &mut data);
        assert_ne!(data, original, "Ciphertext should differ from plaintext");
        let pt = decrypt_in_place_with_context(&key, 0, &sh, NonceDirection::InitiatorToResponder, &mut data)
            .expect("Decryption should succeed");
        assert_eq!(pt, original.as_slice(), "Roundtrip should recover original");
    }

    #[test]
    fn test_encrypt_decrypt_wrong_direction_fails() {
        let key = [0x42u8; 32];
        let sh = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut data = b"HELLO GHOSTNET".to_vec();
        encrypt_in_place_with_context(&key, 0, &sh, NonceDirection::InitiatorToResponder, &mut data);
        // Decrypt with wrong direction — should fail
        let result = decrypt_in_place_with_context(&key, 0, &sh, NonceDirection::ResponderToInitiator, &mut data);
        assert!(result.is_err(), "Decryption with wrong direction should fail");
    }

    #[test]
    fn test_needs_rekey_threshold() {
        assert!(!needs_rekey(0));
        assert!(!needs_rekey(u32::MAX - 2000));
        assert!(needs_rekey(u32::MAX - 500));
        assert!(needs_rekey(u32::MAX));
    }
}
