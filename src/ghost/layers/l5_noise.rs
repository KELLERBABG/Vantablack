/// L5 — Noise Injection / Jitter Padding Layer
///
/// Adds random-length padding (0–64 bytes) to each packet beyond the
/// base GTF size. This frustrates traffic analysis attacks that rely
/// on correlating packet sizes to message lengths or protocol phases.
///
/// The jitter is appended after the auth tag and filled with random bytes,
/// making it indistinguishable from legitimate payload to a passive observer.

use rand::Rng;

/// Maximum number of jitter bytes appended to a base-size GTF packet.
pub const JITTER_MAX: usize = 64;

/// Applies jitter padding to a packet by extending it with random bytes.
/// Returns the number of jitter bytes added.
pub fn apply_jitter(packet: &mut Vec<u8>) -> usize {
    let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
    if jitter > 0 {
        let len = packet.len();
        packet.extend(std::iter::repeat_n(0u8, jitter));
        rand::thread_rng().fill(&mut packet[len..]);
    }
    jitter
}

/// Calculate the effective payload capacity for a given base packet size
/// after accounting for jitter space.
pub fn payload_capacity(base_size: usize) -> usize {
    base_size.saturating_sub(JITTER_MAX) // worst case
}
