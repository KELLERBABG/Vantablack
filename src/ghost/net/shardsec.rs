//! ShardSec: independent authenticated encryption for Reed-Solomon shards.
//!
//! A message is RS-encoded first, then each shard is sealed with a distinct
//! key derived from the session secret, epoch, message nonce, and shard index.
//! A captured shard therefore does not expose a decryptable fragment of the
//! message and a tampered shard is discarded before reconstruction.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::ghost::layers::l2_aead::{xchacha_open, xchacha_seal_in_place, NonceDirection};
use crate::ghost::layers::l4_rs;

pub const SHARDSEC_LABEL: &[u8] = b"GGN_SHARDSEC_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShard {
    pub index: u8,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub is_honey: bool,
}

pub const HONEY_TRAP_LABEL: &[u8] = b"GGN_HONEY_TRAP_KEY_V1";

fn shard_key(master: &[u8; 32], epoch: u64, nonce: &[u8; 12], index: u8) -> [u8; 32] {
    let mut info = Vec::with_capacity(SHARDSEC_LABEL.len() + 8 + 12 + 1);
    info.extend_from_slice(SHARDSEC_LABEL);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(nonce);
    info.push(index);
    let hk = Hkdf::<Sha256>::new(Some(master), &[]);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("32-byte HKDF output");
    key
}

fn shard_nonce(base: &[u8; 12], index: u8) -> [u8; 12] {
    let mut nonce = *base;
    nonce[11] ^= index;
    nonce
}

/// Seal one already RS-encoded shard with its independent key.
pub fn seal_shard(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    index: u8,
    mut shard: Vec<u8>,
) -> SealedShard {
    let key = shard_key(master, epoch, nonce, index);
    let shard_nonce = shard_nonce(nonce, index);
    xchacha_seal_in_place(&key, &shard_nonce, epoch, direction, &mut shard)
        .expect("owned shard seal");
    let tag = shard[shard.len() - 16..].try_into().expect("AEAD tag");
    shard.truncate(shard.len() - 16);
    SealedShard {
        index,
        ciphertext: shard,
        tag,
        is_honey: false,
    }
}

/// Invention §15: Honey-Shards — Adversarial Tamper Traps.
///
/// Seals a shard with a deliberately poisoned trap tag derived from [`HONEY_TRAP_LABEL`].
/// A Byzantine on-path relay that alters bytes will produce an authentication
/// anomaly that isolates the adversary on the reputation matrix.
pub fn seal_honey_shard(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    index: u8,
    mut shard: Vec<u8>,
) -> SealedShard {
    let mut trap_master = *master;
    for (i, b) in HONEY_TRAP_LABEL.iter().enumerate() {
        trap_master[i % 32] ^= b;
    }
    let key = shard_key(&trap_master, epoch, nonce, index);
    let shard_nonce = shard_nonce(nonce, index);
    xchacha_seal_in_place(&key, &shard_nonce, epoch, direction, &mut shard)
        .expect("owned shard seal");
    let tag = shard[shard.len() - 16..].try_into().expect("AEAD tag");
    shard.truncate(shard.len() - 16);
    SealedShard {
        index,
        ciphertext: shard,
        tag,
        is_honey: true,
    }
}

/// Verifies whether a honey shard arrived intact with its expected trap tag.
/// Returns Ok(true) if the honey shard was untampered, Ok(false) if tampered by Byzantine relay.
pub fn verify_honey_shard(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    honey: &SealedShard,
) -> bool {
    if !honey.is_honey || honey.index >= 3 {
        return false;
    }
    let mut trap_master = *master;
    for (i, b) in HONEY_TRAP_LABEL.iter().enumerate() {
        trap_master[i % 32] ^= b;
    }
    let key = shard_key(&trap_master, epoch, nonce, honey.index);
    let shard_nonce = shard_nonce(nonce, honey.index);
    let mut ciphertext = honey.ciphertext.clone();
    ciphertext.extend_from_slice(&honey.tag);
    xchacha_open(&key, &shard_nonce, epoch, direction, &mut ciphertext).is_ok()
}

/// Authenticate and open one independently sealed shard.
pub fn open_shard(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    sealed: &SealedShard,
) -> Result<Vec<u8>, &'static str> {
    if sealed.index >= 3 {
        return Err("invalid shard index");
    }
    let key = shard_key(master, epoch, nonce, sealed.index);
    let shard_nonce = shard_nonce(nonce, sealed.index);
    let mut ciphertext = sealed.ciphertext.clone();
    ciphertext.extend_from_slice(&sealed.tag);
    xchacha_open(&key, &shard_nonce, epoch, direction, &mut ciphertext)
        .map_err(|_| "shard authentication failed")?;
    Ok(ciphertext)
}

/// RS-encode and independently seal every shard.
pub fn seal_message(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    plaintext: &[u8],
) -> Vec<SealedShard> {
    let mut framed = (plaintext.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(plaintext);
    if framed.len() % 2 != 0 {
        framed.push(0);
    }
    let shards = l4_rs::encode(&mut framed);
    shards
        .into_iter()
        .enumerate()
        .map(|(index, shard)| seal_shard(master, epoch, nonce, direction, index as u8, shard))
        .collect()
}

/// Authenticate/decrypt available shards and reconstruct after at least two pass.
pub fn open_message(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    sealed: &[Option<SealedShard>],
) -> Result<Vec<u8>, &'static str> {
    if sealed.len() != 3 {
        return Err("ShardSec requires exactly three shard slots");
    }
    let mut shards: Vec<Option<Vec<u8>>> = vec![None, None, None];
    for candidate in sealed.iter().flatten() {
        if candidate.index >= 3 || shards[candidate.index as usize].is_some() {
            continue;
        }
        if let Ok(plaintext) = open_shard(master, epoch, nonce, direction, candidate) {
            shards[candidate.index as usize] = Some(plaintext);
        }
    }
    if shards.iter().filter(|s| s.is_some()).count() < 2 {
        return Err("fewer than two authenticated shards");
    }
    l4_rs::reconstruct(&mut shards).map_err(|_| "Reed-Solomon reconstruction failed")?;
    let first = shards[0].as_ref().ok_or("missing reconstructed shard")?;
    let second = shards[1].as_ref().ok_or("missing reconstructed shard")?;
    let mut framed = Vec::with_capacity(first.len() + second.len());
    framed.extend_from_slice(first);
    framed.extend_from_slice(second);
    if framed.len() < 2 {
        return Err("reconstructed payload is truncated");
    }
    let length = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    if length + 2 > framed.len() {
        return Err("reconstructed payload length is invalid");
    }
    framed.truncate(length + 2);
    Ok(framed[2..].to_vec())
}

// ═════════════════════════════════════════════════════════════════════════════
// Invention §30: Time-as-the-4th-Shard (Scheduled Shard Dispatch)
// ═════════════════════════════════════════════════════════════════════════════

/// A shard scheduled for temporal egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledShard {
    pub shard: SealedShard,
    /// Delay offset in milliseconds relative to T_0.
    pub delay_ms: u64,
}

/// Temporal dispatch scheduler for Reed-Solomon shards.
///
/// Dispatches shards not only across space (independent routes) but scheduled
/// across time (T_0, T_0 + delta, next beacon epoch).
/// An adversary who intercepts traffic over a limited capture window (e.g. < delta)
/// captures fewer than 2 shards and cannot reconstruct the plaintext.
#[derive(Debug, Clone)]
pub struct TemporalShardScheduler {
    pub base_delay_ms: u64,
    pub jitter_ms: u64,
}

impl Default for TemporalShardScheduler {
    fn default() -> Self {
        Self {
            base_delay_ms: 200, // 200ms nominal staggered dispatch
            jitter_ms: 0,
        }
    }
}

impl TemporalShardScheduler {
    pub fn new(base_delay_ms: u64) -> Self {
        Self {
            base_delay_ms,
            jitter_ms: 0,
        }
    }

    /// Schedule egress flights for a 3-shard message.
    /// Shard 0: T_0 (0 ms delay)
    /// Shard 1: T_0 + base_delay_ms (e.g. 200 ms)
    /// Shard 2: T_0 + 2 * base_delay_ms (e.g. 400 ms)
    pub fn schedule(&self, shards: Vec<SealedShard>) -> Vec<ScheduledShard> {
        shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let delay_ms = (i as u64) * self.base_delay_ms
                    + (self.jitter_ms % (self.base_delay_ms.max(1) + 1));
                ScheduledShard { shard, delay_ms }
            })
            .collect()
    }

    /// Simulates what an attacker captures given an observation window `[window_start_ms, window_end_ms]`.
    /// Returns only the shards dispatched within that temporal window.
    pub fn intercept_window(
        scheduled: &[ScheduledShard],
        window_start_ms: u64,
        window_end_ms: u64,
    ) -> Vec<Option<SealedShard>> {
        let mut captured = vec![None, None, None];
        for s in scheduled {
            if s.delay_ms >= window_start_ms && s.delay_ms <= window_end_ms {
                if (s.shard.index as usize) < 3 {
                    captured[s.shard.index as usize] = Some(s.shard.clone());
                }
            }
        }
        captured
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::ghost::layers::l2_aead::random_xnonce;

    #[test]
    fn two_authenticated_shards_reconstruct() {
        let key = [0x42; 32];
        let nonce = random_xnonce();
        let sealed = seal_message(
            &key,
            3,
            &nonce,
            NonceDirection::InitiatorToResponder,
            b"secret",
        );
        let mut available = vec![Some(sealed[0].clone()), None, Some(sealed[2].clone())];
        assert_eq!(
            open_message(
                &key,
                3,
                &nonce,
                NonceDirection::InitiatorToResponder,
                &available
            )
            .unwrap(),
            b"secret"
        );
        available[0].as_mut().unwrap().ciphertext[0] ^= 1;
        assert!(open_message(
            &key,
            3,
            &nonce,
            NonceDirection::InitiatorToResponder,
            &available
        )
        .is_err());
    }

    #[test]
    fn one_captured_shard_never_opens() {
        let sealed = seal_message(
            &[7; 32],
            1,
            &[9; 12],
            NonceDirection::ResponderToInitiator,
            b"plaintext",
        );
        let available = vec![Some(sealed[1].clone()), None, None];
        assert!(open_message(
            &[7; 32],
            1,
            &[9; 12],
            NonceDirection::ResponderToInitiator,
            &available
        )
        .is_err());
    }

    #[test]
    fn test_honey_shard_tamper_detection() {
        let master = [0x33u8; 32];
        let epoch = 12u64;
        let nonce = [0x55u8; 12];
        let dir = NonceDirection::InitiatorToResponder;
        let payload = b"trap_payload_shard_data".to_vec();

        // Legitimate honey shard verifies intact
        let honey = seal_honey_shard(&master, epoch, &nonce, dir, 1, payload);
        assert!(honey.is_honey);
        assert!(verify_honey_shard(&master, epoch, &nonce, dir, &honey));

        // Tampering with the honey shard payload fails canary verification
        let mut tampered = honey.clone();
        tampered.ciphertext[0] ^= 0x01;
        assert!(!verify_honey_shard(&master, epoch, &nonce, dir, &tampered));

        // Normal shard is not a honey shard
        let normal = seal_shard(&master, epoch, &nonce, dir, 0, b"normal".to_vec());
        assert!(!normal.is_honey);
        assert!(!verify_honey_shard(&master, epoch, &nonce, dir, &normal));
    }

    #[test]
    fn test_temporal_shard_schedule_and_partial_window_adversary() {
        let master = [0x7au8; 32];
        let epoch = 100u64;
        let nonce = [0x11u8; 12];
        let dir = NonceDirection::InitiatorToResponder;
        let secret = b"temporal_scheduled_message";

        let sealed = seal_message(&master, epoch, &nonce, dir, secret);
        assert_eq!(sealed.len(), 3);

        let scheduler = TemporalShardScheduler::new(200);
        let scheduled = scheduler.schedule(sealed);
        assert_eq!(scheduled.len(), 3);
        assert_eq!(scheduled[0].delay_ms, 0);
        assert_eq!(scheduled[1].delay_ms, 200);
        assert_eq!(scheduled[2].delay_ms, 400);

        // Adversary with short capture window (0ms to 100ms) only intercepts shard 0
        let partial_capture = TemporalShardScheduler::intercept_window(&scheduled, 0, 100);
        assert!(partial_capture[0].is_some());
        assert!(partial_capture[1].is_none());
        assert!(partial_capture[2].is_none());
        // Fewer than 2 shards must fail to open
        let open_res = open_message(&master, epoch, &nonce, dir, &partial_capture);
        assert!(
            open_res.is_err(),
            "Partial temporal capture (1 shard) must not reconstruct"
        );

        // Adversary or recipient with full window (0ms to 500ms) receives all shards and reconstructs
        let full_capture = TemporalShardScheduler::intercept_window(&scheduled, 0, 500);
        let reconstructed = open_message(&master, epoch, &nonce, dir, &full_capture)
            .expect("Full temporal window must reconstruct");
        assert_eq!(reconstructed, secret);
    }
}
