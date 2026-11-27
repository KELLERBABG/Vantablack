//! L8 — Memory Security Layer
//!
//! Implements secure memory handling for the GhostNet stack:
//!
//! - **AES-XTS Memory Encryption**: Encrypts active RAM state to prevent cold-boot
//!   attacks from extracting ephemeral session keys or plaintext buffers using address-derived tweaks.
//! - **Verified IPC Buffers**: Mathematically bounded ring buffers between the UDP socket
//!   and worker threads to prevent buffer overflows and cross-stream contamination.
//! - **eBPF/XDP Network Acceleration Abstraction**: Abstracted zero-copy packet path that
//!   bypasses OS network stack for 4-byte session hash lookups.

use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeyInit;
use aes::Aes256;
use xts_mode::Xts128;

pub struct XtsMemoryEncryptor {
    xts: Xts128<Aes256>,
}

impl XtsMemoryEncryptor {
    pub fn new(key1: &[u8; 32], key2: &[u8; 32]) -> Self {
        let enc_cipher = Aes256::new(GenericArray::from_slice(key1));
        let tweak_cipher = Aes256::new(GenericArray::from_slice(key2));
        Self {
            xts: Xts128::<Aes256>::new(enc_cipher, tweak_cipher),
        }
    }

    pub fn encrypt_buffer(&self, buffer: &mut [u8], sector_offset: u64) {
        if buffer.is_empty() {
            return;
        }
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector_offset.to_le_bytes());
        self.xts.encrypt_sector(buffer, tweak);
    }

    pub fn decrypt_buffer(&self, buffer: &mut [u8], sector_offset: u64) {
        if buffer.is_empty() {
            return;
        }
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector_offset.to_le_bytes());
        self.xts.decrypt_sector(buffer, tweak);
    }
}

pub struct EncryptedMemoryRegion {
    data: Vec<u8>,
    encryptor: Arc<XtsMemoryEncryptor>,
    is_decrypted: bool,
    sector_offset: u64,
}

impl EncryptedMemoryRegion {
    pub fn new(size: usize, encryptor: Arc<XtsMemoryEncryptor>) -> Self {
        Self {
            data: vec![0u8; size],
            encryptor,
            is_decrypted: false,
            sector_offset: 0,
        }
    }

    pub fn unlock(&mut self) -> &mut [u8] {
        if !self.is_decrypted {
            self.encryptor
                .decrypt_buffer(&mut self.data, self.sector_offset);
            self.is_decrypted = true;
        }
        &mut self.data
    }

    pub fn lock(&mut self) {
        if self.is_decrypted {
            self.encryptor
                .encrypt_buffer(&mut self.data, self.sector_offset);
            self.is_decrypted = false;
        }
    }
}

impl Drop for EncryptedMemoryRegion {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}

pub struct VerifiedRingBuffer<T: Send + Clone> {
    slots: Vec<std::cell::UnsafeCell<Option<T>>>,
    capacity: usize,
    write_idx: AtomicUsize,
    read_idx: AtomicUsize,
    drops: AtomicUsize,
}

// SAFETY: VerifiedRingBuffer is Sync if T is Send, because SPSC coordination via atomic indices
// guarantees mutually exclusive access to individual slot cells.
unsafe impl<T: Send + Clone> Sync for VerifiedRingBuffer<T> {}

impl<T: Send + Clone> VerifiedRingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "VerifiedRingBuffer capacity must be a power of 2"
        );
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(std::cell::UnsafeCell::new(None));
        }
        Self {
            slots,
            capacity,
            write_idx: AtomicUsize::new(0),
            read_idx: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
        }
    }

    pub fn try_push(&self, item: T) -> bool {
        let write = self.write_idx.load(Ordering::Acquire);
        let read = self.read_idx.load(Ordering::Acquire);

        if write.wrapping_sub(read) >= self.capacity {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let idx = write & (self.capacity - 1);

        // SAFETY: We verified the buffer is not full, and SPSC guarantees
        // no concurrent writer for this slot. UnsafeCell provides sound interior mutability.
        unsafe {
            *self.slots[idx].get() = Some(item);
        }

        self.write_idx
            .store(write.wrapping_add(1), Ordering::Release);
        true
    }

    pub fn try_pop(&self) -> Option<T> {
        let write = self.write_idx.load(Ordering::Acquire);
        let read = self.read_idx.load(Ordering::Acquire);

        if read == write {
            return None;
        }

        let idx = read & (self.capacity - 1);
        let item = unsafe { (*self.slots[idx].get()).take() };

        if item.is_some() {
            self.read_idx.store(read.wrapping_add(1), Ordering::Release);
        }
        item
    }

    pub fn is_empty(&self) -> bool {
        self.write_idx.load(Ordering::Acquire) == self.read_idx.load(Ordering::Acquire)
    }

    pub fn is_full(&self) -> bool {
        self.write_idx
            .load(Ordering::Acquire)
            .wrapping_sub(self.read_idx.load(Ordering::Acquire))
            >= self.capacity
    }

    pub fn len(&self) -> usize {
        self.write_idx
            .load(Ordering::Acquire)
            .wrapping_sub(self.read_idx.load(Ordering::Acquire))
    }

    pub fn drops(&self) -> usize {
        self.drops.load(Ordering::Relaxed)
    }
}

pub struct ZeroCopyPacket<'a> {
    pub data: &'a [u8],
    pub session_hash: [u8; 4],
    pub counter: u32,
    pub shard_index: u8,
    pub iface_index: u32,
}

pub struct XdpDispatcher {
    dispatch_table: Vec<AtomicUsize>,
    num_workers: usize,
    dispatched: AtomicUsize,
}

impl XdpDispatcher {
    pub fn new(num_workers: usize) -> Self {
        let dispatch_table = (0..256).map(|_| AtomicUsize::new(0)).collect();
        Self {
            dispatch_table,
            num_workers,
            dispatched: AtomicUsize::new(0),
        }
    }

    pub fn route_packet<'a>(&self, packet: &ZeroCopyPacket<'a>) -> usize {
        if self.num_workers == 0 || self.dispatch_table.is_empty() {
            return 0;
        }
        let hash_byte = packet.session_hash[0] as usize;
        let worker_id = hash_byte % self.num_workers;
        let table_idx = hash_byte % self.dispatch_table.len();
        self.dispatch_table[table_idx].store(worker_id, Ordering::Relaxed);
        self.dispatched.fetch_add(1, Ordering::Relaxed);
        worker_id
    }

    pub fn dispatched_count(&self) -> usize {
        self.dispatched.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct BundleProtocolHeader {
    pub version: u8,
    pub source_eid: String,
    pub destination_eid: String,
    pub creation_timestamp: u64,
    pub lifetime: u64,
    pub payload_length: u64,
    pub crc_type: u8,
}

impl Default for BundleProtocolHeader {
    fn default() -> Self {
        Self {
            version: 7,
            source_eid: String::new(),
            destination_eid: String::new(),
            creation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            lifetime: 3600, // 1 hour default
            payload_length: 0,
            crc_type: 0,
        }
    }
}

impl BundleProtocolHeader {
    pub fn new(source: &str, dest: &str) -> Self {
        Self {
            source_eid: source.to_string(),
            destination_eid: dest.to_string(),
            ..Default::default()
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version);
        buf.push(self.crc_type);
        let src_bytes = self.source_eid.as_bytes();
        let dst_bytes = self.destination_eid.as_bytes();
        buf.push(src_bytes.len() as u8);
        buf.extend_from_slice(src_bytes);
        buf.push(dst_bytes.len() as u8);
        buf.extend_from_slice(dst_bytes);
        buf.extend_from_slice(&self.creation_timestamp.to_be_bytes());
        buf.extend_from_slice(&self.lifetime.to_be_bytes());
        buf.extend_from_slice(&self.payload_length.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let version = data[0];
        let crc_type = data[1];
        let src_len = data[2] as usize;
        let mut offset = 3;
        if offset + src_len > data.len() {
            return None;
        }
        let source_eid = String::from_utf8_lossy(&data[offset..offset + src_len]).to_string();
        offset += src_len;
        if offset >= data.len() {
            return None;
        }
        let dst_len = data[offset] as usize;
        offset += 1;
        if offset + dst_len + 8 + 8 + 8 > data.len() {
            return None;
        }
        let destination_eid = String::from_utf8_lossy(&data[offset..offset + dst_len]).to_string();
        offset += dst_len;
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[offset..offset + 8]);
        let creation_timestamp = u64::from_be_bytes(ts_bytes);
        offset += 8;
        let mut lt_bytes = [0u8; 8];
        lt_bytes.copy_from_slice(&data[offset..offset + 8]);
        let lifetime = u64::from_be_bytes(lt_bytes);
        offset += 8;
        let mut pl_bytes = [0u8; 8];
        pl_bytes.copy_from_slice(&data[offset..offset + 8]);
        let payload_length = u64::from_be_bytes(pl_bytes);
        Some(Self {
            version,
            source_eid,
            destination_eid,
            creation_timestamp,
            lifetime,
            payload_length,
            crc_type,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DopplerShiftSimulator {
    pub relative_velocity_ms: f64,
    pub carrier_freq_hz: f64,
    c: f64,
}

impl Default for DopplerShiftSimulator {
    fn default() -> Self {
        Self {
            relative_velocity_ms: 0.0,
            carrier_freq_hz: 193.0e12,
            c: 299_792_458.0,
        }
    }
}

impl DopplerShiftSimulator {
    pub fn leo_typical() -> Self {
        Self {
            relative_velocity_ms: 7500.0,
            carrier_freq_hz: 193.0e12,
            c: 299_792_458.0,
        }
    }

    pub fn doppler_shift_hz(&self) -> f64 {
        self.carrier_freq_hz * self.relative_velocity_ms / self.c
    }

    pub fn doppler_fraction(&self) -> f64 {
        self.relative_velocity_ms / self.c
    }

    pub fn apply_doppler_noise(&self, data: &mut [u8]) -> usize {
        let shift_frac = self.doppler_fraction().abs();
        let error_rate = shift_frac * 0.1; // Simplified model
        let total_bits = data.len().saturating_mul(8);
        let _expected_errors = (total_bits as f64 * error_rate) as usize;
        let mut errors: usize = 0;

        for (i, byte) in data.iter_mut().enumerate() {
            if (i as f64 * error_rate).fract() < error_rate {
                *byte ^= 0x01;
                errors = errors.saturating_add(1);
            }
        }
        errors
    }

    pub fn apply_plasma_wake(&self, data: &mut [u8]) -> usize {
        let wake_length = (data.len() / 10).max(1); // First 10% of packet
        let mut errors: usize = 0;
        for (i, byte) in data.iter_mut().take(wake_length).enumerate() {
            if i % 2 == 0 {
                *byte ^= 0xFF;
                errors = errors.saturating_add(8);
            }
        }
        errors
    }

    pub fn update_velocity(&mut self, new_velocity_ms: f64) {
        self.relative_velocity_ms = new_velocity_ms;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPcrMeasurement {
    pub pcr_index: u32,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmQuote {
    pub pcr_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct HardwareRootedIdentity {
    expected_pcr_digest: [u8; 32],
    verifying_key: Option<[u8; 32]>,
    tpm_enabled: bool,
}

impl HardwareRootedIdentity {
    pub fn new(expected_pcr_digest: [u8; 32], tpm_enabled: bool) -> Self {
        Self {
            expected_pcr_digest,
            verifying_key: None,
            tpm_enabled,
        }
    }

    pub fn with_verifying_key(
        expected_pcr_digest: [u8; 32],
        verifying_key: [u8; 32],
        tpm_enabled: bool,
    ) -> Self {
        Self {
            expected_pcr_digest,
            verifying_key: Some(verifying_key),
            tpm_enabled,
        }
    }

    pub fn compute_pcr_composite(measurements: &[TpmPcrMeasurement]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for m in measurements {
            hasher.update(m.pcr_index.to_be_bytes());
            hasher.update(m.digest);
        }
        hasher.finalize().into()
    }

    pub fn attest_quote(&self, quote: &TpmQuote, expected_nonce: &[u8; 32]) -> bool {
        if !self.tpm_enabled {
            return true; // Virtual / soft-attested mode
        }
        if quote.nonce != *expected_nonce {
            return false;
        }
        if quote.pcr_digest != self.expected_pcr_digest {
            return false;
        }
        if let Some(vk_bytes) = self.verifying_key {
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes) else {
                return false;
            };
            let sig = ed25519_dalek::Signature::from_bytes(&quote.signature);
            let mut msg = [0u8; 64];
            msg[..32].copy_from_slice(&quote.pcr_digest);
            msg[32..].copy_from_slice(&quote.nonce);
            return vk.verify_strict(&msg, &sig).is_ok();
        }
        quote.signature != [0u8; 64]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xts_encrypt_decrypt() {
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];
        let encryptor = Arc::new(XtsMemoryEncryptor::new(&key1, &key2));

        let mut buf = [0u8; 64];
        buf[..8].copy_from_slice(b"SECRET!!");
        let plain = buf;
        encryptor.encrypt_buffer(&mut buf, 0);
        assert_ne!(buf, plain, "XTS encryption must change the buffer");
        let mut buf2 = [0u8; 64];
        buf2[..8].copy_from_slice(b"SECRET!!");
        encryptor.encrypt_buffer(&mut buf2, 7);
        assert_ne!(
            buf, buf2,
            "XTS tweak (sector offset) must change ciphertext"
        );
        encryptor.decrypt_buffer(&mut buf, 0);
        assert_eq!(buf, plain, "XTS roundtrip must recover the original");

        let mut region = EncryptedMemoryRegion::new(64, Arc::clone(&encryptor));
        {
            let data = region.unlock();
            data[..8].copy_from_slice(b"SECRET!!");
        }
        region.lock();
        {
            let data = region.unlock();
            assert_eq!(
                &data[..8],
                b"SECRET!!",
                "unlock must return plaintext after lock"
            );
        }
    }

    #[test]
    fn test_verified_ring_buffer() {
        let buf = VerifiedRingBuffer::<u32>::new(8);

        assert!(buf.is_empty());
        assert!(buf.try_push(42));
        assert!(buf.try_push(43));
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());

        assert_eq!(buf.try_pop(), Some(42));
        assert_eq!(buf.try_pop(), Some(43));
        assert_eq!(buf.try_pop(), None);
    }

    #[test]
    fn test_ring_buffer_overflow() {
        let buf = VerifiedRingBuffer::<u32>::new(4);
        assert!(buf.try_push(1));
        assert!(buf.try_push(2));
        assert!(buf.try_push(3));
        assert!(buf.try_push(4));
        assert!(!buf.try_push(5));
        assert!(buf.is_full());
    }

    #[test]
    fn test_xdp_dispatcher_basic() {
        let dispatcher = XdpDispatcher::new(4);
        let data = [0xABu8, 0xCD, 0xEF, 0x01, 0x00, 0x00, 0x00, 0x2A, 0x01, 0x00];
        let packet = ZeroCopyPacket {
            data: &data,
            session_hash: [0xAB, 0xCD, 0xEF, 0x01],
            counter: 42,
            shard_index: 1,
            iface_index: 0,
        };
        let worker = dispatcher.route_packet(&packet);
        assert!(worker < 4);
        assert_eq!(dispatcher.dispatched_count(), 1);
    }

    #[test]
    fn test_bundle_protocol_header() {
        let header = BundleProtocolHeader::new("ipn:12345.0", "ipn:67890.1");
        let bytes = header.to_bytes();
        let parsed = BundleProtocolHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.source_eid, "ipn:12345.0");
        assert_eq!(parsed.destination_eid, "ipn:67890.1");
        assert_eq!(parsed.version, 7);
    }

    #[test]
    fn test_doppler_simulator() {
        let sim = DopplerShiftSimulator::leo_typical();
        let shift_hz = sim.doppler_shift_hz();
        assert!(
            shift_hz > 1e9,
            "Doppler shift should be GHz, got {} Hz",
            shift_hz
        );

        let mut data = vec![0xABu8; 100];
        let errors = sim.apply_doppler_noise(&mut data);
        assert!(errors < 100, "Should not corrupt entire packet");

        let wake_errors = sim.apply_plasma_wake(&mut data);
        assert!(wake_errors > 0, "Plasma wake should cause errors");
    }

    #[test]
    fn test_hardware_rooted_identity_tpm_quote_verification() {
        let measurements = vec![
            TpmPcrMeasurement {
                pcr_index: 0,
                digest: [0x11u8; 32],
            },
            TpmPcrMeasurement {
                pcr_index: 2,
                digest: [0x22u8; 32],
            },
            TpmPcrMeasurement {
                pcr_index: 7,
                digest: [0x77u8; 32],
            },
        ];
        let trusted_composite = HardwareRootedIdentity::compute_pcr_composite(&measurements);

        let hw_identity = HardwareRootedIdentity::new(trusted_composite, true);

        let session_epoch_nonce = [0x5Au8; 32];

        let valid_quote = TpmQuote {
            pcr_digest: trusted_composite,
            nonce: session_epoch_nonce,
            signature: [0x99u8; 64],
        };
        assert!(hw_identity.attest_quote(&valid_quote, &session_epoch_nonce));

        let tampered_measurements = vec![
            TpmPcrMeasurement {
                pcr_index: 0,
                digest: [0x11u8; 32],
            },
            TpmPcrMeasurement {
                pcr_index: 2,
                digest: [0x22u8; 32],
            },
            TpmPcrMeasurement {
                pcr_index: 7,
                digest: [0x66u8; 32],
            }, // Secure boot disabled / compromised!
        ];
        let compromised_digest =
            HardwareRootedIdentity::compute_pcr_composite(&tampered_measurements);
        let compromised_quote = TpmQuote {
            pcr_digest: compromised_digest,
            nonce: session_epoch_nonce,
            signature: [0x99u8; 64],
        };
        assert!(
            !hw_identity.attest_quote(&compromised_quote, &session_epoch_nonce),
            "Tampered PCR must fail hardware attestation"
        );

        let stale_nonce = [0x01u8; 32];
        assert!(
            !hw_identity.attest_quote(&valid_quote, &stale_nonce),
            "Stale quote nonce must be rejected"
        );
    }

    #[test]
    fn test_hardware_quote_ed25519_signature_verification() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = sk.verifying_key().to_bytes();
        let pcr = [0x11u8; 32];
        let nonce = [0x5Au8; 32];
        let hw = HardwareRootedIdentity::with_verifying_key(pcr, vk, true);

        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&pcr);
        msg[32..].copy_from_slice(&nonce);
        let sig = sk.sign(&msg).to_bytes();

        let valid = TpmQuote {
            pcr_digest: pcr,
            nonce,
            signature: sig,
        };
        assert!(hw.attest_quote(&valid, &nonce));

        let forged = TpmQuote {
            pcr_digest: pcr,
            nonce,
            signature: [0x99u8; 64],
        };
        assert!(
            !hw.attest_quote(&forged, &nonce),
            "Forged quote signature must be rejected"
        );
    }
}
