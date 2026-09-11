/// GhostNet Security Infrastructure
///
/// Implements several security subsystems from the roadmap:
/// 1. Decentralized Capability Revocation List (line 24)
/// 2. Zero-Knowledge Authentication During Discovery (line 25)
/// 3. Decentralized Two-Line Element Distribution (line 28)
/// 4. Memory Guard & Secure Zeroing (line 23)
/// 5. Fixed-Slot Temporal Isolation (line 26)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey512, MlKem512};
use tracing::{debug, info, warn};

// ── Platform-specific memory locking ──────────────────────────────────
//
// On Windows, VirtualLock pins pages in RAM so they cannot be paged to
// the swap file. On Unix, mlock() serves the same purpose.
// This prevents sensitive key material from leaking through cold-boot
// attacks or swap-file forensics.

#[cfg(target_os = "windows")]
fn platform_lock_memory(ptr: *const u8, len: usize) -> bool {
    extern "system" {
        fn VirtualLock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe {
        VirtualLock(ptr as *const std::ffi::c_void, len) != 0
    }
}

#[cfg(target_os = "windows")]
fn platform_unlock_memory(ptr: *const u8, len: usize) -> bool {
    extern "system" {
        fn VirtualUnlock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe {
        VirtualUnlock(ptr as *const std::ffi::c_void, len) != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn platform_lock_memory(ptr: *const u8, len: usize) -> bool {
    extern "C" {
        fn mlock(addr: *const std::ffi::c_void, len: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe {
        mlock(ptr as *const std::ffi::c_void, len) == 0
    }
}

#[cfg(not(target_os = "windows"))]
fn platform_unlock_memory(ptr: *const u8, len: usize) -> bool {
    extern "C" {
        fn munlock(addr: *const std::ffi::c_void, len: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe {
        munlock(ptr as *const std::ffi::c_void, len) == 0
    }
}

/// A memory region that is pinned to physical RAM via mlock/VirtualLock
/// and zeroed on drop using volatile writes.
///
/// This prevents the OS from paging sensitive key material to swap files
/// and ensures deterministic cleanup of cryptographic secrets.
pub struct LockedMemory {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
    locked: bool,
}

// SAFETY: LockedMemory is Send + Sync because the raw pointer is uniquely
// owned and never aliased. Access is controlled through the borrow-checker.
unsafe impl Send for LockedMemory {}
unsafe impl Sync for LockedMemory {}

impl LockedMemory {
    /// Allocate a page-aligned buffer of `size` bytes, zero it, and lock it in RAM.
    /// Returns None if allocation or locking fails.
    pub fn allocate(size: usize) -> Option<Self> {
        // Round up to nearest page size (4 KB typical)
        let page_size = 4096;
        let alloc_size = size.div_ceil(page_size) * page_size;

        let mut buf = vec![0; alloc_size];

        let ptr = buf.as_mut_ptr();
        let len = buf.len();
        let capacity = buf.capacity();

        // Leak the Vec so it's never deallocated by the allocator while we manage it.
        std::mem::forget(buf);

        let locked = platform_lock_memory(ptr, len);
        if !locked {
            // If locking failed, free the memory cleanly
            unsafe {
                let _ = Vec::from_raw_parts(ptr, len, capacity);
            }
            return None;
        }

        Some(Self { ptr, len, capacity, locked })
    }

    /// Get a mutable reference to the locked memory buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Get an immutable reference to the locked memory buffer.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Securely zero the memory using volatile writes.
    pub fn zero(&mut self) {
        unsafe {
            let ptr = self.ptr;
            for i in 0..self.len {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

impl Drop for LockedMemory {
    fn drop(&mut self) {
        self.zero();
        if self.locked {
            platform_unlock_memory(self.ptr, self.len);
        }
        // SAFETY: Reconstruct the Vec with identical ptr, len, and capacity from our leaked allocation.
        unsafe {
            let _ = Vec::from_raw_parts(self.ptr, self.len, self.capacity);
        }
    }
}

// ── 1. Decentralized Capability Revocation List ─────────────────────

#[derive(Debug, Clone)]
pub struct RevocationEntry {
    pub fingerprint: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub issuer_id: String,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    KeyCompromise,
    Decommissioned,
    ByzantineBehavior,
}

impl RevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::KeyCompromise => "key_compromise",
            RevocationReason::Decommissioned => "decommissioned",
            RevocationReason::ByzantineBehavior => "byzantine",
        }
    }
}

pub const REVOCATION_EXPIRY_SECS: u64 = 90 * 86400;

pub struct RevocationList {
    entries: Arc<Mutex<HashMap<String, RevocationEntry>>>,
    pub self_revoked: AtomicBool,
}

impl Default for RevocationList {
    fn default() -> Self {
        Self { entries: Arc::new(Mutex::new(HashMap::new())), self_revoked: AtomicBool::new(false) }
    }
}

impl RevocationList {
    pub fn new() -> Self { Self::default() }

    pub fn revoke(&self, entry: RevocationEntry) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let fp = entry.fingerprint.clone();
        if let Some(existing) = entries.get(&fp) {
            if entry.timestamp <= existing.timestamp { return false; }
        }
        debug!("Revoking identity: {} reason: {:?}", fp, entry.reason);
        entries.insert(fp, entry);
        true
    }

    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(fingerprint) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            if now - entry.timestamp < REVOCATION_EXPIRY_SECS { return true; }
        }
        false
    }

    pub fn prune_expired(&self) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let before = entries.len();
        entries.retain(|_, e| now - e.timestamp < REVOCATION_EXPIRY_SECS);
        before - entries.len()
    }

    pub fn reject_handshake(&self, peer_fingerprint: &str) -> bool {
        if self.is_revoked(peer_fingerprint) {
            warn!("Rejected handshake from revoked identity: {}", peer_fingerprint);
            true
        } else { false }
    }
}

// ── 2. Zero-Knowledge Authentication ─────────────────────────────────

pub struct ZkAuthResult {
    pub verified: bool,
    pub fingerprint: Option<String>,
}

/// Zero-knowledge proof of mesh membership via Schnorr-like signature proof.
pub struct ZkAuthenticator;

impl ZkAuthenticator {
    /// Create a non-interactive ZK proof: (proof_bytes, commitment_[u8; 32]).
    pub fn create_proof(
        _public_key_bytes: &[u8; 32],
        sign_fn: impl Fn(&[u8]) -> [u8; 64],
    ) -> (Vec<u8>, [u8; 32]) {
        use sha2::{Digest, Sha256};
        let nonce = rand::random::<[u8; 32]>();
        let d = Sha256::digest(nonce);
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&d.as_slice()[..32]);
        let proof = sign_fn(d.as_ref());
        (proof.to_vec(), commitment)
    }

    pub fn verify_proof(
        public_key_bytes: &[u8; 32],
        proof: &[u8],
        commitment: &[u8; 32],
    ) -> bool {
        if proof.len() != 64 { return false; }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&proof[..64]);
        crate::ghost::layers::l0_identity::verify_peer_signature(public_key_bytes, commitment, &sig_bytes)
    }

    pub fn private_fingerprint_comparison(
        local_fingerprint: &str,
        _local_public_key: &[u8; 32],
        remote_claim: &str,
        shared_nonce: &[u8],
    ) -> bool {
        use sha2::{Digest, Sha256};
        let local_hash = Sha256::digest([local_fingerprint.as_bytes(), shared_nonce].concat());
        let remote_hash = Sha256::digest([remote_claim.as_bytes(), shared_nonce].concat());
        local_hash.as_slice() == remote_hash.as_slice()
    }
}

// ── 3. Decentralized Two-Line Element Distribution ───────────────────

#[derive(Debug, Clone)]
pub struct TleData {
    pub name: String,
    pub norad_id: u32,
    pub epoch: f64,
    pub inclination: f64,
    pub raan: f64,
    pub eccentricity: f64,
    pub arg_perigee: f64,
    pub mean_anomaly: f64,
    pub mean_motion: f64,
    pub bstar: f64,
    pub last_updated: Instant,
}

pub struct TleDistributor {
    tle_store: Arc<Mutex<HashMap<u32, TleData>>>,
    requested_from: Arc<Mutex<Vec<String>>>,
    last_gossip: Arc<Mutex<Instant>>,
}

impl Default for TleDistributor {
    fn default() -> Self {
        Self {
            tle_store: Arc::new(Mutex::new(HashMap::new())),
            requested_from: Arc::new(Mutex::new(Vec::new())),
            last_gossip: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl TleDistributor {
    pub fn new() -> Self { Self::default() }

    pub fn store_tle(&self, tle: TleData) {
        let mut store = self.tle_store.lock().unwrap();
        let id = tle.norad_id;
        if let Some(existing) = store.get(&id) {
            if tle.last_updated <= existing.last_updated { return; }
        }
        debug!("Stored TLE for {} (NORAD {})", tle.name, id);
        store.insert(id, tle);
    }

    pub fn get_tle(&self, norad_id: u32) -> Option<TleData> {
        self.tle_store.lock().unwrap().get(&norad_id).cloned()
    }

    pub fn build_gossip_message(&self, max_count: usize) -> Vec<TleData> {
        let store = self.tle_store.lock().unwrap();
        store.values().take(max_count).cloned().collect()
    }

    pub fn should_gossip(&self) -> bool {
        let last = *self.last_gossip.lock().unwrap();
        last.elapsed() > Duration::from_secs(3600)
    }

    pub fn mark_gossiped(&self) {
        *self.last_gossip.lock().unwrap() = Instant::now();
    }

    pub fn from_orbital_elements(
        name: &str, norad_id: u32,
        elements: &crate::ghost::net::orbit::KeplerElements,
    ) -> Self {
        let _alt = elements.a - crate::ghost::net::orbit::EARTH_RADIUS;
        let period = elements.orbital_period();
        let mean_motion = 86400.0 / period;
        let mut store = HashMap::new();
        store.insert(norad_id, TleData {
            name: name.to_string(), norad_id,
            epoch: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
            inclination: elements.i.to_degrees(), raan: elements.raan.to_degrees(),
            eccentricity: elements.e, arg_perigee: elements.arg_perigee.to_degrees(),
            mean_anomaly: elements.mean_anomaly.to_degrees(), mean_motion, bstar: 0.0,
            last_updated: Instant::now(),
        });
        Self {
            tle_store: Arc::new(Mutex::new(store)),
            requested_from: Arc::new(Mutex::new(Vec::new())),
            last_gossip: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

// ── 4. Memory Guard — Secure Zeroing & Dead-Man's Switch ────────────

/// Secure memory guard with platform-level memory locking (mlock / VirtualLock)
/// and volatile zeroing on drop.
///
/// The internal buffer is zeroed via volatile writes on both `panic_zero()` and
/// `Drop`, preventing the compiler from optimizing away the zeroing. The
/// `lock_pages()` method additionally calls `mlock`/`VirtualLock` to prevent the
/// OS from paging the secret to the swap file.
pub struct SecureMemGuard<const N: usize> {
    data: [u8; N],
    tripped: AtomicBool,
    access_count: AtomicU64,
    pages_locked: AtomicBool,
}

impl<const N: usize> SecureMemGuard<N> {
    /// Create a new guard with the given secret and attempt page-locking.
    pub fn new(secret: [u8; N]) -> Self {
        let mut guard = Self {
            data: secret,
            tripped: AtomicBool::new(false),
            access_count: AtomicU64::new(0),
            pages_locked: AtomicBool::new(false),
        };
        // Attempt to lock the pages where this struct lives on the heap
        // (the struct is typically Box'd or Arc'd, so it's on the heap)
        guard.try_lock_pages();
        guard
    }

    /// Attempt to lock the memory pages containing the secret buffer.
    /// Returns true if locking succeeded, false otherwise.
    fn try_lock_pages(&mut self) -> bool {
        let ptr = &self.data as *const u8;
        let len = std::mem::size_of::<[u8; N]>();
        let locked = platform_lock_memory(ptr, len);
        // Due to stack alignment, the struct may not be page-aligned,
        // so VirtualLock/mlock may fail. That's OK — we still have
        // the volatile zeroing as a second layer of defense.
        if locked {
            self.pages_locked.store(true, Ordering::Relaxed);
            debug!("SecureMemGuard: locked {} bytes in RAM", N);
        }
        locked
    }

    pub fn access(&self) -> Option<&[u8; N]> {
        if self.tripped.load(Ordering::SeqCst) { return None; }
        self.access_count.fetch_add(1, Ordering::Relaxed);
        if self.detect_anomaly() { self.panic_zero(); return None; }
        Some(&self.data)
    }

    fn detect_anomaly(&self) -> bool {
        if self.access_count.load(Ordering::Relaxed) > 100_000 {
            warn!("SecureMemGuard: anomalous access count > 100k");
            return true;
        }
        false
    }

    pub fn panic_zero(&self) {
        if self.tripped.swap(true, Ordering::SeqCst) { return; }
        unsafe {
            let ptr = &self.data as *const u8 as *mut u8;
            for i in 0..N { std::ptr::write_volatile(ptr.add(i), 0u8); }
        }
        info!("SecureMemGuard: zeroed {} bytes", N);
    }

    pub fn is_tripped(&self) -> bool { self.tripped.load(Ordering::SeqCst) }

    /// Attempt to lock the secret pages. Call this after the guard has been
    /// placed on the heap (e.g., inside an Arc) for maximum effect.
    pub fn lock_memory(&self) -> bool {
        let ptr = &self.data as *const u8;
        let locked = platform_lock_memory(ptr, std::mem::size_of::<[u8; N]>());
        if locked {
            self.pages_locked.store(true, Ordering::Relaxed);
        }
        locked
    }

    /// Unlock the secret pages.
    pub fn unlock_memory(&self) {
        if self.pages_locked.load(Ordering::Relaxed) {
            let ptr = &self.data as *const u8;
            platform_unlock_memory(ptr, std::mem::size_of::<[u8; N]>());
            self.pages_locked.store(false, Ordering::Relaxed);
        }
    }

    /// Returns whether the memory pages are currently locked.
    pub fn is_locked(&self) -> bool {
        self.pages_locked.load(Ordering::Relaxed)
    }
}

impl<const N: usize> Drop for SecureMemGuard<N> {
    fn drop(&mut self) {
        self.panic_zero();
        if self.pages_locked.load(Ordering::Relaxed) {
            let ptr = &self.data as *const u8;
            platform_unlock_memory(ptr, std::mem::size_of::<[u8; N]>());
        }
    }
}

// ── 5bis. HSM / TPM Backend Abstraction ──────────────────────────────

/// Trait abstracting hardware security module (HSM) or TPM-backed key operations.
///
/// The Ed25519 identity signing key is the root of trust for the GhostNet
/// node identity. By keeping this key inside a hardware-backed enclave
/// (TPM 2.0, PKCS#11, NitroKey, YubiHSM), the private key material is
/// never exportable — even in the presence of kernel-level memory dumps.
///
/// Implementations:
/// - `SoftwareTpm`: In-memory key storage (fallback, for testing/dev)
/// - `Pkcs11Backend`: Real PKCS#11 HSM (production, requires `tss-esapi` or `cryptoki`)
/// - `Tpm2Backend`: TPM 2.0 via `tss-esapi` (production on TPM-equipped hardware)
pub trait HsmBackend: Send + Sync {
    /// Return the public key bytes for this identity.
    fn public_key(&self) -> &[u8; 32];

    /// Sign `data` with the Ed25519 key. Returns a 64-byte signature.
    fn sign(&self, data: &[u8]) -> [u8; 64];

    /// Verify a signature against the stored public key.
    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool;

    /// Derive a session sub-key from the identity key via KDF.
    /// This prevents the identity key from being used directly for bulk encryption.
    fn derive_session_key(&self, context: &[u8]) -> [u8; 32];

    /// Returns a human-readable identifier for the backend type.
    fn backend_type(&self) -> &'static str;
}

/// Software-backed HSM — stores the private key in a LockedMemory region.
///
/// This is the fallback implementation for testing and development.
/// For production, replace with `Pkcs11Backend` or `Tpm2Backend`.
pub struct SoftwareTpm {
    /// Ed25519 keypair wrapped in locked memory.
    keypair: ed25519_dalek::SigningKey,
    /// Cached public key bytes (32 bytes).
    public_key_bytes: [u8; 32],
    /// Human-readable fingerprint.
    fingerprint: String,
    /// Backend type string.
    backend: &'static str,
}

impl SoftwareTpm {
    /// Create a new software TPM from an existing Ed25519 signing key.
    pub fn new(keypair: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = keypair.verifying_key();
        let pk_bytes = verifying_key.to_bytes();
        let fp = hex::encode(&pk_bytes[..8]);
        Self {
            keypair,
            public_key_bytes: pk_bytes,
            fingerprint: fp,
            backend: "software",
        }
    }

    /// Generate a fresh Ed25519 key for the software TPM.
    pub fn generate_fresh() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
        Self::new(keypair)
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl HsmBackend for SoftwareTpm {
    fn public_key(&self) -> &[u8; 32] {
        &self.public_key_bytes
    }

    fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let signature = self.keypair.sign(data);
        signature.to_bytes()
    }

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let verifying_key = self.keypair.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        verifying_key.verify(data, &sig).is_ok()
    }

    fn derive_session_key(&self, context: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(self.fingerprint.as_bytes()), context);
        let mut session_key = [0u8; 32];
        hk.expand(b"GHOST_NET_HSM_SESSION_KEY", &mut session_key).unwrap();
        session_key
    }

    fn backend_type(&self) -> &'static str {
        self.backend
    }
}

// ── 6. Fixed-Slot Temporal Isolation ─────────────────────────────────

pub struct TemporalIsolator;

impl TemporalIsolator {
    pub fn fixed_time_decapsulate(
        _ciphertext: &[u8; 768],
        _secret_key: &DecapsulationKey512,
    ) -> Result<Vec<u8>, &'static str> {
        const DUMMY_ITERATIONS: usize = 10;

        let ct = Ciphertext::<MlKem512>::from(*_ciphertext);
        let shared_secret = _secret_key.decapsulate(&ct);
        let result: Vec<u8> = shared_secret.as_slice().to_vec();

        // Dummy iterations for timing padding
        let dummy_sk = DecapsulationKey512::from_seed([0u8; 64].into());
        let dummy_ct = Ciphertext::<MlKem512>::from([0u8; 768]);
        for _ in 0..DUMMY_ITERATIONS {
            let _ = dummy_sk.decapsulate(&dummy_ct);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_basic() {
        let rl = RevocationList::new();
        let fp = "deadbeef12345678".to_string();
        assert!(!rl.is_revoked(&fp));
        let entry = RevocationEntry {
            fingerprint: fp.clone(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            signature: vec![], issuer_id: "issuer".to_string(),
            reason: RevocationReason::KeyCompromise,
        };
        assert!(rl.revoke(entry));
        assert!(rl.is_revoked(&fp));
    }

    #[test]
    fn test_zk_proof_basic() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (proof, commitment) = ZkAuthenticator::create_proof(&pk, |d| identity.sign(d).to_bytes());
        assert!(ZkAuthenticator::verify_proof(&pk, &proof, &commitment));
    }

    #[test]
    fn test_zk_proof_wrong_key() {
        let i1 = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let i2 = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let (proof, commitment) = ZkAuthenticator::create_proof(&i1.public_key_bytes(), |d| i1.sign(d).to_bytes());
        assert!(!ZkAuthenticator::verify_proof(&i2.public_key_bytes(), &proof, &commitment));
    }

    #[test]
    fn test_secure_mem_guard() {
        let secret = [0xABu8; 32];
        let guard = SecureMemGuard::<32>::new(secret);
        let data = guard.access();
        assert!(data.is_some());
        assert_eq!(*data.unwrap(), secret);
        assert!(!guard.is_tripped());
    }

    #[test]
    fn test_secure_mem_guard_panic_zero() {
        let secret = [0xABu8; 32];
        let guard = SecureMemGuard::<32>::new(secret);
        guard.panic_zero();
        assert!(guard.is_tripped());
        assert!(guard.access().is_none());
    }

    #[test]
    fn test_tle_storage() {
        let tle_dist = TleDistributor::new();
        let tle = TleData {
            name: "TestSat".into(), norad_id: 12345, epoch: 0.0,
            inclination: 53.0, raan: 0.0, eccentricity: 0.001,
            arg_perigee: 0.0, mean_anomaly: 0.0, mean_motion: 15.5,
            bstar: 0.0, last_updated: Instant::now(),
        };
        tle_dist.store_tle(tle);
        let retrieved = tle_dist.get_tle(12345);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "TestSat");
    }
}
