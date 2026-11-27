//! GhostNet Security Infrastructure.
//!
//! Implements security subsystems including:
//! - Decentralized Capability Revocation Lists (dCRL)
//! - Zero-Knowledge Membership Authentication during peer discovery
//! - Ephemeris Two-Line Element (TLE) distribution
//! - Memory guarding & zeroization invariants
//! - Fixed-slot temporal isolation against side-channel analysis

use std::collections::HashMap;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey512, MlKem512};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_os = "windows")]
fn platform_lock_memory(ptr: *const u8, len: usize) -> bool {
    extern "system" {
        fn VirtualLock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe { VirtualLock(ptr as *const std::ffi::c_void, len) != 0 }
}

#[cfg(target_os = "windows")]
fn platform_unlock_memory(ptr: *const u8, len: usize) -> bool {
    extern "system" {
        fn VirtualUnlock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe { VirtualUnlock(ptr as *const std::ffi::c_void, len) != 0 }
}

#[cfg(not(target_os = "windows"))]
fn platform_lock_memory(ptr: *const u8, len: usize) -> bool {
    extern "C" {
        fn mlock(addr: *const std::ffi::c_void, len: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe { mlock(ptr as *const std::ffi::c_void, len) == 0 }
}

#[cfg(not(target_os = "windows"))]
fn platform_unlock_memory(ptr: *const u8, len: usize) -> bool {
    extern "C" {
        fn munlock(addr: *const std::ffi::c_void, len: usize) -> i32;
    }
    // SAFETY: Caller guarantees the memory region is valid and page-aligned.
    unsafe { munlock(ptr as *const std::ffi::c_void, len) == 0 }
}

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
    pub fn allocate(size: usize) -> Option<Self> {
        let page_size = 4096;
        let alloc_size = size.div_ceil(page_size) * page_size;

        let mut buf = vec![0; alloc_size];

        let ptr = buf.as_mut_ptr();
        let len = buf.len();
        let capacity = buf.capacity();

        std::mem::forget(buf);

        let locked = platform_lock_memory(ptr, len);
        if !locked {
            unsafe {
                let _ = Vec::from_raw_parts(ptr, len, capacity);
            }
            return None;
        }

        Some(Self {
            ptr,
            len,
            capacity,
            locked,
        })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

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
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            self_revoked: AtomicBool::new(false),
        }
    }
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&self, entry: RevocationEntry) -> bool {
        self.revoke_with_issuer_pk(entry, None)
    }

    pub fn revoke_with_issuer_pk(
        &self,
        entry: RevocationEntry,
        issuer_pk: Option<&[u8; 32]>,
    ) -> bool {
        if let Some(pk) = issuer_pk {
            if entry.signature.len() == 64 {
                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(&entry.signature);
                let msg = format!(
                    "REVOKE:{}:{}:{}",
                    entry.fingerprint,
                    entry.timestamp,
                    entry.reason.as_str()
                );
                if !crate::ghost::layers::l0_identity::verify_peer_signature(
                    pk,
                    msg.as_bytes(),
                    &sig_bytes,
                ) {
                    warn!(
                        "Revocation signature verification failed for {}",
                        entry.fingerprint
                    );
                    return false;
                }
            }
        }
        let mut entries = self.entries.lock().unwrap();
        let fp = entry.fingerprint.clone();
        if let Some(existing) = entries.get(&fp) {
            if entry.timestamp <= existing.timestamp {
                return false;
            }
        }
        debug!("Revoking identity: {} reason: {:?}", fp, entry.reason);
        entries.insert(fp, entry);
        true
    }

    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(fingerprint) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now - entry.timestamp < REVOCATION_EXPIRY_SECS {
                return true;
            }
        }
        false
    }

    pub fn prune_expired(&self) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let before = entries.len();
        entries.retain(|_, e| now - e.timestamp < REVOCATION_EXPIRY_SECS);
        before - entries.len()
    }

    pub fn reject_handshake(&self, peer_fingerprint: &str) -> bool {
        if self.is_revoked(peer_fingerprint) {
            warn!(
                "Rejected handshake from revoked identity: {}",
                peer_fingerprint
            );
            true
        } else {
            false
        }
    }
}

const ZK_MEMBER_LABEL: &[u8] = b"GGN_ZK_MEMBERSHIP_v1";
const ZK_CHALLENGE_LABEL: &[u8] = b"GGN_ZK_SCHNORR_CHALLENGE_v1";
pub const ZK_FRESHNESS_SECS: u64 = 300;
pub const ZK_CONTEXT_LEN: usize = 32;
pub const ZK_PROOF_LEN: usize = 64;

pub struct ZkAuthenticator;

impl ZkAuthenticator {
    fn membership_scalar(public_key_bytes: &[u8; 32], psk: &[u8; 32]) -> Scalar {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(psk);
        ikm[32..].copy_from_slice(public_key_bytes);
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(ZK_MEMBER_LABEL), &ikm);
        let mut okm = [0u8; 64];
        hk.expand(ZK_MEMBER_LABEL, &mut okm)
            .expect("64 bytes is inside HKDF-SHA256's output limit");
        let x = Scalar::from_bytes_mod_order_wide(&okm);
        ikm.zeroize();
        okm.zeroize();
        x
    }

    fn member_point(public_key_bytes: &[u8; 32], psk: &[u8; 32]) -> RistrettoPoint {
        RistrettoPoint::mul_base(&Self::membership_scalar(public_key_bytes, psk))
    }

    fn challenge(
        public_key_bytes: &[u8; 32],
        r_point: &RistrettoPoint,
        x_point: &RistrettoPoint,
        ts_be: &[u8; 8],
    ) -> Scalar {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(ZK_CHALLENGE_LABEL);
        h.update(public_key_bytes);
        h.update(r_point.compress().as_bytes());
        h.update(x_point.compress().as_bytes());
        h.update(ts_be);
        let digest = h.finalize();
        let mut wide = [0u8; 32];
        wide.copy_from_slice(&digest);
        Scalar::from_bytes_mod_order(wide)
    }

    pub fn create_proof(public_key_bytes: &[u8; 32], psk: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
        let x = Self::membership_scalar(public_key_bytes, psk);
        let x_point = RistrettoPoint::mul_base(&x);

        let mut r_bytes = [0u8; 64];
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut r_bytes);
        }
        let r = Scalar::from_bytes_mod_order_wide(&r_bytes);
        r_bytes.zeroize();
        let r_point = RistrettoPoint::mul_base(&r);

        let ts_be = now_secs().to_be_bytes();
        let c = Self::challenge(public_key_bytes, &r_point, &x_point, &ts_be);

        let z = r + c * x;
        let mut context = [0u8; ZK_CONTEXT_LEN];
        context[..8].copy_from_slice(&ts_be);
        let mut proof = [0u8; ZK_PROOF_LEN];
        proof[..32].copy_from_slice(r_point.compress().as_bytes());
        proof[32..].copy_from_slice(z.as_bytes());
        (context, proof)
    }

    pub fn verify_proof(
        public_key_bytes: &[u8; 32],
        psk: Option<&[u8; 32]>,
        context: &[u8; 32],
        proof: &[u8],
    ) -> bool {
        Self::verify_proof_at(public_key_bytes, psk, context, proof, now_secs())
    }

    pub fn verify_proof_at(
        public_key_bytes: &[u8; 32],
        psk: Option<&[u8; 32]>,
        context: &[u8; 32],
        proof: &[u8],
        now: u64,
    ) -> bool {
        use subtle::ConstantTimeEq;

        if proof.len() != ZK_PROOF_LEN || context.len() != ZK_CONTEXT_LEN {
            return false;
        }
        let Some(psk) = psk else {
            return false;
        };
        if context[8..].iter().any(|b| *b != 0) {
            return false;
        }
        let mut ts_be = [0u8; 8];
        ts_be.copy_from_slice(&context[..8]);
        let ts = u64::from_be_bytes(ts_be);
        let skew = now.saturating_sub(ts).max(ts.saturating_sub(now));
        if skew > ZK_FRESHNESS_SECS {
            return false;
        }

        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&proof[..32]);
        let Some(r_point) = CompressedRistretto(r_bytes).decompress() else {
            return false;
        };
        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&proof[32..]);
        let z = Scalar::from_canonical_bytes(z_bytes);
        if !bool::from(z.is_some()) {
            return false;
        }
        let z = z.unwrap_or(Scalar::ZERO);

        let x_point = Self::member_point(public_key_bytes, psk);
        let c = Self::challenge(public_key_bytes, &r_point, &x_point, &ts_be);
        let lhs = RistrettoPoint::mul_base(&z);
        let rhs = r_point + c * x_point;
        bool::from(lhs.ct_eq(&rhs))
    }

    pub fn private_fingerprint_comparison(
        local_fingerprint: &str,
        _local_public_key: &[u8; 32],
        remote_claim: &str,
        shared_nonce: &[u8],
    ) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let local_hash = Sha256::digest([local_fingerprint.as_bytes(), shared_nonce].concat());
        let remote_hash = Sha256::digest([remote_claim.as_bytes(), shared_nonce].concat());
        local_hash.as_slice().ct_eq(remote_hash.as_slice()).into()
    }
}

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
    last_gossip: Arc<Mutex<Instant>>,
}

impl Default for TleDistributor {
    fn default() -> Self {
        Self {
            tle_store: Arc::new(Mutex::new(HashMap::new())),
            last_gossip: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl TleDistributor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_tle(&self, tle: TleData) {
        let mut store = self.tle_store.lock().unwrap();
        let id = tle.norad_id;
        if let Some(existing) = store.get(&id) {
            if tle.last_updated <= existing.last_updated {
                return;
            }
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
        name: &str,
        norad_id: u32,
        elements: &crate::ghost::net::orbit::KeplerElements,
    ) -> Self {
        let _alt = elements.a - crate::ghost::net::orbit::EARTH_RADIUS;
        let period = elements.orbital_period();
        let mean_motion = 86400.0 / period;
        let mut store = HashMap::new();
        store.insert(
            norad_id,
            TleData {
                name: name.to_string(),
                norad_id,
                epoch: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
                inclination: elements.i.to_degrees(),
                raan: elements.raan.to_degrees(),
                eccentricity: elements.e,
                arg_perigee: elements.arg_perigee.to_degrees(),
                mean_anomaly: elements.mean_anomaly.to_degrees(),
                mean_motion,
                bstar: 0.0,
                last_updated: Instant::now(),
            },
        );
        Self {
            tle_store: Arc::new(Mutex::new(store)),
            last_gossip: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

pub struct SecureMemGuard<const N: usize> {
    data: std::cell::UnsafeCell<[u8; N]>,
    tripped: AtomicBool,
    access_count: AtomicU64,
    pages_locked: AtomicBool,
}

// SAFETY: SecureMemGuard coordinates interior mutability safely via AtomicBool tripped flag.
unsafe impl<const N: usize> Sync for SecureMemGuard<N> {}

impl<const N: usize> SecureMemGuard<N> {
    pub fn new(secret: [u8; N]) -> Self {
        let mut guard = Self {
            data: std::cell::UnsafeCell::new(secret),
            tripped: AtomicBool::new(false),
            access_count: AtomicU64::new(0),
            pages_locked: AtomicBool::new(false),
        };
        guard.try_lock_pages();
        guard
    }

    fn try_lock_pages(&mut self) -> bool {
        let ptr = self.data.get() as *const u8;
        let len = std::mem::size_of::<[u8; N]>();
        let locked = platform_lock_memory(ptr, len);
        if locked {
            self.pages_locked.store(true, Ordering::Relaxed);
            debug!("SecureMemGuard: locked {} bytes in RAM", N);
        }
        locked
    }

    pub fn access(&self) -> Option<&[u8; N]> {
        if self.tripped.load(Ordering::SeqCst) {
            return None;
        }
        self.access_count.fetch_add(1, Ordering::Relaxed);
        if self.detect_anomaly() {
            self.panic_zero();
            return None;
        }
        unsafe { Some(&*self.data.get()) }
    }

    fn detect_anomaly(&self) -> bool {
        if self.access_count.load(Ordering::Relaxed) > 100_000 {
            warn!("SecureMemGuard: anomalous access count > 100k");
            return true;
        }
        false
    }

    pub fn panic_zero(&self) {
        if self.tripped.swap(true, Ordering::SeqCst) {
            return;
        }
        unsafe {
            let ptr = self.data.get() as *mut u8;
            for i in 0..N {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        info!("SecureMemGuard: zeroed {} bytes", N);
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    pub fn lock_memory(&self) -> bool {
        let ptr = self.data.get() as *const u8;
        let locked = platform_lock_memory(ptr, std::mem::size_of::<[u8; N]>());
        if locked {
            self.pages_locked.store(true, Ordering::Relaxed);
        }
        locked
    }

    pub fn unlock_memory(&self) {
        if self.pages_locked.load(Ordering::Relaxed) {
            let ptr = self.data.get() as *const u8;
            platform_unlock_memory(ptr, std::mem::size_of::<[u8; N]>());
            self.pages_locked.store(false, Ordering::Relaxed);
        }
    }

    pub fn is_locked(&self) -> bool {
        self.pages_locked.load(Ordering::Relaxed)
    }
}

impl<const N: usize> Drop for SecureMemGuard<N> {
    fn drop(&mut self) {
        self.panic_zero();
        if self.pages_locked.load(Ordering::Relaxed) {
            let ptr = self.data.get() as *const u8;
            platform_unlock_memory(ptr, std::mem::size_of::<[u8; N]>());
        }
    }
}

pub mod hsm;

pub use hsm::{create_hsm_backend, create_hsm_backend_from_key, HsmBackend, SoftwareTpm};

#[cfg(feature = "hardware-tpm")]
pub use hsm::Tpm2Backend;

#[cfg(feature = "pkcs11")]
pub use hsm::Pkcs11Backend;

pub mod attest;

pub use attest::{AttestError, AttestationEnvelope};

pub struct TemporalIsolator;

impl TemporalIsolator {
    pub fn fixed_time_decapsulate(
        ciphertext: &[u8; 768],
        secret_key: &DecapsulationKey512,
    ) -> Result<Vec<u8>, &'static str> {
        let ct = Ciphertext::<MlKem512>::from(*ciphertext);
        let shared_secret = secret_key.decapsulate(&ct);
        Ok(shared_secret.as_slice().to_vec())
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
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signature: vec![],
            issuer_id: "issuer".to_string(),
            reason: RevocationReason::KeyCompromise,
        };
        assert!(rl.revoke(entry));
        assert!(rl.is_revoked(&fp));
    }

    fn zk_psk() -> [u8; 32] {
        [0x5A; 32]
    }

    fn zk_ts(context: &[u8; 32]) -> u64 {
        u64::from_be_bytes(context[..8].try_into().expect("8-byte timestamp"))
    }

    #[test]
    fn test_zk_proof_basic() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        assert!(ZkAuthenticator::verify_proof(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof
        ));
    }

    #[test]
    fn test_zk_proof_is_not_the_old_signature_over_a_discarded_nonce() {
        use sha2::{Digest, Sha256};
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let nonce = rand::random::<[u8; 32]>();
        let mut context = [0u8; 32];
        context.copy_from_slice(&Sha256::digest(nonce));
        let proof = identity.sign(&context).to_bytes();
        assert!(
            !ZkAuthenticator::verify_proof(&pk, Some(&zk_psk()), &context, &proof),
            "a signature over a discarded nonce is not a membership proof"
        );
    }

    #[test]
    fn test_zk_proof_wrong_key() {
        let i1 = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let i2 = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let (context, proof) = ZkAuthenticator::create_proof(&i1.public_key_bytes(), &zk_psk());
        assert!(!ZkAuthenticator::verify_proof(
            &i2.public_key_bytes(),
            Some(&zk_psk()),
            &context,
            &proof
        ));
    }

    #[test]
    fn test_zk_proof_wrong_membership_secret() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        assert!(!ZkAuthenticator::verify_proof(
            &pk,
            Some(&[0x99; 32]),
            &context,
            &proof
        ));
    }

    #[test]
    fn test_zk_proof_needs_the_membership_secret_to_verify() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        assert!(!ZkAuthenticator::verify_proof(&pk, None, &context, &proof));
    }

    #[test]
    fn test_zk_proof_alone_does_not_assert_an_identity() {
        let mine = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let theirs = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let (context, proof) = ZkAuthenticator::create_proof(&theirs.public_key_bytes(), &zk_psk());
        assert!(ZkAuthenticator::verify_proof(
            &theirs.public_key_bytes(),
            Some(&zk_psk()),
            &context,
            &proof
        ));
        assert!(!crate::ghost::layers::l0_identity::verify_peer_signature(
            &theirs.public_key_bytes(),
            &theirs.public_key_bytes(),
            &mine.sign(&theirs.public_key_bytes()).to_bytes()
        ));
    }

    #[test]
    fn test_zk_proof_is_fresh_only_inside_the_window() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        let ts = zk_ts(&context);

        assert!(ZkAuthenticator::verify_proof_at(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof,
            ts
        ));
        assert!(ZkAuthenticator::verify_proof_at(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof,
            ts + ZK_FRESHNESS_SECS
        ));
        assert!(ZkAuthenticator::verify_proof_at(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof,
            ts.saturating_sub(ZK_FRESHNESS_SECS)
        ));
        assert!(!ZkAuthenticator::verify_proof_at(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof,
            ts + ZK_FRESHNESS_SECS + 1
        ));
        assert!(!ZkAuthenticator::verify_proof_at(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof,
            ts.saturating_sub(ZK_FRESHNESS_SECS + 1)
        ));
    }

    #[test]
    fn test_zk_proof_cannot_be_refreshed_into_a_later_beacon() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        let mut moved = context;
        moved[..8].copy_from_slice(&(zk_ts(&context) + 1).to_be_bytes());
        assert!(!ZkAuthenticator::verify_proof_at(
            &pk,
            Some(&zk_psk()),
            &moved,
            &proof,
            zk_ts(&context) + 1
        ));
    }

    #[test]
    fn test_zk_proof_rejects_tampering_and_non_canonical_context() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());

        for byte in [0usize, 31, 32, 63] {
            let mut bad = proof;
            bad[byte] ^= 0x01;
            assert!(
                !ZkAuthenticator::verify_proof(&pk, Some(&zk_psk()), &context, &bad),
                "a flipped proof byte at {byte} must not verify"
            );
        }

        let mut bad_context = context;
        bad_context[8] = 0x01; // the reserved 24 bytes must be zero
        assert!(!ZkAuthenticator::verify_proof(
            &pk,
            Some(&zk_psk()),
            &bad_context,
            &proof
        ));

        assert!(!ZkAuthenticator::verify_proof(
            &pk,
            Some(&zk_psk()),
            &context,
            &proof[..63]
        ));
    }

    #[test]
    fn test_zk_proof_is_recomputed_per_call() {
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (c1, p1) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        let (c2, p2) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        assert_ne!(p1, p2);
        assert_eq!(c1[8..], [0u8; 24]);
        assert_eq!(c2[8..], [0u8; 24]);
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
            name: "TestSat".into(),
            norad_id: 12345,
            epoch: 0.0,
            inclination: 53.0,
            raan: 0.0,
            eccentricity: 0.001,
            arg_perigee: 0.0,
            mean_anomaly: 0.0,
            mean_motion: 15.5,
            bstar: 0.0,
            last_updated: Instant::now(),
        };
        tle_dist.store_tle(tle);
        let retrieved = tle_dist.get_tle(12345);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "TestSat");
    }

    #[test]
    fn test_constant_time_decapsulate_round_trips() {
        use ml_kem::kem::Encapsulate;
        use subtle::ConstantTimeEq;
        let (ek, dk) = crate::ghost::layers::l1_kem::generate_kyber_keypair();
        let (ct, ss) = ek.encapsulate();
        let ct_bytes: [u8; 768] = ct.into();

        let got = TemporalIsolator::fixed_time_decapsulate(&ct_bytes, &dk)
            .expect("a well-sized ciphertext decapsulates");
        assert_eq!(got.len(), 32, "ML-KEM-512 shared secret is 32 bytes");
        assert!(
            bool::from(got.as_slice().ct_eq(ss.as_slice())),
            "decapsulation must return exactly the encapsulator's secret"
        );
    }

    #[test]
    fn test_constant_time_decapsulate_never_errors_on_a_tampered_ciphertext() {
        use ml_kem::kem::Encapsulate;
        use subtle::ConstantTimeEq;
        let (ek, dk) = crate::ghost::layers::l1_kem::generate_kyber_keypair();
        let (ct, ss) = ek.encapsulate();
        let mut ct_bytes: [u8; 768] = ct.into();
        ct_bytes[0] ^= 0x01; // flip one byte

        let got = TemporalIsolator::fixed_time_decapsulate(&ct_bytes, &dk)
            .expect("implicit rejection returns a secret, never an error");
        assert_eq!(got.len(), 32);
        assert!(
            !bool::from(got.as_slice().ct_eq(ss.as_slice())),
            "a tampered ciphertext must not yield the true shared secret"
        );
    }

    #[test]
    fn test_constant_time_decapsulate_a_zeroed_ciphertext_is_total() {
        let (_ek, dk) = crate::ghost::layers::l1_kem::generate_kyber_keypair();
        let got = TemporalIsolator::fixed_time_decapsulate(&[0u8; 768], &dk)
            .expect("an all-zero ciphertext is handled, not rejected");
        assert_eq!(got.len(), 32);
    }
}
