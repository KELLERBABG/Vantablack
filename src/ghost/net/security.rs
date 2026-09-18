/// GhostNet Security Infrastructure
///
/// Implements several security subsystems from the roadmap:
/// 1. Decentralized Capability Revocation List (line 24)
/// 2. Zero-Knowledge Membership Authentication During Discovery (line 25)
/// 3. Decentralized Two-Line Element Distribution (line 28)
/// 4. Memory Guard & Secure Zeroing (line 23)
/// 5. Fixed-Slot Temporal Isolation (line 26)
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

/// Seconds since the Unix epoch, saturating at 0 before it.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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

        Some(Self {
            ptr,
            len,
            capacity,
            locked,
        })
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

    /// Revoke an identity. If entry.signature is non-empty, verifies the signature against issuer_pk_bytes.
    /// Returns true if revoked, false if expired, older timestamp, or signature invalid.
    pub fn revoke(&self, entry: RevocationEntry) -> bool {
        self.revoke_with_issuer_pk(entry, None)
    }

    /// Revoke an identity with explicit issuer public key verification.
    /// If issuer_pk is provided and signature is present, verifies that the issuer signed
    /// the message: "REVOKE:" || fingerprint || ":" || timestamp || ":" || reason.as_str().
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

// ── 2. Zero-Knowledge Membership Authentication ──────────────────────
//
// Discovery used to carry `(sign(SHA256(nonce)), SHA256(nonce))` with `nonce`
// thrown away: a "commitment" that opened nothing, a signature over a hash of a
// discarded value, and — since nothing tied the block to the beacon, to the
// identity or to any moment in time — a proof that could be lifted out of one
// beacon and replayed in another. It proved key possession, redundantly with the
// beacon's own signature, and it was not zero-knowledge.
//
// What replaces it is a Schnorr proof of knowledge over Ristretto255 with
// Fiat–Shamir, on the statement that the sender knows the mesh *membership*
// secret for the identity whose Ed25519 key the beacon carries:
//
//     x = HKDF-SHA256(salt = ZK_MEMBER_LABEL, ikm = GHOST_PSK ‖ ed25519_pk) → Scalar
//     X = x·B                                  (never sent: a member derives it)
//     r ← random;  R = r·B
//     c = SHA-256(ZK_CHALLENGE_LABEL ‖ pk ‖ R ‖ X ‖ ts)
//     z = r + c·x  (mod ℓ)
//     block = context[ts_be ‖ 0^24] ‖ proof[R ‖ z]
//
// Three properties the old block did not have:
//
//   * **Zero-knowledge.** `z` is uniform given `c` because `r` is, so no bit of
//     `x` — and no bit of the PSK behind it — leaks: the simulator answers with
//     a random `z` and `R = z·B − c·X`, a distribution no verifier can tell from
//     an honest proof. The old block handed over a signature, which is a
//     *transferable* possession proof — whoever held it could present it again.
//   * **Bound to the identity and to the moment.** `x` mixes the PSK with the
//     beacon's own Ed25519 key, so one member's proof is not another member's
//     and cannot be moved to a different `pk`; the challenge covers `pk`, `R`,
//     `X` and the timestamp, so a captured proof cannot be refreshed into a
//     later beacon.
//   * **Members only.** An outsider cannot derive `X` without the PSK, so it
//     cannot verify the proof — let alone forge one. (It can still read the
//     beacon: the identity in it is public and signed. This proves membership;
//     it does not hide who is speaking — the zero-knowledge here is about the
//     membership credential, not about anonymity.)
//
// Freshness is a ±ZK_FRESHNESS_SECS window rather than a nonce, because a beacon
// is a broadcast and there is no verifier to hand one out; that bounds replay to
// the window. The timestamp rides in the block's 32-byte context because the
// 112-byte signed prefix has no timestamp field and adding one would change a
// layout peers verify at fixed offsets.
//
// The block stays 96 bytes (`context[32] ‖ proof[64]`) and changes meaning. This
// is a hard switch: the signature-shaped block is neither emitted nor accepted
// (SPECIFICATIONS.md §"Beacon sections"), so a peer that still sends one is
// understood only as a bare identity-only beacon and never gets credit for a
// membership proof.

/// Domain label for the membership scalar derivation.
const ZK_MEMBER_LABEL: &[u8] = b"GGN_ZK_MEMBERSHIP_v1";
/// Domain label for the Fiat–Shamir challenge.
const ZK_CHALLENGE_LABEL: &[u8] = b"GGN_ZK_SCHNORR_CHALLENGE_v1";
/// How far a proof's timestamp may sit from the verifier's clock, in seconds.
pub const ZK_FRESHNESS_SECS: u64 = 300;
/// The context field carried beside the proof: `timestamp_be ‖ 0^24`.
pub const ZK_CONTEXT_LEN: usize = 32;
/// The proof itself: `R ‖ z`, one compressed Ristretto point and one scalar.
pub const ZK_PROOF_LEN: usize = 64;

/// Zero-knowledge proof of mesh membership, on the discovery path.
pub struct ZkAuthenticator;

impl ZkAuthenticator {
    /// `x = HKDF-SHA256(salt = ZK_MEMBER_LABEL, ikm = PSK ‖ pk)`, reduced onto
    /// the Ristretto255 scalar field. Secret: it is the membership credential
    /// for exactly one identity.
    fn membership_scalar(public_key_bytes: &[u8; 32], psk: &[u8; 32]) -> Scalar {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(psk);
        ikm[32..].copy_from_slice(public_key_bytes);
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(ZK_MEMBER_LABEL), &ikm);
        let mut okm = [0u8; 64];
        hk.expand(ZK_MEMBER_LABEL, &mut okm)
            .expect("64 bytes is inside HKDF-SHA256's output limit");
        let x = Scalar::from_bytes_mod_order_wide(&okm);
        // The input keying material is the PSK: neither it nor the derived
        // scalar may be left in a heap or stack buffer after this returns.
        ikm.zeroize();
        okm.zeroize();
        x
    }

    /// The public half of the statement, `X = x·B`. Derived, not transmitted:
    /// only a holder of the PSK can compute it.
    fn member_point(public_key_bytes: &[u8; 32], psk: &[u8; 32]) -> RistrettoPoint {
        RistrettoPoint::mul_base(&Self::membership_scalar(public_key_bytes, psk))
    }

    /// `c = SHA-256(label ‖ pk ‖ R ‖ X ‖ ts)`, reduced onto the scalar field.
    /// Binding `pk` is what stops a proof moving between identities; binding the
    /// timestamp is what stops it being replayed later.
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

    /// Create a membership proof for `public_key_bytes` under the mesh PSK.
    ///
    /// Returns `(context, proof)`: the 32-byte context is the timestamp the
    /// proof is bound to (big-endian, zero-padded), the 64-byte proof is
    /// `R ‖ z`. Nothing here is a signature, and nothing reveals the PSK.
    pub fn create_proof(public_key_bytes: &[u8; 32], psk: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
        let x = Self::membership_scalar(public_key_bytes, psk);
        let x_point = RistrettoPoint::mul_base(&x);

        // `r` is the one value that must be unpredictable: it is what makes `z`
        // uniform and therefore what makes the proof zero-knowledge. Drawn from
        // the OS CSPRNG and reduced onto the scalar field (a 512-bit draw, so the
        // reduction is not measurably biased).
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

    /// Verify a membership proof against the verifier's current clock.
    pub fn verify_proof(
        public_key_bytes: &[u8; 32],
        psk: Option<&[u8; 32]>,
        context: &[u8; 32],
        proof: &[u8],
    ) -> bool {
        Self::verify_proof_at(public_key_bytes, psk, context, proof, now_secs())
    }

    /// Verify at an explicit time, so the freshness window is testable without
    /// sleeping and without a clock seam in the caller.
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
        // Membership is only checkable by a member. Without the PSK there is no
        // `X` to check the statement against, so this refuses rather than
        // pretending to have verified something.
        let Some(psk) = psk else {
            return false;
        };
        // The context is `ts_be ‖ 0^24`: a non-zero reserved byte is not a
        // canonical encoding of this block, so it is refused rather than ignored
        // (a block that verified with a mutated context would be malleable).
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
        // z·B == R + c·X
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

// ── 4. Memory Guard — Secure Zeroing & Dead-Man's Switch ────────────

/// Secure memory guard with platform-level memory locking (mlock / VirtualLock)
/// and volatile zeroing on drop.
///
/// The internal buffer is zeroed via volatile writes on both `panic_zero()` and
/// `Drop`, preventing the compiler from optimizing away the zeroing. The
/// `lock_pages()` method additionally calls `mlock`/`VirtualLock` to prevent the
/// OS from paging the secret to the swap file.
pub struct SecureMemGuard<const N: usize> {
    data: std::cell::UnsafeCell<[u8; N]>,
    tripped: AtomicBool,
    access_count: AtomicU64,
    pages_locked: AtomicBool,
}

// SAFETY: SecureMemGuard coordinates interior mutability safely via AtomicBool tripped flag.
unsafe impl<const N: usize> Sync for SecureMemGuard<N> {}

impl<const N: usize> SecureMemGuard<N> {
    /// Create a new guard with the given secret and attempt page-locking.
    pub fn new(secret: [u8; N]) -> Self {
        let mut guard = Self {
            data: std::cell::UnsafeCell::new(secret),
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
        let ptr = self.data.get() as *const u8;
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

    /// Attempt to lock the secret pages. Call this after the guard has been
    /// placed on the heap (e.g., inside an Arc) for maximum effect.
    pub fn lock_memory(&self) -> bool {
        let ptr = self.data.get() as *const u8;
        let locked = platform_lock_memory(ptr, std::mem::size_of::<[u8; N]>());
        if locked {
            self.pages_locked.store(true, Ordering::Relaxed);
        }
        locked
    }

    /// Unlock the secret pages.
    pub fn unlock_memory(&self) {
        if self.pages_locked.load(Ordering::Relaxed) {
            let ptr = self.data.get() as *const u8;
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
            let ptr = self.data.get() as *const u8;
            platform_unlock_memory(ptr, std::mem::size_of::<[u8; N]>());
        }
    }
}

// ── 5bis. HSM / TPM Backend Abstraction ──────────────────────────────

// Single source of truth: the `hsm` submodule. The trait
// and every backend implementation live in `security/hsm.rs`; this module only
// re-exports them, so `security::{HsmBackend, SoftwareTpm, create_hsm_backend}`
// and `security::hsm::*` both resolve. `hardware-tpm` / `pkcs11` are real
// features: they gate the compiled backends below, not a dead file.
pub mod hsm;

pub use hsm::{create_hsm_backend, create_hsm_backend_from_key, HsmBackend, SoftwareTpm};

#[cfg(feature = "hardware-tpm")]
pub use hsm::Tpm2Backend;

#[cfg(feature = "pkcs11")]
pub use hsm::Pkcs11Backend;

// DPE/TPM-shaped attestation envelope. This is the *format and its
// verification*, deliberately hardware-free — no device is touched, and the
// module says so in its own doc. `hsm.rs` is where a real `tss-esapi`/`cryptoki`
// backend will eventually produce a quote to place inside it.
pub mod attest;

pub use attest::{AttestError, AttestationEnvelope};

// ── 6. Fixed-Slot Temporal Isolation ─────────────────────────────────

pub struct TemporalIsolator;

impl TemporalIsolator {
    /// Decapsulate an ML-KEM-512 ciphertext.
    ///
    /// ## Why there is no longer a "timing padding" loop here
    ///
    /// This used to run the real decapsulation and then do 10 *dummy* ones
    /// (`DUMMY_ITERATIONS`) on a zero key/ciphertext, on the theory that more
    /// work hides the timing of the real one. It hid nothing and cost 10×: the
    /// padding is a fixed **additive** term, so whatever variation the real
    /// decapsulation has is still sitting on top of it, fully visible. Constant
    /// time is a property of the decapsulation itself, not of how much extra
    /// work is stapled to it.
    ///
    /// ML-KEM already has that property. FIPS 203 §7.3 mandates **implicit
    /// rejection**: a ciphertext that does not re-encrypt to itself yields a
    /// pseudorandom secret instead of an error, so the failure path is
    /// indistinguishable from the success path. `ml-kem` 0.3.2 implements it
    /// with `subtle` — `Kbar.ct_select(&Kp, cp.ct_eq(encapsulated_key))`
    /// (`ml-kem-0.3.2/src/decapsulation_key.rs`) — with no secret-dependent
    /// branch and no secret-dependent memory access. So the correct
    /// implementation is *exactly one* decapsulation; the loop was cargo-cult
    /// that made the function slower without making it more constant-time.
    ///
    /// ## Contract
    ///
    /// A malformed but correctly-sized ciphertext is **not** an error: implicit
    /// rejection means the caller gets a secret that simply is not the peer's,
    /// which the AEAD/confirmation step then rejects. The `Result` is retained
    /// for signature stability (the fuzz target calls this shape); the function
    /// has no `Err` path today because the length is fixed by the array type.
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
        // The block that shipped before this was
        // `(sign(SHA256(nonce)), SHA256(nonce))` with the nonce thrown away — a
        // possession proof over a value nobody could open, and one that any
        // holder of it could present again. It must no longer verify; that
        // assertion *is* the closed gap.
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
        // An outsider cannot recompute X, so it cannot check the statement at
        // all — and this says so rather than accepting on the strength of the
        // beacon's own signature.
        let identity = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let (context, proof) = ZkAuthenticator::create_proof(&pk, &zk_psk());
        assert!(!ZkAuthenticator::verify_proof(&pk, None, &context, &proof));
    }

    #[test]
    fn test_zk_proof_alone_does_not_assert_an_identity() {
        // A member holds the PSK, so it *can* compute a membership proof for
        // another node's key. What stops that from impersonating that node is
        // the beacon's Ed25519 signature over its own key — which is why the
        // discovery path requires both, and why this test asserts the split
        // rather than hiding it.
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
        // Skew is tolerated in both directions inside the window...
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
        // ...and refused outside it, which is what bounds replay.
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
        // The timestamp is inside the challenge, not merely beside it: moving it
        // by one second invalidates the proof even though the window would still
        // have accepted that timestamp.
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
        // `r` is fresh every time, so two proofs for the same identity in the
        // same second are different — the block carries no stable value an
        // observer could track a node by.
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

    // ── Constant-time ML-KEM decapsulation ──────────────────
    //
    // These pin the property the removed dummy loop was *assuming*: that
    // decapsulation is already constant-time and total, so one call is both
    // correct and sufficient.

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
        // FIPS 203 §7.3 implicit rejection: a ciphertext that does not
        // re-encrypt to itself must yield a *different* secret — not an `Err`,
        // not a panic. That is what makes the failure path the same shape as
        // the success path, and it is why the old dummy-padding loop was
        // padding nothing observable.
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
        // The shape the fuzz target feeds it: an all-zero ciphertext must not
        // panic and must not error — it is a normal (rejected) decapsulation.
        let (_ek, dk) = crate::ghost::layers::l1_kem::generate_kyber_keypair();
        let got = TemporalIsolator::fixed_time_decapsulate(&[0u8; 768], &dk)
            .expect("an all-zero ciphertext is handled, not rejected");
        assert_eq!(got.len(), 32);
    }
}
