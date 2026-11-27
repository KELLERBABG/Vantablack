//! Adversary Goggles — the truth ledger.
//!
//! A privacy product that says "anonymous" in a badge has made a claim it cannot
//! check. This module builds the opposite: a per-view description of what each
//! observer can actually see, plus invariants that are **evaluated** against the
//! live node rather than asserted in a marketing page.
//!
//! The rules are deliberately unflattering:
//!
//! * no anonymity claim below 200 live public relays (roadmap item 8), and never
//!   from a regime that is not [`Regime::Vantablack`];
//! * a strict circuit with fewer hops than configured is a failure, not a
//!   footnote;
//! * anything the node cannot measure is `Unknown`, never `Verified`. A ledger
//!   that treats "we didn't look" as a pass is worse than no ledger.
//!
//! [`TruthLedger::headline`] is what the dashboard shows at the top. It is
//! derived from the invariants, so a failing check necessarily changes the
//! headline.

use crate::ghost::net::discovery::CAP_RELAY;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use super::regime::{effective_population, Plane, Regime, MIN_ANONYMITY_RELAYS};

pub trait Measure: 'static {
    type Value: Copy + std::fmt::Debug;
    const TTL_SECS: u64;
}

pub struct CircuitHops;
impl Measure for CircuitHops {
    type Value = u8;
    const TTL_SECS: u64 = 300;
}

pub struct CoverTx;
impl Measure for CoverTx {
    type Value = u64;
    const TTL_SECS: u64 = 120;
}

pub struct NonceEchoHops;
impl Measure for NonceEchoHops {
    type Value = u8;
    const TTL_SECS: u64 = 300;
}

mod wire {
    use super::Measure;
    use std::marker::PhantomData;

    pub struct WireWitness<P: Measure> {
        value: P::Value,
        observed_at: u64,
        _marker: PhantomData<P>,
    }

    impl<P: Measure> WireWitness<P> {
        pub(super) fn observed(value: P::Value, observed_at: u64) -> Self {
            Self {
                value,
                observed_at,
                _marker: PhantomData,
            }
        }

        pub fn value(&self) -> P::Value {
            self.value
        }

        pub fn observed_at(&self) -> u64 {
            self.observed_at
        }

        pub fn is_fresh(&self) -> bool {
            super::super::now_secs().saturating_sub(self.observed_at) <= P::TTL_SECS
        }
    }

    impl<P: Measure> Clone for WireWitness<P> {
        fn clone(&self) -> Self {
            Self {
                value: self.value,
                observed_at: self.observed_at,
                _marker: PhantomData,
            }
        }
    }

    impl<P: Measure> std::fmt::Debug for WireWitness<P> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WireWitness")
                .field("value", &self.value)
                .field("observed_at", &self.observed_at)
                .finish()
        }
    }
}

pub use wire::WireWitness;

pub mod census {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::sync::{Mutex, OnceLock};

    pub const DEFAULT_SKETCH_M: usize = 64;
    pub const CENSUS_EPOCH_SECS: u64 = 86_400;
    pub const CENSUS_FLOOR: usize = super::MIN_ANONYMITY_RELAYS;

    fn census_message(epoch: u64, cell_commit: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(13 + 8 + 32);
        msg.extend_from_slice(b"VB-CENSUS-V1");
        msg.extend_from_slice(&epoch.to_be_bytes());
        msg.extend_from_slice(cell_commit);
        msg
    }

    pub fn current_epoch() -> u64 {
        super::super::now_secs() / CENSUS_EPOCH_SECS
    }

    pub fn cell_commit(cell_secret: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"VB-CENSUS-CELL-V1");
        h.update(cell_secret);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct CensusTicket {
        pub epoch: u64,
        pub cell_commit: [u8; 32],
        pub value: u64,
        #[serde(serialize_with = "serialize_proof_hex")]
        pub proof: [u8; 64],
    }

    fn serialize_proof_hex<S: serde::Serializer>(
        proof: &[u8; 64],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(proof))
    }

    impl CensusTicket {
        pub fn issue(epoch: u64, cell_secret: &[u8; 32], key: &ed25519_dalek::SigningKey) -> Self {
            use ed25519_dalek::Signer;
            let cell_commit = cell_commit(cell_secret);
            let proof = key.sign(&census_message(epoch, &cell_commit)).to_bytes();
            Self {
                epoch,
                cell_commit,
                value: value_of(&proof),
                proof,
            }
        }

        pub fn verify(&self, epoch: u64, key: &ed25519_dalek::VerifyingKey) -> bool {
            use ed25519_dalek::{Signature, Verifier};
            if self.epoch != epoch || self.value != value_of(&self.proof) {
                return false;
            }
            let signature = Signature::from_bytes(&self.proof);
            key.verify(&census_message(epoch, &self.cell_commit), &signature)
                .is_ok()
        }
    }

    fn value_of(proof: &[u8; 64]) -> u64 {
        let digest = Sha256::digest(proof);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(bytes)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    pub struct CensusEstimate {
        pub cells_observed: usize,
        pub m: usize,
        pub u_m: f64,
        pub n_hat: f64,
        pub n_lower_99: usize,
        pub saturated: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct CensusSketch {
        pub epoch: u64,
        pub m: usize,
        pub tickets: Vec<CensusTicket>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct WireTicket {
        pub value: u64,
        pub cell_commit: String,
    }

    impl CensusSketch {
        pub fn new(epoch: u64, m: usize) -> Self {
            Self {
                epoch,
                m: m.max(2),
                tickets: Vec::new(),
            }
        }

        pub fn insert(&mut self, ticket: CensusTicket) -> bool {
            if ticket.epoch != self.epoch {
                return false;
            }
            self.insert_cell(ticket.cell_commit, ticket.value)
        }

        pub fn insert_cell(&mut self, cell_commit: [u8; 32], value: u64) -> bool {
            if let Some(existing) = self
                .tickets
                .iter_mut()
                .find(|t| t.cell_commit == cell_commit)
            {
                if value >= existing.value {
                    return false;
                }
                existing.value = value;
            } else {
                if self.tickets.len() >= self.m
                    && self.tickets.last().is_some_and(|last| value >= last.value)
                {
                    return false;
                }
                self.tickets.push(CensusTicket {
                    epoch: self.epoch,
                    cell_commit,
                    value,
                    proof: [0u8; 64],
                });
            }
            self.tickets.sort_by_key(|t| (t.value, t.cell_commit));
            self.tickets.truncate(self.m);
            true
        }

        pub fn insert_verified(
            &mut self,
            ticket: CensusTicket,
            key: &ed25519_dalek::VerifyingKey,
        ) -> bool {
            ticket.verify(self.epoch, key) && self.insert(ticket)
        }

        pub fn distinct_cells(&self) -> usize {
            self.tickets.len()
        }

        pub fn wire_tickets(&self) -> Vec<WireTicket> {
            self.tickets
                .iter()
                .map(|t| WireTicket {
                    value: t.value,
                    cell_commit: hex::encode(t.cell_commit),
                })
                .collect()
        }

        pub fn estimate(&self) -> Option<CensusEstimate> {
            let observed = self.tickets.len();
            if observed == 0 {
                return None;
            }
            let last = self.tickets.last()?;
            let u_m = ((last.value as f64) + 1.0) / (u64::MAX as f64 + 1.0);
            if observed < self.m {
                return Some(CensusEstimate {
                    cells_observed: observed,
                    m: self.m,
                    u_m,
                    n_hat: observed as f64,
                    n_lower_99: observed,
                    saturated: true,
                });
            }
            Some(CensusEstimate {
                cells_observed: observed,
                m: self.m,
                u_m,
                n_hat: (self.m as f64 - 1.0) / u_m,
                n_lower_99: lower_confidence_bound(self.m, u_m),
                saturated: false,
            })
        }
    }

    fn binomial_tail(n: u64, u: f64, m: usize) -> f64 {
        let u = u.clamp(1e-12, 1.0 - 1e-12);
        let q = 1.0 - u;
        let mut p = q.powf(n as f64);
        let mut cdf = p;
        for k in 1..m {
            p *= (n as f64 - k as f64 + 1.0) / k as f64 * (u / q);
            cdf += p;
            if cdf >= 1.0 {
                break;
            }
        }
        (1.0 - cdf).clamp(0.0, 1.0)
    }

    pub fn lower_confidence_bound(m: usize, u_m: f64) -> usize {
        const ALPHA: f64 = 0.01;
        let mut lo = m as u64;
        let mut hi = 1u64 << 40;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if binomial_tail(mid, u_m, m) >= ALPHA {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        usize::try_from(lo).unwrap_or(usize::MAX)
    }

    fn global_sketch() -> &'static Mutex<CensusSketch> {
        static SKETCH: OnceLock<Mutex<CensusSketch>> = OnceLock::new();
        SKETCH.get_or_init(|| {
            Mutex::new(CensusSketch::new(
                super::super::now_secs() / CENSUS_EPOCH_SECS,
                DEFAULT_SKETCH_M,
            ))
        })
    }

    pub fn local_cell_secret(fingerprint: &str, epoch: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"VB-CENSUS-LOCAL-CELL-V1");
        h.update(fingerprint.as_bytes());
        h.update(epoch.to_be_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn observed_cell(endpoint: &str, epoch: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"VB-CENSUS-OBSERVED-CELL-V1");
        h.update(super::domain_cluster(endpoint).as_bytes());
        h.update(epoch.to_be_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn observed_value(cell_commit: &[u8; 32], epoch: u64) -> u64 {
        let mut h = Sha256::new();
        h.update(b"VB-CENSUS-CELL-VALUE-V1");
        h.update(epoch.to_be_bytes());
        h.update(cell_commit);
        let digest = h.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(bytes)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CensusBroadcast {
        pub fingerprint: String,
        pub verifying_key: [u8; 32],
        pub ticket: CensusTicket,
    }

    pub const CENSUS_WIRE_ENTRY_LEN: usize = 16 + 32 + 8 + 32 + 8 + 64;

    pub fn announcement(
        key: &ed25519_dalek::SigningKey,
        fingerprint: &str,
        epoch: u64,
    ) -> CensusBroadcast {
        let cell_secret = local_cell_secret(fingerprint, epoch);
        CensusBroadcast {
            fingerprint: fingerprint.to_string(),
            verifying_key: key.verifying_key().to_bytes(),
            ticket: CensusTicket::issue(epoch, &cell_secret, key),
        }
    }

    pub fn encode_gossip(entries: &[CensusBroadcast]) -> Vec<u8> {
        let count = entries.len().min(8);
        let mut out = Vec::with_capacity(1 + count * CENSUS_WIRE_ENTRY_LEN);
        out.push(count as u8);
        for entry in entries.iter().take(count) {
            let mut fingerprint = [0u8; 16];
            let bytes = entry.fingerprint.as_bytes();
            let len = bytes.len().min(16);
            fingerprint[..len].copy_from_slice(&bytes[..len]);
            out.extend_from_slice(&fingerprint);
            out.extend_from_slice(&entry.verifying_key);
            out.extend_from_slice(&entry.ticket.epoch.to_be_bytes());
            out.extend_from_slice(&entry.ticket.cell_commit);
            out.extend_from_slice(&entry.ticket.value.to_be_bytes());
            out.extend_from_slice(&entry.ticket.proof);
        }
        out
    }

    pub fn decode_gossip(body: &[u8]) -> Vec<CensusBroadcast> {
        let Some((&count, mut rest)) = body.split_first() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for _ in 0..count {
            if rest.len() < CENSUS_WIRE_ENTRY_LEN {
                break;
            }
            let (entry, tail) = rest.split_at(CENSUS_WIRE_ENTRY_LEN);
            rest = tail;
            let fingerprint = String::from_utf8_lossy(&entry[..16])
                .trim_end_matches('\0')
                .to_string();
            let mut verifying_key = [0u8; 32];
            verifying_key.copy_from_slice(&entry[16..48]);
            let mut epoch = [0u8; 8];
            epoch.copy_from_slice(&entry[48..56]);
            let mut cell_commit = [0u8; 32];
            cell_commit.copy_from_slice(&entry[56..88]);
            let mut value = [0u8; 8];
            value.copy_from_slice(&entry[88..96]);
            let mut proof = [0u8; 64];
            proof.copy_from_slice(&entry[96..160]);
            out.push(CensusBroadcast {
                fingerprint,
                verifying_key,
                ticket: CensusTicket {
                    epoch: u64::from_be_bytes(epoch),
                    cell_commit,
                    value: u64::from_be_bytes(value),
                    proof,
                },
            });
        }
        out
    }

    pub fn observed_entry(
        announcement: &CensusBroadcast,
        observed_endpoint: &str,
        epoch: u64,
    ) -> Option<([u8; 32], u64)> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&announcement.verifying_key).ok()?;
        if hex::encode(&announcement.verifying_key[..8]) != announcement.fingerprint {
            return None;
        }
        if !announcement.ticket.verify(epoch, &key) {
            return None;
        }
        let cell = observed_cell(observed_endpoint, epoch);
        Some((cell, observed_value(&cell, epoch)))
    }

    fn note_observed_cell(cell_commit: [u8; 32], value: u64) -> bool {
        let epoch = current_epoch();
        let mut sketch = global_sketch().lock().unwrap_or_else(|e| e.into_inner());
        if sketch.epoch != epoch {
            *sketch = CensusSketch::new(epoch, DEFAULT_SKETCH_M);
        }
        sketch.insert_cell(cell_commit, value)
    }

    pub fn note_announcement(announcement: &CensusBroadcast, observed_endpoint: &str) -> bool {
        let epoch = current_epoch();
        match observed_entry(announcement, observed_endpoint, epoch) {
            Some((cell, value)) => note_observed_cell(cell, value),
            None => false,
        }
    }

    pub fn note_ticket(ticket: CensusTicket) -> bool {
        let epoch = super::super::now_secs() / CENSUS_EPOCH_SECS;
        let mut sketch = global_sketch().lock().unwrap_or_else(|e| e.into_inner());
        if sketch.epoch != epoch {
            *sketch = CensusSketch::new(epoch, DEFAULT_SKETCH_M);
        }
        sketch.insert(ticket)
    }

    pub fn current_estimate() -> Option<CensusEstimate> {
        global_sketch()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .estimate()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                self.0
            }
        }

        fn tickets(n: usize) -> Vec<CensusTicket> {
            let mut rng = Rng(0xC3E5);
            (0..n)
                .map(|i| {
                    let mut cell = [0u8; 32];
                    cell[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    CensusTicket {
                        epoch: 7,
                        cell_commit: cell_commit(&cell),
                        value: rng.next(),
                        proof: [0u8; 64],
                    }
                })
                .collect()
        }

        fn population(rng: &mut Rng, n: usize) -> CensusSketch {
            let mut sketch = CensusSketch::new(7, DEFAULT_SKETCH_M);
            for i in 0..n {
                let mut cell = [0u8; 32];
                cell[..8].copy_from_slice(&(i as u64).to_be_bytes());
                sketch.insert(CensusTicket {
                    epoch: 7,
                    cell_commit: cell_commit(&cell),
                    value: rng.next(),
                    proof: [0u8; 64],
                });
            }
            sketch
        }

        #[test]
        fn the_sketch_is_an_unbiased_estimator_of_a_population() {
            let mut rng = Rng(0x9E37);
            let trials = 41;
            let mut sum = 0.0;
            let mut above_truth = 0;
            for _ in 0..trials {
                let sketch = population(&mut rng, 1_000);
                let estimate = sketch.estimate().expect("non-empty sketch");
                assert_eq!(estimate.cells_observed, DEFAULT_SKETCH_M);
                assert!(!estimate.saturated);
                if estimate.n_lower_99 > 1_000 {
                    above_truth += 1;
                }
                assert!(
                    estimate.n_lower_99 <= 1_100,
                    "the bound missed the true population by more than sampling noise: {}",
                    estimate.n_lower_99
                );
                assert!(
                    estimate.n_lower_99 > 600,
                    "the bound should be informative, got {}",
                    estimate.n_lower_99
                );
                sum += estimate.n_hat;
            }
            assert!(
                above_truth <= 3,
                "{above_truth}/{trials} bounds exceeded the true population; a 99% bound expects ~1%"
            );
            let mean = sum / trials as f64;
            assert!(
                (mean - 1_000.0).abs() < 80.0,
                "mean estimate {mean:.1} is biased away from 1000"
            );
        }

        #[test]
        fn sybils_in_one_cell_collapse_to_one_entry() {
            let mut sketch = CensusSketch::new(7, DEFAULT_SKETCH_M);
            let cell = [0x5Au8; 32];
            for i in 0..500u64 {
                let mut proof = [0u8; 64];
                proof[..8].copy_from_slice(&i.to_be_bytes());
                let mut ticket = tickets(1).remove(0);
                ticket.cell_commit = cell_commit(&cell);
                ticket.proof = proof;
                ticket.value = value_of(&proof);
                sketch.insert(ticket);
            }
            let estimate = sketch.estimate().expect("one cell");
            assert_eq!(estimate.cells_observed, 1);
            assert_eq!(estimate.n_hat, 1.0);
            assert!(estimate.saturated, "one cell is the whole population seen");
        }

        #[test]
        fn a_ticket_is_bound_to_its_epoch_cell_and_key() {
            use ed25519_dalek::SigningKey;
            let key = SigningKey::from_bytes(&[0x11u8; 32]);
            let other = SigningKey::from_bytes(&[0x22u8; 32]);
            let cell = [0x33u8; 32];
            let ticket = CensusTicket::issue(5, &cell, &key);
            assert!(ticket.verify(5, &key.verifying_key()));
            assert!(!ticket.verify(6, &key.verifying_key()), "wrong epoch");
            assert!(
                !ticket.verify(5, &other.verifying_key()),
                "another relay's key must not verify"
            );

            let mut forged = ticket.clone();
            forged.value ^= 1;
            assert!(!forged.verify(5, &key.verifying_key()));

            assert_eq!(ticket, CensusTicket::issue(5, &cell, &key));
        }

        #[test]
        fn the_gossiped_sketch_carries_no_address() {
            let mut sketch = CensusSketch::new(7, DEFAULT_SKETCH_M);
            for ticket in tickets(80) {
                sketch.insert(ticket);
            }
            let json = serde_json::to_string(&sketch.wire_tickets()).expect("serialises");
            for needle in ["ip", "port", "addr", "192.", "::1", "cell_secret"] {
                assert!(
                    !json.to_ascii_lowercase().contains(needle),
                    "census wire form leaks {needle:?}: {json}"
                );
            }
            assert!(!json.is_empty());
        }

        #[test]
        fn a_live_announcement_counts_the_observed_cell_not_the_claimed_one() {
            use ed25519_dalek::SigningKey;
            let key = SigningKey::from_bytes(&[0x44u8; 32]);
            let fingerprint = hex::encode(&key.verifying_key().to_bytes()[..8]);
            let epoch = 19_000u64;
            let broadcast = announcement(&key, &fingerprint, epoch);

            let (cell, value) = observed_entry(&broadcast, "203.0.113.9:55225", epoch)
                .expect("the epoch signature verifies");
            assert_eq!(cell, observed_cell("203.0.113.9:55225", epoch));
            assert_ne!(
                cell, broadcast.ticket.cell_commit,
                "the sender's claimed cell must not be what is counted"
            );
            assert_eq!(value, observed_value(&cell, epoch));

            let mut sketch = CensusSketch::new(epoch, DEFAULT_SKETCH_M);
            assert!(sketch.insert_cell(cell, value));
            assert_eq!(sketch.distinct_cells(), 1);
        }

        #[test]
        fn sybils_in_one_subnet_are_one_cell_whatever_they_claim() {
            use ed25519_dalek::SigningKey;
            let epoch = 19_001u64;
            let mut sketch = CensusSketch::new(epoch, DEFAULT_SKETCH_M);
            let mut claimed_cells = std::collections::BTreeSet::new();
            for seed in 1u8..=50 {
                let key = SigningKey::from_bytes(&[seed; 32]);
                let fingerprint = hex::encode(&key.verifying_key().to_bytes()[..8]);
                let broadcast = announcement(&key, &fingerprint, epoch);
                claimed_cells.insert(broadcast.ticket.cell_commit);
                let (cell, value) =
                    observed_entry(&broadcast, "198.51.100.17:4433", epoch).expect("verifies");
                let _ = sketch.insert_cell(cell, value);
            }
            assert_eq!(claimed_cells.len(), 50, "fifty distinct claimed cells");
            let estimate = sketch.estimate().expect("one cell");
            assert_eq!(estimate.cells_observed, 1, "one /24 is one cell");
            assert!(estimate.saturated);
            assert_eq!(estimate.n_lower_99, 1);
        }

        #[test]
        fn a_grinded_value_cannot_move_the_census() {
            use ed25519_dalek::SigningKey;
            let epoch = 19_002u64;
            let a = SigningKey::from_bytes(&[0x71u8; 32]);
            let b = SigningKey::from_bytes(&[0x72u8; 32]);
            let broadcast_a =
                announcement(&a, &hex::encode(&a.verifying_key().to_bytes()[..8]), epoch);
            let broadcast_b =
                announcement(&b, &hex::encode(&b.verifying_key().to_bytes()[..8]), epoch);

            let (cell_a, value_a) =
                observed_entry(&broadcast_a, "192.0.2.10:1", epoch).expect("a verifies");
            let (cell_b, value_b) =
                observed_entry(&broadcast_b, "192.0.2.10:1", epoch).expect("b verifies");
            assert_eq!(cell_a, cell_b);
            assert_eq!(value_a, value_b);

            let (cell_c, _) = observed_entry(&broadcast_a, "192.0.3.10:1", epoch).expect("c");
            assert_ne!(cell_a, cell_c);
        }

        #[test]
        fn a_stale_or_mislabelled_announcement_is_refused() {
            use ed25519_dalek::SigningKey;
            let key = SigningKey::from_bytes(&[0x31u8; 32]);
            let fingerprint = hex::encode(&key.verifying_key().to_bytes()[..8]);
            let broadcast = announcement(&key, &fingerprint, 19_003);

            assert!(observed_entry(&broadcast, "192.0.2.1:1", 19_003).is_some());
            assert!(
                observed_entry(&broadcast, "192.0.2.1:1", 19_004).is_none(),
                "last epoch's announcement is not this epoch's evidence"
            );

            let mut mislabelled = broadcast.clone();
            mislabelled.fingerprint = hex::encode([0xAAu8; 8]);
            assert!(
                observed_entry(&mislabelled, "192.0.2.1:1", 19_003).is_none(),
                "a fingerprint that is not the key's must be refused"
            );

            let mut tampered = broadcast.clone();
            tampered.ticket.value ^= 1;
            assert!(
                observed_entry(&tampered, "192.0.2.1:1", 19_003).is_none(),
                "the claimed value must be the one the proof produces"
            );
        }

        #[test]
        fn the_pex_batch_round_trips_and_carries_no_address() {
            use ed25519_dalek::SigningKey;
            let key = SigningKey::from_bytes(&[0x55u8; 32]);
            let fingerprint = hex::encode(&key.verifying_key().to_bytes()[..8]);
            let broadcast = announcement(&key, &fingerprint, 19_005);
            let wire = encode_gossip(std::slice::from_ref(&broadcast));

            assert_eq!(wire.len(), 1 + CENSUS_WIRE_ENTRY_LEN);
            assert_eq!(decode_gossip(&wire), vec![broadcast]);
            assert!(
                !wire.windows(11).any(|w| w == b"203.0.113.9"),
                "the announcement must not carry the sender's address"
            );
            assert!(decode_gossip(&wire[..wire.len() - 1]).is_empty());
            assert!(decode_gossip(&[]).is_empty());
        }

        #[test]
        fn two_hundred_routing_domains_clear_the_anonymity_floor() {
            use ed25519_dalek::SigningKey;
            let key = SigningKey::from_bytes(&[0x77u8; 32]);
            let fingerprint = hex::encode(&key.verifying_key().to_bytes()[..8]);
            let epoch = 19_010u64;
            let broadcast = announcement(&key, &fingerprint, epoch);
            let mut sketch = CensusSketch::new(epoch, DEFAULT_SKETCH_M);
            let mut distinct = std::collections::BTreeSet::new();

            for i in 0..512u32 {
                let endpoint = format!("10.{}.{}.7:55225", (i / 256) % 256, i % 256);
                let (cell, value) = observed_entry(&broadcast, &endpoint, epoch).expect("verifies");
                distinct.insert(cell);
                let _ = sketch.insert_cell(cell, value);
            }

            assert_eq!(distinct.len(), 512, "one cell per /24");
            let estimate = sketch.estimate().expect("non-empty");
            assert_eq!(estimate.cells_observed, DEFAULT_SKETCH_M);
            assert!(!estimate.saturated);
            assert!(
                estimate.n_lower_99 >= CENSUS_FLOOR,
                "512 routing domains should clear the {CENSUS_FLOOR} floor, got {}",
                estimate.n_lower_99
            );
        }

        #[test]
        fn the_lower_bound_is_never_above_the_truth_for_a_small_sketch() {
            let mut sketch = CensusSketch::new(7, DEFAULT_SKETCH_M);
            for ticket in tickets(12) {
                sketch.insert(ticket);
            }
            let estimate = sketch.estimate().expect("non-empty");
            assert!(estimate.saturated);
            assert_eq!(estimate.n_lower_99, 12);
            assert!(estimate.n_lower_99 < CENSUS_FLOOR);
        }
    }
}

pub mod formal {
    use serde::Serialize;

    include!(concat!(env!("OUT_DIR"), "/formal_attest.rs"));

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct FormalProvenance {
        pub proverif: &'static str,
        pub attested_at: &'static str,
        pub models: usize,
        pub all_queries_hold: bool,
    }

    pub fn provenance() -> FormalProvenance {
        FormalProvenance {
            proverif: PROVERIF_VERSION,
            attested_at: ATTESTED_AT,
            models: MODELS.len(),
            all_queries_hold: MODELS
                .iter()
                .all(|(_, _, results)| results.iter().any(|line| line.ends_with("is true."))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerWitness {
    pub fingerprint: String,
    pub capabilities: u8,
    pub domain: String,
    pub seen_at: u64,
}

const PEER_WITNESS_TTL_SECS: u64 = 7 * 86_400;

fn witnesses() -> &'static RwLock<HashMap<String, PeerWitness>> {
    static W: OnceLock<RwLock<HashMap<String, PeerWitness>>> = OnceLock::new();
    W.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn domain_cluster(endpoint: &str) -> String {
    use std::net::IpAddr;
    let host = endpoint
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']))
        .unwrap_or(endpoint);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(ip)) => {
            let s = ip.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        Err(_) => format!("unparsed:{endpoint}"),
    }
}

pub fn note_verified_peer(fingerprint: &str, capabilities: u8, endpoint: &str) {
    let mut reg = witnesses().write().unwrap_or_else(|e| e.into_inner());
    reg.insert(
        fingerprint.to_string(),
        PeerWitness {
            fingerprint: fingerprint.to_string(),
            capabilities,
            domain: domain_cluster(endpoint),
            seen_at: super::now_secs(),
        },
    );
}

pub fn forget_verified_peer(fingerprint: &str) {
    witnesses()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(fingerprint);
}

#[derive(Default)]
struct NonceEchoState {
    pending: std::collections::HashMap<[u8; 16], u64>,
    last_verified: Option<(u8, u64)>,
}

fn nonce_echo_state() -> &'static std::sync::Mutex<NonceEchoState> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<NonceEchoState>> =
        std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(NonceEchoState::default()))
}

pub fn nonce_echo_signing_input(nonce: &[u8; 16], hops: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 16 + 1);
    out.extend_from_slice(b"VB-NONCE-ECHO-V1");
    out.extend_from_slice(nonce);
    out.push(hops);
    out
}

pub fn issue_nonce_challenge() -> [u8; 16] {
    let nonce: [u8; 16] = rand::random();
    let now = super::now_secs();
    let mut st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
    st.pending.retain(|_, ts| now.saturating_sub(*ts) <= 120);
    if st.pending.len() >= 64 {
        st.pending.clear();
    }
    st.pending.insert(nonce, now);
    nonce
}

pub fn verify_nonce_echo(
    nonce: &[u8; 16],
    signer_pk: &[u8; 32],
    sig_bytes: &[u8; 64],
    hops: u8,
) -> bool {
    let now = super::now_secs();
    {
        let mut st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
        let Some(issued_at) = st.pending.remove(nonce) else {
            return false;
        };
        if now.saturating_sub(issued_at) > 120 {
            return false;
        }
    }
    let msg = nonce_echo_signing_input(nonce, hops);
    if !crate::ghost::layers::l0_identity::verify_peer_signature(signer_pk, &msg, sig_bytes) {
        return false;
    }
    let mut st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
    st.last_verified = Some((hops, now));
    true
}

pub fn last_nonce_echo_hops() -> Option<u8> {
    let now = super::now_secs();
    nonce_echo_measurement().and_then(|(hops, ts)| (now.saturating_sub(ts) <= 300).then_some(hops))
}

fn nonce_echo_measurement() -> Option<(u8, u64)> {
    let st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
    st.last_verified
}

pub fn circuit_hops_witness() -> Option<WireWitness<CircuitHops>> {
    let (hops, observed_at) = super::boomerang::last_circuit_measurement()?;
    Some(WireWitness::observed(hops, observed_at))
}

pub fn cover_tx_witness() -> Option<WireWitness<CoverTx>> {
    let (count, observed_at) = super::racs::cover_measurement();
    (observed_at != 0).then(|| WireWitness::observed(count, observed_at))
}

pub fn nonce_echo_witness() -> Option<WireWitness<NonceEchoHops>> {
    let (hops, observed_at) = nonce_echo_measurement()?;
    Some(WireWitness::observed(hops, observed_at))
}

#[cfg(test)]
pub fn test_witness<P: Measure>(value: P::Value) -> WireWitness<P> {
    WireWitness::observed(value, super::now_secs())
}

fn live_witnesses() -> Vec<PeerWitness> {
    let now = super::now_secs();
    let reg = witnesses().read().unwrap_or_else(|e| e.into_inner());
    reg.values()
        .filter(|w| now.saturating_sub(w.seen_at) <= PEER_WITNESS_TTL_SECS)
        .cloned()
        .collect()
}

pub fn verified_peers() -> Vec<PeerWitness> {
    live_witnesses()
}

pub fn cap_relay_verified() -> usize {
    live_witnesses()
        .iter()
        .filter(|w| w.capabilities & CAP_RELAY != 0)
        .count()
}

pub fn relay_population() -> (usize, Vec<usize>) {
    let peers: Vec<PeerWitness> = live_witnesses()
        .into_iter()
        .filter(|w| w.capabilities & CAP_RELAY != 0)
        .collect();
    let mut groups: HashMap<String, usize> = HashMap::new();
    for peer in &peers {
        *groups.entry(peer.domain.clone()).or_default() += 1;
    }
    (peers.len(), groups.into_values().collect())
}

pub fn relay_domains() -> Vec<usize> {
    relay_population().1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Verified,
    Failed,
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Verified => "verified",
            State::Failed => "failed",
            State::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invariant {
    pub id: &'static str,
    pub state: State,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct LedgerInput {
    pub regime: Option<Regime>,
    pub public_relays: Option<usize>,
    pub circuit_hops: Option<WireWitness<CircuitHops>>,
    pub circuit_asns: Option<usize>,
    pub transport: Option<String>,
    pub outer_sni: Option<String>,
    pub exit_ip: Option<String>,
    pub cover_tx: Option<WireWitness<CoverTx>>,
    pub shaping: Option<super::racs::ShapingEvidence>,
    pub dns_leak: Option<bool>,
    pub pq_hybrid: Option<bool>,
    pub chronos: Option<super::chronos::ChronosEvidence>,
    pub cap_relay_verified: Option<usize>,
    pub nonce_echo_hops: Option<WireWitness<NonceEchoHops>>,
    pub relay_domains: Option<Vec<usize>>,
    pub nvis: Option<super::nvis::NvisProfile>,
    pub census: Option<census::CensusEstimate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub observer: String,
    pub sees: Vec<String>,
    pub does_not_see: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TruthLedger {
    pub headline: String,
    pub claim: String,
    pub regime: String,
    pub plane: String,
    pub observations: Vec<Observation>,
    pub invariants: Vec<Invariant>,
    pub formal: formal::FormalProvenance,
    pub generated_at: u64,
}

impl TruthLedger {
    pub fn headline(&self) -> &str {
        &self.headline
    }

    pub fn failed(&self) -> impl Iterator<Item = &Invariant> {
        self.invariants.iter().filter(|i| i.state == State::Failed)
    }

    pub fn all_verified(&self) -> bool {
        !self.invariants.is_empty() && self.invariants.iter().all(|i| i.state == State::Verified)
    }
}

fn inv(id: &'static str, state: State, detail: impl Into<String>) -> Invariant {
    Invariant {
        id,
        state,
        detail: detail.into(),
    }
}

pub fn build(input: &LedgerInput) -> TruthLedger {
    let regime = input.regime.unwrap_or(Regime::Ghost);
    let plane = regime.plane();
    let relays = input.public_relays;
    let circuit_hops = input
        .circuit_hops
        .as_ref()
        .filter(|w| w.is_fresh())
        .map(|w| w.value());
    let cover_tx = input
        .cover_tx
        .as_ref()
        .filter(|w| w.is_fresh())
        .map(|w| w.value());
    let nonce_echo_hops = input
        .nonce_echo_hops
        .as_ref()
        .filter(|w| w.is_fresh())
        .map(|w| w.value());
    let neff = input
        .relay_domains
        .as_deref()
        .filter(|groups| !groups.is_empty())
        .map(effective_population)
        .map(|n| n.round() as usize);

    let mut invariants = Vec::with_capacity(12);

    invariants.push(match input.pq_hybrid {
        Some(true) => inv(
            "pq_hybrid_handshake",
            State::Verified,
            "handshake used X25519 + ML-KEM-768 (hybrid)",
        ),
        Some(false) => inv(
            "pq_hybrid_handshake",
            State::Failed,
            "handshake fell back to a classical-only suite",
        ),
        None => inv(
            "pq_hybrid_handshake",
            State::Unknown,
            "no session handshake has completed in this process",
        ),
    });

    let required_hops = regime.hops().hops();
    invariants.push(match circuit_hops {
        Some(n) if n >= required_hops => inv(
            "circuit_length",
            State::Verified,
            format!("{n} hops, {required_hops} required by {}", regime.as_str()),
        ),
        Some(n) => inv(
            "circuit_length",
            State::Failed,
            format!(
                "{n} hops in use but {} requires {required_hops}",
                regime.as_str()
            ),
        ),
        None => inv(
            "circuit_length",
            State::Unknown,
            "no circuit is established",
        ),
    });

    if plane == Plane::Umbra {
        invariants.push(match input.cap_relay_verified {
            Some(n) if n >= required_hops as usize => inv(
                "relay_capability",
                State::Verified,
                format!("{n} peers verified CAP_RELAY, {required_hops} required"),
            ),
            Some(n) => inv(
                "relay_capability",
                State::Failed,
                format!(
                    "only {n} peers verified CAP_RELAY; {} needs {required_hops}",
                    regime.as_str()
                ),
            ),
            None => inv(
                "relay_capability",
                State::Unknown,
                "CAP_RELAY not verified against signed peer descriptors",
            ),
        });
        invariants.push(match nonce_echo_hops {
            Some(n) if n >= required_hops => inv(
                "nonce_echo",
                State::Verified,
                format!("{n}-hop signed nonce echo returned within the horizon"),
            ),
            Some(n) => inv(
                "nonce_echo",
                State::Failed,
                format!("signed nonce echo reached {n} of {required_hops} hops"),
            ),
            None => inv(
                "nonce_echo",
                State::Unknown,
                "no signed nonce echo witness for a live circuit",
            ),
        });
    }

    if regime.requires_asn_diversity() {
        invariants.push(match input.circuit_asns {
            Some(n) if n >= required_hops as usize => inv(
                "asn_diversity",
                State::Verified,
                format!("{n} distinct networks across {required_hops} hops"),
            ),
            Some(n) => inv(
                "asn_diversity",
                State::Failed,
                format!("{n} distinct networks across {required_hops} hops — not independent"),
            ),
            None => inv(
                "asn_diversity",
                State::Unknown,
                "network diversity not measured",
            ),
        });
    }

    if plane == Plane::Umbra {
        invariants.push(match (relays, neff) {
            (Some(n), Some(e)) if e >= MIN_ANONYMITY_RELAYS => inv(
                "relay_population",
                State::Verified,
                format!(
                    "{e} independent relays (N_eff) among {n} reachable (floor {MIN_ANONYMITY_RELAYS})"
                ),
            ),
            (Some(n), Some(e)) => inv(
                "relay_population",
                State::Failed,
                format!(
                    "{e} independent relays (N_eff) among {n} reachable; anonymity needs at least {MIN_ANONYMITY_RELAYS}"
                ),
            ),
            (Some(n), None) => inv(
                "relay_population",
                State::Unknown,
                format!(
                    "{n} relays reachable, but their administrative domains are unmeasured, so N_eff is unknown"
                ),
            ),
            (None, _) => inv(
                "relay_population",
                State::Unknown,
                "public relay count not measured",
            ),
        });
    }

    if plane == Plane::Umbra {
        invariants.push(match input.census {
            Some(e) if e.n_lower_99 >= MIN_ANONYMITY_RELAYS => inv(
                "census_population",
                State::Verified,
                format!(
                    "at least {} distinct cells (99% lower bound from {} tickets, floor {MIN_ANONYMITY_RELAYS})",
                    e.n_lower_99, e.cells_observed
                ),
            ),
            Some(e) => inv(
                "census_population",
                State::Failed,
                format!(
                    "at least {} distinct cells (99% lower bound from {} tickets); anonymity needs {MIN_ANONYMITY_RELAYS}",
                    e.n_lower_99, e.cells_observed
                ),
            ),
            None => inv(
                "census_population",
                State::Unknown,
                "no blind-census tickets received; the population is not proven",
            ),
        });
    }

    invariants.push(match input.dns_leak {
        Some(false) => inv(
            "dns_path",
            State::Verified,
            "DNS resolution goes through the mesh",
        ),
        Some(true) => inv(
            "dns_path",
            State::Failed,
            "DNS queries leave directly — the resolver sees every name",
        ),
        None => inv("dns_path", State::Unknown, "DNS path not measured"),
    });

    if regime.cover_traffic() {
        let shaping = input.shaping.filter(|e| e.is_fresh());
        invariants.push(match cover_tx {
            Some(n) if n > 0 => match shaping {
                None => inv(
                    "cover_traffic",
                    State::Unknown,
                    format!("{n} cover frames emitted, but no fresh shaped-schedule evidence: emission alone does not prove the burst bound"),
                ),
                Some(e) if !e.measured_enough() => inv(
                    "cover_traffic",
                    State::Unknown,
                    format!(
                        "only {} slots observed; {} required before shaping is evidence",
                        e.slots,
                        super::racs::MIN_SHAPING_SLOTS
                    ),
                ),
                Some(e) if !e.within_contract() => inv(
                    "cover_traffic",
                    State::Failed,
                    format!(
                        "shaping violates the burst contract: max ON run {} slots (limit {}), duty {:.2} (limit {})",
                        e.max_on_run,
                        super::racs::MAX_ON_RUN_SLOTS,
                        e.duty,
                        super::racs::MAX_DUTY
                    ),
                ),
                Some(e) => inv(
                    "cover_traffic",
                    State::Verified,
                    format!(
                        "{n} cover frames; {}-slot window, max burst {} slots, duty {:.2}",
                        e.slots, e.max_on_run, e.duty
                    ),
                ),
            },
            Some(_) => inv(
                "cover_traffic",
                State::Failed,
                format!(
                    "{} requires cover traffic but the emitter reports none",
                    regime.as_str()
                ),
            ),
            None => inv(
                "cover_traffic",
                State::Unknown,
                "cover traffic emission not measured",
            ),
        });
    }

    if plane == Plane::Umbra {
        let now = super::now_secs();
        invariants.push(match input.chronos {
            None => inv(
                "layer_clocks",
                State::Unknown,
                "no measured clock evidence for the live circuit",
            ),
            Some(e) if !e.is_fresh() => inv(
                "layer_clocks",
                State::Unknown,
                format!(
                    "clock evidence is {}s old (limit {}s)",
                    now.saturating_sub(e.observed_at),
                    super::chronos::EVIDENCE_TTL_SECS
                ),
            ),
            Some(e) if e.is_verified() => inv(
                "layer_clocks",
                State::Verified,
                format!(
                    "inner {:.1} ms inside the stationary {:.0} ms horizon; residual {:.1} ms",
                    e.inner_rtt_ms, e.horizon_ms, e.residual_ms
                ),
            ),
            Some(e) => inv(
                "layer_clocks",
                State::Failed,
                format!(
                    "inner {:.1} ms / horizon {:.0} ms; clocks {:?} — a cross-layer classifier can see the relay",
                    e.inner_rtt_ms, e.horizon_ms, e.verdict
                ),
            ),
        });
    }

    if let Some(profile) = input.nvis {
        invariants.push(if profile.is_fresh() {
            inv(
                "nvis_profile",
                State::Verified,
                format!(
                    "{} kHz / {} Hz / {} bps measured: {:.0} s per {}-byte cell at {:.1} dB spreading",
                    profile.freq_khz,
                    profile.bandwidth_hz,
                    profile.info_bps,
                    profile.airtime_secs,
                    super::nvis::CELL_BYTES,
                    profile.spreading_gain_db
                ),
            )
        } else {
            inv(
                "nvis_profile",
                State::Unknown,
                "the last NVIS channel measurement is stale; no profile is claimed",
            )
        });
    }

    let failed = invariants
        .iter()
        .filter(|i| i.state == State::Failed)
        .count();
    let unknown = invariants
        .iter()
        .filter(|i| i.state == State::Unknown)
        .count();

    let claim = if !regime.anonymity_claim_allowed() {
        format!(
            "{} ({}) — no anonymity claim",
            regime.as_str(),
            plane.as_str()
        )
    } else if failed > 0 || unknown > 0 {
        "Vantablack — anonymity claim withheld while a check fails or is unmeasured".to_string()
    } else {
        format!(
            "anonymous among {} independent public relays",
            neff.unwrap_or(0)
        )
    };

    let headline = if failed > 0 {
        format!(
            "{} {} check{} failing — {}",
            failed,
            "invariant",
            if failed == 1 { " is" } else { "s are" },
            claim
        )
    } else if unknown > 0 {
        format!(
            "{} check{} unmeasured — {claim}",
            unknown,
            if unknown == 1 { " is" } else { "s are" }
        )
    } else {
        claim.clone()
    };

    let mut isp_sees = vec![
        match input.transport.as_deref() {
            Some("quic") => "one QUIC/HTTP-3 flow to a single address".to_string(),
            Some("webrtc") => "a WebRTC media session (DTLS-SRTP)".to_string(),
            Some("tls") => "a TLS 1.3 connection to one host".to_string(),
            Some(other) => format!("one UDP flow ({other}) to a single address"),
            None => "one encrypted flow".to_string(),
        },
        if input
            .chronos
            .as_ref()
            .is_some_and(super::chronos::ChronosEvidence::is_verified)
        {
            "an outer RTT that matches the circuit's"
        } else {
            "an outer RTT that may not match the circuit's"
        }
        .to_string(),
    ];
    if let Some(sni) = &input.outer_sni {
        isp_sees.push(format!("the server name indicator: {sni}"));
    }
    let mut isp_not = vec![
        "which sites you visit inside the circuit".to_string(),
        "the contents of any frame".to_string(),
    ];
    if plane == Plane::Umbra {
        isp_not.push("your exit address or the sites it reaches".to_string());
    }
    if input.dns_leak == Some(false) {
        isp_not.push("the names you resolve".to_string());
    }

    let mut guard_sees = vec![format!(
        "{} hop{}",
        circuit_hops.unwrap_or(0),
        if circuit_hops == Some(1) { "" } else { "s" }
    )];
    if input.public_relays.is_some() {
        guard_sees.push(format!(
            "a relay population of {}",
            input.public_relays.unwrap_or(0)
        ));
    }
    let guard_not = vec![
        "the destination, unless it is the exit".to_string(),
        "plaintext or long-term keys".to_string(),
    ];

    let website = match (&input.exit_ip, plane) {
        (Some(ip), _) => vec![
            format!("the exit address {ip}"),
            "your normal TLS fingerprint".to_string(),
        ],
        (None, Plane::Umbra) => vec!["the exit node's address, not yours".to_string()],
        (None, Plane::Phantom) => {
            vec!["your own address — this plane does not hide it".to_string()]
        }
    };

    TruthLedger {
        headline,
        claim,
        regime: regime.as_str().to_string(),
        plane: plane.as_str().to_string(),
        observations: vec![
            Observation {
                observer: "Your ISP".to_string(),
                sees: isp_sees,
                does_not_see: isp_not,
            },
            Observation {
                observer: "The guard relay".to_string(),
                sees: guard_sees,
                does_not_see: guard_not,
            },
            Observation {
                observer: "The website".to_string(),
                sees: website,
                does_not_see: vec!["your identity".to_string(), "where you are".to_string()],
            },
        ],
        invariants,
        formal: formal::provenance(),
        generated_at: super::now_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness<P: Measure>(value: P::Value) -> WireWitness<P> {
        WireWitness::observed(value, crate::ghost::v2::now_secs())
    }

    fn verified_input() -> LedgerInput {
        LedgerInput {
            regime: Some(Regime::Vantablack),
            public_relays: Some(500),
            circuit_hops: Some(witness(3)),
            circuit_asns: Some(3),
            transport: Some("quic".into()),
            outer_sni: Some("cdn.example".into()),
            exit_ip: None,
            cover_tx: Some(witness(1_024)),
            shaping: Some(super::super::racs::shaping_evidence_for(
                0x5EED,
                240,
                1_024,
                crate::ghost::v2::now_secs(),
            )),
            dns_leak: Some(false),
            pq_hybrid: Some(true),
            chronos: Some(super::super::chronos::ChronosEvidence {
                inner_rtt_ms: 150.0,
                outer_rtt_ms: 30.0,
                horizon_ms: 160.0,
                residual_ms: 0.0,
                observations: 2,
                observed_at: crate::ghost::v2::now_secs(),
                verdict: super::super::chronos::ClockVerdict::Consistent,
            }),
            cap_relay_verified: Some(3),
            nonce_echo_hops: Some(witness(3)),
            relay_domains: Some(vec![1; 500]),
            nvis: None,
            census: Some(census::CensusEstimate {
                cells_observed: 500,
                m: census::DEFAULT_SKETCH_M,
                u_m: 0.06,
                n_hat: 500.0,
                n_lower_99: 480,
                saturated: false,
            }),
        }
    }

    #[test]
    fn a_fully_measured_vantablack_node_may_claim_anonymity() {
        let ledger = build(&verified_input());
        assert!(ledger.all_verified(), "{:?}", ledger.invariants);
        assert_eq!(
            ledger.claim,
            "anonymous among 500 independent public relays"
        );
        assert!(!ledger.headline().contains("FAIL"));
    }

    #[test]
    fn too_few_relays_downgrades_the_headline() {
        let mut input = verified_input();
        input.public_relays = Some(12);
        input.relay_domains = Some(vec![1; 12]);
        let ledger = build(&input);
        assert!(ledger.claim.contains("withheld"));
        assert!(ledger.headline().contains("failing"));
        assert!(ledger
            .invariants
            .iter()
            .any(|i| i.id == "relay_population" && i.state == State::Failed));
    }

    #[test]
    fn ghost_never_claims_anonymity_even_with_a_huge_population() {
        let mut input = verified_input();
        input.regime = Some(Regime::Ghost);
        input.circuit_asns = None; // ghost does not require diversity
        let ledger = build(&input);
        assert_eq!(ledger.claim, "ghost (umbra) — no anonymity claim");
    }

    #[test]
    fn formal_attestation_matches_the_committed_models() {
        use sha2::{Digest, Sha256};
        for &(file, expected, _) in formal::MODELS {
            let bytes = std::fs::read(file).unwrap_or_else(|e| panic!("{file}: {e}"));
            let actual: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                actual, expected,
                "{file} changed without re-running scripts/formal_attest.sh"
            );
        }
        let provenance = formal::provenance();
        assert!(provenance.models >= 5);
        assert!(provenance.all_queries_hold, "{provenance:?}");
    }

    fn chronos_at(
        age: u64,
        inner_ms: f64,
        verdict: super::super::chronos::ClockVerdict,
    ) -> super::super::chronos::ChronosEvidence {
        super::super::chronos::ChronosEvidence {
            inner_rtt_ms: inner_ms,
            outer_rtt_ms: 30.0,
            horizon_ms: 160.0,
            residual_ms: 0.0,
            observations: 2,
            observed_at: crate::ghost::v2::now_secs().saturating_sub(age),
            verdict,
        }
    }

    #[test]
    fn cover_claim_is_withheld_without_fresh_shaping_evidence() {
        let mut input = verified_input();
        input.shaping = None;
        let ledger = build(&input);
        let cover = ledger
            .invariants
            .iter()
            .find(|i| i.id == "cover_traffic")
            .unwrap();
        assert_eq!(cover.state, State::Unknown, "{cover:?}");
        assert!(!ledger.all_verified());
        assert!(ledger.claim.contains("withheld") || ledger.claim.contains("unmeasured"));
    }

    #[test]
    fn a_shaping_burst_violation_fails_the_cover_claim() {
        let mut input = verified_input();
        input.shaping = Some(super::super::racs::ShapingEvidence {
            slots: 240,
            emissions: 1_024,
            max_on_run: super::super::racs::MAX_ON_RUN_SLOTS + 1,
            duty: 0.1,
            last_emission_unix: crate::ghost::v2::now_secs(),
        });
        let ledger = build(&input);
        let cover = ledger
            .invariants
            .iter()
            .find(|i| i.id == "cover_traffic")
            .unwrap();
        assert_eq!(cover.state, State::Failed, "{cover:?}");
        assert!(!ledger.all_verified());
    }

    #[test]
    fn stale_chronos_evidence_is_unmeasured_not_verified() {
        let mut input = verified_input();
        input.chronos = Some(chronos_at(
            super::super::chronos::EVIDENCE_TTL_SECS + 1,
            150.0,
            super::super::chronos::ClockVerdict::Consistent,
        ));
        let ledger = build(&input);
        let clocks = ledger
            .invariants
            .iter()
            .find(|i| i.id == "layer_clocks")
            .unwrap();
        assert_eq!(clocks.state, State::Unknown, "{clocks:?}");
        assert!(!ledger.all_verified());
    }

    #[test]
    fn a_circuit_outside_the_stationary_horizon_fails_the_clock_claim() {
        let mut input = verified_input();
        input.chronos = Some(chronos_at(
            0,
            161.0,
            super::super::chronos::ClockVerdict::Divergent,
        ));
        let ledger = build(&input);
        let clocks = ledger
            .invariants
            .iter()
            .find(|i| i.id == "layer_clocks")
            .unwrap();
        assert_eq!(clocks.state, State::Failed, "{clocks:?}");
    }

    #[test]
    fn fast_and_shielded_are_not_charged_timing_hardening() {
        for regime in [Regime::Fast, Regime::Shielded] {
            let mut input = verified_input();
            input.regime = Some(regime);
            input.chronos = Some(chronos_at(
                0,
                400.0,
                super::super::chronos::ClockVerdict::Divergent,
            ));
            input.shaping = Some(super::super::racs::ShapingEvidence {
                slots: 1,
                emissions: 0,
                max_on_run: 99,
                duty: 1.0,
                last_emission_unix: 0,
            });
            let ledger = build(&input);
            assert!(
                !ledger
                    .invariants
                    .iter()
                    .any(|i| i.id == "layer_clocks" || i.id == "cover_traffic"),
                "{regime:?} must not inherit Umbra timing requirements: {:?}",
                ledger.invariants
            );
        }
    }

    #[test]
    fn nvis_claim_requires_a_fresh_measurement() {
        let mut profile = super::super::nvis::NvisProfile::from_measurement(
            5_000,
            12_000,
            32,
            crate::ghost::v2::now_secs(),
        )
        .unwrap();
        let mut input = verified_input();
        input.nvis = Some(profile);
        assert_eq!(
            build(&input)
                .invariants
                .iter()
                .find(|i| i.id == "nvis_profile")
                .unwrap()
                .state,
            State::Verified
        );

        profile.measured_at =
            crate::ghost::v2::now_secs().saturating_sub(super::super::nvis::EVIDENCE_TTL_SECS + 1);
        input.nvis = Some(profile);
        assert_eq!(
            build(&input)
                .invariants
                .iter()
                .find(|i| i.id == "nvis_profile")
                .unwrap()
                .state,
            State::Unknown,
            "a stale radio measurement is not a profile claim"
        );
    }

    #[test]
    fn stale_wire_witnesses_degrade_to_unmeasured_not_to_verified() {
        let mut input = verified_input();
        let old = crate::ghost::v2::now_secs().saturating_sub(86_400);
        input.circuit_hops = Some(WireWitness::observed(3u8, old));
        input.cover_tx = Some(WireWitness::observed(1_024u64, old));
        input.nonce_echo_hops = Some(WireWitness::observed(3u8, old));
        let ledger = build(&input);
        for id in ["circuit_length", "cover_traffic", "nonce_echo"] {
            let invariant = ledger.invariants.iter().find(|i| i.id == id).unwrap();
            assert_eq!(invariant.state, State::Unknown, "{id}: {invariant:?}");
        }
        assert!(ledger.claim.contains("withheld"));
    }

    #[test]
    fn unmeasured_is_not_a_pass() {
        let ledger = build(&LedgerInput {
            regime: Some(Regime::Vantablack),
            ..Default::default()
        });
        assert!(ledger.invariants.iter().any(|i| i.state == State::Unknown));
        assert!(!ledger.all_verified());
        assert!(ledger.claim.contains("withheld"));
        assert!(ledger.headline().contains("unmeasured"));
    }

    #[test]
    fn dns_leak_and_missing_cover_are_failures() {
        let mut input = verified_input();
        input.dns_leak = Some(true);
        input.cover_tx = Some(witness(0));
        let ledger = build(&input);
        let failed: Vec<&str> = ledger.failed().map(|i| i.id).collect();
        assert!(failed.contains(&"dns_path"));
        assert!(failed.contains(&"cover_traffic"));
    }

    #[test]
    fn a_domain_cluster_is_a_subnet_not_an_address() {
        assert_eq!(domain_cluster("192.0.2.10:2270"), "192.0.2.0/24");
        assert_eq!(domain_cluster("192.0.2.11:2270"), "192.0.2.0/24");
        assert_eq!(domain_cluster("198.51.100.7:2270"), "198.51.100.0/24");
        assert_eq!(domain_cluster("[2001:db8:1::5]:2270"), "2001:db8:1::/48");
    }

    #[test]
    fn the_verified_registry_is_the_source_of_the_population() {
        let fp = "xray-witness-test-9f3a";
        note_verified_peer(fp, CAP_RELAY, "192.0.2.200:2270");
        assert!(verified_peers().iter().any(|w| w.fingerprint == fp));
        let (population, groups) = relay_population();
        assert_eq!(groups.iter().sum::<usize>(), population);
        forget_verified_peer(fp);
        assert!(!verified_peers().iter().any(|w| w.fingerprint == fp));
    }

    #[test]
    fn one_host_with_many_addresses_is_not_a_population() {
        let mut input = verified_input();
        input.public_relays = Some(500);
        input.relay_domains = Some(vec![500]);
        let ledger = build(&input);
        assert!(
            ledger.failed().any(|i| i.id == "relay_population"),
            "N_eff of one domain is 1, not 500"
        );
        assert!(ledger.claim.contains("withheld"));
    }

    #[test]
    fn an_unmeasured_domain_grouping_is_unknown_rather_than_optimistic() {
        let mut input = verified_input();
        input.relay_domains = None;
        let ledger = build(&input);
        let population = ledger
            .invariants
            .iter()
            .find(|i| i.id == "relay_population")
            .unwrap();
        assert_eq!(population.state, State::Unknown);
        assert!(population.detail.contains("N_eff is unknown"));
    }

    #[test]
    fn isp_view_does_not_pretend_to_hide_a_phantom_exit() {
        let input = LedgerInput {
            regime: Some(Regime::Fast),
            exit_ip: Some("203.0.113.7".into()),
            ..Default::default()
        };
        let ledger = build(&input);
        let site = ledger
            .observations
            .iter()
            .find(|o| o.observer == "The website")
            .unwrap();
        assert!(site.sees.iter().any(|s| s.contains("203.0.113.7")));
        assert!(ledger.claim.contains("no anonymity claim"));
    }

    #[test]
    fn signed_nonce_echo_verifies_and_rejects_forgeries() {
        let id = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = id.long_term_signing.verifying_key().to_bytes();
        let nonce = issue_nonce_challenge();
        let msg = nonce_echo_signing_input(&nonce, 3);
        let mut bad_sig = id.sign(&msg).to_bytes();
        bad_sig[0] ^= 0xff;
        assert!(!verify_nonce_echo(&nonce, &pk, &bad_sig, 3));

        let nonce2 = issue_nonce_challenge();
        let msg2 = nonce_echo_signing_input(&nonce2, 3);
        let sig2 = id.sign(&msg2).to_bytes();
        assert!(verify_nonce_echo(&nonce2, &pk, &sig2, 3));
        assert_eq!(last_nonce_echo_hops(), Some(3));
        assert!(!verify_nonce_echo(&nonce2, &pk, &sig2, 3));
    }
}
