#![cfg(feature = "research")]
//! Chrono-Erosion — threshold ephemerizer with unconditional post-expiry
//! oblivion (`DEV/INVENTIONS_AND_PROOFS.md` Invention 7, V3 Stage 7).
//!
//! A committee of `n` peers holds `(t, n)` Shamir shares of an epoch VOPRF
//! secret `k_tau` and publishes `K_tau = k_tau * G`. A sender wraps a bundle key
//! under `mask = H(k_tau * M)`, where `M = H_G("VB-EROSION-BUNDLE-V1" || bundle_id)`.
//! `k_tau * M` is obtained through a blinded threshold evaluation: the receiver
//! sends `B = r * M`, collects `t` partial evaluations `s_j * B` each proved
//! with a Chaum–Pedersen DLEQ against the committee's published share
//! commitment, Lagrange-interpolates at zero, and unblinds with `r^-1`. The
//! committee never learns which bundle was addressed.
//!
//! At the expiry epoch every honest member volatile-zeroizes its share bytes.
//! Once fewer than `t` shares exist, `k_tau * M` is off-limits without breaking
//! CDH in Ristretto255 — the archive of wrapped keys stays, the plaintext does
//! not. The share bytes are held as canonical scalars and wiped with `zeroize`,
//! so the forgetting is a wiper call rather than a dropped reference.

use std::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as BASEPOINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

pub const EROSION_H2G_DOMAIN: &[u8] = b"VB-EROSION-H2G-V1";
pub const EROSION_MASK_DOMAIN: &[u8] = b"VB-EROSION-MASK-V1";
pub const EROSION_TAG_DOMAIN: &[u8] = b"VB-EROSION-TAG-V1";
pub const EROSION_DLEQ_DOMAIN: &[u8] = b"VB-EROSION-DLEQ-V1";

/// Why a bundle cannot be sealed, unsealed, or a partial evaluation combined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErosionError {
    /// The bundle's expiry epoch has passed, or the committee forgot its shares.
    Expired,
    /// Fewer than `t` partial evaluations are available.
    TooFewShares,
    /// A partial evaluation names a committee member that does not exist.
    UnknownMember(usize),
    /// A partial evaluation is not a canonical Ristretto point.
    NotOnCurve,
    /// A partial evaluation's DLEQ does not tie it to the member's commitment.
    BadProof,
    /// The unwrapped key does not match the bundle it claims to be.
    Mismatch,
    /// The requested committee shape is invalid.
    Shape(&'static str),
}

impl fmt::Display for ErosionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "the expiry epoch passed; the bundle key is gone"),
            Self::TooFewShares => write!(f, "fewer than the threshold of shares are available"),
            Self::UnknownMember(i) => write!(f, "committee member {i} does not exist"),
            Self::NotOnCurve => write!(f, "partial evaluation is not a Ristretto point"),
            Self::BadProof => write!(f, "partial evaluation is not bound to its commitment"),
            Self::Mismatch => write!(f, "bundle key does not match its identifier"),
            Self::Shape(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ErosionError {}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
}

/// Hash a bundle identifier to the group element whose mask the committee owns.
pub fn bundle_point(bundle_id: &[u8; 32]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(EROSION_H2G_DOMAIN);
    hasher.update(bundle_id);
    RistrettoPoint::hash_from_bytes::<Sha512>(&hasher.finalize())
}

fn mask_for(point: &RistrettoPoint, bundle_id: &[u8; 32], die_at: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EROSION_MASK_DOMAIN);
    hasher.update(point.compress().as_bytes());
    hasher.update(bundle_id);
    hasher.update(die_at.to_be_bytes());
    hasher.finalize().into()
}

fn tag_for(mask: &[u8; 32], bundle_id: &[u8; 32], die_at: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EROSION_TAG_DOMAIN);
    hasher.update(mask);
    hasher.update(bundle_id);
    hasher.update(die_at.to_be_bytes());
    hasher.finalize().into()
}

// ── DLEQ ────────────────────────────────────────────────────────────────────

/// Chaum–Pedersen proof that a partial evaluation used the member's own share:
/// `log_G C_j == log_B E_j`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErosionDleq {
    pub c: [u8; 32],
    pub s: [u8; 32],
}

fn dleq_challenge(
    commitment: &RistrettoPoint,
    blinded: &RistrettoPoint,
    eval: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(EROSION_DLEQ_DOMAIN);
    for point in [&BASEPOINT, commitment, blinded, eval, a1, a2] {
        hasher.update(point.compress().as_bytes());
    }
    Scalar::from_hash(hasher)
}

impl ErosionDleq {
    fn prove(
        share: &Scalar,
        commitment: &RistrettoPoint,
        blinded: &RistrettoPoint,
        eval: &RistrettoPoint,
    ) -> Self {
        let t = random_scalar();
        let a1 = t * BASEPOINT;
        let a2 = t * blinded;
        let c = dleq_challenge(commitment, blinded, eval, &a1, &a2);
        let s = t + c * share;
        Self {
            c: c.to_bytes(),
            s: s.to_bytes(),
        }
    }

    pub fn verify(
        &self,
        commitment: &RistrettoPoint,
        blinded: &RistrettoPoint,
        eval: &RistrettoPoint,
    ) -> bool {
        let (Some(c), Some(s)) = (scalar_from_bytes(&self.c), scalar_from_bytes(&self.s)) else {
            return false;
        };
        let a1 = s * BASEPOINT - c * commitment;
        let a2 = s * blinded - c * eval;
        dleq_challenge(commitment, blinded, eval, &a1, &a2) == c
    }
}

// ── Committee ───────────────────────────────────────────────────────────────

/// One member's blinded evaluation plus the proof binding it to its share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEvaluation {
    /// Zero-based committee member index.
    pub index: usize,
    /// `s_j * B`, compressed.
    pub evaluation: [u8; 32],
    pub proof: ErosionDleq,
}

/// `n` peers holding `(t, n)` Shamir shares of an epoch secret.
#[derive(Debug, Clone)]
pub struct EphemerizerCommittee {
    threshold: usize,
    deadline: u64,
    commitments: Vec<RistrettoPoint>,
    /// Shares stay in canonical scalar bytes so `expire` is a real wipe rather
    /// than a reference drop.
    shares: Vec<Option<[u8; 32]>>,
}

impl EphemerizerCommittee {
    /// Deal `(threshold, members)` shares of `secret`. Returns the committee and
    /// the published `K = secret * G`.
    pub fn from_secret(
        threshold: usize,
        members: usize,
        deadline: u64,
        secret: Scalar,
    ) -> Result<(Self, RistrettoPoint), ErosionError> {
        if threshold == 0 {
            return Err(ErosionError::Shape("threshold must be at least 1"));
        }
        if threshold > members {
            return Err(ErosionError::Shape("threshold cannot exceed members"));
        }
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(secret);
        for _ in 1..threshold {
            coefficients.push(random_scalar());
        }

        let shares: Vec<[u8; 32]> = (1..=members)
            .map(|x| evaluate_polynomial(&coefficients, Scalar::from(x as u64)).to_bytes())
            .collect();
        let commitments: Vec<RistrettoPoint> = shares
            .iter()
            .map(|bytes| scalar_from_bytes(bytes).expect("fresh share is canonical") * BASEPOINT)
            .collect();
        Ok((
            Self {
                threshold,
                deadline,
                commitments,
                shares: shares.into_iter().map(Some).collect(),
            },
            secret * BASEPOINT,
        ))
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn members(&self) -> usize {
        self.shares.len()
    }

    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Published per-member commitments `C_j = s_j * G`.
    pub fn commitments(&self) -> &[RistrettoPoint] {
        &self.commitments
    }

    /// This member's share, for the peer that will host it.
    ///
    /// The daemon spreads one share per host so that no single machine holds a
    /// threshold of them, which is what makes a seizure of this node reveal no
    /// bundle key. `None` means the member already wiped its share.
    pub fn share_bytes(&self, index: usize) -> Option<[u8; 32]> {
        self.shares.get(index).copied().flatten()
    }

    /// Rebuild a committee from the shares that survived on their hosts.
    ///
    /// Commitments are recomputed as `s_j * G` for the shares present, which is
    /// exactly what the dealer published for those members, so their partial
    /// evaluations still verify. Absent members get the identity point, which no
    /// evaluation can match.
    pub fn from_shares(
        threshold: usize,
        members: usize,
        deadline: u64,
        shares: Vec<Option<[u8; 32]>>,
    ) -> Result<Self, ErosionError> {
        if threshold == 0 {
            return Err(ErosionError::Shape("threshold must be at least 1"));
        }
        if threshold > members {
            return Err(ErosionError::Shape("threshold cannot exceed members"));
        }
        if shares.len() != members {
            return Err(ErosionError::Shape("one share slot per member"));
        }
        if shares.iter().flatten().count() < threshold {
            return Err(ErosionError::TooFewShares);
        }
        let mut commitments = Vec::with_capacity(members);
        for slot in &shares {
            match slot {
                Some(bytes) => {
                    let scalar = scalar_from_bytes(bytes).ok_or(ErosionError::NotOnCurve)?;
                    commitments.push(scalar * BASEPOINT);
                }
                None => commitments.push(RistrettoPoint::identity()),
            }
        }
        Ok(Self {
            threshold,
            deadline,
            commitments,
            shares,
        })
    }

    /// How many shares this member set still holds. Read this after `expire`.
    pub fn retained_shares(&self) -> usize {
        self.shares.iter().filter(|s| s.is_some()).count()
    }

    /// A committee is dead once its epoch passed or it can no longer reach
    /// threshold by itself.
    pub fn is_dead(&self, now: u64) -> bool {
        now >= self.deadline || self.retained_shares() < self.threshold
    }

    /// Blinded partial evaluation `s_j * B` with a DLEQ against `C_j`.
    ///
    /// `None` means this member has already wiped its share.
    pub fn evaluate(&self, index: usize, blinded: &RistrettoPoint) -> Option<PartialEvaluation> {
        let bytes = self.shares.get(index)?.as_ref()?;
        let share = scalar_from_bytes(bytes)?;
        let commitment = self.commitments.get(index)?;
        let evaluation = share * blinded;
        let proof = ErosionDleq::prove(&share, commitment, blinded, &evaluation);
        Some(PartialEvaluation {
            index,
            evaluation: evaluation.compress().to_bytes(),
            proof,
        })
    }

    /// Volatile-zeroize one member's share.
    pub fn retire(&mut self, index: usize) {
        if let Some(slot) = self.shares.get_mut(index) {
            if let Some(bytes) = slot.as_mut() {
                bytes.zeroize();
            }
            *slot = None;
        }
    }

    /// The expiry epoch: every member wipes its share.
    pub fn expire(&mut self) {
        for index in 0..self.shares.len() {
            self.retire(index);
        }
    }
}

fn evaluate_polynomial(coefficients: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for coefficient in coefficients.iter().rev() {
        acc = acc * x + coefficient;
    }
    acc
}

/// Lagrange-interpolate `t` verified partial evaluations at zero.
///
/// Each evaluation is checked against the member's published commitment before
/// its weight is applied, so a single dishonest member cannot move the result.
pub fn combine_partials(
    commitments: &[RistrettoPoint],
    threshold: usize,
    blinded: &RistrettoPoint,
    partials: &[PartialEvaluation],
) -> Result<RistrettoPoint, ErosionError> {
    if partials.len() < threshold {
        return Err(ErosionError::TooFewShares);
    }
    let selected = &partials[..threshold];
    let mut seen = Vec::with_capacity(threshold);
    let mut combined = RistrettoPoint::identity();

    for (position, partial) in selected.iter().enumerate() {
        if partial.index >= commitments.len() {
            return Err(ErosionError::UnknownMember(partial.index));
        }
        if seen.contains(&partial.index) {
            return Err(ErosionError::Shape("duplicate committee member"));
        }
        seen.push(partial.index);

        let evaluation = CompressedRistretto(partial.evaluation)
            .decompress()
            .ok_or(ErosionError::NotOnCurve)?;
        if !partial
            .proof
            .verify(&commitments[partial.index], blinded, &evaluation)
        {
            return Err(ErosionError::BadProof);
        }

        let x_j = Scalar::from(partial.index as u64 + 1);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (other_position, other) in selected.iter().enumerate() {
            if other_position == position {
                continue;
            }
            let x_m = Scalar::from(other.index as u64 + 1);
            numerator *= x_m;
            denominator *= x_m - x_j;
        }
        let weight = numerator * denominator.invert();
        combined += weight * evaluation;
    }
    Ok(combined)
}

/// The shared mask `k_tau * M` round-trip: blind, collect threshold partials,
/// interpolate, unblind. The committee only ever sees `r * M`.
fn threshold_mask(
    committee: &EphemerizerCommittee,
    bundle_id: &[u8; 32],
    die_at: u64,
) -> Result<[u8; 32], ErosionError> {
    let point = bundle_point(bundle_id);
    let blinding = random_scalar();
    let blinded = blinding * point;

    let mut partials = Vec::with_capacity(committee.threshold());
    for index in 0..committee.members() {
        if partials.len() == committee.threshold() {
            break;
        }
        if let Some(partial) = committee.evaluate(index, &blinded) {
            partials.push(partial);
        }
    }
    if partials.len() < committee.threshold() {
        return Err(ErosionError::Expired);
    }

    let shared = combine_partials(
        committee.commitments(),
        committee.threshold(),
        &blinded,
        &partials,
    )?;
    let unblinded = blinding.invert() * shared;
    Ok(mask_for(&unblinded, bundle_id, die_at))
}

// ── Bundles ─────────────────────────────────────────────────────────────────

/// A bundle key wrapped under an epoch the committee will forget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBundle {
    pub bundle_id: [u8; 32],
    pub die_at: u64,
    pub wrapped_key: [u8; 32],
    /// `H(mask || bundle_id || die_at)`: lets the receiver tell "wrong epoch"
    /// apart from "wrong bundle" without ever exposing the mask.
    pub tag: [u8; 32],
}

/// Wrap `message_key` so that it is readable only before `die_at` and only
/// while the committee still holds `threshold` shares.
pub fn seal_bundle(
    committee: &EphemerizerCommittee,
    bundle_id: &[u8; 32],
    die_at: u64,
    message_key: &[u8; 32],
    now: u64,
) -> Result<SealedBundle, ErosionError> {
    if committee.is_dead(now) {
        return Err(ErosionError::Expired);
    }
    let mask = threshold_mask(committee, bundle_id, die_at)?;
    let mut wrapped_key = [0u8; 32];
    for ((dst, key), mask_byte) in wrapped_key
        .iter_mut()
        .zip(message_key.iter())
        .zip(mask.iter())
    {
        *dst = key ^ mask_byte;
    }
    Ok(SealedBundle {
        bundle_id: *bundle_id,
        die_at,
        wrapped_key,
        tag: tag_for(&mask, bundle_id, die_at),
    })
}

/// Recover the bundle key, or refuse because the epoch — not the authority —
/// has ended.
pub fn open_bundle(
    committee: &EphemerizerCommittee,
    bundle: &SealedBundle,
    now: u64,
) -> Result<[u8; 32], ErosionError> {
    if now >= bundle.die_at {
        return Err(ErosionError::Expired);
    }
    if committee.is_dead(now) {
        return Err(ErosionError::Expired);
    }
    let mask = threshold_mask(committee, &bundle.bundle_id, bundle.die_at)?;
    if tag_for(&mask, &bundle.bundle_id, bundle.die_at) != bundle.tag {
        return Err(ErosionError::Mismatch);
    }
    let mut key = [0u8; 32];
    for ((dst, wrapped), mask_byte) in key
        .iter_mut()
        .zip(bundle.wrapped_key.iter())
        .zip(mask.iter())
    {
        *dst = wrapped ^ mask_byte;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn committee(threshold: usize, members: usize, deadline: u64) -> EphemerizerCommittee {
        EphemerizerCommittee::from_secret(threshold, members, deadline, Scalar::from(424_242u64))
            .expect("valid committee")
            .0
    }

    #[test]
    fn a_bundle_is_readable_only_before_its_epoch() {
        let committee = committee(2, 3, NOW + 1_000);
        let bundle_id = [7u8; 32];
        let key = [0x9Au8; 32];

        let sealed = seal_bundle(&committee, &bundle_id, NOW + 600, &key, NOW).expect("seals");
        assert_eq!(
            open_bundle(&committee, &sealed, NOW + 300).expect("before expiry"),
            key
        );
        // At the deadline the bundle is mathematically gone, whatever the
        // committee still holds.
        assert_eq!(
            open_bundle(&committee, &sealed, NOW + 600),
            Err(ErosionError::Expired)
        );
        assert_eq!(
            open_bundle(&committee, &sealed, NOW + 601),
            Err(ErosionError::Expired)
        );
    }

    #[test]
    fn the_committee_forgetting_is_what_kills_the_bundle() {
        let mut committee = committee(2, 3, NOW + 10_000);
        let bundle_id = [3u8; 32];
        let key = [0x5Cu8; 32];
        let sealed = seal_bundle(&committee, &bundle_id, NOW + 900, &key, NOW).expect("seals");

        // One member wiping leaves threshold reachable: the bundle still opens.
        committee.retire(2);
        assert_eq!(
            open_bundle(&committee, &sealed, NOW + 100).expect("two shares survive"),
            key
        );

        // A second wipe drops below threshold: oblivion, with the ciphertext
        // still sitting in the archive.
        committee.retire(1);
        assert_eq!(committee.retained_shares(), 1);
        assert_eq!(
            open_bundle(&committee, &sealed, NOW + 100),
            Err(ErosionError::Expired)
        );
        assert_eq!(
            committee.evaluate(1, &bundle_point(&bundle_id)),
            None,
            "a retired member has nothing left to evaluate"
        );
    }

    #[test]
    fn fewer_than_threshold_partials_cannot_unblind() {
        let committee = committee(2, 3, NOW + 1_000);
        let bundle_id = [1u8; 32];
        let blinded = Scalar::from(5u64) * bundle_point(&bundle_id);
        let partial = committee.evaluate(0, &blinded).expect("member 0 live");

        assert_eq!(
            combine_partials(committee.commitments(), 2, &blinded, &[partial]),
            Err(ErosionError::TooFewShares)
        );
    }

    #[test]
    fn a_partial_evaluation_not_bound_to_its_commitment_is_refused() {
        let committee = committee(2, 3, NOW + 1_000);
        let bundle_id = [2u8; 32];
        let blinded = Scalar::from(9u64) * bundle_point(&bundle_id);

        let p0 = committee.evaluate(0, &blinded).expect("member 0");
        let p1 = committee.evaluate(1, &blinded).expect("member 1");
        // Re-label member 1's valid evaluation as member 0's: the point is on
        // the curve and the proof is well-formed, but it is for another share.
        let impostor = PartialEvaluation {
            index: 0,
            evaluation: p1.evaluation,
            proof: p1.proof.clone(),
        };
        assert_eq!(
            combine_partials(committee.commitments(), 2, &blinded, &[impostor, p0]),
            Err(ErosionError::BadProof)
        );
    }

    #[test]
    fn the_mask_binds_the_bundle_and_its_epoch() {
        let committee = committee(2, 3, NOW + 10_000);
        let key = [0x77u8; 32];
        let sealed = seal_bundle(&committee, &[0x10u8; 32], NOW + 500, &key, NOW).expect("seals");

        let mut relabelled = sealed.clone();
        relabelled.bundle_id = [0x11u8; 32];
        assert_eq!(
            open_bundle(&committee, &relabelled, NOW + 100),
            Err(ErosionError::Mismatch)
        );

        // The DLEQ path is deterministic in the group: both seal and open
        // derive the same mask from the same bundle, so the tag matches.
        assert_eq!(
            open_bundle(&committee, &sealed, NOW + 100).expect("open"),
            key
        );
    }

    #[test]
    fn a_dead_committee_refuses_to_seal() {
        let committee = committee(2, 3, NOW + 50);
        assert_eq!(
            seal_bundle(&committee, &[0u8; 32], NOW + 500, &[1u8; 32], NOW + 50),
            Err(ErosionError::Expired)
        );
        assert!(EphemerizerCommittee::from_secret(0, 3, NOW, Scalar::ONE).is_err());
        assert!(EphemerizerCommittee::from_secret(4, 3, NOW, Scalar::ONE).is_err());
    }
}
