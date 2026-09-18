//! Invention §52: Mesh-as-Archive
//!
//! Permanent, unlinkable public archival mirroring for open standards and public canons.
//!
//! Stores censorship-resistant public artifacts sharded via Reed-Solomon(2,1) erasure coding.
//! Anyone holding any 2 of 3 public shards can reconstruct the canonical document, and the
//! document's identity is verified against an immutable cryptographic content hash.

use crate::ghost::layers::l4_rs;
use sha2::{Digest, Sha256};

/// An immutable public document archived across the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivalRecord {
    pub canonical_uri: String,
    pub content_hash: [u8; 32],
    pub shards: Vec<Vec<u8>>,
}

impl ArchivalRecord {
    /// Archive a canonical document by splitting it into 3 Reed-Solomon shards.
    pub fn create(canonical_uri: String, content: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let content_hash: [u8; 32] = hasher.finalize().into();

        let mut framed = (content.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(content);
        if framed.len() % 2 != 0 {
            framed.push(0);
        }

        let shards = l4_rs::encode(&mut framed);

        Self {
            canonical_uri,
            content_hash,
            shards,
        }
    }

    /// Reconstruct and verify document integrity from available surviving shards.
    pub fn reconstruct(
        &self,
        surviving_shards: &[Option<Vec<u8>>],
    ) -> Result<Vec<u8>, &'static str> {
        if surviving_shards.len() != 3 {
            return Err("exactly 3 shard slots required");
        }
        if surviving_shards.iter().flatten().count() < 2 {
            return Err("at least 2 shards required for reconstruction");
        }

        let mut work = surviving_shards.to_vec();
        l4_rs::reconstruct(&mut work).map_err(|_| "RS reconstruction failed")?;

        let s0 = work[0].as_ref().ok_or("missing shard 0")?;
        let s1 = work[1].as_ref().ok_or("missing shard 1")?;
        let mut combined = Vec::with_capacity(s0.len() + s1.len());
        combined.extend_from_slice(s0);
        combined.extend_from_slice(s1);

        if combined.len() < 2 {
            return Err("truncated archive stream");
        }
        let length = u16::from_be_bytes([combined[0], combined[1]]) as usize;
        if length + 2 > combined.len() {
            return Err("corrupted length header");
        }

        let content = &combined[2..2 + length];

        // Invariant: Reconstructed content MUST match canonical content hash
        let mut hasher = Sha256::new();
        hasher.update(content);
        let actual_hash: [u8; 32] = hasher.finalize().into();

        if actual_hash != self.content_hash {
            return Err("archive integrity violation: content hash mismatch");
        }

        Ok(content.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_archive_creation_and_reconstruction_from_partial_shards() {
        let uri = "urn:standard:ietf:rfc9591".to_string();
        let document = b"FROST: Flexible Round-Optimized Schnorr Threshold Signatures Standard";

        let archive = ArchivalRecord::create(uri, document);
        assert_eq!(archive.shards.len(), 3);

        // 1. Reconstruct from Shard 0 and Shard 1 (Shard 2 missing)
        let surviving_0_1 = vec![
            Some(archive.shards[0].clone()),
            Some(archive.shards[1].clone()),
            None,
        ];
        let recovered = archive
            .reconstruct(&surviving_0_1)
            .expect("reconstructs 0 and 1");
        assert_eq!(&recovered, document);

        // 2. Reconstruct from Shard 1 and Shard 2 (Shard 0 missing)
        let surviving_1_2 = vec![
            None,
            Some(archive.shards[1].clone()),
            Some(archive.shards[2].clone()),
        ];
        let recovered2 = archive
            .reconstruct(&surviving_1_2)
            .expect("reconstructs 1 and 2");
        assert_eq!(&recovered2, document);

        // 3. Exactly 1 shard is insufficient
        let surviving_only_0 = vec![Some(archive.shards[0].clone()), None, None];
        assert!(archive.reconstruct(&surviving_only_0).is_err());
    }
}
