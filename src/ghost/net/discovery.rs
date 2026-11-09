//! Zero-Knowledge 3-Tier Peer Discovery & Blind Rendezvous Subsystem.
//!
//! Eliminates centralized directory exposure, Kademlia crawler surveillance,
//! and timing correlation attacks on public discovery relays.
//!
//! Architecture:
//! - **Tier 1 (Local Disk Cache)**: Authenticated peer descriptors cached in `peers.bin`.
//!   Rebooting nodes reconnect directly with zero external network footprint.
//! - **Tier 2 (Out-Of-Band Rendezvous)**: `vb://<hex>` URI format containing signed
//!   cryptographic descriptors for direct exchange (Signal, QR code, air-gapped USB).
//! - **Tier 3 (Blind Ephemeral Rendezvous)**: ChaCha20-Poly1305 encrypted rendezvous blobs
//!   indexed by deterministic epoch keys (`K_epoch = HKDF(SwarmSecret, Epoch)`). Third-party
//!   hosts (Cloudflare Workers / BEP-44 DHT) see only high-entropy random bytes and zero node graphs.
//! - **Genesis Bootstrapper**: When a node has zero verified peers (`N = 0`) after an IP rotation,
//!   it enters `GenesisSeed` mode to discover initial peers; once $\ge 1$ peer session is verified,
//!   it transitions to `MeshRelay` mode where all peer updates propagate over encrypted 1-hop mesh relays.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::ghost::layers::l0_identity::{verify_peer_signature, GhostIdentity};

/// Prefix for out-of-band Vantablack peer URIs.
pub const VB_URI_PREFIX: &str = "vb://";

/// NAT traversal classification byte.
pub const NAT_DIRECT: u8 = 0;
pub const NAT_CONE: u8 = 1;
pub const NAT_RESTRICTED: u8 = 2;
pub const NAT_SYMMETRIC: u8 = 3;

/// Authenticated peer descriptor for out-of-band exchange and local disk caching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub ed25519_pk: [u8; 32],
    pub ml_kem_hash: [u8; 16],
    pub endpoint: SocketAddr,
    pub nat_type: u8,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl PeerDescriptor {
    pub const MAGIC: &'static [u8; 4] = b"VBPD";

    /// Create and sign a new peer descriptor for this node.
    pub fn sign_new(
        identity: &GhostIdentity,
        ml_kem_pk: &[u8],
        endpoint: SocketAddr,
        nat_type: u8,
    ) -> Self {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(ml_kem_pk);
        let digest = h.finalize();
        let mut ml_kem_hash = [0u8; 16];
        ml_kem_hash.copy_from_slice(&digest[..16]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ed25519_pk = identity.public_key_bytes();
        let signing_material =
            Self::signing_bytes(&ed25519_pk, &ml_kem_hash, endpoint, nat_type, now);
        let signature = identity.sign(&signing_material).to_bytes();

        Self {
            ed25519_pk,
            ml_kem_hash,
            endpoint,
            nat_type,
            timestamp: now,
            signature,
        }
    }

    fn signing_bytes(
        pk: &[u8; 32],
        kem_hash: &[u8; 16],
        endpoint: SocketAddr,
        nat_type: u8,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(80);
        b.extend_from_slice(Self::MAGIC);
        b.extend_from_slice(pk);
        b.extend_from_slice(kem_hash);
        match endpoint.ip() {
            IpAddr::V4(v4) => {
                b.push(4);
                b.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                b.push(6);
                b.extend_from_slice(&v6.octets());
            }
        }
        b.extend_from_slice(&endpoint.port().to_be_bytes());
        b.push(nat_type);
        b.extend_from_slice(&timestamp.to_be_bytes());
        b
    }

    /// Verify signature and timestamp of this descriptor.
    pub fn verify(&self, max_skew_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.timestamp > now + max_skew_secs {
            return false;
        }
        if now > self.timestamp && (now - self.timestamp) > max_skew_secs {
            return false;
        }

        let material = Self::signing_bytes(
            &self.ed25519_pk,
            &self.ml_kem_hash,
            self.endpoint,
            self.nat_type,
            self.timestamp,
        );
        verify_peer_signature(&self.ed25519_pk, &material, &self.signature)
    }

    /// Binary serialization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(140);
        b.extend_from_slice(Self::MAGIC);
        b.extend_from_slice(&self.ed25519_pk);
        b.extend_from_slice(&self.ml_kem_hash);
        match self.endpoint.ip() {
            IpAddr::V4(v4) => {
                b.push(4);
                b.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                b.push(6);
                b.extend_from_slice(&v6.octets());
            }
        }
        b.extend_from_slice(&self.endpoint.port().to_be_bytes());
        b.push(self.nat_type);
        b.extend_from_slice(&self.timestamp.to_be_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    /// Binary deserialization.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 32 + 16 + 1 + 4 + 2 + 1 + 8 + 64 || &bytes[..4] != Self::MAGIC {
            return None;
        }
        let mut at = 4;
        let mut ed25519_pk = [0u8; 32];
        ed25519_pk.copy_from_slice(&bytes[at..at + 32]);
        at += 32;

        let mut ml_kem_hash = [0u8; 16];
        ml_kem_hash.copy_from_slice(&bytes[at..at + 16]);
        at += 16;

        let ip_ver = bytes[at];
        at += 1;
        let ip = match ip_ver {
            4 => {
                let octets: [u8; 4] = bytes[at..at + 4].try_into().ok()?;
                at += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let octets: [u8; 16] = bytes[at..at + 16].try_into().ok()?;
                at += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };

        let port = u16::from_be_bytes(bytes[at..at + 2].try_into().ok()?);
        at += 2;
        let nat_type = bytes[at];
        at += 1;
        let timestamp = u64::from_be_bytes(bytes[at..at + 8].try_into().ok()?);
        at += 8;
        let signature: [u8; 64] = bytes[at..at + 64].try_into().ok()?;

        Some(Self {
            ed25519_pk,
            ml_kem_hash,
            endpoint: SocketAddr::new(ip, port),
            nat_type,
            timestamp,
            signature,
        })
    }

    /// Encode into a standard `vb://<hex>` URI for out-of-band manual exchange.
    pub fn to_uri(&self) -> String {
        format!("{}{}", VB_URI_PREFIX, hex::encode(self.to_bytes()))
    }

    /// Parse a `vb://<hex>` URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let trimmed = uri.trim();
        let payload = trimmed.strip_prefix(VB_URI_PREFIX)?;
        let bytes = hex::decode(payload).ok()?;
        Self::from_bytes(&bytes)
    }
}

/// Tier 1: Local authenticated peer disk cache (`peers.bin`).
pub struct LocalPeerCache;

impl LocalPeerCache {
    /// Save active peer descriptors to local disk cache.
    pub fn save<P: AsRef<Path>>(path: P, peers: &[PeerDescriptor]) -> std::io::Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"VBPCACHE1");
        buf.extend_from_slice(&(peers.len() as u32).to_be_bytes());
        for p in peers {
            let bytes = p.to_bytes();
            buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(&bytes);
        }
        std::fs::write(path, buf)
    }

    /// Load cached peer descriptors from local disk.
    pub fn load<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<PeerDescriptor>> {
        let raw = std::fs::read(path)?;
        if raw.len() < 13 || &raw[..9] != b"VBPCACHE1" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid peer cache header",
            ));
        }
        let count_slice: [u8; 4] = raw[9..13]
            .try_into()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let count = u32::from_be_bytes(count_slice) as usize;
        let mut at = 13;
        let mut peers = Vec::with_capacity(count);

        for _ in 0..count {
            if at + 2 > raw.len() {
                break;
            }
            let len_slice: [u8; 2] = raw[at..at + 2]
                .try_into()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let len = u16::from_be_bytes(len_slice) as usize;
            at += 2;
            if at + len > raw.len() {
                break;
            }
            if let Some(desc) = PeerDescriptor::from_bytes(&raw[at..at + len]) {
                if desc.verify(86400 * 30) {
                    peers.push(desc);
                }
            }
            at += len;
        }

        Ok(peers)
    }
}

/// Tier 3: Zero-knowledge blind rendezvous engine on Cloudflare Workers / BEP-44 DHT.
pub struct BlindRendezvous;

impl BlindRendezvous {
    /// Compute deterministic epoch slot key for a shared swarm secret and hourly time epoch.
    pub fn derive_epoch_key(swarm_secret: &[u8], epoch_hour: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"vb-rendezvous-v1"), swarm_secret);
        let mut okm = [0u8; 32];
        hk.expand(&epoch_hour.to_be_bytes(), &mut okm)
            .expect("32 bytes is valid length for HKDF-SHA256");
        okm
    }

    /// Compute deterministic blind slot ID for querying the public worker or DHT.
    pub fn derive_slot_id(epoch_key: &[u8; 32], slot_index: u32) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"vb-slot-v1"), epoch_key);
        let mut slot_id = [0u8; 32];
        hk.expand(&slot_index.to_be_bytes(), &mut slot_id)
            .expect("32 bytes is valid length");
        slot_id
    }

    /// Encrypt a peer descriptor into a blind high-entropy ciphertext payload.
    pub fn encrypt_descriptor(
        epoch_key: &[u8; 32],
        descriptor: &PeerDescriptor,
    ) -> Result<Vec<u8>, &'static str> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
        let nonce = Nonce::from_slice(b"VB_BLND_NO_1"); // 12-byte static epoch nonce
        let plain = descriptor.to_bytes();
        cipher
            .encrypt(nonce, plain.as_ref())
            .map_err(|_| "ChaCha20Poly1305 blind encryption failed")
    }

    /// Decrypt a blind rendezvous payload retrieved from a worker or DHT.
    pub fn decrypt_descriptor(epoch_key: &[u8; 32], ciphertext: &[u8]) -> Option<PeerDescriptor> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key));
        let nonce = Nonce::from_slice(b"VB_BLND_NO_1");
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        let desc = PeerDescriptor::from_bytes(&plain)?;
        if desc.verify(7200) {
            Some(desc)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_descriptor_roundtrip_and_uri() {
        let id = GhostIdentity::generate_fresh();
        let kem_pk = [0x55u8; 1184];
        let endpoint = SocketAddr::from(([198, 51, 100, 14], 4433));
        let desc = PeerDescriptor::sign_new(&id, &kem_pk, endpoint, NAT_CONE);

        assert!(desc.verify(60));

        let uri = desc.to_uri();
        assert!(uri.starts_with(VB_URI_PREFIX));

        let parsed = PeerDescriptor::from_uri(&uri).expect("failed to parse URI");
        assert_eq!(desc, parsed);
        assert!(parsed.verify(60));
    }

    #[test]
    fn test_blind_rendezvous_encryption() {
        let id = GhostIdentity::generate_fresh();
        let kem_pk = [0x22u8; 1184];
        let endpoint = SocketAddr::from(([203, 0, 113, 8], 8080));
        let desc = PeerDescriptor::sign_new(&id, &kem_pk, endpoint, NAT_DIRECT);

        let swarm_secret = b"my-private-mesh-secret-key-12345";
        let epoch_hour = 1714658400; // Sample Unix epoch hour
        let epoch_key = BlindRendezvous::derive_epoch_key(swarm_secret, epoch_hour);
        let slot_id = BlindRendezvous::derive_slot_id(&epoch_key, 0);

        assert_ne!(slot_id, [0u8; 32]);

        let encrypted =
            BlindRendezvous::encrypt_descriptor(&epoch_key, &desc).expect("encrypt failed");
        // Cloudflare sees only random bytes:
        assert_ne!(&encrypted[..4], PeerDescriptor::MAGIC);

        let decrypted =
            BlindRendezvous::decrypt_descriptor(&epoch_key, &encrypted).expect("decrypt failed");
        assert_eq!(desc, decrypted);
    }
}
