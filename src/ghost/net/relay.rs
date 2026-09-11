/// Multi-hop Encrypted Packet Forwarding
///
/// Implements onion-style encrypted relay through intermediate GhostNet nodes.
/// When node A wants to send to node C through node B:
///   1. A encrypts the payload with session key A↔B (outer layer)
///   2. A encrypts the inner payload with session key B↔C (inner layer)
///   3. A sends to B with a RELAY header indicating the final destination
///   4. B decrypts the outer layer, finds the RELAY header, re-encrypts with
///      its own session key and forwards to C
///   5. C decrypts the inner payload
///
/// This avoids exposing plaintext at intermediate hops since each hop only
/// strips its own encryption layer, while the end-to-end encryption is preserved.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::ghost::layers::l2_aead::encrypt_in_place;
use crate::ghost::layers::l4_rs;
use crate::ghost::net::send_gtf;
use crate::ghost::net::frame_shard;
use crate::ghost::session::Session;

/// Magic prefix for relay packets — distinguishes relay from direct data.
pub const RELAY_MAGIC: &[u8; 4] = b"RLY!";

/// Maximum number of hops in a relay path.
pub const MAX_HOPS: usize = 5;

/// Maximum time (seconds) a bundle is held in store-and-forward before expiry.
pub const BUNDLE_EXPIRY_SECS: u64 = 3600; // 1 hour

/// A relay header prepended to the encrypted payload.
///
/// Wire format (inside the outer encryption layer):
///   [0..4]   RELAY_MAGIC ("RLY!")
///   [4..8]   Number of remaining hops (u32 BE)
///   [8..40]  Next hop fingerprint (hex string, 32 bytes, null-padded)
///   [40..]   Inner encrypted payload
#[derive(Debug, Clone)]
pub struct RelayHeader {
    pub remaining_hops: u32,
    pub next_hop_fingerprint: String,
    pub inner_payload: Vec<u8>,
}

/// Parse a relay header from decrypted bytes.
pub fn parse_relay_header(data: &[u8]) -> Option<RelayHeader> {
    if data.len() < 44 || &data[..4] != RELAY_MAGIC {
        return None;
    }
    let remaining = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let fp_bytes = &data[8..40];
    let fp_end = fp_bytes.iter().position(|&b| b == 0).unwrap_or(32);
    let fingerprint = String::from_utf8_lossy(&fp_bytes[..fp_end]).to_string();
    let inner = data[40..].to_vec();
    Some(RelayHeader {
        remaining_hops: remaining,
        next_hop_fingerprint: fingerprint,
        inner_payload: inner,
    })
}

/// Build a relay header + inner payload.
pub fn build_relay_packet(
    next_hop_fingerprint: &str,
    remaining_hops: u32,
    inner_payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + inner_payload.len());
    buf.extend_from_slice(RELAY_MAGIC);
    buf.extend_from_slice(&remaining_hops.to_be_bytes());
    let mut fp_bytes = [0u8; 32];
    let fp = next_hop_fingerprint.as_bytes();
    let copy_len = fp.len().min(32);
    fp_bytes[..copy_len].copy_from_slice(&fp[..copy_len]);
    buf.extend_from_slice(&fp_bytes);
    buf.extend_from_slice(inner_payload);
    buf
}

/// A pending bundle in the store-and-forward queue.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Target peer fingerprint.
    pub target_fingerprint: String,
    /// Encrypted payload (already in GTF frame-ready form, RS-encoded shard data).
    pub encrypted_shards: Vec<Vec<u8>>,
    /// Session hash for the next hop.
    pub session_hash: [u8; 4],
    /// Bundle creation time.
    pub created_at: Instant,
    /// Number of retries.
    pub retries: u8,
    /// The full relay chain (fingerprints) that this bundle still needs to traverse.
    pub remaining_route: Vec<String>,
}

/// Store-and-Forward Bundle Buffer
///
/// Holds encrypted shards until a line-of-sight contact window opens
/// for the next hop. Bundles are expired after BUNDLE_EXPIRY_SECS.
pub struct BundleBuffer {
    /// Bundles keyed by next-hop fingerprint.
    pub bundles: DashMap<String, Vec<Bundle>>,
    /// Whether the bundle buffer is active.
    pub running: AtomicBool,
}

impl Default for BundleBuffer {
    fn default() -> Self {
        Self {
            bundles: DashMap::new(),
            running: AtomicBool::new(true),
        }
    }
}

impl BundleBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a bundle for deferred delivery.
    pub fn enqueue(&self, bundle: Bundle) {
        let fp = bundle.target_fingerprint.clone();
        self.bundles
            .entry(fp.clone())
            .or_default()
            .push(bundle);
        debug!(
            "Bundle enqueued for {}, buffer size: {}",
            fp,
            self.bundles.len()
        );
    }

    /// Dequeue all pending bundles for a given peer fingerprint.
    pub fn dequeue_for(&self, peer_fp: &str) -> Vec<Bundle> {
        self.bundles
            .remove(peer_fp)
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    /// Expire old bundles.
    pub fn expire_old(&self) -> usize {
        let mut expired = 0usize;
        let cutoff = Duration::from_secs(BUNDLE_EXPIRY_SECS);
        self.bundles.retain(|_, bundles| {
            bundles.retain(|b| {
                let keep = b.created_at.elapsed() < cutoff;
                if !keep {
                    expired += 1;
                }
                keep
            });
            !bundles.is_empty()
        });
        expired
    }

    /// Check if there are any bundles for a given peer.
    pub fn has_pending(&self, peer_fp: &str) -> bool {
        self.bundles
            .get(peer_fp)
            .map(|b| !b.is_empty())
            .unwrap_or(false)
    }
}

/// Attempt to forward a relay packet one hop.
///
/// Returns true if the packet was successfully forwarded.
pub async fn try_forward_relay(
    socket: &UdpSocket,
    sessions: &DashMap<String, Session>,
    peer_addrs: &DashMap<String, SocketAddr>,
    relay_payload: &[u8],    // decrypted outer layer = relay header + inner encrypted
    bundle_buffer: &BundleBuffer,
) -> bool {
    let header = match parse_relay_header(relay_payload) {
        Some(h) => h,
        None => {
            warn!("Invalid relay header, dropping");
            return false;
        }
    };

    if header.remaining_hops == 0 {
        warn!("Relay packet with 0 remaining hops, dropping");
        return false;
    }

    let next_fp = &header.next_hop_fingerprint;
    let next_addr = match peer_addrs.get(next_fp) {
        Some(e) => *e.value(),
        None => {
            // No route to next hop — buffer for later
            debug!(
                "No address for next hop {}, buffering bundle",
                next_fp
            );
            let bundle = Bundle {
                target_fingerprint: next_fp.clone(),
                encrypted_shards: vec![header.inner_payload.clone()],
                session_hash: [0u8; 4],
                created_at: Instant::now(),
                retries: 0,
                remaining_route: vec![],
            };
            bundle_buffer.enqueue(bundle);
            return false;
        }
    };

    // Get the session to the next hop for re-encryption
    let session_entry = match sessions.get(next_fp) {
        Some(s) => s,
        None => {
            warn!("No session for next hop {}", next_fp);
            return false;
        }
    };

    let key = session_entry.master_key;
    let sh = session_entry.session_hash;
    let ctr = session_entry.next_tx_counter();
    let use_bulk = session_entry.use_bulk;
    drop(session_entry);

    // The inner payload is the remaining relay chain.
    // We decrement remaining_hops and re-encrypt for the next hop.
    let new_remaining = header.remaining_hops - 1;

    let inner_relay = if new_remaining > 0 {
        // Still more hops — wrap inner payload in another relay header
        // The inner payload already contains the next relay header from the original sender
        // We just forward it as-is since only the final destination can decrypt it
        header.inner_payload.clone()
    } else {
        // This is the final hop — inner payload is the end-to-end ciphertext
        // Mark with magic so the receiver knows it's direct
        let mut direct = Vec::with_capacity(4 + header.inner_payload.len());
        direct.extend_from_slice(b"DIR!");
        direct.extend_from_slice(&header.inner_payload);
        direct
    };

    // Re-encrypt inner payload with next-hop session key
    let mut framed = inner_relay;
    let needs_padding = if framed.len() % 2 != 0 { 1 } else { 0 };
    if needs_padding > 0 {
        framed.push(0);
    }
    encrypt_in_place(&key, ctr, &mut framed);

    // RS-encode the encrypted payload
    let tag = if framed.len() >= 16 {
        let mut t = [0u8; 16];
        t.copy_from_slice(&framed[framed.len() - 16..]);
        t
    } else {
        [0u8; 16]
    };
    let shards = l4_rs::encode(&mut framed);

        // Send shards to next hop
        for i in 0..3 {
            let shard_data = frame_shard(&shards[i]);
        if let Err(e) = send_gtf(
            socket,
            &next_addr,
            sh,
            ctr,
            i as u8,
            &shard_data,
            &tag,
            use_bulk,
        )
        .await
        {
            debug!("Relay send error to {}: {}", next_fp, e);
            return false;
        }
    }

    info!(
        "Relayed packet {} hop(s) remaining via {}",
        new_remaining, next_fp
    );
    true
}

/// Spawn the store-and-forward background task.
///
/// Periodically checks for pending bundles and attempts delivery
/// when a session becomes available.
pub fn spawn_store_forward_task(
    socket: Arc<UdpSocket>,
    sessions: Arc<DashMap<String, Session>>,
    peer_addrs: Arc<DashMap<String, SocketAddr>>,
    bundle_buffer: Arc<BundleBuffer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let check_interval = Duration::from_secs(15);
        loop {
            sleep(check_interval).await;

            // Expire old bundles
            let expired = bundle_buffer.expire_old();
            if expired > 0 {
                debug!("Expired {} stale bundles", expired);
            }

            // Collect all peer fingerprints that have pending bundles
            let pending_peers: Vec<String> = bundle_buffer
                .bundles
                .iter()
                .map(|e| e.key().clone())
                .collect();

            for fp in pending_peers {
                // Only attempt delivery if we have a session and address for this peer
                let has_route = sessions.contains_key(&fp) && peer_addrs.contains_key(&fp);
                if has_route {
                    let bundles = bundle_buffer.dequeue_for(&fp);
                    for bundle in bundles {
                        // Re-attempt forwarding
                        let relay_header = build_relay_packet(
                            &fp,
                            1, // one hop remaining — direct delivery
                            &bundle.encrypted_shards[0],
                        );
                        let _ = try_forward_relay(
                            &socket,
                            &sessions,
                            &peer_addrs,
                            &relay_header,
                            &bundle_buffer,
                        )
                        .await;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_header_roundtrip() {
        let inner = b"HELLO_RELAY_WORLD".to_vec();
        let fp = "abcdef1234567890".to_string();
        let data = build_relay_packet(&fp, 2, &inner);
        let parsed = parse_relay_header(&data).unwrap();
        assert_eq!(parsed.remaining_hops, 2);
        assert_eq!(parsed.next_hop_fingerprint, fp);
        assert_eq!(parsed.inner_payload, inner);
    }

    #[test]
    fn test_relay_header_bad_magic() {
        let data = b"BAD!......".to_vec();
        assert!(parse_relay_header(&data).is_none());
    }

    #[test]
    fn test_bundle_expiry() {
        let bb = BundleBuffer::new();
        let b = Bundle {
            target_fingerprint: "test".into(),
            encrypted_shards: vec![vec![1, 2, 3]],
            session_hash: [0; 4],
            created_at: Instant::now() - Duration::from_secs(BUNDLE_EXPIRY_SECS + 10),
            retries: 0,
            remaining_route: vec![],
        };
        bb.enqueue(b);
        assert_eq!(bb.expire_old(), 1);
        assert!(!bb.has_pending("test"));
    }

    #[test]
    fn test_bundle_pending() {
        let bb = BundleBuffer::new();
        let b = Bundle {
            target_fingerprint: "peer1".into(),
            encrypted_shards: vec![vec![4, 5, 6]],
            session_hash: [0; 4],
            created_at: Instant::now(),
            retries: 0,
            remaining_route: vec![],
        };
        bb.enqueue(b);
        assert!(bb.has_pending("peer1"));
        let bundles = bb.dequeue_for("peer1");
        assert_eq!(bundles.len(), 1);
        assert!(!bb.has_pending("peer1"));
    }
}