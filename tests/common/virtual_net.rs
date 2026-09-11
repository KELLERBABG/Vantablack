/// Virtual Network — Deterministic In-Memory Transport for GhostNet Testing
///
/// Replaces UDP sockets with channel-based message passing, so tests
/// can run without real networking, in parallel, with full control over
/// packet ordering, latency, and loss.
///
/// ## Architecture
/// A `VirtualNetHub` holds a set of `VirtualNode` instances, each with:
/// - A mpsc Receiver (incoming GTF packets)
/// - A "local address" string (e.g. "virt://node_a:1")
/// - A mapped GhostNode for protocol logic
///
/// When a node sends a GTF packet via `virtual_send_to`, the hub routes
/// it to the target node's receiver channel, preserving all GTF headers.
///
/// Loss simulation: the hub can be configured with a drop probability
/// (0.0 = no loss, 1.0 = all packets dropped).

use vantablack::ghost::net::{OFFSET_PAYLOAD_START, OFFSET_AUTH_TAG_START};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Maximum channel buffer per node (enough for test traffic without backpressure).
pub const VIRTUAL_CHANNEL_SIZE: usize = 1024;

/// A raw GTF packet captured from the virtual wire.
#[derive(Debug, Clone)]
pub struct VirtualPacket {
    /// The raw 512+ byte GTF frame (as would be sent over UDP).
    pub data: Vec<u8>,
    /// The virtual source address (sender).
    pub src: String,
    /// The virtual destination address (receiver).
    pub dst: String,
}

/// A virtual node endpoint: holds the receiver for incoming packets.
pub struct VirtualEndpoint {
    pub addr: String,
    pub rx: mpsc::Receiver<VirtualPacket>,
}

impl VirtualEndpoint {
    pub fn new(addr: String) -> (Self, mpsc::Sender<VirtualPacket>) {
        let (tx, rx) = mpsc::channel(VIRTUAL_CHANNEL_SIZE);
        (Self { addr, rx }, tx)
    }
}

/// The central hub: routes packets between virtual nodes with optional loss/latency.
pub struct VirtualNetHub {
    /// Map: address string → sender channel for that node.
    nodes: HashMap<String, mpsc::Sender<VirtualPacket>>,
    /// Packet drop probability [0.0, 1.0].
    pub drop_probability: f64,
    /// Counters
    pub packets_sent: u64,
    pub packets_dropped: u64,
    pub packets_delivered: u64,
}

impl VirtualNetHub {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            drop_probability: 0.0,
            packets_sent: 0,
            packets_dropped: 0,
            packets_delivered: 0,
        }
    }

    /// Register a virtual node by its address string.
    /// Returns the Sender that should be used by the hub to deliver to this node.
    pub fn register(&mut self, addr: &str, tx: mpsc::Sender<VirtualPacket>) {
        self.nodes.insert(addr.to_string(), tx);
    }

    /// Route a GTF packet from `src` to `dst`.
    /// Returns `true` if delivered, `false` if dropped or destination unknown.
    pub fn route(&mut self, data: Vec<u8>, src: &str, dst: &str) -> bool {
        self.packets_sent += 1;

        // Simulate packet loss
        if self.drop_probability > 0.0 {
            let r: f64 = rand::random();
            if r < self.drop_probability {
                self.packets_dropped += 1;
                return false;
            }
        }

        if let Some(tx) = self.nodes.get(dst) {
            let packet = VirtualPacket {
                data,
                src: src.to_string(),
                dst: dst.to_string(),
            };
            // Try to send — if the channel is full, treat as lost
            match tx.try_send(packet) {
                Ok(()) => {
                    self.packets_delivered += 1;
                    true
                }
                Err(_) => {
                    self.packets_dropped += 1;
                    false
                }
            }
        } else {
            // Destination unknown = black hole
            self.packets_dropped += 1;
            false
        }
    }

    /// Check if a given address is registered.
    pub fn has_node(&self, addr: &str) -> bool {
        self.nodes.contains_key(addr)
    }
}

impl Default for VirtualNetHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the shard index from a GTF packet buffer.
pub fn parse_virtual_shard_index(buf: &[u8]) -> u8 {
    if buf.len() > 8 {
        buf[8]
    } else {
        0
    }
}

/// Parse the 4-byte packet counter from a GTF buffer.
pub fn parse_virtual_counter(buf: &[u8]) -> u32 {
    if buf.len() < 8 {
        return 0;
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(&buf[4..8]);
    u32::from_be_bytes(c)
}

/// Build a minimal GTF packet for test purposes.
/// This follows the same layout as `send_gtf_packet` in net/mod.rs.
/// Build a minimal GTF packet matching the production format (see vantablack.rs).
/// Layout: session_hash[4] | counter[4] | shard_index[1] | flags[1] | payload[486] | auth_tag[16]
pub fn build_test_gtf_packet(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    let base_size = 512usize;
    let mut packet = vec![0u8; base_size];

    // Session hash at offset 0 (4 bytes)
    packet[0..4].copy_from_slice(&session_hash);
    // Counter at offset 4 (4 bytes)
    packet[4..8].copy_from_slice(&counter.to_be_bytes());
    // Shard index at offset 8 (1 byte)
    packet[8] = shard_index;
    // Flags at offset 9 (1 byte) — privacy mode (0)
    packet[9] = 0;
    // Payload at offset 10 (OFFSET_PAYLOAD_START)
    let payload_max = 486; // OFFSET_AUTH_TAG_START - OFFSET_PAYLOAD_START
    let payload_end = OFFSET_PAYLOAD_START + payload.len().min(payload_max);
    packet[OFFSET_PAYLOAD_START..payload_end].copy_from_slice(&payload[..payload.len().min(payload_max)]);
    // Auth tag at offset 496 (OFFSET_AUTH_TAG_START)
    packet[OFFSET_AUTH_TAG_START..OFFSET_AUTH_TAG_START+16].copy_from_slice(auth_tag);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_virtual_net_basic_routing() {
        let mut hub = VirtualNetHub::new();

        // Create two endpoints
        let (ep_a, tx_a) = VirtualEndpoint::new("virt://alice:1".to_string());
        let (mut ep_b, tx_b) = VirtualEndpoint::new("virt://bob:1".to_string());

        hub.register("virt://alice:1", tx_a);
        hub.register("virt://bob:1", tx_b);

        // Send a packet
        let packet = build_test_gtf_packet(
            [1, 2, 3, 4],
            42,
            0,
            b"HELLO",
            &[0u8; 16],
        );

        let delivered = hub.route(packet.clone(), "virt://alice:1", "virt://bob:1");
        assert!(delivered, "Packet should be delivered");

        // Receive on Bob's side
        if let Some(incoming) = ep_b.rx.recv().await {
            assert_eq!(incoming.src, "virt://alice:1");
            assert_eq!(parse_virtual_counter(&incoming.data), 42);
            assert_eq!(parse_virtual_shard_index(&incoming.data), 0);
        } else {
            panic!("Expected a packet but got None");
        }
    }

    #[tokio::test]
    async fn test_virtual_net_packet_loss() {
        let mut hub = VirtualNetHub::new();
        hub.drop_probability = 1.0; // Drop everything

        let (ep_a, tx_a) = VirtualEndpoint::new("virt://alice:1".to_string());
        let (mut ep_b, tx_b) = VirtualEndpoint::new("virt://bob:1".to_string());

        hub.register("virt://alice:1", tx_a);
        hub.register("virt://bob:1", tx_b);

        let packet = build_test_gtf_packet([0; 4], 1, 0, b"LOST", &[0u8; 16]);
        let delivered = hub.route(packet, "virt://alice:1", "virt://bob:1");
        assert!(!delivered, "Packet should be dropped");
        assert_eq!(hub.packets_dropped, 1);

        // Bob should NOT receive anything
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            ep_b.rx.recv(),
        ).await;
        assert!(result.is_err(), "Bob should not receive a dropped packet");
    }
}