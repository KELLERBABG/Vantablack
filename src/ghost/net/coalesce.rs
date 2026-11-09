//! Ingress Stream Coalescing Queue and End-to-End RS(2,1) Dispatcher.
//!
//! Gathers outbound stream and packet chunks into optimal 984-byte batches
//! (split across two 492-byte data shards) to maximize Reed-Solomon throughput
//! and defeat traffic analysis / packet-size side-channels.
//!
//! Features:
//! - 200 µs batch timeout window.
//! - `FLAG_IMMEDIATE` preemption: immediate flush without timer delay for
//!   TCP FIN/RST, DNS queries, or real-time interactive UDP packets.
//! - Zero-allocation in-place parity generation via `l4_rs::encode_parity_slice`.

use crate::ghost::layers::l4_rs;
use std::time::{Duration, Instant};

/// Maximum payload capacity of one coding group (2 data shards x 492 bytes).
pub const COALESCE_TARGET_BYTES: usize = 984;

/// Capacity of a single Reed-Solomon data or parity shard.
pub const SHARD_PAYLOAD_BYTES: usize = 492;

/// Default coalescing flush delay (200 microseconds).
pub const DEFAULT_COALESCE_TIMEOUT: Duration = Duration::from_micros(200);

/// Flag indicating that this packet must bypass the coalescing timer and flush immediately.
pub const FLAG_IMMEDIATE: u8 = 0x01;

/// Flag indicating that the payload contains padding bytes up to shard boundary.
pub const FLAG_PADDED: u8 = 0x02;

/// A self-contained RS(2,1) shard ready for onion wrapping and wire framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalescedShard {
    /// Coding group sequence number.
    pub group_id: u64,
    /// Shard index: 0 = D0 (data low), 1 = D1 (data high), 2 = P0 (parity).
    pub shard_idx: u8,
    /// Control flags (e.g., FLAG_IMMEDIATE, FLAG_PADDED).
    pub flags: u8,
    /// Actual unpadded user payload bytes contained across D0 + D1.
    pub payload_len: u16,
    /// Fixed-size shard data buffer (492 bytes).
    pub data: [u8; SHARD_PAYLOAD_BYTES],
}

impl CoalescedShard {
    pub const HEADER_LEN: usize = 12; // group_id (8) + shard_idx (1) + flags (1) + payload_len (2)

    /// Serialize shard header and payload into a byte buffer.
    pub fn serialize_into(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let total = Self::HEADER_LEN + SHARD_PAYLOAD_BYTES;
        if buf.len() < total {
            return Err("buffer too short for coalesced shard");
        }
        buf[0..8].copy_from_slice(&self.group_id.to_be_bytes());
        buf[8] = self.shard_idx;
        buf[9] = self.flags;
        buf[10..12].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[12..total].copy_from_slice(&self.data);
        Ok(total)
    }

    /// Deserialize shard from wire slice.
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        let total = Self::HEADER_LEN + SHARD_PAYLOAD_BYTES;
        if buf.len() < total {
            return None;
        }
        let group_id = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let shard_idx = buf[8];
        let flags = buf[9];
        let payload_len = u16::from_be_bytes(buf[10..12].try_into().ok()?);
        let mut data = [0u8; SHARD_PAYLOAD_BYTES];
        data.copy_from_slice(&buf[12..total]);

        Some(Self {
            group_id,
            shard_idx,
            flags,
            payload_len,
            data,
        })
    }
}

/// Accumulating buffer for ingress streams before RS(2,1) encoding.
#[derive(Debug)]
pub struct CoalescingQueue {
    buffer: Vec<u8>,
    max_batch_size: usize,
    timeout: Duration,
    last_flush: Instant,
    next_group_id: u64,
}

impl Default for CoalescingQueue {
    fn default() -> Self {
        Self::new(COALESCE_TARGET_BYTES, DEFAULT_COALESCE_TIMEOUT)
    }
}

impl CoalescingQueue {
    /// Create a new coalescing queue with custom target size and flush timeout.
    pub fn new(max_batch_size: usize, timeout: Duration) -> Self {
        let cap = max_batch_size.min(COALESCE_TARGET_BYTES);
        Self {
            buffer: Vec::with_capacity(cap),
            max_batch_size: cap,
            timeout,
            last_flush: Instant::now(),
            next_group_id: 1,
        }
    }

    /// Current buffered byte count.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Ingest data into the queue.
    ///
    /// If `force_immediate` is set (e.g. TCP FIN/RST or real-time UDP), or if the
    /// buffered data reaches `max_batch_size`, flushes immediately and returns the
    /// generated 3-shard triplet [D0, D1, P0].
    pub fn push(&mut self, data: &[u8], force_immediate: bool) -> Vec<[CoalescedShard; 3]> {
        let mut results = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let space = self.max_batch_size.saturating_sub(self.buffer.len());
            let to_take = (data.len() - offset).min(space);
            self.buffer
                .extend_from_slice(&data[offset..offset + to_take]);
            offset += to_take;

            if self.buffer.len() >= self.max_batch_size {
                let flags = if force_immediate { FLAG_IMMEDIATE } else { 0 };
                results.push(self.flush_internal(flags));
            }
        }

        if force_immediate && !self.buffer.is_empty() {
            results.push(self.flush_internal(FLAG_IMMEDIATE));
        }

        results
    }

    /// Periodic tick to flush buffered data if the coalescing timeout has elapsed.
    pub fn tick(&mut self, now: Instant) -> Option<[CoalescedShard; 3]> {
        if self.buffer.is_empty() {
            self.last_flush = now;
            return None;
        }

        if now.duration_since(self.last_flush) >= self.timeout {
            Some(self.flush_internal(0))
        } else {
            None
        }
    }

    /// Manually flush whatever is in the buffer right now into a coding group.
    pub fn flush(&mut self, flags: u8) -> Option<[CoalescedShard; 3]> {
        if self.buffer.is_empty() {
            None
        } else {
            Some(self.flush_internal(flags))
        }
    }

    fn flush_internal(&mut self, mut flags: u8) -> [CoalescedShard; 3] {
        let payload_len = self.buffer.len() as u16;
        let mut d0 = [0u8; SHARD_PAYLOAD_BYTES];
        let mut d1 = [0u8; SHARD_PAYLOAD_BYTES];
        let mut p0 = [0u8; SHARD_PAYLOAD_BYTES];

        let half = SHARD_PAYLOAD_BYTES;
        let first_len = self.buffer.len().min(half);
        d0[..first_len].copy_from_slice(&self.buffer[..first_len]);

        if self.buffer.len() > half {
            let second_len = (self.buffer.len().saturating_sub(half)).min(half);
            let end = half.saturating_add(second_len).min(self.buffer.len());
            if let Some(slice) = self.buffer.get(half..end) {
                d1[..slice.len()].copy_from_slice(slice);
            }
        }

        if (payload_len as usize) < self.max_batch_size {
            flags |= FLAG_PADDED;
        }

        // Compute parity shard P0 in-place using SIMD RS(2,1)
        l4_rs::encode_parity_slice(&d0, &d1, &mut p0);

        let group_id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);
        if self.next_group_id == 0 {
            self.next_group_id = 1;
        }

        self.buffer.clear();
        self.last_flush = Instant::now();

        [
            CoalescedShard {
                group_id,
                shard_idx: 0,
                flags,
                payload_len,
                data: d0,
            },
            CoalescedShard {
                group_id,
                shard_idx: 1,
                flags,
                payload_len,
                data: d1,
            },
            CoalescedShard {
                group_id,
                shard_idx: 2,
                flags,
                payload_len,
                data: p0,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coalescing_immediate_flush() {
        let mut queue = CoalescingQueue::default();
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let groups = queue.push(payload, true);

        assert_eq!(groups.len(), 1);
        let [d0, d1, p0] = &groups[0];
        assert_eq!(d0.group_id, 1);
        assert_eq!(d0.shard_idx, 0);
        assert_eq!(d1.shard_idx, 1);
        assert_eq!(p0.shard_idx, 2);
        assert_eq!(d0.payload_len, payload.len() as u16);
        assert_eq!((d0.flags & FLAG_IMMEDIATE), FLAG_IMMEDIATE);
        assert_eq!((d0.flags & FLAG_PADDED), FLAG_PADDED);
        assert_eq!(&d0.data[..payload.len()], payload);
    }

    #[test]
    fn test_coalescing_exact_target_split() {
        let mut queue = CoalescingQueue::default();
        let payload = vec![0x5A; COALESCE_TARGET_BYTES];
        let groups = queue.push(&payload, false);

        assert_eq!(groups.len(), 1);
        let [d0, d1, _p0] = &groups[0];
        assert_eq!(d0.payload_len, 984);
        assert_eq!(d0.flags & FLAG_PADDED, 0);
        assert_eq!(&d0.data[..], &payload[..492]);
        assert_eq!(&d1.data[..], &payload[492..]);
    }
}
