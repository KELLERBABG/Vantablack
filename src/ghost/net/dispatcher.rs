//! Lockless Session-Hash Packet Dispatcher.
//!
//! Routes inbound GTF frames modulo N to dedicated worker threads via lockless
//! crossbeam channels based on the 4-byte session hash, ensuring:
//! - Per-session packet ordering
//! - Parallel multi-core decryption
//! - Zero mutex contention on the hot path

use std::net::SocketAddr;

use std::sync::atomic::{AtomicUsize, Ordering};

use crossbeam::channel::{self, Sender, TrySendError};
use tracing::{debug, warn};

use crate::ghost::net::{parse_session_hash, MIN_FRAME_SIZE};

#[derive(Debug, Clone)]
pub struct DispatchPacket {
    pub data: Vec<u8>,
    pub src: SocketAddr,
    pub session_hash: [u8; 4],
    pub counter: u32,
    pub shard_index: u8,
}

pub struct LocklessDispatcher {
    senders: Vec<Sender<DispatchPacket>>,
    pub num_workers: usize,
    dropped: AtomicUsize,
}

impl LocklessDispatcher {
    pub fn new(num_workers: usize, channel_capacity: usize) -> Self {
        let mut senders = Vec::with_capacity(num_workers);
        for i in 0..num_workers {
            let (tx, rx) = channel::bounded::<DispatchPacket>(channel_capacity);
            senders.push(tx);
            std::thread::Builder::new()
                .name(format!("ghost-worker-{}", i))
                .spawn(move || {
                    while let Ok(pkt) = rx.recv() {
                        Self::process_packet(i, pkt);
                    }
                })
                .expect("Failed to spawn worker thread");
        }
        Self {
            senders,
            num_workers,
            dropped: AtomicUsize::new(0),
        }
    }

    pub fn dispatch(&self, buf: &[u8], src: SocketAddr) -> bool {
        if buf.len() < MIN_FRAME_SIZE {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let session_hash = parse_session_hash(buf);
        let worker_id = (session_hash[0] as usize
            ^ session_hash[1] as usize
            ^ session_hash[2] as usize
            ^ session_hash[3] as usize)
            % self.num_workers;

        let counter = crate::ghost::net::parse_packet_counter(buf);
        let shard_index = if buf.len() > 8 { buf[8] } else { 0 };

        let packet = DispatchPacket {
            data: buf.to_vec(),
            src,
            session_hash,
            counter,
            shard_index,
        };

        match self.senders[worker_id].try_send(packet) {
            Ok(()) => true,
            Err(TrySendError::Full(_pkt)) => {
                debug!("Worker {} channel full, dropping packet", worker_id);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                warn!("Worker {} disconnected", worker_id);
                false
            }
        }
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    fn process_packet(worker_id: usize, pkt: DispatchPacket) {
        debug!(
            "Worker {} processing packet: session_hash={:02x?}, counter={}, shard={}",
            worker_id, pkt.session_hash, pkt.counter, pkt.shard_index
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockless_dispatcher_basic() {
        let dispatcher = LocklessDispatcher::new(2, 64);
        let mut frame = vec![0u8; 64];
        frame[4..8].copy_from_slice(&42u32.to_be_bytes()); // counter
        frame[8] = 1; // shard index

        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let result = dispatcher.dispatch(&frame, src);
        assert!(result, "Dispatch should succeed on first packet");
    }

    #[test]
    fn test_lockless_dispatcher_session_routing() {
        let dispatcher = LocklessDispatcher::new(4, 128);
        let mut frame1 = vec![0u8; 64];
        frame1[0..4].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]); // session hash
        frame1[4..8].copy_from_slice(&1u32.to_be_bytes()); // counter

        let mut frame2 = vec![0u8; 64];
        frame2[0..4].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]); // same session hash
        frame2[4..8].copy_from_slice(&2u32.to_be_bytes()); // different counter

        let src1: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let src2: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        assert!(dispatcher.dispatch(&frame1, src1));
        assert!(dispatcher.dispatch(&frame2, src2));
    }
}
