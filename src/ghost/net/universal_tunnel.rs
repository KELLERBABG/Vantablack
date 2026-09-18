//! Invention §37: Universal Shard-Tunnel (Generic Port Forwarder)
//!
//! Carries arbitrary legacy protocols (RDP, RTSP, gRPC, SMTP, SOCKS5, HTTP) blind
//! over the Post-Quantum Reed-Solomon GTF mesh.
//!
//! Unmodified applications connect to a local port (e.g. 127.0.0.1:local_port);
//! the Universal Shard-Tunnel slices the stream into sequenced, bounded chunks,
//! pads them to standard 576-byte GTF privacy frames, and routes them across
//! the full anonymity stack. At the exit side, the reassembler reconstitutes
//! the byte stream and proxies it to the remote service.

use std::collections::BTreeMap;
use std::net::SocketAddr;

/// Flag bits for Universal Shard-Tunnel frame headers.
pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_DATA: u8 = 0x08;

/// Privacy frame payload maximum size for tunnel chunks (fitting within 576B GTF).
pub const MAX_TUNNEL_PAYLOAD_CHUNK: usize = 512;

/// Protocol transported by the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelProtocol {
    Tcp,
    Udp,
}

/// Header for sequenced tunnel frames.
/// Layout: [stream_id:4][seq_num:4][flags:1][payload_len:2] = 11 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrameHeader {
    pub stream_id: u32,
    pub seq_num: u32,
    pub flags: u8,
    pub payload_len: u16,
}

impl TunnelFrameHeader {
    pub const HEADER_LEN: usize = 11;

    pub fn to_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8] = self.flags;
        buf[9..11].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    pub fn from_bytes(slice: &[u8]) -> Option<Self> {
        if slice.len() < Self::HEADER_LEN {
            return None;
        }
        let stream_id = u32::from_be_bytes(slice[0..4].try_into().ok()?);
        let seq_num = u32::from_be_bytes(slice[4..8].try_into().ok()?);
        let flags = slice[8];
        let payload_len = u16::from_be_bytes(slice[9..11].try_into().ok()?);
        Some(Self {
            stream_id,
            seq_num,
            flags,
            payload_len,
        })
    }
}

/// Chunks arbitrary application byte streams into 576-byte GTF privacy frames.
#[derive(Debug, Clone)]
pub struct UniversalTunnelChunker {
    pub stream_id: u32,
    next_seq_num: u32,
}

impl UniversalTunnelChunker {
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            next_seq_num: 0,
        }
    }

    /// Slices an application byte buffer into sequenced, constant-size GTF tunnel frames.
    pub fn chunk_payload(&mut self, payload: &[u8], is_final: bool) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let chunks: Vec<&[u8]> = payload.chunks(MAX_TUNNEL_PAYLOAD_CHUNK).collect();

        if chunks.is_empty() {
            // Empty payload (e.g. bare FIN)
            let flags = if is_final { FLAG_FIN } else { FLAG_ACK };
            let hdr = TunnelFrameHeader {
                stream_id: self.stream_id,
                seq_num: self.next_seq_num,
                flags,
                payload_len: 0,
            };
            self.next_seq_num += 1;
            let mut frame = Vec::with_capacity(576);
            frame.extend_from_slice(&hdr.to_bytes());
            frame.resize(576, 0); // Constant privacy frame padding
            frames.push(frame);
            return frames;
        }

        for (i, &chunk) in chunks.iter().enumerate() {
            let is_last_chunk = i == chunks.len() - 1;
            let mut flags = FLAG_DATA;
            if is_last_chunk && is_final {
                flags |= FLAG_FIN;
            }

            let hdr = TunnelFrameHeader {
                stream_id: self.stream_id,
                seq_num: self.next_seq_num,
                flags,
                payload_len: chunk.len() as u16,
            };
            self.next_seq_num += 1;

            let mut frame = Vec::with_capacity(576);
            frame.extend_from_slice(&hdr.to_bytes());
            frame.extend_from_slice(chunk);
            frame.resize(576, 0); // Fixed 576B privacy padding
            frames.push(frame);
        }

        frames
    }

    /// Parses a received 576-byte GTF tunnel frame back into header and payload.
    pub fn parse_frame(frame: &[u8]) -> Option<(TunnelFrameHeader, Vec<u8>)> {
        let hdr = TunnelFrameHeader::from_bytes(frame)?;
        let start = TunnelFrameHeader::HEADER_LEN;
        let end = start + (hdr.payload_len as usize);
        if frame.len() < end {
            return None;
        }
        let payload = frame[start..end].to_vec();
        Some((hdr, payload))
    }
}

/// Reassembles sequenced, out-of-order tunnel frames for a stream.
#[derive(Debug, Default)]
pub struct UniversalTunnelReassembler {
    /// Buffered received chunks keyed by sequence number.
    buffered: BTreeMap<u32, (TunnelFrameHeader, Vec<u8>)>,
    expected_seq: u32,
    pub is_finished: bool,
}

impl UniversalTunnelReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests a frame, handling out-of-order delivery.
    /// Returns any contiguous in-order payload bytes ready for forwarding to the target application.
    pub fn ingest_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (hdr, payload) =
            UniversalTunnelChunker::parse_frame(frame).ok_or("malformed universal tunnel frame")?;

        if hdr.seq_num < self.expected_seq {
            // Duplicate/stale frame
            return Ok(Vec::new());
        }

        self.buffered.insert(hdr.seq_num, (hdr, payload));

        let mut contiguous = Vec::new();
        while let Some((hdr, data)) = self.buffered.remove(&self.expected_seq) {
            contiguous.extend_from_slice(&data);
            if (hdr.flags & FLAG_FIN) != 0 {
                self.is_finished = true;
            }
            self.expected_seq += 1;
        }

        Ok(contiguous)
    }

    pub fn expected_seq_num(&self) -> u32 {
        self.expected_seq
    }
}

/// Universal Shard-Tunnel Configuration.
#[derive(Debug, Clone)]
pub struct UniversalTunnelConfig {
    pub local_listen_addr: SocketAddr,
    pub remote_target_addr: SocketAddr,
    pub protocol: TunnelProtocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_frame_header_serialization() {
        let hdr = TunnelFrameHeader {
            stream_id: 1001,
            seq_num: 42,
            flags: FLAG_SYN | FLAG_DATA,
            payload_len: 256,
        };
        let bytes = hdr.to_bytes();
        let parsed = TunnelFrameHeader::from_bytes(&bytes).expect("parse header");
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_universal_shard_tunnel_chunking_and_reassembly() {
        let mut chunker = UniversalTunnelChunker::new(777);
        // Arbitrary payload (e.g. gRPC or RDP binary stream) exceeding 1 chunk
        let mut original_payload = Vec::new();
        for i in 0..1200 {
            original_payload.push((i % 256) as u8);
        }

        let frames = chunker.chunk_payload(&original_payload, true);
        assert_eq!(
            frames.len(),
            3,
            "1200 bytes with 512B max chunk -> 3 frames"
        );
        for f in &frames {
            assert_eq!(f.len(), 576, "Every tunnel frame must be exactly 576 bytes");
        }

        // Simulate out-of-order arrival: deliver frame 1, frame 0, then frame 2
        let mut reassembler = UniversalTunnelReassembler::new();

        // Deliver frame 1 (out of order) -> no contiguous bytes yielded yet
        let out1 = reassembler.ingest_frame(&frames[1]).expect("ingest");
        assert!(out1.is_empty());
        assert!(!reassembler.is_finished);

        // Deliver frame 0 -> yields frame 0 + frame 1 contiguous bytes!
        let out0 = reassembler.ingest_frame(&frames[0]).expect("ingest");
        assert_eq!(out0.len(), 512 + 512);
        assert!(!reassembler.is_finished);

        // Deliver frame 2 (with FIN) -> yields final bytes and sets is_finished
        let out2 = reassembler.ingest_frame(&frames[2]).expect("ingest");
        assert_eq!(out2.len(), 1200 - 1024);
        assert!(reassembler.is_finished);

        // Verify assembled byte integrity
        let mut full_assembled = Vec::new();
        full_assembled.extend_from_slice(&out0);
        full_assembled.extend_from_slice(&out2);
        assert_eq!(full_assembled, original_payload);
    }
}
