use num_complex::Complex64;
use serde::{Deserialize, Serialize};

/// Unique node identifier: hash of the node's public key
pub type NodeId = [u8; 32];

/// A shard is a redundant fragment of a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    pub file_id: [u8; 32],
    pub shard_index: u32,
    pub total_shards: u32,
    pub data: Vec<u8>,
    pub checksum: u32,
}

/// A DTN bundle encapsulates shards for store-and-forward transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_id: [u8; 32],
    pub source_node: NodeId,
    pub creation_timestamp: u64,
    pub lifetime_seconds: u64,
    pub payload: Vec<u8>,
    pub hop_count: u32,
    pub ttl: u32,
}

pub type FrequencyHz = u64;
pub type SampleRate = f64;

/// Modulation and Coding Scheme index
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MCS {
    Bpsk12,
    Qpsk12,
    Qpsk34,
    Qam1612,
    Qam1634,
    Qam6434,
}

impl MCS {
    pub fn bits_per_symbol(&self) -> f64 {
        match self {
            MCS::Bpsk12 => 0.5,
            MCS::Qpsk12 => 1.0,
            MCS::Qpsk34 => 1.5,
            MCS::Qam1612 => 2.0,
            MCS::Qam1634 => 3.0,
            MCS::Qam6434 => 4.5,
        }
    }
}

/// A burst packet ready for PHY transmission
#[derive(Debug, Clone)]
pub struct BurstPacket {
    pub preamble: Vec<Complex64>,
    pub sync_word: Vec<Complex64>,
    pub header: BurstHeader,
    pub payload: Vec<Complex64>,
}

#[derive(Debug, Clone)]
pub struct BurstHeader {
    pub mcs: MCS,
    pub shard_id: [u8; 32],
    pub length_bytes: u32,
    pub crc: u32,
}

/// I/Q sample buffer wrapper for zero-copy sharing
#[derive(Debug, Clone)]
pub struct IQBuffer {
    pub samples: Vec<Complex64>,
    pub sample_rate: SampleRate,
    pub center_frequency: FrequencyHz,
    pub timestamp: u64,
}

/// SDR hardware configuration
#[derive(Debug, Clone)]
pub struct SDRConfig {
    pub center_frequency: FrequencyHz,
    pub sample_rate: SampleRate,
    pub gain: f64,
    pub bandwidth: f64,
    pub antenna_port: u8,
}
