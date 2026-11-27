//! GhostNet Network Layer.
//!
//! Implements the Ghost Transport Frame (GTF) wire format for UDP datagrams,
//! supporting constant-length privacy framing (576 B) and high-throughput bulk framing (1472 B).
//! Also implements the ACK reliability engine, adaptive token-bucket flow controller,
//! and mesh networking primitives.

pub mod adblock;
#[cfg(feature = "quic")]
pub mod carrier;
pub mod cc;

#[cfg(feature = "research")]
pub mod bandwidth_voucher;
#[cfg(feature = "research")]
pub mod braid_identity;
pub mod coalesce;
pub mod collective_defense;
pub mod consumer;
#[cfg(feature = "research")]
pub mod dead_drop;
pub mod diffusion;
pub mod discovery;
pub mod dispatcher;
pub mod dtn_reconcile;
pub mod egress;
#[cfg(feature = "research")]
pub mod energy_currency;
#[cfg(feature = "research")]
pub mod entropy_beacon;
pub mod fallback;
pub mod ice;
pub mod mesh;
#[cfg(feature = "research")]
pub mod mesh_archive;
#[cfg(feature = "research")]
pub mod metabolic;
#[cfg(feature = "research")]
pub mod model_gossip;
pub mod orbit;
#[cfg(feature = "research")]
pub mod polysemy;
pub mod pow;
#[cfg(feature = "quic")]
pub mod quic;
pub mod reassembly;
pub mod relay;
pub mod rendezvous;
pub mod sdr_bridge;
#[cfg(feature = "research")]
pub mod sharded_compute;
pub mod shardsec;
#[cfg(feature = "research")]
pub mod sheaf;
#[cfg(feature = "research")]
pub mod sovereign_cloud;
#[cfg(feature = "research")]
pub mod stego_physics;
pub mod threat_feed;
pub mod threat_shield;
pub mod universal_tunnel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierPath {
    Datagram,
    Stream,
}

#[cfg(not(feature = "quic"))]
pub mod carrier {
    use super::CarrierPath;
    use std::net::IpAddr;

    #[derive(Debug, Default)]
    pub struct Carrier;

    impl Carrier {
        pub fn disabled() -> Self {
            Carrier
        }
        pub fn enabled(&self) -> bool {
            false
        }
        pub fn peer_count(&self) -> usize {
            0
        }
        pub fn link_count(&self) -> usize {
            0
        }
        pub fn path_count(&self) -> usize {
            0
        }
        pub fn covered(&self, _fp: &str) -> bool {
            false
        }
        pub fn label(&self) -> &'static str {
            "none"
        }
        pub async fn send_frame(&self, _fp: &str, _frame: &[u8]) -> Option<CarrierPath> {
            None
        }
        pub async fn send_shards(&self, _fp: &str, _frames: &[Vec<u8>]) -> usize {
            0
        }
        pub async fn dial_paths(&self, _fp: &str, _addr: std::net::SocketAddr) -> usize {
            0
        }
        pub fn pin_commitment(&self, _fp: &str, _commitment: [u8; 32]) {}
        pub fn pinned_commitment(&self, _fp: &str) -> Option<[u8; 32]> {
            None
        }
        pub fn forget(&self, _fp: &str) {}
        pub fn forget_link(&self, _fp: &str, _local: IpAddr) {}
    }
}
pub mod routing;
pub mod security;
pub mod stun;
pub mod tun;
pub mod turn;
pub mod upnp;
#[cfg(feature = "vpn")]
pub mod vpn;

use bytes::Bytes;
use rand::Rng;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

pub static MIX_BATCH_DELAY_MS: AtomicU64 = AtomicU64::new(20);

pub static LOW_LATENCY_MODE: AtomicBool = AtomicBool::new(false);

pub static ZERO_ADMIN_MODE: AtomicBool = AtomicBool::new(false);

pub fn is_low_latency() -> bool {
    LOW_LATENCY_MODE.load(Ordering::Relaxed)
}

pub fn set_low_latency(enabled: bool) {
    LOW_LATENCY_MODE.store(enabled, Ordering::Relaxed);
    MIX_BATCH_DELAY_MS.store(if enabled { 1 } else { 20 }, Ordering::Relaxed);
}

pub fn mix_batch_delay_ms() -> u64 {
    MIX_BATCH_DELAY_MS.load(Ordering::Relaxed)
}

pub fn set_mix_batch_delay_ms(ms: u64) {
    let bounded = ms.clamp(1, 500);
    MIX_BATCH_DELAY_MS.store(bounded, Ordering::Relaxed);
    LOW_LATENCY_MODE.store(bounded <= 1, Ordering::Relaxed);
}

pub fn is_zero_admin() -> bool {
    ZERO_ADMIN_MODE.load(Ordering::Relaxed)
}

pub fn set_zero_admin(enabled: bool) {
    ZERO_ADMIN_MODE.store(enabled, Ordering::Relaxed);
}

pub const BEACON_MULTICAST_ADDR: &str = "239.255.0.1";
pub const BEACON_PORT: u16 = 2270;
pub const BEACON_INTERVAL_SECS: u64 = 30;
pub const BEACON_PREFIX: &[u8; 16] = b"GHOST_BEACON____";

pub fn poisson_beacon_gap(uniform_sample: f64, mean_interval_secs: f64) -> Duration {
    if !matches!(
        mean_interval_secs.partial_cmp(&0.0),
        Some(std::cmp::Ordering::Greater)
    ) {
        return Duration::from_secs(30);
    }
    let lambda = 1.0 / mean_interval_secs;
    let u = uniform_sample.clamp(0.0, 1.0 - f64::EPSILON);
    let secs = -(1.0 - u).ln() / lambda;
    let min_secs = 1.0f64;
    let max_secs = (mean_interval_secs * 3.0).max(10.0);
    Duration::from_secs_f64(secs.clamp(min_secs, max_secs))
}

pub const BEACON_GRID_MAGIC: &[u8; 4] = b"BGRD";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconGridEpoch {
    pub grid_epoch: u64,
    pub cycle_count: u32,
    pub entropy_commitment: [u8; 16],
}

impl BeaconGridEpoch {
    pub fn new(grid_epoch: u64, cycle_count: u32, entropy_commitment: [u8; 16]) -> Self {
        Self {
            grid_epoch,
            cycle_count,
            entropy_commitment,
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(BEACON_GRID_MAGIC);
        buf[4..12].copy_from_slice(&self.grid_epoch.to_be_bytes());
        buf[12..16].copy_from_slice(&self.cycle_count.to_be_bytes());
        buf[16..32].copy_from_slice(&self.entropy_commitment);
        buf
    }

    pub fn from_bytes(slice: &[u8]) -> Option<Self> {
        if slice.len() < 32 || &slice[0..4] != BEACON_GRID_MAGIC {
            return None;
        }
        let grid_epoch = u64::from_be_bytes(slice[4..12].try_into().ok()?);
        let cycle_count = u32::from_be_bytes(slice[12..16].try_into().ok()?);
        let mut entropy_commitment = [0u8; 16];
        entropy_commitment.copy_from_slice(&slice[16..32]);
        Some(Self {
            grid_epoch,
            cycle_count,
            entropy_commitment,
        })
    }

    pub fn reconcile(&mut self, remote: &BeaconGridEpoch) -> bool {
        if remote.grid_epoch > self.grid_epoch {
            self.grid_epoch = remote.grid_epoch;
            self.cycle_count = remote.cycle_count;
            self.entropy_commitment = remote.entropy_commitment;
            true
        } else if remote.grid_epoch == self.grid_epoch && remote.cycle_count > self.cycle_count {
            self.cycle_count = remote.cycle_count;
            true
        } else {
            false
        }
    }

    pub fn tick(&mut self, next_entropy_slice: &[u8]) {
        self.cycle_count = self.cycle_count.wrapping_add(1);
        if self.cycle_count >= 10 {
            self.grid_epoch = self.grid_epoch.wrapping_add(1);
            self.cycle_count = 0;
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.entropy_commitment);
        hasher.update(next_entropy_slice);
        let res = hasher.finalize();
        self.entropy_commitment.copy_from_slice(&res[..16]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CamouflageMode {
    None,
    QuicDatagram,
    DnsOverHttps,
    HttpsChunk,
}

pub struct CamouflageWrapper;

impl CamouflageWrapper {
    pub const DOH_PREFIX: &'static [u8] = b"/dns-query?dns=";
    pub const H3_DATAGRAM_FRAME_TYPE: u8 = 0x30;

    pub fn wrap(frame: &[u8], mode: CamouflageMode) -> Vec<u8> {
        match mode {
            CamouflageMode::None => frame.to_vec(),
            CamouflageMode::QuicDatagram => {
                let mut out = Vec::with_capacity(1 + 2 + frame.len());
                out.push(Self::H3_DATAGRAM_FRAME_TYPE);
                out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                out.extend_from_slice(frame);
                out
            }
            CamouflageMode::DnsOverHttps => {
                let mut out = Vec::from(Self::DOH_PREFIX);
                let encoded = hex::encode(frame);
                out.extend_from_slice(encoded.as_bytes());
                out
            }
            CamouflageMode::HttpsChunk => {
                let mut out = Vec::with_capacity(4 + frame.len());
                out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
                out.extend_from_slice(frame);
                out
            }
        }
    }

    pub fn unwrap(data: &[u8], mode: CamouflageMode) -> Option<Vec<u8>> {
        match mode {
            CamouflageMode::None => Some(data.to_vec()),
            CamouflageMode::QuicDatagram => {
                if data.len() < 3 || data[0] != Self::H3_DATAGRAM_FRAME_TYPE {
                    return None;
                }
                let len = u16::from_be_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + len {
                    return None;
                }
                Some(data[3..3 + len].to_vec())
            }
            CamouflageMode::DnsOverHttps => {
                let s = std::str::from_utf8(data).ok()?;
                let hex_part = s.strip_prefix("/dns-query?dns=")?;
                hex::decode(hex_part).ok()
            }
            CamouflageMode::HttpsChunk => {
                if data.len() < 4 {
                    return None;
                }
                let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if data.len() < 4 + len {
                    return None;
                }
                Some(data[4..4 + len].to_vec())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCensus {
    pub raw_udp_permitted: bool,
    pub quic_udp443_permitted: bool,
    pub doh_permitted: bool,
    pub https_tcp_permitted: bool,
}

impl Default for NetworkCensus {
    fn default() -> Self {
        Self {
            raw_udp_permitted: true,
            quic_udp443_permitted: true,
            doh_permitted: true,
            https_tcp_permitted: true,
        }
    }
}

impl NetworkCensus {
    pub fn probe() -> Self {
        let raw_blocked = std::env::var("GHOST_CENSUS_BLOCK_UDP")
            .map(|v| v == "1")
            .unwrap_or(false);
        let quic_blocked = std::env::var("GHOST_CENSUS_BLOCK_QUIC")
            .map(|v| v == "1")
            .unwrap_or(false);
        Self {
            raw_udp_permitted: !raw_blocked,
            quic_udp443_permitted: !quic_blocked && !raw_blocked,
            doh_permitted: true,
            https_tcp_permitted: true,
        }
    }

    pub fn ranked_dialects(&self) -> Vec<CamouflageMode> {
        let mut dialects = Vec::with_capacity(4);
        if self.raw_udp_permitted {
            dialects.push(CamouflageMode::None);
        }
        if self.quic_udp443_permitted {
            dialects.push(CamouflageMode::QuicDatagram);
        }
        if self.doh_permitted {
            dialects.push(CamouflageMode::DnsOverHttps);
        }
        if self.https_tcp_permitted {
            dialects.push(CamouflageMode::HttpsChunk);
        }
        if dialects.is_empty() {
            dialects.push(CamouflageMode::None);
        }
        dialects
    }
}

#[derive(Debug, Clone)]
pub struct DialectSession {
    pub active_dialect: CamouflageMode,
    pub supported_dialects: Vec<CamouflageMode>,
    pub messages_sent: u64,
    pub rotation_interval: u64,
}

impl DialectSession {
    pub fn new(
        initial_dialect: CamouflageMode,
        supported_dialects: Vec<CamouflageMode>,
        rotation_interval: u64,
    ) -> Self {
        Self {
            active_dialect: initial_dialect,
            supported_dialects: if supported_dialects.is_empty() {
                vec![initial_dialect]
            } else {
                supported_dialects
            },
            messages_sent: 0,
            rotation_interval: rotation_interval.max(1),
        }
    }

    pub fn negotiate(
        census: &NetworkCensus,
        peer_dialects: &[CamouflageMode],
        rotation_interval: u64,
    ) -> Self {
        let local_ranked = census.ranked_dialects();
        let selected = local_ranked
            .iter()
            .cloned()
            .find(|d| peer_dialects.contains(d))
            .unwrap_or(CamouflageMode::None);

        let mutual: Vec<CamouflageMode> = local_ranked
            .into_iter()
            .filter(|d| peer_dialects.contains(d))
            .collect();

        Self::new(selected, mutual, rotation_interval)
    }

    pub fn wrap_and_advance(&mut self, payload: &[u8]) -> (Vec<u8>, CamouflageMode) {
        let current = self.active_dialect;
        let wrapped = CamouflageWrapper::wrap(payload, current);
        self.messages_sent = self.messages_sent.saturating_add(1);

        if self.rotation_interval > 0
            && self.messages_sent.is_multiple_of(self.rotation_interval)
            && self.supported_dialects.len() > 1
        {
            if let Some(pos) = self.supported_dialects.iter().position(|&d| d == current) {
                let next_idx = (pos.wrapping_add(1)) % self.supported_dialects.len();
                if let Some(&dialect) = self.supported_dialects.get(next_idx) {
                    self.active_dialect = dialect;
                }
            }
        }

        (wrapped, current)
    }

    pub fn unwrap(&self, data: &[u8], mode: CamouflageMode) -> Option<Vec<u8>> {
        CamouflageWrapper::unwrap(data, mode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhyInterfaceBinding {
    pub shard_index: u8,
    pub interface_name: String,
    pub device_tag: u32,
}

#[derive(Debug, Clone, Default)]
pub struct HeterogeneousPhyRouter {
    bindings: Vec<PhyInterfaceBinding>,
}

impl HeterogeneousPhyRouter {
    pub fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    pub fn bind_shard_interface(&mut self, shard_index: u8, iface: &str, device_tag: u32) {
        self.bindings.retain(|b| b.shard_index != shard_index);
        self.bindings.push(PhyInterfaceBinding {
            shard_index,
            interface_name: iface.to_string(),
            device_tag,
        });
    }

    pub fn get_binding(&self, shard_index: u8) -> Option<&PhyInterfaceBinding> {
        self.bindings.iter().find(|b| b.shard_index == shard_index)
    }

    pub fn is_phy_diverse(&self) -> bool {
        if self.bindings.len() < 2 {
            return false;
        }
        let mut ifaces = std::collections::HashSet::new();
        for b in &self.bindings {
            if !ifaces.insert(&b.interface_name) {
                return false;
            }
        }
        true
    }
}

pub const GTF_BASE_SIZE: usize = 512;

pub const GTF_BULK_SIZE: usize = 1472;

pub const JITTER_MAX: usize = 64;

pub const MIN_FRAME_SIZE: usize = 32;

pub const OFFSET_SESSION_HASH: usize = 0;
pub const OFFSET_PACKET_COUNTER: usize = 4;
pub const OFFSET_SHARD_INDEX: usize = 8;
pub const OFFSET_FLAGS: usize = 9; // flags byte: bit 0 = bulk mode
pub const OFFSET_PAYLOAD_START: usize = 10;
pub const OFFSET_AUTH_TAG_START: usize = 496;

pub const MAX_PAYLOAD_LEN: usize = OFFSET_AUTH_TAG_START - OFFSET_PAYLOAD_START; // 486

pub const BULK_OFFSET_PAYLOAD_START: usize = 10;
pub const BULK_OFFSET_AUTH_TAG_START: usize = 1456; // 1472 - 16

pub const MAX_BULK_PAYLOAD_LEN: usize = BULK_OFFSET_AUTH_TAG_START - BULK_OFFSET_PAYLOAD_START; // 1446

pub const GTF_VERSION: u8 = 2;

pub const FLAG_V2: u8 = 0x80;
pub const FLAG_BULK: u8 = 0x01;
pub const FLAG_TUNNEL: u8 = 0x02;
pub const FLAG_DUMMY: u8 = 0x04;
pub const FLAG_SHARDSEC: u8 = 0x08;

pub const DUMMY_MAGIC: &[u8; 6] = b"DUMMY!";

pub fn is_dummy_payload(plain: &[u8]) -> bool {
    plain.len() >= DUMMY_MAGIC.len() && &plain[..DUMMY_MAGIC.len()] == DUMMY_MAGIC.as_slice()
}

pub const V2_OFFSET_SESSION_HASH: usize = 0;
pub const V2_OFFSET_RESERVED: usize = 4;
pub const V2_OFFSET_SHARD_INDEX: usize = 8;
pub const V2_OFFSET_FLAGS: usize = 9;
pub const V2_OFFSET_PACKET_COUNTER: usize = 10;
pub const V2_OFFSET_RATCHET_EPOCH: usize = 18;
pub const V2_OFFSET_NONCE: usize = 26;
pub const V2_OFFSET_PAYLOAD_START: usize = 38;
pub const V2_OFFSET_AUTH_TAG_START: usize = 496;
pub const V2_MAX_PAYLOAD_LEN: usize = V2_OFFSET_AUTH_TAG_START - V2_OFFSET_PAYLOAD_START; // 458
pub const V2_BULK_OFFSET_AUTH_TAG_START: usize = 1456;
pub const V2_MAX_BULK_PAYLOAD_LEN: usize = V2_BULK_OFFSET_AUTH_TAG_START - V2_OFFSET_PAYLOAD_START; // 1418

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtfV2Header {
    pub session_hash: [u8; 4],
    pub counter: u64,
    pub epoch: u64,
    pub nonce: [u8; 12],
    pub shard_index: u8,
    pub flags: u8,
    pub bulk: bool,
    pub tail: [u8; JITTER_MAX],
}

pub fn random_tail() -> [u8; JITTER_MAX] {
    let mut out = [0u8; JITTER_MAX];
    rand::thread_rng().fill(&mut out[..]);
    out
}

pub fn frame_tail(buf: &[u8]) -> &[u8] {
    if is_v2_frame(buf) && !is_bulk_frame(buf) && buf.len() >= GTF_BASE_SIZE + JITTER_MAX {
        &buf[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX]
    } else {
        &[]
    }
}

impl GtfV2Header {
    pub fn new(session_hash: [u8; 4], counter: u64, epoch: u64, shard_index: u8) -> Self {
        Self {
            session_hash,
            counter,
            epoch,
            nonce: crate::ghost::layers::l2_aead::random_xnonce(),
            shard_index,
            flags: 0,
            bulk: false,
            tail: [0u8; JITTER_MAX],
        }
    }

    pub fn bulk(mut self, bulk: bool) -> Self {
        self.bulk = bulk;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_tail(mut self, tail: [u8; JITTER_MAX]) -> Self {
        self.tail = tail;
        self
    }
}

pub fn is_v2_frame(buf: &[u8]) -> bool {
    buf.len() > V2_OFFSET_FLAGS && (buf[V2_OFFSET_FLAGS] & FLAG_V2) != 0
}

pub fn frame_wire_version(buf: &[u8]) -> u8 {
    if is_v2_frame(buf) {
        GTF_VERSION
    } else {
        1
    }
}

pub fn try_build_gtf_v2_frame(
    h: &GtfV2Header,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let (total, tag_start, cap) = if h.bulk {
        (
            GTF_BULK_SIZE,
            V2_BULK_OFFSET_AUTH_TAG_START,
            V2_MAX_BULK_PAYLOAD_LEN,
        )
    } else {
        (GTF_BASE_SIZE, V2_OFFSET_AUTH_TAG_START, V2_MAX_PAYLOAD_LEN)
    };
    if payload.len() > cap {
        return Err("payload exceeds GTF v2 capacity");
    }

    let full_cap = if h.bulk {
        GTF_BULK_SIZE
    } else {
        GTF_BASE_SIZE + JITTER_MAX
    };
    let mut packet = Vec::with_capacity(full_cap);
    packet.resize(total, 0u8);
    packet[V2_OFFSET_SESSION_HASH..V2_OFFSET_SESSION_HASH + 4].copy_from_slice(&h.session_hash);
    packet[V2_OFFSET_RESERVED..V2_OFFSET_RESERVED + 4].copy_from_slice(&[0u8; 4]);
    packet[V2_OFFSET_SHARD_INDEX] = h.shard_index;
    packet[V2_OFFSET_FLAGS] = FLAG_V2
        | (h.flags & (FLAG_BULK | FLAG_TUNNEL | FLAG_DUMMY | FLAG_SHARDSEC))
        | if h.bulk { FLAG_BULK } else { 0 };
    packet[V2_OFFSET_PACKET_COUNTER..V2_OFFSET_PACKET_COUNTER + 8]
        .copy_from_slice(&h.counter.to_be_bytes());
    packet[V2_OFFSET_RATCHET_EPOCH..V2_OFFSET_RATCHET_EPOCH + 8]
        .copy_from_slice(&h.epoch.to_be_bytes());
    packet[V2_OFFSET_NONCE..V2_OFFSET_NONCE + 12].copy_from_slice(&h.nonce);
    packet[V2_OFFSET_PAYLOAD_START..V2_OFFSET_PAYLOAD_START + payload.len()]
        .copy_from_slice(payload);

    if !h.bulk && payload.len() < cap {
        let slack_start = V2_OFFSET_PAYLOAD_START + payload.len();
        rand::thread_rng().fill(&mut packet[slack_start..tag_start]);
    }

    packet[tag_start..total].copy_from_slice(auth_tag);

    if !h.bulk {
        packet.extend_from_slice(&h.tail);
    }
    Ok(packet)
}

pub fn build_gtf_v2_frame(h: &GtfV2Header, payload: &[u8], auth_tag: &[u8; 16]) -> Vec<u8> {
    try_build_gtf_v2_frame(h, payload, auth_tag).unwrap_or_else(|e| {
        panic!(
            "Payload ({} bytes) exceeds GTF v2 capacity ({} bytes): {e}",
            payload.len(),
            if h.bulk {
                V2_MAX_BULK_PAYLOAD_LEN
            } else {
                V2_MAX_PAYLOAD_LEN
            }
        )
    })
}

pub fn parse_gtf_v2_header(buf: &[u8]) -> Option<GtfV2Header> {
    if !is_v2_frame(buf) || buf.len() < V2_OFFSET_PAYLOAD_START {
        return None;
    }
    let mut session_hash = [0u8; 4];
    session_hash.copy_from_slice(&buf[V2_OFFSET_SESSION_HASH..V2_OFFSET_SESSION_HASH + 4]);
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&buf[V2_OFFSET_PACKET_COUNTER..V2_OFFSET_PACKET_COUNTER + 8]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&buf[V2_OFFSET_RATCHET_EPOCH..V2_OFFSET_RATCHET_EPOCH + 8]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buf[V2_OFFSET_NONCE..V2_OFFSET_NONCE + 12]);
    let flags = buf[V2_OFFSET_FLAGS];
    let bulk = (flags & FLAG_BULK) != 0;
    let mut tail = [0u8; JITTER_MAX];
    if !bulk && buf.len() >= GTF_BASE_SIZE + JITTER_MAX {
        tail.copy_from_slice(&buf[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX]);
    }
    Some(GtfV2Header {
        session_hash,
        counter: u64::from_be_bytes(counter),
        epoch: u64::from_be_bytes(epoch),
        nonce,
        shard_index: buf[V2_OFFSET_SHARD_INDEX],
        flags: flags & !FLAG_V2,
        bulk,
        tail,
    })
}

pub const V3_OFFSET_NONCE: usize = 0;
pub const V3_OFFSET_ENC_HEADER: usize = 12;
pub const V3_ENC_HEADER_LEN: usize = 26;
pub const V3_OFFSET_PAYLOAD_START: usize = 38;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtfV3Header {
    pub cid: [u8; 8],
    pub counter: u64,
    pub epoch: u64,
    pub nonce: [u8; 12],
    pub shard_index: u8,
    pub flags: u8,
    pub bulk: bool,
    pub tail: [u8; JITTER_MAX],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtfV3Frame {
    pub bytes: Vec<u8>,
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    #[inline]
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        if a >= 16 || b >= 16 || c >= 16 || d >= 16 {
            return;
        }
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }

    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut working = state;
    for _ in 0..10 {
        qr(&mut working, 0, 4, 8, 12);
        qr(&mut working, 1, 5, 9, 13);
        qr(&mut working, 2, 6, 10, 14);
        qr(&mut working, 3, 7, 11, 15);
        qr(&mut working, 0, 5, 10, 15);
        qr(&mut working, 1, 6, 11, 12);
        qr(&mut working, 2, 7, 8, 13);
        qr(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn try_build_gtf_v3_frame(
    h: &GtfV3Header,
    link_hdr_key: &[u8; 32],
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Result<GtfV3Frame, &'static str> {
    let (total, tag_start, cap) = if h.bulk {
        (
            GTF_BULK_SIZE,
            V2_BULK_OFFSET_AUTH_TAG_START,
            V2_MAX_BULK_PAYLOAD_LEN,
        )
    } else {
        (GTF_BASE_SIZE, V2_OFFSET_AUTH_TAG_START, V2_MAX_PAYLOAD_LEN)
    };
    if payload.len() > cap {
        return Err("payload exceeds GTF v3 capacity");
    }

    let full_cap = if h.bulk {
        GTF_BULK_SIZE
    } else {
        GTF_BASE_SIZE + JITTER_MAX
    };
    let mut packet = Vec::with_capacity(full_cap);
    packet.resize(total, 0u8);

    packet[V3_OFFSET_NONCE..V3_OFFSET_NONCE + 12].copy_from_slice(&h.nonce);

    let mut plain_hdr = [0u8; V3_ENC_HEADER_LEN];
    plain_hdr[0..8].copy_from_slice(&h.cid);
    plain_hdr[8] = h.shard_index;
    plain_hdr[9] = (h.flags & (FLAG_BULK | FLAG_TUNNEL | FLAG_DUMMY | FLAG_SHARDSEC))
        | if h.bulk { FLAG_BULK } else { 0 };
    plain_hdr[10..18].copy_from_slice(&h.counter.to_be_bytes());
    plain_hdr[18..26].copy_from_slice(&h.epoch.to_be_bytes());

    let keystream = chacha20_block(link_hdr_key, 0, &h.nonce);
    for i in 0..V3_ENC_HEADER_LEN {
        packet[V3_OFFSET_ENC_HEADER + i] = plain_hdr[i] ^ keystream[i];
    }

    packet[V3_OFFSET_PAYLOAD_START..V3_OFFSET_PAYLOAD_START + payload.len()]
        .copy_from_slice(payload);

    if !h.bulk && payload.len() < cap {
        let slack_start = V3_OFFSET_PAYLOAD_START + payload.len();
        rand::thread_rng().fill(&mut packet[slack_start..tag_start]);
    }

    packet[tag_start..total].copy_from_slice(auth_tag);
    if !h.bulk {
        packet.extend_from_slice(&h.tail);
    }

    Ok(GtfV3Frame { bytes: packet })
}

pub fn parse_gtf_v3_header(buf: &[u8], link_hdr_key: &[u8; 32]) -> Option<GtfV3Header> {
    if buf.len() < V3_OFFSET_PAYLOAD_START {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buf[V3_OFFSET_NONCE..V3_OFFSET_NONCE + 12]);

    let keystream = chacha20_block(link_hdr_key, 0, &nonce);
    let mut plain_hdr = [0u8; V3_ENC_HEADER_LEN];
    for i in 0..V3_ENC_HEADER_LEN {
        plain_hdr[i] = buf[V3_OFFSET_ENC_HEADER + i] ^ keystream[i];
    }

    let mut cid = [0u8; 8];
    cid.copy_from_slice(&plain_hdr[0..8]);
    let shard_index = plain_hdr[8];
    let flags = plain_hdr[9];
    let bulk = (flags & FLAG_BULK) != 0;
    let counter = u64::from_be_bytes(plain_hdr[10..18].try_into().ok()?);
    let epoch = u64::from_be_bytes(plain_hdr[18..26].try_into().ok()?);

    let mut tail = [0u8; JITTER_MAX];
    if !bulk && buf.len() >= GTF_BASE_SIZE + JITTER_MAX {
        tail.copy_from_slice(&buf[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX]);
    }

    Some(GtfV3Header {
        cid,
        counter,
        epoch,
        nonce,
        shard_index,
        flags,
        bulk,
        tail,
    })
}

pub fn parse_packet_counter_u64(buf: &[u8]) -> u64 {
    match parse_gtf_v2_header(buf) {
        Some(h) => h.counter,
        None => parse_packet_counter(buf) as u64,
    }
}

#[derive(Clone)]
pub struct AckEntry {
    pub seq: u32,
    pub data: Bytes,
    pub auth_tag: [u8; 16],
    pub session_hash: [u8; 4],
    pub sent_at: Instant,
    pub retries: u8,
}

pub struct AckEngine {
    pending: Vec<Option<AckEntry>>,
    pub base_seq: u32,
    pub window_size: u32,
    pub srtt: f64,
    pub congestion: bool,
    pub cwnd: u32,
}

impl Default for AckEngine {
    fn default() -> Self {
        Self {
            pending: vec![None; 4096],
            base_seq: 0,
            window_size: 64,
            srtt: 50_000.0, // 50ms initial estimate (microseconds)
            congestion: false,
            cwnd: 64,
        }
    }
}

impl AckEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, seq: u32, data: Bytes, auth_tag: [u8; 16], session_hash: [u8; 4]) {
        if self.pending.is_empty() {
            return;
        }
        let idx = (seq as usize) % self.pending.len();
        self.pending[idx] = Some(AckEntry {
            seq,
            data,
            auth_tag,
            session_hash,
            sent_at: Instant::now(),
            retries: 0,
        });
    }

    pub fn on_ack(&mut self, seq: u32) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let idx = (seq as usize) % self.pending.len();
        if let Some(ref entry) = self.pending[idx] {
            if entry.seq == seq {
                let rtt = entry.sent_at.elapsed().as_micros() as f64;
                self.srtt = self.srtt * 0.875 + rtt * 0.125;
                self.cwnd = self.cwnd.saturating_add(1).min(512);
                self.congestion = false;
                self.pending[idx] = None;
                return true;
            }
        }
        false
    }

    pub fn on_timeout(&mut self) {
        self.congestion = true;
        self.cwnd = (self.cwnd / 2).max(16);
    }

    pub fn collect_expired(&mut self, timeout: Duration) -> Vec<(u32, Bytes)> {
        let mut retransmit = Vec::new();
        let now = Instant::now();
        for slot in self.pending.iter_mut() {
            if let Some(ref mut entry) = slot {
                if now.duration_since(entry.sent_at) > timeout && entry.retries < 5 {
                    entry.retries = entry.retries.saturating_add(1);
                    entry.sent_at = now;
                    retransmit.push((entry.seq, entry.data.clone()));
                } else if entry.retries >= 5 {
                    slot.take();
                }
            }
        }
        retransmit
    }

    pub fn collect_expired_full(
        &mut self,
        timeout: Duration,
    ) -> Vec<(u32, Bytes, [u8; 16], [u8; 4])> {
        let mut retransmit = Vec::new();
        let now = Instant::now();
        for slot in self.pending.iter_mut() {
            if let Some(ref mut entry) = slot {
                if now.duration_since(entry.sent_at) > timeout && entry.retries < 5 {
                    entry.retries = entry.retries.saturating_add(1);
                    entry.sent_at = now;
                    retransmit.push((
                        entry.seq,
                        entry.data.clone(),
                        entry.auth_tag,
                        entry.session_hash,
                    ));
                } else if entry.retries >= 5 {
                    slot.take();
                }
            }
        }
        retransmit
    }

    pub fn available(&self) -> u32 {
        let in_flight = self.pending.iter().filter(|s| s.is_some()).count() as u32;
        self.cwnd.saturating_sub(in_flight)
    }
}

pub fn frame_shard(d: &[u8]) -> Vec<u8> {
    let l = (d.len() as u16).to_be_bytes();
    let mut f = Vec::with_capacity(d.len() + 2);
    f.extend_from_slice(&l);
    f.extend_from_slice(d);
    f
}

pub fn unframe(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 2 {
        return None;
    }
    let l = u16::from_be_bytes([b[0], b[1]]) as usize;
    if l == 0 || 2 + l > b.len() {
        None
    } else {
        Some(b[2..2 + l].to_vec())
    }
}

pub fn frame_shard_authenticated(
    d: &[u8],
    key: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let l = (d.len() as u16).to_be_bytes();
    let mut f = Vec::with_capacity(d.len() + 2 + 16);
    f.extend_from_slice(&l);
    f.extend_from_slice(d);

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(b"GGN_HEADER_CHAFF_V1");
    mac.update(&epoch.to_be_bytes());
    mac.update(nonce);
    mac.update(&l);
    let tag = &mac.finalize().into_bytes()[..16];
    f.extend_from_slice(tag);
    f
}

pub fn unframe_authenticated(
    b: &[u8],
    key: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, &'static str> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    if b.len() < 2 + 16 {
        return Err("truncated_frame");
    }
    let l = u16::from_be_bytes([b[0], b[1]]) as usize;
    if l == 0 || 2 + l + 16 > b.len() {
        return Err("length_out_of_bounds");
    }

    let payload = &b[2..2 + l];
    let tag_offset = 2 + l;
    let provided_tag = &b[tag_offset..tag_offset + 16];

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(b"GGN_HEADER_CHAFF_V1");
    mac.update(&epoch.to_be_bytes());
    mac.update(nonce);
    mac.update(&[b[0], b[1]]);
    let expected_tag = &mac.finalize().into_bytes()[..16];

    if subtle::ConstantTimeEq::ct_eq(provided_tag, expected_tag).into() {
        Ok(payload.to_vec())
    } else {
        Err("auth_fail")
    }
}

const MIN_TRANSIT_BURST: u64 = 1500;

pub struct FlowController {
    transit_bucket: AtomicU64,
    transit_rate: AtomicU64,
    transit_burst: AtomicU64,
    last_replenish: AtomicU64,
}

impl FlowController {
    pub fn new(transit_rate_mbps: u64) -> Self {
        let bytes_per_sec = transit_rate_mbps.saturating_mul(125_000); // Mbps → bytes/sec
        Self {
            transit_bucket: AtomicU64::new(bytes_per_sec), // start full
            transit_rate: AtomicU64::new(bytes_per_sec),
            transit_burst: AtomicU64::new((bytes_per_sec / 10).max(MIN_TRANSIT_BURST)),
            last_replenish: AtomicU64::new(now_nanos()),
        }
    }

    pub fn replenish(&self) {
        let now = now_nanos();
        let last = self.last_replenish.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);
        if elapsed > 1_000_000 {
            let rate = self.transit_rate.load(Ordering::Relaxed) as u128;
            let tokens = rate.saturating_mul(elapsed as u128) / 1_000_000_000;
            let burst = self.transit_burst.load(Ordering::Relaxed) as u128;
            let current = self.transit_bucket.load(Ordering::Relaxed) as u128;
            let new = (current + tokens).min(burst) as u64;
            self.transit_bucket.store(new, Ordering::Relaxed);
            self.last_replenish.store(now, Ordering::Relaxed);
        }
    }

    pub fn try_consume_transit(&self, bytes: usize) -> bool {
        self.replenish();
        let current = self.transit_bucket.load(Ordering::Relaxed);
        if current >= bytes as u64 {
            self.transit_bucket
                .store(current - bytes as u64, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn try_consume_local(&self, _bytes: usize) -> bool {
        true // no throttle
    }

    pub fn set_transit_rate_mbps(&self, mbps: u64) {
        self.set_transit_rate_bps(mbps.saturating_mul(125_000));
    }

    pub fn set_transit_rate_bps(&self, bytes_per_sec: u64) {
        self.transit_rate.store(bytes_per_sec, Ordering::Relaxed);
        self.transit_burst.store(
            (bytes_per_sec / 10).max(MIN_TRANSIT_BURST),
            Ordering::Relaxed,
        );
        self.transit_bucket.store(bytes_per_sec, Ordering::Relaxed);
        self.last_replenish.store(now_nanos(), Ordering::Relaxed);
    }

    pub fn transit_rate_bps(&self) -> u64 {
        self.transit_rate.load(Ordering::Relaxed)
    }
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub fn build_gtf_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
    bulk: bool,
) -> Vec<u8> {
    if bulk || payload.len() > MAX_PAYLOAD_LEN {
        build_bulk_frame(session_hash, counter, shard_index, payload, auth_tag)
    } else {
        build_privacy_frame(session_hash, counter, shard_index, payload, auth_tag)
    }
}

fn build_privacy_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return build_bulk_frame(session_hash, counter, shard_index, payload, auth_tag);
    }

    let mut packet = vec![0u8; GTF_BASE_SIZE];
    packet[OFFSET_SESSION_HASH..OFFSET_SESSION_HASH + 4].copy_from_slice(&session_hash);
    packet[OFFSET_PACKET_COUNTER..OFFSET_PACKET_COUNTER + 4]
        .copy_from_slice(&counter.to_be_bytes());
    packet[OFFSET_SHARD_INDEX] = shard_index;
    packet[OFFSET_FLAGS] = 0; // privacy mode
    packet[OFFSET_PAYLOAD_START..OFFSET_PAYLOAD_START + payload.len()].copy_from_slice(payload);
    packet[OFFSET_AUTH_TAG_START..GTF_BASE_SIZE].copy_from_slice(auth_tag);

    let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
    if jitter > 0 {
        packet.extend(std::iter::repeat_n(0u8, jitter));
        rand::thread_rng().fill(&mut packet[GTF_BASE_SIZE..]);
    }

    packet
}

fn try_build_bulk_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    if payload.len() > MAX_BULK_PAYLOAD_LEN {
        return Err("payload exceeds bulk frame capacity");
    }

    let mut packet = vec![0u8; GTF_BULK_SIZE];
    packet[OFFSET_SESSION_HASH..OFFSET_SESSION_HASH + 4].copy_from_slice(&session_hash);
    packet[OFFSET_PACKET_COUNTER..OFFSET_PACKET_COUNTER + 4]
        .copy_from_slice(&counter.to_be_bytes());
    packet[OFFSET_SHARD_INDEX] = shard_index;
    packet[OFFSET_FLAGS] = 0x01; // bit 0 = bulk mode
    packet[BULK_OFFSET_PAYLOAD_START..BULK_OFFSET_PAYLOAD_START + payload.len()]
        .copy_from_slice(payload);
    packet[BULK_OFFSET_AUTH_TAG_START..GTF_BULK_SIZE].copy_from_slice(auth_tag);

    Ok(packet)
}

fn build_bulk_frame(
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    try_build_bulk_frame(session_hash, counter, shard_index, payload, auth_tag).unwrap_or_else(
        |e| {
            panic!(
                "Payload ({} bytes) exceeds bulk frame capacity ({} bytes): {e}",
                payload.len(),
                MAX_BULK_PAYLOAD_LEN
            )
        },
    )
}

pub fn is_bulk_frame(buf: &[u8]) -> bool {
    buf.len() > OFFSET_FLAGS && (buf[OFFSET_FLAGS] & 0x01) != 0
}

pub fn frame_size(buf: &[u8]) -> usize {
    if is_bulk_frame(buf) {
        GTF_BULK_SIZE
    } else {
        GTF_BASE_SIZE
    }
}

pub fn parse_packet_counter(buf: &[u8]) -> u32 {
    if buf.len() < OFFSET_PACKET_COUNTER + 4 {
        return 0;
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(&buf[OFFSET_PACKET_COUNTER..OFFSET_PACKET_COUNTER + 4]);
    u32::from_be_bytes(c)
}

pub fn parse_session_hash(buf: &[u8]) -> [u8; 4] {
    if buf.len() < OFFSET_SESSION_HASH + 4 {
        return [0u8; 4];
    }
    let mut h = [0u8; 4];
    h.copy_from_slice(&buf[OFFSET_SESSION_HASH..OFFSET_SESSION_HASH + 4]);
    h
}

pub fn parse_flags(buf: &[u8]) -> u8 {
    if buf.len() > OFFSET_FLAGS {
        buf[OFFSET_FLAGS]
    } else {
        0
    }
}

pub fn extract_payload(buf: &[u8]) -> &[u8] {
    let (start, tag_start) = if is_v2_frame(buf) {
        (
            V2_OFFSET_PAYLOAD_START,
            if is_bulk_frame(buf) {
                V2_BULK_OFFSET_AUTH_TAG_START
            } else {
                V2_OFFSET_AUTH_TAG_START
            },
        )
    } else if is_bulk_frame(buf) {
        (BULK_OFFSET_PAYLOAD_START, BULK_OFFSET_AUTH_TAG_START)
    } else {
        (OFFSET_PAYLOAD_START, OFFSET_AUTH_TAG_START)
    };
    if buf.len() <= start {
        return &[];
    }
    &buf[start..tag_start.min(buf.len())]
}

pub fn extract_auth_tag(buf: &[u8]) -> &[u8] {
    let tag_start = if is_v2_frame(buf) {
        if is_bulk_frame(buf) {
            V2_BULK_OFFSET_AUTH_TAG_START
        } else {
            V2_OFFSET_AUTH_TAG_START
        }
    } else if is_bulk_frame(buf) {
        BULK_OFFSET_AUTH_TAG_START
    } else {
        OFFSET_AUTH_TAG_START
    };
    let tag_end = (tag_start + 16).min(buf.len());
    if tag_end >= tag_start + 16 {
        &buf[tag_start..tag_end]
    } else {
        &[]
    }
}

pub async fn send_gtf(
    socket: &UdpSocket,
    target: &SocketAddr,
    session_hash: [u8; 4],
    counter: u32,
    shard_index: u8,
    payload: &[u8],
    auth_tag: &[u8; 16],
    bulk: bool,
) -> std::io::Result<()> {
    let frame = build_gtf_frame(session_hash, counter, shard_index, payload, auth_tag, bulk);
    socket.send_to(&frame, target).await?;
    Ok(())
}

pub async fn send_gtf_v2(
    socket: &UdpSocket,
    target: &SocketAddr,
    h: &GtfV2Header,
    payload: &[u8],
    auth_tag: &[u8; 16],
) -> std::io::Result<()> {
    let frame = build_gtf_v2_frame(h, payload, auth_tag);
    socket.send_to(&frame, target).await?;
    Ok(())
}

#[cfg(test)]
mod wire_v2_tests {
    use super::*;

    fn tag() -> [u8; 16] {
        [0xABu8; 16]
    }

    #[test]
    fn test_v2_frame_marks_itself_and_parses_back() {
        let h = GtfV2Header::new([1, 2, 3, 4], 0x1_0000_0007, 9, 2);
        let frame = build_gtf_v2_frame(&h, b"payload", &tag());
        assert_eq!(
            frame.len(),
            GTF_BASE_SIZE + JITTER_MAX,
            "a privacy frame is a CONSTANT 576 B — 512 B of authenticated \
             frame plus a full-length jitter tail — so its length carries no signal"
        );
        assert!(is_v2_frame(&frame));
        assert_eq!(frame_wire_version(&frame), GTF_VERSION);
        let parsed = parse_gtf_v2_header(&frame).expect("v2 header");
        assert_eq!(parsed.session_hash, [1, 2, 3, 4]);
        assert_eq!(parsed.counter, 0x1_0000_0007);
        assert_eq!(parsed.epoch, 9);
        assert_eq!(parsed.nonce, h.nonce);
        assert_eq!(parsed.shard_index, 2);
        assert!(!parsed.bulk);
    }

    #[test]
    fn test_p3_1_privacy_frames_are_always_the_same_length() {
        let mut seen = std::collections::HashSet::new();
        for payload_len in [0usize, 1, 64, 200, GTF_BASE_SIZE] {
            for shard in 0u8..3 {
                let payload = vec![0xA5u8; payload_len.min(V2_MAX_PAYLOAD_LEN)];
                let h = GtfV2Header::new([7, 7, 7, 7], 1, 0, shard);
                let frame = build_gtf_v2_frame(&h, &payload, &tag());
                seen.insert(frame.len());
            }
        }
        assert_eq!(
            seen,
            std::collections::HashSet::from([GTF_BASE_SIZE + JITTER_MAX]),
            "every privacy frame must be exactly one length on the wire"
        );

        let t1 = random_tail();
        let t2 = random_tail();
        assert_ne!(t1, [0u8; JITTER_MAX], "not a strippable run of zeros");
        assert_ne!(t1, t2, "two messages must not share a recomputable tail");
        assert_eq!(t1.len(), crate::ghost::layers::l2_aead::SUBLIMINAL_TAIL_LEN);
        let zeros = t1.iter().filter(|b| **b == 0).count();
        assert!(zeros < 8, "random tail must not look like zero padding");
    }

    #[test]
    fn test_v2_counter_survives_the_32_bit_boundary() {
        for counter in [0, 1, u32::MAX as u64, (u32::MAX as u64) + 1, 1u64 << 40] {
            let h = GtfV2Header::new([9, 9, 9, 9], counter, 0, 0);
            let frame = build_gtf_v2_frame(&h, b"x", &tag());
            assert_eq!(parse_packet_counter_u64(&frame), counter);
        }
    }

    #[test]
    fn test_v1_frames_are_still_read_as_v1() {
        for (counter, bulk) in [(0u32, false), (2, false), (3, true), (u32::MAX, true)] {
            let frame = build_gtf_frame([7, 7, 7, 7], counter, 1, b"shard", &tag(), bulk);
            assert!(
                !is_v2_frame(&frame),
                "v1 frame misread as v2 (counter {counter})"
            );
            assert_eq!(frame_wire_version(&frame), 1);
            assert_eq!(parse_packet_counter(&frame), counter);
            assert_eq!(parse_packet_counter_u64(&frame), counter as u64);
            assert_eq!(parse_gtf_v2_header(&frame), None);
        }
    }

    #[test]
    fn test_v2_flags_carry_bulk_and_tunnel() {
        let h = GtfV2Header::new([1, 1, 1, 1], 5, 0, 0)
            .bulk(true)
            .with_flags(FLAG_TUNNEL);
        let frame = build_gtf_v2_frame(&h, b"tunnel", &tag());
        assert!(is_bulk_frame(&frame));
        let parsed = parse_gtf_v2_header(&frame).unwrap();
        assert!(parsed.bulk);
        assert_eq!(parsed.flags & FLAG_TUNNEL, FLAG_TUNNEL);
        assert_eq!(parsed.flags & FLAG_V2, 0, "the marker is not a caller flag");
    }

    #[test]
    fn test_v2_payload_and_tag_offsets_differ_from_v1() {
        assert_eq!(V2_MAX_PAYLOAD_LEN, 458);
        assert_eq!(MAX_PAYLOAD_LEN, 486);
        const _: () = assert!(V2_OFFSET_PAYLOAD_START > OFFSET_PAYLOAD_START);

        let h = GtfV2Header::new([2, 2, 2, 2], 11, 1, 0);
        let mut payload = vec![0u8; V2_MAX_PAYLOAD_LEN];
        payload[..4].copy_from_slice(b"ABCD");
        let frame = build_gtf_v2_frame(&h, &payload, &tag());
        assert_eq!(&extract_payload(&frame)[..4], b"ABCD");
        assert_eq!(extract_auth_tag(&frame), &tag());
        assert_eq!(extract_payload(&frame).len(), V2_MAX_PAYLOAD_LEN);

        let v1 = build_gtf_frame([2, 2, 2, 2], 11, 0, b"shard", &tag(), false);
        assert_eq!(&extract_payload(&v1)[..5], b"shard");
        assert_eq!(extract_payload(&v1).len(), MAX_PAYLOAD_LEN);
        assert_eq!(extract_auth_tag(&v1), &tag());
    }

    #[test]
    fn test_v2_rejects_an_oversized_payload() {
        let h = GtfV2Header::new([1, 1, 1, 1], 1, 0, 0);
        let over = vec![0u8; V2_MAX_PAYLOAD_LEN + 1];
        assert!(std::panic::catch_unwind(|| build_gtf_v2_frame(&h, &over, &tag())).is_err());
        let hb = GtfV2Header::new([1, 1, 1, 1], 1, 0, 0).bulk(true);
        let frames_ok = build_gtf_v2_frame(&hb, &vec![0u8; V2_MAX_BULK_PAYLOAD_LEN], &tag());
        assert_eq!(frames_ok.len(), GTF_BULK_SIZE);
    }

    #[test]
    fn test_v2_short_buffer_is_not_a_v2_frame() {
        assert!(!is_v2_frame(&[]));
        assert!(!is_v2_frame(&[0u8; 5]));
        assert_eq!(parse_gtf_v2_header(&[0x80u8; 4]), None);
        assert_eq!(frame_wire_version(&[0u8; 11]), 1);
    }

    #[test]
    fn test_header_chaff_authenticated_framing_and_tamper() {
        let key = [0x5au8; 32];
        let epoch = 42u64;
        let nonce = [0x12u8; 12];
        let shard_data = b"confidential_payload_data";

        let mut framed = frame_shard_authenticated(shard_data, &key, epoch, &nonce);

        let recovered = unframe_authenticated(&framed, &key, epoch, &nonce).unwrap();
        assert_eq!(&recovered, shard_data);

        let mut tampered_len = framed.clone();
        tampered_len[1] ^= 0x01;
        assert_eq!(
            unframe_authenticated(&tampered_len, &key, epoch, &nonce),
            Err("auth_fail")
        );

        assert_eq!(
            unframe_authenticated(&framed, &key, epoch + 1, &nonce),
            Err("auth_fail")
        );

        let wrong_key = [0x5bu8; 32];
        assert_eq!(
            unframe_authenticated(&framed, &wrong_key, epoch, &nonce),
            Err("auth_fail")
        );

        let last = framed.len() - 1;
        framed[last] ^= 0xff;
        assert_eq!(
            unframe_authenticated(&framed, &key, epoch, &nonce),
            Err("auth_fail")
        );
    }

    #[test]
    fn test_poisson_beacon_gap_distribution() {
        let mean = 30.0f64;
        let mut total_secs = 0.0f64;
        let samples = 10_000;
        let mut saw_shorter_than_mean = false;
        let mut saw_longer_than_mean = false;

        for _ in 0..samples {
            let u: f64 = rand::random();
            let gap = poisson_beacon_gap(u, mean);
            let s = gap.as_secs_f64();
            assert!(s >= 1.0, "gap must not cause tight loop");
            assert!(s <= 90.0, "gap must be bounded");
            total_secs += s;
            if s < mean - 5.0 {
                saw_shorter_than_mean = true;
            }
            if s > mean + 5.0 {
                saw_longer_than_mean = true;
            }
        }

        let empirical_mean = total_secs / (samples as f64);
        assert!(
            (empirical_mean - mean).abs() < 3.0,
            "empirical mean {empirical_mean} should be close to {mean}"
        );
        assert!(
            saw_shorter_than_mean && saw_longer_than_mean,
            "must exhibit exponential dispersion"
        );
    }

    #[test]
    fn test_camouflage_wrapper_modes() {
        let frame = b"gtf_raw_packet_bytes_for_camouflage";

        assert_eq!(CamouflageWrapper::wrap(frame, CamouflageMode::None), frame);
        assert_eq!(
            CamouflageWrapper::unwrap(frame, CamouflageMode::None).unwrap(),
            frame
        );

        let quic_camo = CamouflageWrapper::wrap(frame, CamouflageMode::QuicDatagram);
        assert_eq!(quic_camo[0], CamouflageWrapper::H3_DATAGRAM_FRAME_TYPE);
        let unwrapped_quic =
            CamouflageWrapper::unwrap(&quic_camo, CamouflageMode::QuicDatagram).unwrap();
        assert_eq!(&unwrapped_quic, frame);

        let doh_camo = CamouflageWrapper::wrap(frame, CamouflageMode::DnsOverHttps);
        assert!(doh_camo.starts_with(CamouflageWrapper::DOH_PREFIX));
        let unwrapped_doh =
            CamouflageWrapper::unwrap(&doh_camo, CamouflageMode::DnsOverHttps).unwrap();
        assert_eq!(&unwrapped_doh, frame);

        let https_camo = CamouflageWrapper::wrap(frame, CamouflageMode::HttpsChunk);
        let unwrapped_https =
            CamouflageWrapper::unwrap(&https_camo, CamouflageMode::HttpsChunk).unwrap();
        assert_eq!(&unwrapped_https, frame);
    }

    #[test]
    fn test_heterogeneous_phy_router() {
        let mut router = HeterogeneousPhyRouter::new();

        router.bind_shard_interface(0, "wlan0", 100);
        router.bind_shard_interface(1, "rmnet0", 101);
        router.bind_shard_interface(2, "eth0", 102);

        assert!(
            router.is_phy_diverse(),
            "3 distinct physical interfaces must satisfy diversity"
        );
        assert_eq!(router.get_binding(0).unwrap().interface_name, "wlan0");
        assert_eq!(router.get_binding(1).unwrap().interface_name, "rmnet0");
        assert_eq!(router.get_binding(2).unwrap().interface_name, "eth0");

        router.bind_shard_interface(2, "wlan0", 100);
        assert!(
            !router.is_phy_diverse(),
            "Duplicate interface must violate PHY diversity"
        );
    }

    #[test]
    fn test_shape_shifting_wire_negotiation_and_rotation() {
        let restricted_census = NetworkCensus {
            raw_udp_permitted: false,     // UDP blocked by firewall
            quic_udp443_permitted: false, // QUIC blocked
            ..NetworkCensus::default()
        };

        let peer_dialects = vec![
            CamouflageMode::QuicDatagram,
            CamouflageMode::DnsOverHttps,
            CamouflageMode::HttpsChunk,
        ];

        let mut session = DialectSession::negotiate(&restricted_census, &peer_dialects, 2);
        assert_eq!(session.active_dialect, CamouflageMode::DnsOverHttps);

        let frame = b"gtf_wire_frame_content";

        let (pkt1, mode1) = session.wrap_and_advance(frame);
        assert_eq!(mode1, CamouflageMode::DnsOverHttps);
        assert!(pkt1.starts_with(CamouflageWrapper::DOH_PREFIX));
        assert_eq!(session.unwrap(&pkt1, mode1).unwrap(), frame);

        let (pkt2, mode2) = session.wrap_and_advance(frame);
        assert_eq!(mode2, CamouflageMode::DnsOverHttps);
        assert_eq!(session.unwrap(&pkt2, mode2).unwrap(), frame);
        assert_eq!(session.active_dialect, CamouflageMode::HttpsChunk);

        let (pkt3, mode3) = session.wrap_and_advance(frame);
        assert_eq!(mode3, CamouflageMode::HttpsChunk);
        assert_eq!(session.unwrap(&pkt3, mode3).unwrap(), frame);
    }

    #[test]
    fn test_beacon_grid_serialization_and_partition_reconciliation() {
        let grid1 = BeaconGridEpoch::new(10, 4, [0xAAu8; 16]);
        let bytes = grid1.to_bytes();
        let deserialized = BeaconGridEpoch::from_bytes(&bytes).expect("Valid beacon grid bytes");
        assert_eq!(deserialized, grid1);

        let mut node_a = grid1;
        let node_b = BeaconGridEpoch::new(15, 2, [0xBBu8; 16]);

        let advanced = node_a.reconcile(&node_b);
        assert!(advanced, "Node A must advance to remote epoch");
        assert_eq!(node_a.grid_epoch, 15);
        assert_eq!(node_a.cycle_count, 2);
        assert_eq!(node_a.entropy_commitment, [0xBBu8; 16]);

        let stale_peer = BeaconGridEpoch::new(12, 9, [0xCCu8; 16]);
        let stale_res = node_a.reconcile(&stale_peer);
        assert!(
            !stale_res,
            "Stale epoch grid must not regress monotonic timeline"
        );
        assert_eq!(node_a.grid_epoch, 15);
    }
}

#[derive(Default)]
pub struct ThroughputStats {
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub retransmits: AtomicU64,
    pub drops: AtomicU64,
    pub cover_recv: AtomicU64,
}

impl ThroughputStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn report(&self, interval: Duration) -> (f64, f64, f64, f64) {
        let sent = self.bytes_sent.swap(0, Ordering::Relaxed) as f64;
        let recv = self.bytes_recv.swap(0, Ordering::Relaxed) as f64;
        let secs = interval.as_secs_f64();
        (sent, recv, sent / secs, recv / secs)
    }
}

#[cfg(test)]
mod v3_tests {
    use super::*;

    #[test]
    fn gtf_v3_frame_roundtrip_and_encrypted_header() {
        let link_hdr_key = [0x42u8; 32];
        let cid = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let hdr = GtfV3Header {
            cid,
            counter: 12345,
            epoch: 7,
            nonce: [0x11u8; 12],
            shard_index: 2,
            flags: FLAG_TUNNEL,
            bulk: false,
            tail: [0x5Au8; JITTER_MAX],
        };
        let payload = b"hello-gtf-v3";
        let auth_tag = [0x99u8; 16];

        let frame = try_build_gtf_v3_frame(&hdr, &link_hdr_key, payload, &auth_tag)
            .expect("build v3 frame");
        assert_eq!(frame.bytes.len(), GTF_BASE_SIZE + JITTER_MAX);
        assert_ne!(
            &frame.bytes[V3_OFFSET_ENC_HEADER..V3_OFFSET_ENC_HEADER + 8],
            &cid
        );

        let parsed = parse_gtf_v3_header(&frame.bytes, &link_hdr_key).expect("parse v3 header");
        assert_eq!(parsed, hdr);
    }
}
