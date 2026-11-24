//! HPEB — Heterogeneous PHY Erasure Bonding.
//!
//! Wi-Fi drops when you walk to the kitchen; 5G drops when you take the stairs;
//! Starlink drops for two seconds every few minutes. A single default route makes
//! all three events a stall. A game or a call should not notice any of them.
//!
//! HPEB pins one socket per physical interface — `wlan0`, `rmnet0`, `starlink0` —
//! and splits each message across them as Reed-Solomon shards of an
//! **all-or-nothing** block. Any two shards rebuild the message, so one interface
//! vanishing costs nothing; and a single shard on its own yields nothing, so
//! "no single carrier holds a whole message" becomes a physical fact rather than
//! a routing intention.
//!
//! Two things this module does *not* pretend to do:
//!
//! * **Bind sockets by itself.** `SO_BINDTODEVICE`, `IP_BOUND_IF`, Android
//!   `Network.bindSocket()` and Windows `IP_UNICAST_IF` are four different,
//!   privileged operations. [`PhyPath`] carries the interface name and the
//!   already-bound local address; the platform layer (or the user, with
//!   `--bind-interface`) supplies them.
//! * **Measure a handover.** [`HandoverState`] takes loss notifications from the
//!   real socket loop and applies a cooldown so a flapping interface does not
//!   cause a switch storm. The measured convergence number belongs to the
//!   testbed, not to this file.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::ghost::layers::l4_rs;

/// A physical path a shard can leave by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhyPath {
    /// Interface name (`wlan0`, `rmnet0`, `starlink0`, or `lo` in tests).
    pub interface: String,
    /// Local address already bound to that interface, when the platform layer
    /// has done so. `None` means "not pinned" — the scheduler still assigns
    /// shards, but the caller must not claim physical separation.
    pub local_addr: Option<String>,
    /// Autonomous system of the carrier, when known (`0` = unknown).
    pub asn: u32,
    /// Relative cost: lower is preferred for the *parity* shard on ties.
    pub cost: u8,
    pub available: bool,
}

impl PhyPath {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            local_addr: None,
            asn: 0,
            cost: 100,
            available: true,
        }
    }

    pub fn pinned(mut self, addr: &str) -> Self {
        self.local_addr = Some(addr.to_string());
        self
    }

    pub fn with_asn(mut self, asn: u32) -> Self {
        self.asn = asn;
        self
    }

    pub fn with_cost(mut self, cost: u8) -> Self {
        self.cost = cost;
        self
    }

    /// True when the path is pinned to a real interface address. Diversity
    /// claims are only honest for pinned paths.
    pub fn is_pinned(&self) -> bool {
        self.local_addr.is_some()
    }
}

/// One shard and the path it must leave by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BondedShard {
    pub interface: String,
    pub index: u8,
    /// One shard of the bonded encoding (never a plaintext fragment).
    pub bytes: Vec<u8>,
}

/// The trade a two-carrier bond has to make. On two paths the two goals are
/// mutually exclusive, so the caller states which one it is buying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondMode {
    /// 2-of-2 XOR split: each shard alone is uniformly random, so neither
    /// carrier learns one bit. Losing either path loses the message.
    Confidentiality,
    /// 1-of-2 duplication: either carrier can be lost. Secrecy rests on the L2
    /// AEAD, exactly as it does on every single-path send.
    Availability,
}

/// The split actually applied to one payload.
///
/// This is the receiver's decode instruction, so it travels with the shards:
/// a receiver that guesses wrong gets garbage, never a subtle downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondScheme {
    /// Two paths, 2-of-2 XOR.
    Xor2,
    /// Two paths, full duplication.
    Duplicate2,
    /// Three or more paths, `(c, r, f)` ramp over GF(2^8).
    Ramp(l4_rs::RampParams),
}

impl BondScheme {
    /// Wire length of [`BondScheme::encode`].
    pub const ENCODED_LEN: usize = 4;

    /// `[tag, data, masks, shards]` — four bytes the receiver can trust as far
    /// as its own authentication of the carrier goes.
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        match self {
            BondScheme::Xor2 => [0, 0, 0, 2],
            BondScheme::Duplicate2 => [1, 0, 0, 2],
            BondScheme::Ramp(p) => [2, p.data, p.masks, p.shards],
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::ENCODED_LEN {
            return None;
        }
        match bytes[0] {
            0 => Some(BondScheme::Xor2),
            1 => Some(BondScheme::Duplicate2),
            2 => {
                let (data, masks, shards) = (bytes[1], bytes[2], bytes[3]);
                let failures = shards.checked_sub(data)?.checked_sub(masks)?;
                l4_rs::RampParams::new(masks, data, failures)
                    .ok()
                    .map(BondScheme::Ramp)
            }
            _ => None,
        }
    }

    /// Shards that must arrive before a decode is attempted.
    pub fn required(self) -> usize {
        match self {
            BondScheme::Xor2 => 2,
            BondScheme::Duplicate2 => 1,
            BondScheme::Ramp(p) => p.required(),
        }
    }

    /// Shards the sender emitted.
    pub fn emitted(self) -> usize {
        match self {
            BondScheme::Xor2 | BondScheme::Duplicate2 => 2,
            BondScheme::Ramp(p) => p.shards as usize,
        }
    }

    pub fn describe(self) -> String {
        match self {
            BondScheme::Xor2 => "2-of-2 XOR (confidentiality)".to_string(),
            BondScheme::Duplicate2 => "1-of-2 duplicate (availability)".to_string(),
            BondScheme::Ramp(p) => format!(
                "ramp c={} r={} f={} m={} rate={:.2}",
                p.masks,
                p.data,
                p.failures(),
                p.shards,
                p.rate()
            ),
        }
    }
}

/// A payload split into shards plus the scheme needed to put it back together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedSet {
    pub scheme: BondScheme,
    pub shards: Vec<BondedShard>,
}

impl BondedSet {
    /// Rebuild the payload from whichever shards arrived.
    pub fn recover(&self, shards: &[(u8, Vec<u8>)]) -> Option<Vec<u8>> {
        recover_with(self.scheme, shards)
    }
}

/// XOR a payload with a fresh mask: two shards, neither of which is a fragment.
fn xor_split(payload: &[u8]) -> Vec<Vec<u8>> {
    use rand::RngCore;
    let mut mask = vec![0u8; payload.len()];
    rand::thread_rng().fill_bytes(&mut mask);
    let body: Vec<u8> = mask.iter().zip(payload).map(|(m, p)| m ^ p).collect();
    vec![mask, body]
}

/// Rebuild a payload under a known scheme.
pub fn recover_with(scheme: BondScheme, shards: &[(u8, Vec<u8>)]) -> Option<Vec<u8>> {
    match scheme {
        BondScheme::Xor2 => {
            let a = shards.iter().find(|(i, _)| *i == 0)?;
            let b = shards.iter().find(|(i, _)| *i == 1)?;
            if a.1.len() != b.1.len() {
                return None;
            }
            Some(a.1.iter().zip(&b.1).map(|(x, y)| x ^ y).collect())
        }
        BondScheme::Duplicate2 => shards
            .iter()
            .find(|(i, _)| *i == 0)
            .or_else(|| shards.first())
            .map(|(_, bytes)| bytes.clone()),
        BondScheme::Ramp(params) => l4_rs::decode_ramp(shards, &params),
    }
}

/// Chooses paths and produces bonded shard sets.
#[derive(Debug, Clone)]
pub struct HpebScheduler {
    paths: Vec<PhyPath>,
}

impl HpebScheduler {
    pub fn new(paths: Vec<PhyPath>) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &[PhyPath] {
        &self.paths
    }

    /// Paths that are usable right now.
    pub fn available(&self) -> Vec<&PhyPath> {
        let mut v: Vec<&PhyPath> = self.paths.iter().filter(|p| p.available).collect();
        v.sort_by_key(|p| p.cost);
        v
    }

    /// True when at least two *physically distinct, pinned* paths are live.
    /// Unpinned paths do not count: two sockets that both leave by the default
    /// route are one physical path with extra steps.
    pub fn is_bonded(&self) -> bool {
        let live: Vec<&PhyPath> = self
            .paths
            .iter()
            .filter(|p| p.available && p.is_pinned())
            .collect();
        live.len() >= 2
            && live
                .iter()
                .map(|p| p.local_addr.as_deref())
                .collect::<std::collections::HashSet<_>>()
                .len()
                >= 2
    }

    /// Split `payload` across the live paths.
    ///
    /// The scheme follows the path count, because the number of carriers *is*
    /// the constraint:
    ///
    /// * **two** paths — a 2-of-2 XOR split. Round-robin over three RS(2,1)
    ///   shards put two of them on one carrier, which broke both the "no single
    ///   carrier holds a message" claim and the recovery claim. XOR is 0 %
    ///   overhead and leaks nothing per carrier, but tolerates no outage.
    /// * **three or more** — `(c=1, r=m−2, f=1)` ramp bonding: one carrier learns
    ///   nothing, any one path may drop, rate `1 − 2/m`.
    ///
    /// Errors when fewer than two paths are live, because a "bonded" send over
    /// one path is a lie about redundancy.
    pub fn bond(&self, payload: &[u8]) -> Result<BondedSet, BondError> {
        self.bond_with(payload, BondMode::Confidentiality)
    }

    /// Same, with the two-path trade chosen explicitly.
    pub fn bond_with(&self, payload: &[u8], mode: BondMode) -> Result<BondedSet, BondError> {
        let live = self.available();
        if live.len() < 2 {
            return Err(BondError::NotEnoughPaths { live: live.len() });
        }
        let (scheme, pieces) = match live.len() {
            2 => match mode {
                BondMode::Confidentiality => (BondScheme::Xor2, xor_split(payload)),
                BondMode::Availability => (
                    BondScheme::Duplicate2,
                    vec![payload.to_vec(), payload.to_vec()],
                ),
            },
            n => {
                if n > 255 {
                    return Err(BondError::UnsupportedPathCount { paths: n });
                }
                let shards = n as u8;
                let params = l4_rs::RampParams::new(1, shards - 2, 1)
                    .map_err(|_| BondError::UnsupportedPathCount { paths: n })?;
                let pieces = l4_rs::encode_ramp(payload, &params).map_err(BondError::Encode)?;
                (BondScheme::Ramp(params), pieces)
            }
        };
        let mut out = Vec::with_capacity(pieces.len());
        for (i, shard) in pieces.into_iter().enumerate() {
            let path = &live[i % live.len()];
            out.push(BondedShard {
                interface: path.interface.clone(),
                index: i as u8,
                bytes: shard,
            });
        }
        Ok(BondedSet {
            scheme,
            shards: out,
        })
    }

    /// Mark a path down (or up) as the OS reports interface changes.
    pub fn set_available(&mut self, interface: &str, available: bool) -> bool {
        let mut changed = false;
        for p in self.paths.iter_mut().filter(|p| p.interface == interface) {
            if p.available != available {
                p.available = available;
                changed = true;
            }
        }
        changed
    }

    /// Interfaces currently live — what the dashboard shows as "bonded".
    pub fn live_interfaces(&self) -> Vec<String> {
        self.available()
            .iter()
            .map(|p| p.interface.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondError {
    NotEnoughPaths { live: usize },
    UnsupportedPathCount { paths: usize },
    Encode(String),
}

impl std::fmt::Display for BondError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BondError::NotEnoughPaths { live } => {
                write!(f, "bonding needs 2 live interfaces, {live} available")
            }
            BondError::UnsupportedPathCount { paths } => {
                write!(f, "{paths} paths is outside the ramp code's 3..=255 range")
            }
            BondError::Encode(reason) => write!(f, "bond encoding failed: {reason}"),
        }
    }
}

impl std::error::Error for BondError {}

/// Handover bookkeeping: which interface is preferred, and when it last moved.
///
/// The cooldown exists because real interfaces flap on driver resets and DHCP
/// renewals; without it a "0 ms handover" becomes a switch storm that is worse
/// than staying put. While the cooldown is running, sends continue on the
/// previous interface *and* the shards already in flight on the other one, which
/// is why nothing is lost.
#[derive(Debug, Clone)]
pub struct HandoverState {
    active: Option<String>,
    last_switch: Option<Instant>,
    switches: u64,
    cooldown: Duration,
}

impl HandoverState {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            active: None,
            last_switch: None,
            switches: 0,
            cooldown,
        }
    }

    pub fn active(&self) -> Option<&str> {
        self.active.as_deref()
    }

    pub fn switches(&self) -> u64 {
        self.switches
    }

    fn in_cooldown(&self, now: Instant) -> bool {
        self.last_switch
            .map(|t| now.saturating_duration_since(t) < self.cooldown)
            .unwrap_or(false)
    }

    /// A loss event on `interface`. Returns `true` when this call moved the
    /// active path.
    pub fn note_loss(&mut self, interface: &str, candidates: &[&str], now: Instant) -> bool {
        if self.active.as_deref() != Some(interface) {
            return false; // a loss elsewhere does not move the preferred path
        }
        let next = candidates
            .iter()
            .find(|c| **c != interface)
            .map(|c| c.to_string());
        match next {
            Some(next) if !self.in_cooldown(now) => {
                self.active = Some(next);
                self.last_switch = Some(now);
                self.switches = self.switches.saturating_add(1);
                true
            }
            _ => false,
        }
    }

    /// Preference update when a better interface appears. Same cooldown, so a
    /// returning Wi-Fi does not yank a healthy 5G flow mid-packet.
    pub fn prefer(&mut self, interface: &str, now: Instant) -> bool {
        if self.active.as_deref() == Some(interface) || self.in_cooldown(now) {
            return false;
        }
        self.active = Some(interface.to_string());
        self.last_switch = Some(now);
        self.switches = self.switches.saturating_add(1);
        true
    }
}

// ── Live multipath UDP (one bound socket per path) ────────────────────────

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Split a payload through `HpebScheduler` and send every shard from the UDP
/// socket bound to that shard's path address.
pub fn run_multipath_client(
    connect: &str,
    paths: &[String],
    file: &Path,
    single_source: bool,
) -> Result<(), String> {
    let target: SocketAddr = connect
        .parse()
        .map_err(|e| format!("invalid --connect {connect}: {e}"))?;
    let payload = std::fs::read(file).map_err(|e| format!("read {}: {e}", file.display()))?;
    let checksum = sha256_hex(&payload);
    let phy: Vec<PhyPath> = paths
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            PhyPath::new(&format!("lo-{i}"))
                .pinned(addr)
                .with_cost(i as u8)
        })
        .collect();
    let scheduler = HpebScheduler::new(phy.clone());
    if !scheduler.is_bonded() {
        return Err("need two pinned paths on distinct addresses".into());
    }
    let bonded = scheduler.bond(&payload).map_err(|e| e.to_string())?;
    println!(
        "HPEB client payload={} sha256={} shards={} scheme={} paths={}",
        payload.len(),
        checksum,
        bonded.shards.len(),
        bonded.scheme.describe(),
        paths.join(",")
    );

    let mut sockets: Vec<(&str, UdpSocket, String)> = Vec::new();
    for p in &phy {
        let addr = p.local_addr.as_deref().ok_or("unpinned path")?;
        let bind: SocketAddr = format!("{addr}:0")
            .parse()
            .map_err(|e| format!("invalid path {addr}: {e}"))?;
        let sock = UdpSocket::bind(bind).map_err(|e| format!("bind {addr}: {e}"))?;
        let local = sock.local_addr().map_err(|e| e.to_string())?.to_string();
        sockets.push((&p.interface, sock, local));
    }

    let scheme = bonded.scheme.encode();
    for shard in &bonded.shards {
        // `--single-source` deliberately sends every shard over one binding so
        // the server's refusal path can be exercised; it is not a normal send.
        let (_, sock, local) = if single_source {
            &sockets[0]
        } else {
            sockets
                .iter()
                .find(|(iface, _, _)| *iface == shard.interface)
                .ok_or_else(|| format!("no socket for {}", shard.interface))?
        };
        let mut datagram = Vec::with_capacity(13 + shard.bytes.len());
        datagram.extend_from_slice(&7u64.to_be_bytes());
        datagram.extend_from_slice(&scheme);
        datagram.push(shard.index);
        datagram.extend_from_slice(&shard.bytes);
        sock.send_to(&datagram, target)
            .map_err(|e| format!("send via {}: {e}", shard.interface))?;
        println!(
            "HPEB shard {} iface={} src={} -> {} bytes={}",
            shard.index,
            shard.interface,
            local,
            target,
            shard.bytes.len()
        );
    }
    println!("HPEB client done sha256={checksum}");
    Ok(())
}

/// Receive shards from any source, rebuild through the same AONT+RS path, and
/// report the source addresses each shard actually arrived from.
pub fn run_multipath_server(listen: &str, out: &Path) -> Result<(), String> {
    let sock = UdpSocket::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    println!("HPEB server listening on {listen}");
    let mut buf = vec![0u8; 65_535];
    let mut shards: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut scheme: Option<BondScheme> = None;
    const HEADER: usize = 8 + BondScheme::ENCODED_LEN + 1;
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => return Err(format!("recv: {e}")),
        };
        if n < HEADER {
            continue;
        }
        let parsed = match BondScheme::decode(&buf[8..8 + BondScheme::ENCODED_LEN]) {
            Some(s) => s,
            None => continue,
        };
        if scheme.map(|s| s != parsed).unwrap_or(false) {
            return Err("shards arrived under two different bond schemes".into());
        }
        scheme = Some(parsed);
        let index = buf[8 + BondScheme::ENCODED_LEN];
        if shards.iter().any(|(i, _)| *i == index) {
            continue;
        }
        let source = from.to_string();
        println!(
            "HPEB server shard {} from {} bytes={}",
            index,
            source,
            n - HEADER
        );
        sources.push(source);
        shards.push((index, buf[HEADER..n].to_vec()));
        if shards.len() >= parsed.required() {
            break;
        }
    }
    let scheme = scheme.ok_or("no bonded shard arrived")?;
    let recovered = recover_with(scheme, &shards).ok_or("bonded recovery failed")?;
    std::fs::write(out, &recovered).map_err(|e| format!("write {}: {e}", out.display()))?;
    sources.sort();
    sources.dedup();
    println!(
        "HPEB recovered {} bytes sha256={} distinct_sources={} [{}] out={}",
        recovered.len(),
        sha256_hex(&recovered),
        sources.len(),
        sources.join(","),
        out.display()
    );
    if sources.len() < 2 {
        return Err("all shards arrived from one source binding".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three_paths() -> Vec<PhyPath> {
        vec![
            PhyPath::new("wlan0")
                .pinned("192.168.1.42:0")
                .with_asn(64500)
                .with_cost(10),
            PhyPath::new("rmnet0")
                .pinned("10.64.7.9:0")
                .with_asn(64501)
                .with_cost(50),
            PhyPath::new("starlink0")
                .pinned("100.72.3.4:0")
                .with_asn(64502)
                .with_cost(90),
        ]
    }

    fn two_paths() -> Vec<PhyPath> {
        vec![
            PhyPath::new("wlan0").pinned("192.168.1.42:0").with_cost(10),
            PhyPath::new("rmnet0").pinned("10.64.7.9:0").with_cost(50),
        ]
    }

    #[test]
    fn each_shard_leaves_by_its_own_interface() {
        let sched = HpebScheduler::new(three_paths());
        assert!(sched.is_bonded());
        let bonded = sched
            .bond(b"the whole message, split across three radios")
            .unwrap();
        assert_eq!(bonded.shards.len(), 3);
        assert!(matches!(bonded.scheme, BondScheme::Ramp(_)));
        let ifaces: std::collections::HashSet<&str> =
            bonded.shards.iter().map(|s| s.interface.as_str()).collect();
        assert_eq!(ifaces.len(), 3);
    }

    #[test]
    fn losing_one_interface_loses_nothing() {
        let payload = b"session key rotation at 03:00 UTC; do not drop this";
        let sched = HpebScheduler::new(three_paths());
        let bonded = sched.bond(payload).unwrap();

        // Keep any two of the three and rebuild.
        for drop in 0..3u8 {
            let kept: Vec<(u8, Vec<u8>)> = bonded
                .shards
                .iter()
                .filter(|s| s.index != drop)
                .map(|s| (s.index, s.bytes.clone()))
                .collect();
            let recovered = bonded.recover(&kept).expect("two shards must rebuild");
            assert_eq!(recovered, payload, "dropped shard {drop}");
        }
    }

    #[test]
    fn one_shard_reveals_nothing() {
        let payload = b"TOP_SECRET_PAYLOAD_MARKER_0123456789";
        let sched = HpebScheduler::new(three_paths());
        let bonded = sched.bond(payload).unwrap();
        for shard in &bonded.shards {
            assert!(
                !shard
                    .bytes
                    .windows(8)
                    .any(|w| payload.windows(8).any(|p| p == w)),
                "shard {} leaked plaintext",
                shard.index
            );
        }
        let one = vec![(bonded.shards[0].index, bonded.shards[0].bytes.clone())];
        assert!(bonded.recover(&one).is_none());
    }

    #[test]
    fn two_paths_are_split_in_two_not_three() {
        let payload = b"two carriers cannot hold three shards honestly";
        let sched = HpebScheduler::new(two_paths());
        let bonded = sched.bond(payload).unwrap();

        assert_eq!(bonded.scheme, BondScheme::Xor2);
        assert_eq!(
            bonded.shards.len(),
            2,
            "one shard per carrier, never a third"
        );
        let ifaces: std::collections::HashSet<&str> =
            bonded.shards.iter().map(|s| s.interface.as_str()).collect();
        assert_eq!(ifaces.len(), 2);
        for shard in &bonded.shards {
            assert_ne!(shard.bytes, payload, "neither half may be the plaintext");
            assert!(
                !shard
                    .bytes
                    .windows(8)
                    .any(|w| payload.windows(8).any(|p| p == w)),
                "XOR half {} leaked plaintext",
                shard.index
            );
        }

        let both: Vec<(u8, Vec<u8>)> = bonded
            .shards
            .iter()
            .map(|s| (s.index, s.bytes.clone()))
            .collect();
        assert_eq!(bonded.recover(&both).unwrap(), payload);

        // Zero outage tolerance is the price of zero single-carrier leakage,
        // and it is a refusal, not a corrupt payload.
        assert!(bonded.recover(&both[..1]).is_none());
    }

    #[test]
    fn two_path_availability_mode_survives_either_drop() {
        let payload = b"either radio may vanish";
        let sched = HpebScheduler::new(two_paths());
        let bonded = sched.bond_with(payload, BondMode::Availability).unwrap();
        assert_eq!(bonded.scheme, BondScheme::Duplicate2);
        for shard in &bonded.shards {
            let one = vec![(shard.index, shard.bytes.clone())];
            assert_eq!(bonded.recover(&one).unwrap(), payload);
        }
    }

    #[test]
    fn the_scheme_survives_the_wire() {
        for scheme in [
            BondScheme::Xor2,
            BondScheme::Duplicate2,
            BondScheme::Ramp(l4_rs::RampParams::new(1, 2, 1).unwrap()),
        ] {
            let bytes = scheme.encode();
            assert_eq!(BondScheme::decode(&bytes), Some(scheme));
        }
        assert!(BondScheme::decode(&[9, 0, 0, 0]).is_none());
        assert!(
            BondScheme::decode(&[2, 3, 2, 1]).is_none(),
            "shards < data + masks"
        );
    }

    #[test]
    fn unpinned_paths_do_not_count_as_bonding() {
        let sched = HpebScheduler::new(vec![PhyPath::new("wlan0"), PhyPath::new("rmnet0")]);
        assert!(!sched.is_bonded());
    }

    #[test]
    fn bonding_refuses_a_single_live_path() {
        let mut sched = HpebScheduler::new(three_paths());
        sched.set_available("rmnet0", false);
        sched.set_available("starlink0", false);
        assert_eq!(
            sched.bond(b"x").unwrap_err(),
            BondError::NotEnoughPaths { live: 1 }
        );
    }

    #[test]
    fn handover_moves_once_and_respects_the_cooldown() {
        let t0 = Instant::now();
        let mut h = HandoverState::new(Duration::from_millis(500));
        let live = ["wlan0", "rmnet0"];
        assert!(h.prefer("wlan0", t0));
        assert!(!h.prefer("wlan0", t0), "already active");

        // Loss inside the cooldown does not move yet.
        assert!(!h.note_loss("wlan0", &live, t0 + Duration::from_millis(100)));
        // After the cooldown it moves, once.
        assert!(h.note_loss("wlan0", &live, t0 + Duration::from_millis(600)));
        assert_eq!(h.active(), Some("rmnet0"));
        assert!(!h.note_loss("wlan0", &live, t0 + Duration::from_millis(700)));
        assert_eq!(h.switches(), 2);
    }

    #[test]
    fn loss_on_an_inactive_interface_changes_nothing() {
        let t0 = Instant::now();
        let mut h = HandoverState::new(Duration::ZERO);
        h.prefer("wlan0", t0);
        assert!(!h.note_loss("rmnet0", &["wlan0", "rmnet0"], t0 + Duration::from_secs(1)));
        assert_eq!(h.active(), Some("wlan0"));
    }
}
