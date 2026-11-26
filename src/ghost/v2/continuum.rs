//! Continuum Ladder + `GhostCell-Nano` — six ways to keep a message moving.
//!
//! The WAN path is the fast rung, not the only one. This module defines the
//! 180-byte cell that every rung can carry, the six-rung ladder with an explicit
//! availability decision per rung, a DTN "mule" store for links that are not
//! connected yet, and the UDP send/receive path used by the IP rungs.
//!
//! The cell is fixed at 180 bytes so a LoRa KISS frame, a mesh datagram and a
//! file in a mule bundle all carry the same object:
//!
//! ```text
//! [ cell_id 4 ][ seq 8 ][ sealed 152 ][ poly1305 tag 16 ] = 180 bytes
//! ```
//!
//! `sealed` is XChaCha20-Poly1305 over a 2-byte length prefix plus padding. The
//! nonce is derived from `cell_id ‖ seq`, never random: a DTN bundle can be
//! replayed byte-for-byte and the receiver must decrypt it deterministically,
//! while a changed `seq` produces a different keystream.
//!
//! **What refuses, and why.** Only rungs this build can actually drive are
//! advertised as available:
//!
//! * `MultiPhyIp` and `MeshRelay` — the compiled UDP mesh.
//! * `MuleStore` — a filesystem DTN store with Merkle roots and CRDT union sync.
//!   The roadmap pairs this rung with Wi-Fi Aware and BLE radios; neither has a
//!   portable API in this build, so the radio link is *refused* rather than
//!   silently replaced by a file copy. `--mule-dir` is a removable medium (USB,
//!   SD card) and syncs when it is next mounted.
//! * `StealthWeb` — needs a TLS 1.3 origin and a browser rendezvous. The
//!   `reality` module has the knock and splice decision, not a TLS server.
//! * `LoraKiss` — needs a KISS TNC on a serial port; there is no serial
//!   transport or attached radio here.
//! * `AbosHf` — compiled only with `--features sdr`; otherwise refused.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Total wire size of one cell.
pub const CELL_LEN: usize = 180;
/// Sealed body size.
pub const SEALED_LEN: usize = 152;
/// Authentication tag size.
pub const TAG_LEN: usize = 16;
/// Maximum plaintext that fits in one cell (2-byte length prefix).
pub const MAX_PAYLOAD: usize = SEALED_LEN - 2;
/// A stable domain separator for the nonce derivation.
const NONCE_DOMAIN: &[u8] = b"VB-GHOSTCELL-NANO-V1";

/// One 180-byte DTN cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostCellNano {
    pub cell_id: [u8; 4],
    pub seq: u64,
    pub sealed: [u8; SEALED_LEN],
    pub tag: [u8; TAG_LEN],
}

impl GhostCellNano {
    /// Seal `payload` (never more than [`MAX_PAYLOAD`] bytes).
    pub fn seal(
        key: &[u8; 32],
        cell_id: [u8; 4],
        seq: u64,
        payload: &[u8],
    ) -> Result<Self, String> {
        if payload.len() > MAX_PAYLOAD {
            return Err(format!(
                "payload is {} bytes; one GhostCell-Nano carries at most {MAX_PAYLOAD}",
                payload.len()
            ));
        }
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut body = [0u8; SEALED_LEN];
        body[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        body[2..2 + payload.len()].copy_from_slice(payload);
        let aad = cell_aad(&cell_id, seq);
        let out = cipher
            .encrypt(
                XNonce::from_slice(&cell_nonce(&cell_id, seq)),
                chacha20poly1305::aead::Payload {
                    msg: &body,
                    aad: &aad,
                },
            )
            .map_err(|_| "XChaCha20-Poly1305 sealing failed".to_string())?;
        if out.len() != SEALED_LEN + TAG_LEN {
            return Err("sealed cell has the wrong length".into());
        }
        let mut sealed = [0u8; SEALED_LEN];
        let mut tag = [0u8; TAG_LEN];
        sealed.copy_from_slice(&out[..SEALED_LEN]);
        tag.copy_from_slice(&out[SEALED_LEN..]);
        Ok(Self {
            cell_id,
            seq,
            sealed,
            tag,
        })
    }

    /// Open a cell. A truncated, reordered or tampered cell fails here.
    pub fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut combined = Vec::with_capacity(SEALED_LEN + TAG_LEN);
        combined.extend_from_slice(&self.sealed);
        combined.extend_from_slice(&self.tag);
        let aad = cell_aad(&self.cell_id, self.seq);
        let body = cipher
            .decrypt(
                XNonce::from_slice(&cell_nonce(&self.cell_id, self.seq)),
                chacha20poly1305::aead::Payload {
                    msg: &combined,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                "cell authentication failed (wrong key, reordered, or tampered)".to_string()
            })?;
        if body.len() != SEALED_LEN {
            return Err("cell body has the wrong length".into());
        }
        let len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if len > MAX_PAYLOAD {
            return Err("cell length prefix exceeds the payload budget".into());
        }
        Ok(body[2..2 + len].to_vec())
    }

    /// The exact 180 bytes that cross a rung.
    pub fn to_bytes(&self) -> [u8; CELL_LEN] {
        let mut out = [0u8; CELL_LEN];
        out[..4].copy_from_slice(&self.cell_id);
        out[4..12].copy_from_slice(&self.seq.to_be_bytes());
        out[12..12 + SEALED_LEN].copy_from_slice(&self.sealed);
        out[12 + SEALED_LEN..].copy_from_slice(&self.tag);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != CELL_LEN {
            return Err(format!(
                "a GhostCell-Nano is {CELL_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let mut cell_id = [0u8; 4];
        let mut seq = [0u8; 8];
        let mut sealed = [0u8; SEALED_LEN];
        let mut tag = [0u8; TAG_LEN];
        cell_id.copy_from_slice(&bytes[..4]);
        seq.copy_from_slice(&bytes[4..12]);
        sealed.copy_from_slice(&bytes[12..12 + SEALED_LEN]);
        tag.copy_from_slice(&bytes[12 + SEALED_LEN..]);
        Ok(Self {
            cell_id,
            seq: u64::from_be_bytes(seq),
            sealed,
            tag,
        })
    }
}

fn cell_nonce(cell_id: &[u8; 4], seq: u64) -> [u8; 24] {
    let mut h = Sha256::new();
    h.update(NONCE_DOMAIN);
    h.update(cell_id);
    h.update(seq.to_be_bytes());
    let digest = h.finalize();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

fn cell_aad(cell_id: &[u8; 4], seq: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[..4].copy_from_slice(cell_id);
    aad[4..].copy_from_slice(&seq.to_be_bytes());
    aad
}

// ── Ladder ──────────────────────────────────────────────────────────────────

/// The six rungs, in descending preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    MultiPhyIp,
    MeshRelay,
    StealthWeb,
    MuleStore,
    LoraKiss,
    AbosHf,
}

impl Rung {
    pub const ALL: [Rung; 6] = [
        Rung::MultiPhyIp,
        Rung::MeshRelay,
        Rung::StealthWeb,
        Rung::MuleStore,
        Rung::LoraKiss,
        Rung::AbosHf,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Rung::MultiPhyIp => "multi_phy_ip",
            Rung::MeshRelay => "mesh_relay",
            Rung::StealthWeb => "stealth_web",
            Rung::MuleStore => "mule_store",
            Rung::LoraKiss => "lora_kiss",
            Rung::AbosHf => "abos_hf",
        }
    }

    /// Whether this build can drive the rung, with the reason when it cannot.
    pub fn availability(self) -> (bool, String) {
        match self {
            Rung::MultiPhyIp => (true, "compiled UDP datagram path".into()),
            Rung::MeshRelay => (true, "compiled mesh relay path".into()),
            Rung::StealthWeb => (
                false,
                "needs a TLS 1.3 origin and browser rendezvous; this build has the REALITY knock only"
                    .into(),
            ),
            Rung::MuleStore => (
                true,
                "filesystem/removable-media DTN only; Wi-Fi Aware and BLE radios are refused"
                    .into(),
            ),
            Rung::LoraKiss => (
                false,
                "no KISS TNC serial transport or attached LoRa radio in this build".into(),
            ),
            Rung::AbosHf => (
                false,
                "SDR/ABOS hardware support removed for now".into(),
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RungStatus {
    pub rung: &'static str,
    pub available: bool,
    pub reason: String,
    pub mtu: usize,
}

pub fn ladder() -> Vec<RungStatus> {
    Rung::ALL
        .iter()
        .map(|r| {
            let (available, reason) = r.availability();
            RungStatus {
                rung: r.id(),
                available,
                reason,
                mtu: CELL_LEN,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LadderStep {
    pub rung: &'static str,
    pub cells: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LadderPlan {
    pub steps: Vec<LadderStep>,
    pub cells: usize,
    pub rungs_refused: Vec<&'static str>,
}

/// Build a plan for `bytes` under `max_rungs` rungs.
///
/// A rung that cannot be driven is skipped and named in `rungs_refused`; if no
/// rung is available the call fails with every reason, rather than returning an
/// empty plan that looks like success.
pub fn plan(bytes: usize, max_rungs: usize) -> Result<LadderPlan, String> {
    if bytes == 0 {
        return Err("nothing to carry: payload is empty".into());
    }
    let needed = bytes.div_ceil(MAX_PAYLOAD);
    let mut steps = Vec::new();
    let refused: Vec<&'static str> = Rung::ALL
        .iter()
        .filter(|r| {
            let (available, reason) = r.availability();
            if !available {
                tracing::debug!(rung = r.id(), %reason, "continuum rung refused");
            }
            !available
        })
        .map(|r| r.id())
        .collect();
    for rung in Rung::ALL {
        if steps.len() >= max_rungs.max(1) {
            break;
        }
        let (available, _) = rung.availability();
        if !available {
            continue;
        }
        // Distribute cells across the remaining usable rungs, so a large bundle
        // is not forced through one link while another sits idle.
        steps.push(LadderStep {
            rung: rung.id(),
            cells: 1,
        });
        if steps.len() >= needed {
            break;
        }
    }
    if steps.is_empty() {
        let why: Vec<String> = Rung::ALL
            .iter()
            .map(|r| {
                let (ok, reason) = r.availability();
                format!("{}: {}", r.id(), if ok { "available" } else { &reason })
            })
            .collect();
        return Err(format!("no continuum rung available — {}", why.join("; ")));
    }
    // Spread the remaining cells evenly over the chosen rungs.
    let mut remaining = needed.saturating_sub(steps.len());
    let step_count = steps.len();
    let mut i: usize = 0;
    while remaining > 0 {
        steps[i % step_count].cells = steps[i % step_count].cells.saturating_add(1);
        remaining = remaining.saturating_sub(1);
        i = i.saturating_add(1);
    }
    Ok(LadderPlan {
        cells: needed,
        steps,
        rungs_refused: refused,
    })
}

// ── Mule store (Merkle-CRDT DTN) ────────────────────────────────────────────

/// A content-addressed bundle in a mule store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bundle {
    pub id: String,
    pub len: usize,
    pub created_at: u64,
    pub cell: [u8; 4],
}

/// A directory of bundles. This is the "sneakernet" half of the mule rung: the
/// same contents on a USB stick, an SD card or a synced folder.
#[derive(Debug, Clone)]
pub struct MuleStore {
    dir: PathBuf,
}

impl MuleStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn default_path() -> PathBuf {
        let base = std::env::var("GHOST_CONTINUUM_DIR")
            .or_else(|_| std::env::var("GHOST_DATA_DIR"))
            .unwrap_or_else(|_| ".".to_string());
        Path::new(&base).join("v2").join("mule")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create mule dir {}: {e}", self.dir.display()))
    }

    /// Store a cell's bytes and return its content address.
    pub fn put(&self, bytes: &[u8]) -> Result<Bundle, String> {
        if bytes.len() != CELL_LEN {
            return Err(format!("a bundle carries one {CELL_LEN}-byte cell"));
        }
        self.ensure()?;
        let cell = GhostCellNano::from_bytes(bytes)?;
        let mut h = Sha256::new();
        h.update(bytes);
        let id = hex::encode(h.finalize());
        let path = self.dir.join(format!("{id}.cell"));
        if !path.exists() {
            let tmp = path.with_extension("cell.tmp");
            std::fs::write(&tmp, bytes).map_err(|e| format!("write bundle: {e}"))?;
            std::fs::rename(&tmp, &path).map_err(|e| format!("commit bundle: {e}"))?;
        }
        Ok(Bundle {
            id,
            len: bytes.len(),
            created_at: super::now_secs(),
            cell: cell.cell_id,
        })
    }

    pub fn list(&self) -> Vec<Bundle> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".cell") else {
                continue;
            };
            let Ok(meta) = entry.metadata() else { continue };
            let mut cell = [0u8; 4];
            if let Ok(bytes) = std::fs::read(entry.path()) {
                if bytes.len() == CELL_LEN {
                    cell.copy_from_slice(&bytes[..4]);
                }
            }
            out.push(Bundle {
                id: id.to_string(),
                len: meta.len() as usize,
                created_at: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                cell,
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn get(&self, id: &str) -> Option<Vec<u8>> {
        if !id.chars().all(|c| c.is_ascii_hexdigit()) || id.len() != 64 {
            return None;
        }
        std::fs::read(self.dir.join(format!("{id}.cell"))).ok()
    }

    /// Merkle root over sorted bundle ids. Empty stores have the all-zero root.
    pub fn merkle_root(&self) -> String {
        let mut level: Vec<[u8; 32]> = self
            .list()
            .iter()
            .map(|b| {
                let mut h = Sha256::new();
                h.update(b"VB-MULE-LEAF-V1");
                h.update(b.id.as_bytes());
                let d = h.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                out
            })
            .collect();
        if level.is_empty() {
            return hex::encode([0u8; 32]);
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                let mut h = Sha256::new();
                h.update(b"VB-MULE-NODE-V1");
                h.update(pair[0]);
                h.update(right);
                let d = h.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                next.push(out);
            }
            level = next;
        }
        hex::encode(level[0])
    }

    /// CRDT union sync: copy every bundle this store lacks from `other`.
    ///
    /// Ids are content hashes, so union is commutative, associative and
    /// idempotent; two mules that meet twice end with the same set.
    pub fn sync_from(&self, other: &MuleStore) -> Result<usize, String> {
        self.ensure()?;
        let mut copied: usize = 0;
        for bundle in other.list() {
            if self.get(&bundle.id).is_some() {
                continue;
            }
            if let Some(bytes) = other.get(&bundle.id) {
                let tmp = self.dir.join(format!("{}.cell.tmp", bundle.id));
                std::fs::write(&tmp, &bytes).map_err(|e| format!("copy bundle: {e}"))?;
                std::fs::rename(&tmp, self.dir.join(format!("{}.cell", bundle.id)))
                    .map_err(|e| format!("commit bundle: {e}"))?;
                copied = copied.saturating_add(1);
            }
        }
        Ok(copied)
    }
}

// ── UDP path ────────────────────────────────────────────────────────────────

pub async fn send_cell(
    sock: &UdpSocket,
    dst: SocketAddr,
    cell: &GhostCellNano,
) -> std::io::Result<usize> {
    sock.send_to(&cell.to_bytes(), dst).await
}

/// Receive one cell with a bounded wait.
pub async fn recv_cell(sock: &UdpSocket, timeout_ms: u64) -> Result<GhostCellNano, String> {
    let mut buf = [0u8; CELL_LEN + 64];
    let (n, _) = tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf))
        .await
        .map_err(|_| format!("no cell arrived within {timeout_ms} ms"))?
        .map_err(|e| format!("recv: {e}"))?;
    GhostCellNano::from_bytes(&buf[..n])
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoReport {
    pub cells_sent: usize,
    pub cells_received: usize,
    pub bytes_on_wire: usize,
    pub merkle_before: String,
    pub merkle_after: String,
    pub bundles_merged: usize,
    pub payloads_ok: bool,
}

/// Loopback proof for `ggn ladder --demo`: real UDP sockets, real sealing, real
/// Merkle union. No hardware rung is involved, and none is claimed.
pub async fn loopback_demo() -> Result<DemoReport, String> {
    let key = [9u8; 32];
    let receiver = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind receiver: {e}"))?;
    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind sender: {e}"))?;
    let dst = receiver.local_addr().map_err(|e| format!("addr: {e}"))?;

    let payloads = [
        b"rung-1".as_slice(),
        b"rung-2".as_slice(),
        b"rung-3".as_slice(),
    ];
    let mut sent = Vec::new();
    for (i, payload) in payloads.iter().enumerate() {
        let cell = GhostCellNano::seal(
            &key,
            [0xAB, 0xCD, 0xEF, i as u8],
            (i as u64).saturating_add(1),
            payload,
        )?;
        send_cell(&sender, dst, &cell)
            .await
            .map_err(|e| format!("send: {e}"))?;
        sent.push(cell);
    }

    let stamp = format!(
        "{}-{}-{}",
        std::process::id(),
        super::now_secs(),
        rand::random::<u16>()
    );
    let base = std::env::temp_dir().join(format!("vb-mule-{stamp}"));
    let a = MuleStore::new(base.join("a"));
    let b = MuleStore::new(base.join("b"));
    for cell in &sent {
        a.put(&cell.to_bytes())?;
    }
    let merkle_before = a.merkle_root();
    // Only the first cell reaches the second mule; sync must complete the set.
    b.put(&sent[0].to_bytes())?;
    let merged = b.sync_from(&a)?;
    let merkle_after = b.merkle_root();

    let mut received: usize = 0;
    let mut ok = true;
    for (i, expected) in payloads.iter().enumerate() {
        let cell = recv_cell(&receiver, 2_000).await?;
        let plain = cell.open(&key)?;
        ok &= plain == *expected;
        ok &= cell.seq == (i as u64).saturating_add(1);
        received = received.saturating_add(1);
    }
    let _ = std::fs::remove_dir_all(&base);

    Ok(DemoReport {
        cells_sent: sent.len(),
        cells_received: received,
        bytes_on_wire: sent.len().saturating_mul(CELL_LEN),
        merkle_before,
        merkle_after,
        bundles_merged: merged,
        payloads_ok: ok,
    })
}

pub fn status_json() -> serde_json::Value {
    let store = MuleStore::new(MuleStore::default_path());
    let bundles = store.list();
    serde_json::json!({
        "cell_bytes": CELL_LEN,
        "payload_bytes": MAX_PAYLOAD,
        "rungs": ladder(),
        "mule": {
            "dir": store.dir().display().to_string(),
            "bundles": bundles.len(),
            "merkle_root": store.merkle_root(),
            "sync": "content-addressed CRDT union",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cell_is_exactly_180_bytes_and_round_trips() {
        let key = [3u8; 32];
        let cell = GhostCellNano::seal(&key, [1, 2, 3, 4], 42, b"hello continuum").unwrap();
        let bytes = cell.to_bytes();
        assert_eq!(bytes.len(), 180);
        let parsed = GhostCellNano::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, cell);
        assert_eq!(parsed.open(&key).unwrap(), b"hello continuum");
    }

    #[test]
    fn tampering_and_reordering_are_refused() {
        let key = [3u8; 32];
        let cell = GhostCellNano::seal(&key, [1, 2, 3, 4], 1, b"sealed").unwrap();
        let mut bytes = cell.to_bytes();
        bytes[20] ^= 1;
        assert!(GhostCellNano::from_bytes(&bytes)
            .unwrap()
            .open(&key)
            .is_err());
        let mut reordered = cell.clone();
        reordered.seq = 2;
        assert!(reordered.open(&key).is_err());
        assert!(GhostCellNano::seal(&key, [0; 4], 1, &[0u8; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn unavailable_rungs_are_named_and_skipped() {
        let plan = plan(400, 6).unwrap();
        assert!(plan.cells >= 3);
        assert!(plan.rungs_refused.contains(&"lora_kiss"));
        assert!(plan.rungs_refused.contains(&"stealth_web"));
        assert!(plan.steps.iter().all(|s| {
            let r = Rung::ALL.iter().find(|r| r.id() == s.rung).unwrap();
            r.availability().0
        }));
        let table = ladder();
        assert_eq!(table.len(), 6);
        let expected_available = 3;
        assert_eq!(
            table.iter().filter(|r| r.available).count(),
            expected_available
        );
    }

    #[test]
    fn an_empty_plan_is_refused() {
        // Zero bytes is not a plan, and the refusal must say why.
        let err = plan(0, 6).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn mule_union_converges_and_roots_match() {
        let base = std::env::temp_dir().join(format!(
            "vb-mule-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let a = MuleStore::new(base.join("a"));
        let b = MuleStore::new(base.join("b"));
        let key = [7u8; 32];
        for i in 0..3u64 {
            let cell =
                GhostCellNano::seal(&key, [9, 9, 9, 9], i, format!("cell-{i}").as_bytes()).unwrap();
            a.put(&cell.to_bytes()).unwrap();
        }
        assert_ne!(a.merkle_root(), b.merkle_root());
        assert_eq!(b.sync_from(&a).unwrap(), 3);
        assert_eq!(a.merkle_root(), b.merkle_root());
        assert_eq!(b.sync_from(&a).unwrap(), 0, "union is idempotent");
        assert!(a.put(&[0u8; 10]).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn udp_loopback_carries_three_cells() {
        let report = loopback_demo().await.unwrap();
        assert_eq!(report.cells_sent, 3);
        assert_eq!(report.cells_received, 3);
        assert!(report.payloads_ok);
        assert_eq!(report.bytes_on_wire, 540);
        assert_eq!(report.bundles_merged, 2);
        assert_eq!(report.merkle_before, report.merkle_after);
    }
}
