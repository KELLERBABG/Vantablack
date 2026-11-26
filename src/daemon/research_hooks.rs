//! Live daemon wiring for the seven Tier 1 modules in `docs/DORMANT_MODULES.md`.
//!
//! Each submodule owns the daemon-side state for one dormant primitive and has a
//! named hook in the running packet path. Nothing here re-implements a primitive:
//! the research module does the cryptography and this module only decides *when*
//! the daemon calls it and what the result means for traffic.
//!
//! | Primitive | Live hook |
//! |---|---|
//! | [`braid`] | every registered session braids a transition, persisted before it is published; the PDU is gossiped on auth and PEX beats; a fork proof revokes the peer |
//! | [`beacon_wire`] | every PEX beat contributes an entropy share; the threshold output drives the beacon grid epoch |
//! | [`vault`] | DTN bundles are stored as blind dead-drop chunks, erasure-coded and sealed under an erosion epoch |
//! | [`voucher`] | relay forwarding is charged against a presented bandwidth voucher |
//! | [`worlds`] | a bonded link probes its own surviving path subsets with a polysemic world code |
//!
//! The hooks are no-ops when their env toggle is off, except the vault (on by
//! default in a `research` build) and the braid (always on in a `research` build,
//! because it costs one 200-byte PDU per session).

use crate::*;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use dashmap::DashMap;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use vantablack::ghost::net::{braid_identity, dead_drop, entropy_beacon, mesh_archive, polysemy};
use vantablack::ghost::v2::erosion;

/// Wall-clock seconds, the clock every epoch in this module is expressed on.
fn now_secs() -> u64 {
    super::beacon::unix_now_secs() as u64
}

fn short(id: &[u8; 32]) -> String {
    hex::encode(&id[..8])
}

/// Whether an env toggle is on. `default` covers hooks that are on in a
/// `research` build unless explicitly disabled.
fn toggle(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => default,
    }
}

/// Send one control payload over `peer_fp`'s session, sealed exactly like any
/// other payload. `false` when there is no session to seal for.
async fn deliver(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let Some(sess) = nc.sessions.get(peer_fp) else {
        return false;
    };
    let ctx = SealCtx::from_session(&sess);
    drop(sess);
    let frame = seal_single(&ctx, payload);
    send_frame_to_peer(nc, sock, src, fallback, peer_fp, frame).await;
    true
}

/// Dispatch a decrypted payload to whichever research control PDU claims it.
///
/// Returns `true` when the payload was a research PDU and must not be handled as
/// application traffic. Called before the tunnel, relay and SOCKS branches.
pub(crate) fn handle_control(from_fp: &str, payload: &[u8]) -> bool {
    braid::handle_pdu(from_fp, payload)
        || beacon_wire::handle_pdu(from_fp, payload)
        || voucher::handle_pdu(from_fp, payload)
}

/// The immediate post-authentication burst: advertise the current braid tip and
/// present a bandwidth voucher. Both are idempotent control PDUs; the peer's
/// handlers are what give them meaning.
pub(crate) async fn session_established(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
) {
    if let Some(tip) = braid::tip_payload(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &tip).await;
    }
    if let Some(present) = voucher::present_payload(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &present).await;
    }
}

/// The periodic PEX-beat gossip: re-advertise the braid tip, contribute entropy
/// for this round, and keep the relay voucher current.
pub(crate) async fn gossip_beat(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
) {
    if let Some(tip) = braid::tip_payload(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &tip).await;
    }
    let our_fp = nc.fingerprint();
    let share = beacon_wire::share_payload(&our_fp);
    deliver(nc, sock, src, fallback, peer_fp, &share).await;
    if let Some(present) = voucher::present_payload(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &present).await;
    }
}

// ══════════════════════════════════════════════════════════════════
// 1. braid_identity — epidemic clone suicide on the live session path
// ══════════════════════════════════════════════════════════════════

pub(crate) mod braid {
    use super::*;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use zeroize::Zeroize;

    /// Control PDU magic. Fourteen bytes, matching every other control magic.
    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_BRAID___";

    /// This node's own chain for one peer.
    ///
    /// Deliberately a different map from [`chains`]: ingesting a peer's
    /// transition must not be able to create — and a later session then advance —
    /// a lock of ours. The two directions share a fingerprint but not state.
    struct OurBraid {
        /// This node's rotating key chain for this peer. The seed is stable, so
        /// two clones of this process derive the same key, and every restart
        /// must continue the persisted one rather than re-derive genesis.
        chain: braid_identity::BraidLock,
        /// The last transition we *durably* published, re-gossiped on PEX beats.
        last: Option<braid_identity::Transition>,
    }

    impl OurBraid {
        fn genesis(our_fp: &str, peer_fp: &str) -> Self {
            Self {
                chain: braid_identity::BraidLock::from_seed(seed_for(our_fp, peer_fp)),
                last: None,
            }
        }
    }

    /// Our chains, one per peer.
    fn ours() -> &'static DashMap<String, Mutex<OurBraid>> {
        static OURS: OnceLock<DashMap<String, Mutex<OurBraid>>> = OnceLock::new();
        OURS.get_or_init(DashMap::new)
    }

    /// The verifier for what each peer has shown us: one accepted child per
    /// parent key. Nothing here holds a secret, so an inbound PDU can only ever
    /// grow this map.
    fn chains() -> &'static DashMap<String, Mutex<braid_identity::BraidChain>> {
        static CHAINS: OnceLock<DashMap<String, Mutex<braid_identity::BraidChain>>> = OnceLock::new();
        CHAINS.get_or_init(DashMap::new)
    }

    /// Fingerprints revoked by a clone proof, with the key that equivocated.
    fn revoked() -> &'static DashMap<String, [u8; 32]> {
        static REVOKED: OnceLock<DashMap<String, [u8; 32]>> = OnceLock::new();
        REVOKED.get_or_init(DashMap::new)
    }

    /// A braid chain is only as strong as its seed being *this* node's. Mixing
    /// both fingerprints means two peers derive different chains and a clone of
    /// the process derives the same one — which is what makes a fork possible.
    pub(super) fn seed_for(our_fp: &str, peer_fp: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VB-BRAID-DAEMON-SEED-V1");
        hasher.update(our_fp.as_bytes());
        hasher.update(peer_fp.as_bytes());
        hasher.finalize().into()
    }

    // ── durability ─────────────────────────────────────────────────────
    //
    // The seed is deterministic, so a process that starts from `from_seed`
    // after a restart holds the genesis key again. If it then advances, it
    // signs a *second* child of a key its peers already accepted — byte for
    // byte what a clone does, and grounds for revocation. The primitive leaves
    // persistence to the caller on purpose: `secret_state()` hands back
    // `(secret, braid, height)` so the new state can be fsynced before the
    // transition that belongs to it is sent. This is that caller.

    /// Subdirectory of the app's data dir holding one record per peer.
    const STATE_DIR: &str = "braid";
    const RECORD_MAGIC: &[u8; 8] = b"VBBRAID1";
    const RECORD_VERSION: u8 = 1;

    /// One peer's chain as it must exist on disk. `secret` is the current
    /// signing key; `last` is the certificate it already published, kept so a
    /// restart can re-gossip the same tip (a `Stale` at the peer) and so the
    /// restored key can be checked against the chain the peer accepted.
    struct Record {
        our_fp: String,
        peer_fp: String,
        height: u64,
        secret: [u8; 32],
        braid: [u8; 32],
        last: Option<braid_identity::Transition>,
    }

    impl Drop for Record {
        fn drop(&mut self) {
            self.secret.zeroize();
        }
    }

    fn state_root() -> &'static OnceLock<PathBuf> {
        static ROOT: OnceLock<PathBuf> = OnceLock::new();
        &ROOT
    }

    /// The directory advances fsync into. `None` until [`init`] runs, which is
    /// what keeps a research build's chains in memory when no daemon booted
    /// (unit tests) instead of writing into a developer's data directory.
    fn root() -> Option<&'static Path> {
        state_root().get().map(PathBuf::as_path)
    }

    /// Restore every chain an earlier process persisted, then point future
    /// advances at the same directory.
    ///
    /// Call once, at boot, before a session can register. A build that never
    /// calls this keeps its chains in memory only; the daemon always calls it.
    pub(crate) fn init(our_fp: &str) -> usize {
        if state_root().get().is_some() {
            return 0;
        }
        let root = vantablack::ghost::paths::data_dir().join(STATE_DIR);
        if let Err(error) = std::fs::create_dir_all(&root) {
            // Keep the directory configured anyway: every write will fail and
            // no transition will be published, which is the safe failure.
            tracing::error!(
                dir = %root.display(),
                %error,
                "braid: cannot create the chain directory — no transition will be published"
            );
        }
        let _ = state_root().set(root.clone());
        let restored = restore_from(&root, our_fp);
        if restored > 0 {
            tracing::info!(
                chains = restored,
                dir = %root.display(),
                "braid: restored persisted identity chains — this boot continues them, it does not replay genesis"
            );
        }
        let verifiers = restore_verifiers(&root);
        if verifiers > 0 {
            tracing::info!(
                verifiers,
                dir = %root.display(),
                "braid: restored peer verifiers and revocations — a restart does not forget a fork"
            );
        }
        restored
    }

    fn record_path(root: &Path, our_fp: &str, peer_fp: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(b"VB-BRAID-DAEMON-RECORD-V1");
        hasher.update(our_fp.as_bytes());
        hasher.update([0u8]);
        hasher.update(peer_fp.as_bytes());
        let digest = hex::encode(hasher.finalize());
        root.join(format!("{}.braid", &digest[..32]))
    }

    fn encode_record(record: &Record) -> Vec<u8> {
        let our = record.our_fp.as_bytes();
        let peer = record.peer_fp.as_bytes();
        let mut out = Vec::with_capacity(
            13 + our.len() + peer.len() + 73 + braid_identity::TRANSITION_BYTES,
        );
        out.extend_from_slice(RECORD_MAGIC);
        out.push(RECORD_VERSION);
        out.extend_from_slice(&(our.len() as u16).to_be_bytes());
        out.extend_from_slice(&(peer.len() as u16).to_be_bytes());
        out.extend_from_slice(our);
        out.extend_from_slice(peer);
        out.extend_from_slice(&record.height.to_be_bytes());
        out.extend_from_slice(&record.secret);
        out.extend_from_slice(&record.braid);
        match &record.last {
            Some(transition) => {
                out.push(1);
                out.extend_from_slice(&transition.to_bytes());
            }
            None => out.push(0),
        }
        out
    }

    fn decode_record(bytes: &[u8]) -> Option<Record> {
        const HEADER: usize = 13; // magic 8 + version 1 + our_len 2 + peer_len 2
        if bytes.len() < HEADER || &bytes[..8] != RECORD_MAGIC || bytes[8] != RECORD_VERSION {
            return None;
        }
        let our_len = u16::from_be_bytes(bytes[9..11].try_into().ok()?) as usize;
        let peer_len = u16::from_be_bytes(bytes[11..13].try_into().ok()?) as usize;
        let our_end = HEADER.checked_add(our_len)?;
        let peer_end = our_end.checked_add(peer_len)?;
        let tail = peer_end.checked_add(72)?;
        if bytes.len() <= tail {
            return None;
        }
        let our_fp = std::str::from_utf8(bytes.get(HEADER..our_end)?).ok()?.to_string();
        let peer_fp = std::str::from_utf8(bytes.get(our_end..peer_end)?).ok()?.to_string();
        if our_fp.is_empty() || peer_fp.is_empty() {
            return None;
        }
        let height = u64::from_be_bytes(bytes.get(peer_end..peer_end + 8)?.try_into().ok()?);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(bytes.get(peer_end + 8..peer_end + 40)?);
        let mut braid = [0u8; 32];
        braid.copy_from_slice(bytes.get(peer_end + 40..peer_end + 72)?);
        let last = match bytes[tail] {
            0 if bytes.len() == tail + 1 => None,
            1 if bytes.len() == tail + 1 + braid_identity::TRANSITION_BYTES => {
                Some(braid_identity::Transition::from_bytes(bytes.get(tail + 1..)?)?)
            }
            _ => return None,
        };
        Some(Record {
            our_fp,
            peer_fp,
            height,
            secret,
            braid,
            last,
        })
    }

    /// Persist one record with fsync-before-publish ordering: the bytes are
    /// flushed to a temporary file and `sync_all`ed, the old record is replaced
    /// by an atomic rename, and the directory entry is synced where the platform
    /// has directory handles (Windows does not; the rename is the durability
    /// point there).
    fn write_record(root: &Path, record: &Record) -> std::io::Result<()> {
        std::fs::create_dir_all(root)?;
        let path = record_path(root, &record.our_fp, &record.peer_fp);
        let tmp = path.with_extension("braid.tmp");
        let mut bytes = encode_record(record);
        let result: std::io::Result<()> = (|| {
            let mut file = std::fs::File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            #[cfg(unix)]
            if let Ok(dir) = std::fs::File::open(root) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        bytes.zeroize();
        result
    }

    /// Records that failed their own integrity check. A quarantined peer gets
    /// no further transition: continuing a chain we cannot reconstruct would
    /// either fork the key the peer accepted or sign from one it never saw.
    fn quarantined() -> &'static DashMap<String, &'static str> {
        static QUARANTINED: OnceLock<DashMap<String, &'static str>> = OnceLock::new();
        QUARANTINED.get_or_init(DashMap::new)
    }

    /// Load every record in `root` that belongs to `our_fp`, returning how many
    /// chains were continued. Only our own fingerprint's records are restored:
    /// a record written under a different long-term identity is not ours.
    pub(crate) fn restore_from(root: &Path, our_fp: &str) -> usize {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => return 0,
        };
        let mut restored = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("braid") {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::error!(file = %path.display(), %error, "braid: chain record unreadable — a chain may restart from genesis");
                    continue;
                }
            };
            let Some(record) = decode_record(&bytes) else {
                tracing::error!(file = %path.display(), "braid: malformed chain record — a chain may restart from genesis");
                continue;
            };
            if record.our_fp != our_fp {
                continue;
            }
            let lock = braid_identity::BraidLock::restore(record.secret, record.braid, record.height);
            if let Some(last) = &record.last {
                // The persisted secret must be the key that `last` handed
                // authority to, at the height `last` claims, and `last` must
                // verify. A record that fails this cannot be continued safely:
                // signing from it would fork the key the peer already accepted,
                // and signing around it would rewrite the chain.
                if last.height != record.height
                    || last.next_pk != lock.identity()
                    || !last.verify()
                {
                    tracing::error!(
                        peer = %record.peer_fp,
                        file = %path.display(),
                        "braid: chain record fails its own certificate — peer quarantined"
                    );
                    quarantined().insert(
                        record.peer_fp.clone(),
                        "persisted chain record failed its certificate",
                    );
                    continue;
                }
            }
            ours().insert(
                record.peer_fp.clone(),
                Mutex::new(OurBraid {
                    chain: lock,
                    last: record.last.clone(),
                }),
            );
            restored += 1;
        }
        restored
    }

    // ── verifier durability ────────────────────────────────────────────
    //
    // Our own chains are records; what a peer showed us is a journal. Keeping
    // the two apart means an inbound PDU can append to a verifier without ever
    // touching a signing key, and replay needs no secret material at all.

    const JOURNAL_TRANSITION: u8 = 1;
    const JOURNAL_REVOKED: u8 = 2;

    fn verifier_dir(root: &Path) -> PathBuf {
        root.join("peers")
    }

    /// Fingerprints become file names here, so accept only the shape a real one
    /// has. Anything else is not journaled rather than trusted as a path.
    fn valid_peer_fp(peer_fp: &str) -> bool {
        !peer_fp.is_empty()
            && peer_fp.len() <= 64
            && peer_fp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// Append one verifier frame and fsync it. A fork proof must be on disk
    /// before the handler returns: that is what makes "this peer forked"
    /// outlive the process that learned it.
    fn append_journal(
        root: &Path,
        peer_fp: &str,
        kind: u8,
        body: &[u8],
    ) -> std::io::Result<()> {
        if !valid_peer_fp(peer_fp) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "peer fingerprint is not a safe file name",
            ));
        }
        let dir = verifier_dir(root);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{peer_fp}.journal"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut frame = Vec::with_capacity(1 + body.len());
        frame.push(kind);
        frame.extend_from_slice(body);
        file.write_all(&frame)?;
        file.sync_all()
    }

    /// Rebuild one peer's verifier from its journal. A torn tail (a crash in the
    /// middle of an append) ends replay at the last complete frame; a frame that
    /// does not verify ends it with an error, because everything after it was
    /// written by a process whose view we can no longer trust.
    fn replay_journal(peer_fp: &str, path: &Path) -> Option<braid_identity::BraidChain> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(peer = %peer_fp, %error, "braid: verifier journal unreadable");
                return None;
            }
        };
        let mut chain = braid_identity::BraidChain::new();
        let mut pos = 0usize;
        let mut frames = 0usize;
        while pos < bytes.len() {
            let kind = bytes[pos];
            let body_len = match kind {
                JOURNAL_TRANSITION => braid_identity::TRANSITION_BYTES,
                JOURNAL_REVOKED => 32,
                other => {
                    tracing::error!(
                        peer = %peer_fp,
                        kind = other,
                        "braid: unknown verifier journal frame — remainder ignored"
                    );
                    break;
                }
            };
            let start = pos + 1;
            let end = start + body_len;
            if end > bytes.len() {
                tracing::warn!(
                    peer = %peer_fp,
                    dropped_bytes = bytes.len() - pos,
                    "braid: torn verifier journal tail ignored"
                );
                break;
            }
            let body = &bytes[start..end];
            match kind {
                JOURNAL_TRANSITION => {
                    let Some(transition) = braid_identity::Transition::from_bytes(body) else {
                        tracing::error!(peer = %peer_fp, "braid: malformed journaled transition — remainder ignored");
                        break;
                    };
                    if matches!(
                        chain.accept(&transition),
                        braid_identity::BraidVerdict::Invalid
                    ) {
                        tracing::error!(peer = %peer_fp, "braid: journaled transition does not verify — remainder ignored");
                        break;
                    }
                }
                _ => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(body);
                    chain.revoke(&key);
                    revoked().insert(peer_fp.to_string(), key);
                }
            }
            pos = end;
            frames += 1;
        }
        if frames == 0 {
            None
        } else {
            Some(chain)
        }
    }

    /// Restore every verifier journal under `root`, returning how many chains
    /// were rebuilt. The peer name is the file stem, so no header is needed and
    /// a journal cannot claim to be another peer's.
    pub(crate) fn restore_verifiers(root: &Path) -> usize {
        let entries = match std::fs::read_dir(verifier_dir(root)) {
            Ok(entries) => entries,
            Err(_) => return 0,
        };
        let mut restored = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("journal") {
                continue;
            }
            let Some(peer_fp) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if !valid_peer_fp(peer_fp) {
                continue;
            }
            if let Some(chain) = replay_journal(peer_fp, &path) {
                chains().insert(peer_fp.to_string(), Mutex::new(chain));
                restored += 1;
            }
        }
        restored
    }

    fn framed(transition: &braid_identity::Transition) -> Vec<u8> {
        let mut payload = Vec::with_capacity(MAGIC.len() + braid_identity::TRANSITION_BYTES);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&transition.to_bytes());
        payload
    }

    /// Advance this node's chain with a transcript and publish the tip.
    pub(crate) fn advance_and_tip(
        our_fp: &str,
        peer_fp: &str,
        transcript: &[u8],
    ) -> Option<Vec<u8>> {
        // No boot restore, no signature. A transition signed before the state
        // directory exists cannot be continued after a restart, so the next
        // process would sign a sibling of it — the clone proof this module is
        // supposed to make impossible for an honest node.
        let Some(root) = root() else {
            tracing::error!(
                peer = %peer_fp,
                "braid: state directory not initialized — refusing to publish a non-durable transition"
            );
            return None;
        };
        advance_with(Some(root), our_fp, peer_fp, transcript)
    }

    /// [`advance_and_tip`] with an explicit state directory, so the restart and
    /// failed-fsync paths are testable without touching the process-wide root.
    /// `None` keeps the chain in memory only.
    pub(crate) fn advance_with(
        root: Option<&Path>,
        our_fp: &str,
        peer_fp: &str,
        transcript: &[u8],
    ) -> Option<Vec<u8>> {
        let blocked = quarantined().get(peer_fp).map(|reason| *reason.value());
        if let Some(reason) = blocked {
            tracing::warn!(
                peer = %peer_fp,
                reason,
                "braid: chain quarantined — transition withheld"
            );
            return None;
        }
        // Read the population *before* taking a shard write lock: DashMap's
        // `len` walks every shard, and doing that from inside an entry guard is
        // a self-deadlock.
        let peers_live = ours().len().max(2);
        let guard = ours()
            .entry(peer_fp.to_string())
            .or_insert_with(|| Mutex::new(OurBraid::genesis(our_fp, peer_fp)));
        let mut peer = guard.lock();
        let transition = peer.chain.advance(transcript);

        // The durability contract: the *new* secret, braid and height are on
        // disk before the transition they belong to is handed to a sender. A
        // restart then continues this key instead of signing a sibling of a key
        // a peer already accepted.
        if let Some(root) = root {
            let (secret, braid, height) = peer.chain.secret_state();
            let record = Record {
                our_fp: our_fp.to_string(),
                peer_fp: peer_fp.to_string(),
                height,
                secret,
                braid,
                last: Some(transition.clone()),
            };
            if let Err(error) = write_record(root, &record) {
                tracing::error!(
                    peer = %peer_fp,
                    %error,
                    "braid: durable write failed — transition withheld rather than risking a fork"
                );
                return None;
            }
        }

        peer.last = Some(transition.clone());
        // The theorem's collision bound, logged where an operator can see it:
        // how many gossip rounds a clone needs to be caught.
        tracing::info!(
            peer = %peer_fp,
            height = transition.height,
            parent = %short(&transition.parent_pk),
            next = %short(&transition.next_pk),
            braid = %short(&transition.braid),
            wire_bytes = braid_identity::TRANSITION_BYTES,
            durable = root.is_some(),
            gossip_rounds = ?braid_identity::gossip_rounds_to_collision(peers_live, 4, 1e-6),
            "braid: session braided into the identity chain"
        );
        Some(framed(&transition))
    }

    /// The last transition we published, re-sent on a PEX beat. A replay is
    /// `Stale` at the peer, which is the correct answer and costs one frame.
    pub(crate) fn tip_payload(peer_fp: &str) -> Option<Vec<u8>> {
        let guard = ours().get(peer_fp)?;
        let peer = guard.lock();
        Some(framed(peer.last.as_ref()?))
    }

    /// Ingest a gossiped transition. Returns `true` when the payload was a braid
    /// PDU (whether or not it verified).
    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> bool {
        handle_pdu_at(root(), from_fp, payload)
    }

    /// [`handle_pdu`] with an explicit durable root, so restart replay is
    /// testable without the process-wide boot state.
    pub(crate) fn handle_pdu_at(root: Option<&Path>, from_fp: &str, payload: &[u8]) -> bool {
        if !payload.starts_with(MAGIC) {
            return false;
        }
        let body = &payload[MAGIC.len()..];
        let Some(transition) = braid_identity::Transition::from_bytes(body) else {
            tracing::warn!(peer = %from_fp, bytes = body.len(), "braid: malformed transition dropped");
            return true;
        };
        // Only the peer's verifier is touched here. Our own chain for a peer is
        // created solely by our own durable advance, so a transition arriving
        // from the network can never seed — or advance — a lock of ours.
        let guard = chains().entry(from_fp.to_string()).or_default();
        let mut chain = guard.lock();
        let verdict = chain.accept(&transition);

        // Journal what the verdict changed: a new child, or a fork proof. A
        // restart that forgot the fork would hand the peer a clean slate.
        if let Some(root) = root {
            let frame = match &verdict {
                braid_identity::BraidVerdict::Extended => {
                    Some((JOURNAL_TRANSITION, transition.to_bytes().to_vec()))
                }
                braid_identity::BraidVerdict::Fork(proof) => {
                    Some((JOURNAL_REVOKED, proof.equivocating_key().to_vec()))
                }
                _ => None,
            };
            if let Some((kind, body)) = frame {
                if let Err(error) = append_journal(root, from_fp, kind, &body) {
                    tracing::error!(
                        peer = %from_fp,
                        %error,
                        "braid: verifier journal write failed — a fork may not survive a restart"
                    );
                }
            }
        } else {
            tracing::warn!(
                peer = %from_fp,
                "braid: verifier state is not durable yet — journal write skipped"
            );
        }

        match &verdict {
            braid_identity::BraidVerdict::Extended => tracing::info!(
                peer = %from_fp,
                height = transition.height,
                next = %short(&transition.next_pk),
                "braid: peer identity extended"
            ),
            braid_identity::BraidVerdict::Stale => tracing::debug!(
                peer = %from_fp,
                height = transition.height,
                "braid: transition already seen"
            ),
            braid_identity::BraidVerdict::Fork(proof) => {
                let equivocating = proof.equivocating_key();
                revoked().insert(from_fp.to_string(), equivocating);
                tracing::warn!(
                    peer = %from_fp,
                    equivocating_key = %short(&equivocating),
                    proof_bytes = 2 * braid_identity::TRANSITION_BYTES,
                    "braid: clone-suicide proof accepted — peer identity revoked"
                );
            }
            braid_identity::BraidVerdict::Revoked(key) => {
                revoked().insert(from_fp.to_string(), *key);
                tracing::warn!(peer = %from_fp, key = %short(key), "braid: transition from an already-revoked key");
            }
            braid_identity::BraidVerdict::Invalid => {
                tracing::warn!(peer = %from_fp, "braid: transition signature refused");
            }
        }
        true
    }

    /// Whether this peer has been caught equivocating. The packet path drops
    /// every payload from a revoked fingerprint.
    pub(crate) fn peer_revoked(peer_fp: &str) -> bool {
        revoked().contains_key(peer_fp)
    }

    /// `(tracked peers, revoked peers)` for the status document/tests. A peer is
    /// tracked when either direction has state for it.
    #[cfg(test)]
    pub(crate) fn stats() -> (usize, usize) {
        let mut tracked = std::collections::HashSet::new();
        for entry in ours().iter() {
            tracked.insert(entry.key().clone());
        }
        for entry in chains().iter() {
            tracked.insert(entry.key().clone());
        }
        (tracked.len(), revoked().len())
    }

    /// Height of our in-memory chain for `peer_fp`, when we have one. `None`
    /// after ingesting a peer's transition is the property the split guarantees.
    #[cfg(test)]
    pub(crate) fn our_height(peer_fp: &str) -> Option<u64> {
        let guard = ours().get(peer_fp)?;
        let height = guard.lock().chain.height();
        Some(height)
    }

    /// Drop every in-memory trace of `peer_fp`, leaving only what is on disk —
    /// the state a restart begins from.
    #[cfg(test)]
    pub(crate) fn forget_for_test(peer_fp: &str) {
        ours().remove(peer_fp);
        chains().remove(peer_fp);
        revoked().remove(peer_fp);
    }
}

// ══════════════════════════════════════════════════════════════════
// 4. entropy_beacon — threshold randomness on the PEX beat
// ══════════════════════════════════════════════════════════════════

pub(crate) mod beacon_wire {
    use super::*;
    use vantablack::ghost::net::BeaconGridEpoch;

    /// Control PDU magic for one entropy share.
    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_EBEACON_";
    /// Shares needed before a round finalizes. Three independent contributions.
    pub(crate) const THRESHOLD: usize = 3;
    /// Round length. Short enough that a 30 s PEX beat lands in a fresh round.
    pub(crate) const ROUND_SECS: u64 = 30;

    struct Wire {
        commons: entropy_beacon::EntropyBeaconCommons,
        grid: BeaconGridEpoch,
        round: u64,
        /// A round's output is frozen at the first threshold completion: shares
        /// that arrive later for the same round must not rewrite it.
        finalized: HashMap<u64, [u8; 32]>,
        last: Option<[u8; 32]>,
    }

    fn state() -> &'static Mutex<Wire> {
        static STATE: OnceLock<Mutex<Wire>> = OnceLock::new();
        STATE.get_or_init(|| {
            Mutex::new(Wire {
                commons: entropy_beacon::EntropyBeaconCommons::new(THRESHOLD),
                grid: BeaconGridEpoch::new(0, 0, [0u8; 16]),
                round: 0,
                finalized: HashMap::new(),
                last: None,
            })
        })
    }

    fn contributor(fingerprint: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VB-ENTROPY-CONTRIBUTOR-V1");
        hasher.update(fingerprint.as_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn current_round(now: u64) -> u64 {
        now / ROUND_SECS
    }

    /// Build this node's share for the current round, plus the grid epoch it
    /// currently believes. The grid rides the share because both are 32 bytes and
    /// both are peer-visible state that changes on the same beat.
    pub(crate) fn share_payload(our_fp: &str) -> Vec<u8> {
        let now = now_secs();
        let round = current_round(now);
        let mut entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);

        let grid_bytes = {
            let mut wire = state().lock();
            if wire.round != round {
                // Keep the map bounded: two rounds of history is enough for a
                // share that arrives a beat late.
                wire.commons.retain_rounds(|r| r + 2 >= round);
                wire.finalized.retain(|r, _| *r + 2 >= round);
                wire.round = round;
            }
            let share = entropy_beacon::EntropyShare::new(round, contributor(our_fp), entropy);
            wire.commons.submit_share(share);
            let grid = wire.grid.to_bytes();
            finalize_if_ready(&mut wire, round);
            grid
        };

        let mut payload = Vec::with_capacity(MAGIC.len() + 8 + 32 + 32);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&round.to_be_bytes());
        payload.extend_from_slice(&entropy);
        payload.extend_from_slice(&grid_bytes);
        payload
    }

    fn finalize_if_ready(wire: &mut Wire, round: u64) {
        if wire.finalized.contains_key(&round) {
            return;
        }
        let Some(output) = wire.commons.try_finalize_round(round) else {
            return;
        };
        wire.finalized.insert(round, output.beacon_digest);
        wire.last = Some(output.beacon_digest);
        wire.grid.tick(&output.beacon_digest);
        tracing::info!(
            round = round,
            participants = output.participant_count,
            digest = %short(&output.beacon_digest),
            grid_epoch = wire.grid.grid_epoch,
            grid_cycle = wire.grid.cycle_count,
            "entropy beacon: round frozen — grid epoch advanced"
        );
    }

    /// Ingest a peer's share. Returns `true` when the payload was an entropy PDU.
    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> bool {
        if !payload.starts_with(MAGIC) {
            return false;
        }
        let body = &payload[MAGIC.len()..];
        if body.len() < 40 {
            tracing::warn!(peer = %from_fp, bytes = body.len(), "entropy beacon: truncated share");
            return true;
        }
        let round = u64::from_be_bytes(body[..8].try_into().expect("8 bytes"));
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&body[8..40]);
        let now = now_secs();
        if round + 2 < current_round(now) {
            tracing::debug!(peer = %from_fp, round, "entropy beacon: share from a retired round");
            return true;
        }

        let mut wire = state().lock();
        let mut advanced = false;
        if body.len() >= 72 {
            if let Some(remote) = BeaconGridEpoch::from_bytes(&body[40..72]) {
                if wire.grid.reconcile(&remote) {
                    advanced = true;
                    tracing::info!(
                        peer = %from_fp,
                        grid_epoch = wire.grid.grid_epoch,
                        cycle = wire.grid.cycle_count,
                        "entropy beacon: reconciled the peer's grid epoch"
                    );
                }
            }
        }
        wire.commons.submit_share(entropy_beacon::EntropyShare::new(
            round,
            contributor(from_fp),
            entropy,
        ));
        finalize_if_ready(&mut wire, round);
        let _ = advanced;
        true
    }

    /// The last frozen beacon output, for the status surface and tests.
    #[cfg(test)]
    pub(crate) fn last_output() -> Option<[u8; 32]> {
        state().lock().last
    }

    /// `(grid epoch, grid cycle, rounds frozen)`.
    #[cfg(test)]
    pub(crate) fn snapshot() -> (u64, u32, usize) {
        let wire = state().lock();
        (wire.grid.grid_epoch, wire.grid.cycle_count, wire.finalized.len())
    }
}

// ══════════════════════════════════════════════════════════════════
// 2/3/6. erosion + dead_drop + mesh_archive — the DTN vault
// ══════════════════════════════════════════════════════════════════

pub(crate) mod vault {
    use super::*;

    /// Descriptor magic. A DTN bundle whose payload does not start with this is
    /// legacy plaintext and is delivered unchanged.
    pub(crate) const DESCRIPTOR_MAGIC: &[u8; 4] = b"VBSL";
    /// Blind-blob frame size: the dead-drop module's fixed chunk.
    const CHUNK: usize = dead_drop::DEAD_DROP_FRAME_LEN;
    /// How long a queued bundle may live, in seconds. Past this the erosion
    /// epoch no longer opens it even though the ciphertext is still here.
    const TTL_SECS: u64 = 900;
    /// Erosion epoch length. Turning the epoch over replaces every share, which
    /// is what makes the old wrapped keys unreadable.
    const EPOCH_SECS: u64 = 3_600;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum OpenError {
        /// The erosion epoch passed; the key is gone.
        Expired,
        /// A chunk is missing, the archive hash failed, or the AEAD refused.
        Corrupt,
    }

    struct Epoch {
        id: u64,
        committee: erosion::EphemerizerCommittee,
    }

    #[derive(Clone)]
    struct Stored {
        sealed: erosion::SealedBundle,
        record: mesh_archive::ArchivalRecord,
        cipher_len: usize,
    }

    fn enabled_once() -> &'static bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        ENABLED.get_or_init(|| toggle("GHOST_DTN_VAULT", true))
    }

    /// Whether the vault is the DTN store for this process.
    pub(crate) fn enabled() -> bool {
        *enabled_once()
    }

    fn blobs() -> &'static dead_drop::DeadDropVault {
        static VAULT: OnceLock<dead_drop::DeadDropVault> = OnceLock::new();
        VAULT.get_or_init(dead_drop::DeadDropVault::new)
    }

    fn stored() -> &'static DashMap<[u8; 32], Stored> {
        static STORED: OnceLock<DashMap<[u8; 32], Stored>> = OnceLock::new();
        STORED.get_or_init(DashMap::new)
    }

    fn epoch() -> &'static Mutex<Epoch> {
        static EPOCH: OnceLock<Mutex<Epoch>> = OnceLock::new();
        EPOCH.get_or_init(|| {
            let id = now_secs() / EPOCH_SECS;
            Mutex::new(Epoch {
                id,
                committee: fresh_committee(id),
            })
        })
    }

    fn fresh_committee(epoch_id: u64) -> erosion::EphemerizerCommittee {
        use curve25519_dalek::scalar::Scalar;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        // 2-of-3 is the smallest committee that still tolerates one forgotten
        // share. The daemon plays every member locally; distributing the shares
        // is the only thing standing between this and a real committee.
        erosion::EphemerizerCommittee::from_secret(
            2,
            3,
            (epoch_id + 1) * EPOCH_SECS,
            Scalar::from_bytes_mod_order(seed),
        )
        .expect("2-of-3 is a valid committee")
        .0
    }

    /// Run `f` with the committee for `now`, rotating the epoch first if it has
    /// turned over. A rotation drops the old shares, which is the forgetting.
    fn with_committee<T>(now: u64, f: impl FnOnce(&erosion::EphemerizerCommittee) -> T) -> T {
        let wanted = now / EPOCH_SECS;
        let mut guard = epoch().lock();
        if guard.id != wanted {
            guard.committee.expire();
            let old = guard.id;
            guard.id = wanted;
            guard.committee = fresh_committee(wanted);
            tracing::info!(
                old_epoch = old,
                new_epoch = wanted,
                "erosion: epoch turned over — old wrapped bundle keys are unreadable"
            );
        }
        f(&guard.committee)
    }

    fn bundle_id(peer_fp: &str, payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VB-DTN-VAULT-BUNDLE-V1");
        hasher.update(peer_fp.as_bytes());
        hasher.update(payload);
        hasher.finalize().into()
    }

    /// Seal `payload` for `peer_fp` and return the descriptor that replaces it in
    /// the DTN tree. The bytes themselves live in blind chunks.
    pub(crate) fn deposit(peer_fp: &str, payload: &[u8]) -> Option<Vec<u8>> {
        deposit_at(peer_fp, payload, now_secs())
    }

    /// `deposit` with an explicit clock, so expiry is testable without sleeping.
    pub(crate) fn deposit_at(peer_fp: &str, payload: &[u8], now: u64) -> Option<Vec<u8>> {
        let id = bundle_id(peer_fp, payload);
        if stored().contains_key(&id) {
            return None;
        }
        let die_at = now.saturating_add(TTL_SECS);

        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = vantablack::ghost::layers::l2_aead::xchacha_seal(
            &key,
            &nonce,
            0,
            NonceDirection::InitiatorToResponder,
            payload,
        )
        .expect("XChaCha20-Poly1305 seals");

        let sealed = with_committee(now, |committee| {
            erosion::seal_bundle(committee, &id, die_at, &key, now)
        })
        .ok()?;

        // The archive covers nonce ‖ ciphertext, so a corrupted chunk and a
        // wrong nonce are both an integrity failure rather than a decrypt error.
        let mut wrapped = Vec::with_capacity(nonce.len() + cipher.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&cipher);
        let record = mesh_archive::ArchivalRecord::create(format!("vb:drop:{}", hex::encode(id)), &wrapped);

        let mut chunks = Vec::new();
        for (index, piece) in wrapped.chunks(CHUNK).enumerate() {
            let commitment = dead_drop::BlindDeadDropBlob::derive_commitment(&id, index as u64);
            let blob = dead_drop::BlindDeadDropBlob::new(commitment, piece, now, TTL_SECS);
            blobs().deposit(blob);
            chunks.push(commitment);
        }

        let cipher_len = cipher.len();
        stored().insert(
            id,
            Stored {
                sealed: sealed.clone(),
                record,
                cipher_len,
            },
        );

        tracing::info!(
            peer = %peer_fp,
            bundle = %short(&id),
            bytes = payload.len(),
            chunks = chunks.len(),
            archive_shards = 3,
            die_at,
            "dead-drop: DTN payload sealed into blind chunks under an erosion epoch"
        );

        let mut descriptor = Vec::with_capacity(4 + 32 + 8 + 12 + 32 + 32 + 2 + 32 * chunks.len());
        descriptor.extend_from_slice(DESCRIPTOR_MAGIC);
        descriptor.extend_from_slice(&id);
        descriptor.extend_from_slice(&die_at.to_be_bytes());
        descriptor.extend_from_slice(&nonce);
        descriptor.extend_from_slice(&sealed.wrapped_key);
        descriptor.extend_from_slice(&sealed.tag);
        descriptor.extend_from_slice(&(chunks.len() as u16).to_be_bytes());
        for commitment in &chunks {
            descriptor.extend_from_slice(commitment);
        }
        Some(descriptor)
    }

    struct Descriptor {
        id: [u8; 32],
        die_at: u64,
        nonce: [u8; 12],
        wrapped_key: [u8; 32],
        tag: [u8; 32],
        chunks: Vec<dead_drop::DropCommitment>,
    }

    fn parse_descriptor(bytes: &[u8]) -> Option<Descriptor> {
        if bytes.len() < 4 + 32 + 8 + 12 + 32 + 32 + 2 || &bytes[..4] != DESCRIPTOR_MAGIC {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[4..36]);
        let die_at = u64::from_be_bytes(bytes[36..44].try_into().ok()?);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[44..56]);
        let mut wrapped_key = [0u8; 32];
        wrapped_key.copy_from_slice(&bytes[56..88]);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[88..120]);
        let count = u16::from_be_bytes(bytes[120..122].try_into().ok()?) as usize;
        if bytes.len() != 122 + 32 * count {
            return None;
        }
        let mut chunks = Vec::with_capacity(count);
        for i in 0..count {
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&bytes[122 + 32 * i..154 + 32 * i]);
            chunks.push(commitment);
        }
        Some(Descriptor {
            id,
            die_at,
            nonce,
            wrapped_key,
            tag,
            chunks,
        })
    }

    /// Recover a DTN bundle payload. A payload that is not a descriptor is
    /// returned unchanged, so a vault-off or legacy bundle still delivers.
    pub(crate) fn open(payload: &[u8]) -> Result<Vec<u8>, OpenError> {
        open_at(payload, now_secs())
    }

    pub(crate) fn open_at(payload: &[u8], now: u64) -> Result<Vec<u8>, OpenError> {
        let Some(descriptor) = parse_descriptor(payload) else {
            return Ok(payload.to_vec());
        };
        if now >= descriptor.die_at {
            stored().remove(&descriptor.id);
            EXPIRED.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                bundle = %short(&descriptor.id),
                die_at = descriptor.die_at,
                "erosion: bundle outlived its epoch — key forgotten, payload destroyed"
            );
            return Err(OpenError::Expired);
        }
        let Some(stored_bundle) = stored().get(&descriptor.id).map(|entry| entry.value().clone()) else {
            return Err(OpenError::Corrupt);
        };

        if stored_bundle.sealed.tag != descriptor.tag || stored_bundle.sealed.die_at != descriptor.die_at {
            tracing::warn!(bundle = %short(&descriptor.id), "dead-drop: descriptor does not match the stored bundle");
            return Err(OpenError::Corrupt);
        }

        // `sweep`, not `sweep_and_consume`: a failed send must be able to retry.
        // `forget` is what consumes the chunks once delivery is acknowledged.
        let mut wrapped = Vec::with_capacity(stored_bundle.cipher_len + 12);
        for commitment in &descriptor.chunks {
            let Some(blob) = blobs().sweep(commitment) else {
                tracing::warn!(bundle = %short(&descriptor.id), "dead-drop: chunk missing on sweep");
                return Err(OpenError::Corrupt);
            };
            let used = if wrapped.is_empty() && descriptor.chunks.len() > 1 {
                CHUNK
            } else {
                blob.opaque_ciphertext.len()
            };
            wrapped.extend_from_slice(&blob.opaque_ciphertext[..used]);
        }
        wrapped.truncate(12 + stored_bundle.cipher_len);

        // Two of three archival shards are enough, and one is deliberately
        // withheld to exercise the erasure code on every recovery.
        let reconstructed = stored_bundle
            .record
            .reconstruct(&[
                Some(stored_bundle.record.shards[0].clone()),
                None,
                Some(stored_bundle.record.shards[2].clone()),
            ])
            .map_err(|error| {
                tracing::warn!(bundle = %short(&descriptor.id), %error, "mesh-archive: integrity failure");
                OpenError::Corrupt
            })?;
        if reconstructed != wrapped {
            tracing::warn!(bundle = %short(&descriptor.id), "mesh-archive: recovered bytes differ from the sealed stream");
            return Err(OpenError::Corrupt);
        }

        let sealed = erosion::SealedBundle {
            bundle_id: descriptor.id,
            die_at: descriptor.die_at,
            wrapped_key: descriptor.wrapped_key,
            tag: descriptor.tag,
        };
        let key = with_committee(now, |committee| erosion::open_bundle(committee, &sealed, now))
            .map_err(|error| {
                tracing::warn!(
                    bundle = %short(&descriptor.id),
                    %error,
                    "erosion: threshold shares unavailable — plaintext unobtainable"
                );
                OpenError::Expired
            })?;

        let mut cipher = wrapped[12..].to_vec();
        let plain = xchacha_open(
            &key,
            &descriptor.nonce,
            0,
            NonceDirection::InitiatorToResponder,
            &mut cipher,
        )
        .map_err(|_| OpenError::Corrupt)?
        .to_vec();
        DELIVERED.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            bundle = %short(&descriptor.id),
            bytes = plain.len(),
            "dead-drop: bundle recovered from blind chunks and verified"
        );
        Ok(plain)
    }

    /// Consume a bundle's chunks once it has actually been delivered.
    pub(crate) fn forget(payload: &[u8]) {
        let Some(descriptor) = parse_descriptor(payload) else {
            return;
        };
        stored().remove(&descriptor.id);
        for commitment in &descriptor.chunks {
            blobs().sweep_and_consume(commitment);
        }
    }

    /// Counters behind the adaptive decay rate: a vault losing bundles to expiry
    /// is a vault under stress, and retention stretches while that is true.
    static EXPIRED: AtomicU64 = AtomicU64::new(0);
    static DELIVERED: AtomicU64 = AtomicU64::new(0);

    fn observed_error_rate() -> f64 {
        let expired = EXPIRED.load(Ordering::Relaxed) as f64;
        let delivered = DELIVERED.load(Ordering::Relaxed) as f64;
        if expired + delivered == 0.0 {
            return 0.0;
        }
        (expired / (expired + delivered)).clamp(0.0, 1.0)
    }

    /// Run one self-eating decay pass. Returns the number of reclaimed chunks.
    pub(crate) fn collect_decay() -> usize {
        let rate = observed_error_rate();
        let removed = blobs().collect_self_eating_decay(now_secs(), rate);
        if removed > 0 {
            tracing::info!(
                removed,
                error_rate = rate,
                multiplier = 1.0 + rate * 4.0,
                "dead-drop: self-eating decay reclaimed cold chunks"
            );
        }
        removed
    }

    /// Number of descriptors the vault currently holds. Test/status surface.
    #[cfg(test)]
    pub(crate) fn stored_count() -> usize {
        stored().len()
    }

    /// Number of blind chunks at rest. Test/status surface.
    #[cfg(test)]
    pub(crate) fn chunk_count() -> usize {
        blobs().stored_count()
    }
}

// ══════════════════════════════════════════════════════════════════
// 7. bandwidth_voucher — relay admission credit
// ══════════════════════════════════════════════════════════════════

pub(crate) mod voucher {
    use super::*;
    use vantablack::ghost::net::bandwidth_voucher::{BandwidthVoucher, RelayBandwidthBank};

    /// Control PDU magic for a presented voucher.
    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_VOUCHER_";
    /// Megabytes one voucher buys.
    const QUOTA_MB: u32 = 16;
    /// One epoch of voucher validity.
    const EPOCH_SECS: u64 = 3_600;
    /// Leading zero bits the local mint must find. Eight is one hash in 256 —
    /// enough to make bulk minting cost something, small enough to be invisible
    /// next to a datagram.
    const POW_BITS: u8 = 8;

    struct Bank {
        relay: RelayBandwidthBank,
        /// Sender fingerprint → the nullifier its presented voucher is banked under.
        by_peer: HashMap<String, [u8; 32]>,
        /// Peer → epoch slot its last voucher was minted for.
        issued: HashMap<String, u64>,
        admitted: u64,
        denied: u64,
    }

    fn state() -> &'static Mutex<Bank> {
        static STATE: OnceLock<Mutex<Bank>> = OnceLock::new();
        STATE.get_or_init(|| {
            Mutex::new(Bank {
                relay: RelayBandwidthBank::new(),
                by_peer: HashMap::new(),
                issued: HashMap::new(),
                admitted: 0,
                denied: 0,
            })
        })
    }

    /// Whether relay forwarding is gated on vouchers. Off by default: a relay
    /// that starts charging without its peers knowing would black-hole traffic.
    pub(crate) fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| toggle("GHOST_RELAY_VOUCHERS", false))
    }

    fn proof_of_work(domain: &[u8], seed: &[u8; 32], epoch: u64, bits: u8) -> [u8; 32] {
        for nonce in 0u64.. {
            let mut hasher = Sha256::new();
            hasher.update(domain);
            hasher.update(seed);
            hasher.update(epoch.to_be_bytes());
            hasher.update(nonce.to_be_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            let mut zeros = 0u32;
            for byte in digest {
                if byte == 0 {
                    zeros += 8;
                } else {
                    zeros += byte.leading_zeros();
                    break;
                }
            }
            if zeros >= u32::from(bits) {
                return digest;
            }
        }
        unreachable!("a 64-bit nonce space will find an 8-bit proof")
    }

    /// A voucher payload for `peer_fp`, at most once per epoch. Returns `None`
    /// while the voucher already banked for this peer is still current.
    pub(crate) fn present_payload(peer_fp: &str) -> Option<Vec<u8>> {
        let now = now_secs();
        let slot = now / EPOCH_SECS;
        let mut bank = state().lock();
        if bank.issued.get(peer_fp).copied() == Some(slot) {
            return None;
        }
        let mut preimage = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut preimage);
        let proof = proof_of_work(b"VB-VOUCHER-POW-V1", &preimage, slot, POW_BITS);
        bank.issued.insert(peer_fp.to_string(), slot);
        let voucher = BandwidthVoucher::mint(preimage, slot, QUOTA_MB, proof);
        tracing::debug!(
            peer = %peer_fp,
            epoch = slot,
            quota_mb = QUOTA_MB,
            nullifier = %short(&voucher.compute_nullifier()),
            "voucher: minted for the next relay transit"
        );
        let mut payload = Vec::with_capacity(MAGIC.len() + 76);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&preimage);
        payload.extend_from_slice(&slot.to_be_bytes());
        payload.extend_from_slice(&QUOTA_MB.to_be_bytes());
        payload.extend_from_slice(&proof);
        Some(payload)
    }

    /// Bank a voucher presented by `from_fp`. Returns `true` when the payload was
    /// a voucher PDU.
    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> bool {
        if !payload.starts_with(MAGIC) {
            return false;
        }
        let body = &payload[MAGIC.len()..];
        if body.len() != 76 {
            tracing::warn!(peer = %from_fp, bytes = body.len(), "voucher: malformed presentation");
            return true;
        }
        let mut preimage = [0u8; 32];
        preimage.copy_from_slice(&body[..32]);
        let epoch = u64::from_be_bytes(body[32..40].try_into().expect("8 bytes"));
        let quota = u32::from_be_bytes(body[40..44].try_into().expect("4 bytes"));
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&body[44..76]);
        let voucher = BandwidthVoucher::mint(preimage, epoch, quota, proof);
        let nullifier = voucher.compute_nullifier();
        let mut bank = state().lock();
        match bank.relay.redeem_voucher(&voucher) {
            Ok(granted) => {
                bank.by_peer.insert(from_fp.to_string(), nullifier);
                tracing::info!(
                    peer = %from_fp,
                    granted_mb = granted,
                    nullifier = %short(&nullifier),
                    "voucher: relay credited the peer's transit"
                );
            }
            Err(reason) => tracing::debug!(peer = %from_fp, reason, "voucher: presentation refused"),
        }
        true
    }

    /// Charge `bytes` of relay transit to `from_fp`'s banked voucher. Without a
    /// banked voucher the forward is refused once the gate is on.
    pub(crate) fn admit_transit(from_fp: &str, bytes: usize) -> bool {
        if !enabled() {
            return true;
        }
        let mut bank = state().lock();
        let Some(nullifier) = bank.by_peer.get(from_fp).copied() else {
            bank.denied = bank.denied.saturating_add(1);
            tracing::warn!(peer = %from_fp, "voucher: no banked voucher — relay transit refused");
            return false;
        };
        let charge = (bytes as u64).div_ceil(1_048_576).max(1) as u32;
        if bank.relay.consume_bandwidth(&nullifier, charge) {
            bank.admitted = bank.admitted.saturating_add(1);
            tracing::debug!(peer = %from_fp, mb = charge, remaining = bank.relay.remaining_quota(&nullifier), "voucher: relay transit charged");
            true
        } else {
            bank.denied = bank.denied.saturating_add(1);
            tracing::warn!(peer = %from_fp, mb = charge, "voucher: credit exhausted — relay transit refused");
            false
        }
    }

    /// Test helper: bank a voucher directly, without the PDU framing.
    #[cfg(test)]
    pub(crate) fn present_for_test(from_fp: &str, voucher: &BandwidthVoucher) -> Result<u32, &'static str> {
        let mut bank = state().lock();
        let granted = bank.relay.redeem_voucher(voucher)?;
        bank.by_peer
            .insert(from_fp.to_string(), voucher.compute_nullifier());
        Ok(granted)
    }

    /// Test helper: charge without the env gate.
    #[cfg(test)]
    pub(crate) fn charge_for_test(from_fp: &str, bytes: usize) -> bool {
        let bank = state().lock();
        let Some(nullifier) = bank.by_peer.get(from_fp).copied() else {
            return false;
        };
        let charge = (bytes as u64).div_ceil(1_048_576).max(1) as u32;
        bank.relay.consume_bandwidth(&nullifier, charge)
    }
}

// ══════════════════════════════════════════════════════════════════
// 5. polysemy — causal path-subset probe on the bonded link
// ══════════════════════════════════════════════════════════════════

pub(crate) mod worlds {
    use super::*;

    /// Envelope magic of one polysemic probe shard on the bond socket.
    pub(crate) const MAGIC: &[u8; 4] = b"GBWD";
    const VERSION: u8 = 1;
    /// `[GBWD 4][version 1][n 1][k 1][path 1][id 8][shard]`.
    const HEADER: usize = 16;
    /// A probe world message: 4-byte world index plus the probe tag.
    const MESSAGE: usize = 8;
    const MAX_GROUPS: usize = 64;

    struct Group {
        n: usize,
        k: usize,
        shards: HashMap<usize, Vec<u8>>,
        opened: std::time::Instant,
    }

    fn groups() -> &'static Mutex<HashMap<(IpAddr, [u8; 8]), Group>> {
        static GROUPS: OnceLock<Mutex<HashMap<(IpAddr, [u8; 8]), Group>>> = OnceLock::new();
        GROUPS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Whether the bonded link sends a polysemic path probe. Off unless asked:
    /// it is control traffic, and a bond that only needs carriers should not
    /// carry it.
    pub(crate) fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| toggle("GHOST_BOND_WORLDS", false))
    }

    /// Encode the probe: one world per `k`-subset of `n` paths. World `i`'s
    /// message names `i`, so a receiver that collapses a subset learns which
    /// subset it actually holds.
    pub(crate) fn encode_probe(
        n: usize,
        tag: &[u8; 4],
    ) -> Option<([u8; 8], u8, u8, Vec<Vec<u8>>)> {
        if n < 3 {
            return None;
        }
        let k = n - 1;
        let code = polysemy::PolysemicCode::new(n, k, MESSAGE).ok()?;
        let worlds: Vec<Vec<u8>> = (0..code.world_count())
            .map(|world| {
                let mut message = Vec::with_capacity(MESSAGE);
                message.extend_from_slice(&(world as u32).to_be_bytes());
                message.extend_from_slice(tag);
                message
            })
            .collect();
        let shards = code.encode(&worlds).ok()?;
        let mut id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id);
        Some((id, n as u8, k as u8, shards))
    }

    /// Wrap one path's shard for the bond socket.
    pub(crate) fn wrap(
        id: &[u8; 8],
        path: u8,
        n: u8,
        k: u8,
        shard: &[u8],
    ) -> Vec<u8> {
        let mut datagram = Vec::with_capacity(HEADER + shard.len());
        datagram.extend_from_slice(MAGIC);
        datagram.push(VERSION);
        datagram.push(n);
        datagram.push(k);
        datagram.push(path);
        datagram.extend_from_slice(id);
        datagram.extend_from_slice(shard);
        datagram
    }

    /// Collect one probe shard. When `k` distinct paths have delivered, collapse
    /// the world and verify that the recovered world index names the surviving
    /// subset — the message is only useful if it agrees with the paths that
    /// carried it.
    pub(crate) fn handle_datagram(datagram: &[u8], from: IpAddr) -> Option<(Vec<usize>, [u8; MESSAGE])> {
        if datagram.len() <= HEADER || &datagram[..4] != MAGIC || datagram[4] != VERSION {
            return None;
        }
        let n = datagram[5] as usize;
        let k = datagram[6] as usize;
        let path = datagram[7] as usize;
        if n < 3 || k == 0 || k > n || path >= n {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&datagram[8..HEADER]);
        let shard = datagram[HEADER..].to_vec();

        let mut all = groups().lock();
        if all.len() >= MAX_GROUPS {
            let oldest = all
                .iter()
                .min_by_key(|(_, group)| group.opened)
                .map(|(key, _)| *key);
            if let Some(key) = oldest {
                all.remove(&key);
            }
        }
        if all
            .get(&(from, id))
            .is_some_and(|group| group.n != n || group.k != k)
        {
            all.remove(&(from, id));
        }
        let group = all.entry((from, id)).or_insert_with(|| Group {
            n,
            k,
            shards: HashMap::new(),
            opened: std::time::Instant::now(),
        });
        group.shards.insert(path, shard);
        if group.shards.len() < k {
            return None;
        }
        let mut survivors: Vec<usize> = group.shards.keys().copied().collect();
        survivors.sort_unstable();
        survivors.truncate(k);
        let mut shards: Vec<Vec<u8>> = vec![Vec::new(); n];
        for (&index, bytes) in &group.shards {
            if let Some(slot) = shards.get_mut(index) {
                *slot = bytes.clone();
            }
        }
        all.remove(&(from, id));

        let code = polysemy::PolysemicCode::new(n, k, MESSAGE).ok()?;
        let message = code.collapse(&shards, &survivors).ok()?;
        let mut body = [0u8; MESSAGE];
        body.copy_from_slice(&message);
        let world = u32::from_be_bytes(body[..4].try_into().ok()?) as usize;
        let expected = code.world_index(&survivors)?;
        if world != expected {
            tracing::warn!(
                %from,
                survivors = ?survivors,
                claimed = world,
                expected,
                "polysemy: recovered world does not name the surviving path set"
            );
            return None;
        }
        Some((survivors, body))
    }

    /// Test helper: number of in-flight probe groups.
    #[cfg(test)]
    pub(crate) fn group_count() -> usize {
        groups().lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fresh_voucher(epoch: u64, quota: u32) -> vantablack::ghost::net::bandwidth_voucher::BandwidthVoucher {
        let mut preimage = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut preimage);
        vantablack::ghost::net::bandwidth_voucher::BandwidthVoucher::mint(
            preimage,
            epoch,
            quota,
            [0x51u8; 32],
        )
    }

    #[test]
    fn a_braid_fork_revokes_the_peer_and_a_replay_is_stale() {
        let mut real = braid_identity::BraidLock::from_seed([0x42u8; 32]);
        let mut clone = braid_identity::BraidLock::restore(
            real.secret_state().0,
            real.braid(),
            real.height(),
        );
        let a = real.advance(b"wifi");
        let b = clone.advance(b"five-g");
        assert_eq!(a.parent_pk, b.parent_pk);

        let peer = "braid-unit-fork";
        let mut first = braid::MAGIC.to_vec();
        first.extend_from_slice(&a.to_bytes());
        assert!(braid::handle_pdu(peer, &first));
        assert!(!braid::peer_revoked(peer), "one transition is not a fork");

        let mut second = braid::MAGIC.to_vec();
        second.extend_from_slice(&b.to_bytes());
        assert!(braid::handle_pdu(peer, &second));
        assert!(braid::peer_revoked(peer), "two children of one key revoke it");

        // Replaying the honest half now answers Revoked, and revocation is
        // what the packet path consults.
        assert!(braid::handle_pdu(peer, &first));
        assert!(braid::peer_revoked(peer));
        let (tracked, revoked) = braid::stats();
        assert!(tracked >= 1 && revoked >= 1);
    }

    #[test]
    fn a_tampered_braid_transition_never_revokes_an_innocent_peer() {
        let mut node = braid_identity::BraidLock::from_seed([0x43u8; 32]);
        let mut transition = node.advance(b"tamper").to_bytes();
        transition[48] ^= 0x01; // the child key, inside the signed message
        let peer = "braid-unit-tamper";
        let mut payload = braid::MAGIC.to_vec();
        payload.extend_from_slice(&transition);
        assert!(braid::handle_pdu(peer, &payload));
        assert!(!braid::peer_revoked(peer));
        assert!(!braid::handle_pdu("other-peer", b"not a braid"));
    }

    #[test]
    fn three_entropy_shares_freeze_a_round_and_advance_the_grid() {
        let round = beacon_wire::current_round(now_secs());
        let before = beacon_wire::snapshot();
        for (i, fingerprint) in ["entropy-a", "entropy-b", "entropy-c"].iter().enumerate() {
            let mut payload = beacon_wire::MAGIC.to_vec();
            payload.extend_from_slice(&round.to_be_bytes());
            payload.extend_from_slice(&[0x10 + i as u8; 32]);
            let grid = vantablack::ghost::net::BeaconGridEpoch::new(0, 0, [0u8; 16]).to_bytes();
            payload.extend_from_slice(&grid);
            assert!(beacon_wire::handle_pdu(fingerprint, &payload));
        }
        let frozen = beacon_wire::last_output().expect("a third share finalizes the round");
        assert_ne!(frozen, [0u8; 32]);

        // A fourth share for the same round cannot rewrite the frozen output.
        let mut late = beacon_wire::MAGIC.to_vec();
        late.extend_from_slice(&round.to_be_bytes());
        late.extend_from_slice(&[0x44u8; 32]);
        assert!(beacon_wire::handle_pdu("entropy-d", &late));
        assert_eq!(beacon_wire::last_output(), Some(frozen));

        let after = beacon_wire::snapshot();
        assert_eq!(
            after.1,
            before.1 + 1,
            "the grid cycle advances on every frozen round"
        );
        assert_eq!(after.2, before.2 + 1, "exactly one round was frozen");
    }

    #[test]
    fn a_dtn_payload_survives_the_vault_and_is_gone_after_its_epoch() {
        let peer = "vault-unit-peer";
        let payload = b"GHOST_PEX2____ descriptor batch that belongs in a blind chunk";
        // Ten seconds into the current erosion epoch, so a second-long test
        // cannot straddle a rotation (which would be an Expired result).
        let now = (now_secs() / 3_600) * 3_600 + 10;
        let descriptor = vault::deposit_at(peer, payload, now).expect("deposits");
        assert!(descriptor.starts_with(vault::DESCRIPTOR_MAGIC));
        assert!(vault::chunk_count() >= 1);

        let recovered = vault::open_at(&descriptor, now + 1).expect("opens inside the epoch");
        assert_eq!(recovered, payload);
        assert!(vault::stored_count() >= 1, "the descriptor is still retryable");

        let descriptor = vault::deposit_at(peer, b"second bundle", now).expect("second deposit");
        assert_eq!(
            vault::open_at(&descriptor, now + 10_000),
            Err(vault::OpenError::Expired),
            "a bundle past its die_at cannot be opened even with its descriptor"
        );
    }

    #[test]
    fn a_tampered_descriptor_is_corrupt_not_delivered() {
        let now = (now_secs() / 3_600) * 3_600 + 10;
        let mut descriptor = vault::deposit_at("vault-tamper", b"payload", now).expect("deposits");
        let last = descriptor.len() - 1;
        descriptor[last] ^= 0xFF; // last commitment byte
        assert_eq!(vault::open_at(&descriptor, now + 1), Err(vault::OpenError::Corrupt));
        // A non-descriptor payload is legacy plaintext and passes through.
        assert_eq!(
            vault::open_at(b"GHOST_PEX_____ legacy", now),
            Ok(b"GHOST_PEX_____ legacy".to_vec())
        );
    }

    #[test]
    fn relay_transit_is_refused_without_a_voucher_and_charged_with_one() {
        let peer = "voucher-unit-peer";
        assert!(!voucher::charge_for_test(peer, 1024), "no voucher, no transit");

        let epoch = now_secs() / 3_600;
        let granted = voucher::present_for_test(peer, &fresh_voucher(epoch, 8)).expect("redeems");
        assert_eq!(granted, 8);
        assert!(voucher::charge_for_test(peer, 3_000_000), "one MB charged");
        assert!(voucher::charge_for_test(peer, 3_000_000), "second MB charged");
        assert!(!voucher::charge_for_test(peer, 32 * 1_048_576), "overdraw refused");
    }

    #[test]
    fn a_polysemic_probe_learns_which_paths_survived() {
        let (id, n, k, shards) = worlds::encode_probe(3, b"PROB").expect("encodes");
        assert_eq!((n, k), (3, 2));
        assert_eq!(shards.len(), 3);

        // Paths 0 and 2 survive: their two shards must collapse world {0,2}.
        let from: IpAddr = "192.0.2.7".parse().unwrap();
        assert!(worlds::handle_datagram(&worlds::wrap(&id, 0, n, k, &shards[0]), from).is_none());
        let (survivors, message) =
            worlds::handle_datagram(&worlds::wrap(&id, 2, n, k, &shards[2]), from)
                .expect("two shards collapse the world");
        assert_eq!(survivors, vec![0, 2]);
        assert_eq!(&message[4..], b"PROB");
        assert_eq!(worlds::group_count(), 0, "the group is consumed");
        assert!(
            worlds::encode_probe(2, b"PROB").is_none(),
            "a 2-path link has no k=n-1 world"
        );
    }

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("vb-braid-{tag}-{}-{nanos}", std::process::id()))
    }

    fn transition_of(payload: &[u8]) -> braid_identity::Transition {
        braid_identity::Transition::from_bytes(&payload[braid::MAGIC.len()..])
            .expect("a braid payload carries one transition")
    }

    fn framed_transition(transition: &braid_identity::Transition) -> Vec<u8> {
        let mut payload = braid::MAGIC.to_vec();
        payload.extend_from_slice(&transition.to_bytes());
        payload
    }

    /// Restarting used to re-derive the deterministic genesis key and sign a
    /// second child of a key the peer already accepted — indistinguishable from
    /// a clone, and revoked. The persisted record must let the next process
    /// continue the chain the peer observed.
    #[test]
    fn a_restarted_node_continues_its_persisted_chain_instead_of_forking() {
        let root = unique_dir("restart");
        let our_fp = "braid-restart-self";
        let peer_fp = "braid-restart-peer";

        // Session one, before the restart: durable, and a peer saw it.
        let first_payload = braid::advance_with(Some(&root), our_fp, peer_fp, b"session-1")
            .expect("a durable advance publishes");
        let first = transition_of(&first_payload);
        assert_eq!(first.height, 1);
        let mut peer_chain = braid_identity::BraidChain::new();
        assert_eq!(
            peer_chain.accept(&first),
            braid_identity::BraidVerdict::Extended
        );

        // Restart: process state is gone, only the record survives.
        braid::forget_for_test(peer_fp);
        assert_eq!(braid::restore_from(&root, our_fp), 1);

        // The restored tip is the same transition (a replay is `Stale` at the
        // peer), and the next session extends it rather than forking genesis.
        assert_eq!(
            braid::tip_payload(peer_fp).expect("the published tip is restored"),
            first_payload
        );
        let second_payload = braid::advance_with(Some(&root), our_fp, peer_fp, b"session-2")
            .expect("the restored chain advances");
        let second = transition_of(&second_payload);
        assert_eq!(second.height, 2);
        assert_eq!(
            second.parent_pk, first.next_pk,
            "the chain continues from the key the peer accepted"
        );
        assert_eq!(
            peer_chain.accept(&second),
            braid_identity::BraidVerdict::Extended
        );
        assert!(
            !peer_chain.is_revoked(&first.parent_pk),
            "an honest restart must never be revoked as a clone"
        );

        // A second restart continues again at the new height.
        braid::forget_for_test(peer_fp);
        assert_eq!(braid::restore_from(&root, our_fp), 1);
        let third = transition_of(
            &braid::advance_with(Some(&root), our_fp, peer_fp, b"session-3")
                .expect("advances again"),
        );
        assert_eq!(third.height, 3);
        assert_eq!(third.parent_pk, second.next_pk);
        assert_eq!(
            peer_chain.accept(&third),
            braid_identity::BraidVerdict::Extended
        );

        braid::forget_for_test(peer_fp);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Ingesting a peer's transition used to insert (and therefore seed) an
    /// `ours` lock for that peer from an empty fingerprint. The split keeps the
    /// verifier and our lock in separate maps.
    #[test]
    fn ingesting_a_peers_transition_never_seeds_or_advances_our_own_chain() {
        let peer_fp = "braid-split-peer";
        let mut theirs = braid_identity::BraidLock::from_seed([0x77u8; 32]);
        let their_transition = theirs.advance(b"their session");

        let mut payload = braid::MAGIC.to_vec();
        payload.extend_from_slice(&their_transition.to_bytes());
        assert!(braid::handle_pdu(peer_fp, &payload));
        assert_eq!(
            braid::our_height(peer_fp),
            None,
            "a verifier is not a lock"
        );
        assert!(braid::tip_payload(peer_fp).is_none());

        // Our advance starts at our own genesis, height 1, not from their key.
        let ours_payload = braid::advance_with(None, "braid-split-self", peer_fp, b"our session")
            .expect("publishes in memory");
        let ours = transition_of(&ours_payload);
        assert_eq!(ours.height, 1);
        let genesis = braid_identity::BraidLock::from_seed(braid::seed_for(
            "braid-split-self",
            peer_fp,
        ));
        assert_eq!(ours.parent_pk, genesis.identity());
        assert_ne!(ours.parent_pk, their_transition.next_pk);
        assert_eq!(braid::our_height(peer_fp), Some(1));
        braid::forget_for_test(peer_fp);
    }

    /// The fsync obligation is a publish gate: no durable state, no transition.
    /// The publish gate: before boot restore there is no state directory, so no
    /// transition is signed at all. (No test in this binary calls `init`.)
    #[test]
    fn a_transition_before_boot_restore_is_refused_rather_than_signed() {
        let peer_fp = "braid-preboot-peer";
        assert!(
            braid::advance_and_tip("braid-preboot-self", peer_fp, b"early session").is_none(),
            "no durable root means no signature"
        );
        assert_eq!(braid::our_height(peer_fp), None, "no lock was created");
        assert!(braid::tip_payload(peer_fp).is_none());
    }

    /// A restart must not forget which peers forked, nor which child it accepted
    /// for a parent key that has not forked yet.
    #[test]
    fn verifier_state_and_fork_proofs_survive_restart_through_the_journal() {
        let root = unique_dir("verifier");

        // A linear peer: the accepted child is what makes a later sibling a fork.
        let mut honest = braid_identity::BraidLock::from_seed([0x31u8; 32]);
        let mut sibling = braid_identity::BraidLock::restore(
            honest.secret_state().0,
            honest.braid(),
            honest.height(),
        );
        let linear = honest.advance(b"first session");
        let sibling_transition = sibling.advance(b"a sibling of it");
        assert_eq!(linear.parent_pk, sibling_transition.parent_pk);
        let peer_linear = "braid-journal-linear";
        assert!(braid::handle_pdu_at(
            Some(&root),
            peer_linear,
            &framed_transition(&linear)
        ));

        // A forking peer: two children of one key, caught and journaled.
        let mut real = braid_identity::BraidLock::from_seed([0x32u8; 32]);
        let mut clone = braid_identity::BraidLock::restore(
            real.secret_state().0,
            real.braid(),
            real.height(),
        );
        let a = real.advance(b"wifi");
        let b = clone.advance(b"five-g");
        let peer_fork = "braid-journal-fork";
        assert!(braid::handle_pdu_at(
            Some(&root),
            peer_fork,
            &framed_transition(&a)
        ));
        assert!(!braid::peer_revoked(peer_fork));
        assert!(braid::handle_pdu_at(
            Some(&root),
            peer_fork,
            &framed_transition(&b)
        ));
        assert!(braid::peer_revoked(peer_fork));

        // Restart: every in-memory trace is gone, journals are all that remain.
        braid::forget_for_test(peer_linear);
        braid::forget_for_test(peer_fork);
        assert!(!braid::peer_revoked(peer_fork));

        assert_eq!(braid::restore_verifiers(&root), 2);
        assert!(
            braid::peer_revoked(peer_fork),
            "the fork is remembered across the restart"
        );

        // The linear peer's child survived too: a sibling of its parent is now a
        // fork, not a fresh extension.
        assert!(braid::handle_pdu_at(
            Some(&root),
            peer_linear,
            &framed_transition(&sibling_transition)
        ));
        assert!(
            braid::peer_revoked(peer_linear),
            "the accepted child was replayed from the journal"
        );

        braid::forget_for_test(peer_linear);
        braid::forget_for_test(peer_fork);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_transition_whose_state_cannot_be_fsynced_is_not_published() {
        let blocker = unique_dir("unwritable");
        std::fs::write(&blocker, b"not a directory").expect("create the blocker file");
        let peer_fp = "braid-unwritable-peer";

        assert!(
            braid::advance_with(
                Some(blocker.as_path()),
                "braid-unwritable-self",
                peer_fp,
                b"session"
            )
            .is_none(),
            "a state directory that cannot be written must not yield a transition"
        );
        assert!(
            braid::tip_payload(peer_fp).is_none(),
            "nothing was published, so there is no tip to re-gossip"
        );
        braid::forget_for_test(peer_fp);
        let _ = std::fs::remove_file(Path::new(&blocker));
    }
}
