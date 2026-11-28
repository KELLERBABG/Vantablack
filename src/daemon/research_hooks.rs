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

use vantablack::ghost::net::{
    braid_identity, dead_drop, energy_currency, entropy_beacon, mesh_archive, metabolic, polysemy,
    sharded_compute, sheaf,
};
use vantablack::ghost::v2::erosion;

fn now_secs() -> u64 {
    super::beacon::unix_now_secs() as u64
}

fn short(id: &[u8; 32]) -> String {
    hex::encode(&id[..8])
}

fn toggle(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => default,
    }
}

pub(crate) async fn deliver(
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

pub(crate) fn handle_control(from_fp: &str, payload: &[u8]) -> Option<Vec<Vec<u8>>> {
    if braid::handle_pdu(from_fp, payload)
        || beacon_wire::handle_pdu(from_fp, payload)
        || voucher::handle_pdu(from_fp, payload)
        || sheaf_monitor::handle_pdu(from_fp, payload)
        || repair_ledger::handle_pdu(from_fp, payload)
    {
        return Some(Vec::new());
    }
    vault::handle_pdu(from_fp, payload)
}

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
    let our_fp = nc.fingerprint();
    metabolic_guard::note_peer_pulse(src.ip(), now_secs());
    if let Some(obs) = sheaf_monitor::obs_payload(&our_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &obs).await;
    }
    for queued in vault::take_outbox(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &queued).await;
    }
}

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
    metabolic_guard::note_peer_pulse(src.ip(), now_secs());
    let share = beacon_wire::share_payload(&our_fp);
    deliver(nc, sock, src, fallback, peer_fp, &share).await;
    if let Some(obs) = sheaf_monitor::obs_payload(&our_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &obs).await;
    }
    for edge_pdu in sheaf_monitor::edge_gossip_payloads() {
        deliver(nc, sock, src, fallback, peer_fp, &edge_pdu).await;
    }
    if let Some(present) = voucher::present_payload(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &present).await;
    }
    for queued in vault::take_outbox(peer_fp) {
        deliver(nc, sock, src, fallback, peer_fp, &queued).await;
    }
}

pub(crate) fn status_json(active_sessions: usize) -> serde_json::Value {
    let (grid_epoch, grid_cycle, rounds_frozen) = beacon_wire::snapshot();
    let (tracked, revoked) = braid::stats();
    serde_json::json!({
        "entropy_beacon": {
            "threshold": beacon_wire::THRESHOLD,
            "participants": active_sessions,
            "peers_per_round": active_sessions / beacon_wire::THRESHOLD,
            "grid_epoch": grid_epoch,
            "grid_cycle": grid_cycle,
            "rounds_frozen": rounds_frozen,
        },
        "braid": {
            "tracked_peers": tracked,
            "revoked_peers": revoked,
            "quarantined_peers": braid::quarantined_count(),
        },
        "vault": vault::status(),
        "voucher": voucher::stats(),
        "sheaf": sheaf_monitor::status(),
        "metabolic": metabolic_guard::status(),
        "energy_currency": repair_ledger::status(),
        "sharded_compute": compute_offload::status(),
    })
}

pub(crate) mod braid {
    use super::*;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use zeroize::Zeroize;

    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_BRAID___";

    struct OurBraid {
        chain: braid_identity::BraidLock,
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

    fn ours() -> &'static DashMap<String, Mutex<OurBraid>> {
        static OURS: OnceLock<DashMap<String, Mutex<OurBraid>>> = OnceLock::new();
        OURS.get_or_init(DashMap::new)
    }

    fn chains() -> &'static DashMap<String, Mutex<braid_identity::BraidChain>> {
        static CHAINS: OnceLock<DashMap<String, Mutex<braid_identity::BraidChain>>> =
            OnceLock::new();
        CHAINS.get_or_init(DashMap::new)
    }

    fn revoked() -> &'static DashMap<String, [u8; 32]> {
        static REVOKED: OnceLock<DashMap<String, [u8; 32]>> = OnceLock::new();
        REVOKED.get_or_init(DashMap::new)
    }

    pub(super) fn seed_for(our_fp: &str, peer_fp: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VB-BRAID-DAEMON-SEED-V1");
        hasher.update(our_fp.as_bytes());
        hasher.update(peer_fp.as_bytes());
        hasher.finalize().into()
    }

    const STATE_DIR: &str = "braid";
    const RECORD_MAGIC: &[u8; 8] = b"VBBRAID1";
    const RECORD_VERSION: u8 = 1;

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

    fn root() -> Option<&'static Path> {
        state_root().get().map(PathBuf::as_path)
    }

    pub(crate) fn init(our_fp: &str) -> usize {
        if state_root().get().is_some() {
            return 0;
        }
        let root = vantablack::ghost::paths::data_dir().join(STATE_DIR);
        if let Err(error) = std::fs::create_dir_all(&root) {
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
        let mut out =
            Vec::with_capacity(13 + our.len() + peer.len() + 73 + braid_identity::TRANSITION_BYTES);
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
        let our_fp = std::str::from_utf8(bytes.get(HEADER..our_end)?)
            .ok()?
            .to_string();
        let peer_fp = std::str::from_utf8(bytes.get(our_end..peer_end)?)
            .ok()?
            .to_string();
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
            1 if bytes.len() == tail + 1 + braid_identity::TRANSITION_BYTES => Some(
                braid_identity::Transition::from_bytes(bytes.get(tail + 1..)?)?,
            ),
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

    fn quarantined() -> &'static DashMap<String, &'static str> {
        static QUARANTINED: OnceLock<DashMap<String, &'static str>> = OnceLock::new();
        QUARANTINED.get_or_init(DashMap::new)
    }

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
            let lock =
                braid_identity::BraidLock::restore(record.secret, record.braid, record.height);
            if let Some(last) = &record.last {
                if last.height != record.height || last.next_pk != lock.identity() || !last.verify()
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

    const JOURNAL_TRANSITION: u8 = 1;
    const JOURNAL_REVOKED: u8 = 2;

    fn verifier_dir(root: &Path) -> PathBuf {
        root.join("peers")
    }

    fn valid_peer_fp(peer_fp: &str) -> bool {
        !peer_fp.is_empty()
            && peer_fp.len() <= 64
            && peer_fp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    fn append_journal(root: &Path, peer_fp: &str, kind: u8, body: &[u8]) -> std::io::Result<()> {
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

    pub(crate) fn advance_and_tip(
        our_fp: &str,
        peer_fp: &str,
        transcript: &[u8],
    ) -> Option<Vec<u8>> {
        let Some(root) = root() else {
            tracing::error!(
                peer = %peer_fp,
                "braid: state directory not initialized — refusing to publish a non-durable transition"
            );
            return None;
        };
        advance_with(Some(root), our_fp, peer_fp, transcript)
    }

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
        let peers_live = ours().len().max(2);
        let guard = ours()
            .entry(peer_fp.to_string())
            .or_insert_with(|| Mutex::new(OurBraid::genesis(our_fp, peer_fp)));
        let mut peer = guard.lock();
        let transition = peer.chain.advance(transcript);

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

    pub(crate) fn tip_payload(peer_fp: &str) -> Option<Vec<u8>> {
        let guard = ours().get(peer_fp)?;
        let peer = guard.lock();
        Some(framed(peer.last.as_ref()?))
    }

    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> bool {
        handle_pdu_at(root(), from_fp, payload)
    }

    pub(crate) fn handle_pdu_at(root: Option<&Path>, from_fp: &str, payload: &[u8]) -> bool {
        if !payload.starts_with(MAGIC) {
            return false;
        }
        let body = &payload[MAGIC.len()..];
        let Some(transition) = braid_identity::Transition::from_bytes(body) else {
            tracing::warn!(peer = %from_fp, bytes = body.len(), "braid: malformed transition dropped");
            return true;
        };
        let guard = chains().entry(from_fp.to_string()).or_default();
        let mut chain = guard.lock();
        let verdict = chain.accept(&transition);

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

    pub(crate) fn peer_revoked(peer_fp: &str) -> bool {
        revoked().contains_key(peer_fp)
    }

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

    pub(crate) fn quarantined_count() -> usize {
        quarantined().len()
    }

    #[cfg(test)]
    pub(crate) fn our_height(peer_fp: &str) -> Option<u64> {
        let guard = ours().get(peer_fp)?;
        let height = guard.lock().chain.height();
        Some(height)
    }

    #[cfg(test)]
    pub(crate) fn forget_for_test(peer_fp: &str) {
        ours().remove(peer_fp);
        chains().remove(peer_fp);
        revoked().remove(peer_fp);
    }
}

pub(crate) mod beacon_wire {
    use super::*;
    use vantablack::ghost::net::BeaconGridEpoch;

    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_EBEACON_";
    pub(crate) const THRESHOLD: usize = 3;
    pub(crate) const ROUND_SECS: u64 = 30;

    struct Wire {
        commons: entropy_beacon::EntropyBeaconCommons,
        grid: BeaconGridEpoch,
        round: u64,
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

    pub(crate) fn share_payload(our_fp: &str) -> Vec<u8> {
        let now = now_secs();
        let round = current_round(now);
        let mut entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);

        let grid_bytes = {
            let mut wire = state().lock();
            if wire.round != round {
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

    #[cfg(test)]
    pub(crate) fn last_output() -> Option<[u8; 32]> {
        state().lock().last
    }

    pub(crate) fn snapshot() -> (u64, u32, usize) {
        let wire = state().lock();
        (
            wire.grid.grid_epoch,
            wire.grid.cycle_count,
            wire.finalized.len(),
        )
    }
}

pub(crate) mod vault {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::oneshot;
    use vantablack::ghost::net::dead_drop::DropCommitment;
    use vantablack::ghost::session::Session;

    pub(crate) const DESCRIPTOR_MAGIC: &[u8; 4] = b"VBSL";
    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_VSHARE__";
    const CHUNK: usize = dead_drop::DEAD_DROP_FRAME_LEN;

    const OP_STORE_SHARE: u8 = 1;
    const OP_STORE_SHARD: u8 = 2;
    const OP_STORE_CHUNK: u8 = 3;
    const OP_FETCH: u8 = 4;
    const OP_ITEMS: u8 = 5;
    const OP_PURGE: u8 = 6;
    const OP_KEEP: u8 = 7;

    const ITEM_SHARE: u8 = 0;
    const ITEM_SHARD: u8 = 1;
    const ITEM_CHUNK: u8 = 2;

    const PLACEMENT_HOSTS: usize = 3;
    const DEFAULT_EPOCH_SECS: u64 = 3_600;
    const DEFAULT_TTL_SECS: u64 = 900;
    const MIN_EPOCH_SECS: u64 = 60;
    const MAX_INDICES_PER_PDU: usize = 256;
    const MAX_OUTBOX_PER_PEER: usize = 64;
    const FETCH_TIMEOUT: Duration = Duration::from_millis(700);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum OpenError {
        Expired,
        Corrupt,
    }

    fn window_value(raw: Option<&str>, default: u64, floor: u64) -> u64 {
        raw.and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|secs| *secs >= floor)
            .unwrap_or(default)
    }

    fn window_env(name: &str, default: u64, floor: u64) -> u64 {
        let raw = std::env::var(name).ok();
        window_value(raw.as_deref(), default, floor)
    }

    pub(crate) fn epoch_secs() -> u64 {
        static SECS: OnceLock<u64> = OnceLock::new();
        *SECS.get_or_init(|| {
            window_env(
                "GHOST_EROSION_EPOCH_SECS",
                DEFAULT_EPOCH_SECS,
                MIN_EPOCH_SECS,
            )
        })
    }

    pub(crate) fn ttl_secs() -> u64 {
        static SECS: OnceLock<u64> = OnceLock::new();
        *SECS.get_or_init(|| window_env("GHOST_EROSION_TTL_SECS", DEFAULT_TTL_SECS, 1))
    }

    #[derive(Clone)]
    struct HostedShare {
        share: [u8; 32],
    }

    impl Drop for HostedShare {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.share.zeroize();
        }
    }

    #[derive(Clone)]
    struct Plan {
        hosts: Vec<String>,
        share_hosts: Vec<Option<String>>,
        shard_hosts: Vec<Option<String>>,
        chunk_hosts: Vec<Option<String>>,
        threshold: usize,
        members: usize,
        deadline: u64,
    }

    #[derive(Clone)]
    struct Stored {
        sealed: erosion::SealedBundle,
        cipher_len: usize,
        content_hash: [u8; 32],
        local_committee: Option<erosion::EphemerizerCommittee>,
        local_archive: Option<mesh_archive::ArchivalRecord>,
        plan: Plan,
    }

    struct Pieces {
        shares: Vec<Option<[u8; 32]>>,
        shards: Vec<Option<Vec<u8>>>,
        chunks: Vec<Option<Vec<u8>>>,
    }

    fn enabled_once() -> &'static bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        ENABLED.get_or_init(|| toggle("GHOST_DTN_VAULT", true))
    }

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

    fn hosted_shares() -> &'static DashMap<([u8; 32], u8), HostedShare> {
        static HOSTED: OnceLock<DashMap<([u8; 32], u8), HostedShare>> = OnceLock::new();
        HOSTED.get_or_init(DashMap::new)
    }

    fn hosted_shards() -> &'static DashMap<([u8; 32], u8), Vec<u8>> {
        static HOSTED: OnceLock<DashMap<([u8; 32], u8), Vec<u8>>> = OnceLock::new();
        HOSTED.get_or_init(DashMap::new)
    }

    fn hosted_chunks() -> &'static DashMap<[u8; 32], Vec<DropCommitment>> {
        static HOSTED: OnceLock<DashMap<[u8; 32], Vec<DropCommitment>>> = OnceLock::new();
        HOSTED.get_or_init(DashMap::new)
    }

    fn outbox() -> &'static DashMap<String, Vec<Vec<u8>>> {
        static OUTBOX: OnceLock<DashMap<String, Vec<Vec<u8>>>> = OnceLock::new();
        OUTBOX.get_or_init(DashMap::new)
    }

    fn pending() -> &'static DashMap<[u8; 8], oneshot::Sender<Vec<(u8, Vec<u8>)>>> {
        static PENDING: OnceLock<DashMap<[u8; 8], oneshot::Sender<Vec<(u8, Vec<u8>)>>>> =
            OnceLock::new();
        PENDING.get_or_init(DashMap::new)
    }

    fn sessions() -> &'static OnceLock<Arc<DashMap<String, Session>>> {
        static SESSIONS: OnceLock<Arc<DashMap<String, Session>>> = OnceLock::new();
        &SESSIONS
    }

    pub(crate) fn bind_sessions(table: Arc<DashMap<String, Session>>) {
        let _ = sessions().set(table);
    }

    fn connected_hosts() -> Vec<String> {
        let Some(table) = sessions().get() else {
            return Vec::new();
        };
        let mut hosts: Vec<String> = table.iter().map(|entry| entry.key().clone()).collect();
        hosts.sort();
        hosts.truncate(PLACEMENT_HOSTS);
        hosts
    }

    fn fresh_committee(deadline: u64) -> Option<erosion::EphemerizerCommittee> {
        use curve25519_dalek::scalar::Scalar;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        erosion::EphemerizerCommittee::from_secret(
            2,
            3,
            deadline,
            Scalar::from_bytes_mod_order(seed),
        )
        .ok()
        .map(|(committee, _)| committee)
    }

    fn bundle_id(peer_fp: &str, payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VB-DTN-VAULT-BUNDLE-V1");
        hasher.update(peer_fp.as_bytes());
        hasher.update(payload);
        hasher.finalize().into()
    }

    fn enqueue(host: &str, payload: Vec<u8>) {
        if host.is_empty() {
            return;
        }
        let mut queue = outbox().entry(host.to_string()).or_default();
        if queue.len() >= MAX_OUTBOX_PER_PEER {
            tracing::warn!(
                peer = %host,
                cap = MAX_OUTBOX_PER_PEER,
                "vault: placement queue full — the oldest placement is dropped"
            );
            queue.remove(0);
        }
        queue.push(payload);
    }

    pub(crate) fn take_outbox(peer_fp: &str) -> Vec<Vec<u8>> {
        outbox()
            .remove(peer_fp)
            .map(|(_, queued)| queued)
            .unwrap_or_default()
    }

    pub(crate) async fn flush_outbox(
        nc: &Arc<GhostNode>,
        peers: &DashMap<String, SocketAddr>,
    ) -> usize {
        if outbox().is_empty() {
            return 0;
        }
        let hosts: Vec<String> = outbox().iter().map(|entry| entry.key().clone()).collect();
        let mut sent = 0usize;
        for host in hosts {
            if !nc.sessions.contains_key(&host) {
                continue;
            }
            let items = take_outbox(&host);
            let mut failed_at = None;
            for (index, payload) in items.iter().enumerate() {
                if !crate::daemon::tunnel::send_payload(nc, peers, &host, payload).await {
                    failed_at = Some(index);
                    break;
                }
                sent += 1;
            }
            if let Some(index) = failed_at {
                for payload in items.into_iter().skip(index) {
                    enqueue(&host, payload);
                }
            }
        }
        if sent > 0 {
            tracing::info!(
                pdus = sent,
                "vault: placement PDUs delivered to their hosts"
            );
        }
        sent
    }

    fn random_id() -> [u8; 8] {
        let mut id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }

    fn frame(op: u8, request_id: &[u8; 8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(MAGIC.len() + 9);
        payload.extend_from_slice(MAGIC);
        payload.push(op);
        payload.extend_from_slice(request_id);
        payload
    }

    fn encode_store_share(
        id: &[u8; 32],
        index: u8,
        members: u8,
        deadline: u64,
        share: &[u8; 32],
    ) -> Vec<u8> {
        let mut payload = frame(OP_STORE_SHARE, &random_id());
        payload.extend_from_slice(id);
        payload.push(index);
        payload.push(members);
        payload.extend_from_slice(&deadline.to_be_bytes());
        payload.extend_from_slice(share);
        payload
    }

    fn encode_store_shard(id: &[u8; 32], index: u8, shard: &[u8]) -> Vec<u8> {
        let mut payload = frame(OP_STORE_SHARD, &random_id());
        payload.extend_from_slice(id);
        payload.push(index);
        payload.extend_from_slice(&(shard.len() as u16).to_be_bytes());
        payload.extend_from_slice(shard);
        payload
    }

    fn encode_store_chunk(
        id: &[u8; 32],
        commitment: &DropCommitment,
        deposited_at: u64,
        ttl: u64,
        bytes: &[u8],
    ) -> Vec<u8> {
        let mut payload = frame(OP_STORE_CHUNK, &random_id());
        payload.extend_from_slice(id);
        payload.extend_from_slice(commitment);
        payload.extend_from_slice(&deposited_at.to_be_bytes());
        payload.extend_from_slice(&ttl.to_be_bytes());
        payload.extend_from_slice(bytes);
        payload
    }

    fn encode_fetch(request_id: &[u8; 8], kind: u8, id: &[u8; 32], indices: &[u8]) -> Vec<u8> {
        let mut payload = frame(OP_FETCH, request_id);
        payload.push(kind);
        payload.extend_from_slice(id);
        payload.extend_from_slice(&(indices.len() as u16).to_be_bytes());
        payload.extend_from_slice(indices);
        payload
    }

    fn encode_items(request_id: &[u8; 8], kind: u8, items: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut payload = frame(OP_ITEMS, request_id);
        payload.push(kind);
        payload.extend_from_slice(&(items.len() as u16).to_be_bytes());
        for (index, bytes) in items {
            payload.push(*index);
            payload.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            payload.extend_from_slice(bytes);
        }
        payload
    }

    fn parse_items(body: &[u8]) -> Option<(u8, Vec<(u8, Vec<u8>)>)> {
        if body.len() < 3 {
            return None;
        }
        let kind = body[0];
        let count = u16::from_be_bytes([body[1], body[2]]) as usize;
        if count > MAX_INDICES_PER_PDU {
            return None;
        }
        let mut items = Vec::with_capacity(count);
        let mut pos = 3usize;
        for _ in 0..count {
            if pos + 3 > body.len() {
                return None;
            }
            let index = body[pos];
            let len = u16::from_be_bytes([body[pos + 1], body[pos + 2]]) as usize;
            let start = pos + 3;
            let end = start.checked_add(len)?;
            if end > body.len() {
                return None;
            }
            items.push((index, body[start..end].to_vec()));
            pos = end;
        }
        Some((kind, items))
    }

    fn encode_purge(id: &[u8; 32]) -> Vec<u8> {
        let mut payload = frame(OP_PURGE, &random_id());
        payload.extend_from_slice(id);
        payload
    }

    fn encode_keep(id: &[u8; 32], commitments: &[DropCommitment]) -> Vec<u8> {
        let mut payload = frame(OP_KEEP, &random_id());
        payload.extend_from_slice(id);
        payload.extend_from_slice(&(commitments.len() as u16).to_be_bytes());
        for commitment in commitments {
            payload.extend_from_slice(commitment);
        }
        payload
    }

    pub(crate) fn deposit(peer_fp: &str, payload: &[u8]) -> Option<Vec<u8>> {
        deposit_at(peer_fp, payload, now_secs())
    }

    pub(crate) fn deposit_at(peer_fp: &str, payload: &[u8], now: u64) -> Option<Vec<u8>> {
        deposit_with_hosts(peer_fp, payload, now, &connected_hosts())
    }

    pub(crate) fn deposit_with_hosts(
        peer_fp: &str,
        payload: &[u8],
        now: u64,
        connected: &[String],
    ) -> Option<Vec<u8>> {
        let id = bundle_id(peer_fp, payload);
        if stored().contains_key(&id) {
            return None;
        }
        let die_at = now.saturating_add(ttl_secs());
        let epoch = now / epoch_secs();
        let deadline = (epoch + 1) * epoch_secs();

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

        let mut committee = fresh_committee(deadline)?;
        let threshold = committee.threshold();
        let members = committee.members();
        let Ok(sealed) = erosion::seal_bundle(&committee, &id, die_at, &key, now) else {
            tracing::error!(peer = %peer_fp, "erosion: committee could not seal the bundle");
            return None;
        };

        let mut wrapped = Vec::with_capacity(nonce.len() + cipher.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&cipher);
        let record =
            mesh_archive::ArchivalRecord::create(format!("vb:drop:{}", hex::encode(id)), &wrapped);
        let content_hash = record.content_hash;

        let pieces: Vec<&[u8]> = wrapped.chunks(CHUNK).collect();
        let chunks: Vec<DropCommitment> = (0..pieces.len())
            .map(|index| dead_drop::BlindDeadDropBlob::derive_commitment(&id, index as u64))
            .collect();

        let hosts: Vec<String> = connected.iter().take(PLACEMENT_HOSTS).cloned().collect();
        let distributed = hosts.len() >= PLACEMENT_HOSTS;

        let mut share_hosts = vec![None; committee.members()];
        let mut shard_hosts = vec![None; 3];
        let mut chunk_hosts = vec![None; chunks.len()];
        let mut local_committee = None;
        let mut local_archive = None;

        if distributed {
            for index in 0..committee.members() {
                let host = hosts[index % hosts.len()].clone();
                if let Some(share) = committee.share_bytes(index) {
                    enqueue(
                        &host,
                        encode_store_share(
                            &id,
                            index as u8,
                            committee.members() as u8,
                            deadline,
                            &share,
                        ),
                    );
                    share_hosts[index] = Some(host);
                }
            }
            for (index, shard) in record.shards.iter().enumerate().take(3) {
                let host = hosts[index % hosts.len()].clone();
                enqueue(&host, encode_store_shard(&id, index as u8, shard));
                shard_hosts[index] = Some(host);
            }
            for (index, piece) in pieces.iter().enumerate() {
                let host = hosts[index % hosts.len()].clone();
                enqueue(
                    &host,
                    encode_store_chunk(&id, &chunks[index], now, ttl_secs(), piece),
                );
                chunk_hosts[index] = Some(host);
            }
            committee.expire();
        } else {
            for (index, piece) in pieces.iter().enumerate() {
                blobs().deposit(dead_drop::BlindDeadDropBlob::new(
                    chunks[index],
                    piece,
                    now,
                    ttl_secs(),
                ));
            }
            local_archive = Some(record);
            local_committee = Some(committee);
        }

        stored().insert(
            id,
            Stored {
                sealed: sealed.clone(),
                cipher_len: cipher.len(),
                content_hash,
                local_committee,
                local_archive,
                plan: Plan {
                    hosts: if distributed { hosts } else { Vec::new() },
                    share_hosts,
                    shard_hosts,
                    chunk_hosts,
                    threshold,
                    members,
                    deadline,
                },
            },
        );

        tracing::info!(
            peer = %peer_fp,
            bundle = %short(&id),
            bytes = payload.len(),
            chunks = chunks.len(),
            archive_shards = 3,
            epoch,
            die_at,
            hosts = connected.len().min(PLACEMENT_HOSTS),
            distributed,
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
        chunks: Vec<DropCommitment>,
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

    fn fetch_reply(request_id: &[u8; 8], body: &[u8]) -> Option<Vec<u8>> {
        if body.len() < 35 {
            return None;
        }
        let kind = body[0];
        let mut id = [0u8; 32];
        id.copy_from_slice(&body[1..33]);
        let count = u16::from_be_bytes([body[33], body[34]]) as usize;
        if count > MAX_INDICES_PER_PDU || body.len() != 35 + count {
            return None;
        }
        let mut items: Vec<(u8, Vec<u8>)> = Vec::with_capacity(count);
        for &index in &body[35..] {
            match kind {
                ITEM_SHARE => {
                    if let Some(hosted) = hosted_shares().get(&(id, index)) {
                        items.push((index, hosted.share.to_vec()));
                    }
                }
                ITEM_SHARD => {
                    if let Some(shard) = hosted_shards().get(&(id, index)) {
                        items.push((index, shard.value().clone()));
                    }
                }
                ITEM_CHUNK => {
                    let commitment =
                        dead_drop::BlindDeadDropBlob::derive_commitment(&id, index as u64);
                    if let Some(blob) = blobs().sweep(&commitment) {
                        items.push((index, blob.opaque_ciphertext.to_vec()));
                    }
                }
                _ => return None,
            }
        }
        Some(encode_items(request_id, kind, &items))
    }

    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> Option<Vec<Vec<u8>>> {
        if !payload.starts_with(MAGIC) {
            return None;
        }
        let rest = &payload[MAGIC.len()..];
        if rest.len() < 9 {
            tracing::warn!(peer = %from_fp, bytes = rest.len(), "vault: truncated control PDU");
            return Some(Vec::new());
        }
        let op = rest[0];
        let mut request_id = [0u8; 8];
        request_id.copy_from_slice(&rest[1..9]);
        let body = &rest[9..];
        let mut replies = Vec::new();

        match op {
            OP_STORE_SHARE => {
                if body.len() != 32 + 1 + 1 + 8 + 32 {
                    tracing::warn!(peer = %from_fp, "vault: malformed share placement");
                } else {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&body[..32]);
                    let index = body[32];
                    let members = body[33] as usize;
                    let deadline = u64::from_be_bytes(body[34..42].try_into().expect("8 bytes"));
                    let mut share = [0u8; 32];
                    share.copy_from_slice(&body[42..74]);
                    if members == 0 || index as usize >= members || deadline == 0 {
                        tracing::warn!(peer = %from_fp, index, members, "vault: share placement out of range");
                    } else {
                        hosted_shares().insert((id, index), HostedShare { share });
                        tracing::info!(
                            peer = %from_fp,
                            bundle = %short(&id),
                            index,
                            members,
                            "vault: hosting an erosion share"
                        );
                    }
                }
            }
            OP_STORE_SHARD => {
                if body.len() < 35
                    || body.len() != 35 + u16::from_be_bytes([body[33], body[34]]) as usize
                {
                    tracing::warn!(peer = %from_fp, "vault: malformed shard placement");
                } else {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&body[..32]);
                    let index = body[32];
                    hosted_shards().insert((id, index), body[35..].to_vec());
                    tracing::info!(
                        peer = %from_fp,
                        bundle = %short(&id),
                        index,
                        bytes = body.len() - 35,
                        "vault: hosting an archive shard"
                    );
                }
            }
            OP_STORE_CHUNK => {
                if body.len() < 80 {
                    tracing::warn!(peer = %from_fp, "vault: malformed chunk placement");
                } else {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&body[..32]);
                    let mut commitment = [0u8; 32];
                    commitment.copy_from_slice(&body[32..64]);
                    let deposited_at =
                        u64::from_be_bytes(body[64..72].try_into().expect("8 bytes"));
                    let ttl = u64::from_be_bytes(body[72..80].try_into().expect("8 bytes"));
                    blobs().deposit(dead_drop::BlindDeadDropBlob::new(
                        commitment,
                        &body[80..],
                        deposited_at,
                        ttl,
                    ));
                    hosted_chunks().entry(id).or_default().push(commitment);
                    tracing::debug!(
                        peer = %from_fp,
                        bundle = %short(&id),
                        bytes = body.len() - 80,
                        "vault: hosting a blind chunk"
                    );
                }
            }
            OP_FETCH => {
                if let Some(reply) = fetch_reply(&request_id, body) {
                    replies.push(reply);
                } else {
                    tracing::warn!(peer = %from_fp, "vault: malformed fetch");
                }
            }
            OP_ITEMS => match parse_items(body) {
                Some((_kind, items)) => {
                    if let Some((_, waiter)) = pending().remove(&request_id) {
                        let _ = waiter.send(items);
                    }
                }
                None => tracing::warn!(peer = %from_fp, "vault: malformed fetch reply"),
            },
            OP_PURGE => {
                if body.len() != 32 {
                    tracing::warn!(peer = %from_fp, "vault: malformed purge");
                } else {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(body);
                    hosted_shares().retain(|key, _| key.0 != id);
                    hosted_shards().retain(|key, _| key.0 != id);
                    if let Some((_, commitments)) = hosted_chunks().remove(&id) {
                        for commitment in commitments {
                            blobs().sweep_and_consume(&commitment);
                        }
                    }
                    tracing::info!(
                        peer = %from_fp,
                        bundle = %short(&id),
                        "vault: purge — this host's copy is gone"
                    );
                }
            }
            OP_KEEP => {
                if body.len() < 34 {
                    tracing::warn!(peer = %from_fp, "vault: malformed keep-proof");
                } else {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&body[..32]);
                    let count = u16::from_be_bytes([body[32], body[33]]) as usize;
                    if count > MAX_INDICES_PER_PDU || body.len() != 34 + 32 * count {
                        tracing::warn!(peer = %from_fp, count, "vault: keep-proof does not match its count");
                    } else {
                        let now = now_secs();
                        let mut kept = 0usize;
                        for slot in 0..count {
                            let mut commitment = [0u8; 32];
                            commitment.copy_from_slice(&body[34 + 32 * slot..66 + 32 * slot]);
                            if blobs().prove_retention_interest(&commitment, now) {
                                kept += 1;
                            }
                        }
                        tracing::debug!(
                            peer = %from_fp,
                            bundle = %short(&id),
                            kept,
                            "vault: retention interest renewed"
                        );
                    }
                }
            }
            other => tracing::warn!(peer = %from_fp, op = other, "vault: unknown control opcode"),
        }
        Some(replies)
    }

    pub(crate) fn open_at(payload: &[u8], now: u64) -> Result<Vec<u8>, OpenError> {
        let Some(descriptor) = parse_descriptor(payload) else {
            return Ok(payload.to_vec());
        };
        if expired(&descriptor, now) {
            return Err(OpenError::Expired);
        }
        let Some(stored_bundle) = stored()
            .get(&descriptor.id)
            .map(|entry| entry.value().clone())
        else {
            return Err(OpenError::Corrupt);
        };
        if stored_bundle.sealed.tag != descriptor.tag
            || stored_bundle.sealed.die_at != descriptor.die_at
        {
            tracing::warn!(bundle = %short(&descriptor.id), "dead-drop: descriptor does not match the stored bundle");
            return Err(OpenError::Corrupt);
        }
        if !stored_bundle.plan.hosts.is_empty() {
            tracing::warn!(
                bundle = %short(&descriptor.id),
                hosts = stored_bundle.plan.hosts.len(),
                "vault: bundle is distributed — open it over the mesh, not locally"
            );
            return Err(OpenError::Corrupt);
        }
        let pieces = local_pieces(&descriptor, &stored_bundle)?;
        complete(&stored_bundle, &descriptor, pieces, now)
    }

    pub(crate) async fn open_mesh(
        nc: &Arc<GhostNode>,
        peers: &DashMap<String, SocketAddr>,
        payload: &[u8],
    ) -> Result<Vec<u8>, OpenError> {
        let Some(descriptor) = parse_descriptor(payload) else {
            return Ok(payload.to_vec());
        };
        let now = now_secs();
        if expired(&descriptor, now) {
            return Err(OpenError::Expired);
        }
        let Some(stored_bundle) = stored()
            .get(&descriptor.id)
            .map(|entry| entry.value().clone())
        else {
            return Err(OpenError::Corrupt);
        };
        if stored_bundle.sealed.tag != descriptor.tag
            || stored_bundle.sealed.die_at != descriptor.die_at
        {
            tracing::warn!(bundle = %short(&descriptor.id), "dead-drop: descriptor does not match the stored bundle");
            return Err(OpenError::Corrupt);
        }
        if stored_bundle.plan.hosts.is_empty() {
            return open_at(payload, now);
        }

        let pieces = fetch_pieces(nc, peers, &descriptor, &stored_bundle).await;
        if pieces.shares.iter().flatten().count() < stored_bundle.plan.threshold {
            tracing::warn!(
                bundle = %short(&descriptor.id),
                have = pieces.shares.iter().flatten().count(),
                threshold = stored_bundle.plan.threshold,
                "erosion: hosts did not return threshold shares — the key is unobtainable"
            );
            return Err(OpenError::Expired);
        }
        let plain = complete(&stored_bundle, &descriptor, pieces, now)?;
        keep_hot(&descriptor, &stored_bundle);
        Ok(plain)
    }

    fn expired(descriptor: &Descriptor, now: u64) -> bool {
        if now < descriptor.die_at {
            return false;
        }
        if let Some((_, bundle)) = stored().remove(&descriptor.id) {
            purge_hosts(&descriptor.id, &bundle.plan);
        }
        reap_expired(now_secs());
        EXPIRED.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            bundle = %short(&descriptor.id),
            die_at = descriptor.die_at,
            "erosion: bundle outlived its epoch — key forgotten, payload destroyed"
        );
        true
    }

    fn local_pieces(descriptor: &Descriptor, stored: &Stored) -> Result<Pieces, OpenError> {
        let total = 12 + stored.cipher_len;
        let mut chunks = Vec::with_capacity(descriptor.chunks.len());
        let mut collected = 0usize;
        for commitment in &descriptor.chunks {
            let Some(blob) = blobs().sweep(commitment) else {
                tracing::warn!(bundle = %short(&descriptor.id), "dead-drop: chunk missing on sweep");
                return Err(OpenError::Corrupt);
            };
            let used = blob
                .opaque_ciphertext
                .len()
                .min(total.saturating_sub(collected));
            collected += used;
            chunks.push(Some(blob.opaque_ciphertext[..used].to_vec()));
        }
        let shares = match &stored.local_committee {
            Some(committee) => (0..committee.members())
                .map(|index| committee.share_bytes(index))
                .collect(),
            None => vec![None; stored.plan.members],
        };
        let shards = match &stored.local_archive {
            Some(record) => (0..3)
                .map(|index| {
                    if index == 1 {
                        None
                    } else {
                        record.shards.get(index).cloned()
                    }
                })
                .collect(),
            None => vec![None; 3],
        };
        Ok(Pieces {
            shares,
            shards,
            chunks,
        })
    }

    async fn fetch_pieces(
        nc: &Arc<GhostNode>,
        peers: &DashMap<String, SocketAddr>,
        descriptor: &Descriptor,
        stored: &Stored,
    ) -> Pieces {
        let plan = &stored.plan;
        let mut pieces = Pieces {
            shares: vec![None; plan.members],
            shards: vec![None; 3],
            chunks: vec![None; descriptor.chunks.len()],
        };

        let mut share_requests: HashMap<&str, Vec<u8>> = HashMap::new();
        for (index, host) in plan.share_hosts.iter().enumerate() {
            if let Some(host) = host {
                share_requests
                    .entry(host.as_str())
                    .or_default()
                    .push(index as u8);
            }
        }
        for (host, indices) in share_requests {
            for (index, bytes) in fetch(nc, peers, host, ITEM_SHARE, &descriptor.id, &indices).await
            {
                if bytes.len() == 32 {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(&bytes);
                    if let Some(slot) = pieces.shares.get_mut(index as usize) {
                        *slot = Some(share);
                    }
                }
            }
        }

        let mut shard_requests: HashMap<&str, Vec<u8>> = HashMap::new();
        for (index, host) in plan.shard_hosts.iter().enumerate() {
            if let Some(host) = host {
                shard_requests
                    .entry(host.as_str())
                    .or_default()
                    .push(index as u8);
            }
        }
        for (host, indices) in shard_requests {
            for (index, bytes) in fetch(nc, peers, host, ITEM_SHARD, &descriptor.id, &indices).await
            {
                if let Some(slot) = pieces.shards.get_mut(index as usize) {
                    *slot = Some(bytes);
                }
            }
        }

        let mut chunk_requests: HashMap<&str, Vec<u8>> = HashMap::new();
        for (index, host) in plan.chunk_hosts.iter().enumerate() {
            match host {
                Some(host) => chunk_requests
                    .entry(host.as_str())
                    .or_default()
                    .push(index as u8),
                None => {
                    if let Some(blob) = blobs().sweep(&descriptor.chunks[index]) {
                        pieces.chunks[index] = Some(blob.opaque_ciphertext.to_vec());
                    }
                }
            }
        }
        for (host, indices) in chunk_requests {
            for (index, bytes) in fetch(nc, peers, host, ITEM_CHUNK, &descriptor.id, &indices).await
            {
                if let Some(slot) = pieces.chunks.get_mut(index as usize) {
                    *slot = Some(bytes);
                }
            }
        }
        pieces
    }

    async fn fetch(
        nc: &Arc<GhostNode>,
        peers: &DashMap<String, SocketAddr>,
        host: &str,
        kind: u8,
        bundle: &[u8; 32],
        indices: &[u8],
    ) -> Vec<(u8, Vec<u8>)> {
        if indices.is_empty() {
            return Vec::new();
        }
        let request_id = random_id();
        let (sender, receiver) = oneshot::channel();
        pending().insert(request_id, sender);
        let payload = encode_fetch(&request_id, kind, bundle, indices);
        if !crate::daemon::tunnel::send_payload(nc, peers, host, &payload).await {
            pending().remove(&request_id);
            return Vec::new();
        }
        match tokio::time::timeout(FETCH_TIMEOUT, receiver).await {
            Ok(Ok(items)) => items,
            _ => {
                pending().remove(&request_id);
                tracing::debug!(
                    peer = %host,
                    kind,
                    bundle = %short(bundle),
                    "vault: host did not answer the fetch"
                );
                Vec::new()
            }
        }
    }

    fn complete(
        stored: &Stored,
        descriptor: &Descriptor,
        pieces: Pieces,
        now: u64,
    ) -> Result<Vec<u8>, OpenError> {
        let total = 12 + stored.cipher_len;
        let mut wrapped = Vec::with_capacity(total);
        for slot in &pieces.chunks {
            if wrapped.len() >= total {
                break;
            }
            let Some(bytes) = slot else {
                tracing::warn!(bundle = %short(&descriptor.id), "dead-drop: chunk missing on recovery");
                return Err(OpenError::Corrupt);
            };
            let used = bytes.len().min(total - wrapped.len());
            wrapped.extend_from_slice(&bytes[..used]);
        }
        if wrapped.len() != total {
            tracing::warn!(
                bundle = %short(&descriptor.id),
                got = wrapped.len(),
                want = total,
                "dead-drop: recovered stream is truncated"
            );
            return Err(OpenError::Corrupt);
        }

        let verifier = mesh_archive::ArchivalRecord {
            canonical_uri: format!("vb:drop:{}", hex::encode(descriptor.id)),
            content_hash: stored.content_hash,
            shards: Vec::new(),
        };
        let reconstructed = verifier.reconstruct(&pieces.shards).map_err(|error| {
            tracing::warn!(bundle = %short(&descriptor.id), %error, "mesh-archive: integrity failure");
            OpenError::Corrupt
        })?;
        if reconstructed != wrapped {
            tracing::warn!(bundle = %short(&descriptor.id), "mesh-archive: recovered bytes differ from the sealed stream");
            return Err(OpenError::Corrupt);
        }

        let committee = match &stored.local_committee {
            Some(committee) => committee.clone(),
            None => erosion::EphemerizerCommittee::from_shares(
                stored.plan.threshold,
                stored.plan.members,
                stored.plan.deadline,
                pieces.shares.clone(),
            )
            .map_err(|error| {
                tracing::warn!(bundle = %short(&descriptor.id), %error, "erosion: threshold shares unavailable");
                OpenError::Expired
            })?,
        };
        let sealed = erosion::SealedBundle {
            bundle_id: descriptor.id,
            die_at: descriptor.die_at,
            wrapped_key: descriptor.wrapped_key,
            tag: descriptor.tag,
        };
        let key = erosion::open_bundle(&committee, &sealed, now).map_err(|error| {
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

    pub(crate) fn forget(payload: &[u8]) {
        let Some(descriptor) = parse_descriptor(payload) else {
            return;
        };
        if let Some((_, stored_bundle)) = stored().remove(&descriptor.id) {
            purge_hosts(&descriptor.id, &stored_bundle.plan);
        }
        for commitment in &descriptor.chunks {
            blobs().sweep_and_consume(commitment);
        }
    }

    fn purge_hosts(id: &[u8; 32], plan: &Plan) {
        let mut hosts: Vec<&String> = plan.hosts.iter().collect();
        hosts.sort();
        hosts.dedup();
        for host in hosts {
            enqueue(host, encode_purge(id));
        }
    }

    fn keep_hot(descriptor: &Descriptor, stored: &Stored) {
        let now = now_secs();
        for commitment in &descriptor.chunks {
            blobs().prove_retention_interest(commitment, now);
        }
        let mut by_host: HashMap<&str, Vec<DropCommitment>> = HashMap::new();
        for (index, host) in stored.plan.chunk_hosts.iter().enumerate() {
            if let Some(host) = host {
                if let Some(commitment) = descriptor.chunks.get(index) {
                    by_host.entry(host.as_str()).or_default().push(*commitment);
                }
            }
        }
        for (host, commitments) in by_host {
            enqueue(host, encode_keep(&descriptor.id, &commitments));
        }
    }

    pub(crate) fn reap_expired(now: u64) -> usize {
        let dead: Vec<[u8; 32]> = stored()
            .iter()
            .filter(|entry| {
                let bundle = entry.value();
                now >= bundle.sealed.die_at || now >= bundle.plan.deadline
            })
            .map(|entry| *entry.key())
            .collect();
        for id in &dead {
            if let Some((_, bundle)) = stored().remove(id) {
                purge_hosts(id, &bundle.plan);
            }
        }
        dead.len()
    }

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

    pub(crate) fn collect_decay() -> usize {
        let now = now_secs();
        let reaped = reap_expired(now);
        let rate = observed_error_rate();
        let removed = blobs().collect_self_eating_decay(now, rate);
        if removed > 0 || reaped > 0 {
            tracing::info!(
                removed,
                reaped,
                error_rate = rate,
                multiplier = 1.0 + rate * 4.0,
                "dead-drop: self-eating decay reclaimed cold chunks"
            );
        }
        removed + reaped
    }

    pub(crate) fn status() -> serde_json::Value {
        let total = stored().len();
        let distributed = stored()
            .iter()
            .filter(|entry| !entry.value().plan.hosts.is_empty())
            .count();
        serde_json::json!({
            "stored": total,
            "distributed": distributed,
            "local_only": total.saturating_sub(distributed),
            "hosted_shares": hosted_shares().len(),
            "hosted_shards": hosted_shards().len(),
            "hosted_chunks": hosted_chunks().iter().map(|e| e.value().len()).sum::<usize>(),
            "epoch_secs": epoch_secs(),
            "ttl_secs": ttl_secs(),
        })
    }

    #[cfg(test)]
    pub(crate) fn stored_count() -> usize {
        stored().len()
    }

    #[cfg(test)]
    pub(crate) fn chunk_count() -> usize {
        blobs().stored_count()
    }

    #[cfg(test)]
    pub(crate) fn distributed_hosts_for_test(payload: &[u8]) -> Option<Vec<String>> {
        let descriptor = parse_descriptor(payload)?;
        let bundle = stored().get(&descriptor.id)?.value().clone();
        (!bundle.plan.hosts.is_empty()).then_some(bundle.plan.hosts)
    }

    #[cfg(test)]
    pub(crate) fn open_from_hosts_for_test(payload: &[u8], now: u64) -> Result<Vec<u8>, OpenError> {
        let Some(descriptor) = parse_descriptor(payload) else {
            return Ok(payload.to_vec());
        };
        if now >= descriptor.die_at {
            return Err(OpenError::Expired);
        }
        let Some(bundle) = stored()
            .get(&descriptor.id)
            .map(|entry| entry.value().clone())
        else {
            return Err(OpenError::Corrupt);
        };
        let mut pieces = Pieces {
            shares: vec![None; bundle.plan.members],
            shards: vec![None; 3],
            chunks: vec![None; descriptor.chunks.len()],
        };
        for (index, host) in bundle.plan.share_hosts.iter().enumerate() {
            if host.is_some() {
                if let Some(hosted) = hosted_shares().get(&(descriptor.id, index as u8)) {
                    pieces.shares[index] = Some(hosted.share);
                }
            }
        }
        for (index, host) in bundle.plan.shard_hosts.iter().enumerate() {
            if host.is_some() {
                if let Some(shard) = hosted_shards().get(&(descriptor.id, index as u8)) {
                    pieces.shards[index] = Some(shard.value().clone());
                }
            }
        }
        for (index, _host) in bundle.plan.chunk_hosts.iter().enumerate() {
            if let Some(blob) = blobs().sweep(&descriptor.chunks[index]) {
                pieces.chunks[index] = Some(blob.opaque_ciphertext.to_vec());
            }
        }
        complete(&bundle, &descriptor, pieces, now)
    }

    #[cfg(test)]
    pub(crate) fn local_chunks_for_test(payload: &[u8]) -> Option<usize> {
        let descriptor = parse_descriptor(payload)?;
        Some(
            descriptor
                .chunks
                .iter()
                .filter(|commitment| blobs().sweep(commitment).is_some())
                .count(),
        )
    }

    #[cfg(test)]
    pub(crate) fn hosted_counts_for_test() -> (usize, usize, usize) {
        (
            hosted_shares().len(),
            hosted_shards().len(),
            hosted_chunks()
                .iter()
                .map(|entry| entry.value().len())
                .sum(),
        )
    }

    #[cfg(test)]
    pub(crate) fn clear_hosts_for_test() {
        hosted_shares().clear();
        hosted_shards().clear();
        for entry in hosted_chunks().iter() {
            for commitment in entry.value() {
                blobs().sweep_and_consume(commitment);
            }
        }
        hosted_chunks().clear();
    }

    #[cfg(test)]
    pub(crate) fn hosted_keep_timestamp(commitment: &DropCommitment) -> Option<u64> {
        blobs()
            .sweep(commitment)
            .map(|blob| blob.last_kept_timestamp)
    }

    #[cfg(test)]
    pub(crate) fn store_chunk_for_test(
        id: &[u8; 32],
        commitment: &DropCommitment,
        deposited_at: u64,
        ttl: u64,
        bytes: &[u8],
    ) -> Vec<u8> {
        encode_store_chunk(id, commitment, deposited_at, ttl, bytes)
    }

    #[cfg(test)]
    pub(crate) fn keep_for_test(id: &[u8; 32], commitments: &[DropCommitment]) -> Vec<u8> {
        encode_keep(id, commitments)
    }

    #[cfg(test)]
    pub(crate) fn purge_for_test(id: &[u8; 32]) -> Vec<u8> {
        encode_purge(id)
    }

    #[cfg(test)]
    pub(crate) fn window_value_for_test(raw: Option<&str>, default: u64, floor: u64) -> u64 {
        window_value(raw, default, floor)
    }
}

pub(crate) mod voucher {
    use super::*;
    use vantablack::ghost::net::bandwidth_voucher::{BandwidthVoucher, RelayBandwidthBank};

    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_VOUCHER_";
    const QUOTA_MB: u32 = 16;
    const EPOCH_SECS: u64 = 3_600;
    const POW_BITS: u8 = 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Transit {
        Blind,
        Onion,
    }

    struct Bank {
        relay: RelayBandwidthBank,
        by_peer: HashMap<String, [u8; 32]>,
        issued: HashMap<String, u64>,
        admitted: u64,
        denied: u64,
        blind_bytes: u64,
        onion_bytes: u64,
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
                blind_bytes: 0,
                onion_bytes: 0,
            })
        })
    }

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
            Err(reason) => {
                tracing::debug!(peer = %from_fp, reason, "voucher: presentation refused")
            }
        }
        true
    }

    pub(crate) fn admit_transit(from_fp: &str, bytes: usize) -> bool {
        admit_transit_as(from_fp, bytes, Transit::Blind)
    }

    pub(crate) fn admit_transit_onion(from_fp: &str, bytes: usize) -> bool {
        admit_transit_as(from_fp, bytes, Transit::Onion)
    }

    fn admit_transit_as(from_fp: &str, bytes: usize, path: Transit) -> bool {
        if !enabled() {
            return true;
        }
        let mut bank = state().lock();
        let Some(nullifier) = bank.by_peer.get(from_fp).copied() else {
            bank.denied = bank.denied.saturating_add(1);
            tracing::warn!(peer = %from_fp, ?path, "voucher: no banked voucher — relay transit refused");
            return false;
        };
        let charge = (bytes as u64).div_ceil(1_048_576).max(1) as u32;
        if bank.relay.consume_bandwidth(&nullifier, charge) {
            bank.admitted = bank.admitted.saturating_add(1);
            match path {
                Transit::Blind => bank.blind_bytes = bank.blind_bytes.saturating_add(bytes as u64),
                Transit::Onion => bank.onion_bytes = bank.onion_bytes.saturating_add(bytes as u64),
            }
            tracing::debug!(
                peer = %from_fp,
                ?path,
                mb = charge,
                remaining = bank.relay.remaining_quota(&nullifier),
                "voucher: relay transit charged"
            );
            true
        } else {
            bank.denied = bank.denied.saturating_add(1);
            tracing::warn!(peer = %from_fp, ?path, mb = charge, "voucher: credit exhausted — relay transit refused");
            false
        }
    }

    pub(crate) fn stats() -> serde_json::Value {
        let bank = state().lock();
        serde_json::json!({
            "enabled": enabled(),
            "admitted": bank.admitted,
            "denied": bank.denied,
            "blind_bytes": bank.blind_bytes,
            "onion_bytes": bank.onion_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn present_for_test(
        from_fp: &str,
        voucher: &BandwidthVoucher,
    ) -> Result<u32, &'static str> {
        let mut bank = state().lock();
        let granted = bank.relay.redeem_voucher(voucher)?;
        bank.by_peer
            .insert(from_fp.to_string(), voucher.compute_nullifier());
        Ok(granted)
    }

    #[cfg(test)]
    pub(crate) fn charge_for_test(from_fp: &str, bytes: usize) -> bool {
        charge_as_for_test(from_fp, bytes, Transit::Blind)
    }

    #[cfg(test)]
    pub(crate) fn charge_as_for_test(from_fp: &str, bytes: usize, path: Transit) -> bool {
        let mut bank = state().lock();
        let Some(nullifier) = bank.by_peer.get(from_fp).copied() else {
            return false;
        };
        let charge = (bytes as u64).div_ceil(1_048_576).max(1) as u32;
        let granted = bank.relay.consume_bandwidth(&nullifier, charge);
        if granted {
            match path {
                Transit::Blind => bank.blind_bytes = bank.blind_bytes.saturating_add(bytes as u64),
                Transit::Onion => bank.onion_bytes = bank.onion_bytes.saturating_add(bytes as u64),
            }
        }
        granted
    }
}

pub(crate) mod worlds {
    use super::*;

    pub(crate) const MAGIC: &[u8; 4] = b"GBWD";
    const VERSION: u8 = 1;
    const HEADER: usize = 16;
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

    pub(crate) fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| toggle("GHOST_BOND_WORLDS", false))
    }

    pub(crate) fn encode_probe(n: usize, tag: &[u8; 4]) -> Option<([u8; 8], u8, u8, Vec<Vec<u8>>)> {
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

    pub(crate) fn wrap(id: &[u8; 8], path: u8, n: u8, k: u8, shard: &[u8]) -> Vec<u8> {
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

    pub(crate) fn handle_datagram(
        datagram: &[u8],
        from: IpAddr,
    ) -> Option<(Vec<usize>, [u8; MESSAGE])> {
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

    #[cfg(test)]
    pub(crate) fn group_count() -> usize {
        groups().lock().len()
    }
}

pub(crate) mod sheaf_monitor {
    use super::*;

    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_SHEAF___";
    const OP_OBS: u8 = 1;
    const OP_EDGE: u8 = 2;
    const DIMENSION: usize = 3;
    const MAX_EDGES: usize = 512;

    #[derive(Default)]
    struct SheafState {
        local_fp: Option<String>,
        local_obs: [i64; DIMENSION],
        vertex_ids: HashMap<String, usize>,
        edges: HashMap<(String, String), (String, String, [i64; DIMENSION])>,
    }

    impl SheafState {
        fn vertex(&mut self, fp: &str) -> usize {
            if let Some(&idx) = self.vertex_ids.get(fp) {
                return idx;
            }
            let idx = self.vertex_ids.len();
            self.vertex_ids.insert(fp.to_string(), idx);
            idx
        }

        fn record_edge(&mut self, u_fp: &str, v_fp: &str, delta: [i64; DIMENSION]) {
            if u_fp == v_fp {
                return;
            }
            let key = if u_fp < v_fp {
                (u_fp.to_string(), v_fp.to_string())
            } else {
                (v_fp.to_string(), u_fp.to_string())
            };
            if self.edges.len() >= MAX_EDGES && !self.edges.contains_key(&key) {
                return;
            }
            self.vertex(u_fp);
            self.vertex(v_fp);
            self.edges
                .insert(key, (u_fp.to_string(), v_fp.to_string(), delta));
        }

        fn evaluate(&self) -> (usize, usize, bool, usize) {
            let vertices = self.vertex_ids.len();
            if vertices == 0 || self.edges.is_empty() {
                return (vertices, 0, false, 0);
            }
            let mut complex = sheaf::SheafComplex::new(vertices, DIMENSION);
            for (u_fp, v_fp, delta) in self.edges.values() {
                if let (Some(&u), Some(&v)) = (self.vertex_ids.get(u_fp), self.vertex_ids.get(v_fp))
                {
                    let _ = complex.connect(u, v, delta.to_vec());
                }
            }
            let obs = complex.obstructions();
            (vertices, complex.edges().len(), !obs.is_empty(), obs.len())
        }
    }

    fn state() -> &'static Mutex<SheafState> {
        static STATE: OnceLock<Mutex<SheafState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(SheafState::default()))
    }

    pub(crate) fn enabled() -> bool {
        toggle("GHOST_SHEAF", true)
    }

    pub(crate) fn current_observation() -> [i64; DIMENSION] {
        let (grid_epoch, grid_cycle, rounds_frozen) = beacon_wire::snapshot();
        [grid_epoch as i64, grid_cycle as i64, rounds_frozen as i64]
    }

    pub(crate) fn obs_payload(our_fp: &str) -> Option<Vec<u8>> {
        if !enabled() {
            return None;
        }
        let obs = current_observation();
        {
            let mut st = state().lock();
            st.local_fp = Some(our_fp.to_string());
            st.local_obs = obs;
            st.vertex(our_fp);
        }
        let fp_bytes = our_fp.as_bytes();
        let fp_len = u8::try_from(fp_bytes.len()).ok()?;
        let mut out = Vec::with_capacity(14 + 1 + 1 + fp_bytes.len() + DIMENSION * 8);
        out.extend_from_slice(MAGIC);
        out.push(OP_OBS);
        out.push(fp_len);
        out.extend_from_slice(fp_bytes);
        for val in obs {
            out.extend_from_slice(&val.to_be_bytes());
        }
        Some(out)
    }

    pub(crate) fn edge_gossip_payloads() -> Vec<Vec<u8>> {
        if !enabled() {
            return Vec::new();
        }
        let st = state().lock();
        let mut out = Vec::new();
        for (u_fp, v_fp, delta) in st.edges.values().take(16) {
            let (Ok(ul), Ok(vl)) = (u8::try_from(u_fp.len()), u8::try_from(v_fp.len())) else {
                continue;
            };
            let mut pdu = Vec::with_capacity(14 + 1 + 2 + u_fp.len() + v_fp.len() + DIMENSION * 8);
            pdu.extend_from_slice(MAGIC);
            pdu.push(OP_EDGE);
            pdu.push(ul);
            pdu.extend_from_slice(u_fp.as_bytes());
            pdu.push(vl);
            pdu.extend_from_slice(v_fp.as_bytes());
            for val in delta {
                pdu.extend_from_slice(&val.to_be_bytes());
            }
            out.push(pdu);
        }
        out
    }

    fn parse_i64_triple(bytes: &[u8]) -> Option<[i64; DIMENSION]> {
        if bytes.len() != DIMENSION * 8 {
            return None;
        }
        Some([
            i64::from_be_bytes(bytes[0..8].try_into().ok()?),
            i64::from_be_bytes(bytes[8..16].try_into().ok()?),
            i64::from_be_bytes(bytes[16..24].try_into().ok()?),
        ])
    }

    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> bool {
        if payload.len() < 15 || &payload[..14] != MAGIC {
            return false;
        }
        if !enabled() {
            return true;
        }
        let op = payload[14];
        let body = &payload[15..];
        match op {
            OP_OBS => {
                let Some(&fp_len) = body.first() else {
                    return true;
                };
                let fp_len = fp_len as usize;
                if body.len() != 1 + fp_len + DIMENSION * 8 {
                    return true;
                }
                let Ok(claimed_fp) = std::str::from_utf8(&body[1..1 + fp_len]) else {
                    return true;
                };
                if claimed_fp != from_fp {
                    return true;
                }
                let Some(peer_obs) = parse_i64_triple(&body[1 + fp_len..]) else {
                    return true;
                };
                let mut st = state().lock();
                if let Some(our_fp) = st.local_fp.clone() {
                    let delta = [
                        peer_obs[0].saturating_sub(st.local_obs[0]),
                        peer_obs[1].saturating_sub(st.local_obs[1]),
                        peer_obs[2].saturating_sub(st.local_obs[2]),
                    ];
                    st.record_edge(&our_fp, from_fp, delta);
                }
            }
            OP_EDGE => {
                let Some(&ul) = body.first() else {
                    return true;
                };
                let ul = ul as usize;
                if body.len() < 2 + ul {
                    return true;
                }
                let Ok(u_fp) = std::str::from_utf8(&body[1..1 + ul]) else {
                    return true;
                };
                let vl = body[1 + ul] as usize;
                let rest = &body[2 + ul..];
                if rest.len() != vl + DIMENSION * 8 {
                    return true;
                }
                let Ok(v_fp) = std::str::from_utf8(&rest[..vl]) else {
                    return true;
                };
                let Some(delta) = parse_i64_triple(&rest[vl..]) else {
                    return true;
                };
                state().lock().record_edge(u_fp, v_fp, delta);
            }
            _ => {}
        }
        true
    }

    pub(crate) fn status() -> serde_json::Value {
        let (vertices, edges, split_world, cycles) = state().lock().evaluate();
        serde_json::json!({
            "enabled": enabled(),
            "vertices": vertices,
            "edges": edges,
            "split_world_detected": split_world,
            "obstruction_cycles": cycles,
        })
    }

    #[cfg(test)]
    pub(crate) fn reset_and_record_for_test(
        edges: &[(&str, &str, [i64; DIMENSION])],
    ) -> serde_json::Value {
        let mut st = state().lock();
        *st = SheafState::default();
        for (u, v, d) in edges {
            st.record_edge(u, v, *d);
        }
        let (vertices, edge_cnt, split_world, cycles) = st.evaluate();
        serde_json::json!({
            "vertices": vertices,
            "edges": edge_cnt,
            "split_world_detected": split_world,
            "obstruction_cycles": cycles,
        })
    }
}

pub(crate) mod metabolic_guard {
    use super::*;

    const DEFAULT_HALF_LIFE_SECS: f64 = 300.0;
    const MIN_HALF_LIFE_SECS: f64 = 10.0;
    const DEFAULT_THETA: f64 = 2.0;
    const MIN_THETA: f64 = 0.5;

    struct MetabolicState {
        clock: metabolic::MetabolicClock,
        theta: f64,
    }

    impl MetabolicState {
        fn with_params(half_life: f64, theta: f64) -> Self {
            let clock = metabolic::MetabolicClock::new(half_life)
                .expect("validated positive finite half-life");
            Self { clock, theta }
        }
    }

    fn parse_f64_env(name: &str, default: f64, floor: f64) -> f64 {
        match std::env::var(name) {
            Ok(raw) => raw
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= floor)
                .unwrap_or(default),
            Err(_) => default,
        }
    }

    fn state() -> &'static Mutex<MetabolicState> {
        static STATE: OnceLock<Mutex<MetabolicState>> = OnceLock::new();
        STATE.get_or_init(|| {
            let half_life = parse_f64_env(
                "GHOST_METABOLIC_HALF_LIFE_SECS",
                DEFAULT_HALF_LIFE_SECS,
                MIN_HALF_LIFE_SECS,
            );
            let theta = parse_f64_env("GHOST_METABOLIC_THETA", DEFAULT_THETA, MIN_THETA);
            Mutex::new(MetabolicState::with_params(half_life, theta))
        })
    }

    pub(crate) fn enabled() -> bool {
        toggle("GHOST_METABOLIC", true)
    }

    pub(crate) fn domain_for_ip(ip: IpAddr) -> metabolic::DomainId {
        let mut h = Sha256::new();
        match ip {
            IpAddr::V4(v4) => {
                h.update(b"VB-METABOLIC-V4-16");
                let oct = v4.octets();
                h.update([oct[0], oct[1]]);
            }
            IpAddr::V6(v6) => {
                h.update(b"VB-METABOLIC-V6-32");
                let seg = v6.segments();
                h.update(seg[0].to_be_bytes());
                h.update(seg[1].to_be_bytes());
            }
        }
        let digest = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    pub(crate) fn note_peer_pulse(ip: IpAddr, at: u64) {
        if !enabled() {
            return;
        }
        let domain = domain_for_ip(ip);
        state().lock().clock.note_pulse(domain, at);
    }

    #[allow(dead_code)]
    pub(crate) fn is_authorized() -> bool {
        if !enabled() {
            return true;
        }
        let st = state().lock();
        st.clock.is_authorized(now_secs(), st.theta)
    }

    pub(crate) fn status_at(now: u64) -> serde_json::Value {
        let st = state().lock();
        let mass = st.clock.mass(now);
        let mass_rounded = (mass * 10_000.0).round() / 10_000.0;
        serde_json::json!({
            "enabled": enabled(),
            "domains": st.clock.domains(),
            "mass": mass_rounded,
            "theta": st.theta,
            "half_life_secs": st.clock.half_life(),
            "authorized": st.clock.is_authorized(now, st.theta),
            "projected_death_secs": st.clock.projected_death(now, st.theta),
        })
    }

    pub(crate) fn status() -> serde_json::Value {
        status_at(now_secs())
    }

    #[cfg(test)]
    pub(crate) fn reset_and_record_for_test(
        half_life: f64,
        theta: f64,
        pulses: &[(IpAddr, u64)],
        eval_at: u64,
    ) -> serde_json::Value {
        let mut st = state().lock();
        *st = MetabolicState::with_params(half_life, theta);
        for (ip, at) in pulses {
            st.clock.note_pulse(domain_for_ip(*ip), *at);
        }
        drop(st);
        status_at(eval_at)
    }
}

// ══════════════════════════════════════════════════════════════════
// 8. repair_ledger — Tier-2 proof-of-erasure-repair mutual receipts
// ══════════════════════════════════════════════════════════════════

pub(crate) mod repair_ledger {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    pub(crate) const MAGIC: &[u8; 14] = b"GHOST_REPAIR__";
    const WITNESS_DOMAIN: &[u8] = b"VB-REPAIR-WITNESS-V1";
    const BODY_LEN: usize = 32 + 32 + 32 + 8 + 32 + 64 + 32 + 64;

    #[derive(Debug, Clone)]
    pub(crate) struct MutualRepairReceipt {
        pub(crate) proof: energy_currency::ErasureRepairProof,
        pub(crate) witness_pk: [u8; 32],
        pub(crate) witness_sig: [u8; 64],
    }

    impl MutualRepairReceipt {
        #[allow(dead_code)]
        pub(crate) fn sign_witness(
            proof: energy_currency::ErasureRepairProof,
            witness_sk: &SigningKey,
        ) -> Self {
            let witness_pk = witness_sk.verifying_key().to_bytes();
            let msg = witness_message(&proof.proof_id());
            let witness_sig = witness_sk.sign(&msg).to_bytes();
            Self {
                proof,
                witness_pk,
                witness_sig,
            }
        }

        #[allow(dead_code)]
        pub(crate) fn to_pdu(&self) -> Vec<u8> {
            let mut out = Vec::with_capacity(MAGIC.len() + BODY_LEN);
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&self.proof.input_shard_hashes[0]);
            out.extend_from_slice(&self.proof.input_shard_hashes[1]);
            out.extend_from_slice(&self.proof.repaired_shard_hash);
            out.extend_from_slice(&self.proof.epoch.to_be_bytes());
            out.extend_from_slice(&self.proof.worker_pk);
            out.extend_from_slice(&self.proof.signature);
            out.extend_from_slice(&self.witness_pk);
            out.extend_from_slice(&self.witness_sig);
            out
        }

        pub(crate) fn from_body(body: &[u8]) -> Option<Self> {
            if body.len() != BODY_LEN {
                return None;
            }
            let mut h0 = [0u8; 32];
            let mut h1 = [0u8; 32];
            let mut rep = [0u8; 32];
            h0.copy_from_slice(&body[0..32]);
            h1.copy_from_slice(&body[32..64]);
            rep.copy_from_slice(&body[64..96]);
            let epoch = u64::from_be_bytes(body[96..104].try_into().ok()?);
            let mut worker_pk = [0u8; 32];
            worker_pk.copy_from_slice(&body[104..136]);
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&body[136..200]);
            let mut witness_pk = [0u8; 32];
            witness_pk.copy_from_slice(&body[200..232]);
            let mut witness_sig = [0u8; 64];
            witness_sig.copy_from_slice(&body[232..296]);
            Some(Self {
                proof: energy_currency::ErasureRepairProof {
                    input_shard_hashes: [h0, h1],
                    repaired_shard_hash: rep,
                    epoch,
                    worker_pk,
                    signature,
                },
                witness_pk,
                witness_sig,
            })
        }
    }

    fn witness_message(proof_id: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(WITNESS_DOMAIN);
        h.update(proof_id);
        h.finalize().into()
    }

    fn verify_witness(receipt: &MutualRepairReceipt) -> bool {
        if receipt.proof.worker_pk == receipt.witness_pk {
            return false;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&receipt.witness_pk) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&receipt.witness_sig) else {
            return false;
        };
        let msg = witness_message(&receipt.proof.proof_id());
        vk.verify(&msg, &sig).is_ok()
    }

    struct RepairState {
        ledger: energy_currency::EnergyCreditLedger,
        accepted_receipts: u64,
        rejected_receipts: u64,
        total_credits_minted: u64,
    }

    impl Default for RepairState {
        fn default() -> Self {
            Self {
                ledger: energy_currency::EnergyCreditLedger::new(),
                accepted_receipts: 0,
                rejected_receipts: 0,
                total_credits_minted: 0,
            }
        }
    }

    fn state() -> &'static Mutex<RepairState> {
        static STATE: OnceLock<Mutex<RepairState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(RepairState::default()))
    }

    pub(crate) fn enabled() -> bool {
        toggle("GHOST_ENERGY_CURRENCY", true)
    }

    pub(crate) fn record_mutual_receipt(
        receipt: &MutualRepairReceipt,
    ) -> Result<u64, &'static str> {
        if !enabled() {
            return Err("energy currency disabled");
        }
        let mut st = state().lock();
        if !verify_witness(receipt) {
            st.rejected_receipts += 1;
            return Err("missing, invalid, or self-signed witness receipt");
        }
        match st.ledger.credit_repair(&receipt.proof) {
            Ok(bal) => {
                st.accepted_receipts += 1;
                st.total_credits_minted = st.total_credits_minted.saturating_add(10);
                Ok(bal)
            }
            Err(e) => {
                st.rejected_receipts += 1;
                Err(e)
            }
        }
    }

    pub(crate) fn handle_pdu(from_fp: &str, payload: &[u8]) -> bool {
        if payload.len() < MAGIC.len() || &payload[..MAGIC.len()] != MAGIC {
            return false;
        }
        if !enabled() || braid::peer_revoked(from_fp) {
            return true;
        }
        let Some(receipt) = MutualRepairReceipt::from_body(&payload[MAGIC.len()..]) else {
            state().lock().rejected_receipts += 1;
            return true;
        };
        if let Err(err) = record_mutual_receipt(&receipt) {
            tracing::debug!(peer = %from_fp, error = %err, "repair_ledger: rejected receipt");
        }
        true
    }

    #[allow(dead_code)]
    pub(crate) fn spend_for_priority(
        worker_pk: &[u8; 32],
        credits: u64,
    ) -> Result<u8, &'static str> {
        state().lock().ledger.spend_for_priority(worker_pk, credits)
    }

    #[allow(dead_code)]
    pub(crate) fn balance_of(worker_pk: &[u8; 32]) -> u64 {
        state().lock().ledger.balance_of(worker_pk)
    }

    pub(crate) fn status() -> serde_json::Value {
        let st = state().lock();
        serde_json::json!({
            "enabled": enabled(),
            "accepted_receipts": st.accepted_receipts,
            "rejected_receipts": st.rejected_receipts,
            "total_credits_minted": st.total_credits_minted,
        })
    }

    #[cfg(test)]
    pub(crate) fn reset_for_test() {
        *state().lock() = RepairState::default();
    }
}

// ══════════════════════════════════════════════════════════════════
// 9. compute_offload — Tier-2 Lagrange Coded Inference (d <= 2)
// ══════════════════════════════════════════════════════════════════

pub(crate) mod compute_offload {
    use super::*;
    use sharded_compute::lagrange::{LagrangeCodedInference, LccOutput, LccTask};
    use std::collections::HashSet;

    pub(crate) const MAX_OFFLOAD_DEGREE: usize = 2;

    #[derive(Default)]
    struct ComputeState {
        offloaded_jobs: u64,
        completed_jobs: u64,
        rejected_nonlinear_jobs: u64,
    }

    fn state() -> &'static Mutex<ComputeState> {
        static STATE: OnceLock<Mutex<ComputeState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(ComputeState::default()))
    }

    pub(crate) fn enabled() -> bool {
        toggle("GHOST_SHARDED_COMPUTE", true)
    }

    #[allow(dead_code)]
    pub(crate) fn prepare_offload(
        layer: &[u64],
        inputs: &[Vec<u64>],
        masks: usize,
        worker_asns: &[u32],
    ) -> Result<Vec<LccTask>, &'static str> {
        if !enabled() {
            return Err("sharded_compute disabled");
        }
        if layer.is_empty() {
            return Err("empty layer polynomial");
        }
        let layer_degree = layer.len() - 1;
        if layer_degree > MAX_OFFLOAD_DEGREE {
            state().lock().rejected_nonlinear_jobs += 1;
            return Err("scope rule: only linear/quadratic layers (d <= 2) may be offloaded");
        }
        let unique_asns: HashSet<u32> = worker_asns.iter().copied().collect();
        let lcc = LagrangeCodedInference::new(inputs.len(), masks)
            .map_err(|_| "invalid LCC shape (data_symbols and masks must be >= 1)")?;
        let min_workers = lcc.required_workers(layer_degree, 0, 0);
        if unique_asns.len() < min_workers {
            return Err("insufficient distinct worker ASNs for LCC degree bound");
        }
        let tasks = lcc
            .encode(inputs, worker_asns)
            .map_err(|_| "LCC encode failed")?;
        state().lock().offloaded_jobs += 1;
        Ok(tasks)
    }

    #[allow(dead_code)]
    pub(crate) fn complete_offload(
        data_symbols: usize,
        masks: usize,
        layer_degree: usize,
        byzantine: usize,
        outputs: &[Option<LccOutput>],
    ) -> Result<Vec<Vec<u64>>, &'static str> {
        if !enabled() {
            return Err("sharded_compute disabled");
        }
        if layer_degree > MAX_OFFLOAD_DEGREE {
            state().lock().rejected_nonlinear_jobs += 1;
            return Err("scope rule: layer degree exceeds d <= 2");
        }
        let lcc =
            LagrangeCodedInference::new(data_symbols, masks).map_err(|_| "invalid LCC shape")?;
        let recovered = lcc
            .decode(outputs, layer_degree, byzantine)
            .map_err(|_| "LCC decode failed (too few evaluations or malformed output)")?;
        state().lock().completed_jobs += 1;
        Ok(recovered)
    }

    pub(crate) fn status() -> serde_json::Value {
        let st = state().lock();
        serde_json::json!({
            "enabled": enabled(),
            "max_offload_degree": MAX_OFFLOAD_DEGREE,
            "offloaded_jobs": st.offloaded_jobs,
            "completed_jobs": st.completed_jobs,
            "rejected_nonlinear_jobs": st.rejected_nonlinear_jobs,
        })
    }

    #[cfg(test)]
    pub(crate) fn reset_for_test() {
        *state().lock() = ComputeState::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn host_state_lock() -> parking_lot::MutexGuard<'static, ()> {
        static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
        LOCK.lock()
    }

    fn fresh_voucher(
        epoch: u64,
        quota: u32,
    ) -> vantablack::ghost::net::bandwidth_voucher::BandwidthVoucher {
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
        let mut clone =
            braid_identity::BraidLock::restore(real.secret_state().0, real.braid(), real.height());
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
        assert!(
            braid::peer_revoked(peer),
            "two children of one key revoke it"
        );

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
        let epoch = vault::epoch_secs();
        let now = (now_secs() / epoch) * epoch + 10;
        let descriptor = vault::deposit_at(peer, payload, now).expect("deposits");
        assert!(descriptor.starts_with(vault::DESCRIPTOR_MAGIC));
        assert!(vault::chunk_count() >= 1);

        let recovered = vault::open_at(&descriptor, now + 1).expect("opens inside the epoch");
        assert_eq!(recovered, payload);
        assert!(
            vault::stored_count() >= 1,
            "the descriptor is still retryable"
        );

        let descriptor = vault::deposit_at(peer, b"second bundle", now).expect("second deposit");
        assert_eq!(
            vault::open_at(&descriptor, now + 10_000),
            Err(vault::OpenError::Expired),
            "a bundle past its die_at cannot be opened even with its descriptor"
        );
    }

    #[test]
    fn a_tampered_descriptor_is_corrupt_not_delivered() {
        let epoch = vault::epoch_secs();
        let now = (now_secs() / epoch) * epoch + 10;
        let mut descriptor = vault::deposit_at("vault-tamper", b"payload", now).expect("deposits");
        let last = descriptor.len() - 1;
        descriptor[last] ^= 0xFF; // last commitment byte
        assert_eq!(
            vault::open_at(&descriptor, now + 1),
            Err(vault::OpenError::Corrupt)
        );
        assert_eq!(
            vault::open_at(b"GHOST_PEX_____ legacy", now),
            Ok(b"GHOST_PEX_____ legacy".to_vec())
        );
    }

    #[test]
    fn relay_transit_is_refused_without_a_voucher_and_charged_with_one() {
        let peer = "voucher-unit-peer";
        assert!(
            !voucher::charge_for_test(peer, 1024),
            "no voucher, no transit"
        );

        let epoch = now_secs() / 3_600;
        let granted = voucher::present_for_test(peer, &fresh_voucher(epoch, 8)).expect("redeems");
        assert_eq!(granted, 8);
        assert!(voucher::charge_for_test(peer, 3_000_000), "one MB charged");
        assert!(
            voucher::charge_for_test(peer, 3_000_000),
            "second MB charged"
        );
        assert!(
            !voucher::charge_for_test(peer, 32 * 1_048_576),
            "overdraw refused"
        );
    }

    #[test]
    fn a_polysemic_probe_learns_which_paths_survived() {
        let (id, n, k, shards) = worlds::encode_probe(3, b"PROB").expect("encodes");
        assert_eq!((n, k), (3, 2));
        assert_eq!(shards.len(), 3);

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

    #[test]
    fn a_restarted_node_continues_its_persisted_chain_instead_of_forking() {
        let root = unique_dir("restart");
        let our_fp = "braid-restart-self";
        let peer_fp = "braid-restart-peer";

        let first_payload = braid::advance_with(Some(&root), our_fp, peer_fp, b"session-1")
            .expect("a durable advance publishes");
        let first = transition_of(&first_payload);
        assert_eq!(first.height, 1);
        let mut peer_chain = braid_identity::BraidChain::new();
        assert_eq!(
            peer_chain.accept(&first),
            braid_identity::BraidVerdict::Extended
        );

        braid::forget_for_test(peer_fp);
        assert_eq!(braid::restore_from(&root, our_fp), 1);

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

    #[test]
    fn ingesting_a_peers_transition_never_seeds_or_advances_our_own_chain() {
        let peer_fp = "braid-split-peer";
        let mut theirs = braid_identity::BraidLock::from_seed([0x77u8; 32]);
        let their_transition = theirs.advance(b"their session");

        let mut payload = braid::MAGIC.to_vec();
        payload.extend_from_slice(&their_transition.to_bytes());
        assert!(braid::handle_pdu(peer_fp, &payload));
        assert_eq!(braid::our_height(peer_fp), None, "a verifier is not a lock");
        assert!(braid::tip_payload(peer_fp).is_none());

        let ours_payload = braid::advance_with(None, "braid-split-self", peer_fp, b"our session")
            .expect("publishes in memory");
        let ours = transition_of(&ours_payload);
        assert_eq!(ours.height, 1);
        let genesis =
            braid_identity::BraidLock::from_seed(braid::seed_for("braid-split-self", peer_fp));
        assert_eq!(ours.parent_pk, genesis.identity());
        assert_ne!(ours.parent_pk, their_transition.next_pk);
        assert_eq!(braid::our_height(peer_fp), Some(1));
        braid::forget_for_test(peer_fp);
    }

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

    #[test]
    fn verifier_state_and_fork_proofs_survive_restart_through_the_journal() {
        let root = unique_dir("verifier");

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

        let mut real = braid_identity::BraidLock::from_seed([0x32u8; 32]);
        let mut clone =
            braid_identity::BraidLock::restore(real.secret_state().0, real.braid(), real.height());
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

        braid::forget_for_test(peer_linear);
        braid::forget_for_test(peer_fork);
        assert!(!braid::peer_revoked(peer_fork));

        assert_eq!(braid::restore_verifiers(&root), 2);
        assert!(
            braid::peer_revoked(peer_fork),
            "the fork is remembered across the restart"
        );

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

    #[test]
    fn three_hosts_hold_every_piece_and_none_stays_local() {
        let peer = "vault-mesh-peer";
        let payload = b"GHOST_PEX2____ a batch that belongs on three other machines";
        let epoch = vault::epoch_secs();
        let now = (now_secs() / epoch) * epoch + 10;
        let hosts: Vec<String> = ["mesh-host-a", "mesh-host-b", "mesh-host-c"]
            .iter()
            .map(|host| host.to_string())
            .collect();
        let _serial = host_state_lock();
        vault::clear_hosts_for_test();

        let descriptor =
            vault::deposit_with_hosts(peer, payload, now, &hosts).expect("deposits for placement");
        assert_eq!(
            vault::distributed_hosts_for_test(&descriptor).as_deref(),
            Some(hosts.as_slice()),
            "the plan names exactly the three hosts"
        );
        assert_eq!(
            vault::local_chunks_for_test(&descriptor),
            Some(0),
            "a placed bundle leaves no chunk in the local vault"
        );
        assert_eq!(
            vault::open_at(&descriptor, now + 1),
            Err(vault::OpenError::Corrupt),
            "this node holds below threshold and must not be able to open it"
        );

        let mut placements = 0usize;
        for host in &hosts {
            for pdu in vault::take_outbox(host) {
                assert!(
                    vault::handle_pdu(host, &pdu).is_some(),
                    "every queued PDU is a vault PDU"
                );
                placements += 1;
            }
        }
        assert!(
            placements > 6,
            "three shares, three archive shards and at least one chunk were placed"
        );
        assert_eq!(
            vault::hosted_counts_for_test(),
            (3, 3, 1),
            "each host keeps one share, one shard and its chunk"
        );

        let recovered = vault::open_from_hosts_for_test(&descriptor, now + 1)
            .expect("the hosted pieces reconstruct the bundle");
        assert_eq!(recovered, payload);

        vault::forget(&descriptor);
        for host in &hosts {
            for pdu in vault::take_outbox(host) {
                assert!(vault::handle_pdu(host, &pdu).is_some());
            }
        }
        assert_eq!(
            vault::hosted_counts_for_test(),
            (0, 0, 0),
            "forget purges the mesh copy too"
        );
    }

    #[test]
    fn fewer_than_three_hosts_keeps_the_bundle_local() {
        let epoch = vault::epoch_secs();
        let now = (now_secs() / epoch) * epoch + 10;
        let hosts = vec!["only-host".to_string(), "second-host".to_string()];
        let descriptor = vault::deposit_with_hosts(
            "vault-local-peer",
            b"two hosts is not a committee",
            now,
            &hosts,
        )
        .expect("deposits locally");
        assert!(
            vault::distributed_hosts_for_test(&descriptor).is_none(),
            "the plan is local, not distributed"
        );
        assert!(
            vault::take_outbox("only-host").is_empty(),
            "no placement PDU was queued"
        );
        assert_eq!(
            vault::open_at(&descriptor, now + 1),
            Ok(b"two hosts is not a committee".to_vec())
        );
    }

    #[test]
    fn a_keep_proof_pdu_renews_a_hosted_chunks_retention() {
        let _serial = host_state_lock();
        let id = [0x5Au8; 32];
        let commitment = dead_drop::BlindDeadDropBlob::derive_commitment(&id, 0);
        let store = vault::store_chunk_for_test(&id, &commitment, 1_000, 100, b"blind chunk");
        assert!(vault::handle_pdu("keep-host", &store).is_some());
        assert_eq!(
            vault::hosted_keep_timestamp(&commitment),
            Some(1_000),
            "the chunk is stamped with its deposit time"
        );

        assert!(
            vault::handle_pdu("keep-host", &vault::keep_for_test(&id, &[commitment])).is_some()
        );
        assert!(
            vault::hosted_keep_timestamp(&commitment) > Some(1_000),
            "the keep-proof moved the retention stamp to now"
        );
        vault::handle_pdu("keep-host", &vault::purge_for_test(&id));
    }

    #[test]
    fn erosion_windows_are_parsed_with_a_floor() {
        assert_eq!(vault::window_value_for_test(Some("120"), 3_600, 60), 120);
        assert_eq!(
            vault::window_value_for_test(Some(" 45 "), 900, 1),
            45,
            "surrounding whitespace is trimmed"
        );
        assert_eq!(
            vault::window_value_for_test(Some("10"), 3_600, 60),
            3_600,
            "below the floor is treated as unset"
        );
        assert_eq!(
            vault::window_value_for_test(Some("not a number"), 3_600, 60),
            3_600
        );
        assert_eq!(vault::window_value_for_test(None, 3_600, 60), 3_600);
        assert!(vault::epoch_secs() >= 60 && vault::ttl_secs() >= 1);
    }

    #[test]
    fn onion_and_blind_transit_draw_on_the_same_voucher() {
        let peer = "voucher-unified-peer";
        let epoch = now_secs() / 3_600;
        voucher::present_for_test(peer, &fresh_voucher(epoch, 4)).expect("redeems");
        assert!(voucher::charge_as_for_test(
            peer,
            2 * 1_048_576,
            voucher::Transit::Onion
        ));
        assert!(
            voucher::charge_as_for_test(peer, 2 * 1_048_576, voucher::Transit::Blind),
            "the same quota pays for both forwarding paths"
        );
        assert!(
            !voucher::charge_as_for_test(peer, 1_048_576, voucher::Transit::Onion),
            "one bank, exhausted"
        );
        let stats = voucher::stats();
        assert!(stats["onion_bytes"].as_u64().unwrap_or(0) >= 2 * 1_048_576);
        assert!(stats["blind_bytes"].as_u64().unwrap_or(0) >= 2 * 1_048_576);
    }

    #[test]
    fn the_status_document_reports_beacon_and_braid_counters() {
        let status = status_json(7);
        assert_eq!(status["entropy_beacon"]["threshold"], 3);
        assert_eq!(status["entropy_beacon"]["participants"], 7);
        assert_eq!(
            status["entropy_beacon"]["peers_per_round"], 2,
            "seven peers can fill two three-share rounds"
        );
        assert_eq!(
            status_json(2)["entropy_beacon"]["peers_per_round"],
            0,
            "two peers cannot fill a round"
        );
        assert!(status["braid"]["tracked_peers"].is_number());
        assert!(status["braid"]["revoked_peers"].is_number());
        assert!(status["braid"]["quarantined_peers"].is_number());
        assert!(status["vault"]["epoch_secs"].as_u64().unwrap_or(0) >= 60);
        assert!(status["voucher"]["onion_bytes"].is_number());
        assert!(status["sheaf"]["vertices"].is_number());
        assert!(status["metabolic"]["domains"].is_number());
        assert!(status["metabolic"]["theta"].is_number());
        assert!(status["energy_currency"]["accepted_receipts"].is_number());
        assert_eq!(status["sharded_compute"]["max_offload_degree"], 2);
    }

    #[test]
    fn sheaf_detects_split_world_cycle_and_accepts_consistent_triangle() {
        let ok = sheaf_monitor::reset_and_record_for_test(&[
            ("a", "b", [1, 2, 0]),
            ("b", "c", [0, -1, 1]),
            ("c", "a", [-1, -1, -1]),
        ]);
        assert_eq!(ok["vertices"], 3);
        assert_eq!(ok["edges"], 3);
        assert_eq!(ok["split_world_detected"], false);
        assert_eq!(ok["obstruction_cycles"], 0);

        let split = sheaf_monitor::reset_and_record_for_test(&[
            ("a", "b", [1, 0, 0]),
            ("b", "c", [0, 0, 0]),
            ("c", "a", [0, 0, 0]),
        ]);
        assert_eq!(split["split_world_detected"], true);
        assert_eq!(split["obstruction_cycles"], 1);
    }

    #[test]
    fn metabolic_collapses_same_prefix_sybils_and_decays_across_half_life() {
        let sybil_pulses: Vec<(IpAddr, u64)> = (1u8..=50)
            .map(|host| {
                (
                    IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, host)),
                    1_000,
                )
            })
            .collect();
        let sybil = metabolic_guard::reset_and_record_for_test(60.0, 1.5, &sybil_pulses, 1_000);
        assert_eq!(sybil["domains"], 1);
        assert_eq!(sybil["mass"], 1.0);
        assert_eq!(sybil["authorized"], false);

        let mut two_domains = sybil_pulses;
        two_domains.push((IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)), 1_000));
        let alive = metabolic_guard::reset_and_record_for_test(60.0, 1.5, &two_domains, 1_000);
        assert_eq!(alive["domains"], 2);
        assert_eq!(alive["mass"], 2.0);
        assert_eq!(alive["authorized"], true);
        assert_eq!(alive["projected_death_secs"], 1_025);

        let decayed = metabolic_guard::status_at(1_060);
        assert_eq!(decayed["mass"], 1.0);
        assert_eq!(decayed["authorized"], false);
    }

    /// Tier 2: energy_currency requires distinct mutually-signed worker+witness
    /// receipts, rejects self-repair and duplicate proof_id minting, and spends
    /// earned credits for forwarding priority.
    #[test]
    fn repair_ledger_requires_distinct_mutual_signatures_and_rejects_replay() {
        use ed25519_dalek::SigningKey;
        repair_ledger::reset_for_test();
        let worker_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let witness_sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let worker_pk = worker_sk.verifying_key().to_bytes();

        let proof = vantablack::ghost::net::energy_currency::ErasureRepairProof::mint(
            &worker_sk,
            [[0xAAu8; 32], [0xBBu8; 32]],
            [0xCCu8; 32],
            42,
        );

        let self_signed =
            repair_ledger::MutualRepairReceipt::sign_witness(proof.clone(), &worker_sk);
        assert!(
            repair_ledger::record_mutual_receipt(&self_signed).is_err(),
            "self-repair receipt must be rejected"
        );

        let valid = repair_ledger::MutualRepairReceipt::sign_witness(proof, &witness_sk);
        let pdu = valid.to_pdu();
        assert!(repair_ledger::handle_pdu("witness-peer", &pdu));
        assert_eq!(repair_ledger::balance_of(&worker_pk), 10);

        assert!(repair_ledger::handle_pdu("witness-peer", &pdu));
        assert_eq!(
            repair_ledger::balance_of(&worker_pk),
            10,
            "duplicate proof_id must not double-mint"
        );
        assert_eq!(repair_ledger::spend_for_priority(&worker_pk, 10), Ok(1));
        assert_eq!(repair_ledger::balance_of(&worker_pk), 0);
    }

    /// Tier 2: sharded_compute (LC-Vantablack) rejects degree > 2 non-linear
    /// layers per scope rule and recovers quadratic inference across stragglers.
    #[test]
    fn compute_offload_enforces_quadratic_degree_bound_and_recovers_with_stragglers() {
        use vantablack::ghost::net::sharded_compute::lagrange::apply_layer;
        compute_offload::reset_for_test();

        let inputs = vec![vec![5u64, 7], vec![11, 13]];
        let asns = [64512u32, 64513, 64514, 64515, 64516, 64517];

        assert!(
            compute_offload::prepare_offload(&[1, 1, 1, 1], &inputs, 1, &asns).is_err(),
            "degree 3 non-linear layer must stay client-side"
        );

        let quad_layer = [1u64, 2, 3]; // 1 + 2x + 3x^2
        let tasks = compute_offload::prepare_offload(&quad_layer, &inputs, 1, &asns)
            .expect("quadratic layer offloads");
        let mut outputs: Vec<Option<_>> = tasks
            .iter()
            .map(|t| Some(apply_layer(&quad_layer, t)))
            .collect();
        outputs[2] = None; // drop 1 straggler; 5 remaining satisfy deg 4 + 1 = 5

        let recovered = compute_offload::complete_offload(2, 1, 2, 0, &outputs)
            .expect("recovers quadratic output");
        assert_eq!(
            recovered,
            vec![
                vec![1 + 2 * 5 + 3 * 25, 1 + 2 * 7 + 3 * 49],
                vec![1 + 2 * 11 + 3 * 121, 1 + 2 * 13 + 3 * 169],
            ]
        );
        let st = compute_offload::status();
        assert_eq!(st["offloaded_jobs"], 1);
        assert_eq!(st["completed_jobs"], 1);
        assert_eq!(st["rejected_nonlinear_jobs"], 1);
    }
}
