/// Virtual Network Simulation — Multi-Node GhostNet Mesh Tests
///
/// Mirrors the production protocol from the ghost library exactly:
/// - Builds signed handshake PDUs (944 bytes) and signed response PDUs (912 bytes)
/// - Uses binary-safe length-prefixed frame_shard() / unframe() for RS shard transport
/// - Uses the full encrypt-send-receive-decrypt pipeline with length-prefix framing
///   so binary data is preserved through the RS erasure coding layer
/// - Deletes identity.key before each test to avoid cross-test identity conflict

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

use vantablack::ghost::layers::l0_identity;
use vantablack::ghost::layers::l1_kem;
use vantablack::ghost::layers::l2_aead;
use vantablack::ghost::layers::l4_rs;
use vantablack::ghost::net::{OFFSET_PAYLOAD_START, frame_shard, unframe};
use vantablack::ghost::net::routing::ReputationMatrix;
use vantablack::ghost::session::{Session, SessionRole};

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey512, MlKem512};

mod common;
use common::virtual_net::{
    VirtualNetHub, VirtualEndpoint, build_test_gtf_packet,
    parse_virtual_counter, parse_virtual_shard_index,
};

const TIMEOUT_MS: u64 = 2000;
const _RESPONSE_BLOB_LEN: usize = 912;

/// Counter for assigning unique identity files to simulation nodes.
static SIM_NODE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Create a unique temporary identity file path and set GHOST_IDENTITY_FILE for the current thread/context.
fn next_sim_identity_path() -> std::path::PathBuf {
    let id = SIM_NODE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let temp_dir = std::env::temp_dir();
    temp_dir.join(format!("ggn_sim_{}_{}.key", pid, id))
}

fn cleanup_identity() {
    let path = std::path::Path::new("identity.key");
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

// ── Helpers matching the production enc_split_len / reconstruct_decrypt ──

/// Prepend 2-byte big-endian length, encrypt, RS-encode (production enc_split_len).
/// After encryption, the AEAD tag is appended to `framed`. We strip it for the
/// return value, but RS encoding preserves it so reconstruction yields tag+payload
/// for direct decrypt_in_place.
fn frame_encrypt_binary_safe(key: &[u8; 32], ctr: u32, pay: &[u8]) -> (Vec<Vec<u8>>, [u8; 16]) {
    let pay_len = pay.len() as u16;
    let mut framed = pay_len.to_be_bytes().to_vec();
    framed.extend_from_slice(pay);
    // Pad to even length for RS encoding
    if framed.len() % 2 != 0 {
        framed.push(0);
    }
    l2_aead::encrypt_in_place(key, ctr, &mut framed);

    // Extract the 16-byte AEAD tag appended by encrypt_in_place
    let t = if framed.len() >= 16 {
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&framed[framed.len() - 16..]);
        tag
    } else {
        [0u8; 16]
    };

    // RS encode the entire ciphertext (payload + AEAD tag)
    let raw = l4_rs::encode(&mut framed);

    // Wrap each shard with a 2-byte length prefix (production frame_shard)
    let wrapped: Vec<Vec<u8>> = raw.iter().map(|s| frame_shard(s)).collect();
    (wrapped, t)
}

/// Reconstruct RS shards, decrypt, and extract original payload using length prefix.
/// This is the production reconstruct_decrypt equivalent for binary-safe data.
fn reconstruct_decrypt_binary_safe(
    key: &[u8; 32],
    ctr: u32,
    shards: &mut Vec<Option<Vec<u8>>>,
) -> Result<Vec<u8>, ()> {
    if l4_rs::reconstruct(shards).is_err() {
        return Err(());
    }
    let a = shards[0].as_ref().ok_or(())?;
    let b = shards[1].as_ref().ok_or(())?;
    let combined = [a.as_slice(), b.as_slice()].concat();
    let mut msg = combined;
    let pt = l2_aead::decrypt_in_place(key, ctr, &mut msg).map_err(|_| ())?;
    if pt.len() < 2 {
        return Err(());
    }
    let orig_len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    if 2 + orig_len > pt.len() {
        return Err(());
    }
    Ok(pt[2..2 + orig_len].to_vec())
}

struct SimNode {
    pub node: Arc<vantablack::ghost::GhostNode>,
    pub addr: String,
    rx: tokio::sync::mpsc::Receiver<common::virtual_net::VirtualPacket>,
    peer_addresses: Arc<RwLock<HashMap<String, String>>>,
    assembly_pool: Arc<RwLock<HashMap<(u32, u32), Vec<Option<Vec<u8>>>>>>,
    pending_hs: Arc<RwLock<HashMap<String, (x25519_dalek::EphemeralSecret, DecapsulationKey512)>>>,
    identity_pk: [u8; 32],
}

impl SimNode {
    async fn new(addr: &str, hub: &mut VirtualNetHub) -> Self {
        let id_path = next_sim_identity_path();
        std::env::set_var("GHOST_IDENTITY_FILE", &id_path);
        let node = Arc::new(
            vantablack::ghost::GhostNode::new("127.0.0.1:0")
                .await
                .expect("GhostNode creation"),
        );
        let _ = std::fs::remove_file(&id_path);
        let identity_pk = node.identity.public_key_bytes();
        let (ep, tx) = VirtualEndpoint::new(addr.to_string());
        hub.register(addr, tx);
        Self {
            node,
            addr: addr.to_string(),
            rx: ep.rx,
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            assembly_pool: Arc::new(RwLock::new(HashMap::new())),
            pending_hs: Arc::new(RwLock::new(HashMap::new())),
            identity_pk,
        }
    }

    async fn send_handshake(&self, hub: &mut VirtualNetHub, target: &str) {
        let (x_sec, x_pub) = l1_kem::generate_x25519_keypair();
        let (ky_pub, ky_sec) = l1_kem::generate_kyber_keypair();
        let pdu = l1_kem::build_handshake_pdu(
            &self.identity_pk,
            |data| self.node.identity.sign(data).to_bytes(),
            &x_pub,
            &ky_pub,
        );
        let mut pdu_c = pdu;
        let shards = l4_rs::encode(&mut pdu_c);
        let tag = [0u8; 16];
        for i in 0..3 {
            let wrapped = frame_shard(&shards[i]);
            hub.route(
                build_test_gtf_packet([0; 4], 0, i as u8, &wrapped, &tag),
                &self.addr,
                target,
            );
        }
        self.pending_hs
            .write()
            .await
            .insert(target.to_string(), (x_sec, ky_sec));
    }

    async fn recv(&mut self, hub: &mut VirtualNetHub) -> Option<String> {
        let start = std::time::Instant::now();
        loop {
            // Check assembly pool for completable data packets
            let completable: Vec<(u32, u32)> = {
                let pool = self.assembly_pool.read().await;
                pool.iter()
                    .filter(|(&(sid, _), shards)| {
                        sid == 0 && shards.iter().filter(|s| s.is_some()).count() >= 2
                    })
                    .map(|(&key, _)| key)
                    .collect()
            };
            for (sid, ctr) in completable {
                let rc = {
                    let mut ap = self.assembly_pool.write().await;
                    if let Some(mut ws) = ap.remove(&(sid, ctr)) {
                        if l4_rs::reconstruct(&mut ws).is_ok() {
                            Some(
                                ws[0]
                                    .as_ref()
                                    .unwrap()
                                    .iter()
                                    .chain(ws[1].as_ref().unwrap().iter())
                                    .copied()
                                    .collect::<Vec<u8>>(),
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(data) = rc {
                    let src = self
                        .peer_addresses
                        .read()
                        .await
                        .values()
                        .next()
                        .cloned()
                        .unwrap_or_default();
                    if let Some(r) = self.handle(hub, ctr, &data, &src).await {
                        return Some(r);
                    }
                }
            }

            let elapsed = start.elapsed().as_millis() as u64;
            if elapsed >= TIMEOUT_MS {
                return None;
            }
            let remaining = TIMEOUT_MS - elapsed;
            let pkt = match timeout(Duration::from_millis(remaining.max(1)), self.rx.recv()).await {
                Ok(Some(p)) => p,
                _ => return None,
            };
            if pkt.data.len() < 512 {
                continue;
            }
            let ctr = parse_virtual_counter(&pkt.data);
            let si = parse_virtual_shard_index(&pkt.data) as usize;
            if si > 2 {
                continue;
            }

            let plen = pkt
                .data
                .len()
                .min(512)
                .saturating_sub(OFFSET_PAYLOAD_START);
            let payload = pkt.data[OFFSET_PAYLOAD_START..OFFSET_PAYLOAD_START + plen].to_vec();

            // Use production unframe() for binary-safe length-prefix decoding
            let sc = match unframe(&payload) {
                Some(s) => s,
                None => continue,
            };

            let key = (0u32, ctr);
            let n = {
                let mut p = self.assembly_pool.write().await;
                let e = p.entry(key).or_insert_with(|| vec![None, None, None]);
                e[si] = Some(sc);
                e.iter().filter(|s| s.is_some()).count()
            };
            if n >= 2 {
                if ctr <= 1 || self.node.sessions.len() > 0 {
                    let mut ws = {
                        self.assembly_pool
                            .write()
                            .await
                            .remove(&key)
                            .unwrap()
                    };
                    if l4_rs::reconstruct(&mut ws).is_ok() {
                        let rc: Vec<u8> = ws[0]
                            .as_ref()
                            .unwrap()
                            .iter()
                            .chain(ws[1].as_ref().unwrap().iter())
                            .copied()
                            .collect();
                        if let Some(r) = self.handle(hub, ctr, &rc, &pkt.src).await {
                            return Some(r);
                        }
                    }
                }
            }
        }
    }

    async fn handle(
        &mut self,
        hub: &mut VirtualNetHub,
        counter: u32,
        data: &[u8],
        src: &str,
    ) -> Option<String> {
        // ── HANDLE HANDSHAKE INIT (counter == 0) ──
        if counter == 0
            && data.len() >= l1_kem::HANDSHAKE_BLOB_LEN
            && data.starts_with(b"GHOST_HANDSHAKE_")
        {
            let mut blob = data.to_vec();
            blob.truncate(l1_kem::HANDSHAKE_BLOB_LEN);
            let hs = l1_kem::parse_handshake_pdu(&blob)?;
            let sm = [&hs.x25519_pub[..], &hs.kyber_pub[..]].concat();
            if !l0_identity::verify_peer_signature(&hs.identity_pk, &sm, &hs.signature) {
                return Some("BAD_SIG".into());
            }
            let fp = hex::encode(&hs.identity_pk[0..8]);
            let (ct_arr, ky_ss_full) = l1_kem::kyber_encapsulate(&hs.kyber_pub).ok()?;
            let ky_ss_32: Vec<u8> = ky_ss_full.iter().copied().take(32).collect();
            let b_sec = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
            let b_pub = x25519_dalek::PublicKey::from(&b_sec);
            let x_ss = b_sec.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
            let mk = l1_kem::derive_hybrid_master_key(x_ss.as_bytes(), &ky_ss_32);

            // Build signed response (912 bytes) matching build_response_pdu
            let bp_bytes = b_pub.as_bytes();
            let mut bp_arr = [0u8; 32];
            bp_arr.copy_from_slice(bp_bytes);
            let mut ct_arr_fixed = [0u8; 768];
            ct_arr_fixed.copy_from_slice(&ct_arr[..768]);
            let identity_pk = self.node.identity.public_key_bytes();
            let mut resp = vec![0u8; _RESPONSE_BLOB_LEN];
            resp[0..16].copy_from_slice(b"GHOST_RESPONSE__");
            resp[16..48].copy_from_slice(&bp_arr);
            resp[48..816].copy_from_slice(&ct_arr_fixed);
            resp[816..848].copy_from_slice(&identity_pk);
            let mut signed_material = vec![0u8; 800];
            signed_material[0..32].copy_from_slice(&bp_arr);
            signed_material[32..800].copy_from_slice(&ct_arr_fixed);
            let sig = self.node.identity.sign(&signed_material).to_bytes();
            resp[848..912].copy_from_slice(&sig);

            // RS-encode, wrap with length prefix, send
            let mut r2 = resp;
            let shards = l4_rs::encode(&mut r2);
            let tag = [0u8; 16];
            for i in 0..3 {
                let wrapped = frame_shard(&shards[i]);
                hub.route(
                    build_test_gtf_packet([0; 4], 1, i as u8, &wrapped, &tag),
                    &self.addr,
                    src,
                );
            }
            self.peer_addresses
                .write()
                .await
                .insert(fp.clone(), src.to_string());
            let session = Session::new(mk, fp.clone());
            self.node.sessions.insert(fp.clone(), session);
            return Some(format!("ESTABLISHED:{}", fp));
        }

        // ── HANDLE HANDSHAKE RESPONSE (counter == 1) — signed 912-byte format ──
        if counter == 1
            && data.len() >= _RESPONSE_BLOB_LEN
            && data.starts_with(b"GHOST_RESPONSE__")
        {
            let mut rd = data.to_vec();
            rd.truncate(_RESPONSE_BLOB_LEN);
            let mut bp = [0u8; 32];
            bp.copy_from_slice(&rd[16..48]);
            let mut ct_arr = [0u8; 768];
            ct_arr.copy_from_slice(&rd[48..816]);
            let mut resp_identity_pk = [0u8; 32];
            resp_identity_pk.copy_from_slice(&rd[816..848]);
            let mut resp_sig = [0u8; 64];
            resp_sig.copy_from_slice(&rd[848..912]);

            // Verify responder's Ed25519 signature over (x_pub || ct)
            let signed_material = {
                let mut m = vec![0u8; 800];
                m[0..32].copy_from_slice(&bp);
                m[32..800].copy_from_slice(&ct_arr);
                m
            };
            if !l0_identity::verify_peer_signature(&resp_identity_pk, &signed_material, &resp_sig) {
                return Some("BAD_RESP_SIG".into());
            }

            let fp = hex::encode(&resp_identity_pk[..8]);
            let ct = Ciphertext::<MlKem512>::from(ct_arr);
            if let Some((ax, dk)) = self.pending_hs.write().await.remove(src) {
                let ks = dk.decapsulate(&ct);
                let ky_ss_32: Vec<u8> = ks.as_slice().to_vec();
                    let xss = ax.diffie_hellman(&x25519_dalek::PublicKey::from(bp));
                    let mk = l1_kem::derive_hybrid_master_key(xss.as_bytes(), &ky_ss_32);
                    self.peer_addresses
                        .write()
                        .await
                        .insert(fp.clone(), src.to_string());
                    let session = Session::new_with_role(mk, fp.clone(), SessionRole::Responder);
                    self.node.sessions.insert(fp.clone(), session);
                    return Some(format!("CONFIRMED:{}", fp));
            }
            return None;
        }

        // ── DATA: Use binary-safe reconstruct_decrypt with length-prefix framing ──
        for entry in self.node.sessions.iter() {
            let key = entry.master_key;
            let peer_fp = entry.peer_fingerprint.clone();
            drop(entry);

            // Prepare shards for reconstruction and decryption
            let mut shards: Vec<Option<Vec<u8>>> = vec![None, None, None];
            // Split the combined data back into two shards
            if data.len() >= 2 {
                let mid = data.len() / 2;
                shards[0] = Some(data[0..mid].to_vec());
                shards[1] = Some(data[mid..].to_vec());
            }

            match reconstruct_decrypt_binary_safe(&key, counter, &mut shards) {
                Ok(payload) => {
                    let trimmed =
                        String::from_utf8_lossy(&payload).trim_end_matches('\0').to_string();
                    return Some(format!("MSG:{}:{}", peer_fp, trimmed));
                }
                Err(_) => {
                    continue;
                }
            }
        }
        None
    }

    async fn send_msg(&self, hub: &mut VirtualNetHub, peer_fp: &str, msg: &str) {
        if let Some(st) = self.node.sessions.get(peer_fp) {
            let k = st.master_key;
            let ctr = st.next_tx_counter();
            drop(st);

            // Use binary-safe frame_encrypt with length-prefix
            let (wrapped_shards, tag) = frame_encrypt_binary_safe(&k, ctr, msg.as_bytes());
            let target = self
                .peer_addresses
                .read()
                .await
                .get(peer_fp)
                .cloned()
                .unwrap_or_else(|| peer_fp.to_string());
            for i in 0..3 {
                let pkt = build_test_gtf_packet(
                    ctr.to_be_bytes(),
                    ctr,
                    i as u8,
                    &wrapped_shards[i],
                    &tag,
                );
                hub.route(pkt, &self.addr, &target);
            }
        }
    }
}

async fn make_pair(hub: &mut VirtualNetHub) -> (SimNode, SimNode) {
    cleanup_identity();
    let a = SimNode::new("virt://alice:1", hub).await;
    cleanup_identity();
    let b = SimNode::new("virt://bob:1", hub).await;
    (a, b)
}

#[tokio::test]
async fn test_sim_full_handshake() {
    cleanup_identity();
    let mut hub = VirtualNetHub::new();
    let (mut a, mut b) = make_pair(&mut hub).await;

    a.send_handshake(&mut hub, "virt://bob:1").await;
    let r1 = b.recv(&mut hub).await;
    assert!(r1.is_some(), "Bob should receive handshake");
    let s1 = r1.unwrap();
    assert!(s1.starts_with("ESTABLISHED:"), "Bob establishes: {s1}");

    let r2 = a.recv(&mut hub).await;
    assert!(r2.is_some(), "Alice should receive response");
    let s2 = r2.unwrap();
    assert!(s2.starts_with("CONFIRMED:"), "Alice confirms: {s2}");

    assert_eq!(a.node.sessions.len(), 1, "Alice has 1 session");
    assert_eq!(b.node.sessions.len(), 1, "Bob has 1 session");

    let bfp = b
        .node
        .sessions
        .iter()
        .next()
        .map(|e| e.key().clone())
        .unwrap();
    assert!(bfp.len() >= 8);
    b.send_msg(&mut hub, &bfp, "Hello Alice!").await;

    let r3 = a.recv(&mut hub).await;
    assert!(r3.is_some(), "Alice should receive message");
    let s3 = r3.unwrap();
    assert!(
        s3.contains("Hello Alice!"),
        "Alice decrypts with full pipeline: {s3}"
    );
}

#[tokio::test]
async fn test_sim_packet_loss_recovery() {
    cleanup_identity();
    let mut hub = VirtualNetHub::new();
    hub.drop_probability = 0.3;
    let (mut a, mut b) = make_pair(&mut hub).await;

    for _ in 0..5 {
        a.send_handshake(&mut hub, "virt://bob:1").await;
        if let Some(r) = b.recv(&mut hub).await {
            if r.starts_with("ESTABLISHED:") {
                let _ = a.recv(&mut hub).await;
                break;
            }
        }
    }
}

#[tokio::test]
async fn test_sim_byzantine_reputation() {
    // Test the Poisson-distributed reputation matrix
    use vantablack::ghost::net::routing::PoissonReputationMatrix;
    let rep = PoissonReputationMatrix::new();
    // Initially, no one is flagged as Byzantine
    assert!(!rep.is_byzantine("a", "b"));
}

#[tokio::test]
async fn test_sim_unique_ids() {
    let id_a = next_sim_identity_path();
    std::env::set_var("GHOST_IDENTITY_FILE", &id_a);
    let a = vantablack::ghost::GhostNode::new("127.0.0.1:0")
        .await
        .unwrap();
    let _ = std::fs::remove_file(&id_a);

    let id_b = next_sim_identity_path();
    std::env::set_var("GHOST_IDENTITY_FILE", &id_b);
    let b = vantablack::ghost::GhostNode::new("127.0.0.1:0")
        .await
        .unwrap();
    let _ = std::fs::remove_file(&id_b);

    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[tokio::test]
async fn test_sim_end_to_end_encrypt_decrypt() {
    cleanup_identity();
    let mut hub = VirtualNetHub::new();
    let (mut a, mut b) = make_pair(&mut hub).await;

    // Full handshake
    a.send_handshake(&mut hub, "virt://bob:1").await;
    let r1 = b.recv(&mut hub).await;
    assert!(r1.is_some(), "Bob receives handshake");
    let r2 = a.recv(&mut hub).await;
    assert!(r2.is_some(), "Alice receives response");

    assert_eq!(a.node.sessions.len(), 1, "Alice session established");
    assert_eq!(b.node.sessions.len(), 1, "Bob session established");

    // Test binary-safe end-to-end encrypt-send-receive-decrypt
    let bfp = b
        .node
        .sessions
        .iter()
        .next()
        .map(|e| e.key().clone())
        .unwrap();

    // Test with binary data that could be corrupted by naive framing
    let test_messages = vec![
        "Hello World!".to_string(),
        String::from_utf8_lossy(&[b'B', b'i', b'n', b'a', b'r', b'y', 0x00, b'd', b'a', b't', b'a', 0xFF, b't', b'e', b's', b't']).into_owned(),
        String::new(),
        "A".to_string(),
        "X".repeat(100),
    ];

    for msg in &test_messages {
        b.send_msg(&mut hub, &bfp, msg).await;
        let r = a.recv(&mut hub).await;
        assert!(r.is_some(), "Alice should receive message '{}'", msg);
        let s = r.unwrap();
        assert!(
            s.contains(msg.trim_end_matches('\0')),
            "Full pipeline preserves message. Expected '{}', got '{}'",
            msg,
            s
        );
    }
}