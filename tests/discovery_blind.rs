//! Integration tests for Zero-Knowledge Discovery & Blind Mailbox Rendezvous (B1, B2, B3).
//!
//! Covers:
//! (a) Random 12-byte nonce uniqueness & AEAD tamper rejection
//! (b) PeerDescriptorV2 + vb:// / vb-net:// roundtrip & per-field signature tamper rejection
//! (c) LocalPeerCache v2 (`VBPCACHE2`) save, load, and expired/invalid entry pruning
//! (d) BlindMailboxClient end-to-end against a real `tokio::net::TcpListener` HTTP server,
//!     verifying zero plaintext IP/port/fingerprint leakage, chaff padding to 1024 B,
//!     garbage/other-swarm filtering, and epoch-1 fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::net::discovery::{
    base64url_encode, parse_peer_uri, BlindMailboxClient, BlindRendezvous, LocalPeerCache,
    NetworkInvite, ParsedPeerUri, PeerDescriptor, PeerDescriptorV2, BLIND_MAILBOX_WIRE_LEN,
    BLIND_NONCE_LEN, CAP_EXIT, CAP_QUIC, CAP_RELAY, CAP_VPN_HUB, NAT_CONE, NAT_DIRECT,
    NAT_RESTRICTED, VB_NET_URI_PREFIX, VB_URI_PREFIX, VB_V2_URI_PREFIX,
};

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    target: String,
    headers: String,
    body: Vec<u8>,
}

struct MockServerState {
    slots: HashMap<String, Vec<String>>,
    requests: Vec<RecordedRequest>,
}

async fn spawn_mock_blind_mailbox() -> (String, Arc<Mutex<MockServerState>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock blind mailbox");
    let addr = listener.local_addr().expect("mock local_addr");
    let state = Arc::new(Mutex::new(MockServerState {
        slots: HashMap::new(),
        requests: Vec::new(),
    }));
    let state_bg = Arc::clone(&state);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let st = Arc::clone(&state_bg);
            tokio::spawn(async move {
                let mut raw = Vec::with_capacity(2048);
                let mut tmp = [0u8; 2048];
                let mut header_end = None;
                let mut content_len = 0usize;

                loop {
                    let n = match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    raw.extend_from_slice(&tmp[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            let hdr = String::from_utf8_lossy(&raw[..pos]);
                            for line in hdr.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(hend) = header_end {
                        if raw.len() >= hend + content_len {
                            break;
                        }
                    }
                }

                let Some(hend) = header_end else {
                    return;
                };
                let hdr_str = String::from_utf8_lossy(&raw[..hend - 4]).to_string();
                let body = raw[hend..raw.len().min(hend + content_len)].to_vec();
                let first_line = hdr_str.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let target = parts.next().unwrap_or("").to_string();

                {
                    let mut guard = st.lock().unwrap();
                    guard.requests.push(RecordedRequest {
                        method: method.clone(),
                        target: target.clone(),
                        headers: hdr_str.clone(),
                        body: body.clone(),
                    });
                }

                let rest = target
                    .strip_prefix("/v2/slot/")
                    .or_else(|| target.strip_prefix("/v1/slot/"));
                let Some(rest) = rest else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                };
                let slot_hex = rest.split('/').next().unwrap_or("");

                if method == "PUT" {
                    if body.is_empty() || body.len() > BLIND_MAILBOX_WIRE_LEN {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n",
                            )
                            .await;
                        return;
                    }
                    let encoded = base64url_encode(&body);
                    {
                        let mut guard = st.lock().unwrap();
                        guard
                            .slots
                            .entry(slot_hex.to_string())
                            .or_default()
                            .push(encoded);
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                } else if method == "GET" {
                    let blobs = {
                        let guard = st.lock().unwrap();
                        guard.slots.get(slot_hex).cloned().unwrap_or_default()
                    };
                    let json = serde_json::to_string(&blobs).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        json.len(),
                        json
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });

    (format!("http://{}", addr), state)
}

#[test]
fn blind_rendezvous_random_nonce_uniqueness_and_tamper_rejection() {
    let id = GhostIdentity::generate_fresh();
    let kem_pk = [0x44u8; 1184];
    let v1 = PeerDescriptor::sign_new(
        &id,
        &kem_pk,
        SocketAddr::from(([198, 51, 100, 10], 55225)),
        NAT_CONE,
    );
    let v2 = PeerDescriptorV2::sign_new(
        &id,
        &kem_pk,
        SocketAddr::from(([198, 51, 100, 10], 55225)),
        vec![SocketAddr::from(([192, 168, 10, 2], 55225))],
        55225,
        NAT_CONE,
        CAP_RELAY | CAP_QUIC,
        Some("ice:ufrag123".to_string()),
    );

    let key = BlindRendezvous::derive_epoch_key(b"swarm-test-secret", 490_000);
    let wrong_key = BlindRendezvous::derive_epoch_key(b"other-swarm-secret", 490_000);

    // v1 descriptor encryption must use fresh random 12-byte nonces
    let c1 = BlindRendezvous::encrypt_descriptor(&key, &v1).expect("encrypt v1 #1");
    let c2 = BlindRendezvous::encrypt_descriptor(&key, &v1).expect("encrypt v1 #2");
    assert_ne!(&c1[..BLIND_NONCE_LEN], &c2[..BLIND_NONCE_LEN]);
    assert_ne!(c1, c2);
    assert_eq!(
        BlindRendezvous::decrypt_descriptor(&key, &c1),
        Some(v1.clone())
    );
    assert_eq!(BlindRendezvous::decrypt_descriptor(&key, &c2), Some(v1));
    assert!(BlindRendezvous::decrypt_descriptor(&wrong_key, &c1).is_none());

    // Tampering nonce, ciphertext, or tag fails AEAD verification
    for idx in [0, 11, 12, c1.len() / 2, c1.len() - 1] {
        let mut bad = c1.clone();
        bad[idx] ^= 0x01;
        assert!(
            BlindRendezvous::decrypt_descriptor(&key, &bad).is_none(),
            "tampered v1 byte {idx} should fail"
        );
    }

    // v2 fixed-size 1024 B blob encryption must also use fresh random nonces
    let b1 = BlindRendezvous::encrypt_descriptor_v2(&key, &v2).expect("encrypt v2 #1");
    let b2 = BlindRendezvous::encrypt_descriptor_v2(&key, &v2).expect("encrypt v2 #2");
    assert_eq!(b1.len(), BLIND_MAILBOX_WIRE_LEN);
    assert_eq!(b2.len(), BLIND_MAILBOX_WIRE_LEN);
    assert_ne!(&b1[..BLIND_NONCE_LEN], &b2[..BLIND_NONCE_LEN]);
    assert_ne!(b1, b2);
    assert_eq!(
        BlindRendezvous::decrypt_descriptor_v2(&key, &b1),
        Some(v2.clone())
    );
    assert_eq!(BlindRendezvous::decrypt_descriptor_v2(&key, &b2), Some(v2));
    assert!(BlindRendezvous::decrypt_descriptor_v2(&wrong_key, &b1).is_none());

    for idx in [0, 11, 12, 500, b1.len() - 1] {
        let mut bad = b1.clone();
        bad[idx] ^= 0x80;
        assert!(
            BlindRendezvous::decrypt_descriptor_v2(&key, &bad).is_none(),
            "tampered v2 byte {idx} should fail"
        );
    }
    assert!(BlindRendezvous::decrypt_blob(&key, &b1[..10]).is_none());
}

#[test]
fn descriptor_v2_and_network_invite_roundtrip_and_tamper_rejection() {
    let id = GhostIdentity::generate_fresh();
    let kem_pk = [0x99u8; 1184];

    // Legacy v1 URI remains supported alongside v2
    let v1 = PeerDescriptor::sign_new(
        &id,
        &kem_pk,
        SocketAddr::from(([203, 0, 113, 25], 55225)),
        NAT_DIRECT,
    );
    let v1_uri = v1.to_uri();
    assert!(v1_uri.starts_with(VB_URI_PREFIX));
    assert_eq!(parse_peer_uri(&v1_uri), Some(ParsedPeerUri::V1(v1)));

    // Unified v2 with IPv6 endpoint, multiple LAN endpoints, all capabilities, and ICE offer
    let v2 = PeerDescriptorV2::sign_new(
        &id,
        &kem_pk,
        "[2001:db8::10]:55225".parse().unwrap(),
        vec![
            "192.168.1.50:55225".parse().unwrap(),
            "10.8.0.2:55225".parse().unwrap(),
        ],
        55225,
        NAT_RESTRICTED,
        CAP_RELAY | CAP_EXIT | CAP_VPN_HUB | CAP_QUIC,
        Some("v=0;ufrag=ab12;pwd=secretpwd".to_string()),
    );
    assert!(v2.verify(60));
    assert_eq!(v2.fingerprint(), id.fingerprint());

    let v2_uri = v2.to_uri();
    assert!(v2_uri.starts_with(VB_V2_URI_PREFIX));
    assert_eq!(PeerDescriptorV2::from_uri(&v2_uri), Some(v2.clone()));
    assert_eq!(parse_peer_uri(&v2_uri), Some(ParsedPeerUri::V2(v2.clone())));

    // Tamper each signed field and ensure verification fails
    let mut t = v2.clone();
    t.ed25519_pk[0] ^= 1;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.pq_commitment[5] ^= 1;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.ml_kem_hash[3] ^= 1;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.endpoint = "198.51.100.99:443".parse().unwrap();
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.lan_endpoints.push("172.16.0.9:55225".parse().unwrap());
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.mesh_port = 9999;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.nat_type = NAT_DIRECT;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.capabilities &= !CAP_RELAY;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.ice_offer = None;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.timestamp += 1;
    assert!(!t.verify(60));

    let mut t = v2.clone();
    t.signature[63] ^= 1;
    assert!(!t.verify(60));

    // Trailing garbage rejected by strict parser
    let mut with_trailing = v2.to_bytes();
    with_trailing.push(0x00);
    assert!(PeerDescriptorV2::from_bytes(&with_trailing).is_none());

    // NetworkInvite roundtrip with and without bootstrap peer
    let invite = NetworkInvite {
        network_name: "family-vpn".to_string(),
        swarm_secret: [0x5au8; 32],
        rendezvous_url: Some("https://rendezvous.example.workers.dev".to_string()),
        bootstrap_peer: Some(v2.clone()),
    };
    let invite_uri = invite.to_uri();
    assert!(invite_uri.starts_with(VB_NET_URI_PREFIX));
    let parsed_invite = NetworkInvite::from_uri(&invite_uri).expect("parse invite");
    assert_eq!(parsed_invite, invite);
    assert!(parsed_invite.verify_bootstrap(60));

    let mut tampered_invite = parsed_invite;
    tampered_invite.bootstrap_peer.as_mut().unwrap().mesh_port = 1111;
    assert!(!tampered_invite.verify_bootstrap(60));
}

#[test]
fn local_peer_cache_v2_save_load_and_expiry_pruning() {
    let dir = std::env::temp_dir().join(format!("ggn_cache_v2_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cache_path = dir.join("peers_v2.bin");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let id_fresh = GhostIdentity::generate_fresh();
    let id_expired = GhostIdentity::generate_fresh();
    let id_tampered = GhostIdentity::generate_fresh();
    let kem_pk = [0x11u8; 1184];

    let fresh = PeerDescriptorV2::sign_new_with_timestamp(
        &id_fresh,
        &kem_pk,
        "198.51.100.11:55225".parse().unwrap(),
        vec!["192.168.1.11:55225".parse().unwrap()],
        55225,
        NAT_CONE,
        CAP_RELAY,
        None,
        now,
    );
    let expired = PeerDescriptorV2::sign_new_with_timestamp(
        &id_expired,
        &kem_pk,
        "198.51.100.12:55225".parse().unwrap(),
        vec![],
        55225,
        NAT_DIRECT,
        CAP_EXIT,
        None,
        now.saturating_sub(86400 * 31), // 31 days old -> past 30-day cache TTL
    );
    let mut tampered = PeerDescriptorV2::sign_new_with_timestamp(
        &id_tampered,
        &kem_pk,
        "198.51.100.13:55225".parse().unwrap(),
        vec![],
        55225,
        NAT_DIRECT,
        0,
        None,
        now,
    );
    tampered.signature[0] ^= 0x55;

    LocalPeerCache::save_v2(&cache_path, &[fresh.clone(), expired, tampered]).expect("save_v2");
    let raw = std::fs::read(&cache_path).expect("read cache file");
    assert_eq!(&raw[..9], b"VBPCACHE2");

    // Legacy v1 loader must reject VBPCACHE2 header
    assert!(LocalPeerCache::load(&cache_path).is_err());

    let loaded = LocalPeerCache::load_v2(&cache_path).expect("load_v2");
    assert_eq!(loaded, vec![fresh]);

    let _ = std::fs::remove_file(&cache_path);
    let _ = std::fs::remove_dir(&dir);
}

#[tokio::test]
async fn blind_mailbox_client_e2e_zero_leakage_and_filtering() {
    let (base_url, state) = spawn_mock_blind_mailbox().await;
    let client = BlindMailboxClient::new().expect("BlindMailboxClient");
    let swarm_secret = b"alpha-swarm-shared-secret-32byte";

    let id_a = GhostIdentity::generate_fresh();
    let id_b = GhostIdentity::generate_fresh();
    let kem_a = [0x12u8; 1184];
    let kem_b = [0x34u8; 1184];

    let secret_ip_a = "198.51.100.77";
    let secret_lan_a = "192.168.42.9";
    let desc_a = PeerDescriptorV2::sign_new(
        &id_a,
        &kem_a,
        format!("{secret_ip_a}:55225").parse().unwrap(),
        vec![format!("{secret_lan_a}:55225").parse().unwrap()],
        55225,
        NAT_CONE,
        CAP_RELAY | CAP_QUIC,
        Some("ice-offer-secret-a".to_string()),
    );
    let desc_b = PeerDescriptorV2::sign_new(
        &id_b,
        &kem_b,
        "203.0.113.88:55225".parse().unwrap(),
        vec![],
        55225,
        NAT_DIRECT,
        CAP_EXIT,
        None,
    );

    client
        .publish_descriptor(&base_url, swarm_secret, &desc_a)
        .await
        .expect("publish desc_a");
    client
        .publish_descriptor(&base_url, swarm_secret, &desc_b)
        .await
        .expect("publish desc_b");

    // Verify the HTTP server never saw any plaintext IP, port, fingerprint, or query params
    {
        let guard = state.lock().unwrap();
        let puts: Vec<&RecordedRequest> = guard
            .requests
            .iter()
            .filter(|r| r.method == "PUT")
            .collect();
        assert_eq!(puts.len(), 2);
        for req in puts {
            assert!(!req.target.contains('?'), "URL must not carry query params");
            assert_eq!(req.body.len(), BLIND_MAILBOX_WIRE_LEN);
            let combined = format!("{}\n{}", req.target, req.headers);
            assert!(!combined.contains(secret_ip_a));
            assert!(!combined.contains(secret_lan_a));
            assert!(!combined.contains("55225"));
            assert!(!combined.contains(&id_a.fingerprint()));
            assert!(!combined.contains(&id_b.fingerprint()));
            assert!(
                !req.body
                    .windows(secret_ip_a.len())
                    .any(|w| w == secret_ip_a.as_bytes()),
                "ciphertext must not leak ASCII IP"
            );
            assert!(
                !req.body.windows(4).any(|w| w == [198, 51, 100, 77]),
                "ciphertext must not leak raw IPv4 octets"
            );
            assert!(
                !req.body.windows(32).any(|w| w == id_a.public_key_bytes()),
                "ciphertext must not leak Ed25519 pubkey"
            );
        }

        // Inject garbage, other-swarm blob, and tampered descriptor into the active slot
        drop(guard);
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 3600;
        let (slot_hex, epoch_key) =
            BlindMailboxClient::slot_hex_for_epoch(swarm_secret, now_epoch, 0);
        let other_key = BlindRendezvous::derive_epoch_key(b"unrelated-swarm", now_epoch);
        let other_blob = BlindRendezvous::encrypt_descriptor_v2(&other_key, &desc_a).unwrap();

        let mut tampered_desc = desc_a.clone();
        tampered_desc.mesh_port = 1234; // invalidates signature
        let tampered_blob =
            BlindRendezvous::encrypt_descriptor_v2(&epoch_key, &tampered_desc).unwrap();

        let mut guard = state.lock().unwrap();
        let entry = guard.slots.entry(slot_hex).or_default();
        entry.push("not-valid-base64!!!".to_string());
        entry.push(base64url_encode(b"random-garbage-bytes"));
        entry.push(base64url_encode(&other_blob));
        entry.push(base64url_encode(&tampered_blob));
    }

    let fetched = client
        .fetch_descriptors(&base_url, swarm_secret)
        .await
        .expect("fetch_descriptors");
    assert_eq!(fetched.len(), 2);
    assert!(fetched.contains(&desc_a));
    assert!(fetched.contains(&desc_b));

    // Verify epoch_hour - 1 fallback when current epoch slot is empty
    let prev_swarm = b"rollover-epoch-swarm-secret";
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 3600;
    client
        .publish_descriptor_at_epoch(&base_url, prev_swarm, now_epoch - 1, &desc_a)
        .await
        .expect("publish at epoch - 1");

    let rolled = client
        .fetch_descriptors(&base_url, prev_swarm)
        .await
        .expect("fetch fallback epoch - 1");
    assert_eq!(rolled, vec![desc_a]);
}
