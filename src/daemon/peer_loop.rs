//! daemon::peer_loop — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

pub(crate) async fn handle_pkt(
    node: Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    pending_hs: &PendingHandshakes,
    sock: &UdpSocket,
    ctr: u64,
    data: &[u8],
    // The v2 header's seal metadata, when the frame has one.
    // `None` means a v1 frame: counter-derived nonce, seed key.
    v2: Option<V2FrameMeta>,
    // The session hash parsed from the raw datagram by `ingest`, before any
    // decryption. `handle_pkt` receives already-opened plaintext as `data`, so
    // the ShardSec branch must match candidates against the *wire* hash.
    wire_session_hash: Option<[u8; 4]>,
    src: &SocketAddr,
    revocation_list: Option<&RevocationList>,
    reputation_matrix: Option<&PoissonReputationMatrix>,
    exit_tunnels: &ExitTunnels,
    sessions_rx: &SessionChannels,
    rx_state_map: &RxStateMap,
    connect_acks: &ConnectAcks,
    connect_ok_ctrs: &ConnectOkCtrs,
    trusted_exits: &Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    psk: Option<[u8; 32]>,
    vpn_mode: Option<&VpnMode>,
    tft: Option<&TitForTatEnforcer>,
    exit_rotator: Option<&ExitIpRotator>,
    relay_role: Option<&DerpRelay>,
    fallback_state: Option<&Fallback>,
    nat_puncher: Option<&Arc<vantablack::ghost::net::mesh::NatHolePuncher>>,
    known_descriptors: Option<
        &Arc<DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>>,
    >,
) {
    #[cfg(not(feature = "vpn"))]
    let _ = vpn_mode;
    // C4: Rate-limit ctr == 0 handshakes and unauthenticated beacons when pending_hs >= 50%.
    if ctr == 0
        && (data.starts_with(HANDSHAKE_NEGOTIATION_MAGIC)
            || data.starts_with(HANDSHAKE_V3_MAGIC)
            || (data.len() >= 16 && &data[..16] == b"GHOST_HANDSHAKE_")
            || data.starts_with(b"BEACON"))
        && !wan_rate_limiter().allow(src.ip(), pending_hs.len(), MAX_PENDING_HANDSHAKES)
    {
        tracing::debug!(peer = %src, "C4: rate-limited ctr==0 handshake/beacon");
        return;
    }
    // Explicit suite-list negotiation handshake (counter == 0).
    if ctr == 0 && data.starts_with(HANDSHAKE_NEGOTIATION_MAGIC) {
        let Some(hs) = parse_negotiated_handshake_pdu(data) else {
            tracing::warn!(peer = %src, "Invalid suite-list handshake");
            return;
        };
        let Some(material) = data.get(..data.len() - 64) else {
            return;
        };
        if !l0_identity::verify_peer_signature(&hs.identity_pk, material, &hs.signature) {
            tracing::warn!(peer = %src, "Suite-list handshake signature invalid");
            return;
        }
        let local = [
            HybridCipherSuite::X25519MlKem768V3,
            HybridCipherSuite::X25519MlKem512V2,
        ];
        let Some(selected) = negotiate_cipher_suite(
            &local,
            &hs.supported.iter().map(|s| s.wire_id()).collect::<Vec<_>>(),
        ) else {
            tracing::warn!(peer = %src, "No mutually supported cipher suite");
            return;
        };
        let Some((_, peer_key)) = hs.kyber_keys.iter().find(|(suite, _)| *suite == selected) else {
            return;
        };
        let kem = match selected {
            HybridCipherSuite::X25519MlKem512V2 => {
                kyber_encapsulate(peer_key).map(|(ct, ss)| (ct.to_vec(), ss))
            }
            HybridCipherSuite::X25519MlKem768V3 => kyber768_encapsulate(peer_key),
        };
        let Ok((ct, kem_ss)) = kem else {
            tracing::warn!(peer = %src, "Suite-list KEM encapsulation failed");
            return;
        };
        let responder_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let responder_public = x25519_dalek::PublicKey::from(&responder_secret);
        let x_shared =
            responder_secret.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        // Bind the transcript into the KDF. The initiator's public key comes
        // from the offer, ours is the ephemeral just generated, and the ciphertext is
        // the one about to be sent back — both peers hash identical bytes and both PQ commitments.
        let master = derive_hybrid_master_key_with_transcript(
            selected,
            x_shared.as_bytes(),
            &kem_ss,
            psk.as_ref(),
            &hs.x25519_pub,
            responder_public.as_bytes(),
            &ct,
            &hs.pq_commitment,
            &node.identity.pq_commitment(),
        );
        let response = build_negotiated_response_pdu(
            selected,
            &node.identity.public_key_bytes(),
            &node.identity.pq_commitment(),
            |m| node.identity.sign(m).to_bytes(),
            responder_public.as_bytes(),
            &ct,
        )
        .expect("valid suite-list response");
        let mut encoded = response;
        let raw = l4_rs::encode(&mut encoded);
        let tag = [0u8; 16];
        for (i, shard) in raw.iter().take(3).enumerate() {
            let _ = send_gtf(
                sock,
                src,
                [0, 0, 0, 0],
                1,
                i as u8,
                &frame_shard(shard),
                &tag,
                false,
            )
            .await;
        }
        let fp = hex::encode(&hs.identity_pk[..8]);
        if fp == node.fingerprint() {
            tracing::debug!(peer = %src, "Handshake from self ignored");
            return;
        }
        let mut session = Session::new_with_role(master, fp.clone(), SessionRole::Responder);
        session.set_cipher_suite(selected);
        session.pin_peer_identity(hs.identity_pk);
        session.pin_peer_pq_commitment(hs.pq_commitment);
        register_peer_session(&node, peers, &fp, *src, session, vpn_mode);
        tracing::info!(peer = %src, suite = selected.wire_id(), "Explicit suite-negotiated session established");
        // Immediately transmit local post-quantum authentication chunks
        send_pq_auth_proof(&node, sock, src, fallback_state, &fp).await;
        return;
    }

    // Versioned suite-negotiation handshake (counter == 0).
    // The suite byte is authenticated as part of the handshake transcript.
    // Both ML-KEM variants are accepted here; the response echoes the selected
    // suite, so an initiator cannot be downgraded by rewriting cleartext.
    if ctr == 0 && data.starts_with(HANDSHAKE_V3_MAGIC) {
        let Some(hs) = parse_handshake_pdu_suite(data) else {
            tracing::warn!(peer = %src, "Invalid suite-negotiation handshake");
            return;
        };
        let mut signed = Vec::with_capacity(1 + 32 + hs.kyber_pub.len() + 32);
        signed.push(hs.suite.wire_id());
        signed.extend_from_slice(&hs.x25519_pub);
        signed.extend_from_slice(&hs.kyber_pub);
        signed.extend_from_slice(&hs.identity_pk);
        if !l0_identity::verify_peer_signature(&hs.identity_pk, &signed, &hs.signature) {
            tracing::warn!(peer = %src, "Suite handshake signature invalid");
            return;
        }
        let kem_result = match hs.suite {
            HybridCipherSuite::X25519MlKem512V2 => {
                kyber_encapsulate(&hs.kyber_pub).map(|(ct, ss)| (ct.to_vec(), ss))
            }
            HybridCipherSuite::X25519MlKem768V3 => kyber768_encapsulate(&hs.kyber_pub),
        };
        let (ct, ks) = match kem_result {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(peer = %src, "Suite handshake KEM encapsulation failed");
                return;
            }
        };
        let bs = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bp = x25519_dalek::PublicKey::from(&bs);
        let xs = bs.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        let d = derive_hybrid_master_key_with_suite(hs.suite, xs.as_bytes(), &ks, psk.as_ref());
        let mut bp_arr = [0u8; 32];
        bp_arr.copy_from_slice(bp.as_bytes());
        let resp = build_response_pdu_suite(
            hs.suite,
            &node.identity.public_key_bytes(),
            |m| node.identity.sign(m).to_bytes(),
            &bp_arr,
            &ct,
        )
        .expect("suite response layout");
        let mut rc = resp;
        let raw = l4_rs::encode(&mut rc);
        let tag = [0u8; 16];
        let is_bulk = raw
            .iter()
            .any(|s| frame_shard(s).len() > vantablack::ghost::net::MAX_PAYLOAD_LEN);
        for (i, shard) in raw.iter().take(3).enumerate() {
            let _ = send_gtf(
                sock,
                src,
                [0, 0, 0, 0],
                1,
                i as u8,
                &frame_shard(shard),
                &tag,
                is_bulk,
            )
            .await;
        }
        let fp = hex::encode(&hs.identity_pk[..8]);
        if fp == node.fingerprint() {
            tracing::debug!(peer = %src, "Handshake from self ignored");
            return;
        }
        let mut session = Session::new_with_role(d, fp.clone(), SessionRole::Responder);
        session.set_cipher_suite(hs.suite);
        session.pin_peer_identity(hs.identity_pk);
        register_peer_session(&node, peers, &fp, *src, session, vpn_mode);
        tracing::info!(peer = %src, fingerprint = %fp, suite = hs.suite.wire_id(), "Suite-negotiated session established");
        return;
    }

    // Opt-in §2 uniform handshake. Its random prefix means it must be
    // identified by the reserved handshake counter and exact legacy payload
    // length, never by a magic string.
    if uniform_handshake_enabled()
        && ctr == 0
        && data.len() >= vantablack::ghost::layers::l1_kem::UNIFORM_HANDSHAKE_BLOB_LEN
    {
        let wire = &data[..vantablack::ghost::layers::l1_kem::UNIFORM_HANDSHAKE_BLOB_LEN];
        let Some(hs) = parse_uniform_handshake_pdu(wire) else {
            return;
        };
        let Some(signed_material) = uniform_handshake_signed_material(wire) else {
            return;
        };
        if !l0_identity::verify_peer_signature(&hs.identity_pk, &signed_material, &hs.signature) {
            tracing::warn!(peer = %src, "Uniform handshake signature invalid");
            return;
        }
        let fp = hex::encode(&hs.identity_pk[..8]);
        if node.sessions.len() >= MAX_SESSIONS || node.sessions.contains_key(&fp) {
            tracing::warn!(peer = %src, fingerprint = %fp, "Uniform handshake rejected — session limit or replay");
            return;
        }
        let Ok((ct, ks)) = kyber_encapsulate(&hs.kyber_pub) else {
            tracing::warn!(peer = %src, "Uniform handshake KEM encapsulation failed");
            return;
        };
        let bs = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bp = x25519_dalek::PublicKey::from(&bs);
        let xs = bs.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        let master = derive_hybrid_master_key_with_psk(xs.as_bytes(), &ks, psk.as_ref());
        let mut bp_arr = [0u8; 32];
        bp_arr.copy_from_slice(bp.as_bytes());
        let resp = build_uniform_response_pdu(
            &node.identity.public_key_bytes(),
            |m| node.identity.sign(m).to_bytes(),
            &bp_arr,
            &ct,
        );
        let mut encoded = resp;
        let raw = l4_rs::encode(&mut encoded);
        let tag = [0u8; 16];
        for (i, shard) in raw.iter().take(3).enumerate() {
            let _ = send_gtf(
                sock,
                src,
                [0, 0, 0, 0],
                1,
                i as u8,
                &frame_shard(shard),
                &tag,
                false,
            )
            .await;
        }
        let session = Session::new_with_role(master, fp.clone(), SessionRole::Responder);
        session.pin_peer_identity(hs.identity_pk);
        register_peer_session(&node, peers, &fp, *src, session, vpn_mode);
        tracing::info!(peer = %src, "Uniform handshake session established");
        return;
    }

    // Inbound LAN / WAN discovery beacon on main mesh socket
    if data.len() >= 112 && &data[..16] == BEACON_PREFIX {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[16..48]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[48..112]);
        if l0_identity::verify_peer_signature(&pk, &data[16..48], &sig) {
            let beacon_fp = hex::encode(&pk[..8]);
            if beacon_fp != node.fingerprint() {
                tracing::info!(peer = %src, fingerprint = %beacon_fp, "Mesh beacon received on main socket");
                if !peers.contains_key(&beacon_fp) && pending_hs.len() < MAX_PENDING_HANDSHAKES {
                    initiate_handshake(&node, sock, *src, pending_hs).await;
                }
            }
        }
        return;
    }

    // Handshake (counter == 0)
    if ctr == 0 && data.len() >= 16 && &data[..16] == b"GHOST_HANDSHAKE_" {
        if data.len() < HANDSHAKE_BLOB_LEN {
            tracing::warn!(peer = %src, "Short handshake");
            return;
        }
        let mut b = data.to_vec();
        b.truncate(HANDSHAKE_BLOB_LEN);
        // Anti-replay / anti-flood: refuse to re-handshake an identity we
        // already hold a session for, and bound total sessions (an attacker
        // can mint unlimited self-signed identities).
        if node.sessions.len() >= MAX_SESSIONS {
            tracing::warn!(peer = %src, "Session table full — handshake rejected");
            return;
        }
        let hs = match parse_handshake_pdu(&b) {
            Some(h) => h,
            None => {
                tracing::warn!(peer = %src, "Invalid handshake PDU");
                return;
            }
        };
        let fp = hex::encode(&hs.identity_pk[..8]);
        if fp == node.fingerprint() {
            tracing::debug!(peer = %src, "Handshake from self ignored");
            return;
        }
        // Allow re-handshake: if a peer reconnects or rescans, evict the stale
        // session so the fresh handshake can complete cleanly.
        if node.sessions.contains_key(&fp) {
            tracing::info!(peer = %src, fingerprint = %fp, "Re-handshake from known peer — evicting stale session");
            node.sessions.remove(&fp);
        }

        // VPN hub: gate the MESH session the same way the VPN tunnel already is.
        // Tunnel traffic from an unlisted peer was rejected, but the mesh session
        // itself was not — so a WAN-exposed hub accumulated session state from
        // strangers (PROTOTYPE.md flaw #5). No-op unless this node is a hub.
        #[cfg(feature = "vpn")]
        if let Some(VpnMode::Hub(hub)) = vpn_mode {
            if !hub.authorized(&fp) {
                tracing::warn!(
                    peer = %src, fingerprint = %fp,
                    "Handshake rejected — not in the VPN allowlist (GHOST_VPN_CLIENTS)"
                );
                if let Some(rep) = reputation_matrix {
                    rep.record_interaction(&node.fingerprint(), &fp, false);
                }
                return;
            }
        }

        // WIRED: Byzantine isolation check — drop handshakes from Byzantine-flagged peers
        if let Some(rep) = reputation_matrix {
            if rep.is_byzantine(&node.fingerprint(), &fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Handshake rejected — peer flagged Byzantine");
                return;
            }
        }

        // WIRED: RevocationList check — reject known-compromised identities
        if let Some(rl) = revocation_list {
            if rl.reject_handshake(&fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Handshake rejected — identity revoked");
                if let Some(rep) = reputation_matrix {
                    rep.record_interaction(&node.fingerprint(), &fp, false);
                }
                return;
            }
        }

        let sm = [&hs.x25519_pub[..], &hs.kyber_pub[..]].concat();
        if !l0_identity::verify_peer_signature(&hs.identity_pk, &sm, &hs.signature) {
            tracing::warn!(peer = %src, "Bad handshake signature");
            if let Some(rep) = reputation_matrix {
                rep.record_interaction(&node.fingerprint(), &fp, false);
            }
            return;
        }
        tracing::info!(fingerprint = %fp, peer = %src, "Verified peer");

        let (ct, ks) = match kyber_encapsulate(&hs.kyber_pub) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(peer = %src, "Kyber encapsulate failed: {e}");
                if let Some(rep) = reputation_matrix {
                    rep.record_interaction(&node.fingerprint(), &fp, false);
                }
                return;
            }
        };
        let bs = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bp = x25519_dalek::PublicKey::from(&bs);
        let xs = bs.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        let d = derive_hybrid_master_key_with_psk(xs.as_bytes(), &ks, psk.as_ref());

        // WIRED: Pin key to physical RAM via LockedMemory (mlock / VirtualLock)
        // to prevent sensitive cryptographic material from leaking to swap/pagefile.
        if let Some(mut locked) = LockedMemory::allocate(32) {
            locked.as_mut_slice()[..32].copy_from_slice(&d);
            // Ephemeral locked buffer validated and pinned in RAM
        }

        let mut bp_arr = [0u8; 32];
        bp_arr.copy_from_slice(bp.as_bytes());
        let ct_arr = ct;
        let resp_pdu = build_response_pdu(
            &node.identity.public_key_bytes(),
            |d| node.identity.sign(d).to_bytes(),
            &bp_arr,
            &ct_arr,
        );
        let mut rc = resp_pdu;
        let raw = l4_rs::encode(&mut rc);
        let tag = [0u8; 16];
        for (i, shard) in raw.iter().take(3).enumerate() {
            let _ = send_gtf(
                sock,
                src,
                [0, 0, 0, 0],
                1,
                i as u8,
                &frame_shard(shard),
                &tag,
                false,
            )
            .await;
        }
        let responder_session = Session::new_with_role(d, fp.clone(), SessionRole::Responder);
        responder_session.set_v1_wire(true);
        responder_session.set_pq_authenticated(true);
        // Pin the initiator's identity key: it is what a later ratchet step is
        // verified against, and without it a step is refused rather than trusted.
        responder_session.pin_peer_identity(hs.identity_pk);
        register_peer_session(&node, peers, &fp, *src, responder_session, vpn_mode);
        // Keep the relay's address book current: a session is also the strongest
        // statement that this peer is who it says it is, and its address may have
        // moved since the beacon that first authorized it.
        if let Some(relay) = relay_role {
            relay.authorize(&fp, *src);
        }
        // VPN: a fresh handshake re-anchors the client's lease (precedence 1)
        // and evicts all per-epoch tunnel state.
        #[cfg(feature = "vpn")]
        if let Some(VpnMode::Hub(hub)) = vpn_mode {
            hub.on_handshake(&fp, *src);
        }
        if std::env::var("GGN_DEBUG_SESSION_KEY").is_ok() {
            tracing::info!(peer = %src, session_key8 = %hex::encode(&d[..8]), "Session established");
        } else {
            tracing::info!(peer = %src, "Session established");
        }

        // WIRED: Record successful interaction in reputation
        if let Some(rep) = reputation_matrix {
            rep.record_interaction(&node.fingerprint(), &fp, true);
        }
        return;
    }

    // Explicit suite-list negotiation response (counter == 1).
    if ctr == 1 && data.starts_with(RESPONSE_NEGOTIATION_MAGIC) {
        let Some(resp) = parse_negotiated_response_pdu(data) else {
            tracing::warn!(peer = %src, bytes = data.len(), "Invalid suite-list response");
            return;
        };
        // The signature covers the PDU, which is *not* always the whole
        // datagram: the shard transport pads an odd-length payload, and the
        // ML-KEM-768 response is odd. Slicing 64 bytes off the datagram would
        // include that pad and verify nothing.
        let Some(material) = data.get(..negotiated_response_len(resp.suite) - 64) else {
            return;
        };
        if !l0_identity::verify_peer_signature(&resp.identity_pk, material, &resp.signature) {
            tracing::warn!(peer = %src, "Suite-list response signature invalid");
            return;
        }
        let Some((_, pending)) = pending_hs.remove(&src.to_string()) else {
            tracing::warn!(peer = %src, "Suite-list response has no pending handshake");
            return;
        };
        let PendingHandshake::Negotiated {
            x_secret,
            kem512,
            kem768,
            offered,
        } = pending
        else {
            tracing::warn!(peer = %src, "Suite-list response matched a legacy pending handshake");
            return;
        };
        let local = [
            HybridCipherSuite::X25519MlKem768V3,
            HybridCipherSuite::X25519MlKem512V2,
        ];
        let expected = negotiate_cipher_suite(
            &local,
            &offered
                .iter()
                .map(|suite| suite.wire_id())
                .collect::<Vec<_>>(),
        );
        if expected != Some(resp.suite) {
            tracing::warn!(
                peer = %src,
                selected = resp.suite.wire_id(),
                expected = ?expected,
                "Downgrade/unsupported suite response rejected"
            );
            return;
        }
        let kem_ss = match resp.suite {
            HybridCipherSuite::X25519MlKem512V2 => {
                let Ok(ct) = Ciphertext::<MlKem512>::try_from(resp.kyber_ct.as_slice()) else {
                    return;
                };
                kem512.decapsulate(&ct).as_slice().to_vec()
            }
            HybridCipherSuite::X25519MlKem768V3 => {
                let Ok(ss) = kyber768_decapsulate(&kem768, &resp.kyber_ct) else {
                    return;
                };
                ss
            }
        };
        // Our own public key has to be captured *before* `diffie_hellman` consumes the
        // secret, and it is part of the transcript.
        let initiator_public = x25519_dalek::PublicKey::from(&x_secret);
        let x_shared = x_secret.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
        let master = derive_hybrid_master_key_with_transcript(
            resp.suite,
            x_shared.as_bytes(),
            &kem_ss,
            psk.as_ref(),
            initiator_public.as_bytes(),
            &resp.x25519_pub,
            &resp.kyber_ct,
            &node.identity.pq_commitment(),
            &resp.pq_commitment,
        );
        let fp = hex::encode(&resp.identity_pk[..8]);
        let mut session = Session::new(master, fp.clone());
        session.set_cipher_suite(resp.suite);
        session.pin_peer_identity(resp.identity_pk);
        session.pin_peer_pq_commitment(resp.pq_commitment);
        register_peer_session(&node, peers, &fp, *src, session, vpn_mode);
        tracing::info!(peer = %src, suite = resp.suite.wire_id(), "Explicit suite-negotiated session established (initiator)");
        // Immediately transmit local post-quantum authentication chunks
        send_pq_auth_proof(&node, sock, src, fallback_state, &fp).await;
        return;
    }

    // Versioned suite-negotiation response (counter == 1).
    if ctr == 1 && data.starts_with(RESPONSE_V3_MAGIC) {
        let Some(resp) = parse_response_pdu_suite(data) else {
            tracing::warn!(peer = %src, "Invalid suite-negotiation response");
            return;
        };
        let mut signed = Vec::with_capacity(1 + 32 + resp.kyber_ct.len() + 32);
        signed.push(resp.suite.wire_id());
        signed.extend_from_slice(&resp.x25519_pub);
        signed.extend_from_slice(&resp.kyber_ct);
        signed.extend_from_slice(&resp.identity_pk);
        if !l0_identity::verify_peer_signature(&resp.identity_pk, &signed, &resp.signature) {
            tracing::warn!(peer = %src, "Suite response signature invalid");
            return;
        }
        let fp = hex::encode(&resp.identity_pk[..8]);
        let Some((_, pending)) = pending_hs.remove(&src.to_string()) else {
            tracing::warn!(peer = %src, "Suite response has no pending handshake");
            return;
        };
        let Some((ax, ky_ss)) = (match (resp.suite, pending) {
            (HybridCipherSuite::X25519MlKem512V2, PendingHandshake::Kem512(ax, dk)) => {
                let ct = Ciphertext::<MlKem512>::try_from(resp.kyber_ct.as_slice()).ok();
                ct.map(|ct| (ax, dk.decapsulate(&ct).as_slice().to_vec()))
            }
            _ => None,
        }) else {
            tracing::warn!(peer = %src, "Suite response does not match pending handshake");
            return;
        };
        let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
        let d =
            derive_hybrid_master_key_with_suite(resp.suite, xs.as_bytes(), &ky_ss, psk.as_ref());
        let mut session = Session::new(d, fp.clone());
        session.set_cipher_suite(resp.suite);
        session.pin_peer_identity(resp.identity_pk);
        register_peer_session(&node, peers, &fp, *src, session, vpn_mode);
        tracing::info!(peer = %src, fingerprint = %fp, suite = %resp.suite.wire_id(), "Suite-negotiated session established (initiator)");
        return;
    }

    // Opt-in §2 uniform response. Exact length and reserved response counter
    // keep this separate from ordinary application frames.
    if uniform_handshake_enabled()
        && ctr == 1
        && data.len() >= vantablack::ghost::layers::l1_kem::UNIFORM_RESPONSE_BLOB_LEN
    {
        let wire = &data[..vantablack::ghost::layers::l1_kem::UNIFORM_RESPONSE_BLOB_LEN];
        let Some(resp) = parse_uniform_response_pdu(wire) else {
            return;
        };
        let Some(signed_material) = uniform_response_signed_material(wire) else {
            return;
        };
        if !l0_identity::verify_peer_signature(&resp.identity_pk, &signed_material, &resp.signature)
        {
            tracing::warn!(peer = %src, "Uniform response signature invalid");
            return;
        }
        let Some((_, PendingHandshake::Kem512(ax, dk))) = pending_hs.remove(&src.to_string())
        else {
            tracing::warn!(peer = %src, "Uniform response has no pending handshake");
            return;
        };
        let ct = Ciphertext::<MlKem512>::from(resp.kyber_ct);
        let ks = dk.decapsulate(&ct);
        let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
        let master = derive_hybrid_master_key_with_psk(xs.as_bytes(), ks.as_slice(), psk.as_ref());
        let fp = hex::encode(&resp.identity_pk[..8]);
        let session = Session::new(master, fp.clone());
        session.pin_peer_identity(resp.identity_pk);
        register_peer_session(&node, peers, &fp, *src, session, vpn_mode);
        tracing::info!(peer = %src, "Uniform handshake session established (initiator)");
        return;
    }

    // Handshake response (counter == 1)
    if ctr == 1 && data.len() >= 16 && &data[..16] == b"GHOST_RESPONSE__" {
        let mut rd = data.to_vec();
        if rd.len() < RESPONSE_BLOB_LEN {
            return;
        }
        rd.truncate(RESPONSE_BLOB_LEN);
        let resp = match parse_response_pdu(&rd) {
            Some(r) => r,
            None => {
                return;
            }
        };

        let signed_material = {
            let mut m = vec![0u8; 800];
            m[0..32].copy_from_slice(&resp.x25519_pub);
            m[32..800].copy_from_slice(&resp.kyber_ct);
            m
        };
        if !l0_identity::verify_peer_signature(&resp.identity_pk, &signed_material, &resp.signature)
        {
            tracing::warn!(peer = %src, "Response signature verification failed");
            return;
        }

        let ct = Ciphertext::<MlKem512>::from(resp.kyber_ct);
        let fp = hex::encode(&resp.identity_pk[..8]);
        // WIRED: Byzantine isolation check for initiator
        if let Some(rep) = reputation_matrix {
            if rep.is_byzantine(&node.fingerprint(), &fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Response from peer flagged Byzantine — dropped");
                return;
            }
        }
        // WIRED: RevocationList check for initiator too
        if let Some(rl) = revocation_list {
            if rl.reject_handshake(&fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Response from revoked identity");
                return;
            }
        }
        if let Some((_, PendingHandshake::Kem512(ax, dk))) = pending_hs.remove(&src.to_string()) {
            let ks = dk.decapsulate(&ct);
            let ky_ss: Vec<u8> = ks.as_slice().to_vec();
            let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
            let d = derive_hybrid_master_key_with_suite(
                HybridCipherSuite::X25519MlKem512V2,
                xs.as_bytes(),
                &ky_ss,
                psk.as_ref(),
            );

            // WIRED: Pin key to physical RAM via LockedMemory (mlock / VirtualLock)
            if let Some(mut locked) = LockedMemory::allocate(32) {
                locked.as_mut_slice()[..32].copy_from_slice(&d);
            }

            let initiator_session = Session::new(d, fp.clone());
            initiator_session.set_v1_wire(true);
            initiator_session.set_pq_authenticated(true);
            // Same pin on this side: the answer to a ratchet step is verified
            // against the responder's identity key.
            initiator_session.pin_peer_identity(resp.identity_pk);
            register_peer_session(&node, peers, &fp, *src, initiator_session, vpn_mode);
            if let Some(relay) = relay_role {
                relay.authorize(&fp, *src);
            }
            // VPN: adopt key for client or register lease for hub
            #[cfg(feature = "vpn")]
            match vpn_mode {
                Some(VpnMode::Client(client, _)) => {
                    let e = client.rotate_epoch();
                    client.set_key(d);
                    tracing::info!(epoch = e, "VPN client: epoch rotated for fresh session");
                }
                Some(VpnMode::Hub(hub)) => {
                    hub.on_handshake(&fp, *src);
                }
                None => {}
            }
            tracing::info!(peer = %src, "Session established (initiator)");
        } else {
            tracing::warn!(peer = %src, "No pending handshake for this peer");
        }
        return;
    }

    // Data (counter >= 2) — try to decrypt with existing sessions.
    // Frames may arrive in either AEAD direction (we don't know our role
    // for sure here), so try both; the correct one authenticates.
    //
    // Collect candidate sessions FIRST: taking a write lock (get_mut for the
    // replay guard) while a DashMap iterator is alive deadlocks the task.
    let candidates = OpenCtx::snapshot_of(&node.sessions);
    for cand in &candidates {
        let peer_fp = cand.peer_fp.clone();
        let key = cand.master_key;
        let sh = cand.session_hash;
        let role = cand.role;
        let plain = if v2.is_some_and(|meta| meta.shardsec) {
            // ShardSec frames arrived as *already-opened* shards assembled by
            // the spool: `data` here is plaintext, not a datagram, so the
            // session must be named by the hash parsed off the raw wire
            // header (`wire_session_hash`), never re-parsed from `data`.
            let wire_matches = wire_session_hash.is_some_and(|wire| wire == cand.session_hash);
            if wire_matches {
                // The one commit per message: shards were opened (not committed)
                // in `ingest`, so the chain position for this counter is
                // advanced exactly here, mirroring the legacy path's single
                // `commit_open` per message.
                if let Some(sess) = node.sessions.get(&cand.peer_fp) {
                    let epoch = v2.map(|m| m.epoch).unwrap_or(0);
                    let ours = cand.role.seal_direction();
                    for direction in [ours.peer_direction(), ours] {
                        let plan = sess.plan_open(epoch, direction, ctr);
                        if !matches!(plan, vantablack::ghost::session::ratchet::OpenPlan::Refused) {
                            sess.commit_open(epoch, direction, plan);
                            break;
                        }
                    }
                }
                data.to_vec()
            } else {
                continue;
            }
        } else {
            let Some(sess) = node.sessions.get(&cand.peer_fp) else {
                continue;
            };
            let Some(plain) = open_received_frame(cand, &sess, data, ctr, v2) else {
                continue;
            };
            plain
        };
        let pt: &[u8] = &plain;

        // ── Cover traffic ──
        //
        // A placeholder frame exists only to keep the *rate* constant, so it must
        // have no effect at all: no dispatch, no ratchet bookkeeping, and not even
        // a replay-window slot — which is the plan's "does not disturb the replay
        // window". Dropping it here also keeps it from installing a prepared epoch.
        //
        // The decision is taken on the decrypted marker, never on the header's
        // `FLAG_DUMMY` bit: header flags sit outside the AEAD, so anyone on the
        // path can flip them, and a receiver that trusted the bit could be made
        // either to discard a real frame or to dispatch a placeholder. The marker
        // is inside the ciphertext, so it is unforgeable and cannot be stripped.
        if frame_payload(pt).is_some_and(net::is_dummy_payload) {
            node.stats
                .cover_recv
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::trace!(peer = %peer_fp, "cover-traffic frame dropped by design");
            return;
        }

        // A frame that authenticated under a *prepared* epoch installs it. This is
        // the responder's half of the step: it answers immediately but keeps
        // sealing on the old epoch until the initiator demonstrably committed, so
        // only a frame that actually opens under the new key moves it. A forged
        // frame cannot: it has no key, so it never reaches here.
        if let Some(meta) = v2 {
            if let Some(s) = node.sessions.get(&peer_fp) {
                if meta.epoch > s.epoch() {
                    s.activate_epoch(meta.epoch);
                }
            }
        }

        // Replay protection: the per-session 64-bit sliding window must accept
        // the counter for the current epoch (or v1); retired epochs already enforce
        // single-use keys cryptographically in MsgChain and must not disturb the
        // current epoch's replay window.
        let is_retired = v2.is_some_and(|meta| {
            node.sessions
                .get(&peer_fp)
                .is_some_and(|s| meta.epoch < s.epoch())
        });
        if !is_retired {
            let accepted = node
                .sessions
                .get(&peer_fp)
                .map(|s| s.check_inbound(ctr))
                .unwrap_or(false);
            if !accepted {
                tracing::debug!(peer = %peer_fp, counter = ctr, "Replay/out-of-window frame dropped");
                return;
            }
        }

        // ── Ratchet step ──
        //
        // Before any data handling, and before the tunnel check: these two magics
        // are control PDUs for the ratchet, they are distinct from every other
        // magic in the stack, and neither is ever a message for an application.
        if let Some(payload) = frame_payload(pt) {
            if handle_ratchet_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        // ── Quantum-anchor mix (L10) ──
        //
        // The same shape as the ratchet step above and for the same reason: this
        // is a key-agreement control PDU, it has its own magics, and it must be
        // consumed before anything treats the bytes as application data.
        if let Some(payload) = frame_payload(pt) {
            if handle_qel_mix_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        // ── Post-Quantum Identity Authentication ──
        if let Some(payload) = frame_payload(pt) {
            if handle_pq_auth_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        // ── Authenticated Peer Disconnect / Reroute Notification (GHOST_BYE) ──
        // Checked before the VPN payload handler and before the post-quantum
        // 2nd-stage auth gate so both desktop (v2) and mobile (v1 1-RTT) peers
        // can cleanly announce they are going offline and trigger immediate
        // session/lease eviction and failover.
        if let Some(framed) = frame_payload(pt) {
            let is_bye = framed.starts_with(GHOST_BYE_MAGIC)
                || (framed.len() > 5
                    && &framed[..5] == b"GVPN1"
                    && framed[5..].starts_with(GHOST_BYE_MAGIC));
            if is_bye {
                node.sessions.remove(&peer_fp);
                peers.remove(&peer_fp);
                #[cfg(feature = "vpn")]
                if let Some(VpnMode::Hub(hub)) = vpn_mode {
                    hub.on_disconnect(&peer_fp);
                }
                exit_tunnels.retain(|_, t| t.session_hash != sh);
                sessions_rx.retain(|(s_sh, _), _| *s_sh != sh);
                connect_acks.retain(|(s_sh, _), _| *s_sh != sh);
                connect_ok_ctrs.retain(|(s_sh, _), _| *s_sh != sh);
                rx_state_map.retain(|(s_sh, _), _| *s_sh != sh);
                if let Some(fb) = fallback_state {
                    fb.clear(&peer_fp);
                }
                tracing::info!(
                    peer = %peer_fp,
                    addr = %src,
                    "Peer sent GHOST_BYE disconnect notification — session evicted and routes updated"
                );
                return;
            }
        }

        // ── VPN tunnel payload: [len][GVPN1][epoch u32][ctr u32][ct][tag] ──
        // Hub: ingest client datagrams. Client: write hub replies into TUN.
        // Checked BEFORE all control-channel handling; tunnel traffic has its own
        // inner AEAD and lease authorization and never touches SOCKS5/CHAT/relay logic.
        #[cfg(feature = "vpn")]
        if let Some(framed) = frame_payload(pt) {
            let is_v1 = framed.len() > VPN_PAYLOAD_MAGIC.len()
                && &framed[..VPN_PAYLOAD_MAGIC.len()] == VPN_PAYLOAD_MAGIC.as_slice();
            let is_v2 = framed.len() > vpn::hub::VPN_PAYLOAD_V2_MAGIC.len()
                && &framed[..vpn::hub::VPN_PAYLOAD_V2_MAGIC.len()]
                    == vpn::hub::VPN_PAYLOAD_V2_MAGIC.as_slice();
            if is_v1 || is_v2 {
                let body = if is_v2 {
                    &framed[vpn::hub::VPN_PAYLOAD_V2_MAGIC.len()..]
                } else {
                    &framed[VPN_PAYLOAD_MAGIC.len()..]
                };
                match vpn_mode {
                    Some(VpnMode::Hub(hub)) => {
                        if is_v2 {
                            hub.handle_tunnel_payload_v2(&peer_fp, sh, body, *src);
                        } else {
                            hub.handle_tunnel_payload(&peer_fp, &key, sh, body, *src);
                        }
                    }
                    Some(VpnMode::Client(client, tun)) => {
                        let guard = tun.lock().unwrap_or_else(|e| e.into_inner());
                        if is_v2 {
                            let (_ok, _adv) = vpn::client::open_v2_to_tun(client, body, &*guard);
                        } else {
                            let (_ok, _adv) = vpn::client::open_to_tun(client, body, &*guard);
                        }
                    }
                    None => {}
                }
                return;
            }
        }

        // Gate other application traffic on post-quantum identity verification.
        let is_pq_auth = node
            .sessions
            .get(&peer_fp)
            .map(|s| s.is_pq_authenticated())
            .unwrap_or(false);
        if !is_pq_auth {
            tracing::debug!(
                peer = %peer_fp,
                "Application traffic dropped: session post-quantum authentication pending"
            );
            return;
        }

        let text = String::from_utf8_lossy(pt).into_owned();
        let trimmed = text.trim_end_matches('\0').to_string();
        tracing::info!(peer = %peer_fp, counter = ctr, "Decrypted: {trimmed}");

        // Peer Exchange gossip: learn new peers from connected nodes (v2 signed descriptors + v1 fallback)
        if let Some(payload) = frame_payload(pt) {
            if let Some(body) = payload.strip_prefix(GHOST_BTCR_GOSSIP_MAGIC) {
                let merged = vantablack::ghost::v2::btcr::ingest_gossip_batch(body);
                if merged > 0 {
                    tracing::debug!(peer = %peer_fp, merged, "BTCr gossip: merged bearer tickets");
                }
                return;
            }
            if let Some(body) = payload.strip_prefix(GHOST_FLEET_REVOKE_MAGIC) {
                let merged = vantablack::ghost::v2::fleet::ingest_gossip_revocation_batch(body);
                if merged > 0 {
                    tracing::info!(peer = %peer_fp, merged, "Fleet gossip: merged signed revocations");
                }
                return;
            }
            if let Some(body) = payload.strip_prefix(GHOST_PEX_V2_MAGIC) {
                if !body.is_empty() {
                    let count = body[0] as usize;
                    let mut pos = 1usize;
                    let mut learned_any = false;
                    for _ in 0..count {
                        if pos + 2 > body.len() {
                            break;
                        }
                        let len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
                        pos += 2;
                        if pos + len > body.len() {
                            break;
                        }
                        if let Some(desc) =
                            vantablack::ghost::net::discovery::PeerDescriptorV2::from_bytes(
                                &body[pos..pos + len],
                            )
                        {
                            if desc.verify(86400 * 7) && desc.fingerprint() != node.fingerprint() {
                                install_peer_descriptor_v2(
                                    &node,
                                    sock,
                                    peers,
                                    pending_hs,
                                    nat_puncher.map(|np| np.as_ref()),
                                    fallback_state,
                                    None,
                                    known_descriptors.map(|kd| kd.as_ref()),
                                    desc,
                                )
                                .await;
                                learned_any = true;
                            }
                        }
                        pos += len;
                    }
                    if learned_any {
                        if let Some(kd) = known_descriptors {
                            persist_peer_cache_v2(kd);
                        }
                    }
                }
                return;
            }
            if payload.starts_with(GHOST_PEX_MAGIC) {
                let body = &payload[GHOST_PEX_MAGIC.len()..];
                if !body.is_empty() {
                    let count = body[0] as usize;
                    let mut pos = 1usize;
                    for _ in 0..count {
                        if pos + 16 > body.len() {
                            break;
                        }
                        let fp_bytes = &body[pos..pos + 16];
                        let fp = String::from_utf8_lossy(fp_bytes)
                            .trim_end_matches('\0')
                            .to_string();
                        pos += 16;
                        // Read null-terminated addr string
                        let nul = body[pos..].iter().position(|&b| b == 0);
                        let addr_end = pos + nul.unwrap_or(body.len() - pos);
                        if addr_end > body.len() {
                            break;
                        }
                        let addr_str = String::from_utf8_lossy(&body[pos..addr_end]).to_string();
                        pos = addr_end + 1;
                        // Skip self and already-known peers
                        if fp == node.fingerprint() {
                            continue;
                        }
                        if peers.contains_key(&fp) {
                            continue;
                        }
                        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                            tracing::info!(
                                via = %peer_fp,
                                peer = %fp,
                                addr = %addr,
                                "PEX: learned new peer — initiating handshake"
                            );
                            initiate_handshake(&node, sock, addr, pending_hs).await;
                        }
                    }
                }
                return;
            }
        }

        // Direct chat message (CHAT command): [CHAT!][message]
        // Must run before relay/CONNECT dispatch so a message like
        // "CHAT!1.2.3.4:80" is never mistaken for a SOCKS5 destination.
        if let Some(payload) = frame_payload(pt) {
            if let Some(rest) = payload.strip_prefix(b"CHAT!") {
                let msg = String::from_utf8_lossy(rest)
                    .trim_end_matches('\0')
                    .to_string();
                println!("\n[Chat from {}] {msg}", &peer_fp[..8.min(peer_fp.len())]);
                tracing::info!(peer = %peer_fp, "Chat message delivered");
                return;
            }
        }

        // Blind relay (B22): a decrypted payload may carry a
        // single-hop envelope addressed to another peer. We hold no key for the
        // region it carries and must not touch it — the forward is byte-for-byte
        // by construction, which is the whole security property of the relay.
        //
        // The envelope magic is distinct from the onion's (`BLND!` vs `RLY!`), so
        // the two paths cannot be confused even though the onion's *last* hop also
        // arrives with a hop count of zero.
        if let Some(payload) = frame_payload(pt) {
            if let Some(blind) = relay::parse_blind_frame(payload) {
                let Some(relay) = relay_role else {
                    tracing::debug!(
                        from = %peer_fp,
                        target = %blind.target_fingerprint,
                        "Relay: blind envelope received but relaying is not enabled (GHOST_RELAY)"
                    );
                    return;
                };
                match fallback::relay_hop(relay, &peer_fp, payload) {
                    Ok(hop) => {
                        // Length only, never contents: enough to show the relay
                        // forwarded the frame it was handed, and nothing about it.
                        tracing::debug!(
                            from = %peer_fp,
                            target = %blind.target_fingerprint,
                            dest = %hop.dest,
                            opaque_len = hop.bytes.len(),
                            "Relay: forwarding a sealed frame blindly"
                        );
                        if let Err(e) = sock.send_to(&hop.bytes, hop.dest).await {
                            tracing::debug!(dest = %hop.dest, "Relay: forward failed: {e}");
                        }
                        // Transit is the relay's side of the tit-for-tat ledger: a
                        // peer that uses us as a relay owes us the reciprocal.
                        if let Some(enforcer) = tft {
                            enforcer.forwarded_for(&peer_fp, hop.bytes.len() as u64);
                        }
                    }
                    Err(reason) => tracing::debug!(
                        from = %peer_fp,
                        target = %blind.target_fingerprint,
                        ?reason,
                        "Relay: blind forward refused"
                    ),
                }
                return;
            }
        }

        // Multi-hop relay: a decrypted payload may carry a relay header.
        // (parse the UNFRAMED payload — the length prefix precedes the header)
        if let Some(payload) = frame_payload(pt) {
            // A middle relay receives its downstream layer sealed by the
            // originator under the key the two of them share. Try our session
            // keys to open it before parsing the `RLY!` header inside.
            let mut unsealed: Option<Vec<u8>> = None;
            if payload.starts_with(vantablack::ghost::net::relay::ONION_SEAL_MAGIC) {
                for entry in node.sessions.iter() {
                    if let Some(inner) = vantablack::ghost::net::relay::peel_encrypted_relay_layer(
                        &entry.value().master_key,
                        payload,
                    ) {
                        unsealed = Some(inner);
                        break;
                    }
                }
                if unsealed.is_none() {
                    tracing::debug!(from = %peer_fp, "Relay: sealed layer not addressed to this node");
                    return;
                }
            }
            let payload = unsealed.as_deref().unwrap_or(payload);
            if let Some(relay) = parse_relay_header(payload) {
                if relay.remaining_hops > 0 {
                    // WIRED: Tit-for-Tat enforcer - drop forwarding for evicted leechers
                    if let Some(enforcer) = tft {
                        if enforcer.is_evicted(&peer_fp) {
                            tracing::warn!(peer = %peer_fp, "TFT: relay request dropped — peer evicted for leeching");
                            return;
                        }
                    }

                    // Forward: re-wrap the inner payload for the next hop and send
                    // it through our own session with that hop.
                    let next = &relay.next_hop_fingerprint;
                    // WIRED: Byzantine isolation check for relay path
                    if let Some(rep) = reputation_matrix {
                        if rep.is_byzantine(&node.fingerprint(), next) {
                            tracing::warn!(hop = %next, "Relay: next hop flagged Byzantine — dropping packet");
                            return;
                        }
                    }
                    let tgt = match peers.get(next).map(|v| *v.value()) {
                        Some(addr) => addr,
                        None => {
                            tracing::warn!(hop = %next, "Relay: next hop address unknown");
                            return;
                        }
                    };
                    let Some(sess) = node.sessions.get(next) else {
                        tracing::warn!(hop = %next, "Relay: no session with next hop");
                        return;
                    };
                    let key = sess.master_key;
                    let sh = sess.session_hash;
                    let role = sess.role;
                    drop(sess);
                    let hop_ctr = node
                        .sessions
                        .get(next)
                        .map(|s| s.next_tx_counter())
                        .unwrap_or(2);
                    // For a nested onion, the payload already contains the
                    // next hop's authenticated routing header. Preserve that
                    // header while changing only the transport encryption; if
                    // this is the final relay layer, create the zero-hop form
                    // consumed by the destination. Re-wrapping with `next`
                    // again would make a three-hop route point back at the
                    // middle relay and loop forever.
                    // For a nested onion, forward the inner payload unchanged.
                    // It is either the next plaintext `RLY!` header (legacy
                    // onion) or a *sealed* layer that the next hop opens with
                    // its own session key. Re-wrapping it with `next` would
                    // prepend a header naming the very relay being sent to, so
                    // that relay would look itself up as the next hop and drop
                    // the packet — which is exactly what broke three-hop routes.
                    let rewrap = if relay.remaining_hops > 1 {
                        relay.inner_payload.clone()
                    } else {
                        build_relay_packet(next, 0, &relay.inner_payload)
                    };
                    let hop_ctx = node
                        .sessions
                        .get(next)
                        .map(|s| SealCtx::from_session(&s))
                        .unwrap_or_else(|| SealCtx {
                            key,
                            epoch: 0,
                            counter: hop_ctr,
                            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                            direction: dir_for(role),
                            session_hash: sh,
                            ratchet_due: false,
                        });
                    let (f, tag) = enc_split(&hop_ctx, &rewrap);
                    send3(sock, &tgt, &hop_ctx, &f, &tag).await;

                    // WIRED: Record bytes forwarded for this peer in TFT enforcer
                    if let Some(enforcer) = tft {
                        enforcer.forwarded_for(&peer_fp, relay.inner_payload.len() as u64);
                    }

                    tracing::info!(via = %src, hop = %next, "Relay packet forwarded");
                    return;
                }
                // Final hop: the inner payload is [counter u64 BE (8B)][wire_nonce (12B)][initiator→us
                // encrypted blob + tag]. Try each of our sessions to unwrap it using XChaCha20-Poly1305.
                let inner = &relay.inner_payload;
                if inner.len() >= 20 + 16 {
                    // WIRED: Record bytes forwarded by relay peer for us
                    if let Some(enforcer) = tft {
                        enforcer.forwarded_by(&peer_fp, inner.len() as u64);
                    }

                    let ic = u64::from_be_bytes([
                        inner[0], inner[1], inner[2], inner[3], inner[4], inner[5], inner[6],
                        inner[7],
                    ]);
                    let mut wire_nonce = [0u8; 12];
                    wire_nonce.copy_from_slice(&inner[8..20]);
                    let blob = inner[20..].to_vec();
                    let candidates: Vec<(String, [u8; 32], [u8; 4], SessionRole)> = node
                        .sessions
                        .iter()
                        .map(|e| {
                            (
                                e.peer_fingerprint.clone(),
                                e.master_key,
                                e.session_hash,
                                e.role,
                            )
                        })
                        .collect();
                    for (fp2, key, sh, role) in candidates {
                        // The onion's inner layer now uses XChaCha20-Poly1305 with a
                        // 64-bit counter and transmitted 12-byte random nonce.
                        // Each direction gets a fresh ciphertext copy: an AEAD
                        // attempt may mutate its buffer before returning an error.
                        let pt2 = {
                            let mut first = blob.clone();
                            match xchacha_open(
                                &key,
                                &wire_nonce,
                                0,
                                NonceDirection::InitiatorToResponder,
                                &mut first,
                            ) {
                                Ok(plain) => Some(plain.to_vec()),
                                Err(_) => {
                                    let mut second = blob.clone();
                                    xchacha_open(
                                        &key,
                                        &wire_nonce,
                                        0,
                                        NonceDirection::ResponderToInitiator,
                                        &mut second,
                                    )
                                    .ok()
                                    .map(|plain| plain.to_vec())
                                }
                            }
                        };
                        if let Some(pt2) = pt2 {
                            tracing::info!(peer = %fp2, "Relay payload delivered (final hop)");
                            let payload = pt2.to_vec();
                            if let Some(payload) = frame_payload(&payload) {
                                let initiator_addr =
                                    peers.get(&fp2).map(|v| *v.value()).unwrap_or(*src);
                                if (role == SessionRole::Responder
                                    || payload.starts_with(b"STREAM!"))
                                    && looks_like_dest(payload)
                                {
                                    let allowed = trusted_exits
                                        .read()
                                        .map(|s| s.contains("any") || s.contains(&fp2))
                                        .unwrap_or(false);
                                    if !allowed {
                                        tracing::warn!(peer = %fp2, "Relay Exit CONNECT denied — fingerprint not allowlisted (EXITAUTH)");
                                        return;
                                    }
                                    handle_exit_connect(
                                        Arc::clone(&node),
                                        peers,
                                        sock,
                                        &initiator_addr,
                                        &key,
                                        &sh,
                                        &fp2,
                                        Some(peer_fp.to_string()),
                                        payload,
                                        exit_tunnels,
                                        ic,
                                        exit_rotator,
                                        fallback_state,
                                    )
                                    .await;
                                    return;
                                }
                                if payload == b"OK" || payload.starts_with(b"OK!") {
                                    let stream_id = if payload.starts_with(b"OK!") {
                                        let s = String::from_utf8_lossy(payload);
                                        s.strip_prefix("OK!")
                                            .and_then(|r| r.strip_suffix('!'))
                                            .and_then(|id_str| id_str.parse::<u32>().ok())
                                            .unwrap_or(0)
                                    } else {
                                        0
                                    };
                                    connect_acks.insert((sh, stream_id), true);
                                    connect_ok_ctrs.insert((sh, stream_id), ic);
                                    rx_state_map.remove(&(sh, stream_id));
                                    return;
                                }
                                if payload.starts_with(b"CLOSE!") {
                                    let s = String::from_utf8_lossy(payload);
                                    if let Some(id_str) =
                                        s.strip_prefix("CLOSE!").and_then(|r| r.strip_suffix('!'))
                                    {
                                        if let Ok(sid) = id_str.parse::<u32>() {
                                            exit_tunnels.remove(&exit_tunnel_key(
                                                &initiator_addr,
                                                &sh,
                                                sid,
                                            ));
                                            sessions_rx.remove(&(sh, sid));
                                            connect_acks.remove(&(sh, sid));
                                            rx_state_map.remove(&(sh, sid));
                                        }
                                    }
                                    return;
                                }
                                // Relay unwrapped data frame dispatch
                                let (stream_id, inner_data) =
                                    if payload.len() >= 4 && !looks_like_dest(payload) {
                                        let sid = u32::from_be_bytes([
                                            payload[0], payload[1], payload[2], payload[3],
                                        ]);
                                        (sid, &payload[4..])
                                    } else {
                                        (0u32, payload)
                                    };
                                let tkey = exit_tunnel_key(&initiator_addr, &sh, stream_id);
                                if let Some(mut t_guard) = exit_tunnels.get_mut(&tkey) {
                                    let flush = rx_push(&mut t_guard.rx, ic, inner_data.to_vec());
                                    let out_tx = t_guard.out_tx.clone();
                                    drop(t_guard);
                                    for chunk in flush {
                                        let _ = out_tx.send(chunk);
                                    }
                                    return;
                                }
                                if let Some(tx) =
                                    sessions_rx.get(&(sh, stream_id)).map(|v| v.value().clone())
                                {
                                    let mut st = rx_state_map.entry((sh, stream_id)).or_default();
                                    if st.next.is_none() {
                                        if let Some(ok) = connect_ok_ctrs.get(&(sh, stream_id)) {
                                            st.next = Some(ok.value() + 1);
                                        }
                                    }
                                    let flush = rx_push(&mut st, ic, inner_data.to_vec());
                                    drop(st);
                                    for chunk in flush {
                                        let _ = tx.send(chunk);
                                    }
                                    return;
                                }
                                tracing::info!("Relay data: {}", String::from_utf8_lossy(payload));
                            }
                            return;
                        }
                    }
                    tracing::warn!("Relay final hop: could not unwrap inner payload");
                }
                return;
            }
        }

        // WIRED: Record successful data decryption in reputation
        if let Some(rep) = reputation_matrix {
            rep.record_interaction(&node.fingerprint(), &peer_fp, true);
        }

        // ── Tunnel traffic (framed payloads) ──
        if let Some(payload) = frame_payload(pt) {
            // CONNECT acknowledgement from the exit (supports OK!{stream_id}! and legacy OK)
            if payload == b"OK" || payload.starts_with(b"OK!") {
                let stream_id = if payload.starts_with(b"OK!") {
                    let s = String::from_utf8_lossy(payload);
                    s.strip_prefix("OK!")
                        .and_then(|r| r.strip_suffix('!'))
                        .and_then(|id_str| id_str.parse::<u32>().ok())
                        .unwrap_or(0)
                } else {
                    0
                };
                connect_acks.insert((sh, stream_id), true);
                connect_ok_ctrs.insert((sh, stream_id), ctr);
                rx_state_map.remove(&(sh, stream_id)); // clear stale reorder state
                return;
            }

            // Explicit stream closure notification
            if payload.starts_with(b"CLOSE!") {
                let s = String::from_utf8_lossy(payload);
                if let Some(id_str) = s.strip_prefix("CLOSE!").and_then(|r| r.strip_suffix('!')) {
                    if let Ok(sid) = id_str.parse::<u32>() {
                        exit_tunnels.remove(&exit_tunnel_key(src, &sh, sid));
                        sessions_rx.remove(&(sh, sid));
                        connect_acks.remove(&(sh, sid));
                        rx_state_map.remove(&(sh, sid));
                    }
                }
                return;
            }

            let (stream_id, inner_data) = if payload.len() >= 4 && !looks_like_dest(payload) {
                let sid = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                (sid, &payload[4..])
            } else {
                (0u32, payload)
            };

            let tkey = exit_tunnel_key(src, &sh, stream_id);
            // Existing tunnel → relay data into the remote TCP connection.
            if let Some(mut t_guard) = exit_tunnels.get_mut(&tkey) {
                let flush = rx_push(&mut t_guard.rx, ctr, inner_data.to_vec());
                let out_tx = t_guard.out_tx.clone();
                drop(t_guard);
                for chunk in flush {
                    let _ = out_tx.send(chunk);
                }
                return;
            }
            // We are the exit for this session and this frame is a CONNECT
            // request → open the destination and answer "OK".
            //
            // `STREAM!` is the client's explicit CONNECT marker, so a session
            // role of initiator does not disqualify the request: two peers that
            // handshake each other simultaneously can both hold the initiator
            // role for the surviving session, and refusing the marked CONNECT
            // there would leave a selected home exit silently unusable. The
            // relay branch above already relies on the same marker.
            let is_connect_request = looks_like_dest(payload)
                && (role == SessionRole::Responder || payload.starts_with(b"STREAM!"));
            if is_connect_request {
                // Exit authorization: closed by default; the peer's fingerprint
                // must be allowlisted (or the operator set "any").
                let allowed = trusted_exits
                    .read()
                    .map(|s| s.contains("any") || s.contains(&peer_fp))
                    .unwrap_or(false);
                if !allowed {
                    tracing::warn!(peer = %peer_fp, "Exit CONNECT denied — fingerprint not allowlisted (EXITAUTH)");
                    return;
                }
                handle_exit_connect(
                    Arc::clone(&node),
                    peers,
                    sock,
                    src,
                    &key,
                    &sh,
                    &peer_fp,
                    None,
                    payload,
                    exit_tunnels,
                    ctr,
                    exit_rotator,
                    fallback_state,
                )
                .await;
                return;
            }
            // We are the initiator: relayed remote data (counter >= 3).
            if ctr >= 3 {
                if let Some(tx) = sessions_rx.get(&(sh, stream_id)).map(|v| v.value().clone()) {
                    let mut st = rx_state_map.entry((sh, stream_id)).or_default();
                    // Anchor the reorder window at (OK counter + 1): the exit's
                    // first data frame. This keeps out-of-order frames buffered
                    // instead of anchoring on whichever frame's task wins the
                    // race and dropping the lower counters.
                    if st.next.is_none() {
                        if let Some(ok) = connect_ok_ctrs.get(&(sh, stream_id)) {
                            st.next = Some(ok.value() + 1);
                        }
                    }
                    let flush = rx_push(&mut st, ctr, inner_data.to_vec());
                    drop(st);
                    for chunk in flush {
                        let _ = tx.send(chunk);
                    }
                    return;
                }
            }
            return;
        }
        return;
    }
}

/// Exit node: accept a SOCKS5 CONNECT, open the destination TCP connection,
/// reply "OK" over the mesh, and relay bytes in both directions.
pub(crate) async fn handle_exit_connect(
    node: Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    sock: &UdpSocket,
    src: &SocketAddr,
    key: &[u8; 32],
    sh: &[u8; 4],
    peer_fp: &str,
    via_relay: Option<String>,
    dest: &[u8],
    tunnels: &ExitTunnels,
    connect_ctr: u64,
    exit_rotator: Option<&ExitIpRotator>,
    fallback_state: Option<&Fallback>,
) {
    let raw_request = String::from_utf8_lossy(dest).into_owned();
    let (stream_id, request) = if let Some(rest) = raw_request.strip_prefix("STREAM!") {
        match rest.split_once('!') {
            Some((sid_str, actual_dest)) => {
                (sid_str.parse::<u32>().unwrap_or(0), actual_dest.to_string())
            }
            None => (0u32, raw_request),
        }
    } else {
        (0u32, raw_request)
    };
    // Voucher-bearing requests use `EXITAUTH!<hex-voucher>!<host>:<port>`.
    // The outer GHOST session still authenticates the sender; the voucher adds
    // an explicit, signed capability when the exit requires one.
    let (voucher, dest) = if let Some(rest) = request.strip_prefix("EXITAUTH!") {
        match rest.split_once('!') {
            Some((encoded, target)) => (hex::decode(encoded).ok(), target.to_string()),
            None => (None, request.clone()),
        }
    } else {
        (None, request.clone())
    };
    let (host, port) = match dest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => return,
        },
        None => return,
    };

    // Exit policy is evaluated before DNS resolution and before any socket is
    // opened. This prevents a denied hostname from becoming a DNS oracle and
    // keeps the allowlist enforcement on every exit path (rotated or default).
    let exit_policy = vantablack::ghost::net::relay::ExitPolicy::from_env();
    if !exit_policy.allows(&host) {
        tracing::warn!(peer = %peer_fp, host = %host, "Exit: destination rejected by policy");
        return;
    }
    let require_voucher = std::env::var("GHOST_EXIT_REQUIRE_VOUCHER")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_voucher {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let Some(raw_voucher) = voucher else {
            tracing::warn!(peer = %peer_fp, host = %host, "Exit: capability voucher required");
            return;
        };
        let Some(capability) = vantablack::ghost::net::relay::ExitCapability::decode(&raw_voucher)
        else {
            tracing::warn!(peer = %peer_fp, host = %host, "Exit: malformed capability voucher");
            return;
        };
        if capability.issuer_pk != node.identity.public_key_bytes()
            || !capability.verify(now, peer_fp, &host)
        {
            tracing::warn!(peer = %peer_fp, host = %host, "Exit: invalid, untrusted, or expired capability voucher");
            return;
        }
    }

    let stream = if let Some(rotator) = exit_rotator {
        if rotator.pool_size() > 0 {
            let egress_addr = rotator.get_next_socket_addr(0);
            let connect_res = match egress_addr {
                SocketAddr::V4(v4) => {
                    let socket = tokio::net::TcpSocket::new_v4();
                    match socket {
                        Ok(s) => match s.bind(SocketAddr::V4(v4)) {
                            Ok(()) => match tokio::net::lookup_host(format!("{host}:{port}")).await
                            {
                                Ok(mut addrs) => match addrs.next() {
                                    Some(target) => s.connect(target).await.ok(),
                                    None => None,
                                },
                                Err(_) => None,
                            },
                            Err(e) => {
                                tracing::debug!("Egress bind to {egress_addr} failed: {e}; falling back to default route");
                                tokio::net::TcpStream::connect((host.as_str(), port))
                                    .await
                                    .ok()
                            }
                        },
                        Err(_) => tokio::net::TcpStream::connect((host.as_str(), port))
                            .await
                            .ok(),
                    }
                }
                SocketAddr::V6(v6) => {
                    let socket = tokio::net::TcpSocket::new_v6();
                    match socket {
                        Ok(s) => match s.bind(SocketAddr::V6(v6)) {
                            Ok(()) => match tokio::net::lookup_host(format!("{host}:{port}")).await
                            {
                                Ok(mut addrs) => match addrs.next() {
                                    Some(target) => s.connect(target).await.ok(),
                                    None => None,
                                },
                                Err(_) => None,
                            },
                            Err(e) => {
                                tracing::debug!("Egress bind to {egress_addr} failed: {e}; falling back to default route");
                                tokio::net::TcpStream::connect((host.as_str(), port))
                                    .await
                                    .ok()
                            }
                        },
                        Err(_) => tokio::net::TcpStream::connect((host.as_str(), port))
                            .await
                            .ok(),
                    }
                }
            };
            match connect_res {
                Some(s) => s,
                None => {
                    tracing::warn!(dest = %dest, "Exit: CONNECT failed via rotator");
                    return;
                }
            }
        } else {
            match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(dest = %dest, "Exit: CONNECT failed: {e}");
                    return;
                }
            }
        }
    } else {
        match tokio::net::TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(dest = %dest, "Exit: CONNECT failed: {e}");
                return;
            }
        }
    };

    // Seal the OK under the session's current epoch; the counter, epoch and nonce
    // come from one snapshot so they cannot straddle a ratchet step.
    let ok_ctx = node
        .sessions
        .get(peer_fp)
        .map(|s| SealCtx::from_session(&s))
        .unwrap_or_else(|| SealCtx {
            key: *key,
            epoch: 0,
            counter: 2,
            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
            direction: NonceDirection::ResponderToInitiator,
            session_hash: *sh,
            ratchet_due: false,
        });
    let ok_payload = if stream_id > 0 {
        format!("OK!{stream_id}!").into_bytes()
    } else {
        b"OK".to_vec()
    };
    if let Some(relay_fp) = via_relay.as_deref() {
        let dctr = node
            .sessions
            .get(peer_fp)
            .map(|s| s.next_tx_counter())
            .unwrap_or(2);
        let mut blob = (ok_payload.len() as u16).to_be_bytes().to_vec();
        blob.extend_from_slice(&ok_payload);
        if !blob.len().is_multiple_of(2) {
            blob.push(0);
        }
        let wire_nonce = vantablack::ghost::layers::l2_aead::random_xnonce();
        if vantablack::ghost::layers::l2_aead::xchacha_seal_in_place(
            key,
            &wire_nonce,
            0,
            NonceDirection::ResponderToInitiator,
            &mut blob,
        )
        .is_ok()
        {
            let mut inner = Vec::with_capacity(8 + 12 + blob.len());
            inner.extend_from_slice(&dctr.to_be_bytes());
            inner.extend_from_slice(&wire_nonce);
            inner.extend_from_slice(&blob);
            let relay_envelope = build_relay_packet(peer_fp, 1, &inner);

            let relay_tgt = peers.get(relay_fp).map(|v| *v.value()).unwrap_or(*src);
            let relay_ctx = node
                .sessions
                .get(relay_fp)
                .map(|s| SealCtx::from_session(&s))
                .unwrap_or_else(|| SealCtx {
                    key: *key,
                    epoch: 0,
                    counter: 2,
                    nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                    direction: NonceDirection::ResponderToInitiator,
                    session_hash: *sh,
                    ratchet_due: false,
                });
            let (f, tag) = enc_split(&relay_ctx, &relay_envelope);
            send3(sock, &relay_tgt, &relay_ctx, &f, &tag).await;
        }
    } else {
        let (f, tag) = enc_split(&ok_ctx, &ok_payload);
        // The initiator may have reached us *through* a relay, in which case `src` is
        // the relay's address and a direct reply would go nowhere. Route it the same
        // way the data path is routed.
        match fallback_state.and_then(|f| f.path(peer_fp)) {
            Some(path) => {
                let _ = send3_via_fallback(
                    &node,
                    sock,
                    peer_fp,
                    &ok_ctx,
                    &f,
                    &tag,
                    &path,
                    fallback_state.and_then(|f| f.turn()),
                )
                .await;
            }
            None => send3(sock, src, &ok_ctx, &f, &tag).await,
        }
    }

    let tkey = exit_tunnel_key(src, sh, stream_id);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // Anchor the tunnel's reorder window at (CONNECT counter + 1): the first
    // data frame the initiator sends. Out-of-order frames are buffered, never
    // dropped on a task-scheduling race.
    let rx = RxState {
        next: Some(connect_ctr + 1),
        ..Default::default()
    };
    tunnels.insert(
        tkey.clone(),
        ExitTunnel {
            out_tx,
            rx,
            session_hash: *sh,
        },
    );
    tracing::info!(dest = %dest, peer = %peer_fp, stream_id = stream_id, "Exit tunnel established");

    // Outbound relay: remote TCP → mesh (responder direction), and
    // inbound channel → remote TCP. Idle for 30s tears the tunnel down.
    // Data-frame counters come from the session's shared tx_counter so a later
    // CHAT / keepalive / CONNECT can never reuse a counter the initiator saw
    // (replay-window collision).
    let sock2 = Arc::clone(&node.socket);
    let sessions2 = Arc::clone(&node.sessions);
    let fp2 = peer_fp.to_string();
    let tunnels2 = Arc::clone(tunnels);
    let sh2 = *sh;
    let key2 = *key;
    let addr2 = *src;
    let tkey2 = tkey.clone();
    // Replies take the same route the request did, resolved once: a peer that
    // reached us through a relay cannot be answered directly.
    let node3 = Arc::clone(&node);
    let route2 = fallback_state.and_then(|f| f.path(peer_fp));
    let turn2 = fallback_state.and_then(|f| f.turn().cloned());
    let via_relay_rd = via_relay.clone();
    let relay_target_addr = via_relay
        .as_deref()
        .and_then(|rfp| peers.get(rfp).map(|v| *v.value()))
        .unwrap_or(*src);
    tokio::spawn(async move {
        let (mut rd, mut wr) = stream.into_split();
        let sock3 = sock2;
        let rd_handle = tokio::spawn(async move {
            let mut rbuf = vec![0u8; 900]; // keeps each RS shard ≤ 486 B privacy-frame cap
            loop {
                match rd.read(&mut rbuf).await {
                    Ok(0) | Err(_) => {
                        if stream_id > 0 {
                            let close_msg = format!("CLOSE!{stream_id}!");
                            if let Some(relay_fp) = via_relay_rd.as_deref() {
                                let dctr = sessions2
                                    .get(&fp2)
                                    .map(|s| s.next_tx_counter())
                                    .unwrap_or(2);
                                let mut blob = (close_msg.len() as u16).to_be_bytes().to_vec();
                                blob.extend_from_slice(close_msg.as_bytes());
                                if !blob.len().is_multiple_of(2) {
                                    blob.push(0);
                                }
                                let wire_nonce =
                                    vantablack::ghost::layers::l2_aead::random_xnonce();
                                if vantablack::ghost::layers::l2_aead::xchacha_seal_in_place(
                                    &key2,
                                    &wire_nonce,
                                    0,
                                    NonceDirection::ResponderToInitiator,
                                    &mut blob,
                                )
                                .is_ok()
                                {
                                    let mut inner = Vec::with_capacity(8 + 12 + blob.len());
                                    inner.extend_from_slice(&dctr.to_be_bytes());
                                    inner.extend_from_slice(&wire_nonce);
                                    inner.extend_from_slice(&blob);
                                    let relay_envelope = build_relay_packet(&fp2, 1, &inner);
                                    let relay_ctx = sessions2
                                        .get(relay_fp)
                                        .map(|s| SealCtx::from_session(&s))
                                        .unwrap_or_else(|| SealCtx {
                                            key: key2,
                                            epoch: 0,
                                            counter: 2,
                                            nonce:
                                                vantablack::ghost::layers::l2_aead::random_xnonce(),
                                            direction: NonceDirection::ResponderToInitiator,
                                            session_hash: sh2,
                                            ratchet_due: false,
                                        });
                                    let (rf, rtag) = enc_split(&relay_ctx, &relay_envelope);
                                    send3_mixed(
                                        Arc::clone(&sock3),
                                        &relay_target_addr,
                                        &relay_ctx,
                                        &rf,
                                        &rtag,
                                    )
                                    .await;
                                }
                            }
                        }
                        break;
                    }
                    Ok(n) => {
                        let payload_to_seal = if stream_id > 0 {
                            let mut framed = Vec::with_capacity(4 + n);
                            framed.extend_from_slice(&stream_id.to_be_bytes());
                            framed.extend_from_slice(&rbuf[..n]);
                            framed
                        } else {
                            rbuf[..n].to_vec()
                        };

                        if let Some(relay_fp) = via_relay_rd.as_deref() {
                            let dctr = sessions2
                                .get(&fp2)
                                .map(|s| s.next_tx_counter())
                                .unwrap_or(2);
                            let mut blob = (payload_to_seal.len() as u16).to_be_bytes().to_vec();
                            blob.extend_from_slice(&payload_to_seal);
                            if !blob.len().is_multiple_of(2) {
                                blob.push(0);
                            }
                            let wire_nonce = vantablack::ghost::layers::l2_aead::random_xnonce();
                            if vantablack::ghost::layers::l2_aead::xchacha_seal_in_place(
                                &key2,
                                &wire_nonce,
                                0,
                                NonceDirection::ResponderToInitiator,
                                &mut blob,
                            )
                            .is_ok()
                            {
                                let mut inner = Vec::with_capacity(8 + 12 + blob.len());
                                inner.extend_from_slice(&dctr.to_be_bytes());
                                inner.extend_from_slice(&wire_nonce);
                                inner.extend_from_slice(&blob);
                                let relay_envelope = build_relay_packet(&fp2, 1, &inner);

                                let relay_ctx = sessions2
                                    .get(relay_fp)
                                    .map(|s| SealCtx::from_session(&s))
                                    .unwrap_or_else(|| SealCtx {
                                        key: key2,
                                        epoch: 0,
                                        counter: 2,
                                        nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                                        direction: NonceDirection::ResponderToInitiator,
                                        session_hash: sh2,
                                        ratchet_due: false,
                                    });
                                let (rf, rtag) = enc_split(&relay_ctx, &relay_envelope);
                                send3_mixed(
                                    Arc::clone(&sock3),
                                    &relay_target_addr,
                                    &relay_ctx,
                                    &rf,
                                    &rtag,
                                )
                                .await;
                            }
                        } else {
                            let ctx2 = sessions2
                                .get(&fp2)
                                .map(|s| SealCtx::from_session(&s))
                                .unwrap_or_else(|| SealCtx {
                                    key: key2,
                                    epoch: 0,
                                    counter: 2,
                                    nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                                    direction: NonceDirection::ResponderToInitiator,
                                    session_hash: sh2,
                                    ratchet_due: false,
                                });
                            let (f, tag) = enc_split(&ctx2, &payload_to_seal);
                            match route2.as_ref() {
                                Some(path) => {
                                    let _ = send3_via_fallback(
                                        &node3,
                                        &sock3,
                                        &fp2,
                                        &ctx2,
                                        &f,
                                        &tag,
                                        path,
                                        turn2.as_ref(),
                                    )
                                    .await;
                                }
                                None => {
                                    send3_mixed(Arc::clone(&sock3), &addr2, &ctx2, &f, &tag).await
                                }
                            }
                        }
                    }
                }
            }
        });
        loop {
            tokio::select! {
                chunk = out_rx.recv() => {
                    match chunk {
                        Some(c) => {
                            if wr.write_all(&c).await.is_err() { break; }
                        }
                        None => break,
                    }
                }
                _ = sleep(Duration::from_secs(30)) => break,
            }
        }
        rd_handle.abort();
        tunnels2.remove(&tkey2);
        tracing::info!(dest = %dest, "Exit tunnel closed");
    });
}
