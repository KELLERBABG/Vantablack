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
    v2: Option<V2FrameMeta>,
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
    if ctr == 0 && data.len() >= 12 && &data[..4] == super::experimental::POW_TOKEN_MAGIC {
        let our_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        super::experimental::pow_redeem(
            data,
            *src,
            our_port,
            super::beacon::unix_now_secs() as u64,
        );
        return;
    }

    if ctr == 0 && data.starts_with(HANDSHAKE_NEGOTIATION_MAGIC) {
        if !super::experimental::pow_admit(*src) {
            tracing::debug!(peer = %src, "PoW shield: suite-list handshake without a token — dropped");
            return;
        }
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
        send_pq_auth_proof(&node, sock, src, fallback_state, &fp).await;
        return;
    }

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

    if uniform_handshake_enabled()
        && ctr == 0
        && data.len() >= vantablack::ghost::layers::l1_kem::UNIFORM_HANDSHAKE_BLOB_LEN
    {
        if !super::experimental::pow_admit(*src) {
            tracing::debug!(peer = %src, "PoW shield: uniform handshake without a token — dropped");
            return;
        }
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

    if data.len() >= 112 && &data[..16] == BEACON_PREFIX {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[16..48]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[48..112]);
        if l0_identity::verify_peer_signature(&pk, &data[16..48], &sig) {
            if let Some(sections) = super::beacon::parse_beacon_sections(data, data.len()) {
                if let Some(cdef) = sections.cdef {
                    if super::experimental::note_observable(cdef, *src) {
                        tracing::warn!(
                            peer = %src,
                            "Collective defense: a region crossed the k-anonymity threshold — \
                             peers report sustained loss there"
                        );
                    }
                }
            }
            let beacon_fp = hex::encode(&pk[..8]);
            if beacon_fp != node.fingerprint() {
                tracing::info!(peer = %src, fingerprint = %beacon_fp, "Mesh beacon received on main socket");
                if !peers.contains_key(&beacon_fp)
                    && pending_hs.len() < MAX_PENDING_HANDSHAKES
                    && !std::env::var("GHOST_BEACON")
                        .is_ok_and(|v| v.eq_ignore_ascii_case("off") || v == "0")
                {
                    initiate_handshake(&node, sock, *src, pending_hs).await;
                }
            }
        }
        return;
    }

    if ctr == 0 && data.len() >= 16 && &data[..16] == b"GHOST_HANDSHAKE_" {
        if !super::experimental::pow_admit(*src) {
            tracing::debug!(peer = %src, "PoW shield: handshake without a token — dropped");
            return;
        }
        if data.len() < HANDSHAKE_BLOB_LEN {
            tracing::warn!(peer = %src, "Short handshake");
            return;
        }
        let mut b = data.to_vec();
        b.truncate(HANDSHAKE_BLOB_LEN);
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
        if node.sessions.contains_key(&fp) {
            tracing::info!(peer = %src, fingerprint = %fp, "Re-handshake from known peer — evicting stale session");
            node.sessions.remove(&fp);
        }

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

        if let Some(rep) = reputation_matrix {
            if rep.is_byzantine(&node.fingerprint(), &fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Handshake rejected — peer flagged Byzantine");
                return;
            }
        }

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

        if let Some(mut locked) = LockedMemory::allocate(32) {
            locked.as_mut_slice()[..32].copy_from_slice(&d);
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
        responder_session.pin_peer_identity(hs.identity_pk);
        register_peer_session(&node, peers, &fp, *src, responder_session, vpn_mode);
        if let Some(relay) = relay_role {
            relay.authorize(&fp, *src);
        }
        #[cfg(feature = "vpn")]
        if let Some(VpnMode::Hub(hub)) = vpn_mode {
            hub.on_handshake(&fp, *src);
        }
        if std::env::var("GGN_DEBUG_SESSION_KEY").is_ok() {
            tracing::info!(peer = %src, session_key8 = %hex::encode(&d[..8]), "Session established");
        } else {
            tracing::info!(peer = %src, "Session established");
        }

        if let Some(rep) = reputation_matrix {
            rep.record_interaction(&node.fingerprint(), &fp, true);
        }
        return;
    }

    if ctr == 1 && data.starts_with(RESPONSE_NEGOTIATION_MAGIC) {
        let Some(resp) = parse_negotiated_response_pdu(data) else {
            tracing::warn!(peer = %src, bytes = data.len(), "Invalid suite-list response");
            return;
        };
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
        send_pq_auth_proof(&node, sock, src, fallback_state, &fp).await;
        return;
    }

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
        if let Some(rep) = reputation_matrix {
            if rep.is_byzantine(&node.fingerprint(), &fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Response from peer flagged Byzantine — dropped");
                return;
            }
        }
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

            if let Some(mut locked) = LockedMemory::allocate(32) {
                locked.as_mut_slice()[..32].copy_from_slice(&d);
            }

            let initiator_session = Session::new(d, fp.clone());
            initiator_session.set_v1_wire(true);
            initiator_session.set_pq_authenticated(true);
            initiator_session.pin_peer_identity(resp.identity_pk);
            register_peer_session(&node, peers, &fp, *src, initiator_session, vpn_mode);
            if let Some(relay) = relay_role {
                relay.authorize(&fp, *src);
            }
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

    let candidates = OpenCtx::snapshot_of(&node.sessions);
    for cand in &candidates {
        let peer_fp = cand.peer_fp.clone();
        let key = cand.master_key;
        let sh = cand.session_hash;
        let role = cand.role;
        let plain = if v2.is_some_and(|meta| meta.shardsec) {
            let wire_matches = wire_session_hash.is_some_and(|wire| wire == cand.session_hash);
            if wire_matches {
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

        if frame_payload(pt).is_some_and(net::is_dummy_payload) {
            node.stats
                .cover_recv
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::trace!(peer = %peer_fp, "cover-traffic frame dropped by design");
            return;
        }

        if let Some(meta) = v2 {
            if let Some(s) = node.sessions.get(&peer_fp) {
                if meta.epoch > s.epoch() {
                    s.activate_epoch(meta.epoch);
                }
            }
        }

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

        #[cfg(feature = "research")]
        if super::research_hooks::braid::peer_revoked(&peer_fp) {
            tracing::warn!(peer = %peer_fp, "braid: payload from a revoked identity dropped");
            return;
        }

        if let Some(payload) = frame_payload(pt) {
            if handle_ratchet_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        if let Some(payload) = frame_payload(pt) {
            if handle_qel_mix_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        if let Some(payload) = frame_payload(pt) {
            if handle_pq_auth_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        #[cfg(feature = "research")]
        if let Some(payload) = frame_payload(pt) {
            if let Some(replies) = super::research_hooks::handle_control(&peer_fp, payload) {
                for reply in replies {
                    super::research_hooks::deliver(
                        &node,
                        sock,
                        src,
                        fallback_state,
                        &peer_fp,
                        &reply,
                    )
                    .await;
                }
                return;
            }
        }

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
            if let Some(body) = payload.strip_prefix(GHOST_CENSUS_MAGIC) {
                let endpoint = peers.get(&peer_fp).map(|v| *v);
                let cells = super::discovery::ingest_census_gossip(body, &peer_fp, endpoint);
                if cells > 0 {
                    tracing::debug!(
                        peer = %peer_fp,
                        cells,
                        "Census: recorded a live epoch announcement"
                    );
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
                        let nul = body[pos..].iter().position(|&b| b == 0);
                        let addr_end = pos + nul.unwrap_or(body.len() - pos);
                        if addr_end > body.len() {
                            break;
                        }
                        let addr_str = String::from_utf8_lossy(&body[pos..addr_end]).to_string();
                        pos = addr_end + 1;
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

        if let Some(payload) = frame_payload(pt) {
            if let Some(rest) = payload.strip_prefix(b"CHAT!") {
                let msg = String::from_utf8_lossy(rest)
                    .trim_end_matches('\0')
                    .to_string();
                println!("\n[Chat from {}] {msg}", &peer_fp[..8.min(peer_fp.len())]);
                tracing::info!(peer = %peer_fp, "Chat message delivered");
                return;
            }
            if let Some(rest) = payload.strip_prefix(b"NECHO") {
                if rest.len() >= 17 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(&rest[..16]);
                    let hops = rest[16].max(1);
                    let input = vantablack::ghost::v2::xray::nonce_echo_signing_input(&nonce, hops);
                    let sig = node.identity.sign(&input).to_bytes();
                    let mut reply = Vec::with_capacity(5 + 16 + 1 + 64);
                    reply.extend_from_slice(b"NECH2");
                    reply.extend_from_slice(&nonce);
                    reply.push(hops);
                    reply.extend_from_slice(&sig);
                    if let Some(sess) = node.sessions.get(&peer_fp) {
                        let rctx = SealCtx::from_session(&sess);
                        drop(sess);
                        let frame = seal_single(&rctx, &reply);
                        let _ = super::srtp::send_v2(
                            sock,
                            src,
                            &rctx.data_header(0, false, 0),
                            &frame,
                            &[0u8; 16],
                        )
                        .await;
                    }
                }
                return;
            }
            if let Some(rest) = payload.strip_prefix(b"NECH2") {
                if rest.len() >= 16 + 1 + 64 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(&rest[..16]);
                    let hops = rest[16];
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&rest[17..81]);
                    if let Some(pk) = node
                        .sessions
                        .get(&peer_fp)
                        .and_then(|s| s.peer_identity_pk())
                    {
                        if vantablack::ghost::v2::xray::verify_nonce_echo(&nonce, &pk, &sig, hops) {
                            tracing::debug!(peer = %peer_fp, hops, "X-Ray: verified signed nonce-echo witness");
                        }
                    }
                }
                return;
            }
        }

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
                #[cfg(feature = "research")]
                if !super::research_hooks::voucher::admit_transit(&peer_fp, payload.len()) {
                    return;
                }
                match fallback::relay_hop(relay, &peer_fp, payload) {
                    Ok(hop) => {
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

        if let Some(payload) = frame_payload(pt) {
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
                    #[cfg(feature = "research")]
                    if !super::research_hooks::voucher::admit_transit_onion(&peer_fp, payload.len())
                    {
                        return;
                    }
                    if let Some(enforcer) = tft {
                        if enforcer.is_evicted(&peer_fp) {
                            tracing::warn!(peer = %peer_fp, "TFT: relay request dropped — peer evicted for leeching");
                            return;
                        }
                    }

                    let next = &relay.next_hop_fingerprint;
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
                            tail: vantablack::ghost::net::random_tail(),
                        });
                    let (f, tag) = enc_split(&hop_ctx, &rewrap);
                    send3(sock, &tgt, &hop_ctx, &f, &tag).await;

                    if let Some(enforcer) = tft {
                        enforcer.forwarded_for(&peer_fp, relay.inner_payload.len() as u64);
                    }

                    tracing::info!(via = %src, hop = %next, "Relay packet forwarded");
                    return;
                }
                let inner = &relay.inner_payload;
                if inner.len() >= 20 + 16 {
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

        if let Some(rep) = reputation_matrix {
            rep.record_interaction(&node.fingerprint(), &peer_fp, true);
        }

        if let Some(payload) = frame_payload(pt) {
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
            if let Some(mut t_guard) = exit_tunnels.get_mut(&tkey) {
                let flush = rx_push(&mut t_guard.rx, ctr, inner_data.to_vec());
                let out_tx = t_guard.out_tx.clone();
                drop(t_guard);
                for chunk in flush {
                    let _ = out_tx.send(chunk);
                }
                return;
            }
            let is_connect_request = looks_like_dest(payload)
                && (role == SessionRole::Responder || payload.starts_with(b"STREAM!"));
            if is_connect_request {
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
            if ctr >= 3 {
                if let Some(tx) = sessions_rx.get(&(sh, stream_id)).map(|v| v.value().clone()) {
                    let mut st = rx_state_map.entry((sh, stream_id)).or_default();
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
            tail: vantablack::ghost::net::random_tail(),
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
                    tail: vantablack::ghost::net::random_tail(),
                });
            let (f, tag) = enc_split(&relay_ctx, &relay_envelope);
            send3(sock, &relay_tgt, &relay_ctx, &f, &tag).await;
        }
    } else {
        let (f, tag) = enc_split(&ok_ctx, &ok_payload);
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

    let sock2 = Arc::clone(&node.socket);
    let sessions2 = Arc::clone(&node.sessions);
    let fp2 = peer_fp.to_string();
    let tunnels2 = Arc::clone(tunnels);
    let sh2 = *sh;
    let key2 = *key;
    let addr2 = *src;
    let tkey2 = tkey.clone();
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
                                            tail: vantablack::ghost::net::random_tail(),
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
                                        tail: vantablack::ghost::net::random_tail(),
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
                                    tail: vantablack::ghost::net::random_tail(),
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
