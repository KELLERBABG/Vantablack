//! daemon::ratchet — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

pub(crate) const RATCHET_TICK: Duration = Duration::from_secs(5);
pub(crate) const RATCHET_STEP_STALL: Duration = Duration::from_secs(30);

pub(crate) const QUANTUM_MIX_STALL: Duration = Duration::from_secs(90);

pub(crate) const QUANTUM_MIX_RETRY: Duration = Duration::from_secs(60);

pub(crate) async fn ratchet_maintenance_once(
    nc: &Arc<GhostNode>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    fallback: &Arc<Fallback>,
) {
    let mut work: Vec<(String, SocketAddr, Vec<u8>)> = Vec::new();
    for e in nc.sessions.iter() {
        if e.ratchet_step_stalled(RATCHET_STEP_STALL) {
            tracing::warn!(
                peer = %e.peer_fingerprint,
                "ratchet step unanswered for {RATCHET_STEP_STALL:?} — abandoning and retrying"
            );
            e.abandon_ratchet_step();
        }
        if !e.ratchet_due() {
            continue;
        }
        let fp = e.peer_fingerprint.clone();
        let addr = addrs.get(&fp).map(|v| *v.value());
        if addr.is_none() && fallback.path(&fp).is_none() {
            continue;
        }
        let addr = addr.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
        let Some((x_pub, kem_pub)) = e.begin_ratchet_step() else {
            continue; // a step is already in flight
        };
        let Some(pdu) =
            build_ratchet_step_pdu(|d| nc.identity.sign(d).to_bytes(), &x_pub, &kem_pub)
        else {
            e.abandon_ratchet_step();
            continue;
        };
        work.push((fp, addr, pdu));
    }
    for (fp, addr, pdu) in work {
        let Some(sess) = nc.sessions.get(&fp) else {
            continue;
        };
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        let frame = seal_single(&ctx, &pdu);
        tracing::debug!(peer = %fp, epoch = ctx.epoch, "sending ratchet step");
        send_frame_to_peer(nc, &nc.socket, &addr, Some(fallback), &fp, frame).await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_ratchet_pdu(
    node: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let is_init = payload.starts_with(REKEY_MAGIC);
    let is_answer = payload.starts_with(REKEY_RESPONSE_MAGIC);
    if !is_init && !is_answer {
        return false;
    }
    let Some(sess) = node.sessions.get(peer_fp) else {
        tracing::debug!(peer = %peer_fp, "ratchet PDU for an unknown peer — dropped");
        return true;
    };
    let Some(pk) = sess.peer_identity_pk() else {
        tracing::warn!(
            peer = %peer_fp,
            "ratchet PDU from a session with no pinned identity key — refused"
        );
        return true;
    };

    if is_init {
        let Some(blob) = parse_rekey_pdu(payload) else {
            tracing::warn!(peer = %peer_fp, "malformed ratchet step PDU");
            return true;
        };
        let material = rekey_init_signed_material(&blob.x25519_pub, &blob.kyber_pub);
        if !l0_identity::verify_peer_signature(&pk, &material, &blob.signature) {
            tracing::warn!(peer = %peer_fp, "ratchet step signature invalid — refused");
            return true;
        }
        if !sess.admit_peer_step(&node.fingerprint()) {
            tracing::warn!(
                peer = %peer_fp,
                "crossed ratchet steps — our own step wins the tie-break; the arriving one is dropped"
            );
            return true;
        }
        let Some(answer) = sess.answer_ratchet_step(&blob.x25519_pub, &blob.kyber_pub) else {
            tracing::warn!(peer = %peer_fp, "ratchet step could not be answered");
            return true;
        };
        let pdu = build_rekey_response_pdu(
            |d| node.identity.sign(d).to_bytes(),
            &answer.x_public,
            &answer.kem_ct,
            &answer.confirm,
        );
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        let frame = seal_single(&ctx, &pdu);
        send_frame_to_peer(node, sock, src, fallback, peer_fp, frame).await;
        tracing::info!(
            peer = %peer_fp,
            epoch = answer.epoch,
            "ratchet step answered (epoch prepared, not yet installed)"
        );
        return true;
    }

    let Some(blob) = parse_rekey_response_pdu(payload) else {
        tracing::warn!(peer = %peer_fp, "malformed ratchet answer PDU");
        return true;
    };
    let material = rekey_answer_signed_material(&blob.x25519_pub, &blob.kyber_ct, &blob.confirm);
    if !l0_identity::verify_peer_signature(&pk, &material, &blob.signature) {
        tracing::warn!(peer = %peer_fp, "ratchet answer signature invalid — refused");
        return true;
    }
    let expected = sess.epoch() + 1;
    let answer = RatchetAnswer {
        x_public: blob.x25519_pub,
        kem_ct: blob.kyber_ct,
        confirm: blob.confirm,
        epoch: expected,
    };
    match sess.finish_ratchet_step(&answer) {
        Some(epoch) => tracing::info!(peer = %peer_fp, epoch, "ratchet step complete"),
        None => tracing::warn!(
            peer = %peer_fp,
            "ratchet answer did not confirm the step — epoch unchanged"
        ),
    }
    true
}

pub(crate) fn qel_topology_path() -> PathBuf {
    std::env::var("GHOST_QEL_TOPOLOGY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| vantablack::ghost::paths::data_file("ghost-topology.json"))
}

pub(crate) fn mesh_topology_json(
    nc: &Arc<GhostNode>,
    addrs: &DashMap<String, SocketAddr>,
    plan: &ContactPlan,
) -> (String, usize, usize) {
    let local_fp = nc.fingerprint();
    let mut nodes = vec![serde_json::json!({
        "fingerprint": local_fp,
        "addr": nc.local_addr.to_string(),
    })];
    for e in addrs.iter() {
        nodes.push(serde_json::json!({
            "fingerprint": e.key(),
            "addr": e.value().to_string(),
        }));
    }
    let mut links = Vec::new();
    for e in nc.sessions.iter() {
        let peer = e.key().clone();
        let range_km = plan
            .contacts_from(&local_fp)
            .find(|c| c.destination == peer && c.range_km > 0.0)
            .map(|c| c.range_km);
        let mut link = serde_json::json!({"a": local_fp.clone(), "b": peer});
        if let Some(km) = range_km {
            link["length_km"] = serde_json::json!(km);
        }
        links.push(link);
    }
    let doc = serde_json::json!({
        "schema_version": 1,
        "generator": "vantablack",
        "exported_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "nodes": nodes,
        "links": links,
    });
    let n = nodes.len();
    let l = links.len();
    (serde_json::to_string_pretty(&doc).unwrap_or_default(), n, l)
}

pub(crate) async fn quantum_mix_maintenance_once(
    nc: &Arc<GhostNode>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    fallback: &Arc<Fallback>,
    ctrl: &Arc<QuantumAnchorController>,
) {
    let our_fp = nc.fingerprint();
    let topology = qel_topology_path();
    let mut due: Vec<String> = Vec::new();
    for e in nc.sessions.iter() {
        let peer_fp = e.peer_fingerprint.clone();
        if e.quantum_mix_stalled(QUANTUM_MIX_STALL) {
            tracing::warn!(
                peer = %peer_fp,
                "quantum mix unanswered for {QUANTUM_MIX_STALL:?} — abandoning (epoch unchanged)"
            );
            e.abandon_quantum_mix();
        }
        if e.quantum_mix_due(QUANTUM_MIX_RETRY) && our_fp < peer_fp {
            due.push(peer_fp);
        }
    }
    if due.is_empty() {
        return;
    }

    let (json, nodes, links) = {
        let plan = nc.contact_plan.read().await;
        mesh_topology_json(nc, addrs, &plan)
    };
    match std::fs::write(&topology, json) {
        Ok(()) => {
            tracing::debug!(
                path = %topology.display(),
                nodes,
                links,
                "qel: refreshed the mesh topology export for the quantum mix"
            );
        }
        Err(e) => tracing::debug!(
            path = %topology.display(),
            error = %e,
            "qel: could not refresh the mesh topology export — the mix has nothing to route over"
        ),
    }

    let mut work: Vec<(String, SocketAddr, Vec<u8>)> = Vec::new();
    for peer_fp in due {
        let addr = addrs.get(&peer_fp).map(|v| *v.value());
        if addr.is_none() && fallback.path(&peer_fp).is_none() {
            continue;
        }
        let addr = addr.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
        let Some(sess) = nc.sessions.get(&peer_fp) else {
            continue;
        };
        sess.note_quantum_mix_attempt();
        drop(sess);

        let outcome = ctrl
            .establish_quantum_link(&topology, &our_fp, &peer_fp)
            .await;
        let (Some(key), Some(label)) = (outcome.key, outcome.label.clone()) else {
            tracing::debug!(
                peer = %peer_fp,
                error = outcome.error.as_deref().unwrap_or("unknown"),
                "qel: no quantum key for this peer — session continues without quantum entropy"
            );
            continue;
        };
        let Some(sess) = nc.sessions.get(&peer_fp) else {
            continue;
        };
        let Some(pending) = sess.begin_quantum_mix(&key, &label) else {
            continue;
        };
        let pdu = build_qel_mix_pdu(
            |d| nc.identity.sign(d).to_bytes(),
            pending.epoch,
            &pending.label,
            &pending.confirm,
        );
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        tracing::info!(
            peer = %peer_fp,
            epoch = pending.epoch,
            backend = ctrl.backend_name(),
            key_label = %label,
            "qel: starting quantum mix (epoch prepared from quantum entropy)"
        );
        work.push((peer_fp, addr, seal_single(&ctx, &pdu)));
    }
    for (fp, addr, frame) in work {
        send_frame_to_peer(nc, &nc.socket, &addr, Some(fallback), &fp, frame).await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_qel_mix_pdu(
    node: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let is_init = payload.starts_with(QEL_MIX_MAGIC);
    let is_answer = payload.starts_with(QEL_MIX_RESPONSE_MAGIC);
    if !is_init && !is_answer {
        return false;
    }
    if is_init {
        let Some(blob) = parse_qel_mix_pdu(payload) else {
            tracing::warn!(peer = %peer_fp, "malformed quantum mix PDU");
            return true;
        };
        {
            let Some(sess) = node.sessions.get(peer_fp) else {
                tracing::debug!(peer = %peer_fp, "quantum mix PDU for an unknown peer — dropped");
                return true;
            };
            let Some(pk) = sess.peer_identity_pk() else {
                tracing::warn!(
                    peer = %peer_fp,
                    "quantum mix PDU from a session with no pinned identity key — refused"
                );
                return true;
            };
            let material = qel_mix_signed_material(blob.epoch, &blob.label, &blob.confirm);
            if !l0_identity::verify_peer_signature(&pk, &material, &blob.signature) {
                tracing::warn!(peer = %peer_fp, "quantum mix signature invalid — refused");
                return true;
            }
            if !sess.admit_peer_quantum_mix(&node.fingerprint()) {
                tracing::warn!(
                    peer = %peer_fp,
                    "crossed quantum mixes — our own mix wins the tie-break; the arriving one is dropped"
                );
                return true;
            }
        }

        let ctrl = l10_qel::shared_controller();
        let outcome = ctrl.redeem_key(peer_fp, &blob.label).await;
        let Some(key) = outcome.key else {
            tracing::warn!(
                peer = %peer_fp,
                epoch = blob.epoch,
                error = outcome.error.as_deref().unwrap_or("unknown"),
                "quantum mix key unavailable — refused (the peer keeps its epoch)"
            );
            return true;
        };

        let Some(sess) = node.sessions.get(peer_fp) else {
            tracing::debug!(peer = %peer_fp, "quantum mix: session closed during the key fetch");
            return true;
        };
        let Some(answer) = sess.answer_quantum_mix(&key, blob.epoch, &blob.confirm, &blob.label)
        else {
            tracing::warn!(peer = %peer_fp, "quantum mix could not be answered");
            return true;
        };
        let pdu =
            build_qel_mix_response_pdu(|d| node.identity.sign(d).to_bytes(), blob.epoch, &answer);
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        let frame = seal_single(&ctx, &pdu);
        send_frame_to_peer(node, sock, src, fallback, peer_fp, frame).await;
        tracing::info!(
            peer = %peer_fp,
            epoch = blob.epoch,
            "quantum mix answered (epoch prepared, not yet installed)"
        );
        return true;
    }

    let Some(blob) = parse_qel_mix_response_pdu(payload) else {
        tracing::warn!(peer = %peer_fp, "malformed quantum mix answer PDU");
        return true;
    };
    let Some(sess) = node.sessions.get(peer_fp) else {
        tracing::debug!(peer = %peer_fp, "quantum mix answer for an unknown peer — dropped");
        return true;
    };
    let Some(pk) = sess.peer_identity_pk() else {
        tracing::warn!(
            peer = %peer_fp,
            "quantum mix answer from a session with no pinned identity key — refused"
        );
        return true;
    };
    let material = qel_mix_response_signed_material(blob.epoch, &blob.confirm);
    if !l0_identity::verify_peer_signature(&pk, &material, &blob.signature) {
        tracing::warn!(peer = %peer_fp, "quantum mix answer signature invalid — refused");
        return true;
    }
    match sess.finish_quantum_mix(blob.epoch, &blob.confirm) {
        Some(epoch) => tracing::info!(
            peer = %peer_fp,
            epoch,
            "quantum mix complete — epoch advanced on quantum entropy"
        ),
        None => tracing::warn!(
            peer = %peer_fp,
            "quantum mix answer did not confirm the derivation — epoch unchanged"
        ),
    }
    true
}

pub(crate) async fn send_frame_to_peer(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    frame: Vec<u8>,
) {
    match fallback.and_then(|f| f.path(peer_fp)) {
        Some(FallbackPath::MeshRelay {
            relay_fp,
            relay_addr,
        }) => {
            let _ =
                send_datagram_via_relay(nc, sock, &relay_fp, &relay_addr, peer_fp, &frame).await;
        }
        Some(FallbackPath::Turn { peer_relayed }) => match fallback.and_then(|f| f.turn()) {
            Some(t) => t.send_sealed(peer_relayed, frame),
            None => tracing::warn!(
                peer = %peer_fp,
                "ratchet PDU: TURN route with no allocation — dropped"
            ),
        },
        Some(FallbackPath::Skywave { nvis_freq_khz }) => {
            tracing::debug!(
                peer = %peer_fp,
                freq_khz = nvis_freq_khz,
                "ratchet PDU: routing across Skywave NVIS carrier"
            );
            if let Some(bridge) = net::sdr_bridge::SkywaveBridge::global() {
                if let Err(e) = bridge.transmit(&frame).await {
                    tracing::warn!(
                        peer = %peer_fp,
                        error = %e,
                        "ratchet PDU: skywave transmit failed — frame dropped"
                    );
                }
            } else {
                tracing::warn!(peer = %peer_fp, "ratchet PDU: skywave route with no bridge — frame dropped");
            }
        }
        Some(FallbackPath::Masque { peer }) => {
            if !super::try_send_masque(&peer, &frame) {
                let _ = super::srtp::send_raw(sock, src, &frame).await;
            }
        }
        Some(FallbackPath::Direct) | None => {
            let _ = super::srtp::send_raw(sock, src, &frame).await;
        }
    }
}

#[cfg(test)]
mod ratchet_live_tests {
    //! The ratchet end to end: two nodes, two real sockets, the real maintenance
    //! tick, the real ingress (`RxContext::ingest`) and the real handler
    //! (`handle_pkt`) — the epoch is observed to change on a *live* session.
    //!
    //! Why this exists at all, and why the other tests were not enough: they called
    //! `handle_pkt` or the session API directly, so nothing ever exercised the path a
    //! *datagram* takes between the socket and the handler. That path carried a
    //! `#[cfg(feature = "vpn")]` on its self-contained-frame bypass, so the step PDU
    //! was delivered under `--features vpn` and silently swallowed by the shard spool
    //! in a default build — where a single frame is one shard of three and never
    //! assembles. Both were "the ratchet works"; one of them was false, and only a
    //! test that drives a datagram in can tell them apart.
    //!
    //! The same harness (a real node, real sockets, the real ingress) also carries
    //! the spool-isolation regression: two peers handshaking at once, fed in
    //! interleaved shard by shard.
    use crate::*;
    use std::time::Instant as StdInstant;
    use vantablack::ghost::net::is_v2_frame;
    use vantablack::ghost::session::ratchet::RATCHET_INTERVAL;

    pub(crate) async fn node(id: Arc<l0_identity::GhostIdentity>) -> Arc<GhostNode> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
        let local_addr = socket.local_addr().expect("local addr").to_string();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        Arc::new(GhostNode {
            identity: id,
            sessions: Arc::new(DashMap::new()),
            socket,
            contact_plan: tokio::sync::RwLock::new(ContactPlan::default()),
            created_at: StdInstant::now(),
            local_addr,
            flow_controller: Arc::new(net::FlowController::new(100)),
            stats: Arc::new(net::ThroughputStats::new()),
            running: std::sync::atomic::AtomicBool::new(true),
            workers: vec![tx],
            worker_idx: std::sync::atomic::AtomicUsize::new(0),
            beacon_enabled: std::sync::atomic::AtomicBool::new(false),
            keepalive_interval_secs: std::sync::atomic::AtomicU64::new(120),
        })
    }

    pub(crate) fn rx_for(
        node: &Arc<GhostNode>,
        peers: Arc<DashMap<String, SocketAddr>>,
        fallback: Arc<Fallback>,
    ) -> Arc<RxContext> {
        let reputation = Arc::new(PoissonReputationMatrix::new());
        Arc::new(RxContext {
            node: Arc::clone(node),
            peers,
            spool: Arc::new(DashMap::new()),
            pending_hs: Arc::new(DashMap::new()),
            revocation_list: Arc::new(RevocationList::new()),
            reputation: Arc::clone(&reputation),
            vpn: None,
            exit_tunnels: Arc::new(DashMap::new()),
            sessions_rx: Arc::new(DashMap::new()),
            rx_state_map: Arc::new(DashMap::new()),
            connect_acks: Arc::new(DashMap::new()),
            connect_ok_ctrs: Arc::new(DashMap::new()),
            trusted_exits: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
            psk: None,
            tft: Arc::new(TitForTatEnforcer::new(
                node.fingerprint(),
                Arc::clone(&reputation),
            )),
            rotator: None,
            relay_role: None,
            fallback: Some(fallback),
            dispatcher: Arc::new(net::dispatcher::LocklessDispatcher::new(1, 256)),
            socket: Arc::clone(&node.socket),
            connected: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            nat_puncher: None,
            known_descriptors: None,
        })
    }

    pub(crate) async fn recv_one(sock: &UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; GTF_BULK_SIZE + 64];
        let (amt, _src) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("a datagram should have arrived")
            .expect("recv_from");
        buf.truncate(amt);
        buf
    }

    pub(crate) async fn wait_for(label: &str, mut cond: impl FnMut() -> bool) {
        let deadline = StdInstant::now() + Duration::from_secs(5);
        while StdInstant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {label}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    pub(crate) async fn a_live_session_rotates_its_epoch_through_the_real_receive_path() {
        let alice_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let bob_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let alice = node(Arc::clone(&alice_id)).await;
        let bob = node(Arc::clone(&bob_id)).await;
        let alice_addr = alice.socket.local_addr().expect("alice addr");
        let bob_addr = bob.socket.local_addr().expect("bob addr");
        let alice_fp = alice_id.fingerprint();
        let bob_fp = bob_id.fingerprint();
        assert_ne!(alice_addr, bob_addr);

        let master = [0x5Au8; 32];
        let a_sess = Session::new_with_role(master, bob_fp.clone(), SessionRole::Initiator);
        a_sess.pin_peer_identity(bob_id.public_key_bytes());
        let b_sess = Session::new_with_role(master, alice_fp.clone(), SessionRole::Responder);
        b_sess.pin_peer_identity(alice_id.public_key_bytes());
        let a_hash = a_sess.session_hash;
        alice.sessions.insert(bob_fp.clone(), a_sess);
        bob.sessions.insert(alice_fp.clone(), b_sess);
        assert_eq!(
            a_hash,
            bob.sessions.get(&alice_fp).unwrap().session_hash,
            "both seats derive one session"
        );

        let alice_addrs = Arc::new(DashMap::new());
        alice_addrs.insert(bob_fp.clone(), bob_addr);
        let bob_addrs = Arc::new(DashMap::new());
        bob_addrs.insert(alice_fp.clone(), alice_addr);
        let alice_fb = Arc::new(Fallback::new(None));
        let alice_rx = rx_for(&alice, Arc::clone(&alice_addrs), Arc::clone(&alice_fb));
        let bob_rx = rx_for(&bob, Arc::clone(&bob_addrs), Arc::new(Fallback::new(None)));

        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            for _ in 0..RATCHET_INTERVAL {
                s.note_sealed_frame();
            }
            assert!(s.ratchet_due(), "a spent epoch owes a step");
            assert_eq!(s.epoch(), 0);
        }

        ratchet_maintenance_once(&alice, &alice_addrs, &alice_fb).await;
        let step_frame = recv_one(&bob.socket).await;
        assert!(is_v2_frame(&step_frame), "the step is a v2 frame");
        assert_ne!(
            net::parse_flags(&step_frame) & net::FLAG_TUNNEL,
            0,
            "and a self-contained one: the ingress must not spool it"
        );
        assert_eq!(
            net::parse_gtf_v2_header(&step_frame)
                .expect("v2 header")
                .epoch,
            0,
            "the step travels on the epoch that is still live"
        );

        bob_rx.ingest(&step_frame, alice_addr).await; // src = alice, as recv_from reports
        wait_for("bob to prepare epoch 1", || {
            bob.sessions.get(&alice_fp).map(|s| s.prepared_epoch()) == Some(Some(1))
        })
        .await;
        {
            let s = bob.sessions.get(&alice_fp).expect("bob's session");
            assert_eq!(
                s.epoch(),
                0,
                "answering prepares the epoch, it does not install it"
            );
            assert_eq!(s.ratchet_steps.load(Ordering::Relaxed), 0);
        }

        let answer_frame = recv_one(&alice.socket).await;
        alice_rx.ingest(&answer_frame, bob_addr).await;
        wait_for("alice's epoch to rotate", || {
            alice.sessions.get(&bob_fp).map(|s| s.epoch()) == Some(1)
        })
        .await;
        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            assert_eq!(s.ratchet_steps.load(Ordering::Relaxed), 1);
            assert!(
                !s.ratchet_in_progress.load(Ordering::Relaxed),
                "a completed step leaves nothing in flight"
            );
            assert_eq!(s.epoch_capacity_left(), RATCHET_INTERVAL, "a fresh epoch");
        }

        let (ctx, shards, tag) = {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            let ctx = SealCtx::from_session(&s);
            assert_eq!(ctx.epoch, 1, "the data path seals on the new epoch");
            let (shards, tag) = enc_split(&ctx, b"epoch one");
            (ctx, shards, tag)
        };
        send3_mixed(Arc::clone(&alice.socket), &bob_addr, &ctx, &shards, &tag).await;
        for _ in 0..3 {
            let f = recv_one(&bob.socket).await;
            assert_eq!(
                net::parse_flags(&f) & net::FLAG_TUNNEL,
                0,
                "a data frame is a shard, not a whole message"
            );
            bob_rx.ingest(&f, alice_addr).await;
        }
        wait_for("bob to install epoch 1", || {
            bob.sessions.get(&alice_fp).map(|s| s.epoch()) == Some(1)
        })
        .await;

        let a = alice.sessions.get(&bob_fp).expect("alice's session");
        let b = bob.sessions.get(&alice_fp).expect("bob's session");
        assert_eq!(a.epoch(), b.epoch());
        assert_eq!(a.ratchet_steps.load(Ordering::Relaxed), 1);
        assert_eq!(b.ratchet_steps.load(Ordering::Relaxed), 1);
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 1)
                .expect("bob holds epoch 1"),
            "alice seals epoch 1 with the key bob opens it under"
        );
        assert_eq!(
            b.seal_key(NonceDirection::ResponderToInitiator),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .expect("alice holds epoch 1"),
            "and bob's sending key is the one alice opens"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    pub(crate) async fn a_step_that_cannot_be_verified_never_moves_the_epoch() {
        let alice_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let bob_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let alice = node(Arc::clone(&alice_id)).await;
        let bob = node(Arc::clone(&bob_id)).await;
        let alice_addr = alice.socket.local_addr().expect("alice addr");
        let bob_addr = bob.socket.local_addr().expect("bob addr");
        let alice_fp = alice_id.fingerprint();
        let bob_fp = bob_id.fingerprint();

        let master = [0x11u8; 32];
        let a_sess = Session::new_with_role(master, bob_fp.clone(), SessionRole::Initiator);
        a_sess.pin_peer_identity(bob_id.public_key_bytes());
        let b_sess = Session::new_with_role(master, alice_fp.clone(), SessionRole::Responder);
        alice.sessions.insert(bob_fp.clone(), a_sess);
        bob.sessions.insert(alice_fp.clone(), b_sess);

        let alice_addrs = Arc::new(DashMap::new());
        alice_addrs.insert(bob_fp.clone(), bob_addr);
        let alice_fb = Arc::new(Fallback::new(None));
        let alice_rx = rx_for(&alice, Arc::clone(&alice_addrs), Arc::clone(&alice_fb));
        let bob_rx = rx_for(
            &bob,
            Arc::new(DashMap::new()),
            Arc::new(Fallback::new(None)),
        );
        let _ = &alice_rx;

        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            for _ in 0..RATCHET_INTERVAL {
                s.note_sealed_frame();
            }
        }
        ratchet_maintenance_once(&alice, &alice_addrs, &alice_fb).await;
        let step_frame = recv_one(&bob.socket).await;
        bob_rx.ingest(&step_frame, alice_addr).await;

        tokio::time::sleep(Duration::from_millis(200)).await;
        let b = bob.sessions.get(&alice_fp).expect("bob's session");
        assert_eq!(b.epoch(), 0, "an unverifiable step must not move the epoch");
        assert_eq!(b.prepared_epoch(), None, "nor prepare one");
        assert!(alice
            .sessions
            .get(&bob_fp)
            .expect("alice's session")
            .ratchet_in_progress
            .load(Ordering::Relaxed));
    }

    pub(crate) fn negotiated_offer_frames(id: &l0_identity::GhostIdentity) -> Vec<Vec<u8>> {
        let (_xs, xp) = generate_x25519_keypair();
        let (kp512, _ks512) = generate_kyber_keypair();
        let (kp768, _ks768) = generate_kyber768_keypair();
        let supported = vec![
            HybridCipherSuite::X25519MlKem768V3,
            HybridCipherSuite::X25519MlKem512V2,
        ];
        let keys = vec![
            (
                HybridCipherSuite::X25519MlKem768V3,
                kp768.to_bytes().to_vec(),
            ),
            (
                HybridCipherSuite::X25519MlKem512V2,
                kp512.to_bytes().to_vec(),
            ),
        ];
        let pdu = build_negotiated_handshake_pdu(
            &supported,
            &id.public_key_bytes(),
            &id.pq_commitment(),
            |d| id.sign(d).to_bytes(),
            &xp,
            &keys,
        )
        .expect("valid suite-list handshake");
        let mut encoded = pdu;
        let raw = l4_rs::encode(&mut encoded);
        let tag = [0u8; 16];
        let is_bulk = raw
            .iter()
            .any(|s| frame_shard(s).len() > vantablack::ghost::net::MAX_PAYLOAD_LEN);
        raw.iter()
            .enumerate()
            .map(|(i, shard)| {
                net::build_gtf_frame([0, 0, 0, 0], 0, i as u8, &frame_shard(shard), &tag, is_bulk)
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    pub(crate) async fn interleaved_handshakes_from_two_peers_each_get_their_own_session() {
        let alice_id = l0_identity::GhostIdentity::generate_fresh();
        let bob_id = l0_identity::GhostIdentity::generate_fresh();
        let ours = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let node = node(Arc::clone(&ours)).await;
        let alice_fp = alice_id.fingerprint();
        let bob_fp = bob_id.fingerprint();
        assert_ne!(alice_fp, bob_fp);

        let rx = rx_for(
            &node,
            Arc::new(DashMap::new()),
            Arc::new(Fallback::new(None)),
        );
        let alice_from: SocketAddr = "127.0.0.1:41001".parse().expect("addr");
        let bob_from: SocketAddr = "127.0.0.1:41002".parse().expect("addr");

        let alice_frames = negotiated_offer_frames(&alice_id);
        let bob_frames = negotiated_offer_frames(&bob_id);
        assert_eq!(alice_frames.len(), 3);
        assert_eq!(bob_frames.len(), 3);
        for (i, frame) in alice_frames.iter().enumerate() {
            assert_eq!(net::parse_packet_counter_u64(frame), 0);
            assert_eq!(net::parse_session_hash(frame), [0, 0, 0, 0]);
            assert_eq!(frame[net::OFFSET_SHARD_INDEX] as usize, i);
        }

        for i in 0..3 {
            rx.ingest(&alice_frames[i], alice_from).await;
            rx.ingest(&bob_frames[i], bob_from).await;
        }

        wait_for("both handshakes to establish a session", || {
            node.sessions.len() == 2
        })
        .await;
        assert!(
            node.sessions.contains_key(&alice_fp),
            "interleaving must not steal alice's handshake"
        );
        assert!(
            node.sessions.contains_key(&bob_fp),
            "interleaving must not steal bob's handshake"
        );
    }
}

#[cfg(test)]
mod ratchet_transport_tests {
    //! The ratchet's *transport* — the half that turns a complete-and-tested step
    //! API into an epoch that a live session actually rotates.
    //!
    //! These tests deliberately re-run the byte path the two call sites use: the
    //! maintenance tick's `begin_ratchet_step` → `build_ratchet_step_pdu` →
    //! `seal_single`, and the receive path's open → `frame_payload` →
    //! `parse_rekey_pdu` → signature check → `answer_ratchet_step`. Driving the
    //! sessions directly would have passed while the PDU framing was wrong, which
    //! is exactly the class of bug a "no transport" gap hides.
    use crate::*;
    use vantablack::ghost::net::{extract_payload, is_v2_frame, parse_gtf_v2_header};
    use vantablack::ghost::session::ratchet::RATCHET_INTERVAL;

    pub(crate) fn session_pair() -> (
        Session,
        Session,
        l0_identity::GhostIdentity,
        l0_identity::GhostIdentity,
    ) {
        let alice_id = l0_identity::GhostIdentity::generate_fresh();
        let bob_id = l0_identity::GhostIdentity::generate_fresh();
        let master = [0x5Au8; 32];
        let alice = Session::new_with_role(master, bob_id.fingerprint(), SessionRole::Initiator);
        let bob = Session::new_with_role(master, alice_id.fingerprint(), SessionRole::Responder);
        alice.pin_peer_identity(bob_id.public_key_bytes());
        bob.pin_peer_identity(alice_id.public_key_bytes());
        (alice, bob, alice_id, bob_id)
    }

    pub(crate) fn spend_the_epoch(s: &Session) {
        for _ in 0..RATCHET_INTERVAL {
            s.note_sealed_frame();
        }
        assert!(s.ratchet_due(), "a full epoch owes a step");
        assert_eq!(s.epoch_capacity_left(), 0);
    }

    pub(crate) fn open_like_the_receive_path(
        opener: &Session,
        frame: &[u8],
        direction: NonceDirection,
    ) -> Vec<u8> {
        let h = parse_gtf_v2_header(frame).expect("a v2 header");
        let plan = opener.plan_open(h.epoch, direction, h.counter);
        let key = match plan {
            vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => key,
            vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => key,
            _ => panic!("plan failed for counter {}", h.counter),
        };
        let mut carried = unframe(extract_payload(frame)).expect("a framed shard");
        let opened = xchacha_open(&key, &h.nonce, h.epoch, direction, &mut carried)
            .expect("the epoch key opens it");
        opener.commit_open(h.epoch, direction, plan);
        frame_payload(opened).expect("a framed payload").to_vec()
    }

    #[test]
    pub(crate) fn a_full_epoch_makes_a_live_session_rotate_its_epoch() {
        let (alice, bob, alice_id, bob_id) = session_pair();
        assert_eq!(alice.epoch(), 0);
        spend_the_epoch(&alice);

        let (x_pub, kem_pub) = alice
            .begin_ratchet_step()
            .expect("a due session starts a step");
        assert!(
            alice.begin_ratchet_step().is_none(),
            "and does not start a second one while the first is in flight"
        );
        let pdu = build_ratchet_step_pdu(|d| alice_id.sign(d).to_bytes(), &x_pub, &kem_pub)
            .expect("our own ephemeral material round-trips");
        assert!(
            pdu.len() > 458,
            "a step PDU exceeds a privacy payload, so it needs a bulk frame"
        );
        let ctx = SealCtx::from_session(&alice);
        assert_eq!(
            ctx.epoch, 0,
            "the step itself still travels on the live epoch"
        );
        let frame = seal_single(&ctx, &pdu);
        assert!(is_v2_frame(&frame));
        assert_eq!(frame.len(), GTF_BULK_SIZE);

        let payload =
            open_like_the_receive_path(&bob, &frame, NonceDirection::InitiatorToResponder);
        let blob = parse_rekey_pdu(&payload).expect("a step PDU");
        assert!(
            l0_identity::verify_peer_signature(
                &alice_id.public_key_bytes(),
                &rekey_init_signed_material(&blob.x25519_pub, &blob.kyber_pub),
                &blob.signature,
            ),
            "the PDU is signed by the identity the session pinned"
        );
        assert_eq!(blob.x25519_pub, x_pub);
        assert_eq!(blob.kyber_pub.as_slice(), kem_pub.as_slice());

        let answer = bob
            .answer_ratchet_step(&blob.x25519_pub, &blob.kyber_pub)
            .expect("the peer answers");
        assert_eq!(
            bob.epoch(),
            0,
            "answering prepares the epoch, it does not install it"
        );
        assert_eq!(bob.prepared_epoch(), Some(1));
        let reply = build_rekey_response_pdu(
            |d| bob_id.sign(d).to_bytes(),
            &answer.x_public,
            &answer.kem_ct,
            &answer.confirm,
        );
        let rblob_raw = parse_rekey_response_pdu(&reply).expect("a well-formed answer");
        assert!(
            l0_identity::verify_peer_signature(
                &bob_id.public_key_bytes(),
                &rekey_answer_signed_material(
                    &rblob_raw.x25519_pub,
                    &rblob_raw.kyber_ct,
                    &rblob_raw.confirm,
                ),
                &rblob_raw.signature,
            ),
            "the answer is signed by the responder's pinned identity"
        );

        let reply_ctx = SealCtx::from_session(&bob);
        assert_eq!(reply_ctx.epoch, 0);
        let reply_frame = seal_single(&reply_ctx, &reply);

        let reply_payload =
            open_like_the_receive_path(&alice, &reply_frame, NonceDirection::ResponderToInitiator);
        let rblob = parse_rekey_response_pdu(&reply_payload).expect("a step answer");
        assert_eq!(
            alice.finish_ratchet_step(&RatchetAnswer {
                x_public: rblob.x25519_pub,
                kem_ct: rblob.kyber_ct,
                confirm: rblob.confirm,
                epoch: alice.epoch() + 1,
            }),
            Some(1),
            "the answer confirms the step and the epoch moves"
        );
        assert_eq!(alice.epoch(), 1);
        assert!(
            !alice.ratchet_in_progress.load(Ordering::Relaxed),
            "a completed step leaves nothing in flight"
        );

        assert!(bob.activate_epoch(1));
        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(
            alice.seal_key(NonceDirection::InitiatorToResponder),
            bob.open_key(1, NonceDirection::InitiatorToResponder, 0)
                .expect("epoch 1 key"),
            "one round trip, one epoch, one key"
        );
    }

    #[test]
    pub(crate) fn a_step_pdu_that_does_not_verify_never_moves_the_epoch() {
        let (alice, bob, _alice_id, _bob_id) = session_pair();
        let impostor = l0_identity::GhostIdentity::generate_fresh();
        spend_the_epoch(&alice);
        let (x_pub, kem_pub) = alice.begin_ratchet_step().unwrap();
        let pdu = build_ratchet_step_pdu(|d| impostor.sign(d).to_bytes(), &x_pub, &kem_pub)
            .expect("a well-formed PDU from the wrong signer");
        let frame = seal_single(&SealCtx::from_session(&alice), &pdu);
        let payload =
            open_like_the_receive_path(&bob, &frame, NonceDirection::InitiatorToResponder);
        let blob = parse_rekey_pdu(&payload).expect("well-formed on the wire");

        let pinned = bob.peer_identity_pk().expect("the handshake pinned alice");
        assert!(
            !l0_identity::verify_peer_signature(
                &pinned,
                &rekey_init_signed_material(&blob.x25519_pub, &blob.kyber_pub),
                &blob.signature,
            ),
            "the impostor's signature must not verify against the pinned key"
        );
        assert_eq!(bob.epoch(), 0);
        assert_eq!(
            bob.prepared_epoch(),
            None,
            "nothing was prepared for an unauthenticated step"
        );
    }
}

#[cfg(test)]
mod l10_quantum_mix_transport_tests {
    //! The L10 quantum-anchor mix over the byte path a *live* session uses.
    //!
    //! The session API and the ratchet's derivation are unit-tested next to their
    //! definitions; what those cannot catch is the wiring — the PDU magics, the
    //! two signature materials, the direction each half seals in, and the epoch
    //! both sides end on. So these tests re-run the maintenance tick's body and
    //! the receive path's body, byte for byte, exactly as
    //! `ratchet_transport_tests` does for the DH step.
    use crate::*;
    use vantablack::ghost::net::{extract_payload, is_v2_frame, parse_gtf_v2_header};
    use vantablack::ghost::session::ratchet::OpenPlan;

    const QUANTUM_KEY: [u8; 32] = [0x11; 32];
    const KEY_LABEL: &str = "qkd-sim/1/f=3fedc00000000000/s=00000000000051ee";

    pub(crate) struct Pair {
        pub(crate) starter: Session,
        pub(crate) answerer: Session,
        pub(crate) starter_id: l0_identity::GhostIdentity,
        pub(crate) answerer_id: l0_identity::GhostIdentity,
    }

    pub(crate) fn pair_with_starter_role(starter_role: SessionRole) -> Pair {
        let a_id = l0_identity::GhostIdentity::generate_fresh();
        let b_id = l0_identity::GhostIdentity::generate_fresh();
        let master = [0x5Au8; 32];
        let (starter, answerer) = match starter_role {
            SessionRole::Initiator => (
                Session::new_with_role(master, b_id.fingerprint(), SessionRole::Initiator),
                Session::new_with_role(master, a_id.fingerprint(), SessionRole::Responder),
            ),
            SessionRole::Responder => (
                Session::new_with_role(master, b_id.fingerprint(), SessionRole::Responder),
                Session::new_with_role(master, a_id.fingerprint(), SessionRole::Initiator),
            ),
        };
        starter.pin_peer_identity(b_id.public_key_bytes());
        answerer.pin_peer_identity(a_id.public_key_bytes());
        Pair {
            starter,
            answerer,
            starter_id: a_id,
            answerer_id: b_id,
        }
    }

    pub(crate) fn open_like_the_receive_path(
        opener: &Session,
        frame: &[u8],
        direction: NonceDirection,
    ) -> Vec<u8> {
        let h = parse_gtf_v2_header(frame).expect("a v2 header");
        let (key, plan) = match opener.plan_open(h.epoch, direction, h.counter) {
            OpenPlan::Forward {
                key,
                new_chain,
                new_pos,
                cache,
            } => (
                key,
                OpenPlan::Forward {
                    key,
                    new_chain,
                    new_pos,
                    cache,
                },
            ),
            OpenPlan::Cached { counter, key } => (key, OpenPlan::Cached { counter, key }),
            OpenPlan::Refused => panic!("plan failed for counter {}", h.counter),
        };
        let mut carried = unframe(extract_payload(frame)).expect("a framed shard");
        let opened = xchacha_open(&key, &h.nonce, h.epoch, direction, &mut carried)
            .expect("the epoch key opens it");
        opener.commit_open(h.epoch, direction, plan);
        frame_payload(opened).expect("a framed payload").to_vec()
    }

    pub(crate) fn run_mix(pair: &Pair) {
        let starter_dir = pair.starter.seal_direction();

        let pending = pair
            .starter
            .begin_quantum_mix(&QUANTUM_KEY, KEY_LABEL)
            .expect("a due session starts a mix");
        assert_eq!(pending.epoch, 1, "the mix prepares the next epoch");
        assert!(
            pair.starter
                .begin_quantum_mix(&QUANTUM_KEY, KEY_LABEL)
                .is_none(),
            "and does not start a second one while the first is in flight"
        );
        let pdu = build_qel_mix_pdu(
            |d| pair.starter_id.sign(d).to_bytes(),
            pending.epoch,
            &pending.label,
            &pending.confirm,
        );
        assert_eq!(
            pdu.len(),
            vantablack::ghost::session::QEL_MIX_BLOB_LEN,
            "the mix PDU is a privacy-frame payload"
        );
        let ctx = SealCtx::from_session(&pair.starter);
        assert_eq!(ctx.epoch, 0);
        assert_eq!(ctx.direction, starter_dir);
        let frame = seal_single(&ctx, &pdu);
        assert!(is_v2_frame(&frame));

        let payload = open_like_the_receive_path(&pair.answerer, &frame, starter_dir);
        let blob = parse_qel_mix_pdu(&payload).expect("a mix PDU");
        assert_eq!(blob.epoch, 1);
        assert_eq!(
            blob.label, KEY_LABEL,
            "the label names the key, and nothing else about it travels"
        );
        assert!(
            !payload.windows(QUANTUM_KEY.len()).any(|w| w == QUANTUM_KEY),
            "the key material itself must not appear anywhere in the PDU"
        );
        assert!(
            l0_identity::verify_peer_signature(
                &pair.starter_id.public_key_bytes(),
                &qel_mix_signed_material(blob.epoch, &blob.label, &blob.confirm),
                &blob.signature,
            ),
            "the PDU is signed by the identity the session pinned"
        );
        let tag = pair
            .answerer
            .answer_quantum_mix(&QUANTUM_KEY, blob.epoch, &blob.confirm, &blob.label)
            .expect("the peer answers");
        assert_eq!(
            tag, blob.confirm,
            "the answer carries the tag both sides derived — that equality is the proof of agreement"
        );
        assert_eq!(
            pair.answerer.epoch(),
            0,
            "answering prepares the epoch, it does not install it"
        );
        assert_eq!(pair.answerer.prepared_epoch(), Some(1));
        assert!(!pair.answerer.quantum_mixed());

        let reply =
            build_qel_mix_response_pdu(|d| pair.answerer_id.sign(d).to_bytes(), blob.epoch, &tag);
        let rblob_raw = parse_qel_mix_response_pdu(&reply).expect("a well-formed answer");
        assert!(
            l0_identity::verify_peer_signature(
                &pair.answerer_id.public_key_bytes(),
                &qel_mix_response_signed_material(rblob_raw.epoch, &rblob_raw.confirm),
                &rblob_raw.signature,
            ),
            "the answer is signed by the answering peer's pinned identity"
        );
        let answerer_dir = pair.answerer.seal_direction();
        let reply_frame = seal_single(&SealCtx::from_session(&pair.answerer), &reply);

        let reply_payload = open_like_the_receive_path(&pair.starter, &reply_frame, answerer_dir);
        let rblob = parse_qel_mix_response_pdu(&reply_payload).expect("a mix answer");
        assert_eq!(
            pair.starter.finish_quantum_mix(rblob.epoch, &rblob.confirm),
            Some(1),
            "the answer confirms the derivation and the epoch moves"
        );
        assert_eq!(pair.starter.epoch(), 1);
        assert!(pair.starter.quantum_mixed());
        assert!(
            !pair.starter.quantum_mix_in_progress(),
            "a completed mix leaves nothing in flight"
        );
        assert!(!pair.starter.quantum_mix_due(Duration::ZERO));

        assert!(pair.answerer.activate_epoch(1));
        assert!(pair.answerer.quantum_mixed());
        assert_eq!(pair.starter.epoch(), pair.answerer.epoch());
        assert_eq!(
            pair.starter.seal_key(starter_dir),
            pair.answerer
                .open_key(1, starter_dir, 0)
                .expect("epoch 1 key"),
            "one round trip, one epoch, one key — and it came from the quantum channel"
        );
    }

    #[test]
    pub(crate) fn a_quantum_mix_advances_both_sides_to_one_epoch() {
        run_mix(&pair_with_starter_role(SessionRole::Initiator));
    }

    #[test]
    pub(crate) fn the_responder_can_be_the_one_that_starts_the_mix() {
        run_mix(&pair_with_starter_role(SessionRole::Responder));
    }

    #[test]
    pub(crate) fn divergent_quantum_keys_refuse_the_mix_and_move_nothing() {
        let pair = pair_with_starter_role(SessionRole::Initiator);
        let pending = pair
            .starter
            .begin_quantum_mix(&QUANTUM_KEY, KEY_LABEL)
            .unwrap();
        let pdu = build_qel_mix_pdu(
            |d| pair.starter_id.sign(d).to_bytes(),
            pending.epoch,
            &pending.label,
            &pending.confirm,
        );
        let frame = seal_single(&SealCtx::from_session(&pair.starter), &pdu);
        let blob = parse_qel_mix_pdu(&open_like_the_receive_path(
            &pair.answerer,
            &frame,
            NonceDirection::InitiatorToResponder,
        ))
        .expect("a mix PDU");

        let other_key = [0x22u8; 32];
        assert!(
            pair.answerer
                .answer_quantum_mix(&other_key, blob.epoch, &blob.confirm, &blob.label)
                .is_none(),
            "a different key must not reproduce the starter's tag"
        );
        assert_eq!(pair.answerer.epoch(), 0, "no epoch moved");
        assert_eq!(
            pair.answerer.prepared_epoch(),
            None,
            "and nothing was prepared — the refusal happens before the epoch slot is taken"
        );
        assert!(pair.starter.quantum_mix_in_progress());
        assert_eq!(pair.starter.epoch(), 0);
    }

    #[test]
    pub(crate) fn a_mix_pdu_signed_by_a_stranger_never_reaches_the_derivation() {
        let pair = pair_with_starter_role(SessionRole::Initiator);
        let impostor = l0_identity::GhostIdentity::generate_fresh();
        let pending = pair
            .starter
            .begin_quantum_mix(&QUANTUM_KEY, KEY_LABEL)
            .unwrap();
        let pdu = build_qel_mix_pdu(
            |d| impostor.sign(d).to_bytes(),
            pending.epoch,
            &pending.label,
            &pending.confirm,
        );
        let frame = seal_single(&SealCtx::from_session(&pair.starter), &pdu);
        let blob = parse_qel_mix_pdu(&open_like_the_receive_path(
            &pair.answerer,
            &frame,
            NonceDirection::InitiatorToResponder,
        ))
        .expect("well-formed on the wire");

        let pinned = pair
            .answerer
            .peer_identity_pk()
            .expect("the handshake pinned the starter");
        assert!(
            !l0_identity::verify_peer_signature(
                &pinned,
                &qel_mix_signed_material(blob.epoch, &blob.label, &blob.confirm),
                &blob.signature,
            ),
            "the impostor's signature must not verify against the pinned key"
        );
        assert_eq!(pair.answerer.epoch(), 0);
        assert_eq!(pair.answerer.prepared_epoch(), None);
    }
}
