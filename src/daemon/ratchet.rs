//! daemon::ratchet — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

/// How often the maintenance tick looks for sessions whose epoch is spent.
pub(crate) const RATCHET_TICK: Duration = Duration::from_secs(5);
/// How long one unanswered step may sit before it is abandoned and retried.
///
/// A step that is never answered costs a PDU and a retry — it must not wedge the
/// session at the current epoch forever, which is why the bound exists at all.
pub(crate) const RATCHET_STEP_STALL: Duration = Duration::from_secs(30);

/// How long one unanswered quantum mix may sit before it is abandoned.
///
/// Much longer than a DH step's bound, because the round trip is not symmetric:
/// the answering peer only has to fetch key material at a label, but the peer
/// that *starts* a mix first derives a route, which is a python subprocess. An
/// abandoned mix costs the epoch nothing — the live generation was never
/// touched — so the only thing this bound buys is against a session that would
/// otherwise hold the prepared-epoch slot forever.
pub(crate) const QUANTUM_MIX_STALL: Duration = Duration::from_secs(90);

/// How often one session may *try* to start a quantum mix.
///
/// Each attempt can spawn a python subprocess (seconds), so a peer whose route
/// never resolves — a mesh that has not been exported, or a link below the BB84
/// cutoff — must not be retried on every five-second tick. One attempt a minute
/// is enough for an anchor that becomes available later, and cheap enough that a
/// permanently unavailable one is unnoticeable.
pub(crate) const QUANTUM_MIX_RETRY: Duration = Duration::from_secs(60);

/// One pass of the ratchet maintenance tick.
///
/// This is what makes the ratchet real rather than dormant: an epoch holds at most
/// `RATCHET_INTERVAL` datagrams, and when one is spent the session pays for a fresh
/// hybrid exchange. The step is *started* here and *completed* in `handle_pkt` when
/// the peer's signed answer arrives — or, on the answering side, when the
/// initiator's first frame in the new epoch authenticates.
///
/// Nothing stalls on it: traffic keeps flowing on the current epoch until the step
/// lands, and a lost step is abandoned after `RATCHET_STEP_STALL` and retried on the
/// next tick.
///
/// Extracted from the tick loop so the initiation site is callable as a unit — the
/// alternative was a body reachable only by waiting five seconds inside a spawned
/// task, which is how it stayed untested while it was wrong (see the self-contained
/// bit's history in `RxContext::ingest`).
pub(crate) async fn ratchet_maintenance_once(
    nc: &Arc<GhostNode>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    fallback: &Arc<Fallback>,
) {
    // Collect first: a DashMap guard must never be held across an await, and every
    // send below is one.
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
        // Reachability first. A step we cannot deliver would sit in flight for the
        // whole stall window and block the next attempt, so a peer with neither a
        // known address nor a fallback route is skipped rather than charged a
        // round trip.
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
            // Our own freshly generated material failed to parse: a bug, but the
            // step must not be left in flight over it.
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

/// Handle a ratchet-step PDU that arrived (decrypted) in `payload`.
///
/// Returns `true` when the payload *was* a step PDU — including when it was
/// refused — so the caller stops interpreting it as application data.
///
/// Both directions live here because they are two halves of one exchange, and a
/// step that is only half understood is worse than one that is not understood at
/// all: a responder that acts on an unauthenticated step moves its epoch while the
/// initiator does not, which breaks a working session.
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
    // Fail closed. The step is authenticated by the peer's *identity* key, which
    // is the same key the handshake verified; without a pinned key there is
    // nothing to check the step against, so it is refused rather than trusted.
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
        // A *crossed* pair of steps — both peers due in the same interval — is not a
        // harmless duplicate: each side would complete its own step and install epoch
        // `n+1` derived from its own secrets, so both would hold the same epoch number
        // over different keys and nothing on the link would open again. The tie-break
        // is the fingerprint order (see `Session::admit_peer_step`), applied before the
        // step is answered so exactly one side advances.
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
        // Sealed on the epoch the peer still holds — we have only *prepared* the
        // new one, so a reply on it would be unopenable to the sender of the step.
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

/// Where the mesh topology export lives: the operator's override, else the data
/// directory.
///
/// One function so the manual `EXPORTTOPOLOGY` path, the control plane's route
/// endpoint and the mix tick cannot drift onto three different files — they read
/// the same graph, so a route computed for an operator and a route computed for
/// a session are computed over the same thing.
pub(crate) fn qel_topology_path() -> PathBuf {
    std::env::var("GHOST_QEL_TOPOLOGY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| vantablack::ghost::paths::data_file("ghost-topology.json"))
}

/// Serialize the live mesh graph — real fingerprints, addresses and sessions —
/// in the schema `quantumnet ghost-net --topology` reads.
///
/// Returns the pretty JSON plus the node and link counts, so the manual command
/// can report what it wrote without re-parsing its own output.
///
/// Each link carries `length_km` where the daemon has **measured** the path. That
/// field is what makes the export routable at all: the quantum layer derives a
/// link's attenuation from its physical length, and a link with no length is not
/// an optical link, so it is skipped. The daemon has a real length for any peer
/// whose round trip it has timed (the contact plan's `range_km`, from the same
/// measurement the DTN router routes on), and none for a peer it has not — no
/// number is invented to fill the gap, because a fabricated length would decide
/// the fidelity of a link nobody measured.
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

/// One pass of the quantum-anchor mix tick: start a mix for any session that
/// should have one and does not.
///
/// This is what turns the L10 anchor from a tested primitive into a property of a
/// live session. A session begins on its handshake's hybrid root key; this tick
/// re-derives its *next* epoch from quantum-derived entropy as soon as the peer
/// is reachable, so the key that protects later traffic was not solely a
/// function of the classical handshake.
///
/// Three rules decide whether a given session is attempted, and each is
/// deliberate:
///
/// * **The lower-fingerprint peer drives.** Only one side may start a mix, or two
///   would prepare the same epoch from different inputs; the fingerprint order is
///   the tie-break `admit_peer_step` already uses, and it costs no round trip. The
///   other side answers, and needs neither a route nor a topology export to do it.
/// * **Reachability first**, exactly as the ratchet step does: a mix we cannot
///   deliver would hold the prepared-epoch slot for the whole stall window.
/// * **At most one attempt per retry interval**, because an attempt may cost a
///   python subprocess. See `QUANTUM_MIX_RETRY`.
///
/// Nothing here is fatal. Every failure — anchor degraded, no topology export, a
/// route below the BB84 cutoff — leaves the session exactly as it was, on its
/// current epoch, and is retried later.
pub(crate) async fn quantum_mix_maintenance_once(
    nc: &Arc<GhostNode>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    fallback: &Arc<Fallback>,
    ctrl: &Arc<QuantumAnchorController>,
) {
    let our_fp = nc.fingerprint();
    let topology = qel_topology_path();
    // Cheap pre-pass: the tick must not pay for a topology export — let alone a
    // python subprocess — when no session is due. It also settles the stall and
    // the tie-break before any work is queued.
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
        // The peer whose fingerprint sorts higher never starts a mix; it answers
        // ours. Without this the two sides race and cross.
        if e.quantum_mix_due(QUANTUM_MIX_RETRY) && our_fp < peer_fp {
            due.push(peer_fp);
        }
    }
    if due.is_empty() {
        return;
    }

    // Refresh the export before routing: the graph is the thing the route is
    // computed over, and a peer that connected since the last export would be
    // missing from a stale one. Doing it here (rather than requiring the
    // operator to run `EXPORTTOPOLOGY`) is what lets a live session use the
    // anchor unattended; a failure is not fatal, because the route computation
    // below refuses cleanly on a missing or unusable export.
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

    // (peer, addr, PDU) collected first: a DashMap guard must never be held
    // across an await, and deriving a key *is* one.
    let mut work: Vec<(String, SocketAddr, Vec<u8>)> = Vec::new();
    for peer_fp in due {
        let addr = addrs.get(&peer_fp).map(|v| *v.value());
        // Reachability first, as for a DH step: a mix we cannot deliver would
        // hold the prepared-epoch slot for the whole stall window.
        if addr.is_none() && fallback.path(&peer_fp).is_none() {
            continue;
        }
        let addr = addr.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
        let Some(sess) = nc.sessions.get(&peer_fp) else {
            continue;
        };
        // Throttle before the derivation, not after: the point is to bound how
        // often a subprocess can be spawned, including for a failed attempt.
        sess.note_quantum_mix_attempt();
        drop(sess);

        // We already know we sort lower, so the ordered pair is (us, peer) — the
        // same question both sides would ask, which is what makes the label
        // identical for the two of them.
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
            // A DH step or another mix owns the slot. The attempt is already
            // recorded, so this session waits a retry interval rather than
            // spinning on the tick.
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
        // The PDU travels sealed on the *live* epoch: the peer can only open a
        // frame it has a key for, and the new epoch's key is exactly what the
        // exchange is negotiating.
        work.push((peer_fp, addr, seal_single(&ctx, &pdu)));
    }
    for (fp, addr, frame) in work {
        send_frame_to_peer(nc, &nc.socket, &addr, Some(fallback), &fp, frame).await;
    }
}

/// Handle a quantum-mix PDU that arrived (decrypted) in `payload`.
///
/// Returns `true` when the payload *was* a quantum-mix PDU — including when it
/// was refused — so the caller stops interpreting it as application data.
///
/// Deliberately the same shape as [`handle_ratchet_pdu`]: both exchanges send
/// signed parameters, prepare an epoch, and prove agreement with a tag over the
/// new key before either side advances. That symmetry is the point — the two
/// must be read together, because they share one hazard (a peer that advances an
/// epoch its counterpart did not) and one resolution (prove the key first).
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
        // Everything that needs the session, and nothing that awaits, in one
        // scope: a `DashMap` guard held across the key fetch below would block
        // every other task touching this shard — a session insert, an eviction —
        // for as long as a python subprocess takes, which is up to 45 s. The
        // ratchet step's handler gets this for free because it never awaits while
        // holding a session; here the fetch is unavoidable.
        {
            let Some(sess) = node.sessions.get(peer_fp) else {
                tracing::debug!(peer = %peer_fp, "quantum mix PDU for an unknown peer — dropped");
                return true;
            };
            // Fail closed, like the ratchet step: the mix is authenticated by the
            // peer's *identity* key, and a session with no pinned key has nothing
            // to check the parameters against.
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

        // Resolve the label into our copy of the same key. No key crosses the
        // wire: the label is public, and the quantum channel's contribution is
        // what it names — a simulated derivation label, or, on an appliance, the
        // standard's `key_ID` redeemed with `dec_keys`.
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

        // Re-acquire: the peer may have gone while the key was being fetched, and
        // the mix must be answered on the session as it is now, not as it was.
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
        // Sealed on the epoch the peer still holds — we have only *prepared* the
        // new one, so a reply on it would be unopenable to whoever sent the mix.
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

/// Route one already-built GTF datagram to a peer.
///
/// A ratchet step must travel by the same ladder as the data it protects: if the
/// session exists because a relay or a TURN allocation made it possible, a direct
/// reply to the source address would be filtered or unroutable, and the step would
/// silently never complete.
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
    // `PoissonReputationMatrix` and `RevocationList` come in through `super::*`, which
    // is also what guarantees this test wires the pipeline with the same types `main`
    // does rather than with lookalikes.
    use vantablack::ghost::net::is_v2_frame;
    use vantablack::ghost::session::ratchet::RATCHET_INTERVAL;

    /// A real node, built by hand.
    ///
    /// Deliberately not `GhostNode::new`: that loads or **generates** an identity
    /// file in the working directory and spawns four worker tasks, neither of which a
    /// test should be doing to a developer's checkout. Everything else is the real
    /// node type, driving the real code paths.
    pub(crate) async fn node(id: Arc<l0_identity::GhostIdentity>) -> Arc<GhostNode> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
        let local_addr = socket.local_addr().expect("local addr").to_string();
        // `dispatch_packet` indexes `workers`, so there has to be at least one, and a
        // drained channel keeps the dispatcher from filling up mid-test.
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

    /// The receive pipeline for one node, wired the way `main` wires it.
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

    /// Take one datagram off a socket, as the receive loop does.
    pub(crate) async fn recv_one(sock: &UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; GTF_BULK_SIZE + 64];
        let (amt, _src) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("a datagram should have arrived")
            .expect("recv_from");
        buf.truncate(amt);
        buf
    }

    /// `handle_pkt` runs on a spawned task, so effects are waited for rather than
    /// assumed to have landed when `ingest` returns.
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

        // The two seats on one session, exactly as the handshake leaves them: one
        // shared master key, complementary roles, and each peer's identity pinned.
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

        // Address books, so the tick has a route to send the step down.
        let alice_addrs = Arc::new(DashMap::new());
        alice_addrs.insert(bob_fp.clone(), bob_addr);
        let bob_addrs = Arc::new(DashMap::new());
        bob_addrs.insert(alice_fp.clone(), alice_addr);
        let alice_fb = Arc::new(Fallback::new(None));
        let alice_rx = rx_for(&alice, Arc::clone(&alice_addrs), Arc::clone(&alice_fb));
        let bob_rx = rx_for(&bob, Arc::clone(&bob_addrs), Arc::new(Fallback::new(None)));

        // Spend a whole epoch: 1M datagrams is the trigger the interval names.
        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            for _ in 0..RATCHET_INTERVAL {
                s.note_sealed_frame();
            }
            assert!(s.ratchet_due(), "a spent epoch owes a step");
            assert_eq!(s.epoch(), 0);
        }

        // ── The real tick body, one pass, on the real socket ─────────────────────
        ratchet_maintenance_once(&alice, &alice_addrs, &alice_fb).await;
        // The step goes alice → bob, so it is *bob's* socket that has it — reading
        // it from alice's would only prove the send went nowhere.
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

        // ── Into bob's ingress, the way the socket loop feeds it ────────────────
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

        // ── The answer comes back into alice's ingress ──────────────────────────
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

        // ── A data frame in the new epoch makes bob install it ──────────────────
        // Sent exactly the way the data path sends one: sealed once, Reed-Solomon
        // split into three shards *without* the self-contained bit, so this also
        // exercises the spool and the assembled branch of the ingress.
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

        // ── And the two sides agree on the new epoch, one key per direction ─────
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
        // The fail-closed half, through the same ingress: the step is authenticated
        // by the identity pinned at handshake time, so a peer whose pin is absent
        // gets a refusal and nothing else.
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
        // Bob deliberately has **no** pin: the session exists, the identity does not.
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

        // Give it every chance to be acted on before concluding it was not.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let b = bob.sessions.get(&alice_fp).expect("bob's session");
        assert_eq!(b.epoch(), 0, "an unverifiable step must not move the epoch");
        assert_eq!(b.prepared_epoch(), None, "nor prepare one");
        // Bob answered nothing either, so alice is still waiting (and will retry).
        assert!(alice
            .sessions
            .get(&bob_fp)
            .expect("alice's session")
            .ratchet_in_progress
            .load(Ordering::Relaxed));
    }

    /// One negotiated suite-list offer, framed exactly as `initiate_handshake`
    /// sends it: three bulk v1 datagrams that share counter 0 and session hash
    /// `[0, 0, 0, 0]`, because there is no session yet to number the message with.
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

    /// Two peers handshake at once: their shards must not share a bucket.
    ///
    /// This is the regression for the counter-keyed spool. Every handshake is
    /// sent with session hash `[0, 0, 0, 0]` and counter `0`, so under the old
    /// key both offers landed in one `spool[0]` bucket; interleaved arrivals then
    /// reconstructed a single PDU out of two different messages and **neither**
    /// peer got a session. Nothing downstream could see that — every shard was
    /// authentic and the reassembly "succeeded" — so only a test that
    /// deliberately interleaves two real handshakes catches it.
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
        // Two sources with no session yet: the address is what separates the two
        // conversations, because the header bytes are identical.
        let alice_from: SocketAddr = "127.0.0.1:41001".parse().expect("addr");
        let bob_from: SocketAddr = "127.0.0.1:41002".parse().expect("addr");

        let alice_frames = negotiated_offer_frames(&alice_id);
        let bob_frames = negotiated_offer_frames(&bob_id);
        assert_eq!(alice_frames.len(), 3);
        assert_eq!(bob_frames.len(), 3);
        // Both offers really do look identical in the fields the old key used.
        for (i, frame) in alice_frames.iter().enumerate() {
            assert_eq!(net::parse_packet_counter_u64(frame), 0);
            assert_eq!(net::parse_session_hash(frame), [0, 0, 0, 0]);
            assert_eq!(frame[net::OFFSET_SHARD_INDEX] as usize, i);
        }

        // Interleave shard-by-shard: the arrival order that used to interleave
        // two messages into one bucket.
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

    /// A live session pair: real identities, pinned the way the handshake pins
    /// them, and one shared master key — two seats on one session.
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

    /// Spend a whole epoch, which is what makes the tick act.
    pub(crate) fn spend_the_epoch(s: &Session) {
        for _ in 0..RATCHET_INTERVAL {
            s.note_sealed_frame();
        }
        assert!(s.ratchet_due(), "a full epoch owes a step");
        assert_eq!(s.epoch_capacity_left(), 0);
    }

    /// Open a frame the way the receive path does and hand back the payload the
    /// ratchet handler sees.
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

        // ── The maintenance tick's body, line for line ──────────────────────────
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

        // ── The receive path's body ────────────────────────────────────────────
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
        // The material that arrived is the material the session handed out — both
        // halves, so the PQ half of the exchange is bound too.
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

        // The reply is sealed on the epoch the peer still holds — bob has only
        // *prepared* the new one, so a reply on it would be unopenable to alice.
        let reply_ctx = SealCtx::from_session(&bob);
        assert_eq!(reply_ctx.epoch, 0);
        let reply_frame = seal_single(&reply_ctx, &reply);

        // ── Back on the initiating side ────────────────────────────────────────
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

        // The responder installs it only when a frame of the new epoch opens.
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
        // The fail-closed half of the handler: the step is authenticated by the
        // pinned identity key, so a PDU signed by somebody else is refused before
        // `answer_ratchet_step` is ever reached and the epoch stays put.
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

        // What `handle_ratchet_pdu` checks before answering.
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

    /// The 32 bytes the quantum channel produced. Both seats hold the *same* key
    /// and neither sends it: that is the whole point of the exchange, and it is
    /// why every test below can hand both sides one value.
    const QUANTUM_KEY: [u8; 32] = [0x11; 32];
    /// The label the starter's backend gave its key, as the answering side
    /// receives it (in the PDU) rather than as the starter computed it. A label
    /// is opaque to the session layer — this one is the simulated backend's
    /// format, and an appliance would put a key ID here instead.
    const KEY_LABEL: &str = "qkd-sim/1/f=3fedc00000000000/s=00000000000051ee";

    pub(crate) struct Pair {
        pub(crate) starter: Session,
        pub(crate) answerer: Session,
        pub(crate) starter_id: l0_identity::GhostIdentity,
        pub(crate) answerer_id: l0_identity::GhostIdentity,
    }

    /// Two seats on one session with real pinned identities.
    ///
    /// `starter_role` is the *sealing* role of whichever peer begins the mix. The
    /// initiator rule is the fingerprint order, not the role, so the starter can
    /// legitimately be either side — and both orderings must work, because the
    /// epoch's two directional chains are derived from the role.
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

    /// Open a frame the way the receive path does and hand back the payload the
    /// mix handler sees.
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

    /// The half of the exchange both orderings share: the starter's PDU, the
    /// answerer's reply, and the epoch both sides land on.
    pub(crate) fn run_mix(pair: &Pair) {
        let starter_dir = pair.starter.seal_direction();

        // ── The maintenance tick's body, where the anchor is used ──────────────
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
        // The mix itself travels on the *live* epoch: the new epoch's key is
        // exactly what the exchange is negotiating, so neither side could open a
        // frame sealed with it yet.
        let ctx = SealCtx::from_session(&pair.starter);
        assert_eq!(ctx.epoch, 0);
        assert_eq!(ctx.direction, starter_dir);
        let frame = seal_single(&ctx, &pdu);
        assert!(is_v2_frame(&frame));

        // ── The receive path's body, answering side ───────────────────────────
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

        // ── Back on the starting side ─────────────────────────────────────────
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

        // The answering side installs it when a frame of the new epoch opens.
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
        // The initiator rule is the fingerprint order, so either role can drive.
        // This is the case a role-based implementation would get wrong: the
        // starter seals in *its* direction either way, and the answering side has
        // to work out that direction from its own role, not from who spoke first.
        run_mix(&pair_with_starter_role(SessionRole::Responder));
    }

    #[test]
    pub(crate) fn divergent_quantum_keys_refuse_the_mix_and_move_nothing() {
        // The failure the confirmation tag exists for: a route that resolves on
        // one node and not the other, two quantumnet versions, a link that
        // dropped below the cutoff between the two derivations. A side that
        // advanced the epoch anyway would move alone and never open another
        // frame, so this must refuse *before* preparing.
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

        // The label is the *same* one — a correct derivation of the wrong key, as
        // an appliance handing over a key that is not the one the ID names would
        // be, or a peer whose route resolved differently.
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
        // The starter is still waiting, and its own epoch is untouched.
        assert!(pair.starter.quantum_mix_in_progress());
        assert_eq!(pair.starter.epoch(), 0);
    }

    #[test]
    pub(crate) fn a_mix_pdu_signed_by_a_stranger_never_reaches_the_derivation() {
        // The fail-closed half of the handler, as for the DH step: the mix is
        // authenticated by the pinned identity key, so a PDU signed by anyone
        // else is refused before `answer_quantum_mix` is reached.
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
