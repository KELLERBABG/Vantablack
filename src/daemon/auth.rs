//! daemon::auth — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

pub const PQ_AUTH_CHUNK_MAGIC: &[u8; 14] = b"PQ_AUTH_CHUNK:";
pub const PQ_AUTH_ACK_MAGIC: &[u8; 14] = b"PQ_AUTH_ACK__:";
pub const PQ_AUTH_CHUNK_PAYLOAD_SIZE: usize = 500;

/// Transmit this node's 5,358-byte hybrid identity proof in encrypted chunks over the session.
pub(crate) async fn send_pq_auth_proof(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
) {
    let binding = {
        let Some(sess) = nc.sessions.get(peer_fp) else {
            return;
        };
        l0_identity::create_identity_binding(&nc.identity, &sess.master_key)
    };
    let chunks: Vec<&[u8]> = binding.chunks(PQ_AUTH_CHUNK_PAYLOAD_SIZE).collect();
    let total_chunks = chunks.len() as u8;

    for (idx, chunk) in chunks.iter().enumerate() {
        let Some(sess) = nc.sessions.get(peer_fp) else {
            return;
        };
        let ctx = SealCtx::from_session(&sess);
        drop(sess);

        let mut payload = Vec::with_capacity(14 + 1 + 1 + 2 + chunk.len());
        payload.extend_from_slice(PQ_AUTH_CHUNK_MAGIC);
        payload.push(idx as u8);
        payload.push(total_chunks);
        payload.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        payload.extend_from_slice(chunk);

        let frame = seal_single(&ctx, &payload);
        send_frame_to_peer(nc, sock, src, fallback, peer_fp, frame).await;
    }
}

/// Handle incoming chunked PQ authentication control messages.
pub(crate) async fn handle_pq_auth_pdu(
    node: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let is_chunk = payload.starts_with(PQ_AUTH_CHUNK_MAGIC);
    let is_ack = payload.starts_with(PQ_AUTH_ACK_MAGIC);
    if !is_chunk && !is_ack {
        return false;
    }
    let Some(sess) = node.sessions.get(peer_fp) else {
        return true;
    };
    if is_chunk {
        let hlen = PQ_AUTH_CHUNK_MAGIC.len();
        if payload.len() < hlen + 4 {
            tracing::warn!(peer = %peer_fp, "malformed PQ auth chunk PDU");
            return true;
        }
        let chunk_idx = payload[hlen];
        let total_chunks = payload[hlen + 1];
        let chunk_len = u16::from_be_bytes([payload[hlen + 2], payload[hlen + 3]]) as usize;
        let data_start = hlen + 4;
        if payload.len() < data_start + chunk_len {
            tracing::warn!(peer = %peer_fp, "truncated PQ auth chunk data");
            return true;
        }
        let chunk_data = payload[data_start..data_start + chunk_len].to_vec();

        let (ctx, already_authed, role, full_binding, pinned_pk, pinned_pq_comm, master_key) = {
            let ctx = SealCtx::from_session(&sess);
            let already_authed = sess.is_pq_authenticated();
            let role = sess.role;
            let full_binding = if already_authed {
                None
            } else {
                sess.store_pq_chunk(chunk_idx, total_chunks, chunk_data)
            };
            let pinned_pk = sess.peer_identity_pk();
            let pinned_pq_comm = sess.peer_pq_commitment();
            let master_key = sess.master_key;
            (
                ctx,
                already_authed,
                role,
                full_binding,
                pinned_pk,
                pinned_pq_comm,
                master_key,
            )
        };
        drop(sess);

        // Send ACK back to peer
        let mut ack_pdu = Vec::with_capacity(PQ_AUTH_ACK_MAGIC.len() + 1);
        ack_pdu.extend_from_slice(PQ_AUTH_ACK_MAGIC);
        ack_pdu.push(chunk_idx);
        let ack_frame = seal_single(&ctx, &ack_pdu);
        send_frame_to_peer(node, sock, src, fallback, peer_fp, ack_frame).await;

        if already_authed {
            return true;
        }

        if let Some(full_binding) = full_binding {
            if let Some(pk) = pinned_pk {
                match l0_identity::verify_hybrid_binding(
                    &pk,
                    pinned_pq_comm.as_ref(),
                    &master_key,
                    &full_binding,
                ) {
                    Ok(pq_pk) => {
                        if let Some(s) = node.sessions.get(peer_fp) {
                            s.set_pq_authenticated(true);
                            s.set_peer_pq_pk(pq_pk);
                        }
                        tracing::info!(
                            peer = %peer_fp,
                            "Post-quantum hybrid authentication SUCCEEDED (ML-DSA-65) — session elevated to active"
                        );
                        // The responder's initial PQ-auth burst leaves at ctr=0 immediately
                        // after RESPONSE_NEGOTIATION_MAGIC (ctr=1), so on a fast carrier or
                        // multi-core host its self-contained chunks can reach the initiator
                        // before the initiator finishes ML-KEM-768 decapsulation and inserts
                        // the session. Once the initiator's own proof authenticates here, the
                        // initiator's session is guaranteed to be installed.
                        if role == SessionRole::Responder {
                            send_pq_auth_proof(node, sock, src, fallback, peer_fp).await;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            peer = %peer_fp,
                            error = %err,
                            "Post-quantum hybrid authentication FAILED — evicting session"
                        );
                        if let Some(s) = node.sessions.get(peer_fp) {
                            s.set_pq_authenticated(false);
                        }
                        node.sessions.remove(peer_fp);
                    }
                }
            } else {
                tracing::warn!(
                    peer = %peer_fp,
                    "Cannot verify PQ auth: missing pinned peer identity PK"
                );
                node.sessions.remove(peer_fp);
            }
        }
        return true;
    }
    if is_ack {
        tracing::debug!(peer = %peer_fp, "PQ auth chunk acknowledged by peer");
        return true;
    }
    false
}

/// Initiate a mesh handshake to `t` (PEER command and the VPN client
/// watchdog share this path). Inserts into `pending_hs`; the response
/// completes asynchronously in handle_pkt.
pub(crate) async fn initiate_handshake(
    nc: &GhostNode,
    sock: &UdpSocket,
    t: SocketAddr,
    pending_hs: &PendingHandshakes,
) {
    let (xs, xp) = generate_x25519_keypair();

    // §2 spike: opt-in uniform mode intentionally uses the existing legacy
    // ML-KEM-512 payload sizes so it can be compared on the wire without
    // changing the transport fragmentation contract. It also avoids the
    // explicit suite-list magic, which would defeat the experiment.
    if uniform_handshake_enabled() {
        let (kp, ks) = generate_kyber_keypair();
        let pdu = build_uniform_handshake_pdu(
            &nc.identity.public_key_bytes(),
            |d| nc.identity.sign(d).to_bytes(),
            &xp,
            &kp,
        );
        let mut c = pdu;
        let raw = l4_rs::encode(&mut c);
        let tag = [0u8; 16];
        for (i, shard) in raw.iter().take(3).enumerate() {
            let _ = send_gtf(
                sock,
                &t,
                [0, 0, 0, 0],
                0,
                i as u8,
                &frame_shard(shard),
                &tag,
                false,
            )
            .await;
        }
        if pending_hs.len() >= MAX_PENDING_HANDSHAKES {
            tracing::warn!("Pending-handshake table full — uniform handshake skipped");
            return;
        }
        pending_hs.insert(t.to_string(), PendingHandshake::Kem512(xs, ks));
        tracing::info!(target = %t, "Uniform handshake sent");
        return;
    }
    // Advertise both suites with a public KEM key for each. The responder can
    // therefore select the strongest common suite rather than trusting a clear
    // preference byte or being forced to use the initiator's first choice.
    let (kp512, ks512) = generate_kyber_keypair();
    let (kp768, ks768) = generate_kyber768_keypair();
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
        &nc.identity.public_key_bytes(),
        &nc.identity.pq_commitment(),
        |d| nc.identity.sign(d).to_bytes(),
        &xp,
        &keys,
    )
    .expect("valid suite-list handshake");
    let mut c = pdu;
    let raw = l4_rs::encode(&mut c);
    let tag = [0u8; 16];
    let is_bulk = raw
        .iter()
        .any(|s| frame_shard(s).len() > vantablack::ghost::net::MAX_PAYLOAD_LEN);
    for (i, shard) in raw.iter().take(3).enumerate() {
        let _ = send_gtf(
            sock,
            &t,
            [0, 0, 0, 0],
            0,
            i as u8,
            &frame_shard(shard),
            &tag,
            is_bulk,
        )
        .await;
    }
    // Prune stale entries aggressively: if the table is more than half-full,
    // clear it entirely so subnet sweeps never permanently block new handshakes.
    // Entries that were answered are already removed; only unanswered (dead host)
    // entries accumulate, so clearing them is safe.
    if pending_hs.len() >= MAX_PENDING_HANDSHAKES / 2 {
        pending_hs.clear();
        tracing::debug!("Pending-handshake table pruned to make room");
    }
    pending_hs.insert(
        t.to_string(),
        PendingHandshake::Negotiated {
            x_secret: xs,
            kem512: ks512,
            kem768: ks768,
            offered: supported,
        },
    );
    tracing::info!(target = %t, "Handshake sent");
}

/// Insert a received frame into the reorder buffer; return frames that
/// can be flushed in sequence order (duplicates/old frames are dropped).
pub(crate) fn uniform_handshake_enabled() -> bool {
    std::env::var("GHOST_HANDSHAKE_UNIFORM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
