//! SOCKS5 proxy server implementation for Vantablack (initiator mode).
//!
//! Handles RFC 1928 negotiation, split tunneling bypass, multi-port policy mapping,
//! credit-based stream flow control, and mesh-tunnel egress.

use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::sleep;

use vantablack::ghost::net::coalesce::CoalescedShard;
use vantablack::ghost::net::reassembly::ReassemblyBuffer;
use vantablack::ghost::net::relay::{build_encrypted_onion_route, AsnDiversityConstraint};

/// Emergency diffusion (`exp_diffusion`): when the ordinary path reports that no
/// route could carry the carriers, flood each of them as an opaque hop envelope.
///
/// Gated on the toggle and on `Unroutable`, so a working path never pays for this
/// and a disabled toggle leaves the send path exactly as it was. The carriers stay
/// sealed to their session: a hop forwarding the flood cannot read them.
async fn diffuse_unroutable(
    nc: &Arc<GhostNode>,
    peers: &Arc<DashMap<String, SocketAddr>>,
    ctx: &SealCtx,
    carriers: &[Vec<u8>],
    tag: &[u8; 16],
    routed: crate::daemon::relay_fallback::Routed,
) {
    use crate::daemon::relay_fallback::Routed;
    if routed != Routed::Unroutable || !vantablack::ghost::net::diffusion::is_enabled() {
        return;
    }
    for (i, shard) in carriers.iter().take(3).enumerate() {
        let datagram = vantablack::ghost::net::build_gtf_v2_frame(
            &ctx.data_header(i as u8, false, 0),
            shard,
            tag,
        );
        let reached = crate::daemon::diffusion::flood(nc, peers, &datagram).await;
        tracing::debug!(
            shard = i,
            reached,
            "Diffusion: flooded a carrier no route could carry"
        );
    }
}

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);
static PINNED_GUARD: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Select `hop_count` (2 or 3) diverse hops ending at `exit_fp` using
/// deterministic sorting, persistent Guard pinning, and [`AsnDiversityConstraint`].
pub fn select_diverse_hops(
    candidates: &[String],
    exit_fp: &str,
    hop_count: usize,
    peer_asns: &std::collections::HashMap<String, u32>,
    pinned_guard: &std::sync::Mutex<Option<String>>,
) -> Option<Vec<String>> {
    if !(2..=3).contains(&hop_count) {
        return None;
    }
    let mut other_peers: Vec<String> = candidates
        .iter()
        .filter(|p| p.as_str() != exit_fp)
        .cloned()
        .collect();
    other_peers.sort();
    other_peers.dedup();
    if other_peers.len() < hop_count - 1 {
        return None;
    }

    let mut constraint = AsnDiversityConstraint::new(1);
    let asn_for = |fp: &str, fallback_idx: u32| -> u32 {
        peer_asns
            .get(fp)
            .copied()
            .unwrap_or(0x8000_0000 + fallback_idx)
    };
    let exit_asn = asn_for(exit_fp, 999);
    constraint.assign_shard_asn((hop_count - 1) as u8, exit_asn);

    // Pick Guard (or Relay in 2-hop) with persistent Guard pinning
    let mut guard_guard = pinned_guard.lock().ok()?;
    let guard_fp = if let Some(ref pinned) = *guard_guard {
        if other_peers.contains(pinned) && constraint.is_asn_permitted(0, asn_for(pinned, 1)) {
            pinned.clone()
        } else {
            let chosen = other_peers
                .iter()
                .enumerate()
                .find(|(i, p)| constraint.is_asn_permitted(0, asn_for(p, *i as u32 + 1)))
                .map(|(_, p)| p.clone())?;
            *guard_guard = Some(chosen.clone());
            chosen
        }
    } else {
        let chosen = other_peers
            .iter()
            .enumerate()
            .find(|(i, p)| constraint.is_asn_permitted(0, asn_for(p, *i as u32 + 1)))
            .map(|(_, p)| p.clone())?;
        *guard_guard = Some(chosen.clone());
        chosen
    };
    drop(guard_guard);

    constraint.assign_shard_asn(0, asn_for(&guard_fp, 1));

    if hop_count == 2 {
        return Some(vec![guard_fp, exit_fp.to_string()]);
    }

    // Pick Middle hop with distinct ASN from Guard and Exit
    let middle_fp = other_peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.as_str() != guard_fp)
        .find(|(i, p)| constraint.is_asn_permitted(1, asn_for(p, *i as u32 + 100)))
        .map(|(_, p)| p.clone())?;
    constraint.assign_shard_asn(1, asn_for(&middle_fp, 100));

    Some(vec![guard_fp, middle_fp, exit_fp.to_string()])
}

/// Maximum stream flow credit (64 KB window) to prevent congestion and bufferbloat.
pub const MAX_STREAM_CREDIT: usize = 65536;

/// Maximum TCP payload bytes coalesced into a single tunnel frame so that
/// `[stream_id (4B) || payload]` plus optional multi-hop `RLY!` + XChaCha20 E2E
/// headers always fit inside a single 2-data + 1-parity RS(2,1) coding group.
const MAX_STREAM_COALESCE_BYTES: usize = 850;

/// Seal `payload` end-to-end for `exit_fp` using XChaCha20-Poly1305 and wrap it
/// in the `RLY!` onion headers for `route` (`[guard, exit]` or `[guard, middle, exit]`).
fn wrap_onion_e2e(
    nn: &GhostNode,
    exit_fp: &str,
    exit_key: &[u8; 32],
    exit_role: SessionRole,
    route: &[String],
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (dctr, exit_epoch) = nn
        .sessions
        .get(exit_fp)
        .map(|s| (s.next_tx_counter(), s.epoch()))
        .unwrap_or((2, 0));
    let mut blob = (payload.len() as u16).to_be_bytes().to_vec();
    blob.extend_from_slice(payload);
    if !blob.len().is_multiple_of(2) {
        blob.push(0);
    }
    let wire_nonce = vantablack::ghost::layers::l2_aead::random_xnonce();
    vantablack::ghost::layers::l2_aead::xchacha_seal_in_place(
        exit_key,
        &wire_nonce,
        exit_epoch,
        dir_for(exit_role),
        &mut blob,
    )
    .ok()?;
    let mut inner = Vec::with_capacity(8 + 12 + blob.len());
    inner.extend_from_slice(&dctr.to_be_bytes());
    inner.extend_from_slice(&wire_nonce);
    inner.extend_from_slice(&blob);
    let route_refs: Vec<&str> = route.iter().map(|s| s.as_str()).collect();
    let hop_keys: Vec<[u8; 32]> = route
        .iter()
        .map(|fp| {
            if fp == exit_fp {
                *exit_key
            } else {
                nn.sessions
                    .get(fp.as_str())
                    .map(|s| s.master_key)
                    .unwrap_or(*exit_key)
            }
        })
        .collect();
    build_encrypted_onion_route(&route_refs, &hop_keys, &inner)
}

/// Hop and routing policy for SOCKS5 connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopPolicy {
    /// Port :1080 (Auto Mode): dynamically chooses hop count based on active swarm size.
    /// N >= 3 -> 3-hop onion; N == 2 -> 2-hop circuit; N == 1 -> 1-hop direct fast path.
    Auto,
    /// Port :1081 (1-Hop Fast Path): direct Client -> Exit low-latency high-bandwidth path.
    OneHop,
    /// Port :1082 (2-Hop Circuit): Client -> Relay -> Exit.
    TwoHop,
    /// Port :1083 (Strict 3-Hop Onion): Client -> Guard -> Middle -> Exit.
    /// If active swarm size N < 3, refuses connection (0x05) instead of silently degrading privacy.
    StrictThreeHop,
}

/// Copy bytes from `r` to `w` until the reader closes.
pub async fn pump<R, W>(mut r: R, mut w: W) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
    }
    Ok(())
}

/// Answer a SOCKS5 CONNECT with success and relay the client to an upstream
/// socket we already opened locally. Used by split tunneling, where the target
/// is deliberately *not* sent through the mesh.
pub async fn socks_relay_direct(s: tokio::net::TcpStream, upstream: tokio::net::TcpStream) {
    let mut s = s;
    if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
        return;
    }
    let (client_r, client_w) = s.into_split();
    let (up_r, up_w) = upstream.into_split();
    let up = tokio::spawn(pump(client_r, up_w));
    let down = tokio::spawn(pump(up_r, client_w));
    let _ = tokio::join!(up, down);
}

/// Handle a single incoming SOCKS5 connection under a specified HopPolicy.
#[allow(clippy::too_many_arguments)]
pub async fn handle_socks5_connection(
    mut s: tokio::net::TcpStream,
    policy: HopPolicy,
    nn: Arc<GhostNode>,
    aa: Arc<DashMap<String, SocketAddr>>,
    chh: SessionChannels,
    ak2: ConnectAcks,
    de2: Arc<std::sync::Mutex<Option<String>>>,
    shard_router_proxy: Arc<vantablack::ghost::net::mesh::AdaptiveShardRouter>,
    cs2: Arc<parking_lot::RwLock<ConsumerSettings>>,
    fallback_routes_proxy: Arc<fallback::Fallback>,
    carrier_proxy: Arc<net::carrier::Carrier>,
    turn_path_proxy: Option<Arc<TurnPath>>,
) {
    let mut b = [0u8; 2];
    if s.read_exact(&mut b).await.is_err() || b[0] != 5 {
        return;
    }
    let mut m = vec![0u8; b[1] as usize];
    if s.read_exact(&mut m).await.is_err() {
        return;
    }
    if s.write_all(&[5, 0]).await.is_err() {
        return;
    }
    let mut h = [0u8; 4];
    if s.read_exact(&mut h).await.is_err() || h[1] != 1 {
        return;
    }
    let addr = match h[3] {
        1 => {
            let mut ip = [0u8; 4];
            if s.read_exact(&mut ip).await.is_err() {
                return;
            }
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        3 => {
            let mut l = [0u8; 1];
            if s.read_exact(&mut l).await.is_err() {
                return;
            }
            let mut d = vec![0u8; l[0] as usize];
            if s.read_exact(&mut d).await.is_err() {
                return;
            }
            String::from_utf8_lossy(&d).to_string()
        }
        _ => return,
    };
    let mut pb = [0u8; 2];
    if s.read_exact(&mut pb).await.is_err() {
        return;
    }
    let port = u16::from_be_bytes(pb);

    // ── Ad & tracker blocking (works immediately even with 0 mesh peers) ──
    if vantablack::ghost::net::adblock::is_shielded_target(&addr)
        || vantablack::ghost::net::adblock::is_blocked_port(port)
    {
        vantablack::ghost::net::adblock::record_blocked();
        tracing::debug!(dest = %addr, port = port, "SOCKS5: blocked ad/tracker/DoH target");
        let _ = s.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    }

    // ── Split tunneling bypass ───────────────────────────────────────
    if cs2.read().should_bypass(&addr) {
        let dest_direct = format!("{addr}:{port}");
        tracing::info!(dest = %dest_direct, "SOCKS5: bypassing mesh (split tunnel)");
        match tokio::net::TcpStream::connect((addr.as_str(), port)).await {
            Ok(upstream) => socks_relay_direct(s, upstream).await,
            Err(e) => {
                tracing::warn!(dest = %dest_direct, error = %e, "SOCKS5: split-tunnel dial failed");
                let _ = s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            }
        }
        return;
    }

    // ── Swarm Policy Verification ────────────────────────────────────
    let active_sessions = nn.sessions.len();
    match policy {
        HopPolicy::StrictThreeHop => {
            if active_sessions < 3 {
                tracing::warn!(
                    active = active_sessions,
                    required = 3,
                    "SOCKS5 :1083 Strict 3-Hop refused: Insufficient swarm size. Refusing to degrade privacy silently."
                );
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        }
        HopPolicy::TwoHop => {
            if active_sessions < 2 {
                tracing::warn!(
                    active = active_sessions,
                    required = 2,
                    "SOCKS5 :1082 2-Hop refused: Insufficient swarm size."
                );
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        }
        HopPolicy::OneHop | HopPolicy::Auto => {
            if active_sessions == 0 {
                tracing::warn!("SOCKS5: No active peer session. Connect to a peer first.");
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        }
    }

    // ── Exit Node Selection ──────────────────────────────────────────
    // A pinned home exit (roadmap item 3) outranks any adaptive choice. If it is
    // pinned but unreachable, refuse: silently using another exit would route
    // the user's traffic through a node they did not choose, which is exactly
    // what this feature exists to prevent.
    let pinned_home = vantablack::ghost::v2::boomerang::selected();
    let (fp, tgt) = match pinned_home {
        Some(home_fp) => {
            if !nn.sessions.contains_key(&home_fp) {
                tracing::warn!(exit = %home_fp, "SOCKS5 refused: pinned home exit has no live session");
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
            tracing::info!(exit = %home_fp, "SOCKS5: using pinned home exit");
            let addr = aa
                .get(&home_fp)
                .map(|v| *v.value())
                .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
            (home_fp, addr)
        }
        None => {
            let chosen = match de2.lock().unwrap().clone() {
                Some(fp) if aa.contains_key(&fp) => Some(fp),
                _ => None,
            };
            match chosen {
                Some(fp) => {
                    let addr = aa
                        .get(&fp)
                        .map(|v| *v.value())
                        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                    (fp, addr)
                }
                None => match nn.sessions.iter().next() {
                    Some(e) => {
                        let fp = e.key().clone();
                        let addr = aa
                            .get(&fp)
                            .map(|v| *v.value())
                            .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                        (fp, addr)
                    }
                    None => {
                        tracing::warn!("SOCKS5: No session available.");
                        let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    }
                },
            }
        }
    };

    // Allocate monotonic stream ID for this SOCKS5 TCP connection
    let stream_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);

    // ── Circuit Route & First-Hop Resolution ─────────────────────────
    let effective_policy = match policy {
        HopPolicy::Auto => {
            if active_sessions >= 3 {
                HopPolicy::StrictThreeHop
            } else if active_sessions == 2 {
                HopPolicy::TwoHop
            } else {
                HopPolicy::OneHop
            }
        }
        other => other,
    };

    let (first_hop_fp, first_hop_addr, onion_route) = match effective_policy {
        HopPolicy::StrictThreeHop => {
            let candidates: Vec<String> = nn.sessions.iter().map(|e| e.key().clone()).collect();
            if candidates.len() < 3 {
                tracing::warn!("SOCKS5 :1083 Strict 3-Hop: insufficient swarm size");
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
            let empty_asns = std::collections::HashMap::new();
            let Some(route) = select_diverse_hops(&candidates, &fp, 3, &empty_asns, &PINNED_GUARD)
            else {
                tracing::warn!("SOCKS5 :1083 Strict 3-Hop: diverse peers unavailable");
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            };
            let guard_fp = route[0].clone();
            let guard_addr = aa.get(&guard_fp).map(|v| *v.value()).unwrap_or(tgt);
            vantablack::ghost::v2::boomerang::record_circuit(&route, "StrictThreeHop");
            (guard_fp, guard_addr, Some(route))
        }
        HopPolicy::TwoHop => {
            let candidates: Vec<String> = nn.sessions.iter().map(|e| e.key().clone()).collect();
            if candidates.len() < 2 {
                tracing::warn!("SOCKS5 :1082 2-Hop: insufficient swarm size");
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
            let empty_asns = std::collections::HashMap::new();
            let Some(route) = select_diverse_hops(&candidates, &fp, 2, &empty_asns, &PINNED_GUARD)
            else {
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            };
            let relay_fp = route[0].clone();
            let relay_addr = aa.get(&relay_fp).map(|v| *v.value()).unwrap_or(tgt);
            vantablack::ghost::v2::boomerang::record_circuit(&route, "TwoHop");
            (relay_fp, relay_addr, Some(route))
        }
        HopPolicy::OneHop | HopPolicy::Auto => (fp.clone(), tgt, None),
    };

    let exit_sess = match nn.sessions.get(&fp) {
        Some(s) => s,
        None => {
            tracing::warn!("SOCKS5: No session for exit {fp}");
            let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    let exit_key = exit_sess.master_key;
    let exit_sh = exit_sess.session_hash;
    let exit_role = exit_sess.role;
    drop(exit_sess);

    let ss = match nn.sessions.get(&first_hop_fp) {
        Some(s) => s,
        None => {
            tracing::warn!("SOCKS5: No session for first hop {first_hop_fp}");
            let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    let key = ss.master_key;
    let sh = ss.session_hash;
    let role = ss.role;
    drop(ss);

    // Return traffic and OK!{stream_id}! from the exit arrive under `exit_sh`.
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    chh.insert((exit_sh, stream_id), tx);

    let connect_ctr = nn
        .sessions
        .get(&first_hop_fp)
        .map(|s| s.next_tx_counter())
        .unwrap_or(2);
    let plain_dest = format!("{}:{}", addr, port);
    let dest_with_voucher = std::env::var("GHOST_EXIT_VOUCHER")
        .ok()
        .filter(|voucher| !voucher.is_empty())
        .map(|voucher| format!("EXITAUTH!{voucher}!{plain_dest}"))
        .unwrap_or(plain_dest);
    let dest = format!("STREAM!{stream_id}!{dest_with_voucher}");
    tracing::info!(dest = %dest, policy = ?policy, stream_id = stream_id, "SOCKS5 CONNECT initiated");

    let connect_ctx = nn
        .sessions
        .get(&first_hop_fp)
        .map(|s| SealCtx::from_session(&s))
        .unwrap_or_else(|| SealCtx {
            key,
            epoch: 0,
            counter: connect_ctr,
            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
            direction: dir_for(role),
            session_hash: sh,
            ratchet_due: false,
            tail: vantablack::ghost::net::random_tail(),
        });

    let connect_payload = match onion_route.as_ref() {
        Some(route) => wrap_onion_e2e(&nn, &fp, &exit_key, exit_role, route, dest.as_bytes())
            .unwrap_or_else(|| dest.into_bytes()),
        None => dest.into_bytes(),
    };

    let (f, tag) = enc_split(&connect_ctx, &connect_payload);
    match fallback_routes_proxy.path(&first_hop_fp) {
        Some(path) => {
            let _ = send3_via_fallback(
                &nn,
                &nn.socket,
                &first_hop_fp,
                &connect_ctx,
                &f,
                &tag,
                &path,
                turn_path_proxy.as_ref(),
            )
            .await;
        }
        None => {
            send3_mixed(
                Arc::clone(&nn.socket),
                &first_hop_addr,
                &connect_ctx,
                &f,
                &tag,
            )
            .await
        }
    }

    // Wait for the exit's framed "OK!{stream_id}!" or "OK" (delivered via handle_pkt).
    let mut connected = false;
    for _ in 0..50 {
        if ak2
            .get(&(exit_sh, stream_id))
            .map(|v| *v.value())
            .unwrap_or(false)
        {
            connected = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    if !connected {
        tracing::warn!(
            stream_id = stream_id,
            "SOCKS5 CONNECT failed (timeout waiting for CONNECT_OK)"
        );
        chh.remove(&(exit_sh, stream_id));
        let _ = s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await; // 0x04 = Host unreachable
        return;
    }
    tracing::info!(stream_id = stream_id, "SOCKS5 CONNECT_OK established");
    // RACS: real traffic is flowing, so cover yields for the yield window.
    vantablack::ghost::v2::racs::note_real_traffic();
    if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
        chh.remove(&(exit_sh, stream_id));
        return;
    }

    // ── Ingress & Egress Data Pump with Credit-Based Flow Control ─────
    let (mut rd, mut wr) = s.into_split();
    let nn2 = Arc::clone(&nn);
    let first_hop_out = first_hop_fp.clone();
    let exit_fp_out = fp.clone();
    let key_out = key;
    let sh_out = sh;
    let role_out = role;
    let exit_key_out = exit_key;
    let exit_sh_out = exit_sh;
    let exit_role_out = exit_role;
    let tgt_out = first_hop_addr;
    let chh2 = Arc::clone(&chh);
    let ak2_out = Arc::clone(&ak2);
    let srouter = Arc::clone(&shard_router_proxy);
    let aa_proxy = Arc::clone(&aa);
    let routes_out = Arc::clone(&fallback_routes_proxy);
    let turn_path_out = turn_path_proxy.clone();
    let carrier_out = Arc::clone(&carrier_proxy);
    let onion_route_out = onion_route.clone();

    let stream_credit = Arc::new(AtomicUsize::new(MAX_STREAM_CREDIT));
    let credit_in = Arc::clone(&stream_credit);

    // Client -> Mesh pumping task: coalesces small TCP writes within a 200 µs
    // window up to MAX_STREAM_COALESCE_BYTES and dispatches each batch as a
    // single SIMD RS(2,1) coding group (zero double-RS amplification, zero
    // request-response deadlock).
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; MAX_STREAM_COALESCE_BYTES];
        let mut coalesce_buf: Vec<u8> = Vec::with_capacity(4 + MAX_STREAM_COALESCE_BYTES);
        let mut checked_sni = port != 443;

        loop {
            while credit_in.load(Ordering::Relaxed) == 0 {
                sleep(Duration::from_micros(200)).await;
            }

            let max_read = (4 + MAX_STREAM_COALESCE_BYTES)
                .saturating_sub(coalesce_buf.len())
                .min(rbuf.len());

            let should_flush = if coalesce_buf.is_empty() {
                match rd.read(&mut rbuf[..max_read]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if !checked_sni {
                            checked_sni = true;
                            if let Some(sni) =
                                vantablack::ghost::net::adblock::extract_tls_sni(&rbuf[..n])
                            {
                                if vantablack::ghost::net::adblock::is_shielded_target(&sni) {
                                    vantablack::ghost::net::adblock::record_blocked();
                                    tracing::debug!(
                                        sni = %sni,
                                        stream_id = stream_id,
                                        "SOCKS5: blocked TLS ClientHello SNI"
                                    );
                                    break;
                                }
                            }
                        }
                        vantablack::ghost::v2::racs::note_real_traffic();
                        let current_credit = credit_in.load(Ordering::Relaxed);
                        credit_in.fetch_sub(n.min(current_credit), Ordering::Relaxed);
                        coalesce_buf.extend_from_slice(&stream_id.to_be_bytes());
                        coalesce_buf.extend_from_slice(&rbuf[..n]);
                        coalesce_buf.len() >= 4 + MAX_STREAM_COALESCE_BYTES
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    res = rd.read(&mut rbuf[..max_read]) => {
                        match res {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                vantablack::ghost::v2::racs::note_real_traffic();
                        let current_credit = credit_in.load(Ordering::Relaxed);
                                credit_in.fetch_sub(n.min(current_credit), Ordering::Relaxed);
                                coalesce_buf.extend_from_slice(&rbuf[..n]);
                                coalesce_buf.len() >= 4 + MAX_STREAM_COALESCE_BYTES
                            }
                        }
                    }
                    _ = sleep(Duration::from_micros(200)) => true,
                }
            };

            if should_flush && !coalesce_buf.is_empty() {
                let batch = std::mem::replace(
                    &mut coalesce_buf,
                    Vec::with_capacity(4 + MAX_STREAM_COALESCE_BYTES),
                );
                let c = nn2
                    .sessions
                    .get(&first_hop_out)
                    .map(|s| s.next_tx_counter())
                    .unwrap_or(2);
                let ctx_out = nn2
                    .sessions
                    .get(&first_hop_out)
                    .map(|s| SealCtx::from_session(&s))
                    .unwrap_or_else(|| SealCtx {
                        key: key_out,
                        epoch: 0,
                        counter: c,
                        nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                        direction: dir_for(role_out),
                        session_hash: sh_out,
                        ratchet_due: false,
                        tail: vantablack::ghost::net::random_tail(),
                    });

                let wire_payload = match onion_route_out.as_ref() {
                    Some(route) => wrap_onion_e2e(
                        &nn2,
                        &exit_fp_out,
                        &exit_key_out,
                        exit_role_out,
                        route,
                        &batch,
                    )
                    .unwrap_or(batch),
                    None => batch,
                };

                let (f, tag) = enc_split(&ctx_out, &wire_payload);
                let me = nn2.fingerprint();
                let plan = nn2.contact_plan.read().await;
                let route = routes_out.path(&first_hop_out);
                let routed = send3_adaptive(
                    &nn2,
                    &nn2.socket,
                    &tgt_out,
                    &first_hop_out,
                    &ctx_out,
                    &f,
                    &tag,
                    &srouter,
                    &aa_proxy,
                    Some(&plan),
                    &me,
                    route.as_ref(),
                    turn_path_out.as_ref(),
                    Some(&carrier_out),
                )
                .await;
                diffuse_unroutable(&nn2, &aa_proxy, &ctx_out, &f, &tag, routed).await;
            }
        }

        // Flush any remaining buffered bytes on stream EOF
        if !coalesce_buf.is_empty() {
            let c = nn2
                .sessions
                .get(&first_hop_out)
                .map(|s| s.next_tx_counter())
                .unwrap_or(2);
            let ctx_out = nn2
                .sessions
                .get(&first_hop_out)
                .map(|s| SealCtx::from_session(&s))
                .unwrap_or_else(|| SealCtx {
                    key: key_out,
                    epoch: 0,
                    counter: c,
                    nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                    direction: dir_for(role_out),
                    session_hash: sh_out,
                    ratchet_due: false,
                    tail: vantablack::ghost::net::random_tail(),
                });
            let wire_payload = match onion_route_out.as_ref() {
                Some(route) => wrap_onion_e2e(
                    &nn2,
                    &exit_fp_out,
                    &exit_key_out,
                    exit_role_out,
                    route,
                    &coalesce_buf,
                )
                .unwrap_or(coalesce_buf),
                None => coalesce_buf,
            };
            let (f, tag) = enc_split(&ctx_out, &wire_payload);
            let me = nn2.fingerprint();
            let plan = nn2.contact_plan.read().await;
            let route = routes_out.path(&first_hop_out);
            let routed = send3_adaptive(
                &nn2,
                &nn2.socket,
                &tgt_out,
                &first_hop_out,
                &ctx_out,
                &f,
                &tag,
                &srouter,
                &aa_proxy,
                Some(&plan),
                &me,
                route.as_ref(),
                turn_path_out.as_ref(),
                Some(&carrier_out),
            )
            .await;
            diffuse_unroutable(&nn2, &aa_proxy, &ctx_out, &f, &tag, routed).await;
        }

        // Send CLOSE notification to exit node
        let close_msg = format!("CLOSE!{stream_id}!");
        let close_payload = match onion_route_out.as_ref() {
            Some(route) => wrap_onion_e2e(
                &nn2,
                &exit_fp_out,
                &exit_key_out,
                exit_role_out,
                route,
                close_msg.as_bytes(),
            )
            .unwrap_or_else(|| close_msg.into_bytes()),
            None => close_msg.into_bytes(),
        };
        let c = nn2
            .sessions
            .get(&first_hop_out)
            .map(|s| s.next_tx_counter())
            .unwrap_or(2);
        let ctx_close = nn2
            .sessions
            .get(&first_hop_out)
            .map(|s| SealCtx::from_session(&s))
            .unwrap_or_else(|| SealCtx {
                key: key_out,
                epoch: 0,
                counter: c,
                nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                direction: dir_for(role_out),
                session_hash: sh_out,
                ratchet_due: false,
                tail: vantablack::ghost::net::random_tail(),
            });
        let (f, tag) = enc_split(&ctx_close, &close_payload);
        let me = nn2.fingerprint();
        let plan = nn2.contact_plan.read().await;
        let route = routes_out.path(&first_hop_out);
        let routed = send3_adaptive(
            &nn2,
            &nn2.socket,
            &tgt_out,
            &first_hop_out,
            &ctx_close,
            &f,
            &tag,
            &srouter,
            &aa_proxy,
            Some(&plan),
            &me,
            route.as_ref(),
            turn_path_out.as_ref(),
            Some(&carrier_out),
        )
        .await;
        diffuse_unroutable(&nn2, &aa_proxy, &ctx_close, &f, &tag, routed).await;

        chh2.remove(&(exit_sh_out, stream_id));
        ak2_out.remove(&(exit_sh_out, stream_id));
    });

    // Mesh -> Client pumping task: delivers reassembled exit chunks and replenishes flow credits.
    // Note: `handle_pkt` already strips the 4-byte `stream_id` header before pushing to `sessions_rx`.
    let mut reassembly_buf = ReassemblyBuffer::new();
    while let Some(chunk) = rx.recv().await {
        let len = chunk.len();
        if let Some(shard) = CoalescedShard::deserialize(&chunk) {
            if let Some(assembled) = reassembly_buf.ingest_shard(&shard) {
                if wr.write_all(&assembled).await.is_err() {
                    break;
                }
            }
        } else if wr.write_all(&chunk).await.is_err() {
            break;
        }
        // Replenish credit window
        stream_credit.fetch_add(len, Ordering::Relaxed);
    }
    chh.remove(&(exit_sh, stream_id));
    ak2.remove(&(exit_sh, stream_id));
}

/// Spawns the port-multiplexed SOCKS5 proxy server listeners:
/// - `:1080` (Auto Mode): dynamically selects hop count based on active swarm size.
/// - `:1081` (1-Hop Fast Path): direct Client -> Exit.
/// - `:1082` (2-Hop Circuit): Client -> Relay -> Exit.
/// - `:1083` (Strict 3-Hop Onion): Client -> Guard -> Middle -> Exit (rejects if N < 3).
pub fn spawn_socks5_server(
    socks_port: u16,
    nc: Arc<GhostNode>,
    addrs: Arc<DashMap<String, SocketAddr>>,
    sess_chan: SessionChannels,
    rx_state_map: RxStateMap,
    connect_acks: ConnectAcks,
    default_exit: Arc<std::sync::Mutex<Option<String>>>,
    shard_router: Arc<vantablack::ghost::net::mesh::AdaptiveShardRouter>,
    consumer_settings: Arc<parking_lot::RwLock<ConsumerSettings>>,
    fallback_routes: Arc<fallback::Fallback>,
    carrier: Arc<net::carrier::Carrier>,
    turn_path: Option<Arc<TurnPath>>,
    // A configured regime replaces the four fixed ports with the one listener
    // and hop policy that regime names.
    regime_policy: Option<HopPolicy>,
) {
    let port_policies: Vec<(u16, HopPolicy, &str)> = match regime_policy {
        Some(policy) => vec![(socks_port, policy, "Regime")],
        None => vec![
            (socks_port, HopPolicy::Auto, "Auto (Adaptive)"),
            (
                socks_port.saturating_add(1),
                HopPolicy::OneHop,
                "1-Hop Fast Path",
            ),
            (
                socks_port.saturating_add(2),
                HopPolicy::TwoHop,
                "2-Hop Circuit",
            ),
            (
                socks_port.saturating_add(3),
                HopPolicy::StrictThreeHop,
                "Strict 3-Hop Onion",
            ),
        ],
    };

    for (port, policy, desc) in port_policies {
        let nc = Arc::clone(&nc);
        let addrs = Arc::clone(&addrs);
        let sess_chan = Arc::clone(&sess_chan);
        let _rx_state_map = Arc::clone(&rx_state_map);
        let connect_acks = Arc::clone(&connect_acks);
        let default_exit = Arc::clone(&default_exit);
        let shard_router = Arc::clone(&shard_router);
        let consumer_settings = Arc::clone(&consumer_settings);
        let fallback_routes = Arc::clone(&fallback_routes);
        let carrier = Arc::clone(&carrier);
        let turn_path = turn_path.clone();

        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                Ok(lis) => {
                    tracing::info!("SOCKS5 proxy [{desc}] listening on 127.0.0.1:{port}");
                    loop {
                        if let Ok((s, _)) = lis.accept().await {
                            tokio::spawn(handle_socks5_connection(
                                s,
                                policy,
                                Arc::clone(&nc),
                                Arc::clone(&addrs),
                                Arc::clone(&sess_chan),
                                Arc::clone(&connect_acks),
                                Arc::clone(&default_exit),
                                Arc::clone(&shard_router),
                                Arc::clone(&consumer_settings),
                                Arc::clone(&fallback_routes),
                                Arc::clone(&carrier),
                                turn_path.clone(),
                            ));
                        }
                    }
                }
                Err(e) => {
                    if policy == HopPolicy::Auto {
                        panic!("Failed to bind primary SOCKS5 proxy on 127.0.0.1:{port}: {e}");
                    } else {
                        tracing::warn!(
                            "SOCKS5 auxiliary port 127.0.0.1:{port} ({desc}) unavailable: {e}"
                        );
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_multi_port_socks5_live_listeners() {
        let test_base_port = 19180u16;
        let node = GhostNode::new("127.0.0.1:0")
            .await
            .expect("GhostNode failed to bind");
        let nc = Arc::new(node);
        let addrs = Arc::new(DashMap::new());
        let sess_chan = Arc::new(DashMap::new());
        let rx_state_map = Arc::new(DashMap::new());
        let connect_acks = Arc::new(DashMap::new());
        let default_exit = Arc::new(std::sync::Mutex::new(None));
        let shard_router = Arc::new(vantablack::ghost::net::mesh::AdaptiveShardRouter::new());
        let consumer_settings = Arc::new(parking_lot::RwLock::new(ConsumerSettings::default()));
        let fallback_routes = Arc::new(fallback::Fallback::new(None));
        let carrier = Arc::new(net::carrier::Carrier::disabled());

        spawn_socks5_server(
            test_base_port,
            Arc::clone(&nc),
            Arc::clone(&addrs),
            sess_chan,
            rx_state_map,
            connect_acks,
            default_exit,
            shard_router,
            consumer_settings,
            fallback_routes,
            carrier,
            None,
            None,
        );

        sleep(Duration::from_millis(150)).await;

        let ports = [
            (test_base_port, "Auto"),
            (test_base_port + 1, "1-Hop Fast"),
            (test_base_port + 2, "2-Hop"),
            (test_base_port + 3, "Strict 3-Hop"),
        ];

        for (port, desc) in ports {
            let mut stream = TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap_or_else(|e| {
                    panic!("Failed to connect to SOCKS5 port {port} ({desc}): {e}")
                });

            stream.write_all(&[5, 1, 0]).await.expect("write handshake");
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await.expect("read handshake");
            assert_eq!(resp, [5, 0], "SOCKS5 handshake must succeed on {port}");

            // Send CONNECT 127.0.0.1:8080
            stream
                .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90])
                .await
                .expect("write CONNECT");
            let mut conn_resp = [0u8; 10];
            stream
                .read_exact(&mut conn_resp)
                .await
                .expect("read CONNECT response");
            assert_eq!(conn_resp[0], 5);
            assert_eq!(conn_resp[1], 5, "Port {port} ({desc}) must reject with 0x05 Connection Refused when swarm size is insufficient");
        }
    }

    #[tokio::test]
    async fn test_multi_stream_allocates_distinct_stream_ids() {
        let sid1 = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        let sid2 = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        assert_ne!(
            sid1, sid2,
            "Concurrent streams must receive distinct monotone stream IDs"
        );
        assert!(sid2 > sid1);
    }

    #[tokio::test]
    async fn test_wrap_onion_e2e_roundtrips_3_hop_circuit_envelope() {
        let node = GhostNode::new("127.0.0.1:0").await.expect("GhostNode bind");
        let exit_key = [0x42u8; 32];
        let route = vec![
            "guard_fp_0001".to_string(),
            "middle_fp_002".to_string(),
            "exit_fp_00003".to_string(),
        ];
        let original = b"STREAM!7!example.com:443";
        let onion = wrap_onion_e2e(
            &node,
            "exit_fp_00003",
            &exit_key,
            SessionRole::Initiator,
            &route,
            original,
        )
        .expect("3-hop onion envelope must build");

        // Guard peels outer RLY! layer -> points to middle_fp_002 with remaining_hops == 2
        let hop1 = vantablack::ghost::net::relay::parse_relay_header(&onion)
            .expect("guard layer must parse");
        assert_eq!(hop1.next_hop_fingerprint, "middle_fp_002");
        assert_eq!(hop1.remaining_hops, 2);
        // Guard must NOT be able to read the Exit fingerprint in cleartext
        assert!(
            !hop1
                .inner_payload
                .windows(b"exit_fp_00003".len())
                .any(|w| w == b"exit_fp_00003"),
            "Guard must not see Exit fingerprint in cleartext"
        );

        // Middle peels its per-hop encrypted layer, then parses RLY! -> points to exit_fp_00003
        let middle_key = exit_key;
        let middle_plain = vantablack::ghost::net::relay::peel_encrypted_relay_layer(
            &middle_key,
            &hop1.inner_payload,
        )
        .expect("middle encrypted layer must decrypt");
        let hop2 = vantablack::ghost::net::relay::parse_relay_header(&middle_plain)
            .expect("middle layer must parse");
        assert_eq!(hop2.next_hop_fingerprint, "exit_fp_00003");
        assert_eq!(hop2.remaining_hops, 1);

        // Exit unwraps inner [dctr (8B)][wire_nonce (12B)][xchacha_seal([len u16][payload])]
        let inner = &hop2.inner_payload;
        assert!(inner.len() >= 20 + 16);
        let mut wire_nonce = [0u8; 12];
        wire_nonce.copy_from_slice(&inner[8..20]);
        let mut blob = inner[20..].to_vec();
        let pt = vantablack::ghost::layers::l2_aead::xchacha_open(
            &exit_key,
            &wire_nonce,
            0,
            NonceDirection::InitiatorToResponder,
            &mut blob,
        )
        .expect("Exit must authenticate and decrypt E2E inner layer");
        let unpacked = frame_payload(pt).expect("frame_payload must strip u16 length prefix");
        assert_eq!(unpacked, original);
    }

    #[test]
    fn test_guard_pinning_and_asn_diversity() {
        let pinned = std::sync::Mutex::new(None);
        let mut asns = std::collections::HashMap::new();
        asns.insert("peer_a".to_string(), 64501);
        asns.insert("peer_b".to_string(), 64501); // Same ASN as peer_a
        asns.insert("peer_c".to_string(), 64502);
        asns.insert("exit_z".to_string(), 64503);

        let candidates = vec![
            "peer_c".to_string(),
            "peer_b".to_string(),
            "peer_a".to_string(),
            "exit_z".to_string(),
        ];

        // 1. First 3-hop selection pins peer_a (sorted first) as Guard, skips peer_b (same ASN), picks peer_c as Middle
        let route1 = select_diverse_hops(&candidates, "exit_z", 3, &asns, &pinned)
            .expect("diverse 3-hop route");
        assert_eq!(route1, vec!["peer_a", "peer_c", "exit_z"]);
        assert_eq!(pinned.lock().unwrap().as_deref(), Some("peer_a"));

        // 2. Even if a new peer_0 appears, Guard remains pinned to peer_a
        let candidates2 = vec![
            "peer_0".to_string(),
            "peer_a".to_string(),
            "peer_c".to_string(),
            "exit_z".to_string(),
        ];
        asns.insert("peer_0".to_string(), 64504);
        let route2 = select_diverse_hops(&candidates2, "exit_z", 3, &asns, &pinned)
            .expect("pinned guard route");
        assert_eq!(route2[0], "peer_a");

        // 3. 2-hop selection also respects pinned guard and ASN diversity
        let route_2hop =
            select_diverse_hops(&candidates2, "exit_z", 2, &asns, &pinned).expect("2-hop route");
        assert_eq!(route_2hop, vec!["peer_a", "exit_z"]);
    }

    #[test]
    fn test_telescoping_circuit_isolation_in_socks() {
        use ml_kem::kem::{Kem, KeyExport};
        use ml_kem::MlKem768;
        use vantablack::ghost::net::relay::{
            CircuitId, CircuitSwapTable, ExtendPqCell, TelescopingCircuit,
        };

        let x_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let x_pk = x25519_dalek::PublicKey::from(&x_sk).to_bytes();
        let (dk, ek) = MlKem768::generate_keypair();
        let ek_bytes = ek.to_bytes().as_slice().to_vec();

        let cid_in = CircuitId::random();
        let (cell, client_key) =
            ExtendPqCell::initiate(cid_in, None, &x_pk, &ek_bytes).expect("initiate");
        let exit_key = cell.accept(&x_sk, &dk).expect("accept");
        assert_eq!(client_key, exit_key);

        let exit_table = CircuitSwapTable::new();
        exit_table.insert(cid_in, None, cid_in, exit_key);

        let mut circuit = TelescopingCircuit::new(cid_in);
        circuit.extend_hop("exit_fp".into(), cid_in, client_key);
        let sealed = circuit.seal_onion(b"socks_telescoping_test").expect("seal");
        let (next, _out_id, plain) = exit_table.swap_and_peel(&cid_in, &sealed).expect("peel");
        assert!(next.is_none());
        assert_eq!(plain, b"socks_telescoping_test");
    }
}
