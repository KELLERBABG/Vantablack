//! SOCKS5 proxy server implementation for Vantablack (initiator mode).
//!
//! Handles RFC 1928 negotiation, split tunneling bypass, multi-port policy mapping,
//! credit-based stream flow control, and mesh-tunnel egress.

use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::sleep;

/// Maximum stream flow credit (64 KB window) to prevent congestion and bufferbloat.
pub const MAX_STREAM_CREDIT: usize = 65536;

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
    let fp = match de2.lock().unwrap().clone() {
        Some(fp) if aa.contains_key(&fp) => Some(fp),
        _ => None,
    };
    let (fp, tgt) = match fp {
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
    };

    let ss = match nn.sessions.get(&fp) {
        Some(s) => s,
        None => {
            tracing::warn!("SOCKS5: No session for {fp}");
            let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    let key = ss.master_key;
    let sh = ss.session_hash;
    let role = ss.role;
    drop(ss);

    if chh.contains_key(&sh) {
        tracing::warn!("SOCKS5: another tunnel is already open on this session");
        let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    chh.insert(sh, tx);

    let connect_ctr = nn
        .sessions
        .get(&fp)
        .map(|s| s.next_tx_counter())
        .unwrap_or(2);
    let plain_dest = format!("{}:{}", addr, port);
    let dest = std::env::var("GHOST_EXIT_VOUCHER")
        .ok()
        .filter(|voucher| !voucher.is_empty())
        .map(|voucher| format!("EXITAUTH!{voucher}!{plain_dest}"))
        .unwrap_or(plain_dest);
    tracing::info!(dest = %dest, policy = ?policy, "SOCKS5 CONNECT initiated");

    let connect_ctx = nn
        .sessions
        .get(&fp)
        .map(|s| SealCtx::from_session(&s))
        .unwrap_or_else(|| SealCtx {
            key,
            epoch: 0,
            counter: connect_ctr,
            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
            direction: dir_for(role),
            session_hash: sh,
            ratchet_due: false,
        });

    let (f, tag) = enc_split(&connect_ctx, dest.as_bytes());
    match fallback_routes_proxy.path(&fp) {
        Some(path) => {
            let _ = send3_via_fallback(
                &nn,
                &nn.socket,
                &fp,
                &connect_ctx,
                &f,
                &tag,
                &path,
                turn_path_proxy.as_ref(),
            )
            .await;
        }
        None => {
            send3_mixed(Arc::clone(&nn.socket), &tgt, &connect_ctx, &f, &tag).await
        }
    }

    // Wait for the exit's framed "OK" (delivered via handle_pkt).
    let mut connected = false;
    for _ in 0..50 {
        if ak2.get(&sh).map(|v| *v.value()).unwrap_or(false) {
            connected = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    if !connected {
        tracing::warn!("SOCKS5 CONNECT failed (timeout waiting for CONNECT_OK)");
        chh.remove(&sh);
        let _ = s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await; // 0x04 = Host unreachable
        return;
    }
    tracing::info!("SOCKS5 CONNECT_OK established");
    if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
        chh.remove(&sh);
        return;
    }

    // ── Ingress & Egress Data Pump with Credit-Based Flow Control ─────
    let (mut rd, mut wr) = s.into_split();
    let nn2 = Arc::clone(&nn);
    let fp_out = fp.clone();
    let key_out = key;
    let sh_out = sh;
    let tgt_out = tgt;
    let chh2 = Arc::clone(&chh);
    let srouter = Arc::clone(&shard_router_proxy);
    let aa_proxy = Arc::clone(&aa);
    let routes_out = Arc::clone(&fallback_routes_proxy);
    let turn_path_out = turn_path_proxy.clone();
    let carrier_out = Arc::clone(&carrier_proxy);

    let stream_credit = Arc::new(AtomicUsize::new(MAX_STREAM_CREDIT));
    let credit_in = Arc::clone(&stream_credit);

    // Client -> Mesh pumping task
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; 984];
        loop {
            // Check credit limit before pulling more from TCP stream
            while credit_in.load(Ordering::Relaxed) == 0 {
                sleep(Duration::from_micros(200)).await;
            }

            match rd.read(&mut rbuf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let current_credit = credit_in.load(Ordering::Relaxed);
                    let to_consume = n.min(current_credit);
                    credit_in.fetch_sub(to_consume, Ordering::Relaxed);

                    let c = nn2
                        .sessions
                        .get(&fp_out)
                        .map(|s| s.next_tx_counter())
                        .unwrap_or(2);
                    let ctx_out = nn2
                        .sessions
                        .get(&fp_out)
                        .map(|s| SealCtx::from_session(&s))
                        .unwrap_or_else(|| SealCtx {
                            key: key_out,
                            epoch: 0,
                            counter: c,
                            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                            direction: NonceDirection::InitiatorToResponder,
                            session_hash: sh_out,
                            ratchet_due: false,
                        });
                    let (f, tag) = enc_split(&ctx_out, &rbuf[..n]);
                    let me = nn2.fingerprint();
                    let plan = nn2.contact_plan.read().await;
                    let route = routes_out.path(&fp_out);
                    let _ = send3_adaptive(
                        &nn2,
                        &nn2.socket,
                        &tgt_out,
                        &fp_out,
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
                }
            }
        }
        chh2.remove(&sh_out);
    });

    // Mesh -> Client pumping task: replenishes flow credits
    while let Some(chunk) = rx.recv().await {
        let len = chunk.len();
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
        // Replenish credit window
        stream_credit.fetch_add(len, Ordering::Relaxed);
    }
    chh.remove(&sh);
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
) {
    let port_policies = [
        (socks_port, HopPolicy::Auto, "Auto (Adaptive)"),
        (socks_port.saturating_add(1), HopPolicy::OneHop, "1-Hop Fast Path"),
        (socks_port.saturating_add(2), HopPolicy::TwoHop, "2-Hop Circuit"),
        (socks_port.saturating_add(3), HopPolicy::StrictThreeHop, "Strict 3-Hop Onion"),
    ];

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
                        tracing::warn!("SOCKS5 auxiliary port 127.0.0.1:{port} ({desc}) unavailable: {e}");
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
        let node = GhostNode::new("127.0.0.1:0").await.expect("GhostNode failed to bind");
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
                .unwrap_or_else(|e| panic!("Failed to connect to SOCKS5 port {port} ({desc}): {e}"));

            stream.write_all(&[5, 1, 0]).await.expect("write handshake");
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await.expect("read handshake");
            assert_eq!(resp, [5, 0], "SOCKS5 handshake must succeed on {port}");

            // Send CONNECT 127.0.0.1:8080
            stream.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]).await.expect("write CONNECT");
            let mut conn_resp = [0u8; 10];
            stream.read_exact(&mut conn_resp).await.expect("read CONNECT response");
            assert_eq!(conn_resp[0], 5);
            assert_eq!(conn_resp[1], 5, "Port {port} ({desc}) must reject with 0x05 Connection Refused when swarm size is insufficient");
        }
    }
}
