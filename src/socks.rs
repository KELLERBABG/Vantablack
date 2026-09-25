//! SOCKS5 proxy server implementation for Vantablack (initiator mode).
//!
//! Handles RFC 1928 negotiation, split tunneling bypass, and mesh-tunnel egress.

use super::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::sleep;

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

/// Spawns the SOCKS5 proxy listening loop on 127.0.0.1:[socks_port].
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
    let n2 = Arc::clone(&nc);
    let a2 = Arc::clone(&addrs);
    let ch = Arc::clone(&sess_chan);
    let rsm = Arc::clone(&rx_state_map);
    let ak = Arc::clone(&connect_acks);
    let de = Arc::clone(&default_exit);
    let srouter_socks = Arc::clone(&shard_router);
    let cs_socks = Arc::clone(&consumer_settings);
    let fallback_routes_socks = Arc::clone(&fallback_routes);
    let carrier_socks = Arc::clone(&carrier);
    let turn_path_socks = turn_path;
    let sp = socks_port;

    tokio::spawn(async move {
        let lis = tokio::net::TcpListener::bind(("127.0.0.1", sp))
            .await
            .expect("Failed to bind SOCKS5 proxy");
        tracing::info!("SOCKS5 proxy ready on 127.0.0.1:{sp}");
        loop {
            if let Ok((mut s, _)) = lis.accept().await {
                let nn = Arc::clone(&n2);
                let aa = Arc::clone(&a2);
                let chh = Arc::clone(&ch);
                let _rsm2 = Arc::clone(&rsm);
                let ak2 = Arc::clone(&ak);
                let de2 = Arc::clone(&de);
                let shard_router_proxy = Arc::clone(&srouter_socks);
                let cs2 = Arc::clone(&cs_socks);
                let fallback_routes_proxy = Arc::clone(&fallback_routes_socks);
                let carrier_proxy = Arc::clone(&carrier_socks);
                let turn_path_proxy = turn_path_socks.clone();
                tokio::spawn(async move {
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

                    // ── Split tunneling ──────────────────────────────────
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

                    // Prefer the explicitly configured exit node (EXIT <fp>);
                    // fall back to the first established session.
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
                                tracing::warn!("SOCKS5: No session. Use PEER command first.");
                                return;
                            }
                        },
                    };
                    let ss = match nn.sessions.get(&fp) {
                        Some(s) => s,
                        None => {
                            tracing::warn!("SOCKS5: No session for {fp}");
                            return;
                        }
                    };
                    let key = ss.master_key;
                    let sh = ss.session_hash;
                    let role = ss.role;
                    drop(ss);

                    if chh.contains_key(&sh) {
                        tracing::warn!("SOCKS5: another tunnel is already open on this session");
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
                    tracing::info!(dest = %dest, "SOCKS5 CONNECT");
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
                        tracing::warn!("SOCKS5 CONNECT failed");
                        chh.remove(&sh);
                        return;
                    }
                    tracing::info!("CONNECT_OK received");
                    if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
                        chh.remove(&sh);
                        return;
                    }

                    // client → mesh (initiator direction).
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
                    tokio::spawn(async move {
                        let mut rbuf = vec![0u8; 900];
                        loop {
                            match rd.read(&mut rbuf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
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
                                            nonce:
                                                vantablack::ghost::layers::l2_aead::random_xnonce(),
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

                    // mesh → client: ordered decrypted data via the session channel
                    while let Some(chunk) = rx.recv().await {
                        if wr.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                    chh.remove(&sh);
                });
            }
        }
    });
}
