#[cfg(feature = "vpn")]
use std::sync::Arc;

#[cfg(feature = "vpn")]
use vantablack::ghost::net::vpn::{
    self,
    hub::VpnHub,
    tun::{open_fake_tun, open_tun, PlatformTun},
    VpnConfig, VpnRole, OVERLAY_HUB_HOST, OVERLAY_PREFIX, OVERLAY_SECOND_OCTET,
};

#[cfg(feature = "vpn")]
#[derive(Clone)]
pub enum VpnMode {
    Hub(Arc<VpnHub>),
    Client(
        Arc<vpn::client::ClientState>,
        Arc<std::sync::Mutex<PlatformTun>>,
    ),
}

#[cfg(not(feature = "vpn"))]
#[derive(Clone)]
pub enum VpnMode {}

/// Exports VPN Prometheus metrics, status string, and JSON telemetry.
#[cfg(feature = "vpn")]
pub fn vpn_export(mode: &Option<VpnMode>) -> (&'static str, String, serde_json::Value) {
    match mode {
        Some(VpnMode::Hub(h)) => {
            let m = h.metrics();
            let prom = format!(
                "# HELP ghost_vpn_active_leases VPN hub: active overlay leases\n\
                 # TYPE ghost_vpn_active_leases gauge\nghost_vpn_active_leases {}\n\
                 # HELP ghost_vpn_tunnel_frames_in_total VPN hub: tunnel frames received\n\
                 # TYPE ghost_vpn_tunnel_frames_in_total counter\nghost_vpn_tunnel_frames_in_total {}\n\
                 # HELP ghost_vpn_tunnel_frames_out_total VPN hub: tunnel frames sent\n\
                 # TYPE ghost_vpn_tunnel_frames_out_total counter\nghost_vpn_tunnel_frames_out_total {}\n\
                 # HELP ghost_vpn_frames_dropped_total VPN hub: tunnel frames dropped\n\
                 # TYPE ghost_vpn_frames_dropped_total counter\nghost_vpn_frames_dropped_total {}\n\
                 # HELP ghost_vpn_tcp_flows VPN hub: live netstack TCP flows\n\
                 # TYPE ghost_vpn_tcp_flows gauge\nghost_vpn_tcp_flows {}\n\
                 # HELP ghost_vpn_udp_flows VPN hub: live UDP flow bindings\n\
                 # TYPE ghost_vpn_udp_flows gauge\nghost_vpn_udp_flows {}\n\
                 # HELP ghost_vpn_counter_headroom_min VPN hub: smallest remaining per-epoch tunnel-counter headroom across leases\n\
                 # TYPE ghost_vpn_counter_headroom_min gauge\nghost_vpn_counter_headroom_min {}\n",
                m.leases,
                m.frames_in,
                m.frames_out,
                m.frames_dropped,
                m.tcp_flows,
                m.udp_flows,
                m.counter_headroom_min,
            );
            (
                "hub",
                prom,
                serde_json::json!({
                    "leases": m.leases,
                    "tcp_flows": m.tcp_flows,
                    "udp_flows": m.udp_flows,
                    "tunnel_frames_in": m.frames_in,
                    "tunnel_frames_out": m.frames_out,
                    "frames_dropped": m.frames_dropped,
                    "counter_headroom_min": m.counter_headroom_min,
                }),
            )
        }
        Some(VpnMode::Client(c, _)) => {
            let ctr = c.tx_counter();
            let headroom = u64::MAX.saturating_sub(ctr);
            let dead = c.watchdog.lock().is_dead();
            let prom = format!(
                "# HELP ghost_vpn_tx_counter VPN client: per-epoch tunnel TX counter\n\
                 # TYPE ghost_vpn_tx_counter gauge\nghost_vpn_tx_counter {ctr}\n\
                 # HELP ghost_vpn_counter_headroom VPN client: remaining tunnel-counter headroom\n\
                 # TYPE ghost_vpn_counter_headroom gauge\nghost_vpn_counter_headroom {headroom}\n\
                 # HELP ghost_vpn_epoch VPN client: current session epoch\n\
                 # TYPE ghost_vpn_epoch gauge\nghost_vpn_epoch {}\n\
                 # HELP ghost_vpn_watchdog_dead VPN client: 1 once the watchdog declares the tunnel dead\n\
                 # TYPE ghost_vpn_watchdog_dead gauge\nghost_vpn_watchdog_dead {}\n",
                c.current_epoch(),
                u8::from(dead),
            );
            (
                "client",
                prom,
                serde_json::json!({
                    "tx_counter": ctr,
                    "counter_headroom": headroom,
                    "epoch": c.current_epoch(),
                    "watchdog_dead": dead,
                }),
            )
        }
        None => ("disabled", String::new(), serde_json::json!({})),
    }
}

#[cfg(not(feature = "vpn"))]
pub fn vpn_export(_mode: &Option<VpnMode>) -> (&'static str, String, serde_json::Value) {
    ("disabled", String::new(), serde_json::json!({}))
}

/// Initializes the VPN subsystem based on the `GHOST_VPN` environment variable.
pub fn init_vpn_mode() -> anyhow::Result<Option<VpnMode>> {
    #[cfg(feature = "vpn")]
    {
        use std::time::Duration;
        use tokio::time::sleep;

        match std::env::var("GHOST_VPN").as_deref() {
            Ok("hub") => {
                let (subnet, prefix) = std::env::var("GHOST_VPN_LAN_SUBNET")
                    .ok()
                    .and_then(|s| {
                        let (a, pr) = s.split_once('/')?;
                        Some((
                            a.parse::<std::net::Ipv4Addr>().ok()?,
                            pr.parse::<u8>().ok()?,
                        ))
                    })
                    .unwrap_or((std::net::Ipv4Addr::new(192, 168, 1, 0), 24));
                let cfg = VpnConfig {
                    role: VpnRole::Hub,
                    lan_subnet: (subnet, prefix),
                    dns_server: std::env::var("GHOST_VPN_DNS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                    search_domain: std::env::var("GHOST_VPN_SEARCH")
                        .ok()
                        .filter(|x| !x.is_empty()),
                    allowed_fingerprints: std::env::var("GHOST_VPN_CLIENTS")
                        .ok()
                        .map(|v| {
                            v.split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    lan_bind_addr: std::env::var("GHOST_VPN_BIND")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    ..VpnConfig::default()
                };
                tracing::info!(
                    "VPN: hub mode — allowlisted clients: {}",
                    cfg.allowed_fingerprints.len()
                );
                Ok(Some(VpnMode::Hub(VpnHub::start(cfg))))
            }
            Ok("client") => {
                let hub_fp = std::env::var("GHOST_VPN_HUB_FP").unwrap_or_default();
                if hub_fp.is_empty() {
                    anyhow::bail!("VPN client requires GHOST_VPN_HUB_FP (hub fingerprint)");
                }
                let key: [u8; 32] = std::env::var("GHOST_VPN_KEY")
                    .ok()
                    .filter(|h| h.len() == 64)
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0u8; 32]);
                let local_ip: std::net::Ipv4Addr = std::env::var("GHOST_VPN_LOCAL_IP")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(std::net::Ipv4Addr::new(10, 66, 0, 10));
                let fake_tun = std::env::var("GHOST_VPN_FAKE_TUN")
                    .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                    .unwrap_or(false);
                let tun = if fake_tun {
                    tracing::warn!(
                        "VPN client: GHOST_VPN_FAKE_TUN is set — in-memory TUN, no OS interface \
                         is created and no traffic can leave this machine. Self-test mode only."
                    );
                    let (dev, handle) = open_fake_tun();
                    let hub_overlay = std::net::Ipv4Addr::new(
                        OVERLAY_PREFIX,
                        OVERLAY_SECOND_OCTET,
                        0,
                        OVERLAY_HUB_HOST,
                    );
                    tokio::spawn(async move {
                        let probe = vpn::client::build_keepalive(hub_overlay, local_ip);
                        let mut sent: u32 = 0;
                        let mut replies_total: u32 = 0;
                        loop {
                            sleep(Duration::from_millis(1000)).await;
                            handle.push_inbound(probe.clone());
                            sent += 1;
                            let mut replies = 0u32;
                            for pkt in handle.drain_outbound() {
                                if pkt.len() >= 21 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 0
                                {
                                    replies += 1;
                                }
                            }
                            if replies > 0 {
                                replies_total += replies;
                                tracing::info!(
                                    sent, replies, replies_total,
                                    "FAKE-TUN self-test: PASS — ICMP echo reply returned through the mesh"
                                );
                            } else {
                                tracing::info!(sent, "FAKE-TUN self-test: probe sent, no reply yet");
                            }
                        }
                    });
                    Arc::new(std::sync::Mutex::new(dev))
                } else {
                    open_tun("ggn0", local_ip, std::net::Ipv4Addr::new(255, 255, 255, 0))
                        .map(|t| Arc::new(std::sync::Mutex::new(t)))
                        .map_err(|e| anyhow::anyhow!(
                            "VPN client: TUN unavailable ({e}) — run as Administrator with wintun.dll \
                             present, or set GHOST_VPN_FAKE_TUN=1 for the zero-elevation loopback self-test"
                        ))?
                };
                tracing::info!("VPN: client mode — hub {hub_fp}, TUN {local_ip}");
                Ok(Some(VpnMode::Client(
                    Arc::new(vpn::client::ClientState::new(hub_fp, key)),
                    tun,
                )))
            }
            _ => Ok(None),
        }
    }
    #[cfg(not(feature = "vpn"))]
    {
        Ok(None)
    }
}
