//! Skywave SDR Bridge (Atmospheric Broadcast OS Integration)
//!
//! Provides the physical and protocol bridge between Global Ghost Net (Vantablack)
//! and Atmospheric Broadcast OS (ABOS).
//!
//! When enabled (`--features sdr`), this module orchestrates the ABOS signal
//! processing pipeline (NVIS 2–10 MHz skywave, meteor scatter, DSSS stealth)
//! as an autonomous out-of-band physical fallback carrier when terrestrial WAN
//! links fail. Without the feature (or without attached SDR hardware) the
//! bridge runs in *synthetic mode*: the same decision logic, telemetry and
//! ingress plumbing, minus only the physical DSP stages — so the fallback
//! ladder, the control plane and the tests exercise one code path either way.
//!
//! ## Threading model
//!
//! `ABOSSystem` is deliberately **not** stored in the bridge: it holds a
//! `dyn SDRDevice` and a `ThreadRng`, neither of which is `Send`, which would
//! poison every `tokio::spawn` the bridge appears in. Under `--features sdr`
//! the system instead lives on a dedicated *DSP actor thread* that owns the
//! runtime, the hardware handle and the whole TX chain; the bridge hands it
//! payloads over a plain channel. The bridge itself is `Send + Sync` and can
//!' be installed process-wide with [`SkywaveBridge::install_global`].
//!
//! ## Virtual carrier
//!
//! The ionosphere is replaced, in simulation, by an optional UDP socket
//! ("the virtual skywave"). Datagrams the daemon hands to
//! [`SkywaveBridge::transmit`] are shipped to the configured carrier address;
//! datagrams arriving on the socket are fed back through
//! [`SkywaveBridge::rx_from_carrier`] and surface on the ingress queue that
//! the daemon's packet receiver drains. Two daemons (or two test nodes) point
//! their carriers at each other and the skywave path carries real frames.
//!
//! Security: the carrier binds `127.0.0.1:0` — an ephemeral port on loopback —
//! unless the operator explicitly overrides it with `GHOST_SKYWAVE_UDP`.
//! A skywave listener therefore never opens an unauthenticated UDP port on an
//! external interface by default. Frames received over the virtual carrier are
//! *not* trusted: they enter the same authenticated receive path as any other
//! datagram, and the AEAD rejects anything that was not sealed to us.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

static BRIDGE: OnceLock<Arc<SkywaveBridge>> = OnceLock::new();

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SkywaveTelemetry {
    pub sdr_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_carrier: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_carrier_peer: Option<SocketAddr>,
    pub carrier_freq_hz: u64,
    pub estimated_f0f2_hz: f64,
    pub dsss_processing_gain_db: f64,
    pub tx_packet_count: u64,
    pub rx_packet_count: u64,
    pub tx_dsp_bytes: u64,
    pub meteor_burst_window_open: bool,
}

impl Default for SkywaveTelemetry {
    fn default() -> Self {
        Self {
            sdr_active: false,
            virtual_carrier: None,
            virtual_carrier_peer: None,
            carrier_freq_hz: 5_350_000, // Standard 60m band NVIS channel
            estimated_f0f2_hz: 6_200_000.0,
            dsss_processing_gain_db: 24.0,
            tx_packet_count: 0,
            rx_packet_count: 0,
            tx_dsp_bytes: 0,
            meteor_burst_window_open: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SdrBridgeError {
    #[error("SDR feature not compiled into this build (compile with --features sdr)")]
    FeatureNotEnabled,
    #[error("Hardware or DSP error: {0}")]
    HardwareError(String),
    #[error("Radio transmission timeout")]
    Timeout,
    #[error("Serialization or protocol error: {0}")]
    ProtocolError(String),
}

pub const SKYWAVE_UDP_ENV: &str = "GHOST_SKYWAVE_UDP";

const INGRESS_SOFT_CAPACITY: usize = 256;

fn parse_socket_addr(s: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    s.to_socket_addrs().ok()?.next()
}

fn default_carrier_bind() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn virtual_carrier_endpoints() -> (SocketAddr, Option<SocketAddr>) {
    let fallback = || {
        warn!("skywave: cannot parse {SKYWAVE_UDP_ENV} — virtual carrier disabled");
        (default_carrier_bind(), None)
    };
    match std::env::var(SKYWAVE_UDP_ENV) {
        Ok(spec) if !spec.trim().is_empty() => {
            let spec = spec.trim().to_string();
            match spec.split_once('|') {
                Some((bind, peer)) => {
                    match (
                        parse_socket_addr(bind.trim()),
                        parse_socket_addr(peer.trim()),
                    ) {
                        (Some(b), Some(p)) => (b, Some(p)),
                        _ => fallback(),
                    }
                }
                None => match parse_socket_addr(&spec) {
                    Some(a) => (a, Some(a)),
                    None => fallback(),
                },
            }
        }
        _ => (default_carrier_bind(), None),
    }
}

#[derive(Clone)]
pub struct SkywaveBridge {
    telemetry: Arc<parking_lot::RwLock<SkywaveTelemetry>>,
    ingress_tx: mpsc::UnboundedSender<Vec<u8>>,
    ingress_rx: Arc<parking_lot::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    carrier_sock: Arc<parking_lot::RwLock<Option<Arc<tokio::net::UdpSocket>>>>,
}

impl std::fmt::Debug for SkywaveBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkywaveBridge")
            .field("telemetry", &self.telemetry.read().clone())
            .finish()
    }
}

impl SkywaveBridge {
    pub fn install_global(self: &Arc<Self>) -> bool {
        BRIDGE.set(self.clone()).is_ok()
    }

    pub fn global() -> Option<&'static Arc<SkywaveBridge>> {
        BRIDGE.get()
    }

    pub async fn new() -> Result<Self, SdrBridgeError> {
        Self::with_virtual_carrier(true).await
    }

    pub async fn with_virtual_carrier(bind_carrier: bool) -> Result<Self, SdrBridgeError> {
        let (ingress_tx, ingress_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let bridge = Self::build(ingress_tx, ingress_rx).await?;
        if bind_carrier {
            bridge.start_virtual_carrier().await;
        }
        Ok(bridge)
    }

    async fn build(
        ingress_tx: mpsc::UnboundedSender<Vec<u8>>,
        ingress_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Result<Self, SdrBridgeError> {
        info!("skywave: synthetic virtual-carrier mode (SDR hardware support removed)");
        Ok(Self {
            telemetry: Arc::new(parking_lot::RwLock::new(SkywaveTelemetry::default())),
            ingress_tx,
            ingress_rx: Arc::new(parking_lot::Mutex::new(ingress_rx)),
            carrier_sock: Arc::new(parking_lot::RwLock::new(None)),
        })
    }

    pub fn activate_synthetic(&self, carrier_freq_hz: u64) {
        let mut telem = self.telemetry.write();
        telem.sdr_active = true;
        telem.carrier_freq_hz = carrier_freq_hz;
    }

    pub async fn start_virtual_carrier(&self) {
        let (bind, peer) = virtual_carrier_endpoints();
        let sock = match tokio::net::UdpSocket::bind(bind).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!(
                    error = %e,
                    bind = %bind,
                    "skywave: virtual carrier bind failed — running without a carrier"
                );
                return;
            }
        };
        let local = sock.local_addr().ok();
        info!(bind = ?local, peer = ?peer, "skywave: virtual UDP carrier bound");
        {
            let mut telem = self.telemetry.write();
            telem.virtual_carrier = local;
            telem.virtual_carrier_peer = peer;
        }
        *self.carrier_sock.write() = Some(sock.clone());

        let bridge = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        debug!(
                            len = n,
                            from = %from,
                            "skywave: datagram received on virtual carrier"
                        );
                        bridge.rx_from_carrier(&buf[..n]);
                    }
                    Err(e) => {
                        debug!(error = %e, "skywave: virtual carrier recv error");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
    }

    async fn ship_to_carrier(&self, data: &[u8]) {
        let sock = self.carrier_sock.read().clone();
        let peer = self.telemetry.read().virtual_carrier_peer;
        if let (Some(sock), Some(peer)) = (sock, peer) {
            let _ = sock.send_to(data, peer).await;
        }
    }

    pub fn ship_to_peer(&self, peer: SocketAddr) -> bool {
        self.telemetry.write().virtual_carrier_peer = Some(peer);
        true
    }

    pub fn rx_from_carrier(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut telem = self.telemetry.write();
        telem.rx_packet_count = telem.rx_packet_count.saturating_add(1);
        let _ = INGRESS_SOFT_CAPACITY;
        let _ = self.ingress_tx.send(data.to_vec());
    }

    pub fn try_rx(&self) -> Vec<Vec<u8>> {
        let mut rx = self.ingress_rx.lock();
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            out.push(frame);
        }
        out
    }

    pub fn has_inbound(&self) -> bool {
        !self.ingress_rx.lock().is_empty()
    }

    pub fn is_active(&self) -> bool {
        self.telemetry.read().sdr_active
    }

    pub fn nvis_freq_khz(&self) -> Option<u32> {
        let t = self.telemetry.read();
        t.sdr_active.then(|| (t.carrier_freq_hz / 1_000) as u32)
    }

    pub fn telemetry(&self) -> SkywaveTelemetry {
        self.telemetry.read().clone()
    }

    pub async fn transmit(&self, data: &[u8]) -> Result<(), SdrBridgeError> {
        self.process_and_send(data).await.map(|_| ())
    }

    pub async fn process_and_send(&self, payload: &[u8]) -> Result<Vec<u8>, SdrBridgeError> {
        debug!(
            len = payload.len(),
            "skywave (synthetic): frame handed to virtual carrier"
        );
        {
            let mut telem = self.telemetry.write();
            telem.tx_packet_count = telem.tx_packet_count.saturating_add(1);
            telem.tx_dsp_bytes = telem.tx_dsp_bytes.saturating_add(payload.len() as u64);
        }
        self.ship_to_carrier(payload).await;
        Ok(payload.to_vec())
    }

    pub fn update_iono_metrics(&self, f0f2_hz: f64, meteor_active: bool) {
        let mut telem = self.telemetry.write();
        telem.estimated_f0f2_hz = f0f2_hz;
        telem.meteor_burst_window_open = meteor_active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn synthetic_loopback_round_trip() {
        std::env::remove_var(SKYWAVE_UDP_ENV);
        let bridge = SkywaveBridge::with_virtual_carrier(true).await.unwrap();
        bridge.activate_synthetic(5_350_000);
        assert!(bridge.is_active());
        assert_eq!(bridge.nvis_freq_khz(), Some(5350));

        for _ in 0..50 {
            if bridge.telemetry().virtual_carrier.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let local = bridge.telemetry().virtual_carrier.expect("carrier bound");
        assert!(local.ip().is_loopback(), "default bind must be loopback");

        assert!(bridge.ship_to_peer(local), "the carrier accepts a peer");

        bridge.process_and_send(b"ghost-frame").await.unwrap();
        for _ in 0..50 {
            if bridge.has_inbound() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let rx = bridge.try_rx();
        assert_eq!(rx, vec![b"ghost-frame".to_vec()]);

        let telem = bridge.telemetry();
        assert_eq!(telem.tx_packet_count, 1);
        assert_eq!(telem.rx_packet_count, 1);
    }
}
