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

#[cfg(feature = "sdr")]
use abos::ABOSSystem;
#[cfg(feature = "sdr")]
use tracing::error;

/// The process-wide bridge, installed once at daemon boot. Egress paths and
/// the control plane read this instead of threading a handle through every
/// signature; `None` means the run has no skywave carrier and every skywave
/// route fails honestly.
static BRIDGE: OnceLock<Arc<SkywaveBridge>> = OnceLock::new();

/// Telemetry metrics for the Skywave ionospheric radio interface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SkywaveTelemetry {
    pub sdr_active: bool,
    /// `Some(addr)` when the virtual UDP carrier is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_carrier: Option<SocketAddr>,
    /// Address outbound virtual-carrier datagrams are shipped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_carrier_peer: Option<SocketAddr>,
    pub carrier_freq_hz: u64,
    pub estimated_f0f2_hz: f64,
    pub dsss_processing_gain_db: f64,
    pub tx_packet_count: u64,
    pub rx_packet_count: u64,
    /// Bytes pushed through the TX path (DSP chain in `sdr` builds).
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

/// Errors occurring across the SDR ionospheric bridge.
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

/// Environment override for the virtual skywave carrier bind address.
///
/// Unset/empty → loopback ephemeral. One `<addr:port>` → bind there *and*
/// loop outbound datagrams back to the same socket (single-node testing).
/// `<bind>|<peer>` → asymmetric two-node carrier: bind the first, ship to the
/// second.
pub const SKYWAVE_UDP_ENV: &str = "GHOST_SKYWAVE_UDP";

/// Soft bound on queued skywave ingress. The channel is unbounded — a stuck
/// receiver must never stall the carrier loop — but the daemon drains it every
/// receive tick, so steady state stays far below this.
const INGRESS_SOFT_CAPACITY: usize = 256;

/// How long boot waits for the DSP actor to report the ABOS system online.
#[cfg(feature = "sdr")]
const DSP_ONLINE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn parse_socket_addr(s: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    s.to_socket_addrs().ok()?.next()
}

fn default_carrier_bind() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// Resolve the virtual-carrier endpoints from `GHOST_SKYWAVE_UDP`.
///
/// Returns `(bind, peer)`. The default is loopback ephemeral with no peer —
/// outbound datagrams go nowhere unless a peer is configured, and the listener
/// is never reachable off this machine.
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
                    // Single address: bind it and loop back to it (self-loop).
                    Some(a) => (a, Some(a)),
                    None => fallback(),
                },
            }
        }
        _ => (default_carrier_bind(), None),
    }
}

/// The bridge controller managing ionospheric SDR communication.
///
/// `Clone` is cheap: everything behind it is an `Arc`.
#[derive(Clone)]
pub struct SkywaveBridge {
    telemetry: Arc<parking_lot::RwLock<SkywaveTelemetry>>,
    ingress_tx: mpsc::UnboundedSender<Vec<u8>>,
    ingress_rx: Arc<parking_lot::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    /// Persistent outbound socket for the virtual carrier, if started.
    carrier_sock: Arc<parking_lot::RwLock<Option<Arc<tokio::net::UdpSocket>>>>,
    /// Handle to the DSP actor thread (feature `sdr` only). `None` when the
    /// ABOS system failed to come online and the bridge runs synthetic.
    #[cfg(feature = "sdr")]
    dsp_tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
}

impl std::fmt::Debug for SkywaveBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkywaveBridge")
            .field("telemetry", &self.telemetry.read().clone())
            .finish()
    }
}

/// Spawn the ABOS DSP actor thread and wait for it to report system state.
///
/// The actor owns the whole `ABOSSystem` for the process lifetime: a non-Send
/// type behind a thread boundary is the one arrangement that lets the bridge
/// stay `Send + Sync`. Returns the payload channel when the system is online.
#[cfg(feature = "sdr")]
fn spawn_dsp_actor() -> Option<std::sync::mpsc::Sender<Vec<u8>>> {
    let (payload_tx, payload_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (online_tx, online_rx) = std::sync::mpsc::channel::<bool>();

    let spawned = std::thread::Builder::new()
        .name("abos-dsp".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = online_tx.send(false);
                    error!(error = %e, "skywave: DSP actor runtime failed");
                    return;
                }
            };
            match rt.block_on(ABOSSystem::new()) {
                Ok(mut system) => {
                    let _ = rt.block_on(system.start());
                    let _ = online_tx.send(true);
                    info!("skywave: ABOS DSP actor online — full TX chain owned by the actor thread");
                    for payload in payload_rx {
                        if let Err(e) = rt.block_on(system.transmit(&payload)) {
                            error!(error = %e, "skywave: DSP transmit failed");
                        }
                    }
                }
                Err(e) => {
                    let _ = online_tx.send(false);
                    warn!(
                        error = %e,
                        "skywave: ABOS system init failed — DSP actor runs synthetic (frames discarded)"
                    );
                    // Drain so senders never block, discarding the frames: the
                    // bridge keeps shipping to the virtual carrier, which is
                    // where the loop actually lives in synthetic mode.
                    for _ in payload_rx {}
                }
            }
        });

    if spawned.is_err() {
        error!("skywave: could not spawn the DSP actor thread");
        return None;
    }
    match online_rx.recv_timeout(DSP_ONLINE_TIMEOUT) {
        Ok(true) => Some(payload_tx),
        Ok(false) | Err(_) => None,
    }
}

impl SkywaveBridge {
    /// Install this bridge as the process-wide carrier (daemon boot).
    /// Returns `false` if a bridge was already installed.
    pub fn install_global(self: &Arc<Self>) -> bool {
        BRIDGE.set(self.clone()).is_ok()
    }

    /// The process-wide bridge, if one was installed.
    pub fn global() -> Option<&'static Arc<SkywaveBridge>> {
        BRIDGE.get()
    }

    /// Initialize a new SkywaveBridge instance (virtual carrier included).
    pub async fn new() -> Result<Self, SdrBridgeError> {
        Self::with_virtual_carrier(true).await
    }

    /// Initialize the bridge, optionally starting the virtual UDP carrier.
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
        #[cfg(feature = "sdr")]
        {
            info!("skywave: initializing Atmospheric Broadcast OS (ABOS) SDR bridge...");
            let dsp_tx = spawn_dsp_actor();
            if dsp_tx.is_some() {
                info!("skywave: ABOS SDR physical layer online and listening on NVIS HF channels");
            } else {
                warn!(
                    "skywave: ABOS system not available — running in synthetic mode (virtual carrier only)"
                );
            }
            let mut telem = SkywaveTelemetry::default();
            telem.sdr_active = dsp_tx.is_some();
            Ok(Self {
                telemetry: Arc::new(parking_lot::RwLock::new(telem)),
                ingress_tx,
                ingress_rx: Arc::new(parking_lot::Mutex::new(ingress_rx)),
                carrier_sock: Arc::new(parking_lot::RwLock::new(None)),
                dsp_tx,
            })
        }

        #[cfg(not(feature = "sdr"))]
        {
            // Synthetic mode without the `sdr` feature: the fallback ladder,
            // telemetry and the virtual carrier stay fully functional; only the
            // DSP stages are skipped. `sdr_active` stays false, so the ladder
            // never selects skywave unless the operator turns the synthetic
            // carrier on deliberately (see `activate_synthetic`).
            info!(
                "skywave: synthetic mode — no DSP (compile with --features sdr for the ABOS chain)"
            );
            Ok(Self {
                telemetry: Arc::new(parking_lot::RwLock::new(SkywaveTelemetry::default())),
                ingress_tx,
                ingress_rx: Arc::new(parking_lot::Mutex::new(ingress_rx)),
                carrier_sock: Arc::new(parking_lot::RwLock::new(None)),
            })
        }
    }

    /// Mark the synthetic carrier as active for the fallback ladder.
    ///
    /// Used by tests and by operators who want the skywave rung without the
    /// `sdr` feature. The production build flips this on when an ABOS system
    /// attaches; synthetic activation is always explicit.
    pub fn activate_synthetic(&self, carrier_freq_hz: u64) {
        let mut telem = self.telemetry.write();
        telem.sdr_active = true;
        telem.carrier_freq_hz = carrier_freq_hz;
    }

    /// Bind the virtual UDP carrier socket and start its receive loop.
    ///
    /// Default bind is `127.0.0.1:0` (loopback, ephemeral port) so no
    /// unauthenticated listener ever appears on an external interface unless
    /// `GHOST_SKYWAVE_UDP` explicitly says so.
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

    /// Ship a datagram to the configured carrier peer (if any).
    async fn ship_to_carrier(&self, data: &[u8]) {
        let sock = self.carrier_sock.read().clone();
        let peer = self.telemetry.read().virtual_carrier_peer;
        if let (Some(sock), Some(peer)) = (sock, peer) {
            // Best effort: a lost skywave frame is a lost radio packet; the
            // upper layers treat the carrier as lossy by design.
            let _ = sock.send_to(data, peer).await;
        }
    }

    /// Point the virtual carrier at `peer` after the fact (tests, or an
    /// operator who learns the peer's carrier address at runtime).
    pub fn ship_to_peer(&self, peer: SocketAddr) -> bool {
        self.telemetry.write().virtual_carrier_peer = Some(peer);
        true
    }

    /// Feed a datagram that "arrived over the air" into the ingress queue.
    ///
    /// This is the seam every future physical receiver plugs into: an SDR RX
    /// thread calls this with decoded payloads, exactly as the virtual UDP
    /// carrier does.
    pub fn rx_from_carrier(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut telem = self.telemetry.write();
        telem.rx_packet_count += 1;
        let _ = INGRESS_SOFT_CAPACITY;
        let _ = self.ingress_tx.send(data.to_vec());
    }

    /// Take datagrams that arrived over the skywave (drains the ingress queue).
    pub fn try_rx(&self) -> Vec<Vec<u8>> {
        let mut rx = self.ingress_rx.lock();
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            out.push(frame);
        }
        out
    }

    /// Whether an ingress datagram is waiting (non-blocking poll).
    pub fn has_inbound(&self) -> bool {
        !self.ingress_rx.lock().is_empty()
    }

    /// Check if the SDR radio stack is currently active.
    pub fn is_active(&self) -> bool {
        self.telemetry.read().sdr_active
    }

    /// The NVIS frequency the bridge is tuned to, in kHz — `Some` exactly when
    /// the fallback ladder may select the skywave carrier.
    pub fn nvis_freq_khz(&self) -> Option<u32> {
        let t = self.telemetry.read();
        t.sdr_active.then(|| (t.carrier_freq_hz / 1_000) as u32)
    }

    /// Query live skywave radio telemetry.
    pub fn telemetry(&self) -> SkywaveTelemetry {
        self.telemetry.read().clone()
    }

    /// Transmit a Ghost Transport Frame or DTN bundle across the ionosphere via ABOS.
    pub async fn transmit(&self, data: &[u8]) -> Result<(), SdrBridgeError> {
        self.process_and_send(data).await.map(|_| ())
    }

    /// Transmit a payload through the TX path.
    ///
    /// `feature = "sdr"` + online system: the payload is handed to the DSP
    /// actor thread, which runs the full ABOS chain (shard split → bundle →
    /// scramble → interleave → LDPC → OFDM/DSSS → burst build → SDR TX).
    /// Synthetic mode: the frame is shipped over the virtual carrier unchanged.
    /// Either way the datagram is also shipped to the virtual carrier peer when
    /// one is configured, so loopback nodes and real radios converge on one
    /// code path.
    ///
    /// Returns the payload as handed to the medium — the wire-level unit tests
    /// round-trip against [`SkywaveBridge::rx_from_carrier`].
    pub async fn process_and_send(&self, payload: &[u8]) -> Result<Vec<u8>, SdrBridgeError> {
        #[cfg(feature = "sdr")]
        if let Some(dsp) = &self.dsp_tx {
            dsp.send(payload.to_vec()).map_err(|_| {
                SdrBridgeError::HardwareError("ABOS DSP actor thread is gone".to_string())
            })?;
            {
                let mut telem = self.telemetry.write();
                telem.tx_packet_count += 1;
                telem.tx_dsp_bytes += payload.len() as u64;
            }
            self.ship_to_carrier(payload).await;
            return Ok(payload.to_vec());
        }

        debug!(
            len = payload.len(),
            "skywave (synthetic): frame handed to virtual carrier"
        );
        {
            let mut telem = self.telemetry.write();
            telem.tx_packet_count += 1;
            telem.tx_dsp_bytes += payload.len() as u64;
        }
        self.ship_to_carrier(payload).await;
        Ok(payload.to_vec())
    }

    /// Update cognitive ionospheric telemetry (critical frequency f0F2, meteor windows).
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

        // Wait for the bind to land in telemetry.
        for _ in 0..50 {
            if bridge.telemetry().virtual_carrier.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let local = bridge.telemetry().virtual_carrier.expect("carrier bound");
        assert!(local.ip().is_loopback(), "default bind must be loopback");

        // The carrier has to be *told* where to send: `ship_to_carrier` requires
        // both a bound socket and a peer, and with neither the transmit path is a
        // silent no-op. Point it at itself, which is the self-loop this test
        // claims to exercise -- without this the round trip cannot happen at all
        // and the assertion below would be about an unsent frame.
        assert!(bridge.ship_to_peer(local), "the carrier accepts a peer");

        bridge.process_and_send(b"ghost-frame").await.unwrap();
        // Self-loop: the bound peer is the same socket, so the frame comes back.
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
