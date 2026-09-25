//! Skywave SDR Bridge (Atmospheric Broadcast OS Integration)
//!
//! Provides the physical and protocol bridge between Global Ghost Net (Vantablack)
//! and Atmospheric Broadcast OS (ABOS).
//!
//! When enabled (`--features sdr`), this module orchestrates the ABOS SDR hardware
//! and signal processing pipeline (NVIS 2–10 MHz skywave, meteor scatter, DSSS stealth)
//! as an autonomous out-of-band physical fallback carrier when terrestrial WAN links fail.

use std::sync::Arc;

#[cfg(feature = "sdr")]
use abos::ABOSSystem;
#[cfg(feature = "sdr")]
use tokio::sync::Mutex;
#[cfg(feature = "sdr")]
use tracing::{debug, error, info, warn};


/// Telemetry metrics for the Skywave ionospheric radio interface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SkywaveTelemetry {
    pub sdr_active: bool,
    pub carrier_freq_hz: u64,
    pub estimated_f0f2_hz: f64,
    pub dsss_processing_gain_db: f64,
    pub tx_packet_count: u64,
    pub rx_packet_count: u64,
    pub meteor_burst_window_open: bool,
}

impl Default for SkywaveTelemetry {
    fn default() -> Self {
        Self {
            sdr_active: false,
            carrier_freq_hz: 5_350_000, // Standard 60m band NVIS channel
            estimated_f0f2_hz: 6_200_000.0,
            dsss_processing_gain_db: 24.0,
            tx_packet_count: 0,
            rx_packet_count: 0,
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

/// The bridge controller managing ionospheric SDR communication.
#[derive(Clone)]
pub struct SkywaveBridge {
    #[cfg(feature = "sdr")]
    inner: Arc<Mutex<Option<ABOSSystem>>>,
    telemetry: Arc<parking_lot::RwLock<SkywaveTelemetry>>,
}

impl std::fmt::Debug for SkywaveBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkywaveBridge")
            .field("telemetry", &self.telemetry.read().clone())
            .finish()
    }
}

impl SkywaveBridge {
    /// Initialize a new SkywaveBridge instance.
    pub async fn new() -> Result<Self, SdrBridgeError> {
        #[cfg(feature = "sdr")]
        {
            info!("skywave: initializing Atmospheric Broadcast OS (ABOS) SDR bridge...");
            match ABOSSystem::new().await {
                Ok(mut system) => {
                    let _ = system.start().await;
                    info!("skywave: ABOS SDR physical layer online and listening on NVIS HF channels");
                    let mut telem = SkywaveTelemetry::default();
                    telem.sdr_active = true;
                    Ok(Self {
                        inner: Arc::new(Mutex::new(Some(system))),
                        telemetry: Arc::new(parking_lot::RwLock::new(telem)),
                    })
                }
                Err(e) => {
                    warn!(error = %e, "skywave: SDR hardware not attached or failed to initialize, running in synthetic mode");
                    Ok(Self {
                        inner: Arc::new(Mutex::new(None)),
                        telemetry: Arc::new(parking_lot::RwLock::new(SkywaveTelemetry::default())),
                    })
                }
            }
        }

        #[cfg(not(feature = "sdr"))]
        {
            Ok(Self {
                telemetry: Arc::new(parking_lot::RwLock::new(SkywaveTelemetry::default())),
            })
        }
    }

    /// Check if the SDR radio stack is currently active.
    pub fn is_active(&self) -> bool {
        self.telemetry.read().sdr_active
    }

    /// Query live skywave radio telemetry.
    pub fn telemetry(&self) -> SkywaveTelemetry {
        self.telemetry.read().clone()
    }

    /// Transmit a Ghost Transport Frame or DTN bundle across the ionosphere via ABOS.
    pub async fn transmit(&self, data: &[u8]) -> Result<(), SdrBridgeError> {
        #[cfg(feature = "sdr")]
        {
            let mut guard = self.inner.lock().await;
            if let Some(system) = guard.as_mut() {
                debug!(len = data.len(), "skywave: transmitting packet through NVIS / DSSS pipeline");
                system.transmit(data).await.map_err(|e| {
                    error!(error = %e, "skywave: transmit failed");
                    SdrBridgeError::HardwareError(e.to_string())
                })?;
                let mut telem = self.telemetry.write();
                telem.tx_packet_count += 1;
                return Ok(());
            } else {
                debug!(len = data.len(), "skywave (synthetic): packet transmitted to mock skywave medium");
                let mut telem = self.telemetry.write();
                telem.tx_packet_count += 1;
                return Ok(());
            }
        }

        #[cfg(not(feature = "sdr"))]
        {
            let _ = data;
            Err(SdrBridgeError::FeatureNotEnabled)
        }
    }

    /// Update cognitive ionospheric telemetry (critical frequency f0F2, meteor windows).
    pub fn update_iono_metrics(&self, f0f2_hz: f64, meteor_active: bool) {
        let mut telem = self.telemetry.write();
        telem.estimated_f0f2_hz = f0f2_hz;
        telem.meteor_burst_window_open = meteor_active;
    }
}
