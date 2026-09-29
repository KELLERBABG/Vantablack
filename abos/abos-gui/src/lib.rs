//! ABOS dashboard state (headless, fully testable without a display).
//!
//! The GUI crate separates *what the dashboard shows* ([`GuiState`],
//! updated from `ABOSSystem` or the simulation harness) from *how it is
//! drawn* (the `gui` feature's egui widgets). This keeps `cargo test
//! --workspace` display-free while still unit-testing every dashboard rule.

pub mod view;

/// One plotted spectrum bin.
#[derive(Debug, Clone, PartialEq)]
pub struct SpectrumPoint {
    /// Bin index.
    pub index: usize,
    /// Normalized power (0.0–1.0).
    pub power: f64,
}

/// A mesh peer row for the dashboard table.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerRow {
    /// Hex node id (lowercase, 64 chars).
    pub node_id: String,
    /// Alias shown in the table.
    pub alias: String,
    /// Seconds since last beacon.
    pub last_seen_secs: u64,
    /// Beacons observed.
    pub beacon_count: u64,
}

/// Severity for the log tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Informational event.
    Info,
    /// Recoverable problem.
    Warn,
    /// Failure.
    Error,
}

/// One log line in the tail view.
#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    /// Severity.
    pub level: LogLevel,
    /// Message text.
    pub message: String,
}

/// Everything the dashboard renders. Pure data — no egui types.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GuiState {
    /// Hex id of the local node.
    pub node_id: String,
    /// Whether the SDR stream is running.
    pub running: bool,
    /// Center frequency in Hz.
    pub center_frequency_hz: u64,
    /// Sample rate in sps.
    pub sample_rate_sps: f64,
    /// TX gain in dB.
    pub tx_gain_db: f64,
    /// RX gain in dB.
    pub rx_gain_db: f64,
    /// Current MCS name.
    pub mcs: String,
    /// Live mesh peers.
    pub peers: Vec<PeerRow>,
    /// Bundles awaiting ACK.
    pub pending_acks: usize,
    /// Bundles in persistent store.
    pub stored_bundles: usize,
    /// Latest spectrum (already normalized).
    pub spectrum: Vec<SpectrumPoint>,
    /// Rolling white-space regions as (start_bin, end_bin).
    pub whitespace: Vec<(usize, usize)>,
    /// Log tail, newest last.
    pub log: Vec<LogLine>,
    /// Last noise-floor estimate.
    pub noise_floor: f64,
}

impl GuiState {
    /// Cap on retained log lines.
    pub const LOG_CAP: usize = 200;

    /// Append a log line, evicting the oldest beyond [`Self::LOG_CAP`].
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.log.push(LogLine {
            level,
            message: message.into(),
        });
        if self.log.len() > Self::LOG_CAP {
            let overflow = self.log.len() - Self::LOG_CAP;
            self.log.drain(0..overflow);
        }
    }

    /// Feed raw PSD bins; normalizes to 0..=1 against the current max.
    pub fn update_spectrum(&mut self, psd: &[f64]) {
        let max = psd.iter().cloned().fold(f64::MIN, f64::max);
        if !max.is_finite() || max <= 0.0 {
            self.spectrum.clear();
            return;
        }
        self.spectrum = psd
            .iter()
            .enumerate()
            .map(|(index, &power)| SpectrumPoint {
                index,
                power: power / max,
            })
            .collect();
    }

    /// Recompute white-space regions above `noise_floor * margin`.
    pub fn update_whitespace(&mut self, psd: &[f64], noise_floor: f64, margin: f64) {
        self.noise_floor = noise_floor;
        let threshold = noise_floor * margin;
        self.whitespace.clear();
        let mut start: Option<usize> = None;
        for (i, &p) in psd.iter().enumerate() {
            if p < threshold {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                self.whitespace.push((s, i - 1));
            }
        }
        if let Some(s) = start {
            self.whitespace.push((s, psd.len().saturating_sub(1)));
        }
    }

    /// Overall status line for the header bar.
    pub fn status_text(&self) -> String {
        if self.running {
            format!(
                "ON AIR — {:.3} MHz, {}, {} peers",
                self.center_frequency_hz as f64 / 1e6,
                self.mcs,
                self.peers.len()
            )
        } else {
            "IDLE".to_string()
        }
    }

    /// Count of error lines currently in the tail.
    pub fn error_count(&self) -> usize {
        self.log
            .iter()
            .filter(|l| l.level == LogLevel::Error)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spectrum_normalizes_against_peak() {
        let mut state = GuiState::default();
        state.update_spectrum(&[1.0, 3.0, 0.5]);
        assert_eq!(state.spectrum.len(), 3);
        assert!((state.spectrum[1].power - 1.0).abs() < 1e-12);
        assert!((state.spectrum[0].power - 1.0 / 3.0).abs() < 1e-12);
        assert_eq!(state.spectrum[2].index, 2);
    }

    #[test]
    fn spectrum_handles_degenerate_input() {
        let mut state = GuiState::default();
        state.update_spectrum(&[]);
        assert!(state.spectrum.is_empty());
        state.update_spectrum(&[0.0, 0.0]);
        assert!(state.spectrum.is_empty(), "all-zero PSD yields no plot");
        state.update_spectrum(&[f64::NAN]);
        assert!(state.spectrum.is_empty(), "NaN PSD yields no plot");
    }

    #[test]
    fn whitespace_detection_finds_quiet_regions() {
        let mut state = GuiState::default();
        // noisy, noisy, quiet, quiet, quiet, noisy
        let psd = vec![10.0, 12.0, 1.0, 1.0, 1.0, 9.0];
        state.update_whitespace(&psd, 2.0, 2.0); // threshold = 4.0
        assert_eq!(state.whitespace, vec![(2, 4)]);
    }

    #[test]
    fn whitespace_all_quiet_spans_everything() {
        let mut state = GuiState::default();
        state.update_whitespace(&[1.0, 1.0, 1.0], 5.0, 1.5);
        assert_eq!(state.whitespace, vec![(0, 2)]);
    }

    #[test]
    fn log_tail_caps_at_limit() {
        let mut state = GuiState::default();
        for i in 0..(GuiState::LOG_CAP + 25) {
            state.log(LogLevel::Info, format!("line {}", i));
        }
        assert_eq!(state.log.len(), GuiState::LOG_CAP);
        assert_eq!(state.log.first().unwrap().message, "line 25");
        assert_eq!(
            state.log.last().unwrap().message,
            format!("line {}", GuiState::LOG_CAP + 24)
        );
    }

    #[test]
    fn status_text_reflects_running_and_idle() {
        let mut state = GuiState::default();
        assert_eq!(state.status_text(), "IDLE");
        state.running = true;
        state.center_frequency_hz = 7_100_000;
        state.mcs = "QPSK-1/2".into();
        let text = state.status_text();
        assert!(text.contains("ON AIR"));
        assert!(text.contains("7.100 MHz"));
        assert!(text.contains("QPSK-1/2"));
    }

    #[test]
    fn error_count_tracks_severity() {
        let mut state = GuiState::default();
        state.log(LogLevel::Info, "ok");
        state.log(LogLevel::Warn, "meh");
        state.log(LogLevel::Error, "boom");
        state.log(LogLevel::Error, "boom2");
        assert_eq!(state.error_count(), 2);
    }

    #[test]
    fn peer_rows_render_key() {
        let mut state = GuiState::default();
        state.peers.push(PeerRow {
            node_id: "ab".repeat(32),
            alias: "ghost-1".into(),
            last_seen_secs: 12,
            beacon_count: 4,
        });
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].node_id.len(), 64);
        assert_eq!(state.status_text(), "IDLE"); // peers don't imply running
    }
}
