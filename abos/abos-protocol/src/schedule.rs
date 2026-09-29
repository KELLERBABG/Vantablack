/// Phoenix Window Scheduler: opportunistic transmission for meteor scatter
///
/// The OS does not always transmit. It listens for a beacon signal.
/// Once an SNR peak is detected (meteor trail ionization), the scheduler
/// switches to transmit mode and blasts handshake shards at maximum
/// symbol rate before the trail collapses (typically milliseconds to seconds).
pub struct PhoenixScheduler {
    pub snr_threshold: f64,
    pub window_open: bool,
    window_start: Option<u64>,
    window_duration_estimate: f64, // seconds, based on typical meteor trail lifetime
    snr_history: Vec<f64>,
}

impl PhoenixScheduler {
    pub fn new(snr_threshold: f64) -> Self {
        Self {
            snr_threshold,
            window_open: false,
            window_start: None,
            window_duration_estimate: 0.5, // typical meteor burst: 100ms - few seconds
            snr_history: Vec::new(),
        }
    }

    /// Detect if a transmission window has opened based on SNR peak
    pub fn detect_window(&mut self, snr: f64) -> bool {
        self.snr_history.push(snr);
        if self.snr_history.len() > 100 {
            self.snr_history.remove(0);
        }

        if !self.window_open && snr > self.snr_threshold {
            self.window_open = true;
            self.window_start = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            );
            return true;
        }

        // Close window if SNR has collapsed
        if self.window_open && snr < self.snr_threshold * 0.5 {
            self.window_open = false;
            self.window_start = None;
        }

        false
    }

    /// Get remaining time in current transmission window (seconds)
    pub fn transmit_window_remaining(&self) -> f64 {
        if let Some(start) = self.window_start {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let elapsed = (now.saturating_sub(start)) as f64 / 1000.0;
            (self.window_duration_estimate - elapsed).max(0.0)
        } else {
            0.0
        }
    }

    /// Force close the current window
    pub fn close_window(&mut self) {
        self.window_open = false;
        self.window_start = None;
    }
}
