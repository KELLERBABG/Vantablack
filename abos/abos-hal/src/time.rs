use std::time::{SystemTime, UNIX_EPOCH};

/// GPS-disciplined oscillator timer
pub struct GPSDOTimer {
    /// Nominal frequency in Hz
    pub frequency_hz: f64,
}

impl GPSDOTimer {
    /// Create a new GPSDOTimer with the given reference frequency
    pub fn new(frequency_hz: f64) -> Self {
        Self { frequency_hz }
    }

    /// Return the GPS-disciplined frequency
    pub fn disciplined_frequency(&self) -> f64 {
        self.frequency_hz
    }
}

/// Return the current system time in nanoseconds since UNIX epoch
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX epoch")
        .as_nanos() as u64
}

/// Busy-wait until the given timestamp (in nanoseconds since UNIX epoch)
pub fn sleep_until(timestamp_ns: u64) {
    loop {
        if now_ns() >= timestamp_ns {
            break;
        }
        // Busy-wait: spin with a pause hint to avoid saturating the CPU
        std::hint::spin_loop();
    }
}
