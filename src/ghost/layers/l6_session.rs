/// L6 - Session Guard Layer
///
/// Provides replay protection via a sliding window bitmask and session
/// lifecycle management through hard and idle timeouts.
///
/// ## Window Mechanics
/// - The default window covers the 128 most recent counter values (WINDOW_SIZE = 128)
/// - Any counter <= v_max - 128 is unconditionally rejected (too old)
/// - Any counter already set in the bitmask is rejected (replay detected)
/// - A new highest counter shifts the bitmask and sets the leading bit
/// - Also provides `ReplayWindow64` and `ReplayWindow128` for 64-bit and 32-bit counter spaces.
///
/// ## Timeout Policy
/// - Hard timeout: 24 hours absolute session lifetime
/// - Idle timeout:  30 minutes of inactivity before session expires

use std::time::{Duration, Instant};

/// Size of the sliding replay window in counter values.
pub const WINDOW_SIZE: u32 = 128;

/// Absolute maximum session lifetime.
pub const SESSION_HARD_TIMEOUT: Duration = Duration::from_secs(86400); // 24 hours

/// Maximum inactivity before automatic session expiry.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);  // 30 minutes

/// The anti-replay sliding window state (supports 32-bit counter windowing).
pub struct SessionGuard {
    /// When the session was established (hard timeout reference).
    pub start_time: Instant,
    /// Timestamp of the last valid packet received (idle timeout reference).
    pub last_activity: Instant,
    /// The highest counter value seen so far.
    pub v_max: u32,
    /// 128-bit bitmask tracking received counters in [v_max-127, v_max].
    pub bitmask: u128,
}

impl SessionGuard {
    /// Create a fresh session guard with zero state.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
        }
    }

    /// Check whether the session has exceeded either timeout.
    pub fn is_valid(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.start_time) < SESSION_HARD_TIMEOUT
            && now.duration_since(self.last_activity) < SESSION_IDLE_TIMEOUT
    }

    /// Validate a counter value against the replay window.
    ///
    /// Returns `true` if the packet should be accepted, `false` if
    /// it should be dropped (too old, replay detected, or session expired).
    pub fn check_and_update(&mut self, counter: u32) -> bool {
        if !self.is_valid() {
            return false;
        }

        // Scenario A: Packet is far too old (outside the window)
        if counter < self.v_max.saturating_sub(WINDOW_SIZE) {
            return false; // DROP
        }

        // Scenario C: Packet is newer than the current maximum
        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= WINDOW_SIZE {
                // Window completely skipped - reset to just the new bit
                self.bitmask = 1;
            } else {
                // Shift left by the jump distance, set the new (rightmost) bit
                self.bitmask = (self.bitmask << shift) | 1;
            }
            self.v_max = counter;
            self.last_activity = Instant::now();
            return true; // ACCEPT
        }

        // Scenario B: Packet within window - check the bit
        let offset = self.v_max.saturating_sub(counter);
        if offset >= WINDOW_SIZE {
            return false; // DROP (too old)
        }
        if (self.bitmask & (1u128 << offset)) != 0 {
            return false; // DROP (replay attack)
        }

        // Scenario D: Legitimate in-window packet - register the bit
        self.bitmask |= 1u128 << offset;
        self.last_activity = Instant::now();
        true // ACCEPT
    }

    /// Check and update with 64-bit counter support.
    pub fn check_and_update_u64(&mut self, counter: u64) -> bool {
        if counter > u32::MAX as u64 {
            return false;
        }
        self.check_and_update(counter as u32)
    }

    /// Reset the guard state (for new sessions or re-keying).
    pub fn reset(&mut self) {
        self.start_time = Instant::now();
        self.last_activity = Instant::now();
        self.v_max = 0;
        self.bitmask = 0;
    }
}

/// 64-bit anti-replay sliding window guard for full 64-bit monotonic packet counters.
pub struct SessionGuardU64 {
    pub start_time: Instant,
    pub last_activity: Instant,
    pub v_max: u64,
    pub bitmask: u128,
}

impl Default for SessionGuardU64 {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionGuardU64 {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.start_time) < SESSION_HARD_TIMEOUT
            && now.duration_since(self.last_activity) < SESSION_IDLE_TIMEOUT
    }

    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.is_valid() {
            return false;
        }

        let window_size = 128u64;
        if counter < self.v_max.saturating_sub(window_size) {
            return false;
        }

        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= window_size {
                self.bitmask = 1;
            } else {
                self.bitmask = (self.bitmask << shift) | 1;
            }
            self.v_max = counter;
            self.last_activity = Instant::now();
            return true;
        }

        let offset = self.v_max.saturating_sub(counter);
        if offset >= window_size {
            return false;
        }
        if (self.bitmask & (1u128 << offset)) != 0 {
            return false;
        }

        self.bitmask |= 1u128 << offset;
        self.last_activity = Instant::now();
        true
    }

    pub fn reset(&mut self) {
        self.start_time = Instant::now();
        self.last_activity = Instant::now();
        self.v_max = 0;
        self.bitmask = 0;
    }
}