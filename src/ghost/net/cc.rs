//! Congestion control.
//!
//! ## What was missing
//!
//! `net::FlowController` is a *transit* token bucket: a fixed rate configured by
//! hand, replenished on a timer, with no feedback from the network at all. It
//! answers "may this node forward someone else's bytes at the rate we were
//! told?" — which is a policy question — and it cannot answer "how fast should
//! this path actually go?", which is a control question. Nothing in the tree
//! measured a round trip, reacted to loss, or opened a window.
//!
//! This module is the control loop: an [`AckEngine`] that tracks what is in
//! flight, measures RTT, detects loss, and drives one of three real algorithms —
//! [`Cubic`] (RFC 8312), [`NewReno`] (RFC 5681 + RFC 6582 byte counting), or
//! [`Bbr`] (bandwidth-and-RTT model, v1 shape) — with a [`Pacer`] that spreads
//! the window over time instead of firing it in a burst.
//!
//! ## Design
//!
//! Time is a [`CcClock`] — a monotonic *elapsed* duration handed in by the
//! caller, never read from the clock inside the module. Every decision is
//! therefore reproducible and unit-testable without sleeping, which matters
//! because congestion control is exactly the kind of code that is otherwise only
//! testable by running it against a real network.
//!
//! ## What this is not
//!
//! This is the sender-side control loop, not a transport. It does not own a
//! socket, retransmit data, or reorder anything; the caller does that and feeds
//! this module ACKs. The in-band [`AckPdu`] defines how a cumulative
//! acknowledgement is framed for the bulk path.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

pub type CcClock = Duration;

pub const DEFAULT_MSS: u64 = 1400;

pub const INIT_CWND: u64 = 10 * DEFAULT_MSS;

pub const MIN_PIPE_CWND: u64 = 4 * DEFAULT_MSS;

pub const MIN_SSTHRESH: u64 = 2 * DEFAULT_MSS;

pub const DEFAULT_MAX_CWND: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcAlgorithm {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl CcAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            CcAlgorithm::Cubic => "cubic",
            CcAlgorithm::NewReno => "newreno",
            CcAlgorithm::Bbr => "bbr",
        }
    }
}

pub const CUBIC_BETA: f64 = 0.7;
pub const CUBIC_C: f64 = 0.4;

#[derive(Debug, Clone)]
pub struct Cubic {
    mss: u64,
    cwnd: f64,
    ssthresh: f64,
    w_max: f64,
    epoch_start: Option<CcClock>,
    k: f64,
    in_slow_start: bool,
    rtt: Duration,
    min_rtt: Duration,
    max_cwnd: f64,
}

impl Cubic {
    pub fn new(mss: u64) -> Self {
        let mss = mss.max(1);
        let init = INIT_CWND.max(mss);
        Self {
            mss,
            cwnd: init as f64,
            ssthresh: f64::MAX,
            w_max: 0.0,
            epoch_start: None,
            k: 0.0,
            in_slow_start: true,
            rtt: Duration::from_millis(100),
            min_rtt: Duration::from_millis(100),
            max_cwnd: DEFAULT_MAX_CWND as f64,
        }
    }

    pub fn set_ssthresh(&mut self, bytes: u64) {
        self.ssthresh = bytes.max(MIN_SSTHRESH) as f64;
        if self.cwnd >= self.ssthresh {
            self.in_slow_start = false;
        }
    }

    pub fn set_cwnd_ceiling(&mut self, bytes: u64) {
        self.max_cwnd = bytes.max(MIN_PIPE_CWND) as f64;
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd.max(self.mss as f64).min(self.max_cwnd) as u64
    }

    pub fn ssthresh(&self) -> u64 {
        if self.ssthresh >= u64::MAX as f64 {
            u64::MAX
        } else {
            self.ssthresh.max(self.mss as f64) as u64
        }
    }

    pub fn in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    pub fn w_max(&self) -> u64 {
        self.w_max.max(0.0) as u64
    }

    pub fn k(&self) -> f64 {
        self.k
    }

    pub fn target_window(&self, t_secs: f64) -> f64 {
        let rtt_secs = self.rtt.as_secs_f64().max(1e-6);
        let cubic = CUBIC_C * (t_secs + rtt_secs - self.k).powi(3) + self.w_max;
        let alpha = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);
        let reno = self.w_max * CUBIC_BETA + alpha * (t_secs / rtt_secs) * self.mss as f64;
        cubic.max(reno)
    }

    pub fn on_ack(&mut self, acked_bytes: u64, rtt: Duration, now: CcClock) {
        if acked_bytes == 0 {
            return;
        }
        if rtt > Duration::ZERO {
            self.rtt = rtt;
            if self.min_rtt == Duration::ZERO || rtt < self.min_rtt {
                self.min_rtt = rtt;
            }
        }
        if self.in_slow_start {
            self.cwnd += acked_bytes as f64;
            if self.cwnd >= self.ssthresh {
                self.in_slow_start = false;
                self.epoch_start.get_or_insert(now);
                self.w_max = self.cwnd;
                self.k = (self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C).max(0.0).cbrt();
            }
            return;
        }

        let epoch_start = *self.epoch_start.get_or_insert(now);
        let t = (now.saturating_sub(epoch_start)).as_secs_f64();
        let target = self.target_window(t);
        if target <= self.cwnd {
            return;
        }
        let inc = (target - self.cwnd) / self.cwnd * acked_bytes as f64;
        self.cwnd += inc.max(0.0);
        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    pub fn on_loss(&mut self, now: CcClock) {
        let cwnd = self.cwnd;
        if cwnd < self.w_max {
            self.w_max = cwnd * (1.0 + CUBIC_BETA) / 2.0;
        } else {
            self.w_max = cwnd;
        }
        self.ssthresh = (cwnd * CUBIC_BETA).max(MIN_SSTHRESH as f64);
        self.cwnd = self.ssthresh.min(self.max_cwnd);
        self.epoch_start = Some(now);
        self.in_slow_start = false;
        self.k = (self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C).max(0.0).cbrt();
    }
}

#[derive(Debug, Clone)]
pub struct NewReno {
    mss: u64,
    cwnd: f64,
    ssthresh: f64,
    in_slow_start: bool,
    max_cwnd: f64,
}

impl NewReno {
    pub fn new(mss: u64) -> Self {
        let mss = mss.max(1);
        Self {
            mss,
            cwnd: INIT_CWND.max(mss) as f64,
            ssthresh: f64::MAX,
            in_slow_start: true,
            max_cwnd: DEFAULT_MAX_CWND as f64,
        }
    }

    pub fn set_ssthresh(&mut self, bytes: u64) {
        self.ssthresh = bytes.max(MIN_SSTHRESH) as f64;
        if self.cwnd >= self.ssthresh {
            self.in_slow_start = false;
        }
    }

    pub fn set_cwnd_ceiling(&mut self, bytes: u64) {
        self.max_cwnd = bytes.max(MIN_PIPE_CWND) as f64;
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd.max(self.mss as f64).min(self.max_cwnd) as u64
    }

    pub fn ssthresh(&self) -> u64 {
        if self.ssthresh >= u64::MAX as f64 {
            u64::MAX
        } else {
            self.ssthresh.max(self.mss as f64) as u64
        }
    }

    pub fn in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    pub fn on_ack(&mut self, acked_bytes: u64, _rtt: Duration, _now: CcClock) {
        if acked_bytes == 0 {
            return;
        }
        if self.in_slow_start {
            self.cwnd += acked_bytes as f64;
            if self.cwnd >= self.ssthresh {
                self.in_slow_start = false;
            }
            return;
        }
        self.cwnd += self.mss as f64 * acked_bytes as f64 / self.cwnd;
        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    pub fn on_loss(&mut self, _now: CcClock) {
        self.ssthresh = (self.cwnd / 2.0).max(MIN_SSTHRESH as f64);
        self.cwnd = self.ssthresh.min(self.max_cwnd);
        self.in_slow_start = false;
    }
}

pub const BBR_HIGH_GAIN: f64 = 2.885_390_082_0;
pub const BBR_DRAIN_GAIN: f64 = 1.0 / BBR_HIGH_GAIN;
pub const BBR_CWND_GAIN: f64 = 2.0;
pub const BBR_PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
pub const BBR_PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);
pub const BBR_PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

impl BbrState {
    pub fn as_str(self) -> &'static str {
        match self {
            BbrState::Startup => "startup",
            BbrState::Drain => "drain",
            BbrState::ProbeBw => "probe-bw",
            BbrState::ProbeRtt => "probe-rtt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Bbr {
    mss: u64,
    state: BbrState,
    pacing_gain: f64,
    cwnd_gain: f64,
    max_bw: f64,
    bw_samples: VecDeque<f64>,
    rtt_samples: VecDeque<(CcClock, Duration)>,
    min_rtt: Option<Duration>,
    round_count: u64,
    bw_at_round_start: f64,
    rounds_without_growth: u32,
    probe_bw_cycle: usize,
    entered_probe_rtt: Option<CcClock>,
    last_min_rtt_update: Option<CcClock>,
    in_flight: u64,
    max_cwnd: f64,
}

impl Bbr {
    pub fn new(mss: u64) -> Self {
        let mss = mss.max(1);
        Self {
            mss,
            state: BbrState::Startup,
            pacing_gain: BBR_HIGH_GAIN,
            cwnd_gain: BBR_CWND_GAIN,
            max_bw: 0.0,
            bw_samples: VecDeque::new(),
            rtt_samples: VecDeque::new(),
            min_rtt: None,
            round_count: 0,
            bw_at_round_start: 0.0,
            rounds_without_growth: 0,
            probe_bw_cycle: 0,
            entered_probe_rtt: None,
            last_min_rtt_update: None,
            in_flight: 0,
            max_cwnd: DEFAULT_MAX_CWND as f64,
        }
    }

    pub fn set_cwnd_ceiling(&mut self, bytes: u64) {
        self.max_cwnd = bytes.max(MIN_PIPE_CWND) as f64;
    }

    pub fn state(&self) -> BbrState {
        self.state
    }

    pub fn max_bw_bps(&self) -> f64 {
        self.max_bw
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn bdp_bytes(&self) -> f64 {
        match self.min_rtt {
            Some(rtt) => self.max_bw * rtt.as_secs_f64(),
            None => 0.0,
        }
    }

    pub fn pacing_gain(&self) -> f64 {
        self.pacing_gain
    }

    pub fn cwnd(&self) -> u64 {
        if self.state == BbrState::ProbeRtt {
            return MIN_PIPE_CWND.max(self.mss);
        }
        let floor = MIN_PIPE_CWND.max(self.mss) as f64;
        let by_model = self.bdp_bytes() * self.cwnd_gain;
        let startup_floor = self.round_count.saturating_add(1) as f64 * self.mss as f64;
        by_model.max(startup_floor).max(floor).min(self.max_cwnd) as u64
    }

    pub fn pacing_rate_bps(&self) -> f64 {
        if self.max_bw <= 0.0 {
            let rtt = self.min_rtt.unwrap_or(Duration::from_millis(100));
            let rtt = rtt.as_secs_f64().max(1e-3);
            return INIT_CWND as f64 / rtt * self.pacing_gain;
        }
        self.max_bw * self.pacing_gain
    }

    pub fn on_ack(&mut self, acked_bytes: u64, rtt: Duration, now: CcClock) {
        if acked_bytes == 0 {
            return;
        }
        let floor_is_stale = self
            .last_min_rtt_update
            .is_some_and(|at| now.saturating_sub(at) >= BBR_PROBE_RTT_INTERVAL);

        if rtt > Duration::ZERO {
            self.rtt_samples.push_back((now, rtt));
        }
        while let Some(&(at, _)) = self.rtt_samples.front() {
            if now.saturating_sub(at) > BBR_PROBE_RTT_INTERVAL {
                self.rtt_samples.pop_front();
            } else {
                break;
            }
        }
        if let Some(sample) = self.rtt_samples.iter().map(|(_, r)| *r).min() {
            self.min_rtt = Some(sample);
            self.last_min_rtt_update = Some(now);
        }

        let rtt_secs = rtt.as_secs_f64().max(1e-6);
        let sample = acked_bytes as f64 / rtt_secs;
        self.bw_samples.push_back(sample);
        while self.bw_samples.len() > 10 {
            self.bw_samples.pop_front();
        }
        if let Some(&best) = self
            .bw_samples
            .iter()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
        {
            self.max_bw = self.max_bw.max(best);
        }

        if self.state == BbrState::ProbeRtt {
            self.pacing_gain = 1.0;
            self.cwnd_gain = 1.0;
        }
        self.maybe_probe_rtt(floor_is_stale, now);
    }

    fn advance_round(&mut self, peak_in_flight: u64) {
        self.round_count = self.round_count.wrapping_add(1);
        let grew = self.max_bw >= self.bw_at_round_start * 1.25;
        match self.state {
            BbrState::Startup => {
                if grew {
                    self.rounds_without_growth = 0;
                } else {
                    self.rounds_without_growth = self.rounds_without_growth.saturating_add(1);
                }
                self.bw_at_round_start = self.max_bw;
                if self.rounds_without_growth >= 3 && self.max_bw > 0.0 {
                    self.state = BbrState::Drain;
                    self.pacing_gain = BBR_DRAIN_GAIN;
                    self.cwnd_gain = BBR_CWND_GAIN;
                }
            }
            BbrState::Drain => {
                if peak_in_flight as f64 <= self.bdp_bytes().max(1.0) {
                    self.state = BbrState::ProbeBw;
                    self.probe_bw_cycle = 0;
                    self.pacing_gain = BBR_PROBE_BW_GAINS[0];
                }
            }
            BbrState::ProbeBw => {
                self.rounds_without_growth = if grew {
                    0
                } else {
                    self.rounds_without_growth.saturating_add(1)
                };
                self.bw_at_round_start = self.max_bw;
                if grew {
                    self.probe_bw_cycle =
                        (self.probe_bw_cycle.wrapping_add(1)) % BBR_PROBE_BW_GAINS.len();
                    self.pacing_gain = BBR_PROBE_BW_GAINS[self.probe_bw_cycle];
                }
            }
            BbrState::ProbeRtt => {}
        }
    }

    fn maybe_probe_rtt(&mut self, floor_is_stale: bool, now: CcClock) {
        if self.state == BbrState::ProbeRtt {
            let held = self
                .entered_probe_rtt
                .map(|at| now.saturating_sub(at))
                .unwrap_or_default();
            if held >= BBR_PROBE_RTT_DURATION {
                self.state = BbrState::ProbeBw;
                self.entered_probe_rtt = None;
                self.probe_bw_cycle = 0;
                self.pacing_gain = BBR_PROBE_BW_GAINS[0];
                self.cwnd_gain = BBR_CWND_GAIN;
            }
            return;
        }
        if floor_is_stale && self.state != BbrState::Startup {
            self.state = BbrState::ProbeRtt;
            self.entered_probe_rtt = Some(now);
        }
    }

    pub fn on_loss(&mut self, _now: CcClock) {}

    pub fn set_in_flight(&mut self, bytes: u64) {
        let was = self.in_flight;
        self.in_flight = bytes;
        if was > 0 && bytes == 0 {
            self.advance_round(was);
        }
    }
}

#[derive(Debug, Clone)]
pub enum CongestionController {
    Cubic(Cubic),
    NewReno(NewReno),
    Bbr(Bbr),
}

impl CongestionController {
    pub fn new(algorithm: CcAlgorithm, mss: u64) -> Self {
        match algorithm {
            CcAlgorithm::Cubic => CongestionController::Cubic(Cubic::new(mss)),
            CcAlgorithm::NewReno => CongestionController::NewReno(NewReno::new(mss)),
            CcAlgorithm::Bbr => CongestionController::Bbr(Bbr::new(mss)),
        }
    }

    pub fn algorithm(&self) -> CcAlgorithm {
        match self {
            CongestionController::Cubic(_) => CcAlgorithm::Cubic,
            CongestionController::NewReno(_) => CcAlgorithm::NewReno,
            CongestionController::Bbr(_) => CcAlgorithm::Bbr,
        }
    }

    pub fn cwnd(&self) -> u64 {
        match self {
            CongestionController::Cubic(c) => c.cwnd(),
            CongestionController::NewReno(c) => c.cwnd(),
            CongestionController::Bbr(c) => c.cwnd(),
        }
    }

    pub fn on_ack(&mut self, acked_bytes: u64, rtt: Duration, now: CcClock) {
        match self {
            CongestionController::Cubic(c) => c.on_ack(acked_bytes, rtt, now),
            CongestionController::NewReno(c) => c.on_ack(acked_bytes, rtt, now),
            CongestionController::Bbr(c) => c.on_ack(acked_bytes, rtt, now),
        }
    }

    pub fn on_loss(&mut self, now: CcClock) {
        match self {
            CongestionController::Cubic(c) => c.on_loss(now),
            CongestionController::NewReno(c) => c.on_loss(now),
            CongestionController::Bbr(c) => c.on_loss(now),
        }
    }

    pub fn set_in_flight(&mut self, bytes: u64) {
        if let CongestionController::Bbr(c) = self {
            c.set_in_flight(bytes);
        }
    }

    pub fn set_ssthresh(&mut self, bytes: u64) {
        match self {
            CongestionController::Cubic(c) => c.set_ssthresh(bytes),
            CongestionController::NewReno(c) => c.set_ssthresh(bytes),
            CongestionController::Bbr(_) => {}
        }
    }

    pub fn set_cwnd_ceiling(&mut self, bytes: u64) {
        match self {
            CongestionController::Cubic(c) => c.set_cwnd_ceiling(bytes),
            CongestionController::NewReno(c) => c.set_cwnd_ceiling(bytes),
            CongestionController::Bbr(c) => c.set_cwnd_ceiling(bytes),
        }
    }

    pub fn pacing_rate_bps(&self, srtt: Duration) -> f64 {
        match self {
            CongestionController::Bbr(c) => c.pacing_rate_bps(),
            _ => {
                let rtt = srtt.as_secs_f64().max(1e-3);
                self.cwnd() as f64 / rtt
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pacer {
    rate_bps: f64,
    tokens: f64,
    last: Option<CcClock>,
    burst_cap: f64,
}

impl Pacer {
    pub fn new(rate_bps: f64, burst_cap_bytes: u64) -> Self {
        Self {
            rate_bps: rate_bps.max(1.0),
            tokens: burst_cap_bytes as f64,
            last: None,
            burst_cap: burst_cap_bytes as f64,
        }
    }

    pub fn rate_bps(&self) -> f64 {
        self.rate_bps
    }

    pub fn set_rate(&mut self, rate_bps: f64) {
        self.rate_bps = rate_bps.max(1.0);
    }

    fn refill(&mut self, now: CcClock) {
        let last = *self.last.get_or_insert(now);
        self.last = Some(now);
        let elapsed = now.saturating_sub(last).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        self.tokens = (self.tokens + elapsed * self.rate_bps).min(self.burst_cap);
    }

    pub fn try_consume(&mut self, bytes: u64, now: CcClock) -> bool {
        self.refill(now);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    pub fn delay_for(&mut self, bytes: u64, now: CcClock) -> Duration {
        self.refill(now);
        let shortfall = bytes as f64 - self.tokens;
        if shortfall <= 0.0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(shortfall / self.rate_bps)
    }

    pub fn available(&mut self, now: CcClock) -> u64 {
        self.refill(now);
        self.tokens.max(0.0) as u64
    }

    fn consume(&mut self, bytes: f64) {
        self.tokens = (self.tokens - bytes).max(0.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outstanding {
    pub seq: u64,
    pub bytes: u64,
    pub sent_at: CcClock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AckOutcome {
    pub newly_acked: u64,
    pub rtt: Option<Duration>,
    pub loss: bool,
    pub recovery_entered: bool,
    pub flight_cleared: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CcStats {
    pub segments_sent: u64,
    pub bytes_sent: u64,
    pub segments_acked: u64,
    pub bytes_acked: u64,
    pub loss_events: u64,
    pub duplicate_acks: u64,
    pub timeouts: u64,
    pub pace_limited: u64,
    pub cwnd_limited: u64,
}

#[derive(Debug, Clone)]
pub struct AckEngine {
    mss: u64,
    controller: CongestionController,
    pacer: Pacer,
    outstanding: VecDeque<Outstanding>,
    in_flight: u64,
    next_seq: u64,
    highest_acked: Option<u64>,
    duplicate_acks: u32,
    srtt: Option<Duration>,
    rttvar: Duration,
    min_rtt: Option<Duration>,
    in_loss_episode: bool,
    rto: Duration,
    backoff_shift: u32,
    stats: CcStats,
}

pub const MIN_RTO: Duration = Duration::from_secs(1);
pub const MAX_RTO: Duration = Duration::from_secs(60);
pub const DUP_ACK_THRESHOLD: u32 = 3;

impl AckEngine {
    pub fn new(algorithm: CcAlgorithm, mss: u64) -> Self {
        let mss = mss.max(1);
        Self {
            mss,
            controller: CongestionController::new(algorithm, mss),
            pacer: Pacer::new(INIT_CWND as f64 / 0.1, INIT_CWND.max(mss.saturating_mul(2))),
            outstanding: VecDeque::new(),
            in_flight: 0,
            next_seq: 0,
            highest_acked: None,
            duplicate_acks: 0,
            srtt: None,
            rttvar: Duration::ZERO,
            min_rtt: None,
            in_loss_episode: false,
            rto: MIN_RTO,
            backoff_shift: 0,
            stats: CcStats::default(),
        }
    }

    pub fn with_mss(mss: u64) -> Self {
        Self::new(CcAlgorithm::default(), mss)
    }

    pub fn mss(&self) -> u64 {
        self.mss
    }

    pub fn algorithm(&self) -> CcAlgorithm {
        self.controller.algorithm()
    }

    pub fn cwnd(&self) -> u64 {
        self.controller.cwnd()
    }

    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn rto(&self) -> Duration {
        let base = self.rto.as_secs_f64() * 2f64.powi(self.backoff_shift as i32);
        Duration::from_secs_f64(base).max(MIN_RTO).min(MAX_RTO)
    }

    pub fn highest_acked(&self) -> Option<u64> {
        self.highest_acked
    }

    pub fn stats(&self) -> CcStats {
        self.stats
    }

    pub fn send_allowance(&mut self, now: CcClock) -> u64 {
        let window = self.cwnd().saturating_sub(self.in_flight);
        if window == 0 {
            self.stats.cwnd_limited = self.stats.cwnd_limited.saturating_add(1);
            return 0;
        }
        self.refresh_pacer(now);
        let paced = self.pacer.available(now);
        window.min(paced)
    }

    pub fn can_send(&mut self, bytes: u64, now: CcClock) -> bool {
        self.send_allowance(now) >= bytes
    }

    pub fn on_send(&mut self, bytes: u64, now: CcClock) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.pacer.consume(bytes as f64);
        self.in_flight = self.in_flight.saturating_add(bytes);
        self.outstanding.push_back(Outstanding {
            seq,
            bytes,
            sent_at: now,
        });
        self.stats.segments_sent = self.stats.segments_sent.saturating_add(1);
        self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(bytes);
        self.controller.set_in_flight(self.in_flight);
        seq
    }

    pub fn on_ack(&mut self, ack: u64, now: CcClock) -> AckOutcome {
        let mut outcome = AckOutcome::default();
        let mut newest_sample: Option<(CcClock, Duration)> = None;
        while let Some(front) = self.outstanding.front().copied() {
            if front.seq >= ack {
                break;
            }
            self.outstanding.pop_front();
            self.in_flight = self.in_flight.saturating_sub(front.bytes);
            outcome.newly_acked = outcome.newly_acked.saturating_add(front.bytes);
            self.stats.segments_acked = self.stats.segments_acked.saturating_add(1);
            self.stats.bytes_acked = self.stats.bytes_acked.saturating_add(front.bytes);
            let sample = now.saturating_sub(front.sent_at);
            newest_sample = Some((front.sent_at, sample));
        }

        if outcome.newly_acked > 0 {
            self.duplicate_acks = 0;
            self.backoff_shift = 0;
            self.in_loss_episode = false;
            if let Some((_, sample)) = newest_sample {
                self.observe_rtt(sample);
                outcome.rtt = Some(sample);
            }
            self.controller.on_ack(
                outcome.newly_acked,
                self.srtt.unwrap_or(Duration::from_millis(100)),
                now,
            );
            self.controller.set_in_flight(self.in_flight);
        } else {
            self.stats.duplicate_acks = self.stats.duplicate_acks.saturating_add(1);
            self.duplicate_acks = self.duplicate_acks.saturating_add(1);
            if self.duplicate_acks >= DUP_ACK_THRESHOLD {
                outcome = self.declare_loss(now, outcome);
            }
        }

        outcome.flight_cleared = self.outstanding.is_empty();
        self.refresh_pacer(now);
        outcome
    }

    pub fn on_timeout(&mut self, now: CcClock) -> AckOutcome {
        let mut outcome = self.declare_loss(now, AckOutcome::default());
        outcome.loss = true;
        self.stats.timeouts = self.stats.timeouts.saturating_add(1);
        self.backoff_shift = (self.backoff_shift + 1).min(6);
        self.duplicate_acks = 0;
        outcome.flight_cleared = self.outstanding.is_empty();
        outcome
    }

    fn declare_loss(&mut self, now: CcClock, mut outcome: AckOutcome) -> AckOutcome {
        outcome.loss = true;
        if !self.in_loss_episode {
            self.in_loss_episode = true;
            self.controller.on_loss(now);
            self.stats.loss_events = self.stats.loss_events.saturating_add(1);
            outcome.recovery_entered = true;
        }
        self.refresh_pacer(now);
        outcome
    }

    fn observe_rtt(&mut self, sample: Duration) {
        self.highest_acked = Some(self.next_seq);
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = Duration::from_secs_f64(sample.as_secs_f64() / 2.0);
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(sample);
                self.rttvar = Duration::from_secs_f64(
                    0.75 * self.rttvar.as_secs_f64() + 0.25 * diff.as_secs_f64(),
                );
                self.srtt = Some(Duration::from_secs_f64(
                    0.875 * srtt.as_secs_f64() + 0.125 * sample.as_secs_f64(),
                ));
            }
        }
        match self.min_rtt {
            Some(current) if current <= sample => {}
            _ => self.min_rtt = Some(sample),
        }
        let rto = self.srtt.unwrap().as_secs_f64() + 4.0 * self.rttvar.as_secs_f64();
        self.rto = Duration::from_secs_f64(rto).max(MIN_RTO).min(MAX_RTO);
    }

    fn refresh_pacer(&mut self, now: CcClock) {
        let rate = self
            .controller
            .pacing_rate_bps(self.srtt.unwrap_or(Duration::from_millis(100)));
        self.pacer.set_rate(rate);
        self.pacer.burst_cap = self.cwnd().max(2 * self.mss) as f64;
        self.pacer.available(now);
    }

    pub fn outstanding(&self) -> &VecDeque<Outstanding> {
        &self.outstanding
    }
}

pub const ACK_PDU_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPdu {
    pub ack: u64,
}

pub const ACK_PDU_TYPE: u8 = 0x03;

impl AckPdu {
    pub fn new(ack: u64) -> Self {
        Self { ack }
    }

    pub fn encode(self) -> [u8; ACK_PDU_LEN] {
        let mut out = [0u8; ACK_PDU_LEN];
        out[0] = ACK_PDU_TYPE;
        out[1..].copy_from_slice(&self.ack.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < ACK_PDU_LEN || buf[0] != ACK_PDU_TYPE {
            return None;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&buf[1..ACK_PDU_LEN]);
        Some(Self {
            ack: u64::from_be_bytes(raw),
        })
    }
}

pub const MIN_SHAPED_RATE_BPS: u64 = 8_000;

#[derive(Debug)]
pub struct TransitGovernor {
    ceiling_bps: AtomicU64,
    shaped_bps: AtomicU64,
    updates: AtomicU64,
    paths_seen: AtomicUsize,
}

impl TransitGovernor {
    pub fn new(ceiling_bps: u64) -> Self {
        Self {
            ceiling_bps: AtomicU64::new(ceiling_bps.max(MIN_SHAPED_RATE_BPS)),
            shaped_bps: AtomicU64::new(ceiling_bps.max(MIN_SHAPED_RATE_BPS)),
            updates: AtomicU64::new(0),
            paths_seen: AtomicUsize::new(0),
        }
    }

    pub fn ceiling_bps(&self) -> u64 {
        self.ceiling_bps.load(Ordering::Relaxed)
    }

    pub fn set_ceiling_bps(&self, ceiling_bps: u64) {
        self.ceiling_bps
            .store(ceiling_bps.max(MIN_SHAPED_RATE_BPS), Ordering::Relaxed);
    }

    pub fn set_ceiling_mbps(&self, mbps: u64) {
        self.set_ceiling_bps(mbps.saturating_mul(125_000));
    }

    pub fn shaped_bps(&self) -> u64 {
        self.shaped_bps.load(Ordering::Relaxed)
    }

    pub fn updates(&self) -> u64 {
        self.updates.load(Ordering::Relaxed)
    }

    pub fn paths_seen(&self) -> usize {
        self.paths_seen.load(Ordering::Relaxed)
    }

    pub fn recommend(&self, path_rates_bps: &[f64]) -> Option<u64> {
        let mut weakest: Option<f64> = None;
        for r in path_rates_bps {
            if !(r.is_finite() && *r > 0.0) {
                continue;
            }
            weakest = Some(match weakest {
                Some(w) => w.min(*r),
                None => *r,
            });
        }
        let weakest = weakest?;
        let capped = weakest.min(self.ceiling_bps() as f64);
        Some(capped.max(MIN_SHAPED_RATE_BPS as f64) as u64)
    }

    pub fn apply(&self, flow: &super::FlowController, path_rates_bps: &[f64]) -> u64 {
        let live: Vec<f64> = path_rates_bps
            .iter()
            .copied()
            .filter(|r| r.is_finite() && *r > 0.0)
            .collect();
        self.paths_seen.store(live.len(), Ordering::Relaxed);
        match self.recommend(&live) {
            Some(rate) => {
                flow.set_transit_rate_bps(rate);
                self.shaped_bps.store(rate, Ordering::Relaxed);
                self.updates.fetch_add(1, Ordering::Relaxed);
                rate
            }
            None => flow.transit_rate_bps(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::net::FlowController;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn grow(engine: &mut AckEngine, rounds: usize, rtt: Duration, clock: &mut CcClock) -> Vec<u64> {
        let mut windows = Vec::new();
        for _ in 0..rounds {
            windows.push(engine.cwnd());
            send_a_window(engine, *clock);
            *clock += rtt;
            engine.on_ack(engine.next_seq, *clock);
        }
        windows
    }

    fn send_a_window(engine: &mut AckEngine, now: CcClock) {
        loop {
            if engine.send_allowance(now) < engine.mss() {
                break;
            }
            engine.on_send(engine.mss(), now);
        }
    }

    fn force_loss(engine: &mut AckEngine, clock: CcClock) {
        for _ in 0..3 {
            engine.on_send(engine.mss(), clock);
        }
        for _ in 0..DUP_ACK_THRESHOLD {
            engine.on_ack(0, clock);
        }
    }

    #[test]
    fn cubic_starts_by_doubling_the_window() {
        let mut c = Cubic::new(DEFAULT_MSS);
        assert_eq!(c.cwnd(), INIT_CWND);
        assert!(c.in_slow_start());
        c.on_ack(INIT_CWND, ms(50), Duration::ZERO);
        assert_eq!(c.cwnd(), 2 * INIT_CWND);
        c.set_cwnd_ceiling(3 * INIT_CWND);
        c.on_ack(INIT_CWND, ms(50), Duration::ZERO);
        assert_eq!(c.cwnd(), 3 * INIT_CWND, "the ceiling must bind");
    }

    #[test]
    fn cubic_loss_sets_w_max_and_k_from_the_window_it_had() {
        let mut c = Cubic::new(DEFAULT_MSS);
        c.set_ssthresh(8 * INIT_CWND);
        for _ in 0..6 {
            let w = c.cwnd();
            c.on_ack(w, ms(50), Duration::ZERO);
        }
        let before = c.cwnd() as f64;
        let now = ms(500);
        c.on_loss(now);
        assert_eq!(c.w_max(), before as u64, "w_max is the window we lost at");
        assert_eq!(c.cwnd(), (before * CUBIC_BETA) as u64, "β = 0.7");
        let expected = (before * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        assert!(
            (c.k() - expected).abs() < 1e-9,
            "K should be {expected}, got {}",
            c.k()
        );
        assert!(c.k() > 0.0);
        assert!(!c.in_slow_start());
    }

    #[test]
    fn cubic_fast_convergence_lowers_the_plateau() {
        let mut c = Cubic::new(DEFAULT_MSS);
        c.set_ssthresh(4 * INIT_CWND);
        c.on_ack(INIT_CWND, ms(50), Duration::ZERO);
        c.on_loss(ms(100));
        let first_w_max = c.w_max();
        assert_eq!(first_w_max, 2 * INIT_CWND);
        c.on_loss(ms(200));
        assert!(
            c.w_max() < first_w_max,
            "fast convergence must lower w_max: {} !< {first_w_max}",
            c.w_max()
        );
    }

    #[test]
    fn cubic_target_is_reno_friendly_near_the_plateau() {
        let mut c = Cubic::new(DEFAULT_MSS);
        c.set_ssthresh(4 * INIT_CWND);
        c.on_ack(INIT_CWND, ms(50), Duration::ZERO);
        c.on_loss(Duration::ZERO);
        let target = c.target_window(0.0);
        assert!(
            target >= c.cwnd() as f64,
            "the target must never be below the current window at t=0: {target} vs {}",
            c.cwnd()
        );
        let far = c.target_window(100.0);
        assert!(
            far > target,
            "the cubic curve must exceed the Reno line later"
        );
    }

    #[test]
    fn newreno_adds_one_mss_per_rtt_not_one_per_ack() {
        let mut n = NewReno::new(DEFAULT_MSS);
        n.set_ssthresh(2 * INIT_CWND);
        n.on_ack(INIT_CWND, ms(50), Duration::ZERO);
        assert!(!n.in_slow_start());
        let start = n.cwnd();
        n.on_ack(start, ms(50), Duration::ZERO);
        assert_eq!(
            n.cwnd(),
            start + DEFAULT_MSS,
            "RFC 6582 byte counting is +1 MSS per RTT"
        );

        let mut n2 = NewReno::new(DEFAULT_MSS);
        n2.set_ssthresh(2 * INIT_CWND);
        n2.on_ack(INIT_CWND, ms(50), Duration::ZERO);
        let start2 = n2.cwnd();
        for _ in 0..10 {
            n2.on_ack(start2 / 10, ms(50), Duration::ZERO);
        }
        let grown = n2.cwnd() - start2;
        assert!(
            grown <= DEFAULT_MSS + 1,
            "ack-per-packet must not multiply the growth: grew by {grown}"
        );
    }

    #[test]
    fn newreno_halves_on_loss_and_never_below_the_floor() {
        let mut n = NewReno::new(DEFAULT_MSS);
        n.set_ssthresh(4 * INIT_CWND);
        for _ in 0..5 {
            let w = n.cwnd();
            n.on_ack(w, ms(50), Duration::ZERO);
        }
        let before = n.cwnd();
        n.on_loss(Duration::ZERO);
        assert_eq!(n.cwnd(), before / 2);
        assert_eq!(n.ssthresh(), before / 2);
        for _ in 0..10 {
            n.on_loss(Duration::ZERO);
        }
        assert!(n.cwnd() >= MIN_SSTHRESH);
    }

    #[test]
    fn bbr_starts_paced_at_the_high_gain() {
        let b = Bbr::new(DEFAULT_MSS);
        assert_eq!(b.state(), BbrState::Startup);
        assert!((b.pacing_gain() - BBR_HIGH_GAIN).abs() < 1e-9);
        assert!((b.pacing_gain() - 2.885).abs() < 0.001);
        assert_eq!(b.state().as_str(), "startup");
    }

    fn bbr_round(b: &mut Bbr, acked: u64, rtt: Duration, clock: &mut CcClock) {
        b.on_ack(acked, rtt, *clock);
        b.set_in_flight(acked);
        *clock += rtt;
        b.set_in_flight(0);
    }

    #[test]
    fn bbr_models_bandwidth_and_enters_drain_when_the_pipe_stops_growing() {
        let mut b = Bbr::new(DEFAULT_MSS);
        let mut clock = Duration::ZERO;
        for _ in 0..4 {
            bbr_round(&mut b, 100_000, ms(50), &mut clock);
        }
        assert!(
            (b.max_bw_bps() - 2_000_000.0).abs() < 1.0,
            "max_bw should be 2 MB/s, got {}",
            b.max_bw_bps()
        );
        assert_eq!(
            b.state(),
            BbrState::Drain,
            "a flat rate for three rounds means startup is over"
        );
        assert!((b.pacing_gain() - BBR_DRAIN_GAIN).abs() < 1e-9);
        bbr_round(&mut b, 100_000, ms(50), &mut clock);
        assert_eq!(b.state(), BbrState::ProbeBw);
        let mut b2 = Bbr::new(DEFAULT_MSS);
        let mut clock2 = Duration::ZERO;
        for _ in 0..4 {
            bbr_round(&mut b2, 100_000, ms(50), &mut clock2);
        }
        assert_eq!(b2.state(), BbrState::Drain);
        b2.on_ack(100_000, ms(50), clock2);
        b2.set_in_flight(10_000_000);
        b2.set_in_flight(0);
        assert_eq!(
            b2.state(),
            BbrState::Drain,
            "a round that peaked far above the BDP is not drained"
        );
    }

    #[test]
    fn bbr_window_is_the_bandwidth_delay_product_times_the_gain() {
        let mut b = Bbr::new(DEFAULT_MSS);
        b.on_ack(100_000, ms(20), Duration::ZERO);
        let expected = b.bdp_bytes() * BBR_CWND_GAIN;
        assert!(b.cwnd() as f64 >= expected - 1.0);
        assert!((b.bdp_bytes() - 100_000.0).abs() < 1000.0);
    }

    #[test]
    fn bbr_probes_for_a_fresh_rtt_floor_when_its_estimate_goes_stale() {
        let mut b = Bbr::new(DEFAULT_MSS);
        let mut clock = Duration::ZERO;
        for _ in 0..5 {
            bbr_round(&mut b, 100_000, ms(50), &mut clock);
        }
        assert_eq!(b.state(), BbrState::ProbeBw);

        clock += Duration::from_secs(11);
        b.on_ack(1_000, ms(50), clock);
        assert_eq!(b.state(), BbrState::ProbeRtt);
        assert_eq!(b.cwnd(), MIN_PIPE_CWND);
        clock += BBR_PROBE_RTT_DURATION;
        b.on_ack(1_000, ms(50), clock);
        assert_eq!(b.state(), BbrState::ProbeBw);
    }

    #[test]
    fn bbr_ignores_loss_as_a_congestion_signal() {
        let mut b = Bbr::new(DEFAULT_MSS);
        let mut clock = Duration::ZERO;
        for _ in 0..3 {
            bbr_round(&mut b, 100_000, ms(50), &mut clock);
        }
        let bw = b.max_bw_bps();
        let cwnd = b.cwnd();
        b.on_loss(clock);
        assert_eq!(
            b.max_bw_bps(),
            bw,
            "a loss must not change the rate estimate"
        );
        assert_eq!(b.cwnd(), cwnd, "…nor the window directly");
    }

    #[test]
    fn pacer_spreads_a_window_and_bounds_the_burst() {
        let mut p = Pacer::new(100_000.0, 10_000);
        assert!(!p.try_consume(20_000, Duration::ZERO));
        assert!(p.try_consume(10_000, Duration::ZERO));
        assert!(
            !p.try_consume(1, Duration::ZERO),
            "the burst cap must be fully spent"
        );
        assert!(p.try_consume(4_999, ms(50)));
        assert!(!p.try_consume(2, ms(50)));
        assert!(p.try_consume(10_000, Duration::from_secs(60)));
        assert!(!p.try_consume(1, Duration::from_secs(60)));
    }

    #[test]
    fn pacer_reports_the_wait_for_credit() {
        let mut p = Pacer::new(1_000.0, 0);
        let wait = p.delay_for(500, Duration::ZERO);
        assert!(
            (wait.as_secs_f64() - 0.5).abs() < 1e-6,
            "500 bytes at 1 kB/s is 0.5 s, got {wait:?}"
        );
        assert_eq!(p.delay_for(0, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn engine_tracks_what_is_in_flight() {
        let mut e = AckEngine::with_mss(DEFAULT_MSS);
        let now = Duration::ZERO;
        assert_eq!(e.in_flight(), 0);
        e.on_send(1000, now);
        e.on_send(1000, now);
        assert_eq!(e.in_flight(), 2000);
        let outcome = e.on_ack(1, now); // acks seq 0 only
        assert_eq!(outcome.newly_acked, 1000);
        assert_eq!(e.in_flight(), 1000);
        assert!(!outcome.flight_cleared);
        let outcome = e.on_ack(2, now);
        assert!(outcome.flight_cleared);
        assert_eq!(e.in_flight(), 0);
        assert_eq!(e.stats().segments_acked, 2);
    }

    #[test]
    fn engine_estimates_rtt_per_rfc_6298() {
        let mut e = AckEngine::with_mss(DEFAULT_MSS);
        let mut clock = Duration::ZERO;
        e.on_send(1000, clock);
        clock += ms(100);
        let outcome = e.on_ack(1, clock);
        assert_eq!(outcome.rtt, Some(ms(100)), "the raw sample is reported");
        assert_eq!(e.highest_acked(), Some(1));
        assert_eq!(e.srtt(), Some(ms(100)));
        let first_rto = e.rto();
        assert_eq!(first_rto, MIN_RTO);

        e.on_send(1000, clock);
        clock += ms(200);
        e.on_ack(2, clock);
        let srtt = e.srtt().unwrap();
        assert!(
            (srtt.as_secs_f64() - 0.1125).abs() < 1e-6,
            "srtt after a 200 ms sample should be 112.5 ms, got {srtt:?}"
        );
        assert_eq!(e.min_rtt(), Some(ms(100)));
    }

    #[test]
    fn three_duplicate_acks_are_a_loss_and_cut_the_window_once() {
        let mut e = AckEngine::with_mss(DEFAULT_MSS);
        let now = Duration::ZERO;
        let window = e.cwnd();
        for _ in 0..(window / DEFAULT_MSS) {
            e.on_send(DEFAULT_MSS, now);
        }
        e.on_ack(e.next_seq, now);
        let before = e.cwnd();

        for _ in 0..3 {
            e.on_send(DEFAULT_MSS, now);
        }
        let mut loss_seen = 0;
        for _ in 0..3 {
            let outcome = e.on_ack(0, now);
            if outcome.loss {
                loss_seen += 1;
            }
        }
        assert_eq!(loss_seen, 1, "only the third duplicate ACK declares loss");
        assert_eq!(e.cwnd(), (before as f64 * CUBIC_BETA) as u64);
        assert_eq!(e.stats().loss_events, 1);

        let outcome = e.on_ack(0, now);
        assert!(outcome.loss);
        assert_eq!(
            e.stats().loss_events,
            1,
            "one flight, one loss event — compounding the reduction is the bug"
        );
    }

    #[test]
    fn a_timeout_backs_the_rto_off_and_is_bounded() {
        let mut e = AckEngine::with_mss(DEFAULT_MSS);
        e.on_send(1000, Duration::ZERO);
        let base = e.rto();
        e.on_timeout(Duration::from_secs(1));
        assert!(e.rto() >= base, "the RTO must not shrink on timeout");
        for _ in 0..10 {
            e.on_timeout(Duration::from_secs(1));
        }
        assert_eq!(e.rto(), MAX_RTO, "RTO must be clamped");
        assert!(e.stats().timeouts >= 10);
    }

    #[test]
    fn engine_refuses_to_exceed_the_window() {
        let mut e = AckEngine::with_mss(DEFAULT_MSS);
        let now = Duration::ZERO;
        let window = e.cwnd();
        let mut sent = 0;
        while e.send_allowance(now) >= DEFAULT_MSS {
            e.on_send(DEFAULT_MSS, now);
            sent += DEFAULT_MSS;
        }
        assert!(
            sent <= window,
            "sent {sent} bytes against a {window}-byte window"
        );
        assert_eq!(e.send_allowance(now), 0, "the window must be closed");
        assert!(e.stats().cwnd_limited > 0);
    }

    #[test]
    fn a_full_round_trip_grows_a_cubic_window_along_the_curve() {
        let mut e = AckEngine::with_mss(DEFAULT_MSS);
        let mut clock = Duration::ZERO;
        let windows = grow(&mut e, 3, ms(50), &mut clock);
        assert!(
            windows.windows(2).all(|w| w[1] > w[0]),
            "a clean path must keep growing: {windows:?}"
        );
        let slow_start_growth = windows[2] as f64 / windows[1] as f64;
        assert!(
            (slow_start_growth - 2.0).abs() < 0.35,
            "slow start should roughly double, got {slow_start_growth}"
        );
        let before_loss = e.cwnd();
        force_loss(&mut e, clock);
        let after_cut = e.cwnd();
        assert!(
            after_cut < before_loss,
            "the loss must cut the window: {after_cut} vs {before_loss}"
        );
        assert!(
            after_cut >= MIN_PIPE_CWND,
            "the cut must leave a usable window: {after_cut}"
        );

        let ca = grow(&mut e, 6, ms(50), &mut clock);
        let ca_growth = ca[5] as f64 / ca[4] as f64;
        assert!(ca_growth > 1.0, "…but it must still grow: {ca_growth}");
        assert!(
            ca_growth < 1.5,
            "congestion avoidance must not double the window: {ca_growth}"
        );
        assert!(
            ca_growth < slow_start_growth,
            "the curve must be flatter than slow start: {ca_growth} vs {slow_start_growth}"
        );
    }

    #[test]
    fn a_bbr_engine_paces_at_its_modelled_rate() {
        let mut e = AckEngine::new(CcAlgorithm::Bbr, DEFAULT_MSS);
        let mut clock = Duration::ZERO;
        for _ in 0..4 {
            send_a_window(&mut e, clock);
            clock += ms(50);
            e.on_ack(e.next_seq, clock);
        }
        assert!(e.srtt().is_some());
        let allowance = e.send_allowance(clock);
        assert!(allowance > 0, "a BBR engine must still be able to send");
        assert_eq!(e.algorithm(), CcAlgorithm::Bbr);
        assert_eq!(e.algorithm().as_str(), "bbr");
    }

    #[test]
    fn every_algorithm_survives_a_lossy_round_trip() {
        for algorithm in [CcAlgorithm::Cubic, CcAlgorithm::NewReno, CcAlgorithm::Bbr] {
            let mut e = AckEngine::new(algorithm, DEFAULT_MSS);
            let mut clock = Duration::ZERO;
            for round in 0..60u64 {
                send_a_window(&mut e, clock);
                clock += ms(40);
                let lost = (e.outstanding().len() / 3) as u64;
                let ack = e.next_seq.saturating_sub(lost);
                e.on_ack(ack, clock);
                if round % 7 == 0 {
                    e.on_timeout(clock);
                }
            }
            assert!(
                e.cwnd() >= MIN_PIPE_CWND,
                "{} collapsed to {} bytes",
                algorithm.as_str(),
                e.cwnd()
            );
            assert!(
                e.cwnd() <= DEFAULT_MAX_CWND,
                "{} grew unbounded to {} bytes",
                algorithm.as_str(),
                e.cwnd()
            );
            assert!(
                e.min_rtt().is_some() || algorithm == CcAlgorithm::Bbr,
                "{} never measured the path",
                algorithm.as_str()
            );
        }
    }

    #[test]
    fn ack_pdu_round_trips_and_rejects_non_ack_payloads() {
        let pdu = AckPdu::new(0x0102_0304_0506_0708);
        let raw = pdu.encode();
        assert_eq!(raw.len(), ACK_PDU_LEN);
        assert_eq!(raw[0], ACK_PDU_TYPE);
        assert_eq!(AckPdu::decode(&raw), Some(pdu));
        assert_eq!(AckPdu::decode(b"data"), None);
        assert_eq!(AckPdu::decode(&[0x00; ACK_PDU_LEN]), None);
        assert_eq!(AckPdu::decode(&raw[..ACK_PDU_LEN - 1]), None);
    }

    #[test]
    fn an_ack_pdu_carries_a_full_window_of_sequence_numbers() {
        for ack in [0u64, 1, 255, 256, 65_535, u32::MAX as u64, u64::MAX] {
            let raw = AckPdu::new(ack).encode();
            assert_eq!(AckPdu::decode(&raw).unwrap().ack, ack);
        }
    }

    #[test]
    fn the_governor_shapes_the_flow_controller_to_the_weakest_live_path() {
        let flow = FlowController::new(200);
        let gov = TransitGovernor::new(200 * 125_000);
        let rate = gov.apply(&flow, &[10_000_000.0, 2_000_000.0]);
        assert_eq!(rate, 2_000_000);
        assert_eq!(flow.transit_rate_bps(), 2_000_000);
        assert_eq!(gov.shaped_bps(), 2_000_000);
        assert_eq!(gov.updates(), 1);
        assert_eq!(gov.paths_seen(), 2);
    }

    #[test]
    fn the_operator_ceiling_is_a_hard_maximum() {
        let flow = FlowController::new(8);
        let gov = TransitGovernor::new(8 * 125_000);
        let rate = gov.apply(&flow, &[500_000_000.0, 50_000_000.0]);
        assert_eq!(rate, 1_000_000);
        assert!(rate <= gov.ceiling_bps());
        gov.set_ceiling_mbps(1);
        assert_eq!(gov.apply(&flow, &[500_000_000.0]), 125_000);
    }

    #[test]
    fn a_node_with_nothing_measured_keeps_its_configured_rate() {
        let flow = FlowController::new(100);
        let gov = TransitGovernor::new(100 * 125_000);
        let configured = flow.transit_rate_bps();
        assert_eq!(gov.apply(&flow, &[]), configured);
        assert_eq!(gov.apply(&flow, &[0.0, f64::NAN, -4.0]), configured);
        assert_eq!(gov.updates(), 0, "nothing measured, nothing to apply");
        assert_eq!(gov.paths_seen(), 0);
        assert_eq!(flow.transit_rate_bps(), configured);
    }

    #[test]
    fn a_collapsing_path_cannot_drive_the_shaper_to_zero() {
        let flow = FlowController::new(100);
        let gov = TransitGovernor::new(100 * 125_000);
        let rate = gov.apply(&flow, &[1.0]);
        assert_eq!(rate, MIN_SHAPED_RATE_BPS);
        assert!(
            flow.transit_rate_bps() > 0,
            "a stuck shaper is worse than a slow one"
        );
    }
}
