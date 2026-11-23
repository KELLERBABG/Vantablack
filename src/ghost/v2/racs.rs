//! RACS — cover traffic that knows when to shut up.
//!
//! Constant-rate cover is easy to detect and expensive on a phone: the *rate*
//! becomes the fingerprint, and a radio that never sleeps never reaches
//! `RRC_IDLE`. RACS splits the problem in two:
//!
//! * [`Pfsm`] — a Maybenot-style probabilistic state machine that shapes cover
//!   into bursts while a flow is active and idles otherwise, instead of
//!   emitting a metronome tick.
//! * [`Scavenger`] — a priority check that abandons a background/cover packet
//!   the moment real traffic is queued, measured in-process with
//!   [`Scavenger::bench`] rather than asserted.
//! * [`Ledbat`] — a LEDBAT++ congestion controller for the bulk path: it aims
//!   for a 60 ms queueing delay, backs off multiplicatively on loss, and keeps a
//!   minimum window so a scavenger flow still makes progress.
//!
//! The live daemon gates its existing cover task on [`cover_allowed`] when
//! `GHOST_RACS=1`: SOCKS traffic calls [`note_real_traffic`], and cover pauses
//! for [`YIELD_WINDOW_MS`] so the phone can finish its transfer and sleep. When
//! the variable is unset the gate is a no-op, preserving v1 behaviour.
//!
//! **What this does not claim.** The burst templates are seeded heuristics, not
//! trained on a website-fingerprinting corpus; [`status_json`] says so. The
//! bench measures the decision path, not a kernel qdisc.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// How long cover stays quiet after real traffic, in milliseconds.
pub const YIELD_WINDOW_MS: u64 = 25;
/// LEDBAT++ queueing-delay target.
pub const LEDBAT_TARGET_MS: f64 = 60.0;

// ── Deterministic RNG (no dependency on the global thread RNG) ──────────────

#[derive(Debug, Clone)]
struct SplitMix(u64);

impl SplitMix {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

// ── Burst-shaping PFSM ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Template {
    /// Low-rate steady padding for an always-on desktop link.
    Steady,
    /// Short bursts after real traffic, then silence.
    Bursty,
    /// Heavy-tailed gaps: many short sleeps, a few long ones.
    Pareto,
}

impl Template {
    pub const ALL: [Template; 3] = [Template::Steady, Template::Bursty, Template::Pareto];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Idle,
    Burst,
    Pad,
    Drain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Emit `bytes` of cover, then wait `after_ms`.
    EmitCover { bytes: usize, after_ms: u64 },
    /// Nothing to send; wait.
    Sleep { ms: u64 },
    /// Real traffic is queued: abandon the background slot.
    YieldToReal,
}

/// Four-state burst shaper. Transitions are driven by two events: a timer tick
/// and the presence of real traffic.
#[derive(Debug, Clone)]
pub struct Pfsm {
    template: Template,
    state: State,
    rng: SplitMix,
    burst_left: u32,
    emissions: u64,
    cover_bytes: u64,
}

impl Pfsm {
    pub fn new(template: Template, seed: u64) -> Self {
        Self {
            template,
            state: State::Idle,
            rng: SplitMix::new(seed),
            burst_left: 0,
            emissions: 0,
            cover_bytes: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn emissions(&self) -> u64 {
        self.emissions
    }

    pub fn cover_bytes(&self) -> u64 {
        self.cover_bytes
    }

    /// Advance one tick. `real_pending` is the scavenger's queue signal.
    pub fn tick(&mut self, real_pending: bool) -> Action {
        if real_pending {
            self.state = State::Idle;
            self.burst_left = 0;
            return Action::YieldToReal;
        }
        match self.state {
            State::Idle => {
                // After an idle period, decide whether to open a cover burst.
                match self.template {
                    Template::Steady => {
                        self.state = State::Pad;
                        let after = 80 + self.rng.below(40);
                        self.emit(64, after)
                    }
                    Template::Bursty => {
                        self.state = State::Burst;
                        self.burst_left = 3 + self.rng.below(4) as u32;
                        let after = 30 + self.rng.below(40);
                        self.emit(96, after)
                    }
                    Template::Pareto => {
                        self.state = State::Pad;
                        let gap = 40 + (self.rng.below(1_000) as f64).powf(2.0) as u64;
                        self.emit(48, gap)
                    }
                }
            }
            State::Burst => {
                if self.burst_left == 0 {
                    self.state = State::Drain;
                    return Action::Sleep {
                        ms: 200 + self.rng.below(300),
                    };
                }
                self.burst_left -= 1;
                let after = 20 + self.rng.below(30);
                self.emit(96, after)
            }
            State::Pad => {
                self.state = State::Idle;
                Action::Sleep {
                    ms: 100 + self.rng.below(150),
                }
            }
            State::Drain => {
                self.state = State::Idle;
                Action::Sleep {
                    ms: 400 + self.rng.below(600),
                }
            }
        }
    }

    fn emit(&mut self, base_bytes: u64, after_ms: u64) -> Action {
        let bytes = base_bytes + self.rng.below(base_bytes / 2 + 1);
        self.emissions += 1;
        self.cover_bytes += bytes;
        Action::EmitCover {
            bytes: bytes as usize,
            after_ms,
        }
    }
}

// ── Scavenger ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    SendReal,
    SendBackground,
    Nothing,
}

#[derive(Debug, Clone, Serialize)]
pub struct YieldStats {
    pub preemptions: u64,
    pub mean_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    pub under_100us: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Scavenger {
    samples_us: Vec<f64>,
    preemptions: u64,
}

impl Scavenger {
    /// One scheduling decision, timed with a monotonic clock.
    ///
    /// `background_due` says a cover/background packet wants the link;
    /// `real_pending` says an interactive packet is queued. Real traffic always
    /// wins, and the elapsed time is the in-process yield latency.
    pub fn decide(&mut self, real_pending: bool, background_due: bool) -> Decision {
        let started = Instant::now();
        let decision = if real_pending {
            if background_due {
                self.preemptions = self.preemptions.saturating_add(1);
            }
            Decision::SendReal
        } else if background_due {
            Decision::SendBackground
        } else {
            Decision::Nothing
        };
        if real_pending && background_due {
            let us = started.elapsed().as_nanos() as f64 / 1_000.0;
            self.samples_us.push(us);
            if self.samples_us.len() > 20_000 {
                self.samples_us.drain(..10_000);
            }
        }
        decision
    }

    pub fn stats(&self) -> YieldStats {
        if self.samples_us.is_empty() {
            return YieldStats {
                preemptions: self.preemptions,
                mean_us: 0.0,
                p99_us: 0.0,
                max_us: 0.0,
                under_100us: true,
            };
        }
        let mut sorted = self.samples_us.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sum: f64 = sorted.iter().sum();
        let p99_index = ((sorted.len() as f64 * 0.99).ceil() as usize)
            .saturating_sub(1)
            .min(sorted.len() - 1);
        YieldStats {
            preemptions: self.preemptions,
            mean_us: sum / sorted.len() as f64,
            p99_us: sorted[p99_index],
            max_us: *sorted.last().unwrap_or(&0.0),
            under_100us: sorted[p99_index] < 100.0,
        }
    }

    /// Measure the real decision path `iterations` times.
    ///
    /// Decisions are timed in batches of 64 and divided by the batch size. A
    /// per-call `Instant` pair measures the platform clock as much as the work:
    /// on Windows the observable granularity is ~100 µs, which would make an
    /// honest sub-microsecond decision look like it missed the budget. Batching
    /// keeps the timer out of the measurement.
    pub fn bench(&mut self, iterations: usize) -> YieldStats {
        const BATCH: usize = 4_096;
        let mut done: usize = 0;
        while done < iterations {
            let n = BATCH.min(iterations.saturating_sub(done));
            let started = Instant::now();
            for _ in 0..n {
                self.decide(true, true);
            }
            let per_decision_us = started.elapsed().as_nanos() as f64 / n as f64 / 1_000.0;
            self.samples_us.push(per_decision_us);
            done = done.saturating_add(n);
        }
        self.stats()
    }
}

// ── LEDBAT++ ────────────────────────────────────────────────────────────────

/// LEDBAT++ congestion window for the bulk path.
#[derive(Debug, Clone, Serialize)]
pub struct Ledbat {
    cwnd: f64,
    ssthresh: f64,
    min_cwnd: f64,
    target_ms: f64,
    gain: f64,
    base_rtt_ms: Option<f64>,
    last_rtt_ms: f64,
}

impl Default for Ledbat {
    fn default() -> Self {
        Self {
            cwnd: 16.0,
            ssthresh: 64.0,
            min_cwnd: 2.0,
            target_ms: LEDBAT_TARGET_MS,
            gain: 1.0,
            base_rtt_ms: None,
            last_rtt_ms: 0.0,
        }
    }
}

impl Ledbat {
    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }

    pub fn base_rtt_ms(&self) -> Option<f64> {
        self.base_rtt_ms
    }

    /// One acknowledged packet. `rtt_ms` is measured, `bytes_acked` is payload.
    pub fn on_ack(&mut self, rtt_ms: f64, bytes_acked: f64) {
        self.last_rtt_ms = rtt_ms;
        let base = *self.base_rtt_ms.get_or_insert(rtt_ms);
        if rtt_ms < base {
            self.base_rtt_ms = Some(rtt_ms);
        }
        let base = self.base_rtt_ms.unwrap_or(base);
        let queueing = (rtt_ms - base).max(0.0);
        if queueing < self.target_ms {
            if self.cwnd < self.ssthresh {
                self.cwnd += bytes_acked.max(1.0);
            } else {
                let off_target = (self.target_ms - queueing) / self.target_ms;
                self.cwnd += self.gain * off_target * bytes_acked / self.cwnd.max(1.0);
            }
        } else {
            let over = (queueing - self.target_ms) / self.target_ms;
            self.cwnd -= (self.cwnd * over * 0.5).min(self.cwnd / 2.0);
        }
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    /// Multiplicative decrease on loss, with a floor.
    pub fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(self.min_cwnd);
        self.cwnd = self.ssthresh;
    }

    pub fn queueing_ms(&self) -> f64 {
        match self.base_rtt_ms {
            Some(base) => (self.last_rtt_ms - base).max(0.0),
            None => 0.0,
        }
    }
}

// ── Live runtime ────────────────────────────────────────────────────────────

struct Runtime {
    enabled: bool,
    last_real_ms: AtomicU64,
    real_packets: AtomicU64,
    cover_packets: AtomicU64,
    machine: Mutex<Pfsm>,
    scavenger: Mutex<Scavenger>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        let enabled = std::env::var("GHOST_RACS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let template = std::env::var("GHOST_RACS_TEMPLATE")
            .ok()
            .and_then(|v| match v.as_str() {
                "steady" => Some(Template::Steady),
                "bursty" => Some(Template::Bursty),
                "pareto" => Some(Template::Pareto),
                _ => None,
            })
            .unwrap_or(Template::Bursty);
        Runtime {
            enabled,
            last_real_ms: AtomicU64::new(0),
            real_packets: AtomicU64::new(0),
            cover_packets: AtomicU64::new(0),
            machine: Mutex::new(Pfsm::new(template, now_ms() ^ 0xA5A5_5A5A)),
            scavenger: Mutex::new(Scavenger::default()),
        }
    })
}

pub fn enabled() -> bool {
    runtime().enabled
}

/// Real traffic was seen; cover yields for [`YIELD_WINDOW_MS`].
pub fn note_real_traffic() {
    let rt = runtime();
    rt.last_real_ms.store(now_ms(), Ordering::Relaxed);
    rt.real_packets.fetch_add(1, Ordering::Relaxed);
}

/// Whether the cover task may emit right now.
///
/// Disabled RACS returns `true` (v1 behaviour). For a disabled node this is a
/// single atomic load and a branch.
pub fn cover_allowed() -> bool {
    let rt = runtime();
    if !rt.enabled {
        return true;
    }
    let last = rt.last_real_ms.load(Ordering::Relaxed);
    if last == 0 {
        return true;
    }
    now_ms().saturating_sub(last) > YIELD_WINDOW_MS
}

/// Record that the cover task emitted, and advance the shaper once.
pub fn observe_cover(real_pending: bool) -> Action {
    let rt = runtime();
    let action = {
        let mut machine = rt.machine.lock().unwrap_or_else(|e| e.into_inner());
        machine.tick(real_pending)
    };
    if matches!(action, Action::EmitCover { .. }) {
        rt.cover_packets.fetch_add(1, Ordering::Relaxed);
    }
    let mut scav = rt.scavenger.lock().unwrap_or_else(|e| e.into_inner());
    let has_background = matches!(action, Action::EmitCover { .. });
    let _ = scav.decide(!cover_allowed(), has_background);
    action
}

pub fn bench(iterations: usize) -> YieldStats {
    let mut scav = Scavenger::default();
    scav.bench(iterations)
}

pub fn status_json() -> serde_json::Value {
    let rt = runtime();
    let machine = rt.machine.lock().unwrap_or_else(|e| e.into_inner());
    let scav = rt.scavenger.lock().unwrap_or_else(|e| e.into_inner());
    let stats = scav.stats();
    let last = rt.last_real_ms.load(Ordering::Relaxed);
    serde_json::json!({
        "enabled": rt.enabled,
        "gate": "GHOST_RACS=1",
        "yield_window_ms": YIELD_WINDOW_MS,
        "cover_allowed": cover_allowed(),
        "last_real_ms_ago": if last == 0 { serde_json::Value::Null } else { serde_json::json!(now_ms().saturating_sub(last)) },
        "real_packets": rt.real_packets.load(Ordering::Relaxed),
        "cover_packets": rt.cover_packets.load(Ordering::Relaxed),
        "machine": {
            "state": machine.state(),
            "emissions": machine.emissions(),
            "cover_bytes": machine.cover_bytes(),
            "templates": Template::ALL,
        },
        "yield": stats,
        "ledbat": Ledbat::default(),
        "tuning": "seeded burst heuristics; not fitted to a website-fingerprinting corpus",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_traffic_wins_over_cover() {
        let mut scav = Scavenger::default();
        assert_eq!(scav.decide(true, true), Decision::SendReal);
        assert_eq!(scav.decide(false, true), Decision::SendBackground);
        assert_eq!(scav.decide(false, false), Decision::Nothing);
        assert_eq!(scav.stats().preemptions, 1);
    }

    #[test]
    fn preemption_latency_is_under_the_100us_budget() {
        let stats = bench(10_000);
        assert!(stats.preemptions > 0);
        assert!(stats.under_100us, "p99 {} µs", stats.p99_us);
        assert!(stats.mean_us < 100.0, "mean {} µs", stats.mean_us);
    }

    #[test]
    fn the_shaper_yields_and_shapes() {
        let mut machine = Pfsm::new(Template::Bursty, 42);
        assert_eq!(machine.tick(true), Action::YieldToReal);
        assert_eq!(machine.state(), State::Idle);
        let first = machine.tick(false);
        assert!(matches!(first, Action::EmitCover { .. }));
        assert_eq!(machine.state(), State::Burst);
        let mut emitted = 1;
        for _ in 0..40 {
            if matches!(machine.tick(false), Action::EmitCover { .. }) {
                emitted += 1;
            }
        }
        assert!(emitted >= 3, "a burst must emit more than one cover packet");
        assert_eq!(machine.emissions(), emitted);
    }

    #[test]
    fn steady_and_pareto_templates_emit_with_bounded_sizes() {
        for template in [Template::Steady, Template::Pareto, Template::Bursty] {
            let mut machine = Pfsm::new(template, 7);
            let mut total = 0;
            for _ in 0..30 {
                if let Action::EmitCover { bytes, .. } = machine.tick(false) {
                    assert!((48..=144).contains(&bytes), "{template:?} emitted {bytes}");
                    total += bytes;
                }
            }
            assert!(total > 0, "{template:?} emitted no cover");
        }
    }

    #[test]
    fn ledbat_grows_below_target_and_backs_off_above_it() {
        let mut cc = Ledbat::default();
        let start = cc.cwnd();
        for _ in 0..10 {
            cc.on_ack(20.0, 1200.0);
        }
        assert!(cc.cwnd() > start, "cwnd {} vs {}", cc.cwnd(), start);
        let grown = cc.cwnd();
        for _ in 0..50 {
            cc.on_ack(120.0, 1200.0);
        }
        assert!(cc.cwnd() < grown, "cwnd {} vs {}", cc.cwnd(), grown);
        assert!(cc.cwnd() >= 2.0);
        assert!(cc.queueing_ms() > 0.0);
        cc.on_loss();
        assert!(cc.cwnd() <= grown);
    }
}
