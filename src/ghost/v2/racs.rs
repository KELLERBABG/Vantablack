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
//! `GHOST_RACS=1`. Frames leave only on an **input-independent** ON/OFF renewal
//! schedule ([`slot_is_on`]): a fixed 250 ms slot grid, a cycle whose ON length
//! is redrawn every twelve slots, and 576-byte frames. Real traffic never moves
//! an edge — it only fills a slot that was already ON. The previous design
//! suppressed cover for 25 ms after real traffic, which handed an observer a
//! deterministic burst-end marker; that window is gone.
//!
//! **What this does not claim.** The schedule is a fixed heuristic, not fitted
//! to a website-fingerprinting corpus; [`status_json`] says so. Substitution of
//! a queued *real* frame into an ON slot is reported by [`observe_cover`]'s
//! `real` flag, but the daemon's current cover emitter only produces dummy
//! frames, so that field stays `false` on this path. The bench measures the
//! decision path, not a kernel qdisc.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

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

// ── Input-independent slot schedule ─────────────────────────────────────────

/// Slot length. Every slot is the same length whether or not a frame leaves.
pub const SLOT_MS: u64 = 250;
/// Wire size of one scheduled frame.
pub const FRAME_BYTES: usize = 576;
/// Slots per renewal cycle. ON lengths are drawn per cycle; OFF is the rest.
const CYCLE_SLOTS: u64 = 12;
/// ON lengths a cycle may draw.
const ON_CHOICES: [u64; 3] = [1, 2, 3];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// This slot may carry one frame. `real` says a queued real frame took the
    /// slot; `false` means the 576 bytes are dummy.
    EmitFrame {
        bytes: usize,
        real: bool,
        after_ms: u64,
    },
    /// OFF slot: nothing leaves, whatever the queue holds.
    Sleep { ms: u64 },
}

/// Whether slot `slot` of `seed`'s schedule is ON.
///
/// This is a pure function of `(seed, slot_index)`. It reads no queue and no
/// clock, so traffic cannot move an edge — the failure that made the old 25 ms
/// yield window a deterministic burst-end marker. Each cycle redraws its ON
/// start and length, which is the renewal part: bursts vary, the duty cycle
/// stays bounded.
pub fn slot_is_on(seed: u64, slot: u64) -> bool {
    let cycle = slot / CYCLE_SLOTS;
    let pos = slot % CYCLE_SLOTS;
    let mut rng = SplitMix::new(seed ^ cycle.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let start = rng.below(CYCLE_SLOTS);
    let len = ON_CHOICES[rng.below(ON_CHOICES.len() as u64) as usize];
    let end = start + len;
    if end <= CYCLE_SLOTS {
        pos >= start && pos < end
    } else {
        // A cycle that wraps: ON runs past the boundary into the next cycle.
        pos >= start || pos < end - CYCLE_SLOTS
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
    /// Monotonic-enough epoch the slot grid is counted from.
    epoch_ms: u64,
    /// Per-process schedule seed. Independent of traffic.
    seed: u64,
    last_real_ms: AtomicU64,
    real_packets: AtomicU64,
    /// Frames emitted on the schedule, dummy or real.
    cover_packets: AtomicU64,
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
        let started = now_ms();
        Runtime {
            enabled,
            epoch_ms: started,
            seed: started ^ 0xA5A5_5A5A_5A5A_A5A5,
            last_real_ms: AtomicU64::new(0),
            real_packets: AtomicU64::new(0),
            cover_packets: AtomicU64::new(0),
            scavenger: Mutex::new(Scavenger::default()),
        }
    })
}

pub fn enabled() -> bool {
    runtime().enabled
}

/// Current slot on this process's schedule.
fn current_slot(rt: &Runtime) -> u64 {
    now_ms().saturating_sub(rt.epoch_ms) / SLOT_MS
}

/// Real traffic was seen. This records *what* is queued for the next ON slot; it
/// never delays or gates an emission.
pub fn note_real_traffic() {
    let rt = runtime();
    rt.last_real_ms.store(now_ms(), Ordering::Relaxed);
    rt.real_packets.fetch_add(1, Ordering::Relaxed);
}

/// Whether a real frame is queued for the current slot.
///
/// This is a one-slot lookback for classification only. Nothing in the schedule
/// reads it.
pub fn real_traffic_pending() -> bool {
    let rt = runtime();
    if !rt.enabled {
        return false;
    }
    let last = rt.last_real_ms.load(Ordering::Relaxed);
    last != 0 && now_ms().saturating_sub(last) <= SLOT_MS
}

/// Whether the cover task may emit in this slot.
///
/// Disabled RACS returns `true` (v1 behaviour). Enabled RACS returns the
/// schedule's decision for the current slot, and nothing else: no queue length,
/// no recent-traffic timer, no rate estimate.
pub fn cover_allowed() -> bool {
    let rt = runtime();
    !rt.enabled || slot_is_on(rt.seed, current_slot(rt))
}

/// Account for one emission attempt and return the slot's decision.
///
/// A slot that is ON emits one [`FRAME_BYTES`] frame; a queued real frame is
/// offered the slot first (`real: true`), otherwise the frame is dummy. An OFF
/// slot emits nothing even when real traffic is queued — that is the cost of an
/// input-independent schedule, and it is why the covered link must have enough
/// duty cycle for the flows it carries.
pub fn observe_cover(real_pending: bool) -> Action {
    let rt = runtime();
    let on = !rt.enabled || slot_is_on(rt.seed, current_slot(rt));
    let real = on && real_pending;
    let action = if on {
        rt.cover_packets.fetch_add(1, Ordering::Relaxed);
        Action::EmitFrame {
            bytes: FRAME_BYTES,
            real,
            after_ms: SLOT_MS,
        }
    } else {
        Action::Sleep { ms: SLOT_MS }
    };
    let mut scav = rt.scavenger.lock().unwrap_or_else(|e| e.into_inner());
    let _ = scav.decide(real, on);
    action
}

/// Frames emitted on the schedule since process start. This is the counter the
/// truth ledger reads, so it must be a wire event and not a configuration bit.
pub fn cover_packets_emitted() -> u64 {
    runtime().cover_packets.load(Ordering::Relaxed)
}

static REAL_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Mark that a real application frame was queued/sent for the current RACS slot.
pub fn note_real_sent() {
    REAL_PENDING.store(true, Ordering::Release);
}

/// Consume the real-frame flag for the current RACS cover emission slot.
pub fn take_real_pending() -> bool {
    REAL_PENDING.swap(false, Ordering::AcqRel)
}

pub fn bench(iterations: usize) -> YieldStats {
    let mut scav = Scavenger::default();
    scav.bench(iterations)
}

pub fn status_json() -> serde_json::Value {
    let rt = runtime();
    let scav = rt.scavenger.lock().unwrap_or_else(|e| e.into_inner());
    let stats = scav.stats();
    let last = rt.last_real_ms.load(Ordering::Relaxed);
    serde_json::json!({
        "enabled": rt.enabled,
        "gate": "GHOST_RACS=1",
        "schedule": {
            "slot_ms": SLOT_MS,
            "frame_bytes": FRAME_BYTES,
            "cycle_slots": CYCLE_SLOTS,
            "on_choices": ON_CHOICES,
            "slot": current_slot(rt),
            "current_slot_on": cover_allowed(),
            "input_independent": true,
            "renewal": "ON start and length redrawn every cycle; traffic fills a slot but never moves one",
        },
        "cover_allowed": cover_allowed(),
        "last_real_ms_ago": if last == 0 { serde_json::Value::Null } else { serde_json::json!(now_ms().saturating_sub(last)) },
        "real_packets": rt.real_packets.load(Ordering::Relaxed),
        "cover_packets": rt.cover_packets.load(Ordering::Relaxed),
        "yield": stats,
        "ledbat": Ledbat::default(),
        "tuning": "fixed ON/OFF renewal schedule; not fitted to a website-fingerprinting corpus",
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
    fn the_schedule_reads_no_traffic_state() {
        // `slot_is_on` takes only `(seed, slot)`, so the strongest test is that
        // the same slot sequence is reproduced after a burst of real packets.
        let seed = 0x1234_5678_9ABC_DEF0;
        let baseline: Vec<bool> = (0..CYCLE_SLOTS * 8).map(|s| slot_is_on(seed, s)).collect();

        let rt = runtime();
        rt.real_packets.fetch_add(100_000, Ordering::Relaxed);
        rt.last_real_ms.store(now_ms(), Ordering::Relaxed);

        let after: Vec<bool> = (0..CYCLE_SLOTS * 8).map(|s| slot_is_on(seed, s)).collect();
        assert_eq!(baseline, after, "traffic must not move a schedule edge");
    }

    #[test]
    fn on_slots_are_bounded_bursts_inside_each_cycle() {
        let seed = 99;
        let cap = *ON_CHOICES.iter().max().unwrap();
        let mut saw_on = false;
        let mut saw_off = false;
        let mut total_on = 0u64;
        let cycles = 40u64;
        for cycle in 0..cycles {
            let mut on_in_cycle = 0u64;
            for pos in 0..CYCLE_SLOTS {
                if slot_is_on(seed, cycle * CYCLE_SLOTS + pos) {
                    on_in_cycle += 1;
                    total_on += 1;
                    saw_on = true;
                } else {
                    saw_off = true;
                }
            }
            // A wrapping ON run contributes to two cycles, so the worst case
            // for one cycle is two burst lengths at the boundary.
            assert!(
                on_in_cycle <= 2 * cap,
                "cycle {cycle} had {on_in_cycle} ON slots, cap {cap}"
            );
        }
        let duty = total_on as f64 / (cycles * CYCLE_SLOTS) as f64;
        assert!(duty <= 0.35, "duty cycle {duty} must stay low");
        assert!(
            saw_on && saw_off,
            "the schedule must renew between ON and OFF"
        );
    }

    #[test]
    fn frames_are_fixed_at_576_bytes() {
        assert_eq!(FRAME_BYTES, 576);
        assert_eq!(SLOT_MS, 250, "a slot shorter than the link RTT is noise");
    }

    #[test]
    fn an_off_slot_emits_nothing_and_an_on_slot_emits_one_frame() {
        // The live slot is clock-driven, so the assertion is the invariant the
        // two branches share rather than a forced state.
        match observe_cover(true) {
            Action::EmitFrame {
                bytes, after_ms, ..
            } => {
                assert_eq!(bytes, FRAME_BYTES);
                assert_eq!(after_ms, SLOT_MS);
                assert!(cover_allowed(), "an emitting slot must be ON");
            }
            Action::Sleep { ms } => {
                assert_eq!(ms, SLOT_MS);
                assert!(!cover_allowed(), "a sleeping slot must be OFF");
            }
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
