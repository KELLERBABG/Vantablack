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

pub const LEDBAT_TARGET_MS: f64 = 60.0;

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

pub const SLOT_MS: u64 = 250;
pub const FRAME_BYTES: usize = 576;
const CYCLE_SLOTS: u64 = 12;
const ON_CHOICES: [u64; 3] = [1, 2, 3];
pub const MAX_ON_RUN_SLOTS: u64 = 3;
pub const MAX_DUTY: f64 = 0.35;
pub const MIN_SHAPING_SLOTS: u64 = 48;
pub const SHAPING_TTL_SECS: u64 = 120;
const EVIDENCE_WINDOW_SLOTS: u64 = 240;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ShapingEvidence {
    pub slots: u64,
    pub emissions: u64,
    pub max_on_run: u64,
    pub duty: f64,
    pub last_emission_unix: u64,
}

impl ShapingEvidence {
    pub fn measured_enough(&self) -> bool {
        self.slots >= MIN_SHAPING_SLOTS && self.emissions > 0
    }

    pub fn within_contract(&self) -> bool {
        self.max_on_run <= MAX_ON_RUN_SLOTS && self.duty <= MAX_DUTY
    }

    pub fn is_fresh(&self) -> bool {
        self.last_emission_unix != 0
            && super::now_secs().saturating_sub(self.last_emission_unix) <= SHAPING_TTL_SECS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    EmitFrame {
        bytes: usize,
        real: bool,
        after_ms: u64,
    },
    Sleep { ms: u64 },
}

pub fn slot_is_on(seed: u64, slot: u64) -> bool {
    let cycle = slot / CYCLE_SLOTS;
    let pos = slot % CYCLE_SLOTS;
    let mut rng = SplitMix::new(seed ^ cycle.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let len = ON_CHOICES[rng.below(ON_CHOICES.len() as u64) as usize];
    let start = 1 + rng.below(CYCLE_SLOTS - len);
    pos >= start && pos < start + len
}

pub fn shaping_evidence_for(
    seed: u64,
    slots: u64,
    emissions: u64,
    last_emission_unix: u64,
) -> ShapingEvidence {
    let mut max_on_run = 0u64;
    let mut run = 0u64;
    let mut on = 0u64;
    for slot in 0..slots {
        if slot_is_on(seed, slot) {
            run = run.saturating_add(1);
            on = on.saturating_add(1);
            max_on_run = max_on_run.max(run);
        } else {
            run = 0;
        }
    }
    ShapingEvidence {
        slots,
        emissions,
        max_on_run,
        duty: if slots == 0 {
            0.0
        } else {
            on as f64 / slots as f64
        },
        last_emission_unix,
    }
}

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

struct Runtime {
    enabled: bool,
    epoch_ms: u64,
    seed: u64,
    last_real_ms: AtomicU64,
    real_packets: AtomicU64,
    cover_packets: AtomicU64,
    last_cover_emission: AtomicU64,
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
            last_cover_emission: AtomicU64::new(0),
            scavenger: Mutex::new(Scavenger::default()),
        }
    })
}

pub fn enabled() -> bool {
    runtime().enabled
}

fn current_slot(rt: &Runtime) -> u64 {
    now_ms().saturating_sub(rt.epoch_ms) / SLOT_MS
}

pub fn note_real_traffic() {
    let rt = runtime();
    rt.last_real_ms.store(now_ms(), Ordering::Relaxed);
    rt.real_packets.fetch_add(1, Ordering::Relaxed);
}

pub fn real_traffic_pending() -> bool {
    let rt = runtime();
    if !rt.enabled {
        return false;
    }
    let last = rt.last_real_ms.load(Ordering::Relaxed);
    last != 0 && now_ms().saturating_sub(last) <= SLOT_MS
}

pub fn cover_allowed() -> bool {
    let rt = runtime();
    !rt.enabled || slot_is_on(rt.seed, current_slot(rt))
}

pub fn observe_cover(real_pending: bool) -> Action {
    let rt = runtime();
    let on = !rt.enabled || slot_is_on(rt.seed, current_slot(rt));
    let real = on && real_pending;
    let action = if on {
        rt.cover_packets.fetch_add(1, Ordering::Relaxed);
        rt.last_cover_emission
            .store(super::now_secs(), Ordering::Relaxed);
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

pub fn cover_packets_emitted() -> u64 {
    runtime().cover_packets.load(Ordering::Relaxed)
}

pub fn cover_measurement() -> (u64, u64) {
    let rt = runtime();
    (
        rt.cover_packets.load(Ordering::Relaxed),
        rt.last_cover_emission.load(Ordering::Relaxed),
    )
}

pub fn shaping_evidence() -> Option<ShapingEvidence> {
    let rt = runtime();
    let (emissions, last) = cover_measurement();
    if emissions == 0 || last == 0 {
        return None;
    }
    let slots = current_slot(rt)
        .saturating_add(1)
        .min(EVIDENCE_WINDOW_SLOTS);
    Some(shaping_evidence_for(rt.seed, slots, emissions, last))
}

static REAL_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn note_real_sent() {
    REAL_PENDING.store(true, Ordering::Release);
}

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
        "shaping": shaping_evidence(),
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
            assert!(
                on_in_cycle <= cap,
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

    #[test]
    fn measured_windows_never_exceed_the_burst_or_duty_contract() {
        let last = super::super::now_secs();
        for seed in [0u64, 1, 99, 0x1234_5678_9ABC_DEF0, u64::MAX] {
            for slots in [MIN_SHAPING_SLOTS, 240, 1_000] {
                let evidence = shaping_evidence_for(seed, slots, slots, last);
                assert!(
                    evidence.max_on_run <= MAX_ON_RUN_SLOTS,
                    "seed {seed}, {slots} slots: max run {}",
                    evidence.max_on_run
                );
                assert!(
                    evidence.duty <= MAX_DUTY,
                    "seed {seed}, {slots} slots: duty {}",
                    evidence.duty
                );
                assert!(evidence.measured_enough());
                assert!(evidence.within_contract());
            }
        }
    }

    #[test]
    fn the_contract_rejects_a_long_burst_or_a_high_duty_cycle() {
        let base = shaping_evidence_for(7, 240, 240, super::super::now_secs());
        assert!(base.within_contract());
        assert!(!ShapingEvidence {
            max_on_run: MAX_ON_RUN_SLOTS + 1,
            ..base
        }
        .within_contract());
        assert!(!ShapingEvidence {
            duty: MAX_DUTY + 0.01,
            ..base
        }
        .within_contract());
    }

    #[test]
    fn too_short_a_window_is_not_shaping_evidence_yet() {
        let evidence = shaping_evidence_for(7, MIN_SHAPING_SLOTS - 1, 10, 1);
        assert!(!evidence.measured_enough());
    }
}
