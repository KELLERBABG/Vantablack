//! Chronos-Splice — pacing outer ACKs to the inner circuit's RTT.
//!
//! A three-hop circuit has a longer round-trip time than the single link it
//! rides on. An on-path observer can therefore measure two clocks in the same
//! flow: the **outer transport RTT** (TCP/QUIC acknowledgements on the wire) and
//! the **application's effective RTT** (how long a request actually takes). The
//! NDSS 2025 cross-layer attack is exactly that subtraction (`ARTT − TRTT`): when
//! the gap is large and stable, the sender is relaying for someone else.
//!
//! Chronos-Splice removes the difference at its source. The Guard holds its
//! transport acknowledgements for half the deficit and releases them in a paced
//! stream, so the outer transport's measured RTT converges on the inner
//! circuit's, and the two clocks say the same thing.
//!
//! Two constraints keep this honest:
//!
//! * **Bounded.** The delay is capped (250 ms by default) and the whole session
//!   is held to a stationary latency horizon `H ∈ {80, 160, 280} ms`, chosen
//!   once per session and never re-chosen mid-flow. A circuit whose inner RTT
//!   exceeds `H` cannot be masked, and this module says so instead of
//!   pretending: [`SplicePlan::residual`] reports what is left over.
//! * **One delay, not two.** An ACK is delayed once, so the observer's measured
//!   RTT grows by exactly that delay. The correct compensation is therefore
//!   `delay = inner − outer` and `paced = outer + delay`; halving the deficit
//!   and counting it twice left the loop 2× short.
//! * **Never negative, never ahead of real data.** ACKs are only ever *delayed*,
//!   never sent early, so the mechanism cannot manufacture an RTT shorter than
//!   the link's own. That is also why it cannot be used to hide an *inner* RTT
//!   that is smaller than the outer one — that case needs a faster link, not a
//!   pacer.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_SPLICE: Duration = Duration::from_millis(250);

pub const HORIZONS_MS: [u64; 3] = [80, 160, 280];

pub fn stationary_horizon(seed: u64) -> Duration {
    Duration::from_millis(HORIZONS_MS[(seed % HORIZONS_MS.len() as u64) as usize])
}

pub const MATCH_TOLERANCE_FRAC: f64 = 0.05;
pub const MATCH_TOLERANCE_FLOOR: Duration = Duration::from_millis(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplicePlan {
    pub inner_rtt: Duration,
    pub outer_rtt: Duration,
    pub delay_per_ack: Duration,
    pub paced_outer_rtt: Duration,
    pub residual: Duration,
    pub horizon: Duration,
}

impl SplicePlan {
    pub fn is_indistinguishable(&self) -> bool {
        self.inner_rtt <= self.horizon && self.residual <= tolerance_for(self.inner_rtt)
    }

    pub fn exceeds_horizon(&self) -> bool {
        self.inner_rtt > self.horizon
    }
}

pub fn tolerance_for(rtt: Duration) -> Duration {
    let frac = rtt.mul_f64(MATCH_TOLERANCE_FRAC);
    frac.max(MATCH_TOLERANCE_FLOOR)
}

#[derive(Debug, Clone, Copy)]
pub struct ChronosSplice {
    inner_rtt: Duration,
    outer_rtt: Duration,
    max_delay: Duration,
    horizon: Duration,
}

impl ChronosSplice {
    pub fn new(inner_rtt: Duration, outer_rtt: Duration) -> Self {
        Self {
            inner_rtt,
            outer_rtt,
            max_delay: DEFAULT_MAX_SPLICE,
            horizon: Duration::from_millis(*HORIZONS_MS.last().unwrap_or(&280)),
        }
    }

    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    pub fn with_horizon(mut self, horizon: Duration) -> Self {
        self.horizon = horizon;
        self
    }

    pub fn observe_outer_rtt(&mut self, outer_rtt: Duration) {
        self.outer_rtt = outer_rtt;
    }

    pub fn observe_inner_rtt(&mut self, inner_rtt: Duration) {
        self.inner_rtt = inner_rtt;
    }

    pub fn plan(&self) -> SplicePlan {
        let delay = self
            .inner_rtt
            .saturating_sub(self.outer_rtt)
            .min(self.max_delay);
        let paced = self.outer_rtt.saturating_add(delay);
        let residual = self.inner_rtt.abs_diff(paced);
        SplicePlan {
            inner_rtt: self.inner_rtt,
            outer_rtt: self.outer_rtt,
            delay_per_ack: delay,
            paced_outer_rtt: paced,
            residual,
            horizon: self.horizon,
        }
    }
}

#[derive(Debug)]
pub struct AckPacer {
    delay: Duration,
    queue: VecDeque<(Instant, u64)>,
    capacity: usize,
    dropped: u64,
}

impl AckPacer {
    pub fn new(delay: Duration, capacity: usize) -> Self {
        Self {
            delay,
            queue: VecDeque::with_capacity(capacity.min(4096)),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    pub fn set_delay(&mut self, delay: Duration) {
        self.delay = delay;
    }

    pub fn delay(&self) -> Duration {
        self.delay
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn schedule(&mut self, seq: u64, now: Instant) {
        if self.queue.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.queue.push_back((now + self.delay, seq));
    }

    pub fn due(&mut self, now: Instant) -> Vec<u64> {
        let mut out = Vec::new();
        while let Some(&(release, seq)) = self.queue.front() {
            if release <= now {
                out.push(seq);
                self.queue.pop_front();
            } else {
                break;
            }
        }
        out
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.queue.front().map(|(t, _)| *t)
    }
}

pub const EVIDENCE_TTL_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockVerdict {
    Consistent,
    Masking,
    Divergent,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ChronosEvidence {
    pub inner_rtt_ms: f64,
    pub outer_rtt_ms: f64,
    pub horizon_ms: f64,
    pub residual_ms: f64,
    pub observations: u64,
    pub observed_at: u64,
    pub verdict: ClockVerdict,
}

impl ChronosEvidence {
    pub fn measured(&self) -> bool {
        self.observations >= 2
    }

    pub fn is_fresh(&self) -> bool {
        self.observed_at != 0
            && super::now_secs().saturating_sub(self.observed_at) <= EVIDENCE_TTL_SECS
    }

    pub fn is_verified(&self) -> bool {
        self.measured()
            && self.is_fresh()
            && self.verdict == ClockVerdict::Consistent
            && self.inner_rtt_ms <= self.horizon_ms
    }
}

pub fn classify(plan: &SplicePlan) -> ClockVerdict {
    if plan.exceeds_horizon() {
        ClockVerdict::Divergent
    } else if plan.residual <= tolerance_for(plan.inner_rtt) {
        ClockVerdict::Consistent
    } else if plan.delay_per_ack >= DEFAULT_MAX_SPLICE {
        ClockVerdict::Divergent
    } else {
        ClockVerdict::Masking
    }
}

struct ChronosRuntime {
    outer_rtt: Option<Duration>,
    inner_rtt: Option<Duration>,
    pacer: AckPacer,
    observations: u64,
    last_observed_unix: u64,
    horizon: Duration,
}

fn session_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl ChronosRuntime {
    fn new() -> Self {
        Self {
            outer_rtt: None,
            inner_rtt: None,
            pacer: AckPacer::new(Duration::ZERO, 1024),
            observations: 0,
            last_observed_unix: 0,
            horizon: stationary_horizon(session_seed()),
        }
    }

    fn plan(&self) -> Option<SplicePlan> {
        let (inner, outer) = (self.inner_rtt?, self.outer_rtt?);
        Some(
            ChronosSplice::new(inner, outer)
                .with_horizon(self.horizon)
                .plan(),
        )
    }

    fn sync_pacer(&mut self) {
        if let Some(plan) = self.plan() {
            self.pacer.set_delay(plan.delay_per_ack);
        }
    }
}

static RT: OnceLock<Mutex<ChronosRuntime>> = OnceLock::new();

fn runtime() -> &'static Mutex<ChronosRuntime> {
    RT.get_or_init(|| Mutex::new(ChronosRuntime::new()))
}

pub fn observe_outer_rtt(rtt: Duration) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.outer_rtt = Some(rtt);
    rt.observations = rt.observations.saturating_add(1);
    rt.last_observed_unix = super::now_secs();
    rt.sync_pacer();
}

pub fn observe_inner_rtt(rtt: Duration) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.inner_rtt = Some(rtt);
    rt.observations = rt.observations.saturating_add(1);
    rt.last_observed_unix = super::now_secs();
    rt.sync_pacer();
}

pub fn current_plan() -> Option<SplicePlan> {
    let rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.plan()
}

pub fn evidence() -> Option<ChronosEvidence> {
    let rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    let plan = rt.plan()?;
    Some(ChronosEvidence {
        inner_rtt_ms: plan.inner_rtt.as_secs_f64() * 1000.0,
        outer_rtt_ms: plan.outer_rtt.as_secs_f64() * 1000.0,
        horizon_ms: plan.horizon.as_secs_f64() * 1000.0,
        residual_ms: plan.residual.as_secs_f64() * 1000.0,
        observations: rt.observations,
        observed_at: rt.last_observed_unix,
        verdict: classify(&plan),
    })
}

pub fn clock_consistent() -> Option<bool> {
    current_plan().map(|p| p.is_indistinguishable())
}

pub fn horizon() -> Duration {
    runtime().lock().unwrap_or_else(|e| e.into_inner()).horizon
}

pub fn set_horizon(horizon: Duration) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.horizon = horizon;
    rt.sync_pacer();
}

pub fn suggested_ack_delay() -> Option<Duration> {
    current_plan().map(|p| p.delay_per_ack)
}

pub fn schedule_ack(seq: u64, now: Instant) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.pacer.schedule(seq, now);
}

pub fn drain_due_acks(now: Instant) -> Vec<u64> {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.pacer.due(now)
}

pub fn status_json() -> serde_json::Value {
    let rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    let plan = rt.plan();
    let verdict = plan.as_ref().map(classify).map(|v| match v {
        ClockVerdict::Consistent => "consistent",
        ClockVerdict::Masking => "masking",
        ClockVerdict::Divergent => "divergent",
    });
    let fresh = rt.last_observed_unix != 0
        && super::now_secs().saturating_sub(rt.last_observed_unix) <= EVIDENCE_TTL_SECS;
    let claim = match &plan {
        Some(p) if fresh && p.is_indistinguishable() && classify(p) == ClockVerdict::Consistent => {
            "verified"
        }
        _ => "withheld",
    };
    serde_json::json!({
        "observed": plan.is_some(),
        "observations": rt.observations,
        "max_splice_ms": DEFAULT_MAX_SPLICE.as_millis() as u64,
        "outer_rtt_ms": rt.outer_rtt.map(|d| d.as_secs_f64() * 1000.0),
        "inner_rtt_ms": rt.inner_rtt.map(|d| d.as_secs_f64() * 1000.0),
        "horizon_ms": rt.horizon.as_secs_f64() * 1000.0,
        "horizons_ms": HORIZONS_MS,
        "inner_exceeds_horizon": rt
            .inner_rtt
            .map(|d| d > rt.horizon)
            .unwrap_or(false),
        "delay_per_ack_ms": plan.as_ref().map(|p| p.delay_per_ack.as_secs_f64() * 1000.0),
        "paced_outer_rtt_ms": plan.as_ref().map(|p| p.paced_outer_rtt.as_secs_f64() * 1000.0),
        "residual_ms": plan.as_ref().map(|p| p.residual.as_secs_f64() * 1000.0),
        "verdict": verdict.unwrap_or("unmeasured"),
        "evidence_age_secs": if rt.last_observed_unix == 0 {
            serde_json::Value::Null
        } else {
            serde_json::json!(super::now_secs().saturating_sub(rt.last_observed_unix))
        },
        "evidence_ttl_secs": EVIDENCE_TTL_SECS,
        "claim": claim,
        "pacer_queued": rt.pacer.len(),
        "pacer_dropped": rt.pacer.dropped(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn splice_closes_the_gap_between_the_two_clocks() {
        let plan = ChronosSplice::new(ms(150), ms(30))
            .with_horizon(ms(160))
            .plan();
        assert_eq!(plan.delay_per_ack, ms(120));
        assert_eq!(plan.paced_outer_rtt, ms(150));
        assert_eq!(plan.residual, Duration::ZERO);
        assert!(plan.is_indistinguishable());
        assert_eq!(classify(&plan), ClockVerdict::Consistent);
    }

    #[test]
    fn a_circuit_slower_than_the_horizon_is_divergent_even_when_paced() {
        let plan = ChronosSplice::new(ms(150), ms(30))
            .with_horizon(ms(80))
            .plan();
        assert_eq!(plan.paced_outer_rtt, plan.inner_rtt, "pacing still works");
        assert!(plan.exceeds_horizon());
        assert!(!plan.is_indistinguishable());
        assert_eq!(classify(&plan), ClockVerdict::Divergent);
    }

    #[test]
    fn horizons_are_the_three_stationary_values() {
        assert_eq!(HORIZONS_MS, [80, 160, 280]);
        assert_eq!(stationary_horizon(0), ms(80));
        assert_eq!(stationary_horizon(1), ms(160));
        assert_eq!(stationary_horizon(2), ms(280));
        assert_eq!(stationary_horizon(5), ms(280), "deterministic per seed");
    }

    #[test]
    fn a_fast_circuit_is_never_slowed_down() {
        let plan = ChronosSplice::new(ms(20), ms(35)).plan();
        assert_eq!(plan.delay_per_ack, Duration::ZERO);
        assert_eq!(plan.paced_outer_rtt, ms(35));
        assert_eq!(classify(&plan), ClockVerdict::Masking);
    }

    #[test]
    fn an_enormous_gap_is_reported_not_hidden() {
        let plan = ChronosSplice::new(Duration::from_secs(2), ms(20)).plan();
        assert_eq!(plan.delay_per_ack, DEFAULT_MAX_SPLICE);
        assert!(!plan.is_indistinguishable());
        assert_eq!(classify(&plan), ClockVerdict::Divergent);
        assert!(plan.residual > ms(1000));
    }

    #[test]
    fn pacer_releases_in_order_and_only_when_due() {
        let t0 = Instant::now();
        let mut pacer = AckPacer::new(ms(50), 16);
        pacer.schedule(1, t0);
        pacer.schedule(2, t0 + ms(10));
        assert!(pacer.due(t0 + ms(49)).is_empty());
        assert_eq!(pacer.due(t0 + ms(50)), vec![1]);
        assert_eq!(pacer.next_deadline(), Some(t0 + ms(60)));
        assert_eq!(pacer.due(t0 + ms(60)), vec![2]);
        assert!(pacer.is_empty());
    }

    #[test]
    fn pacer_is_bounded_and_counts_what_it_drops() {
        let t0 = Instant::now();
        let mut pacer = AckPacer::new(ms(1), 2);
        for seq in 0..5 {
            pacer.schedule(seq, t0);
        }
        assert_eq!(pacer.len(), 2);
        assert_eq!(pacer.dropped(), 3);
        assert_eq!(pacer.due(t0 + ms(2)), vec![0, 1]);
    }

    #[test]
    fn tolerance_scales_with_rtt_and_has_a_floor() {
        assert_eq!(tolerance_for(ms(20)), ms(2));
        assert_eq!(tolerance_for(ms(200)), ms(10));
    }

    #[test]
    fn runtime_reports_plan_and_status_after_both_clocks_observed() {
        set_horizon(ms(280));
        observe_outer_rtt(ms(30));
        observe_inner_rtt(ms(150));
        let plan = current_plan().expect("plan available after both observations");
        assert_eq!(plan.delay_per_ack, ms(120));
        assert_eq!(clock_consistent(), Some(true));
        let json = status_json();
        assert_eq!(json["observed"], true);
        assert_eq!(json["verdict"], "consistent");
        assert_eq!(json["horizon_ms"], 280.0);
        assert_eq!(json["inner_exceeds_horizon"], false);
    }

    #[test]
    fn the_horizon_boundary_is_inclusive_and_one_millisecond_past_it_fails() {
        let now = super::super::now_secs();
        let mut evidence = ChronosEvidence {
            inner_rtt_ms: 160.0,
            outer_rtt_ms: 30.0,
            horizon_ms: 160.0,
            residual_ms: 0.0,
            observations: 2,
            observed_at: now,
            verdict: ClockVerdict::Consistent,
        };
        assert!(evidence.is_verified(), "inner == horizon is inside");
        evidence.inner_rtt_ms = 161.0;
        assert!(!evidence.is_verified(), "one ms past the horizon is not");
    }

    #[test]
    fn clock_evidence_expires_at_the_ttl_boundary() {
        let now = super::super::now_secs();
        let mut evidence = ChronosEvidence {
            inner_rtt_ms: 150.0,
            outer_rtt_ms: 30.0,
            horizon_ms: 160.0,
            residual_ms: 0.0,
            observations: 2,
            observed_at: now.saturating_sub(EVIDENCE_TTL_SECS),
            verdict: ClockVerdict::Consistent,
        };
        assert!(evidence.is_fresh(), "exactly at the TTL is still fresh");
        evidence.observed_at = now.saturating_sub(EVIDENCE_TTL_SECS + 1);
        assert!(!evidence.is_fresh(), "one second past is stale");
        assert!(!evidence.is_verified());
    }

    #[test]
    fn a_single_observation_is_not_a_clock_claim() {
        let evidence = ChronosEvidence {
            inner_rtt_ms: 150.0,
            outer_rtt_ms: 30.0,
            horizon_ms: 160.0,
            residual_ms: 0.0,
            observations: 1,
            observed_at: super::super::now_secs(),
            verdict: ClockVerdict::Consistent,
        };
        assert!(!evidence.measured());
        assert!(!evidence.is_verified());
    }
}
