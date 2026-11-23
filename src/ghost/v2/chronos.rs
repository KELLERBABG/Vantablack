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
//! * **Bounded.** The delay is capped (250 ms by default). A circuit whose inner
//!   RTT exceeds that cannot be masked, and this module says so instead of
//!   pretending: [`ChronosSplice::residual`] reports what is left over.
//! * **Never negative, never ahead of real data.** ACKs are only ever *delayed*,
//!   never sent early, so the mechanism cannot manufacture an RTT shorter than
//!   the link's own. That is also why it cannot be used to hide an *inner* RTT
//!   that is smaller than the outer one — that case needs a faster link, not a
//!   pacer.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Default ceiling on artificial ACK delay.
pub const DEFAULT_MAX_SPLICE: Duration = Duration::from_millis(250);

/// How closely the two clocks have to agree before the flow is uninteresting to
/// an `ARTT − TRTT` classifier. Five percent or 2 ms, whichever is larger, is
/// about the noise floor of a Wi-Fi link.
pub const MATCH_TOLERANCE_FRAC: f64 = 0.05;
pub const MATCH_TOLERANCE_FLOOR: Duration = Duration::from_millis(2);

/// A splice decision plus the arithmetic behind it, kept for the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplicePlan {
    pub inner_rtt: Duration,
    pub outer_rtt: Duration,
    /// Extra delay applied to each outer ACK.
    pub delay_per_ack: Duration,
    /// RTT the outer observer will measure once pacing is applied.
    pub paced_outer_rtt: Duration,
    /// What the classifier can still see after pacing.
    pub residual: Duration,
}

impl SplicePlan {
    /// True when the paced outer RTT is inside the classifier's tolerance of the
    /// inner one.
    pub fn is_indistinguishable(&self) -> bool {
        self.residual <= tolerance_for(self.inner_rtt)
    }
}

/// The tolerance for a given RTT: max(5 %, 2 ms).
pub fn tolerance_for(rtt: Duration) -> Duration {
    let frac = rtt.mul_f64(MATCH_TOLERANCE_FRAC);
    frac.max(MATCH_TOLERANCE_FLOOR)
}

/// The pacing engine for one Guard session.
#[derive(Debug, Clone, Copy)]
pub struct ChronosSplice {
    inner_rtt: Duration,
    outer_rtt: Duration,
    max_delay: Duration,
}

impl ChronosSplice {
    pub fn new(inner_rtt: Duration, outer_rtt: Duration) -> Self {
        Self {
            inner_rtt,
            outer_rtt,
            max_delay: DEFAULT_MAX_SPLICE,
        }
    }

    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    /// Update the measured outer RTT as the session's congestion controller
    /// refines it.
    pub fn observe_outer_rtt(&mut self, outer_rtt: Duration) {
        self.outer_rtt = outer_rtt;
    }

    /// Update the inner circuit RTT from a real round-trip through all hops.
    pub fn observe_inner_rtt(&mut self, inner_rtt: Duration) {
        self.inner_rtt = inner_rtt;
    }

    pub fn plan(&self) -> SplicePlan {
        let delay = if self.outer_rtt >= self.inner_rtt {
            Duration::ZERO
        } else {
            // Half the deficit per direction: the observer sees RTT, which is two
            // one-way legs, while a delay is applied to each ACK.
            (self.inner_rtt - self.outer_rtt) / 2
        }
        .min(self.max_delay);

        let paced = self.outer_rtt.saturating_add(delay * 2);
        let residual = self.inner_rtt.abs_diff(paced);
        SplicePlan {
            inner_rtt: self.inner_rtt,
            outer_rtt: self.outer_rtt,
            delay_per_ack: delay,
            paced_outer_rtt: paced,
            residual,
        }
    }
}

/// A queue of ACK obligations with release times.
///
/// The pacer only holds *our own* acknowledgements: an ACK is queued when the
/// transport would have emitted it and released when the splice delay has
/// elapsed. Ordering is FIFO by release time, and the queue is bounded so a
/// stalled reader cannot grow it without limit.
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

    /// ACKs dropped because the queue was full. Counted, never hidden: a pacer
    /// that silently discards acknowledgements would cause spurious
    /// retransmissions and a very visible RTT inflation.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Queue one acknowledgement for `seq`.
    pub fn schedule(&mut self, seq: u64, now: Instant) {
        if self.queue.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.queue.push_back((now + self.delay, seq));
    }

    /// Release every ACK whose delay has elapsed. FIFO: a short delay never lets
    /// a later ACK overtake an earlier one, which keeps the sequence monotone.
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

    /// When the next ACK becomes due, or `None` when the queue is empty.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.queue.front().map(|(t, _)| *t)
    }
}

/// How a live flow looks to the cross-layer classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockVerdict {
    /// Both clocks agree.
    Consistent,
    /// The gap is inside the pacing ceiling and being masked.
    Masking,
    /// The gap exceeds what pacing may hide; the flow looks like a relay.
    Divergent,
}

pub fn classify(plan: &SplicePlan) -> ClockVerdict {
    if plan.residual <= tolerance_for(plan.inner_rtt) {
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
}

impl ChronosRuntime {
    fn new() -> Self {
        Self {
            outer_rtt: None,
            inner_rtt: None,
            pacer: AckPacer::new(Duration::ZERO, 1024),
            observations: 0,
        }
    }

    fn plan(&self) -> Option<SplicePlan> {
        let (inner, outer) = (self.inner_rtt?, self.outer_rtt?);
        Some(ChronosSplice::new(inner, outer).plan())
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

/// Record a measured outer transport RTT (e.g. direct ICE/link probe).
pub fn observe_outer_rtt(rtt: Duration) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.outer_rtt = Some(rtt);
    rt.observations = rt.observations.saturating_add(1);
    rt.sync_pacer();
}

/// Record a measured inner circuit RTT (e.g. multi-hop / relayed path).
pub fn observe_inner_rtt(rtt: Duration) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.inner_rtt = Some(rtt);
    rt.observations = rt.observations.saturating_add(1);
    rt.sync_pacer();
}

/// Compute the current splice plan once both outer and inner RTTs are known.
pub fn current_plan() -> Option<SplicePlan> {
    let rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.plan()
}

/// Whether the outer and inner clocks currently agree, or `None` if unmeasured.
pub fn clock_consistent() -> Option<bool> {
    current_plan().map(|p| p.is_indistinguishable())
}

/// Current per-ACK splice delay, if both outer and inner RTTs have been observed.
pub fn suggested_ack_delay() -> Option<Duration> {
    current_plan().map(|p| p.delay_per_ack)
}

/// Queue an ACK sequence number on the shared pacer.
pub fn schedule_ack(seq: u64, now: Instant) {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.pacer.schedule(seq, now);
}

/// Drain all due ACKs from the shared pacer.
pub fn drain_due_acks(now: Instant) -> Vec<u64> {
    let mut rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    rt.pacer.due(now)
}

/// JSON summary for `/api/v2/chronos` and diagnostics.
pub fn status_json() -> serde_json::Value {
    let rt = runtime().lock().unwrap_or_else(|e| e.into_inner());
    let plan = rt.plan();
    let verdict = plan.as_ref().map(classify).map(|v| match v {
        ClockVerdict::Consistent => "consistent",
        ClockVerdict::Masking => "masking",
        ClockVerdict::Divergent => "divergent",
    });
    serde_json::json!({
        "observed": plan.is_some(),
        "observations": rt.observations,
        "max_splice_ms": DEFAULT_MAX_SPLICE.as_millis() as u64,
        "outer_rtt_ms": rt.outer_rtt.map(|d| d.as_secs_f64() * 1000.0),
        "inner_rtt_ms": rt.inner_rtt.map(|d| d.as_secs_f64() * 1000.0),
        "delay_per_ack_ms": plan.as_ref().map(|p| p.delay_per_ack.as_secs_f64() * 1000.0),
        "paced_outer_rtt_ms": plan.as_ref().map(|p| p.paced_outer_rtt.as_secs_f64() * 1000.0),
        "residual_ms": plan.as_ref().map(|p| p.residual.as_secs_f64() * 1000.0),
        "verdict": verdict.unwrap_or("unmeasured"),
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
        // 30 ms link carrying a 150 ms three-hop circuit.
        let plan = ChronosSplice::new(ms(150), ms(30)).plan();
        assert_eq!(plan.delay_per_ack, ms(60));
        assert_eq!(plan.paced_outer_rtt, ms(150));
        assert_eq!(plan.residual, Duration::ZERO);
        assert!(plan.is_indistinguishable());
        assert_eq!(classify(&plan), ClockVerdict::Consistent);
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
        observe_outer_rtt(ms(30));
        observe_inner_rtt(ms(150));
        let plan = current_plan().expect("plan available after both observations");
        assert_eq!(plan.delay_per_ack, ms(60));
        assert_eq!(clock_consistent(), Some(true));
        let json = status_json();
        assert_eq!(json["observed"], true);
        assert_eq!(json["verdict"], "consistent");
    }
}
