//! Contact Graph Routing (CGR) & Time-Variable Graph (TVG).
//!
//! Implements predictive routing across intermittently connected nodes using Contact Graph Routing,
//! along with Poisson-distributed error rate modeling to distinguish between benign cosmic bit-flips
//! and Byzantine / malicious node behaviors.

use std::cmp::Ordering;

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::orbit::{GroundPosition, OrbitalState};

pub type NodeId = String;

pub type Timestamp = f64;

pub const C_KM_S: f64 = 299_792.458;

pub const FIBRE_KM_S: f64 = C_KM_S / 1.468;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkMedium {
    #[default]
    Laser,
    Radio,
    Fibre,
}

impl LinkMedium {
    pub fn speed_km_s(self) -> f64 {
        match self {
            LinkMedium::Laser | LinkMedium::Radio => C_KM_S,
            LinkMedium::Fibre => FIBRE_KM_S,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EnergyClass {
    #[default]
    Mains, // Plugged desktop/server with stable grid power
    Battery,   // Mobile device / battery-constrained node
    Harvested, // Solar / energy-harvesting / intermittent node
}

#[derive(Debug, Clone, Default)]
pub struct Contact {
    pub source: NodeId,
    pub destination: NodeId,
    pub t_start: Timestamp,
    pub t_end: Timestamp,
    pub x_cap: f64,
    pub range_km: f64,
    pub medium: LinkMedium,
    pub energy_class: EnergyClass,
    pub rate_bps: f64,
    pub measured_owlt_secs: Option<f64>,
}

impl Contact {
    pub fn new(
        source: impl Into<NodeId>,
        destination: impl Into<NodeId>,
        t_start: Timestamp,
        t_end: Timestamp,
        x_cap: f64,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            t_start,
            t_end,
            x_cap,
            ..Default::default()
        }
    }

    pub fn with_range_km(mut self, range_km: f64, medium: LinkMedium) -> Self {
        self.range_km = range_km.max(0.0);
        self.medium = medium;
        self
    }

    pub fn with_rate_bps(mut self, rate_bps: f64) -> Self {
        self.rate_bps = rate_bps.max(0.0);
        self.x_cap = self.rate_bps * self.window_secs();
        self
    }

    pub fn with_measured_owlt(mut self, owlt_secs: f64) -> Self {
        self.measured_owlt_secs = Some(owlt_secs.max(0.0));
        self
    }

    pub fn with_energy_class(mut self, energy_class: EnergyClass) -> Self {
        self.energy_class = energy_class;
        self
    }

    pub fn window_secs(&self) -> f64 {
        (self.t_end - self.t_start).max(0.0)
    }

    pub fn owlt_secs(&self) -> f64 {
        match self.measured_owlt_secs {
            Some(m) => m,
            None => self.range_km.max(0.0) / self.medium.speed_km_s(),
        }
    }
}

pub fn edge_presence(contact: &Contact, t: Timestamp) -> bool {
    t >= contact.t_start && t <= contact.t_end
}

pub fn latency(contact: &Contact, _t: Timestamp) -> Duration {
    let secs = contact.owlt_secs();
    if secs.is_finite() && secs > 0.0 {
        Duration::from_secs_f64(secs)
    } else {
        Duration::ZERO
    }
}

#[derive(Debug, Clone, Default)]
pub struct Journey {
    pub contacts: Vec<(Contact, Timestamp)>,
    pub total_latency: Duration,
    pub arrival_time: Timestamp,
}

impl Journey {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, contact: Contact, send_time: Timestamp) -> bool {
        if !send_time.is_finite() {
            return false;
        }
        if let Some((last_contact, last_send)) = self.contacts.last() {
            let previous_arrival = last_send + last_contact.owlt_secs();
            if send_time < previous_arrival {
                return false;
            }
        }
        if !edge_presence(&contact, send_time) {
            return false;
        }
        self.total_latency += latency(&contact, send_time);
        self.arrival_time = send_time + contact.owlt_secs();
        self.contacts.push((contact, send_time));
        true
    }

    pub fn hops(&self) -> usize {
        self.contacts.len()
    }

    pub fn nodes(&self) -> Vec<NodeId> {
        let mut out = Vec::with_capacity(self.contacts.len() + 1);
        for (c, _) in &self.contacts {
            if out.is_empty() {
                out.push(c.source.clone());
            }
            out.push(c.destination.clone());
        }
        out
    }

    pub fn path_string(&self) -> String {
        self.nodes().join(" -> ")
    }

    pub fn transit_nodes(&self) -> Vec<NodeId> {
        let nodes = self.nodes();
        if nodes.len() <= 2 {
            return Vec::new();
        }
        nodes[1..nodes.len() - 1].to_vec()
    }

    pub fn energy_classes(&self) -> Vec<EnergyClass> {
        self.contacts.iter().map(|(c, _)| c.energy_class).collect()
    }

    pub fn primary_energy_class(&self) -> EnergyClass {
        self.contacts
            .last()
            .map(|(c, _)| c.energy_class)
            .unwrap_or_default()
    }
}

pub fn energy_heterogeneity_score(classes: &[EnergyClass]) -> usize {
    let mut unique = std::collections::HashSet::new();
    for &c in classes {
        unique.insert(c);
    }
    unique.len()
}

#[derive(Debug, Clone)]
pub struct RouteOptions {
    pub max_hops: usize,
    pub max_arrival: Option<Timestamp>,
    pub excluded_nodes: HashSet<NodeId>,
    pub excluded_edges: HashSet<(NodeId, NodeId)>,
}

impl Default for RouteOptions {
    fn default() -> Self {
        Self {
            max_hops: DEFAULT_MAX_HOPS,
            max_arrival: None,
            excluded_nodes: HashSet::new(),
            excluded_edges: HashSet::new(),
        }
    }
}

pub const DEFAULT_MAX_HOPS: usize = 8;

#[derive(Debug, PartialEq)]
struct QueueEntry {
    arrival: f64,
    hops: usize,
    node: NodeId,
}

impl Eq for QueueEntry {}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .arrival
            .partial_cmp(&self.arrival)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.hops.cmp(&self.hops))
            .then_with(|| other.node.cmp(&self.node))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContactPlan {
    pub contacts: Vec<Contact>,
    pub by_source: HashMap<NodeId, Vec<usize>>,
}

impl ContactPlan {
    pub fn add_contact(&mut self, contact: Contact) {
        let source = contact.source.clone();
        let key = contact.t_start;
        let idx = self.contacts.len();
        self.contacts.push(contact);
        let pos = self.by_source.get(&source).map_or(0, |list| {
            list.partition_point(|&i| self.contacts[i].t_start <= key)
        });
        self.by_source.entry(source).or_default().insert(pos, idx);
    }

    pub fn contacts_from(&self, node: &str) -> impl Iterator<Item = &Contact> {
        self.by_source
            .get(node)
            .into_iter()
            .flatten()
            .map(move |&i| &self.contacts[i])
    }

    pub fn get_contacts_from(&self, source: &str, t: Timestamp) -> Vec<&Contact> {
        self.contacts_from(source)
            .filter(|c| edge_presence(c, t))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    pub fn select_thermal_heterogeneous_triple(
        candidates: &[Journey],
    ) -> Option<(Journey, Journey, Journey)> {
        let n = candidates.len();
        if n < 3 {
            return None;
        }
        let mut best_triple = None;
        let mut best_score = 0;
        for i in 0..n.saturating_sub(2) {
            for j in (i.saturating_add(1))..n.saturating_sub(1) {
                for k in (j.saturating_add(1))..n {
                    let c_i = candidates.get(i)?;
                    let c_j = candidates.get(j)?;
                    let c_k = candidates.get(k)?;
                    let classes = [
                        c_i.primary_energy_class(),
                        c_j.primary_energy_class(),
                        c_k.primary_energy_class(),
                    ];
                    let score = energy_heterogeneity_score(&classes);
                    if score > best_score {
                        best_score = score;
                        best_triple = Some((c_i.clone(), c_j.clone(), c_k.clone()));
                        if score == 3 {
                            return best_triple;
                        }
                    }
                }
            }
        }
        best_triple
    }

    pub fn observe_link(
        &mut self,
        from: &str,
        to: &str,
        rtt: Duration,
        now: Timestamp,
        window_secs: f64,
        rate_bps: f64,
    ) {
        let owlt = (rtt.as_secs_f64() / 2.0).max(0.0);
        let window_secs = window_secs.max(0.0);
        let end = now + window_secs;

        let live = self.by_source.get(from).and_then(|list| {
            list.iter().copied().find(|&i| {
                let c = &self.contacts[i];
                c.destination == to && c.t_end >= now
            })
        });
        if let Some(i) = live {
            let c = &mut self.contacts[i];
            c.t_end = c.t_end.max(end);
            c.measured_owlt_secs = Some(owlt);
            c.range_km = c.medium.speed_km_s() * owlt;
            if rate_bps > 0.0 {
                c.rate_bps = rate_bps;
            }
            c.x_cap = c.rate_bps.max(1.0) * c.window_secs();
            return;
        }

        let mut contact = Contact::new(
            from.to_string(),
            to.to_string(),
            now,
            end,
            rate_bps.max(1.0) * window_secs,
        )
        .with_measured_owlt(owlt);
        contact.rate_bps = rate_bps;
        contact.medium = LinkMedium::Laser;
        contact.range_km = C_KM_S * owlt;
        self.add_contact(contact);
    }

    pub fn project_orbital_pass(
        &mut self,
        sat: &str,
        ground_node: &str,
        orbit: &mut OrbitalState,
        ground: &GroundPosition,
        t_start: Timestamp,
        horizon_secs: f64,
        step_secs: f64,
        rate_bps: f64,
    ) -> usize {
        if step_secs <= 0.0 || horizon_secs <= 0.0 {
            return 0;
        }
        let mut added: usize = 0;
        let mut window: Option<(Timestamp, Timestamp, f64)> = None;
        let mut t = t_start;
        while t <= t_start + horizon_secs {
            orbit.propagate(t);
            if orbit.can_see(ground) {
                let delay = orbit.signal_delay(ground);
                match window {
                    Some((start, _, _)) => window = Some((start, t, delay)),
                    None => window = Some((t, t, delay)),
                }
            } else if let Some((start, last_seen, delay)) = window.take() {
                self.push_ground_contact(sat, ground_node, start, last_seen, delay, rate_bps);
                added = added.saturating_add(1);
            }
            t += step_secs;
        }
        if let Some((start, last_seen, delay)) = window.take() {
            self.push_ground_contact(sat, ground_node, start, last_seen, delay, rate_bps);
            added = added.saturating_add(1);
        }
        added
    }

    fn push_ground_contact(
        &mut self,
        sat: &str,
        ground_node: &str,
        start: Timestamp,
        last_seen: Timestamp,
        delay_secs: f64,
        rate_bps: f64,
    ) {
        let end = (last_seen + (last_seen - start).max(0.0)).max(last_seen);
        let contact = Contact::new(
            sat.to_string(),
            ground_node.to_string(),
            start,
            end,
            rate_bps.max(1.0) * (end - start),
        )
        .with_rate_bps(rate_bps)
        .with_measured_owlt(delay_secs);
        self.add_contact(contact);
    }

    pub fn find_earliest_arrival(
        &self,
        source: &str,
        destination: &str,
        t_now: Timestamp,
    ) -> Option<Journey> {
        self.find_earliest_arrival_with(source, destination, t_now, &RouteOptions::default())
    }

    pub fn find_earliest_arrival_with(
        &self,
        source: &str,
        destination: &str,
        t_now: Timestamp,
        opts: &RouteOptions,
    ) -> Option<Journey> {
        if source == destination || !t_now.is_finite() {
            return None;
        }
        let mut best: HashMap<NodeId, (f64, usize)> = HashMap::new();
        let mut prev: HashMap<NodeId, (Contact, Timestamp)> = HashMap::new();
        let mut heap = BinaryHeap::new();
        best.insert(source.to_string(), (t_now, 0));
        heap.push(QueueEntry {
            arrival: t_now,
            hops: 0,
            node: source.to_string(),
        });

        let mut reached = false;
        while let Some(QueueEntry {
            arrival,
            hops,
            node,
        }) = heap.pop()
        {
            if node == destination {
                reached = true;
                break;
            }
            match best.get(&node) {
                Some(&(b, h)) if b < arrival || (b == arrival && h < hops) => continue,
                _ => {}
            }
            if hops >= opts.max_hops {
                continue;
            }
            for contact in self.contacts_from(&node) {
                if contact.t_end < arrival {
                    continue;
                }
                if contact.destination == source {
                    continue;
                }
                if opts
                    .excluded_edges
                    .contains(&(contact.source.clone(), contact.destination.clone()))
                {
                    continue;
                }
                let is_transit = contact.destination != destination;
                if is_transit && opts.excluded_nodes.contains(&contact.destination) {
                    continue;
                }
                let send = if arrival > contact.t_start {
                    arrival
                } else {
                    contact.t_start
                };
                if !edge_presence(contact, send) {
                    continue;
                }
                let owlt = contact.owlt_secs();
                if !owlt.is_finite() || owlt < 0.0 {
                    continue;
                }
                let next_arrival = send + owlt;
                if let Some(max) = opts.max_arrival {
                    if next_arrival > max {
                        continue;
                    }
                }
                let next_hops = hops + 1;
                let improves = match best.get(&contact.destination) {
                    None => true,
                    Some(&(b, h)) => next_arrival < b || (next_arrival == b && next_hops < h),
                };
                if improves {
                    best.insert(contact.destination.clone(), (next_arrival, next_hops));
                    prev.insert(contact.destination.clone(), (contact.clone(), send));
                    heap.push(QueueEntry {
                        arrival: next_arrival,
                        hops: next_hops,
                        node: contact.destination.clone(),
                    });
                }
            }
        }
        if !reached && !best.contains_key(destination) {
            return None;
        }

        let mut chain: Vec<(Contact, Timestamp)> = Vec::new();
        let mut cursor = destination.to_string();
        while let Some((contact, send)) = prev.get(&cursor).cloned() {
            chain.push((contact.clone(), send));
            cursor = contact.source;
            if chain.len() > opts.max_hops {
                debug_assert!(false, "predecessor chain longer than max_hops");
                return None;
            }
        }
        if chain.is_empty() || cursor != source {
            return None;
        }
        chain.reverse();
        let mut journey = Journey::new();
        for (contact, send) in chain {
            if !journey.append(contact, send) {
                debug_assert!(false, "CGR produced a causally impossible journey");
                return None;
            }
        }
        Some(journey)
    }

    pub fn find_disjoint_journeys(
        &self,
        source: &str,
        destination: &str,
        t_now: Timestamp,
        k: usize,
        opts: &RouteOptions,
    ) -> Vec<Journey> {
        let mut used: HashSet<NodeId> = HashSet::new();
        let mut out = Vec::new();
        for _ in 0..k {
            let mut trial = opts.clone();
            trial.max_hops = opts.max_hops;
            for node in &used {
                trial.excluded_nodes.insert(node.clone());
            }
            match self.find_earliest_arrival_with(source, destination, t_now, &trial) {
                Some(journey) => {
                    for node in journey.transit_nodes() {
                        used.insert(node);
                    }
                    out.push(journey);
                }
                None => break,
            }
        }
        out
    }
}

pub const COSMIC_ERROR_RATE: f64 = 0.001;

pub const BYZANTINE_PROB_THRESHOLD: f64 = 1e-6;

pub const OBSERVATION_WINDOW_SIZE: usize = 1000;

fn poisson_pmf(k: u64, lambda: f64) -> f64 {
    if lambda <= 0.0 {
        return if k == 0 { 1.0 } else { 0.0 };
    }
    let log_p = -lambda + k as f64 * lambda.ln() - log_factorial(k);
    log_p.exp()
}

fn poisson_cdf_tail(k: u64, lambda: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let mut cumulative = 0.0f64;
    for i in 0..k {
        cumulative += poisson_pmf(i, lambda);
        if cumulative > 1.0 {
            cumulative = 1.0;
            break;
        }
    }
    (1.0 - cumulative).max(0.0)
}

fn log_factorial(k: u64) -> f64 {
    if k <= 20 {
        (1..=k).map(|i| (i as f64).ln()).sum()
    } else {
        let kf = k as f64;
        kf * kf.ln() - kf + 0.5 * (2.0 * std::f64::consts::PI * kf).ln()
    }
}

#[derive(Debug, Clone)]
pub struct InteractionObservation {
    pub success: bool,
    pub timestamp: Instant,
}

pub struct PoissonReputationMatrix {
    observations: DashMap<(NodeId, NodeId), Vec<InteractionObservation>>,
    cosmic_lambda: f64,
    byzantine_threshold: f64,
    window_size: usize,
    flagged: DashMap<(NodeId, NodeId), bool>,
}

impl Default for PoissonReputationMatrix {
    fn default() -> Self {
        Self {
            observations: DashMap::new(),
            cosmic_lambda: COSMIC_ERROR_RATE,
            byzantine_threshold: BYZANTINE_PROB_THRESHOLD,
            window_size: OBSERVATION_WINDOW_SIZE,
            flagged: DashMap::new(),
        }
    }
}

impl PoissonReputationMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_interaction(&self, from: &str, to: &str, success: bool) {
        let key = (from.to_string(), to.to_string());
        let mut observations = self.observations.entry(key.clone()).or_default();

        observations.push(InteractionObservation {
            success,
            timestamp: Instant::now(),
        });

        while observations.len() > self.window_size {
            observations.remove(0);
        }

        let error_count = observations.iter().filter(|o| !o.success).count() as u64;
        let total = observations.len() as f64;
        let expected_errors = self.cosmic_lambda * total;
        let p_value = poisson_cdf_tail(error_count, expected_errors);

        let is_byzantine = p_value < self.byzantine_threshold && error_count > 5;
        self.flagged.insert(key, is_byzantine);
    }

    pub fn is_byzantine(&self, from: &str, to: &str) -> bool {
        self.flagged
            .get(&(from.to_string(), to.to_string()))
            .map(|v| *v.value())
            .unwrap_or(false)
    }

    pub fn observed_error_rate(&self, from: &str, to: &str) -> f64 {
        let key = (from.to_string(), to.to_string());
        if let Some(obs) = self.observations.get(&key) {
            let total = obs.len() as f64;
            if total > 0.0 {
                let errors = obs.iter().filter(|o| !o.success).count() as f64;
                errors / total
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    pub fn cosmic_consistency_p_value(&self, from: &str, to: &str) -> f64 {
        let key = (from.to_string(), to.to_string());
        if let Some(obs) = self.observations.get(&key) {
            let total = obs.len() as f64;
            if total > 0.0 {
                let errors = obs.iter().filter(|o| !o.success).count() as u64;
                let expected = self.cosmic_lambda * total;
                poisson_cdf_tail(errors, expected)
            } else {
                1.0
            }
        } else {
            1.0
        }
    }

    pub fn reset(&self, from: &str, to: &str) {
        let key = (from.to_string(), to.to_string());
        self.observations.remove(&key);
        self.flagged.remove(&key);
    }

    pub fn set_cosmic_rate(&mut self, rate: f64) {
        self.cosmic_lambda = rate;
    }
}

pub struct ReputationMatrix {
    scores: HashMap<(NodeId, NodeId), f64>,
    alpha: f64,
    drop_threshold: f64,
}

impl Default for ReputationMatrix {
    fn default() -> Self {
        Self {
            scores: HashMap::new(),
            alpha: 0.9,
            drop_threshold: 0.3,
        }
    }
}

impl ReputationMatrix {
    pub fn record_interaction(&mut self, from: &str, to: &str, success: bool) {
        let key = (from.to_string(), to.to_string());
        let ratio = if success { 1.0 } else { 0.0 };
        let current = self.scores.get(&key).copied().unwrap_or(1.0);
        self.scores
            .insert(key, self.alpha * current + (1.0 - self.alpha) * ratio);
    }

    pub fn get_reputation(&self, from: &str, to: &str) -> f64 {
        self.scores
            .get(&(from.to_string(), to.to_string()))
            .copied()
            .unwrap_or(1.0)
    }

    pub fn is_trusted(&self, from: &str, to: &str) -> bool {
        self.get_reputation(from, to) >= self.drop_threshold
    }
}

pub fn min_nodes_for_byzantine_tolerance(f: u32) -> u32 {
    f.checked_mul(3)
        .and_then(|x| x.checked_add(1))
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::net::orbit::KeplerElements;

    #[test]
    fn test_poisson_pmf_small() {
        let p0 = poisson_pmf(0, 0.001);
        assert!((p0 - 0.9990005).abs() < 0.001);

        let p1 = poisson_pmf(1, 0.001);
        assert!((p1 - 0.000999).abs() < 0.001);
    }

    #[test]
    fn test_cosmic_consistency_normal() {
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        for _ in 0..1000 {
            rep.record_interaction("alice", "bob", true);
        }
        for _ in 0..2 {
            rep.record_interaction("alice", "bob", false);
        }

        let p_value = rep.cosmic_consistency_p_value("alice", "bob");
        assert!(
            p_value > 0.05,
            "p_value={} should be >0.05 for cosmic-consistent errors",
            p_value
        );
        assert!(
            !rep.is_byzantine("alice", "bob"),
            "Should not flag as Byzantine for cosmic-consistent errors"
        );
    }

    #[test]
    fn test_byzantine_detection() {
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        for _ in 0..70 {
            rep.record_interaction("alice", "mallory", true);
        }
        for _ in 0..30 {
            rep.record_interaction("alice", "mallory", false);
        }

        let p_value = rep.cosmic_consistency_p_value("alice", "mallory");
        assert!(
            p_value < 0.001,
            "p_value={} should be <0.001 for malicious errors",
            p_value
        );
        assert!(
            rep.is_byzantine("alice", "mallory"),
            "Should flag malicious peer as Byzantine"
        );
        assert!(rep.observed_error_rate("alice", "mallory") > 0.2);
    }

    #[test]
    fn test_reset_clears_flag() {
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        for _ in 0..50 {
            rep.record_interaction("a", "b", false);
        }
        assert!(rep.is_byzantine("a", "b"));

        rep.reset("a", "b");
        assert!(!rep.is_byzantine("a", "b"));
        assert_eq!(rep.observed_error_rate("a", "b"), 0.0);
    }

    #[test]
    fn test_legacy_reputation() {
        let mut rep = ReputationMatrix::default();
        assert!(rep.is_trusted("a", "b"));
        for _ in 0..5 {
            rep.record_interaction("a", "b", false);
        }
        assert!(rep.get_reputation("a", "b") < 1.0);
        for _ in 0..20 {
            rep.record_interaction("a", "b", true);
        }
        assert!(rep.get_reputation("a", "b") > 0.9);
    }

    fn ms(v: f64) -> Duration {
        Duration::from_secs_f64(v / 1000.0)
    }

    #[test]
    fn owlt_follows_range_and_medium() {
        let laser =
            Contact::new("sat", "gs", 0.0, 100.0, 0.0).with_range_km(600.0, LinkMedium::Laser);
        let l = laser.owlt_secs();
        assert!(
            (l - 0.002_0).abs() < 1e-4,
            "laser owlt should be ≈2.0 ms, got {l}"
        );

        let fibre = Contact::new("a", "b", 0.0, 100.0, 0.0).with_range_km(600.0, LinkMedium::Fibre);
        let f = fibre.owlt_secs();
        assert!(f > l, "fibre must be slower than vacuum: {f} vs {l}");
        assert!(
            (f / l - 1.468).abs() < 1e-3,
            "fibre/laser ratio should be the refractive index, got {}",
            f / l
        );

        assert_eq!(latency(&laser, 0.0), Duration::from_secs_f64(l));
    }

    #[test]
    fn a_measurement_overrides_the_geometric_model() {
        let contact = Contact::new("a", "b", 0.0, 60.0, 0.0)
            .with_range_km(30_000.0, LinkMedium::Laser)
            .with_measured_owlt(0.012);
        assert_eq!(contact.owlt_secs(), 0.012);
        assert_eq!(latency(&contact, 0.0), Duration::from_millis(12));
    }

    #[test]
    fn multi_hop_can_beat_a_slow_direct_link() {
        let mut plan = ContactPlan::default();
        plan.add_contact(Contact::new("src", "dst", 0.0, 100.0, 0.0).with_measured_owlt(0.200));
        plan.add_contact(Contact::new("src", "relay", 0.0, 100.0, 0.0).with_measured_owlt(0.001));
        plan.add_contact(Contact::new("relay", "dst", 0.0, 100.0, 0.0).with_measured_owlt(0.001));

        let journey = plan
            .find_earliest_arrival("src", "dst", 0.0)
            .expect("a route exists");
        assert_eq!(journey.hops(), 2, "the relay path must win on arrival time");
        assert_eq!(journey.path_string(), "src -> relay -> dst");
        assert_eq!(journey.arrival_time, 0.002);
        assert_eq!(journey.total_latency, ms(2.0));
        assert_eq!(journey.transit_nodes(), vec!["relay".to_string()]);
    }

    #[test]
    fn a_window_that_has_not_opened_is_waited_for() {
        let mut plan = ContactPlan::default();
        plan.add_contact(Contact::new("src", "dst", 10.0, 20.0, 0.0).with_measured_owlt(0.001));
        let journey = plan.find_earliest_arrival("src", "dst", 0.0).unwrap();
        assert_eq!(
            journey.contacts[0].1, 10.0,
            "send time must be the window open"
        );
        assert_eq!(journey.arrival_time, 10.001);
    }

    #[test]
    fn a_closed_contact_cannot_be_used() {
        let mut plan = ContactPlan::default();
        plan.add_contact(Contact::new("src", "dst", 0.0, 5.0, 0.0).with_measured_owlt(0.001));
        assert!(plan.find_earliest_arrival("src", "dst", 6.0).is_none());
        assert!(plan.find_earliest_arrival("src", "dst", 4.999).is_some());
    }

    #[test]
    fn unreachable_destination_is_none() {
        let mut plan = ContactPlan::default();
        plan.add_contact(Contact::new("src", "other", 0.0, 100.0, 0.0).with_measured_owlt(0.001));
        assert!(plan.find_earliest_arrival("src", "dst", 0.0).is_none());
        assert!(plan.find_earliest_arrival("src", "src", 0.0).is_none());
    }

    #[test]
    fn hops_are_bounded_by_route_options() {
        let mut plan = ContactPlan::default();
        for (a, b) in [("a", "b"), ("b", "c"), ("c", "d")] {
            plan.add_contact(Contact::new(a, b, 0.0, 100.0, 0.0).with_measured_owlt(0.001));
        }
        let opts = RouteOptions {
            max_hops: 2,
            ..Default::default()
        };
        assert!(
            plan.find_earliest_arrival_with("a", "d", 0.0, &opts)
                .is_none(),
            "a 3-hop path must not be returned under max_hops=2"
        );
        let opts = RouteOptions {
            max_hops: 3,
            ..Default::default()
        };
        assert_eq!(
            plan.find_earliest_arrival_with("a", "d", 0.0, &opts)
                .unwrap()
                .hops(),
            3
        );
    }

    #[test]
    fn journey_rejects_causally_impossible_hops() {
        let mut journey = Journey::new();
        let first = Contact::new("a", "b", 0.0, 100.0, 0.0).with_measured_owlt(0.010);
        assert!(journey.append(first, 0.0));
        assert_eq!(journey.arrival_time, 0.010);

        let second = Contact::new("b", "c", 0.0, 100.0, 0.0).with_measured_owlt(0.010);
        assert!(!journey.append(second.clone(), 0.005));
        let late = Contact::new("b", "c", 50.0, 60.0, 0.0).with_measured_owlt(0.010);
        assert!(!journey.append(late, 0.020));
        assert!(journey.append(second, 0.010));
        assert_eq!(journey.arrival_time, 0.020);
        assert_eq!(journey.total_latency, ms(20.0));
    }

    #[test]
    fn disjoint_journeys_share_no_transit_node() {
        let mut plan = ContactPlan::default();
        for (a, b, owlt) in [
            ("src", "r1", 0.001),
            ("r1", "dst", 0.001),
            ("src", "r2", 0.002),
            ("r2", "dst", 0.002),
            ("src", "r3", 0.003),
            ("r3", "r4", 0.003),
            ("r4", "dst", 0.003),
        ] {
            plan.add_contact(Contact::new(a, b, 0.0, 100.0, 0.0).with_measured_owlt(owlt));
        }
        let journeys = plan.find_disjoint_journeys("src", "dst", 0.0, 3, &RouteOptions::default());
        assert_eq!(journeys.len(), 3, "three separate paths are available");
        let mut seen: HashSet<NodeId> = HashSet::new();
        for j in &journeys {
            for node in j.transit_nodes() {
                assert!(seen.insert(node.clone()), "transit node {node} reused");
            }
        }
        assert_eq!(journeys[0].path_string(), "src -> r1 -> dst");
        assert_eq!(journeys[1].path_string(), "src -> r2 -> dst");
        assert_eq!(journeys[2].path_string(), "src -> r3 -> r4 -> dst");
    }

    #[test]
    fn observe_link_records_measured_rtt_and_refreshes_in_place() {
        let mut plan = ContactPlan::default();
        plan.observe_link(
            "me",
            "peer",
            Duration::from_millis(40),
            0.0,
            60.0,
            1_000_000.0,
        );
        assert_eq!(plan.len(), 1);
        let c = &plan.contacts[0];
        assert_eq!(c.owlt_secs(), 0.020);
        assert_eq!(c.measured_owlt_secs, Some(0.020));
        assert_eq!(c.x_cap, 1_000_000.0 * 60.0);

        plan.observe_link("me", "peer", Duration::from_millis(10), 10.0, 60.0, 0.0);
        assert_eq!(
            plan.len(),
            1,
            "a live window must be refreshed, not duplicated"
        );
        let c = &plan.contacts[0];
        assert_eq!(c.owlt_secs(), 0.005, "the newer measurement wins");
        assert_eq!(c.t_end, 70.0);

        plan.observe_link("me", "peer", Duration::from_millis(10), 100.0, 60.0, 0.0);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.get_contacts_from("me", 0.0).len(), 1);
        assert!(plan.get_contacts_from("me", 200.0).is_empty());
    }

    #[test]
    fn measured_direct_link_routes_without_a_geometric_model() {
        let mut plan = ContactPlan::default();
        plan.observe_link("me", "peer", Duration::from_millis(30), 0.0, 120.0, 0.0);
        let journey = plan.find_earliest_arrival("me", "peer", 0.0).unwrap();
        assert_eq!(journey.hops(), 1);
        assert_eq!(journey.arrival_time, 0.015);
    }

    #[test]
    fn an_orbital_pass_yields_contacts_with_propagated_light_times() {
        let elements = KeplerElements::typical_leo();
        let period = elements.orbital_period();
        let mut orbit = OrbitalState::new(elements, 0.0, 0.0);
        let sub = orbit.ground_pos.clone();
        let mut plan = ContactPlan::default();
        let added = plan.project_orbital_pass(
            "sat-1",
            "gs-1",
            &mut orbit,
            &sub,
            0.0,
            period * 2.0,
            10.0,
            10_000_000.0,
        );
        assert!(added >= 1, "a satellite must see its own sub-point at t=0");
        for c in plan.contacts_from("sat-1") {
            assert!(c.t_end > c.t_start, "a window must have positive length");
            let owlt = c.owlt_secs();
            assert!(
                owlt > 0.001 && owlt < 0.020,
                "LEO light time out of range: {owlt}"
            );
            assert!(c.x_cap > 0.0);
        }
    }

    #[test]
    fn test_thermal_mesh_energy_heterogeneity_scoring() {
        let uniform = [EnergyClass::Mains, EnergyClass::Mains, EnergyClass::Mains];
        assert_eq!(
            energy_heterogeneity_score(&uniform),
            1,
            "Uniform cluster must score 1"
        );

        let partial = [EnergyClass::Mains, EnergyClass::Battery, EnergyClass::Mains];
        assert_eq!(
            energy_heterogeneity_score(&partial),
            2,
            "Two distinct classes must score 2"
        );

        let full_hetero = [
            EnergyClass::Mains,
            EnergyClass::Battery,
            EnergyClass::Harvested,
        ];
        assert_eq!(
            energy_heterogeneity_score(&full_hetero),
            3,
            "All three distinct must score 3"
        );
    }

    #[test]
    fn test_thermal_mesh_triple_selection() {
        let mut j_mains1 = Journey::new();
        let c1 = Contact::new("A", "B", 0.0, 100.0, 1000.0).with_energy_class(EnergyClass::Mains);
        j_mains1.append(c1, 10.0);

        let mut j_mains2 = Journey::new();
        let c2 = Contact::new("A", "C", 0.0, 100.0, 1000.0).with_energy_class(EnergyClass::Mains);
        j_mains2.append(c2, 10.0);

        let mut j_battery = Journey::new();
        let c3 = Contact::new("A", "D", 0.0, 100.0, 1000.0).with_energy_class(EnergyClass::Battery);
        j_battery.append(c3, 10.0);

        let mut j_harvested = Journey::new();
        let c4 =
            Contact::new("A", "E", 0.0, 100.0, 1000.0).with_energy_class(EnergyClass::Harvested);
        j_harvested.append(c4, 10.0);

        let candidates = vec![j_mains1, j_mains2, j_battery, j_harvested];
        let triple = ContactPlan::select_thermal_heterogeneous_triple(&candidates)
            .expect("Must select a triple");

        let classes = [
            triple.0.primary_energy_class(),
            triple.1.primary_energy_class(),
            triple.2.primary_energy_class(),
        ];
        assert_eq!(
            energy_heterogeneity_score(&classes),
            3,
            "Must pick a fully heterogeneous triple (Mains + Battery + Harvested)"
        );
    }
}
