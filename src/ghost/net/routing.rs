/// Contact Graph Routing (CGR) & Time-Variable Graph (TVG)
///
/// Implements the routing abstractions described in the Vantablack architecture:
///
/// ## Poisson-Distributed Error Rate Checking
/// The reputation matrix now uses a Poisson-distributed error model to distinguish
/// between benign cosmic radiation bit-flips (which follow a Poisson process with
/// known rate λ_cosmic) and malicious behavior (which has a significantly higher
/// error rate). This allows the node to issue Byzantine isolation accusations only
/// when the probability of the observed errors being due to cosmic radiation is
/// negligibly small (< 10^-6).
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::orbit::{GroundPosition, OrbitalState};

/// A node identifier (e.g., satellite ID or ground station).
pub type NodeId = String;

/// Timestamp as seconds since epoch (or relative offset).
pub type Timestamp = f64;

/// Speed of light in vacuum, km/s.
pub const C_KM_S: f64 = 299_792.458;

/// Group velocity in single-mode optical fibre (n ≈ 1.468), km/s.
pub const FIBRE_KM_S: f64 = C_KM_S / 1.468;

/// The physical bearer a contact runs over. This is what turns a distance into a
/// delay: the previous implementation returned a hard-coded 10 ms for every
/// contact regardless of range, which made every route look identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkMedium {
    /// Free-space optical (laser inter-satellite link): propagates at `c`.
    #[default]
    Laser,
    /// Radio (RF ground or space link): also effectively `c`.
    Radio,
    /// Terrestrial fibre: ≈ 0.68·`c`.
    Fibre,
}

impl LinkMedium {
    /// Signal velocity in km/s.
    pub fn speed_km_s(self) -> f64 {
        match self {
            LinkMedium::Laser | LinkMedium::Radio => C_KM_S,
            LinkMedium::Fibre => FIBRE_KM_S,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Thermal-Mesh (Energy-Heterogeneous Routing)
// ═════════════════════════════════════════════════════════════════════════════

/// Physical energy class of a node or link.
///
/// Route selection uses energy heterogeneity as an anti-Sybil constraint:
/// a uniform-energy cluster (e.g. cloud VMs) is deprioritized in favor of
/// heterogeneous triples (Mains + Battery + Harvested/Solar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EnergyClass {
    #[default]
    Mains, // Plugged desktop/server with stable grid power
    Battery,   // Mobile device / battery-constrained node
    Harvested, // Solar / energy-harvesting / intermittent node
}

/// A contact window between two nodes.
#[derive(Debug, Clone, Default)]
pub struct Contact {
    pub source: NodeId,
    pub destination: NodeId,
    /// Start of the visibility window (seconds since epoch or offset).
    pub t_start: Timestamp,
    /// End of the visibility window.
    pub t_end: Timestamp,
    /// Maximum data capacity in bits.
    pub x_cap: f64,
    /// Slant range between the endpoints, kilometres. The geometric input to
    /// [`latency`] when no measurement is available.
    pub range_km: f64,
    /// Physical bearer for this contact.
    pub medium: LinkMedium,
    /// Energy class of the contact / bearer node.
    pub energy_class: EnergyClass,
    /// Link rate in bits per second; `0.0` means unspecified. Used to derive
    /// [`Contact::x_cap`] and to price queuing in a capacity-aware route.
    pub rate_bps: f64,
    /// A **measured** one-way light time in seconds. When present it overrides
    /// the geometric model, because a real round trip beats an assumed distance.
    pub measured_owlt_secs: Option<f64>,
}

impl Contact {
    /// A contact with no geometry and no measurement — only a window.
    ///
    /// This is the shape a caller knows from a beacon: *the peer is reachable
    /// now, at this address*. Latency stays zero until something measures it, so
    /// prefer [`ContactPlan::observe_link`] when an RTT is available.
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

    /// Set the slant range and bearer, which together define the light time.
    pub fn with_range_km(mut self, range_km: f64, medium: LinkMedium) -> Self {
        self.range_km = range_km.max(0.0);
        self.medium = medium;
        self
    }

    /// Set the link rate (bits per second) and recompute `x_cap` from it.
    pub fn with_rate_bps(mut self, rate_bps: f64) -> Self {
        self.rate_bps = rate_bps.max(0.0);
        self.x_cap = self.rate_bps * self.window_secs();
        self
    }

    /// Pin a measured one-way light time, overriding the geometric model.
    pub fn with_measured_owlt(mut self, owlt_secs: f64) -> Self {
        self.measured_owlt_secs = Some(owlt_secs.max(0.0));
        self
    }

    /// Set the energy class of this contact.
    pub fn with_energy_class(mut self, energy_class: EnergyClass) -> Self {
        self.energy_class = energy_class;
        self
    }

    /// Length of the visibility window in seconds.
    pub fn window_secs(&self) -> f64 {
        (self.t_end - self.t_start).max(0.0)
    }

    /// One-way light time in seconds.
    ///
    /// A measurement always wins, because a real RTT beats an assumed distance;
    /// otherwise the range and bearer give the propagation delay.
    pub fn owlt_secs(&self) -> f64 {
        match self.measured_owlt_secs {
            Some(m) => m,
            None => self.range_km.max(0.0) / self.medium.speed_km_s(),
        }
    }
}

/// The edge presence function: ρ(e, t) → whether an edge exists at time t.
pub fn edge_presence(contact: &Contact, t: Timestamp) -> bool {
    t >= contact.t_start && t <= contact.t_end
}

/// The latency function: ζ(e, t) — signal propagation delay.
///
/// For a 500 km laser link this is ≈1.7 ms; the same link over fibre is ≈2.5 ms.
/// Serialisation and queuing are deliberately *not* included here: this is the
/// propagation term the routing algorithm composes, and mixing in a per-packet
/// term would make the same contact cost different amounts for different packets.
pub fn latency(contact: &Contact, _t: Timestamp) -> Duration {
    let secs = contact.owlt_secs();
    if secs.is_finite() && secs > 0.0 {
        Duration::from_secs_f64(secs)
    } else {
        Duration::ZERO
    }
}

/// A journey is a sequence of time-ordered contacts.
///
/// Each entry is the contact and the instant data is put on it; the moment the
/// hop *completes* is `send_time + owlt`. `arrival_time` tracks the completion of
/// the final hop, which is the quantity earliest-arrival routing minimises.
#[derive(Debug, Clone, Default)]
pub struct Journey {
    pub contacts: Vec<(Contact, Timestamp)>,
    /// Sum of the hop light times — propagation only, no queuing.
    pub total_latency: Duration,
    /// When the last hop's data lands at the destination, in the same clock as
    /// the contact timestamps.
    pub arrival_time: Timestamp,
}

impl Journey {
    /// Create an empty journey.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a contact with the transmission time to this journey.
    ///
    /// Rejected when the hop cannot be taken: data cannot be put on a contact
    /// before the previous hop has arrived, nor outside the contact's own
    /// visibility window. Returns false in either case, so a caller looping over
    /// contacts cannot silently build a physically impossible route.
    pub fn append(&mut self, contact: Contact, send_time: Timestamp) -> bool {
        if !send_time.is_finite() {
            return false;
        }
        if let Some((last_contact, last_send)) = self.contacts.last() {
            let previous_arrival = last_send + last_contact.owlt_secs();
            // A hop that starts before the previous one lands would be a
            // causality violation, not a fast route.
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

    /// Number of hops.
    pub fn hops(&self) -> usize {
        self.contacts.len()
    }

    /// The node sequence `source → … → destination`.
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

    /// Human-readable route, e.g. `A -> B -> C`.
    pub fn path_string(&self) -> String {
        self.nodes().join(" -> ")
    }

    /// Every node the journey passes *through*, i.e. excluding the endpoints.
    /// These are the nodes a disjoint-route search must avoid reusing.
    pub fn transit_nodes(&self) -> Vec<NodeId> {
        let nodes = self.nodes();
        if nodes.len() <= 2 {
            return Vec::new();
        }
        nodes[1..nodes.len() - 1].to_vec()
    }

    /// Sequence of energy classes across all hops in this journey.
    pub fn energy_classes(&self) -> Vec<EnergyClass> {
        self.contacts.iter().map(|(c, _)| c.energy_class).collect()
    }

    /// Dominant / terminating hop energy class of the journey.
    pub fn primary_energy_class(&self) -> EnergyClass {
        self.contacts
            .last()
            .map(|(c, _)| c.energy_class)
            .unwrap_or_default()
    }
}

/// Computes the heterogeneity score of a set of energy classes.
/// Returns the number of distinct energy classes represented (e.g. 3 for Mains+Battery+Harvested).
pub fn energy_heterogeneity_score(classes: &[EnergyClass]) -> usize {
    let mut unique = std::collections::HashSet::new();
    for &c in classes {
        unique.insert(c);
    }
    unique.len()
}

/// Knobs for the earliest-arrival search.
#[derive(Debug, Clone)]
pub struct RouteOptions {
    /// Hard bound on hop count, so a pathological contact list cannot produce an
    /// unbounded path.
    pub max_hops: usize,
    /// Optional deadline: journeys arriving later than this are not returned.
    pub max_arrival: Option<Timestamp>,
    /// Nodes that may not be used as *transit* (multi-hop) hops. The source and
    /// destination are never treated as transit, so they may appear here.
    pub excluded_nodes: HashSet<NodeId>,
    /// Individual hops to forbid, as `(source, destination)`. This is the
    /// mechanism that keeps shards on disjoint physical links.
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

/// Default hop bound for [`ContactPlan::find_earliest_arrival`].
pub const DEFAULT_MAX_HOPS: usize = 8;

/// One relaxation candidate in the earliest-arrival search.
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
        // `BinaryHeap` is a max-heap; invert so the earliest arrival pops first.
        other
            .arrival
            .partial_cmp(&self.arrival)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.hops.cmp(&self.hops))
            .then_with(|| other.node.cmp(&self.node))
    }
}

/// Contact plan: the set of all known contacts in the network.
#[derive(Debug, Clone, Default)]
pub struct ContactPlan {
    /// Every contact, in insertion order.
    pub contacts: Vec<Contact>,
    /// Node → indices into [`Self::contacts`], kept sorted by `t_start`.
    ///
    /// Indices rather than copies: a measured link has to be *updated*, and a
    /// cloned edge list would let the two views drift apart.
    pub by_source: HashMap<NodeId, Vec<usize>>,
}

impl ContactPlan {
    /// Add a contact, keeping the per-source list sorted by window start.
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

    /// Every contact originating at `node`, regardless of when it is active.
    pub fn contacts_from(&self, node: &str) -> impl Iterator<Item = &Contact> {
        self.by_source
            .get(node)
            .into_iter()
            .flatten()
            .map(move |&i| &self.contacts[i])
    }

    /// Contacts from `source` that are active at `t`.
    pub fn get_contacts_from(&self, source: &str, t: Timestamp) -> Vec<&Contact> {
        self.contacts_from(source)
            .filter(|c| edge_presence(c, t))
            .collect()
    }

    /// Total number of contacts known.
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Selects a triple of candidate journeys for 3 RS shards,
    /// searching and picking candidate paths that maximize physical energy heterogeneity
    /// (preferring Mains + Battery + Harvested/Solar over uniform clusters).
    pub fn select_thermal_heterogeneous_triple(
        candidates: &[Journey],
    ) -> Option<(Journey, Journey, Journey)> {
        if candidates.len() < 3 {
            return None;
        }
        let mut best_triple = None;
        let mut best_score = 0;
        for i in 0..candidates.len() {
            for j in (i + 1)..candidates.len() {
                for k in (j + 1)..candidates.len() {
                    let classes = [
                        candidates[i].primary_energy_class(),
                        candidates[j].primary_energy_class(),
                        candidates[k].primary_energy_class(),
                    ];
                    let score = energy_heterogeneity_score(&classes);
                    if score > best_score {
                        best_score = score;
                        best_triple = Some((
                            candidates[i].clone(),
                            candidates[j].clone(),
                            candidates[k].clone(),
                        ));
                        if score == 3 {
                            return best_triple;
                        }
                    }
                }
            }
        }
        best_triple
    }

    /// Register (or refresh) a **measured** direct contact to a peer.
    ///
    /// `rtt` comes from a completed round trip — an ICE check, a keepalive echo,
    /// a beacon reply. Its one-way light time is half of it, which is the honest
    /// latency for this link; the peer's address is not consulted, because a
    /// measured delay beats a modelled distance.
    ///
    /// An existing live window is *updated in place* rather than duplicated, so
    /// repeatedly observing a stable peer does not grow the plan without bound.
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
            // Keep the geometric view consistent with the measurement instead of
            // leaving two contradicting latency numbers on one contact.
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
        // A measurement over an unknown bearer is modelled on the faster one, so
        // the derived range never *understates* the path.
        contact.medium = LinkMedium::Laser;
        contact.range_km = C_KM_S * owlt;
        self.add_contact(contact);
    }

    /// Populate a contact plan from a real orbital pass.
    ///
    /// Propagates `orbit` from `t_start` to `t_start + horizon_secs` in
    /// `step_secs` steps and records one contact per contiguous stretch of
    /// line-of-sight to `ground`, with latency taken from the orbital geometry
    /// ([`OrbitalState::signal_delay`], i.e. slant range over `c`) rather than
    /// from an assumption. Returns the number of contacts added.
    ///
    /// This is what makes a `Contact` mean something for the space segment: the
    /// windows and the light times both come from the propagated elements.
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
        let mut added = 0;
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
                added += 1;
            }
            t += step_secs;
        }
        if let Some((start, last_seen, delay)) = window.take() {
            self.push_ground_contact(sat, ground_node, start, last_seen, delay, rate_bps);
            added += 1;
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
        // The window stays open until the next step, since visibility was true at
        // `last_seen`; the contact closes one step later, not at the instant of
        // the last sample.
        let end = (last_seen + (last_seen - start).max(0.0)).max(last_seen);
        let contact = Contact::new(
            sat.to_string(),
            ground_node.to_string(),
            start,
            end,
            rate_bps.max(1.0) * (end - start),
        )
        .with_rate_bps(rate_bps)
        // A ground↔space hop over RF/laser travels at `c`; the delay is the
        // propagated slant range, so it is recorded as a measurement.
        .with_measured_owlt(delay_secs);
        self.add_contact(contact);
    }

    /// Earliest-arrival (CGR) route with default options.
    ///
    /// Unlike a single-hop lookup, this is a Dijkstra over the *time-varying*
    /// graph: the cost of an edge is the arrival instant it produces, not its
    /// latency, because waiting for a fast link can beat taking a slow one now.
    pub fn find_earliest_arrival(
        &self,
        source: &str,
        destination: &str,
        t_now: Timestamp,
    ) -> Option<Journey> {
        self.find_earliest_arrival_with(source, destination, t_now, &RouteOptions::default())
    }

    /// Earliest-arrival route honouring [`RouteOptions`].
    ///
    /// Returns `None` when no time-respecting path exists. Termination is
    /// guaranteed: every relaxation strictly decreases a node's best arrival
    /// time, and candidate arrivals only grow with hop count, so no cycle can
    /// improve a node twice.
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
            // Skip entries superseded while they sat in the heap.
            match best.get(&node) {
                Some(&(b, h)) if b < arrival || (b == arrival && h < hops) => continue,
                _ => {}
            }
            if hops >= opts.max_hops {
                continue;
            }
            for contact in self.contacts_from(&node) {
                // The contact must still be open when we would arrive at its
                // source. `t_end < arrival` means it closed before we got here.
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

        // Walk the predecessor chain back from the destination.
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
                // The search already enforced causality; a failure here would
                // mean the two disagree, so refuse rather than return a route we
                // cannot justify.
                debug_assert!(false, "CGR produced a causally impossible journey");
                return None;
            }
        }
        Some(journey)
    }

    /// Up to `k` node-disjoint earliest-arrival journeys.
    ///
    /// Each journey after the first avoids every node the previous ones transit, which is what
    /// the shard router needs: three shards on three genuinely separate paths
    /// survive a single-node compromise, whereas three shards over the same
    /// intermediate hop do not. Overlapping only at the endpoints is allowed —
    /// that is inherent to any multi-path.
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

// ── Poisson-Distributed Error Rate Checking ──────────────────────────

/// Baseline cosmic radiation bit-flip rate per packet (λ_cosmic).
/// In LEO, the typical single-event upset rate is ~10^-7 to 10^-6 errors/bit/day.
/// For a 512-byte (4096-bit) GTF privacy frame, this gives ~4×10^-4 to 4×10^-3
/// errors per packet per day. We use λ = 0.001 as the baseline per-packet error rate
/// due to cosmic radiation.
pub const COSMIC_ERROR_RATE: f64 = 0.001;

/// Threshold for Byzantine isolation: if the probability of observing the
/// actual error count under the Poisson(λ_cosmic) model is below this value,
/// the behavior is classified as malicious.
pub const BYZANTINE_PROB_THRESHOLD: f64 = 1e-6;

/// Maximum number of packets in the sliding observation window.
pub const OBSERVATION_WINDOW_SIZE: usize = 1000;

/// Compute the Poisson probability mass function: P(X = k) = e^{-λ} * λ^k / k!
/// Where λ is the expected number of errors under cosmic radiation.
fn poisson_pmf(k: u64, lambda: f64) -> f64 {
    if lambda <= 0.0 {
        return if k == 0 { 1.0 } else { 0.0 };
    }
    // Use log domain for numerical stability
    let log_p = -lambda + k as f64 * lambda.ln() - log_factorial(k);
    log_p.exp()
}

/// Compute the cumulative Poisson probability: P(X ≥ k) = 1 - Σ_{i=0}^{k-1} P(X = i)
/// This tells us the probability of seeing k or more errors if the true rate is λ.
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

/// Natural log of factorial using Stirling's approximation for large k,
/// or direct multiplication for small k.
fn log_factorial(k: u64) -> f64 {
    if k <= 20 {
        // Direct computation for small values
        (1..=k).map(|i| (i as f64).ln()).sum()
    } else {
        // Stirling's approximation: ln(k!) ≈ k*ln(k) - k + 0.5*ln(2πk)
        let kf = k as f64;
        kf * kf.ln() - kf + 0.5 * (2.0 * std::f64::consts::PI * kf).ln()
    }
}

/// A single interaction observation stored per peer pair.
/// Records whether a packet interaction succeeded or failed, and when.
#[derive(Debug, Clone)]
pub struct InteractionObservation {
    /// Whether the interaction was successful (true) or failed (false).
    pub success: bool,
    /// When the interaction occurred.
    pub timestamp: Instant,
}

/// Concurrent reputation matrix using DashMap for lock-free reads.
///
/// Instead of wrapping the whole matrix in a Mutex, we use DashMap for the
/// observation storage so that multiple concurrent packet handlers can
/// record interactions without blocking each other.
pub struct PoissonReputationMatrix {
    /// Internal map: (from, to) → sliding window of observations.
    /// Uses DashMap for concurrent access without a global mutex.
    observations: DashMap<(NodeId, NodeId), Vec<InteractionObservation>>,
    /// The expected Poisson rate λ for cosmic radiation errors per packet.
    cosmic_lambda: f64,
    /// The p-value threshold below which we classify behavior as malicious.
    byzantine_threshold: f64,
    /// Maximum window size for observations.
    window_size: usize,
    /// Whether a peer has been flagged as potentially Byzantine.
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

    /// Record an interaction outcome between two peers.
    /// `success` is true if the packet was verified as authentic,
    /// false if it failed authentication or was corrupted.
    pub fn record_interaction(&self, from: &str, to: &str, success: bool) {
        let key = (from.to_string(), to.to_string());
        let mut observations = self.observations.entry(key.clone()).or_default();

        // Add observation
        observations.push(InteractionObservation {
            success,
            timestamp: Instant::now(),
        });

        // Prune old observations beyond window size
        while observations.len() > self.window_size {
            observations.remove(0);
        }

        // Re-evaluate Byzantine status (statistical aggregation)
        let error_count = observations.iter().filter(|o| !o.success).count() as u64;
        let total = observations.len() as f64;
        let expected_errors = self.cosmic_lambda * total;
        let p_value = poisson_cdf_tail(error_count, expected_errors);

        // Flag as Byzantine if the observed error rate is statistically
        // unlikely under the cosmic radiation model
        let is_byzantine = p_value < self.byzantine_threshold && error_count > 5;
        self.flagged.insert(key, is_byzantine);
    }

    /// Check if `from` considers `to` to be potentially Byzantine.
    pub fn is_byzantine(&self, from: &str, to: &str) -> bool {
        self.flagged
            .get(&(from.to_string(), to.to_string()))
            .map(|v| *v.value())
            .unwrap_or(false)
    }

    /// Get the observed error rate as a fraction.
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

    /// Get the p-value that the observed error rate is consistent with
    /// the cosmic radiation baseline.
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

    /// Clear observations for a peer pair (e.g., after re-establishing a session).
    pub fn reset(&self, from: &str, to: &str) {
        let key = (from.to_string(), to.to_string());
        self.observations.remove(&key);
        self.flagged.remove(&key);
    }

    /// Set a custom cosmic radiation baseline rate.
    pub fn set_cosmic_rate(&mut self, rate: f64) {
        self.cosmic_lambda = rate;
    }
}

/// Legacy reputation matrix (kept for backward compatibility).
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
        // For λ=0.001, P(X=0) = e^{-0.001} ≈ 0.999
        let p0 = poisson_pmf(0, 0.001);
        assert!((p0 - 0.9990005).abs() < 0.001);

        // P(X=1) = e^{-0.001} * 0.001 ≈ 0.000999
        let p1 = poisson_pmf(1, 0.001);
        assert!((p1 - 0.000999).abs() < 0.001);
    }

    #[test]
    fn test_cosmic_consistency_normal() {
        // Simulate a peer with errors consistent with cosmic radiation
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        // 1000 interactions, ~1 error expected (λ * N = 1)
        for _ in 0..1000 {
            rep.record_interaction("alice", "bob", true);
        }
        // A few errors due to cosmic rays
        for _ in 0..2 {
            rep.record_interaction("alice", "bob", false);
        }

        let p_value = rep.cosmic_consistency_p_value("alice", "bob");
        // p-value should be high (errors are consistent with cosmic radiation)
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
        // Simulate a malicious peer with high error rate
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        // 100 interactions, 30% error rate — clearly malicious
        for _ in 0..70 {
            rep.record_interaction("alice", "mallory", true);
        }
        for _ in 0..30 {
            rep.record_interaction("alice", "mallory", false);
        }

        let p_value = rep.cosmic_consistency_p_value("alice", "mallory");
        // p-value should be extremely low (errors are NOT consistent with cosmic radiation)
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

        // Induce Byzantine flag
        for _ in 0..50 {
            rep.record_interaction("a", "b", false);
        }
        assert!(rep.is_byzantine("a", "b"));

        // Reset should clear the flag
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

    // ── CGR / contact plan ──────────────────────────────────────────

    fn ms(v: f64) -> Duration {
        Duration::from_secs_f64(v / 1000.0)
    }

    #[test]
    fn owlt_follows_range_and_medium() {
        // 600 km over a laser link: 600 / 299 792.458 km/s ≈ 2.0 ms.
        let laser =
            Contact::new("sat", "gs", 0.0, 100.0, 0.0).with_range_km(600.0, LinkMedium::Laser);
        let l = laser.owlt_secs();
        assert!(
            (l - 0.002_0).abs() < 1e-4,
            "laser owlt should be ≈2.0 ms, got {l}"
        );

        // The same distance over fibre is slower, and by the known ratio.
        let fibre = Contact::new("a", "b", 0.0, 100.0, 0.0).with_range_km(600.0, LinkMedium::Fibre);
        let f = fibre.owlt_secs();
        assert!(f > l, "fibre must be slower than vacuum: {f} vs {l}");
        assert!(
            (f / l - 1.468).abs() < 1e-3,
            "fibre/laser ratio should be the refractive index, got {}",
            f / l
        );

        // …and through the public latency accessor.
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

    /// Two hops through a fast relay arrive before a slow direct link that is
    /// open right now. A single-hop lookup cannot represent this.
    #[test]
    fn multi_hop_can_beat_a_slow_direct_link() {
        let mut plan = ContactPlan::default();
        // Direct, open immediately, but 200 ms of light time.
        plan.add_contact(Contact::new("src", "dst", 0.0, 100.0, 0.0).with_measured_owlt(0.200));
        // Two hops of 1 ms each, open immediately.
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

    /// A contact that has not opened yet is *waited for*, not teleported onto:
    /// the arrival is `t_start + owlt`, not `t_now + owlt`.
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
        // Just inside the window it is still usable.
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

        // Sending on the next hop before the first lands is a causality break.
        let second = Contact::new("b", "c", 0.0, 100.0, 0.0).with_measured_owlt(0.010);
        assert!(!journey.append(second.clone(), 0.005));
        // …and so is sending outside the contact's own window.
        let late = Contact::new("b", "c", 50.0, 60.0, 0.0).with_measured_owlt(0.010);
        assert!(!journey.append(late, 0.020));
        // Sending after it lands, inside the window, is fine.
        assert!(journey.append(second, 0.010));
        assert_eq!(journey.arrival_time, 0.020);
        assert_eq!(journey.total_latency, ms(20.0));
    }

    #[test]
    fn disjoint_journeys_share_no_transit_node() {
        let mut plan = ContactPlan::default();
        // Two parallel 2-hop routes plus one 3-hop route, all open now.
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
        // Fastest first: the 2 ms route, then the 4 ms route, then 9 ms.
        assert_eq!(journeys[0].path_string(), "src -> r1 -> dst");
        assert_eq!(journeys[1].path_string(), "src -> r2 -> dst");
        assert_eq!(journeys[2].path_string(), "src -> r3 -> r4 -> dst");
    }

    #[test]
    fn observe_link_records_measured_rtt_and_refreshes_in_place() {
        let mut plan = ContactPlan::default();
        // A 40 ms round trip means 20 ms of one-way light time.
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

        // A second observation while the window is live updates rather than adds.
        plan.observe_link("me", "peer", Duration::from_millis(10), 10.0, 60.0, 0.0);
        assert_eq!(
            plan.len(),
            1,
            "a live window must be refreshed, not duplicated"
        );
        let c = &plan.contacts[0];
        assert_eq!(c.owlt_secs(), 0.005, "the newer measurement wins");
        assert_eq!(c.t_end, 70.0);

        // Once the window has closed, a new observation opens a new contact.
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
        // Start the ground station directly under the satellite so a pass is
        // guaranteed inside one orbital period.
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
            // LEO slant range is ~550 km, so light time is a few milliseconds —
            // never the hard-coded 10 ms the old implementation returned.
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
        // Build 4 journeys: 2 mains, 1 battery, 1 solar/harvested
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
