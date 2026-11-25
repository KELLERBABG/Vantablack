#![cfg(feature = "research")]
//! Epistemic Sheaf Cohomology — topological detection of split-world reality
//! (`DEV/UNPRECEDENTED_PRIMITIVES.md` §4, V3 Stage 7).
//!
//! Peers are 0-simplices; an authenticated session is a 1-simplex carrying the
//! discrepancy 1-cochain `delta_uv` between the two endpoints' local
//! observations (relay key sets, certificates, clock offsets). If every honest
//! node reports a projection of one global reality `g`, then
//! `delta_uv = g(v) - g(u)` is exact, every closed loop integrates to zero, and
//! `[delta] = 0` in `H^1`. A single censored or lying edge makes the cocycle
//! non-exact, and the fundamental cycle of that edge is a *witness*: it names a
//! loop whose holonomy is non-zero, which no consistent global reality can
//! explain — even though every node passes its own local checks.
//!
//! This module computes exactly that: a potential fit over a spanning forest,
//! an exactness test, and the non-zero-holonomy cycles that prove a split
//! world. Everything is closed-form integer arithmetic; there is no consensus
//! directory and no trusting of any single peer.

use std::collections::VecDeque;
use std::fmt;

/// An authenticated session between two peers and the discrepancy it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub u: usize,
    pub v: usize,
    /// `observation(v) - observation(u)` as asserted by the session.
    pub delta: Vec<i64>,
}

/// A cycle whose holonomy is non-zero: proof that no global reality exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleWitness {
    /// Closed walk, first vertex repeated at the end.
    pub cycle: Vec<usize>,
    /// Non-zero sum of `delta` around it.
    pub holonomy: Vec<i64>,
}

/// Why a complex could not be built or queried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SheafError {
    UnknownVertex(usize),
    SelfLoop(usize),
    Dimension { expected: usize, got: usize },
    DuplicateEdge { u: usize, v: usize },
    CycleNotClosed { start: usize, end: usize },
    NoPath { u: usize, v: usize },
}

impl fmt::Display for SheafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVertex(v) => write!(f, "vertex {v} is not in the complex"),
            Self::SelfLoop(v) => write!(f, "vertex {v} cannot session with itself"),
            Self::Dimension { expected, got } => {
                write!(f, "observation has dimension {expected}, got {got}")
            }
            Self::DuplicateEdge { u, v } => write!(f, "session {u}-{v} already exists"),
            Self::CycleNotClosed { start, end } => {
                write!(f, "cycle starts at {start} and ends at {end}")
            }
            Self::NoPath { u, v } => write!(f, "no session path from {u} to {v}"),
        }
    }
}

impl std::error::Error for SheafError {}

/// The 1-skeleton of the epistemic sheaf over `G = Z^dimension`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheafComplex {
    vertices: usize,
    dimension: usize,
    edges: Vec<Edge>,
}

impl SheafComplex {
    pub fn new(vertices: usize, dimension: usize) -> Self {
        Self {
            vertices,
            dimension,
            edges: Vec::new(),
        }
    }

    /// Add an authenticated session reporting `delta`.
    pub fn connect(&mut self, u: usize, v: usize, delta: Vec<i64>) -> Result<(), SheafError> {
        if u >= self.vertices {
            return Err(SheafError::UnknownVertex(u));
        }
        if v >= self.vertices {
            return Err(SheafError::UnknownVertex(v));
        }
        if u == v {
            return Err(SheafError::SelfLoop(u));
        }
        if delta.len() != self.dimension {
            return Err(SheafError::Dimension {
                expected: self.dimension,
                got: delta.len(),
            });
        }
        if self.edge_between(u, v).is_some() {
            return Err(SheafError::DuplicateEdge { u, v });
        }
        self.edges.push(Edge { u, v, delta });
        Ok(())
    }

    pub fn vertices(&self) -> usize {
        self.vertices
    }

    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    fn edge_between(&self, u: usize, v: usize) -> Option<&Edge> {
        self.edges
            .iter()
            .find(|e| (e.u == u && e.v == v) || (e.u == v && e.v == u))
    }

    /// Oriented discrepancy: `delta(u,v)` is the reverse of `delta(v,u)`.
    pub fn delta(&self, u: usize, v: usize) -> Option<Vec<i64>> {
        let edge = self.edge_between(u, v)?;
        let sign = if edge.u == u { 1 } else { -1 };
        Some(edge.delta.iter().map(|d| sign * d).collect())
    }

    /// The 2-coboundary on a triangle: `delta_uv + delta_vw + delta_wu`.
    pub fn coboundary(&self, u: usize, v: usize, w: usize) -> Option<Vec<i64>> {
        let a = self.delta(u, v)?;
        let b = self.delta(v, w)?;
        let c = self.delta(w, u)?;
        Some(
            a.iter()
                .zip(b.iter())
                .zip(c.iter())
                .map(|((x, y), z)| x + y + z)
                .collect(),
        )
    }

    /// Sum of `delta` along a closed walk. Non-zero means the walk is a proof
    /// that no single global reality produced these observations.
    pub fn holonomy(&self, cycle: &[usize]) -> Result<Vec<i64>, SheafError> {
        let (&start, &end) = match (cycle.first(), cycle.last()) {
            (Some(a), Some(b)) => (a, b),
            _ => return Err(SheafError::CycleNotClosed { start: 0, end: 0 }),
        };
        if start != end {
            return Err(SheafError::CycleNotClosed { start, end });
        }
        let mut total = vec![0i64; self.dimension];
        for pair in cycle.windows(2) {
            let step = self.delta(pair[0], pair[1]).ok_or(SheafError::NoPath {
                u: pair[0],
                v: pair[1],
            })?;
            for (dst, src) in total.iter_mut().zip(step.iter()) {
                *dst += *src;
            }
        }
        Ok(total)
    }

    /// Breadth-first potential fit plus the tree edges it used.
    fn tree_fit(&self) -> (Vec<Vec<i64>>, Vec<bool>) {
        let mut adjacency: Vec<Vec<(usize, usize)>> = vec![Vec::new(); self.vertices];
        for (idx, edge) in self.edges.iter().enumerate() {
            adjacency[edge.u].push((edge.v, idx));
            adjacency[edge.v].push((edge.u, idx));
        }

        let mut potentials = vec![vec![0i64; self.dimension]; self.vertices];
        let mut seen = vec![false; self.vertices];
        let mut in_tree = vec![false; self.edges.len()];

        for root in 0..self.vertices {
            if seen[root] {
                continue;
            }
            seen[root] = true;
            let mut queue = VecDeque::from([root]);
            while let Some(u) = queue.pop_front() {
                for &(v, idx) in &adjacency[u] {
                    if seen[v] {
                        continue;
                    }
                    let edge = &self.edges[idx];
                    let step = if edge.u == u {
                        edge.delta.clone()
                    } else {
                        edge.delta.iter().map(|d| -d).collect()
                    };
                    potentials[v] = potentials[u]
                        .iter()
                        .zip(step.iter())
                        .map(|(g, d)| g + d)
                        .collect();
                    seen[v] = true;
                    in_tree[idx] = true;
                    queue.push_back(v);
                }
            }
        }
        (potentials, in_tree)
    }

    /// The unique global reality consistent with every session, if one exists.
    ///
    /// `None` is the `[delta] != 0` case: local views cannot be projections of
    /// any single world, so a split-world MitM, eclipse boundary or wormhole is
    /// present.
    pub fn global_reality(&self) -> Option<Vec<Vec<i64>>> {
        let (potentials, _) = self.tree_fit();
        for edge in &self.edges {
            let exact = edge
                .delta
                .iter()
                .zip(potentials[edge.v].iter())
                .zip(potentials[edge.u].iter())
                .all(|((delta, high), low)| *delta == high - low);
            if !exact {
                return None;
            }
        }
        Some(potentials)
    }

    /// True when every session is a projection of one global reality.
    pub fn is_exact(&self) -> bool {
        self.global_reality().is_some()
    }

    fn tree_path(&self, in_tree: &[bool], u: usize, v: usize) -> Option<Vec<usize>> {
        if u == v {
            return Some(vec![u]);
        }
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); self.vertices];
        for (idx, edge) in self.edges.iter().enumerate() {
            if !in_tree[idx] {
                continue;
            }
            adjacency[edge.u].push(edge.v);
            adjacency[edge.v].push(edge.u);
        }
        let mut parent = vec![usize::MAX; self.vertices];
        let mut seen = vec![false; self.vertices];
        seen[u] = true;
        let mut queue = VecDeque::from([u]);
        while let Some(node) = queue.pop_front() {
            for &next in &adjacency[node] {
                if seen[next] {
                    continue;
                }
                seen[next] = true;
                parent[next] = node;
                if next == v {
                    let mut path = vec![v];
                    let mut cursor = v;
                    while cursor != u {
                        cursor = parent[cursor];
                        path.push(cursor);
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back(next);
            }
        }
        None
    }

    /// One witness cycle per non-tree session that contradicts the fit.
    ///
    /// Each witness is a closed walk around which the discrepancy does not
    /// cancel. In a split-world the witnesses traverse the horizon: the edges
    /// of the censor's boundary necessarily appear in them.
    pub fn obstructions(&self) -> Vec<CycleWitness> {
        let (potentials, in_tree) = self.tree_fit();
        let mut witnesses = Vec::new();
        for (idx, edge) in self.edges.iter().enumerate() {
            if in_tree[idx] {
                continue;
            }
            let exact = edge
                .delta
                .iter()
                .zip(potentials[edge.v].iter())
                .zip(potentials[edge.u].iter())
                .all(|((delta, high), low)| *delta == high - low);
            if exact {
                continue;
            }
            let Some(path) = self.tree_path(&in_tree, edge.u, edge.v) else {
                continue;
            };
            let mut cycle = path;
            cycle.push(edge.u);
            if let Ok(holonomy) = self.holonomy(&cycle) {
                if holonomy.iter().any(|h| *h != 0) {
                    witnesses.push(CycleWitness { cycle, holonomy });
                }
            }
        }
        witnesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_consistent_reality_has_no_obstruction() {
        // Four peers observing one global bit-vector; every session reports the
        // true difference.
        let truth = [[1i64, 2], [3i64, 5], [0i64, 7], [9i64, 1]];
        let mut complex = SheafComplex::new(4, 2);
        for (u, v) in [(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)] {
            let delta = truth[v]
                .iter()
                .zip(truth[u].iter())
                .map(|(a, b)| a - b)
                .collect();
            complex.connect(u, v, delta).expect("consistent session");
        }

        // The fit is unique only up to the arbitrary baseline of the root
        // vertex, so compare in the root's gauge: g(v) - g(0) == truth[v] - truth[0].
        let fitted = complex.global_reality().expect("one reality fits");
        for (v, value) in fitted.iter().enumerate() {
            for k in 0..2 {
                assert_eq!(value[k], truth[v][k] - truth[0][k]);
            }
        }
        assert!(complex.is_exact());
        assert!(complex.obstructions().is_empty());
        assert_eq!(complex.holonomy(&[0, 1, 2, 3, 0]).unwrap(), vec![0, 0]);
        assert_eq!(complex.coboundary(0, 1, 2).unwrap(), vec![0, 0]);
    }

    #[test]
    fn a_split_horizon_leaves_a_non_zero_cohomology_class() {
        // Two fully connected cliques, each internally consistent, joined by
        // two sessions that a censor reports as "no difference". Every node
        // passes its local checks; the loop through both joins does not close.
        let mut complex = SheafComplex::new(6, 1);
        // Clique A sees the relay set as 1,2,3; clique B as 8,9,10.
        for (u, v, delta) in [
            (0, 1, 1),
            (1, 2, 1),
            (0, 2, 2),
            (3, 4, 1),
            (4, 5, 1),
            (3, 5, 2),
            // The horizon: both sessions claim the two sides agree.
            (2, 3, 0),
            (1, 4, 0),
        ] {
            complex.connect(u, v, vec![delta]).expect("session");
        }

        assert!(complex.global_reality().is_none(), "no single world fits");
        assert!(!complex.is_exact());

        let witnesses = complex.obstructions();
        assert!(!witnesses.is_empty(), "H^1 obstruction must be witnessed");
        for witness in &witnesses {
            assert!(witness.holonomy.iter().any(|h| *h != 0));
            assert_eq!(witness.cycle.first(), witness.cycle.last());
            // A witness must cross the horizon: it contains at least one of the
            // two censored sessions (2,3) or (1,4).
            let crosses = witness.cycle.windows(2).any(|p| {
                (p[0] == 2 && p[1] == 3)
                    || (p[0] == 3 && p[1] == 2)
                    || (p[0] == 1 && p[1] == 4)
                    || (p[0] == 4 && p[1] == 1)
            });
            assert!(crosses, "witness {:?} misses the horizon", witness.cycle);
        }
    }

    #[test]
    fn a_single_falsified_session_is_localised_and_quantified() {
        // A 4-cycle where one session under-reports the difference by 5.
        let mut complex = SheafComplex::new(4, 1);
        complex.connect(0, 1, vec![2]).unwrap();
        complex.connect(1, 2, vec![2]).unwrap();
        complex.connect(2, 3, vec![2]).unwrap();
        complex.connect(3, 0, vec![-1]).unwrap(); // truth is -6, lie is 5 short

        // In forward orientation the loop sums to the exact size of the lie.
        assert_eq!(complex.holonomy(&[0, 1, 2, 3, 0]).unwrap(), vec![5]);
        let witnesses = complex.obstructions();
        assert_eq!(witnesses.len(), 1);
        let witness = &witnesses[0];
        assert!(witness.holonomy.iter().any(|h| *h != 0));
        // The witness is the whole 4-cycle: the lie cannot be pinned on a
        // vertex, only on the loop that fails to close.
        let mut vertices = witness.cycle.clone();
        vertices.sort_unstable();
        vertices.dedup();
        assert_eq!(vertices, vec![0, 1, 2, 3]);
    }

    #[test]
    fn holonomy_is_invariant_under_a_gauge_shift() {
        // Adding any potential to every observation leaves every loop sum
        // unchanged: the obstruction is a property of the cocycle, not of the
        // arbitrary per-peer baseline.
        let base = [(0usize, 1usize, 3i64), (1, 2, 4), (2, 0, -7)];
        let shift = [10i64, -3, 6];

        let mut plain = SheafComplex::new(3, 1);
        let mut shifted = SheafComplex::new(3, 1);
        for &(u, v, delta) in &base {
            plain.connect(u, v, vec![delta]).unwrap();
            // delta' = delta + g(v) - g(u)
            shifted
                .connect(u, v, vec![delta + shift[v] - shift[u]])
                .unwrap();
        }

        assert_eq!(
            plain.holonomy(&[0, 1, 2, 0]).unwrap(),
            shifted.holonomy(&[0, 1, 2, 0]).unwrap()
        );
        assert_eq!(plain.holonomy(&[0, 1, 2, 0]).unwrap(), vec![0]);
        assert!(plain.is_exact());
        assert!(shifted.is_exact());
    }

    #[test]
    fn malformed_sessions_are_refused() {
        let mut complex = SheafComplex::new(3, 2);
        assert_eq!(
            complex.connect(0, 0, vec![0, 0]),
            Err(SheafError::SelfLoop(0))
        );
        assert_eq!(
            complex.connect(0, 3, vec![0, 0]),
            Err(SheafError::UnknownVertex(3))
        );
        assert_eq!(
            complex.connect(0, 1, vec![0]),
            Err(SheafError::Dimension {
                expected: 2,
                got: 1
            })
        );
        complex.connect(0, 1, vec![1, 2]).unwrap();
        assert_eq!(
            complex.connect(1, 0, vec![1, 2]),
            Err(SheafError::DuplicateEdge { u: 1, v: 0 })
        );
        assert_eq!(
            complex.holonomy(&[0, 1, 0, 1]).unwrap_err(),
            SheafError::CycleNotClosed { start: 0, end: 1 }
        );
    }
}
