#![cfg(feature = "research")]
//! Causal Polysemy — counterfactually blind world-collapsed transport
//! (`DEV/UNPRECEDENTED_PRIMITIVES.md` §1, V3 Stage 7).
//!
//! A link with `n` physical paths carries one independent `r`-symbol message
//! per `k`-subset of paths. Each subset is a *world*: whichever `k` paths
//! survive, the receiver collapses to that world's message. An observer that
//! holds every path except `i` learns **zero bits** about any world that needed
//! path `i`, because every such world is hidden behind `C(n-1, k-1)` uniform
//! masks, one per world it belongs to, and shard `i` holds exactly one mask per
//! such world.
//!
//! The construction is additive sharing over `F_{2^8}` (XOR) on the complete
//! `k`-uniform hypergraph. Adding the `k` masks of a world reproduces its
//! message, and any `k-1` of them are uniform and independent of it. Shard size
//! is therefore exactly the counterfactual capacity of the theorem:
//!
//! ```text
//! |Y_i| = C(n-1, k-1) * r bytes
//! ```

use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolysemyError {
    Shape { n: usize, k: usize, r: usize },
    WorldCount { expected: usize, got: usize },
    MessageLen { expected: usize, got: usize },
    MaskCount { expected: usize, got: usize },
    Survivors { expected: usize, got: usize },
    PathOutOfRange(usize),
    ShardLen { expected: usize, got: usize },
}

impl fmt::Display for PolysemyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape { n, k, r } => write!(f, "invalid polysemic shape n={n} k={k} r={r}"),
            Self::WorldCount { expected, got } => {
                write!(f, "expected {expected} worlds, got {got}")
            }
            Self::MessageLen { expected, got } => {
                write!(f, "expected {expected}-byte message, got {got}")
            }
            Self::MaskCount { expected, got } => {
                write!(f, "expected {expected} masks for the world, got {got}")
            }
            Self::Survivors { expected, got } => {
                write!(f, "collapse needs {expected} paths, got {got}")
            }
            Self::PathOutOfRange(i) => write!(f, "path {i} is outside the link"),
            Self::ShardLen { expected, got } => {
                write!(f, "shard must be {expected} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for PolysemyError {}

fn binomial(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    let k = k.min(n - k);
    let mut out = 1usize;
    for i in 0..k {
        out = out * (n - i) / (i + 1);
    }
    out
}

fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn walk(start: usize, n: usize, k: usize, pick: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if pick.len() == k {
            out.push(pick.clone());
            return;
        }
        for i in start..n {
            pick.push(i);
            walk(i + 1, n, k, pick, out);
            pick.pop();
        }
    }
    let mut out = Vec::new();
    walk(0, n, k, &mut Vec::with_capacity(k), &mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolysemicCode {
    n: usize,
    k: usize,
    r: usize,
    subsets: Vec<Vec<usize>>,
    slot_of: Vec<Vec<usize>>,
}

impl PolysemicCode {
    pub fn new(n: usize, k: usize, r: usize) -> Result<Self, PolysemyError> {
        if n < 2 || k == 0 || k > n || r == 0 {
            return Err(PolysemyError::Shape { n, k, r });
        }
        let subsets = combinations(n, k);
        let mut slot_of = vec![vec![usize::MAX; subsets.len()]; n];
        for (s_idx, subset) in subsets.iter().enumerate() {
            for &path in subset {
                let next = slot_of[path].iter().filter(|&&s| s != usize::MAX).count();
                slot_of[path][s_idx] = next;
            }
        }
        Ok(Self {
            n,
            k,
            r,
            subsets,
            slot_of,
        })
    }

    pub fn paths(&self) -> usize {
        self.n
    }

    pub fn survivors_required(&self) -> usize {
        self.k
    }

    pub fn symbol_len(&self) -> usize {
        self.r
    }

    pub fn world_count(&self) -> usize {
        self.subsets.len()
    }

    pub fn world_subsets(&self) -> &[Vec<usize>] {
        &self.subsets
    }

    pub fn world_index(&self, survivors: &[usize]) -> Option<usize> {
        let mut sorted = survivors.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.k {
            return None;
        }
        self.subsets.iter().position(|subset| *subset == sorted)
    }

    pub fn shard_len(&self) -> usize {
        binomial(self.n - 1, self.k - 1) * self.r
    }

    pub fn encode(&self, worlds: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, PolysemyError> {
        let masks: Vec<Vec<Vec<u8>>> = self
            .subsets
            .iter()
            .map(|_| {
                (0..self.k - 1)
                    .map(|_| {
                        let mut m = vec![0u8; self.r];
                        OsRng.fill_bytes(&mut m);
                        m
                    })
                    .collect()
            })
            .collect();
        self.encode_with_masks(worlds, &masks)
    }

    pub fn encode_with_masks(
        &self,
        worlds: &[Vec<u8>],
        masks: &[Vec<Vec<u8>>],
    ) -> Result<Vec<Vec<u8>>, PolysemyError> {
        if worlds.len() != self.subsets.len() {
            return Err(PolysemyError::WorldCount {
                expected: self.subsets.len(),
                got: worlds.len(),
            });
        }
        let mut shards = vec![vec![0u8; self.shard_len()]; self.n];
        for (s_idx, subset) in self.subsets.iter().enumerate() {
            let message = &worlds[s_idx];
            if message.len() != self.r {
                return Err(PolysemyError::MessageLen {
                    expected: self.r,
                    got: message.len(),
                });
            }
            let mask_set = masks.get(s_idx).ok_or(PolysemyError::MaskCount {
                expected: self.k - 1,
                got: 0,
            })?;
            if mask_set.len() + 1 < self.k {
                return Err(PolysemyError::MaskCount {
                    expected: self.k - 1,
                    got: mask_set.len(),
                });
            }
            for mask in mask_set.iter().take(self.k - 1) {
                if mask.len() != self.r {
                    return Err(PolysemyError::MessageLen {
                        expected: self.r,
                        got: mask.len(),
                    });
                }
            }
            let mut last = message.clone();
            for mask in mask_set.iter().take(self.k - 1) {
                for (dst, src) in last.iter_mut().zip(mask.iter()) {
                    *dst ^= *src;
                }
            }
            for (position, &path) in subset.iter().enumerate() {
                let share: &[u8] = if position + 1 == self.k {
                    &last
                } else {
                    &mask_set[position]
                };
                let offset = self.slot_of[path][s_idx] * self.r;
                shards[path][offset..offset + self.r].copy_from_slice(share);
            }
        }
        Ok(shards)
    }

    pub fn collapse(
        &self,
        shards: &[Vec<u8>],
        survivors: &[usize],
    ) -> Result<Vec<u8>, PolysemyError> {
        if shards.len() != self.n {
            return Err(PolysemyError::Survivors {
                expected: self.n,
                got: shards.len(),
            });
        }
        let mut sorted = survivors.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.k {
            return Err(PolysemyError::Survivors {
                expected: self.k,
                got: sorted.len(),
            });
        }
        if let Some(&bad) = sorted.iter().find(|&&i| i >= self.n) {
            return Err(PolysemyError::PathOutOfRange(bad));
        }
        let s_idx =
            self.subsets
                .iter()
                .position(|s| *s == sorted)
                .ok_or(PolysemyError::Survivors {
                    expected: self.k,
                    got: sorted.len(),
                })?;
        let mut message = vec![0u8; self.r];
        for &path in &sorted {
            let offset = self.slot_of[path][s_idx] * self.r;
            let shard = &shards[path];
            if shard.len() < offset + self.r {
                return Err(PolysemyError::ShardLen {
                    expected: offset + self.r,
                    got: shard.len(),
                });
            }
            for (dst, src) in message.iter_mut().zip(&shard[offset..offset + self.r]) {
                *dst ^= *src;
            }
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(values: &[u8]) -> Vec<Vec<u8>> {
        values.iter().map(|v| vec![*v]).collect()
    }

    #[test]
    fn every_world_collapses_from_its_own_paths() {
        let code = PolysemicCode::new(3, 2, 2).expect("3-path link");
        assert_eq!(code.world_count(), 3);
        assert_eq!(code.shard_len(), 4);

        let worlds = vec![
            vec![0x11, 0x12], // {Wi-Fi, 5G}
            vec![0x21, 0x22], // {Wi-Fi, HF}
            vec![0x31, 0x32], // {5G, HF}
        ];
        let shards = code.encode(&worlds).expect("encodes");

        assert_eq!(code.collapse(&shards, &[0, 1]).unwrap(), worlds[0]);
        assert_eq!(code.collapse(&shards, &[0, 2]).unwrap(), worlds[1]);
        assert_eq!(code.collapse(&shards, &[1, 2]).unwrap(), worlds[2]);
    }

    #[test]
    fn a_cut_path_selects_the_world_that_survives() {
        let code = PolysemicCode::new(3, 2, 1).expect("3-path link");
        let worlds = bytes(&[0xA1, 0xB2, 0xC3]);
        let shards = code.encode(&worlds).expect("encodes");

        let collapsed = code.collapse(&shards, &[0, 2]).expect("collapse");
        assert_eq!(collapsed, worlds[1]);
        assert!(code.collapse(&shards, &[0]).is_err());
        assert!(code.collapse(&shards, &[0, 1, 2]).is_err());
    }

    #[test]
    fn a_lost_path_leaves_the_hidden_world_a_bijection() {
        let code = PolysemicCode::new(3, 2, 1).expect("3-path link");
        let worlds = bytes(&[0xAA, 0xBB, 0xCC]);
        let masks = vec![vec![vec![0x11u8]], vec![vec![0x22u8]], vec![vec![0x33u8]]];
        let shards = code
            .encode_with_masks(&worlds, &masks)
            .expect("encodes with pinned masks");

        let mut reachable = std::collections::BTreeSet::new();
        for candidate in 0u8..=255 {
            let mut alt_masks = masks.clone();
            alt_masks[0][0][0] = shards[1][0] ^ candidate;
            let alt_worlds = vec![vec![candidate], worlds[1].clone(), worlds[2].clone()];
            let rebuilt = code
                .encode_with_masks(&alt_worlds, &alt_masks)
                .expect("re-encodes");
            assert_eq!(&rebuilt[1], &shards[1], "path 1 unchanged");
            assert_eq!(&rebuilt[2], &shards[2], "path 2 unchanged");
            reachable.insert(candidate);
        }
        assert_eq!(reachable.len(), 256, "every hidden world is equally likely");
    }

    #[test]
    fn the_shard_is_exactly_the_counterfactual_capacity() {
        assert_eq!(PolysemicCode::new(3, 2, 1).unwrap().shard_len(), 2);
        assert_eq!(PolysemicCode::new(3, 2, 3).unwrap().shard_len(), 6);
        assert_eq!(PolysemicCode::new(4, 2, 3).unwrap().shard_len(), 9);
        assert_eq!(PolysemicCode::new(4, 3, 2).unwrap().shard_len(), 6);
        let code = PolysemicCode::new(5, 3, 2).unwrap();
        for path_slots in code.slot_of.iter().take(5) {
            let slots = path_slots.iter().filter(|&&s| s != usize::MAX).count();
            assert_eq!(slots, binomial(4, 2));
        }
        assert_eq!(code.shard_len(), 6 * 2);
    }

    #[test]
    fn malformed_frames_are_refused() {
        let code = PolysemicCode::new(3, 2, 1).unwrap();
        assert_eq!(
            code.encode(&[vec![1], vec![2]]),
            Err(PolysemyError::WorldCount {
                expected: 3,
                got: 2
            })
        );
        assert_eq!(
            code.encode(&[vec![1, 2], vec![2], vec![3]]),
            Err(PolysemyError::MessageLen {
                expected: 1,
                got: 2
            })
        );
        assert!(PolysemicCode::new(3, 4, 1).is_err());
        assert!(PolysemicCode::new(3, 0, 1).is_err());
        assert!(PolysemicCode::new(3, 2, 0).is_err());
    }
}
